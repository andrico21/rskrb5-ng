//! The `kcm_mach_service` of a configuration reaches the transport an
//! installed [`TransportFactory`] makes for it (MIT-config-25): per
//! configuration, never captured from whichever configuration came first, with
//! `-` disabling it, a missing service falling back to the configured socket,
//! and a lost request never sent a second time.
//!
//! The installation is process-wide and the first one wins, so this target has
//! its own process and every test shares the one factory.

#![cfg(unix)]

/// Factory tests.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    extern crate alloc;

    use alloc::sync::Arc;
    use core::error;
    use std::{
        env, fs, io,
        io::{Read as _, Write as _},
        os::unix::net::{UnixListener, UnixStream},
        path::{Path, PathBuf},
        process,
        sync::{
            Mutex, OnceLock, PoisonError,
            atomic::{AtomicBool, AtomicU32, Ordering},
        },
        thread::{self, JoinHandle},
    };

    use rskrb5_ng::{
        ccache::{
            CCache, configured,
            kcm::{
                Store,
                seam::{KcmTransport, TransportFactory, install_transport_factory},
            },
            stores::CredentialStore as _,
        },
        config::Config,
        error::{Ccache as CcacheError, Kcm, KcmRefusal, KcmStage},
    };

    /// Error type of the `Result`-returning tests.
    type TestError = Box<dyn error::Error>;

    /// `KCM_OP_DESTROY`.
    const DESTROY: u16 = 5;
    /// `KCM_OP_GET_DEFAULT_CACHE`.
    const GET_DEFAULT_CACHE: u16 = 20;
    /// `KCM_OP_REPLACE`.
    const REPLACE: u16 = 13_002;

    /// A daemon on a temporary Unix socket that answers every request with a
    /// bare success and records the opcodes.
    struct Daemon {
        /// The socket path.
        path: PathBuf,
        /// The opcodes received, in order.
        seen: Arc<Mutex<Vec<u16>>>,
        /// Set to stop the accept loop.
        stop: Arc<AtomicBool>,
        /// The accept loop.
        thread: Option<JoinHandle<()>>,
    }

    /// Serve one connection: read frames, record opcodes, answer status 0.
    fn serve(seen: &Mutex<Vec<u16>>, mut stream: UnixStream) -> io::Result<()> {
        loop {
            let mut length = [0_u8; 4];
            stream.read_exact(&mut length)?;
            let size = usize::try_from(u32::from_be_bytes(length)).map_err(io::Error::other)?;
            let mut request = vec![0_u8; size];
            stream.read_exact(&mut request)?;
            let opcode = request
                .get(2..4)
                .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
                .map_or(0, u16::from_be_bytes);
            seen.lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(opcode);
            // Reply frame: body length, transport code, then the status.
            stream.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0])?;
        }
    }

    impl Daemon {
        /// Start a daemon in a private directory.
        fn start() -> Result<Self, TestError> {
            static NEXT: AtomicU32 = AtomicU32::new(0);
            let directory = env::temp_dir().join(format!(
                "rskrb5-kcmf-{}-{}",
                process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&directory)?;
            let path = directory.join("k.sock");
            let listener = UnixListener::bind(&path)?;
            let seen = Arc::new(Mutex::new(Vec::new()));
            let stop = Arc::new(AtomicBool::new(false));
            let (record, halt) = (Arc::clone(&seen), Arc::clone(&stop));
            let thread = thread::spawn(move || {
                while let Ok((stream, _peer)) = listener.accept() {
                    if halt.load(Ordering::SeqCst) {
                        return;
                    }
                    let connection = Arc::clone(&record);
                    drop(thread::spawn(move || serve(&connection, stream)));
                }
            });
            Ok(Self {
                path,
                seen,
                stop,
                thread: Some(thread),
            })
        }

        /// The socket path.
        fn path(&self) -> &Path {
            &self.path
        }

        /// The opcodes received so far.
        fn seen(&self) -> Vec<u16> {
            self.seen
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }
    }

    impl Drop for Daemon {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            drop(UnixStream::connect(&self.path));
            if let Some(thread) = self.thread.take() {
                drop(thread.join());
            }
            drop(fs::remove_dir_all(self.path.parent().unwrap_or(&self.path)));
        }
    }

    /// What the factory saw: the service names it was asked for and the
    /// requests of its transports as `(service, opcode)`.
    #[derive(Debug, Default)]
    struct Log {
        /// The service names, in the order they were asked for.
        asked: Mutex<Vec<String>>,
        /// The requests, in arrival order.
        requests: Mutex<Vec<(String, u16)>>,
    }

    /// The transport of one service: `absent` has no server, `lost` loses
    /// every reply, any other answers `<service>:cache` as the primary cache.
    #[derive(Debug)]
    struct Service {
        /// The service name.
        name: String,
        /// The shared log.
        log: Arc<Log>,
    }

    impl KcmTransport for Service {
        fn call(&self, request: &[u8]) -> Result<Vec<u8>, Kcm> {
            let opcode = request
                .get(2..4)
                .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
                .map_or(0, u16::from_be_bytes);
            self.log
                .requests
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push((self.name.clone(), opcode));
            match (self.name.as_str(), opcode) {
                ("absent", _) => Err(Kcm::NoServer),
                ("lost", _) => Err(Kcm::Io {
                    stage: KcmStage::Read,
                    source: io::ErrorKind::BrokenPipe.into(),
                }),
                (_, GET_DEFAULT_CACHE) => {
                    Ok([&[0_u8; 4][..], self.name.as_bytes(), b":cache\0"].concat())
                }
                (_, _) => Ok(vec![0; 4]),
            }
        }
    }

    /// The factory: a transport per service name.
    #[derive(Debug)]
    struct Factory(Arc<Log>);

    impl TransportFactory for Factory {
        fn transport(&self, service: &str) -> Result<Arc<dyn KcmTransport>, Kcm> {
            self.0
                .asked
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(service.to_owned());
            if service == "refused" {
                return Err(Kcm::TransportInstalled);
            }
            Ok(Arc::new(Service {
                name: service.to_owned(),
                log: Arc::clone(&self.0),
            }))
        }
    }

    /// The log of the installed factory, installed by the first test that
    /// needs it.
    fn log() -> Result<&'static Arc<Log>, TestError> {
        static INSTALLED: OnceLock<Result<Arc<Log>, String>> = OnceLock::new();
        INSTALLED
            .get_or_init(|| {
                let log = Arc::new(Log::default());
                install_transport_factory(Arc::new(Factory(Arc::clone(&log))))
                    .map(|()| log)
                    .map_err(|error| error.to_string())
            })
            .as_ref()
            .map_err(|message| message.clone().into())
    }

    /// A configuration naming `service` and, when given, a socket.
    fn config(service: &str, socket: Option<&Path>) -> Result<Config, TestError> {
        let socket = socket.map_or_else(String::new, |path| {
            format!(" kcm_socket = {}\n", path.display())
        });
        Ok(Config::parse(&format!(
            "[libdefaults]\n kcm_mach_service = {service}\n{socket}"
        ))?)
    }

    /// The primary cache name of the store of `config`.
    fn primary(config: &Config) -> Result<String, CcacheError> {
        Ok(Store::from_libdefaults(&config.libdefaults)
            .map_err(CcacheError::Kcm)?
            .collection("")?
            .primary()?
            .name())
    }

    /// The configured Mach service picks the transport, per configuration:
    /// two configurations naming two services reach two services.
    #[test]
    fn configured_kcm_names_use_mach_service() -> Result<(), TestError> {
        let log = log()?;
        let first = primary(&config("org.example.first", None)?)?;
        let second = primary(&config("org.example.second", None)?)?;
        assert_eq!(first, "KCM:org.example.first:cache");
        assert_eq!(second, "KCM:org.example.second:cache");
        let asked = log
            .asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        assert!(asked.contains(&"org.example.first".to_owned()), "{asked:?}");
        assert!(
            asked.contains(&"org.example.second".to_owned()),
            "{asked:?}"
        );
        Ok(())
    }

    /// A configured cache name goes through the service too: the cache of the
    /// name route is the one the transport answered for.
    #[test]
    fn the_name_routes_use_the_configured_service() -> Result<(), TestError> {
        let log = log()?;
        let config = config("org.example.routes", None)?;
        let loaded = configured::load_name(&config, "KCM:no-such-cache");
        // The transport answers every request with a bare status, which is
        // not a cache: the point is where the request went.
        assert!(loaded.is_err());
        assert!(
            log.requests
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .iter()
                .any(|(service, _opcode)| service == "org.example.routes")
        );
        Ok(())
    }

    /// `-` disables Mach: the factory is not asked and the configured socket
    /// serves.
    #[test]
    fn disabled_mach_uses_configured_socket() -> Result<(), TestError> {
        let log = log()?;
        let daemon = Daemon::start()?;
        let config = config("-", Some(daemon.path()))?;
        let saved = configured::save_name(&config, &CCache::new(principal()), "KCM:disabled-mach");
        if cfg!(target_os = "linux") {
            saved?;
            assert!(daemon.seen().contains(&REPLACE));
        } else {
            assert!(matches!(
                saved,
                Err(CcacheError::Kcm(Kcm::Untrusted(
                    KcmRefusal::IdentityUnavailable
                )))
            ));
        }
        assert!(
            !log.asked
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .contains(&"-".to_owned())
        );
        Ok(())
    }

    /// A service the transport cannot find never received the request: the
    /// configured socket gets it, as MIT falls back from Mach to the socket.
    #[test]
    fn an_absent_service_falls_back_to_the_socket() -> Result<(), TestError> {
        let log = log()?;
        let daemon = Daemon::start()?;
        let config = config("absent", Some(daemon.path()))?;
        let saved = configured::save_name(&config, &CCache::new(principal()), "KCM:fallback");
        let tried = log
            .requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .any(|(service, opcode)| service == "absent" && *opcode == REPLACE);
        assert!(tried, "the Mach transport was tried first");
        if cfg!(target_os = "linux") {
            saved?;
            assert!(daemon.seen().contains(&REPLACE));
        } else {
            assert!(saved.is_err());
        }
        Ok(())
    }

    /// A failure other than "no server" may have delivered the request: the
    /// outcome is unknown and the socket is never tried.
    #[test]
    fn a_lost_request_is_not_sent_to_the_socket() -> Result<(), TestError> {
        let _log = log()?;
        let daemon = Daemon::start()?;
        let config = config("lost", Some(daemon.path()))?;
        let destroyed = Store::from_libdefaults(&config.libdefaults)?
            .resolve("lost-cache")?
            .destroy();
        assert!(
            matches!(
                destroyed,
                Err(CcacheError::Kcm(Kcm::OutcomeUnknown {
                    opcode: DESTROY,
                    cause: _,
                }))
            ),
            "{destroyed:?}"
        );
        assert!(
            daemon.seen().is_empty(),
            "the socket saw {:?}",
            daemon.seen()
        );
        Ok(())
    }

    /// The factory's own refusal reaches the caller of the constructor.
    #[test]
    fn a_factory_error_is_returned() -> Result<(), TestError> {
        let _log = log()?;
        let refused = Store::from_libdefaults(&config("refused", None)?.libdefaults);
        assert!(
            matches!(refused, Err(Kcm::TransportInstalled)),
            "{refused:?}"
        );
        Ok(())
    }

    /// A configuration that sets no service reaches the default one.
    #[test]
    fn the_default_service_is_asked_for_by_name() -> Result<(), TestError> {
        let log = log()?;
        let config = Config::parse("[libdefaults]\n")?;
        let primary = primary(&config)?;
        assert_eq!(primary, "KCM:org.h5l.kcm:cache");
        assert!(
            log.asked
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .contains(&"org.h5l.kcm".to_owned())
        );
        Ok(())
    }

    /// The principal of the caches saved here.
    fn principal() -> rskrb5_ng::ccache::Principal {
        rskrb5_ng::ccache::Principal::new("TEST.RSKRB5", 1, vec!["alice".to_owned()])
    }
}

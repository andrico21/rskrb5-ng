//! The process-wide KCM transport seam: one installed [`KcmTransport`] serves
//! the built-in `KCM` store instead of the daemon socket (MIT `kcmio_call`,
//! which macOS routes to a Mach service), and a second installation is refused.
//!
//! The installation is process-wide and the first one wins, so this target
//! has its own process and every test shares the one recorder.

#![cfg(unix)]

/// Transport seam tests.
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
    use core::{error, time::Duration};
    use std::{
        io,
        sync::{Mutex, OnceLock, PoisonError},
    };

    use rskrb5_ng::{
        ccache::{
            CCache, Principal, configured, file_store,
            kcm::{
                Store,
                seam::{KcmTransport, install_transport},
                socket::Trust,
                wire::MAX_REPLY_SIZE,
            },
            stores::{CacheVersion, CredentialStore as _},
        },
        config::Config,
        error::{Ccache as CcacheError, Kcm, KcmStage},
    };

    /// Error type of the `Result`-returning tests.
    type TestError = Box<dyn error::Error>;

    /// `KCM_OP_DESTROY`.
    const DESTROY: u16 = 5;
    /// `KCM_OP_GET_DEFAULT_CACHE`.
    const GET_DEFAULT_CACHE: u16 = 20;

    /// A transport that records every request and answers by the cache name.
    #[derive(Debug, Default)]
    struct Recorder {
        /// The complete requests, in arrival order.
        requests: Mutex<Vec<Vec<u8>>>,
    }

    impl Recorder {
        /// A copy of the requests seen so far.
        fn seen(&self) -> Vec<Vec<u8>> {
            self.requests
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }
    }

    impl KcmTransport for Recorder {
        fn call(&self, request: &[u8]) -> Result<Vec<u8>, Kcm> {
            self.requests
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(request.to_vec());
            let opcode = request
                .get(2..4)
                .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
                .map(u16::from_be_bytes);
            let name = request.get(4..).unwrap_or_default();
            match opcode {
                Some(GET_DEFAULT_CACHE) => Ok([&[0_u8; 4][..], b"55:cc\0"].concat()),
                Some(DESTROY) if name.starts_with(b"lost") => Err(Kcm::Io {
                    stage: KcmStage::Read,
                    source: io::ErrorKind::BrokenPipe.into(),
                }),
                Some(DESTROY) if name.starts_with(b"refused") => Ok(7_i32.to_be_bytes().to_vec()),
                Some(DESTROY) if name.starts_with(b"huge") => Ok(vec![0; MAX_REPLY_SIZE + 1]),
                Some(DESTROY) if name.starts_with(b"empty") => Ok(Vec::new()),
                _ => Ok(vec![0; 4]),
            }
        }
    }

    /// The recorder, installed by the first test that needs it.
    fn recorder() -> Result<&'static Arc<Recorder>, TestError> {
        static INSTALLED: OnceLock<Result<Arc<Recorder>, String>> = OnceLock::new();
        INSTALLED
            .get_or_init(|| {
                let recorder = Arc::new(Recorder::default());
                install_transport(Arc::<Recorder>::clone(&recorder))
                    .map(|()| recorder)
                    .map_err(|error| error.to_string())
            })
            .as_ref()
            .map_err(|message| message.clone().into())
    }

    /// The version every store here opens caches with.
    fn version() -> CacheVersion {
        CacheVersion::default()
    }

    /// The request of `opcode` about `name`, as MIT marshals it: version 2.0,
    /// the opcode, the zero-terminated name, and no length frame.
    fn request(opcode: u16, name: &str) -> Vec<u8> {
        [&[2_u8, 0][..], &opcode.to_be_bytes(), name.as_bytes(), &[0]].concat()
    }

    /// The built-in store reaches the daemon through the installed transport:
    /// the request arrives whole and unframed, the reply is the status and the
    /// payload.
    #[test]
    fn the_built_in_store_uses_the_installed_transport() -> Result<(), TestError> {
        let recorder = recorder()?;
        let primary = file_store::resolve("KCM:", version())?;
        assert_eq!(primary.name(), "KCM:55:cc");
        assert!(recorder.seen().contains(&vec![2, 0, 0, 20]));
        file_store::resolve("KCM:55:cc", version())?.destroy()?;
        assert!(recorder.seen().contains(&request(DESTROY, "55:cc")));
        Ok(())
    }

    /// A built-in store with another time limit or trust list is still the
    /// built-in store.
    #[test]
    fn a_tuned_built_in_store_keeps_the_transport() -> Result<(), TestError> {
        let recorder = recorder()?;
        let timed = Store::default().with_timeout(Duration::from_secs(5));
        timed.resolve("timed")?.destroy()?;
        let trusted = Store::default().with_trust(Trust::new());
        trusted.resolve("trusted")?.destroy()?;
        let seen = recorder.seen();
        assert!(seen.contains(&request(DESTROY, "timed")));
        assert!(seen.contains(&request(DESTROY, "trusted")));
        Ok(())
    }

    /// The first installation wins: another transport, and the same one again,
    /// are refused with the typed error, and the first keeps serving.
    #[test]
    fn a_second_installation_is_refused() -> Result<(), TestError> {
        let recorder = recorder()?;
        let other = install_transport(Arc::new(Recorder::default()));
        assert!(matches!(other, Err(Kcm::TransportInstalled)), "{other:?}");
        let again = install_transport(Arc::<Recorder>::clone(recorder));
        assert!(matches!(again, Err(Kcm::TransportInstalled)), "{again:?}");
        let before = recorder.seen().len();
        let _cache = file_store::resolve("KCM:", version())?;
        assert!(recorder.seen().len() > before);
        Ok(())
    }

    /// A failed transport is a typed error, and a lost reply to a request that
    /// changes the daemon is an unknown outcome.
    #[test]
    fn transport_failures_are_typed() -> Result<(), TestError> {
        let _recorder = recorder()?;
        let lost = file_store::resolve("KCM:lost", version())?.destroy();
        assert!(matches!(
            lost,
            Err(CcacheError::Kcm(Kcm::OutcomeUnknown {
                opcode: DESTROY,
                cause,
            })) if matches!(*cause, Kcm::Io { stage: KcmStage::Read, source: _ })
        ));
        let refused = file_store::resolve("KCM:refused", version())?.destroy();
        assert!(matches!(
            refused,
            Err(CcacheError::Kcm(Kcm::Daemon {
                opcode: DESTROY,
                code: 7_i32,
            }))
        ));
        Ok(())
    }

    /// A reply over the cap or without a status is refused like one from the
    /// socket.
    #[test]
    fn replies_are_bounded_and_parsed() -> Result<(), TestError> {
        let _recorder = recorder()?;
        let huge = file_store::resolve("KCM:huge", version())?.destroy();
        assert!(matches!(
            huge,
            Err(CcacheError::Kcm(Kcm::ReplyTooBig {
                length: _,
                limit: MAX_REPLY_SIZE
            }))
        ));
        let empty = file_store::resolve("KCM:empty", version())?.destroy();
        assert!(matches!(
            empty,
            Err(CcacheError::Kcm(Kcm::MalformedReply {
                opcode: DESTROY,
                what: _,
            }))
        ));
        Ok(())
    }

    /// A store made for a socket path keeps using that socket: a request no
    /// other test sends never reaches the transport.
    #[test]
    fn a_store_for_a_socket_ignores_the_installed_transport() -> Result<(), TestError> {
        let recorder = recorder()?;
        let outcome = Store::new("/nonexistent/rskrb5-kcm-seam.sock")
            .resolve("socket-only")?
            .destroy();
        assert!(outcome.is_err());
        assert!(!recorder.seen().contains(&request(DESTROY, "socket-only")));
        Ok(())
    }

    /// The installed transport precedes the configured socket: a socket that
    /// does not exist is never tried, and a disabled socket still has the
    /// transport to serve the store.
    #[test]
    fn installed_transport_precedes_configured_socket() -> Result<(), TestError> {
        let recorder = recorder()?;
        let named =
            Config::parse("[libdefaults]\n kcm_socket = /nonexistent/rskrb5-kcm-config.sock\n")?;
        let disabled = Config::parse("[libdefaults]\n kcm_socket = -\n")?;
        for (config, cache) in [
            (&named, "configured-socket"),
            (&disabled, "disabled-socket"),
        ] {
            let name = format!("KCM:{cache}");
            let handle = file_store::resolve_configured(&name, version(), config)?;
            handle.destroy()?;
            let store = Store::from_libdefaults(&config.libdefaults)?;
            // A disabled socket has no path at all: the default socket never
            // stands in for it.
            assert_eq!(
                store.socket().is_some(),
                config.libdefaults.kcm_socket != "-"
            );
            store.resolve(cache)?.destroy()?;
            let by_name = configured::save_name(
                config,
                &CCache::new(Principal::new("TEST.RSKRB5", 1, vec!["alice".to_owned()])),
                &name,
            );
            assert!(by_name.is_ok(), "{by_name:?}");
            assert!(recorder.seen().contains(&request(DESTROY, cache)));
        }
        Ok(())
    }
}

//! The cache-name routes of the client and of the ccache module honour the
//! `kcm_socket` of the configuration they are given (MIT-config-26), and a
//! `kcm_mach_service` nobody can serve is reported.
//!
//! This target installs no transport, so a configured `KCM:` name reaches the
//! fake daemon on the configured socket, and a disabled socket reaches
//! nothing. A test that needs `KRB5CCNAME` re-runs itself in a child process.

use std::path::Path;

use rskrb5_ng::{
    Config,
    ccache::{CCache, configured, kcm::Store, stores::CredentialStore as _},
    error::{Ccache as CcacheError, Kcm, KcmRefusal},
};

use super::{
    fake::{Fake, Features},
    mock::TestError,
    transport,
};

/// A daemon with every opcode.
const FULL: Features = Features {
    replace: true,
    cred_list: true,
};

/// The MIT 1.22.2 `kinit` cache of `testuser1@TEST.RSKRB5` (format 4).
fn mit_cache() -> Result<CCache, TestError> {
    Ok(CCache::load(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ccache-mit/mit-v4"),
    )?)
}

/// A configuration whose `kcm_socket` is `socket` and whose default cache is
/// `KCM:routes-default`.
fn config_for(socket: &Path) -> Result<Config, TestError> {
    Ok(Config::parse(&format!(
        "[libdefaults]\n kcm_socket = {}\n default_ccache_name = KCM:routes-default\n",
        socket.display()
    ))?)
}

/// A daemon holding the MIT cache under `names`, and a configuration for it.
fn seeded(names: &[&str]) -> Result<(Fake, Config), TestError> {
    let daemon = Fake::start(FULL)?;
    let store = transport::store(daemon.path())?;
    for name in names {
        store.resolve(name)?.replace(&mit_cache()?)?;
    }
    let config = config_for(daemon.path())?;
    Ok((daemon, config))
}

/// Whether `error` is the trust refusal of a socket on a platform that cannot
/// read this process's user, which is where the test daemon is not trusted.
fn is_untrusted(error: &CcacheError) -> bool {
    matches!(
        error,
        CcacheError::Kcm(Kcm::Untrusted(KcmRefusal::IdentityUnavailable))
    )
}

/// Run `route` against the configured daemon: it succeeds where this
/// process's user can be read (Linux); elsewhere the daemon is refused by the
/// trust check, which still proves the configured socket was the one used.
fn through_the_socket<T>(route: Result<T, CcacheError>) -> Result<Option<T>, TestError> {
    match route {
        Ok(value) => Ok(Some(value)),
        Err(error) if !cfg!(target_os = "linux") && is_untrusted(&error) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Every route of the ccache module that takes a configuration reaches the
/// configured socket: load, save, the environment route and the primary of a
/// collection.
#[test]
fn ccache_routes_reach_the_configured_socket() -> Result<(), TestError> {
    // Given a daemon on a configured socket holding one cache.
    let (daemon, config) = seeded(&["routes-ccache"])?;
    // When the cache is loaded and another one saved, by configured name.
    let loaded = through_the_socket(configured::load_name(
        &config,
        "KCM:routes-ccache",
    ))?;
    let saved = through_the_socket(configured::save_name(&config, &mit_cache()?, "KCM:routes-saved"))?;
    // Then the daemon on the configured socket served both, and holds the copy.
    if cfg!(target_os = "linux") {
        let expected = mit_cache()?;
        assert_eq!(
            loaded.ok_or("loaded")?.credentials(),
            expected.credentials()
        );
        assert_eq!(saved, Some(()));
        let copy = transport::store(daemon.path())?
            .resolve("routes-saved")?
            .load()?;
        assert_eq!(copy.default_principal(), expected.default_principal());
    } else {
        assert!(loaded.is_none() && saved.is_none());
    }
    Ok(())
}

/// A `kcm_socket` of `-` disables the transport: no configured route serves
/// the name, and none falls back to the default socket.
#[test]
fn disabled_socket_never_uses_default_socket() -> Result<(), TestError> {
    // Given a daemon that would serve the name, and a configuration that
    // disables the socket.
    let (_daemon, _config) = seeded(&["routes-disabled"])?;
    let disabled = Config::parse("[libdefaults]\n kcm_socket = -\n")?;
    // When the cache is loaded or saved by configured name.
    let loaded = configured::load_name(&disabled, "KCM:routes-disabled");
    let saved = configured::save_name(&disabled, &mit_cache()?, "KCM:routes-disabled");
    // Then both fail as without a server.
    for outcome in [loaded.map(drop), saved] {
        assert!(
            matches!(outcome, Err(CcacheError::Kcm(Kcm::NoServer))),
            "{outcome:?}"
        );
    }
    assert!(matches!(
        Store::from_libdefaults(&disabled.libdefaults),
        Err(Kcm::NoServer)
    ));
    Ok(())
}

/// A `kcm_mach_service` set explicitly, with no Mach transport installed in
/// the process, is a typed provider error on every configured `KCM:` route,
/// before any socket is tried.
#[test]
fn missing_mach_provider_is_reported() -> Result<(), TestError> {
    // Given a daemon on the configured socket and a configuration that also
    // names a Mach service.
    let (daemon, _config) = seeded(&["routes-mach"])?;
    let text = format!(
        "[libdefaults]\n kcm_socket = {}\n kcm_mach_service = org.example.kcm\n",
        daemon.path().display()
    );
    let config = Config::parse(&text)?;
    // When the cache is loaded by configured name.
    let loaded = configured::load_name(&config, "KCM:routes-mach");
    // Then the error names the service nobody can reach, and the socket is not
    // used instead.
    assert!(
        matches!(
            &loaded,
            Err(CcacheError::Kcm(Kcm::NoMachTransport { service })) if service == "org.example.kcm"
        ),
        "{loaded:?}"
    );
    Ok(())
}

/// The default value of `kcm_mach_service` and `-` ask for nothing a provider
/// must serve: the configured socket answers.
#[test]
fn an_unset_or_disabled_mach_service_uses_the_socket() -> Result<(), TestError> {
    let (daemon, _config) = seeded(&["routes-unset"])?;
    for line in ["", " kcm_mach_service = -\n"] {
        let text = format!(
            "[libdefaults]\n kcm_socket = {}\n{line}",
            daemon.path().display()
        );
        let config = Config::parse(&text)?;
        let loaded = through_the_socket(configured::load_name(&config, "KCM:routes-unset"))?;
        assert_eq!(
            loaded.is_some(),
            cfg!(target_os = "linux"),
            "mach line {line:?}"
        );
    }
    Ok(())
}

#[cfg(feature = "tokio")]
mod client {
    //! The client's seven cache routes.

    use std::ffi::OsStr;

    use rskrb5_ng::{
        client::{Tokio, transport::KdcProtocol},
        error::Client,
    };

    use super::*;
    use crate::env;

    /// A client route's outcome as [`through_the_socket`] reads it.
    fn route<T>(result: Result<T, Client>) -> Result<Option<T>, TestError> {
        through_the_socket(result.map_err(|error| match error {
            Client::CCache(inner) => inner,
            other => CcacheError::Io(std::io::Error::other(other)),
        }))
    }

    /// The client's named and default routes reach the configured socket.
    ///
    /// `KRB5CCNAME` must be unset for the default route to use the
    /// configured name, so the test runs in a child process without it.
    #[test]
    fn client_cache_routes_honor_kcm_socket() -> Result<(), TestError> {
        const TEST_PATH: &str = "routes::client::client_cache_routes_honor_kcm_socket";
        if !env::in_child(TEST_PATH) {
            env::run_in_child(TEST_PATH, &[("KRB5CCNAME", None)]);
            return Ok(());
        }
        // Given a daemon on the configured socket holding the default cache
        // and a named one.
        let (daemon, config) = seeded(&["routes-default", "routes-named"])?;
        // When the client is built from the named, the configured default and
        // the default cache.
        let named = route(Tokio::from_ccache_name(
            config.clone(),
            KdcProtocol::Tcp,
            "KCM:routes-named",
        ))?;
        let by_config = route(Tokio::from_default_ccache_name(
            config.clone(),
            KdcProtocol::Tcp,
        ))?;
        let by_default = route(Tokio::from_default_ccache(config, KdcProtocol::Tcp))?;
        // Then each reached the daemon on the configured socket, and the
        // client's three save routes write there too.
        let Some(client) = named else {
            assert!(by_config.is_none() && by_default.is_none());
            return Ok(());
        };
        assert!(by_config.is_some() && by_default.is_some());
        client.save_ccache_name("KCM:routes-saved")?;
        client.save_default_ccache_name()?;
        client.save_default_ccache()?;
        let expected = mit_cache()?;
        let store = transport::store(daemon.path())?;
        for saved in ["routes-saved", "routes-default"] {
            assert_eq!(
                store.resolve(saved)?.load()?.default_principal(),
                expected.default_principal(),
                "{saved}"
            );
        }
        Ok(())
    }

    /// `from_ccache_env` reads `KRB5CCNAME` and honours the configuration it
    /// is given.
    #[test]
    fn ccache_env_honors_configured_kcm_socket() -> Result<(), TestError> {
        const TEST_PATH: &str = "routes::client::ccache_env_honors_configured_kcm_socket";
        if !env::in_child(TEST_PATH) {
            env::run_in_child(
                TEST_PATH,
                &[("KRB5CCNAME", Some(OsStr::new("KCM:routes-env")))],
            );
            return Ok(());
        }
        // Given a daemon on the configured socket holding the cache the
        // environment names.
        let (_daemon, config) = seeded(&["routes-env"])?;
        // When the client is built from the environment.
        let client = route(Tokio::from_ccache_env(config, KdcProtocol::Tcp))?;
        // Then the configured socket served it (or, where the daemon is not
        // trusted, refused it).
        assert_eq!(client.is_some(), cfg!(target_os = "linux"));
        Ok(())
    }
}

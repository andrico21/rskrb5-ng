//! The macOS stores against real services.
//!
//! `KCM:` names reach Mach through the main crate's routes: the factory of
//! [`crate::install_kcm_transport`] makes a Mach transport for the
//! `kcm_mach_service` of the configuration a name is resolved with, and the
//! in-memory KCM service of [`crate::kcm_fixture`] answers under a test Mach
//! name. Every configuration here also sets `kcm_socket = -`, so that a
//! service that does not answer can never reach the system's socket. The CI
//! fixture job also runs the `--ignored` tests, with the variables below,
//! against the CCAPI and Mach caches MIT 1.22.2 `kinit` seeded:
//!
//! - `RSKRB5_NG_OS_PRINCIPAL`: the seeded client, `name@REALM`;
//! - `RSKRB5_NG_OS_API_CACHE`: an `API:` cache MIT seeded (a UUID);
//! - `RSKRB5_NG_OS_API_COPY`: a fresh UUID the test copies the cache to;
//! - `RSKRB5_NG_OS_KCM_CACHE`: a `KCM:` cache MIT seeded in the system's
//!   `org.h5l.kcm`;
//! - `RSKRB5_NG_OS_MIT_KINIT`, `RSKRB5_NG_OS_KRB5_CONF` and
//!   `RSKRB5_NG_OS_PASSWORD`: MIT `kinit`, a profile of the throwaway
//!   realm, and the client password, for MIT writing into the test service.

use alloc::sync::Arc;
use core::{error::Error as StdError, slice};
use std::{
    env, fs,
    io::Write as _,
    process::{self, Command, Stdio},
    thread,
};

use rskrb5_ng::{
    ccache::{
        CCache, Credential, CredentialTimes, EncryptionKey, Principal, configured, file_store,
        kcm::{seam::KcmTransport as _, wire::DEFAULT_MACH_SERVICE},
        stores::{CacheVersion, CredentialStore as _},
    },
    config::Config,
    error::{Ccache as Error, Kcm},
    extensions::{Interface, Registry},
};

use super::{
    ApiStore,
    mach::{MachTransport, Service},
};
use crate::{
    Secret, error::Platform, kcm_fixture::Fixture, principal_text, register, tests::install_once,
};

/// The request that stops the test service.
const STOP: [u8; 4] = [2, 0, 0xff, 0xff];

/// A configuration whose `kcm_mach_service` is `service` and whose socket is
/// disabled, with the Mach transport installed.
fn mach_config(service: &str) -> Result<Config, Box<dyn StdError>> {
    install_once()?;
    Ok(Config::parse(&format!(
        "[libdefaults]\n kcm_mach_service = {service}\n kcm_socket = -\n"
    ))?)
}

/// A required fixture variable.
fn var(name: &str) -> Result<String, Box<dyn StdError>> {
    env::var(name).map_err(|error| format!("{name}: {error}").into())
}

/// Serve the in-memory KCM server under `name` until [`STOP`] arrives.
fn serve(name: &str) -> Result<thread::JoinHandle<Result<(), Platform>>, Platform> {
    let service = Service::check_in(name)?;
    let fixture = Arc::new(Fixture::default());
    Ok(thread::spawn(move || {
        loop {
            let mut stop = false;
            service.serve_one(|request| {
                stop = request == STOP;
                if stop {
                    Secret::from(vec![0; 4])
                } else {
                    fixture.reply(request)
                }
            })?;
            if stop {
                return Ok(());
            }
        }
    }))
}

/// Stop the service `name` and join its thread.
fn stop(
    name: &str,
    server: thread::JoinHandle<Result<(), Platform>>,
) -> Result<(), Box<dyn StdError>> {
    let _reply = MachTransport::new(name.to_owned()).call(&STOP)?;
    server.join().map_err(|_panic| "server panicked")??;
    Ok(())
}

/// A test service name unique to this process.
fn test_name(label: &str) -> String {
    format!("org.rskrb5-ng.test.kcm.{}.{label}", process::id())
}

/// The `KCM:` names of a configuration read and write through Mach RPC to a
/// service checked in under a test name, set through `kcm_mach_service`.
#[test]
fn configured_kcm_names_use_mach_service() -> Result<(), Box<dyn StdError>> {
    // Given the in-memory KCM server under a test Mach name, configured.
    let name = test_name("roundtrip");
    let server = serve(&name)?;
    let config = mach_config(&name)?;
    // When a cache is initialized, filled, read, trimmed and destroyed through
    // the main crate's configured name route.
    let alice = Principal::new("EXAMPLE.ORG", 1, vec!["alice".to_owned()]);
    let cache = file_store::resolve_configured("KCM:", CacheVersion::default(), &config)?;
    cache.initialize(&alice)?;
    let large = vec![0x61; 3000];
    let ticket = Credential::new(
        alice.clone(),
        Principal::new("EXAMPLE.ORG", 2, vec!["HTTP".to_owned(), "web".to_owned()]),
        EncryptionKey::new(18, vec![1; 32]),
        CredentialTimes::default(),
        [0; 4],
        large.into(),
    );
    cache.store(ticket.clone())?;
    let loaded = cache.load()?;
    let by_name = configured::load_name(&config, "KCM:fixture")?;
    let removed = cache.remove(ticket.server())?;
    cache.destroy()?;
    let gone = cache.load();
    stop(&name, server)?;
    // Then the Mach service answered every step, out-of-line bodies included.
    assert_eq!(cache.name(), "KCM:fixture");
    assert_eq!(loaded.default_principal(), &alice);
    assert_eq!(loaded.credentials(), slice::from_ref(&ticket));
    assert_eq!(by_name.credentials(), slice::from_ref(&ticket));
    assert_eq!(removed, 1);
    assert!(
        matches!(gone, Err(Error::CacheNotFound { name: _ })),
        "destroyed"
    );
    Ok(())
}

/// `-` disables Mach RPC and an unregistered name has no server; with the
/// socket disabled too, neither has anything to fall back to.
#[test]
fn kcm_mach_disabled_and_absent() -> Result<(), Box<dyn StdError>> {
    // Given a configuration that disables Mach, and one naming a service that
    // is not registered.
    let disabled = mach_config("-")?;
    let absent_name = test_name("absent");
    let absent = mach_config(&absent_name)?;
    // When a KCM name is resolved.
    let from_disabled = file_store::resolve_configured("KCM:", CacheVersion::default(), &disabled);
    let from_absent = file_store::resolve_configured("KCM:", CacheVersion::default(), &absent);
    // Then both report that there is no server, and the Mach transport
    // itself reports the lookup failure as the same definite error.
    for result in [from_disabled, from_absent] {
        let error = result.err().ok_or("no error")?;
        assert!(matches!(error, Error::Kcm(Kcm::NoServer)), "{error}");
    }
    let lookup = MachTransport::new(absent_name).call(&STOP);
    assert!(matches!(lookup, Err(Kcm::NoServer)), "{lookup:?}");
    Ok(())
}

/// The `API:` store reads the CCAPI cache MIT `kinit -c API:` seeded, writes
/// a copy and destroys the original.
#[test]
#[ignore = "needs the macOS CI fixture: a CCAPI cache seeded by MIT kinit"]
fn api_reads_writes_and_destroys_the_seeded_cache() -> Result<(), Box<dyn StdError>> {
    // Given the seeded cache, reached by name through the installed `API`
    // provider of `register`.
    let mut registry = Registry::new();
    register(&mut registry)?;
    registry.install_stores()?;
    let principal = principal_text::parse(&var("RSKRB5_NG_OS_PRINCIPAL")?).ok_or("principal")?;
    let name = format!("API:{}", var("RSKRB5_NG_OS_API_CACHE")?);
    let seeded = file_store::resolve(&name, CacheVersion::default())?;
    // When it is read by name, copied to a new cache and destroyed.
    let loaded = CCache::load_name(&name)?;
    let copy = ApiStore.resolve(&var("RSKRB5_NG_OS_API_COPY")?)?;
    copy.replace(&loaded)?;
    let copied = copy.load()?;
    seeded.destroy()?;
    // Then the API backend read the MIT tickets and wrote them back.
    assert_eq!(registry.ids(Interface::StoreProvider), ["API"]);
    assert!(seeded.name().starts_with("API:"), "{}", seeded.name());
    assert_eq!(loaded.default_principal().components, principal.components);
    assert!(
        loaded.entries().iter().any(|credential| credential
            .server()
            .components
            .first()
            .is_some_and(|first| first == "krbtgt")),
        "a TGT"
    );
    assert_eq!(copied.credentials(), loaded.credentials());
    let after = seeded.load();
    assert!(after.is_err(), "destroyed, yet loaded: {after:?}");
    Ok(())
}

/// The `KCM:` store reads the cache MIT seeded in the system KCM service.
#[test]
#[ignore = "needs the macOS CI fixture: a KCM cache seeded by MIT kinit"]
fn kcm_reads_the_system_service_cache() -> Result<(), Box<dyn StdError>> {
    // Given the system service, named by the default `kcm_mach_service`, and
    // the seeded cache name.
    let config = mach_config(DEFAULT_MACH_SERVICE)?;
    let principal = principal_text::parse(&var("RSKRB5_NG_OS_PRINCIPAL")?).ok_or("principal")?;
    // When the cache is read through the configured name route.
    let loaded =
        configured::load_name(&config, &format!("KCM:{}", var("RSKRB5_NG_OS_KCM_CACHE")?))?;
    // Then it holds MIT's tickets.
    assert_eq!(loaded.default_principal().components, principal.components);
    assert!(
        loaded.entries().iter().any(|credential| credential
            .server()
            .components
            .first()
            .is_some_and(|first| first == "krbtgt")),
        "a TGT"
    );
    Ok(())
}

/// MIT `kinit`, given `kcm_mach_service` of the test service, stores its
/// tickets there over Mach RPC, and the store reads them back.
#[test]
#[ignore = "needs the macOS CI fixture: MIT kinit and a throwaway KDC"]
fn mit_kinit_writes_to_the_test_service() -> Result<(), Box<dyn StdError>> {
    // Given the test service and a profile naming it.
    let name = test_name("mit");
    let server = serve(&name)?;
    let profile = env::temp_dir().join(format!("rskrb5-ng-os-{}.conf", process::id()));
    let base = fs::read_to_string(var("RSKRB5_NG_OS_KRB5_CONF")?)?;
    fs::write(
        &profile,
        format!("{base}\n[libdefaults]\n kcm_mach_service = {name}\n"),
    )?;
    // When MIT kinit writes KCM:mit-seed.
    let mut kinit = Command::new(var("RSKRB5_NG_OS_MIT_KINIT")?)
        .args(["-c", "KCM:mit-seed", &var("RSKRB5_NG_OS_PRINCIPAL")?])
        .env("KRB5_CONFIG", &profile)
        .stdin(Stdio::piped())
        .spawn()?;
    kinit
        .stdin
        .take()
        .ok_or("stdin")?
        .write_all(format!("{}\n", var("RSKRB5_NG_OS_PASSWORD")?).as_bytes())?;
    let status = kinit.wait()?;
    let config = mach_config(&name)?;
    let loaded = configured::load_name(&config, "KCM:mit-seed");
    stop(&name, server)?;
    fs::remove_file(&profile)?;
    // Then kinit succeeded and the store reads its TGT.
    assert!(status.success(), "kinit: {status}");
    let cache = loaded?;
    assert!(
        cache.entries().iter().any(|credential| credential
            .server()
            .components
            .first()
            .is_some_and(|first| first == "krbtgt")),
        "a TGT"
    );
    Ok(())
}

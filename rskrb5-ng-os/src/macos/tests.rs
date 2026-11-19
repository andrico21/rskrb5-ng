//! The macOS stores against real services.
//!
//! An in-process KCM service under a test Mach name is always used. The CI
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
use core::error::Error as StdError;
use std::{
    env, fs,
    io::Write as _,
    process::{self, Command, Stdio},
    thread,
};

use rskrb5_ng::{
    ccache::{
        CCache, Credential, CredentialTimes, EncryptionKey, Principal, file_store,
        stores::{CacheVersion, CredentialStore as _},
    },
    config::{Config, ParseMode},
    error::Ccache as Error,
    extensions::{Interface, Registry},
};

use super::{
    ApiStore, DEFAULT_KCM_MACH_SERVICE, KcmMachStore,
    mach::{Mach, Service},
};
use crate::{
    Secret, error::Platform, kcm_fixture::Fixture, kcm_store::Exchange as _, principal_text,
    register,
};

/// The request that stops the test service.
const STOP: [u8; 4] = [2, 0, 0xff, 0xff];

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
    let _reply = Mach::new(name.to_owned()).call(&STOP)?;
    server.join().map_err(|_panic| "server panicked")??;
    Ok(())
}

/// A test service name unique to this process.
fn test_name(label: &str) -> String {
    format!("org.rskrb5-ng.test.kcm.{}.{label}", process::id())
}

/// The KCM store reads and writes through Mach RPC to a service checked in
/// under a test name, set through `kcm_mach_service`.
#[test]
fn kcm_over_mach_round_trip() -> Result<(), Box<dyn StdError>> {
    // Given the in-memory KCM server under a test Mach name, configured.
    let name = test_name("roundtrip");
    let server = serve(&name)?;
    let text = format!("[libdefaults]\n kcm_mach_service = {name}\n");
    let config = Config::parse_with_mode(&text, ParseMode::Compatible)?;
    let store = KcmMachStore::from_libdefaults(&config.libdefaults);
    // When a cache is initialized, filled, read, trimmed and destroyed.
    let alice = Principal::new("EXAMPLE.ORG", 1, vec!["alice".to_owned()]);
    let cache = store.resolve("")?;
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
    let removed = cache.remove(ticket.server())?;
    cache.destroy()?;
    let gone = cache.load();
    stop(&name, server)?;
    // Then the KCM backend answered every step, out-of-line bodies included.
    assert_eq!(store.cache_type(), "KCM");
    assert_eq!(cache.name(), "KCM:fixture");
    assert_eq!(loaded.default_principal(), &alice);
    assert_eq!(loaded.credentials(), [ticket]);
    assert_eq!(removed, 1);
    assert!(
        matches!(gone, Err(Error::CacheNotFound { name: _ })),
        "destroyed"
    );
    Ok(())
}

/// `-` disables Mach RPC; an unregistered name has no server.
#[test]
fn kcm_mach_disabled_and_absent() -> Result<(), Box<dyn StdError>> {
    // Given a disabled store and one naming an unregistered service.
    let disabled = KcmMachStore::new("-").resolve("");
    let absent = KcmMachStore::new(&test_name("absent")).resolve("");
    // When they are used.
    // Then the failures name the reason.
    for (result, expected) in [
        (disabled, Platform::MachDisabled),
        (absent, Platform::NoServer { code: 1102_i32 }),
    ] {
        let error = result.err().ok_or("no error")?;
        let platform = if let Error::Io(io) = &error {
            io.get_ref()
                .and_then(|inner| inner.downcast_ref::<Platform>())
                .copied()
        } else {
            None
        };
        assert_eq!(platform, Some(expected), "{error}");
    }
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
    // Given the system service and the seeded cache name.
    let store = KcmMachStore::new(DEFAULT_KCM_MACH_SERVICE);
    let principal = principal_text::parse(&var("RSKRB5_NG_OS_PRINCIPAL")?).ok_or("principal")?;
    // When the cache is read.
    let loaded = store.resolve(&var("RSKRB5_NG_OS_KCM_CACHE")?)?.load()?;
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
    let loaded = KcmMachStore::new(&name).resolve("mit-seed")?.load();
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

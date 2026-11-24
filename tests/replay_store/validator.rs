//! The service acceptor on a replay store.

use alloc::sync::Arc;
use core::time::Duration;
use std::{io::ErrorKind, path::PathBuf, time::UNIX_EPOCH};

use rskrb5_ng::{
    error::{Replay, Service as Error},
    keytab::Keytab,
    replay::{File2ReplayStore, MemoryReplayStore, NoneReplayStore, Store},
    service::Validator,
};

use super::support::{Fault, MemoryFs, TempDir};
use crate::context::{Context as _, TestError};

/// The gokrb5 service keytab of `tests/service.rs`.
const HTTP_KEYTAB: &str = concat!(
    "0502000000440002000b544553542e474f4b5242350004485454500010686f73742e746573742e676f6b",
    "72623500000001590dc4dc010011001057a7754c70c4d85c155c718c2f1292b0000000540002000b",
    "544553542e474f4b5242350004485454500010686f73742e746573742e676f6b72623500000001590d",
    "c4dc01001200209cad00bbc72d703258e911dc18e6d5487cf737bf67fd111f0c2463ad6033bf51",
    "000000440002000b544553542e474f4b5242350004485454500010686f73742e746573742e676f6b",
    "72623500000001590dc4dc020011001057a7754c70c4d85c155c718c2f1292b0000000540002000b",
    "544553542e474f4b5242350004485454500010686f73742e746573742e676f6b72623500000001590d",
    "c4dc02001200209cad00bbc72d703258e911dc18e6d5487cf737bf67fd111f0c2463ad6033bf51",
);

/// The gokrb5 AP-REQ fixture, valid at [`NOW`].
const AP_REQ: &[u8] = include_bytes!("../fixtures/valid_ap_req.der");

/// The validation time of the fixture.
const NOW: u64 = 1_893_553_447;

/// The keytab of the fixture service.
fn keytab() -> Result<Keytab, TestError> {
    Keytab::parse(&hex::decode(HTTP_KEYTAB)?).context("keytab parses")
}

/// A validator fixed at [`NOW`] that records in `store`.
fn validator_on(keytab: &Keytab, store: Arc<dyn Store>) -> Result<Validator<'_>, TestError> {
    let now = UNIX_EPOCH
        .checked_add(Duration::from_secs(NOW))
        .context("time is representable")?;
    Validator::new(keytab)
        .with_now(now)
        .with_replay_store(store)
        .context("the store covers the default skew")
}

/// Pins that two validators, standing for two processes, share one file: the second refuses the replay.
#[test]
fn a_second_validator_on_the_same_file_refuses_the_replay() -> Result<(), TestError> {
    let keytab = keytab()?;
    let directory = TempDir::new("validator")?;
    let path = directory.path().join("service.rcache2");
    let mut first = validator_on(&keytab, Arc::new(File2ReplayStore::new(path.clone())))?;
    let mut second = validator_on(&keytab, Arc::new(File2ReplayStore::new(path)))?;

    let accepted = first
        .validate_ap_req(AP_REQ)
        .context("the first presentation is accepted")?;
    let refused = second.validate_ap_req(AP_REQ);

    assert_eq!(accepted.client().name(), "testuser1");
    assert!(matches!(refused, Err(Error::Replay)), "{refused:?}");
    Ok(())
}

/// Pins that a store that cannot be read refuses the AP-REQ instead of accepting it.
#[test]
fn a_store_failure_refuses_the_ap_req() -> Result<(), TestError> {
    let keytab = keytab()?;
    let files = MemoryFs::default();
    let store =
        File2ReplayStore::new(PathBuf::from("memory")).with_file_system(Arc::new(files.clone()));
    let mut validator = validator_on(&keytab, Arc::new(store))?;
    files.inject(Fault::Open(ErrorKind::PermissionDenied))?;

    let outcome = validator.validate_ap_req(AP_REQ);

    assert!(
        matches!(
            outcome,
            Err(Error::ReplayStore(Replay::Io {
                operation: "open",
                path: _,
                source: _
            }))
        ),
        "{outcome:?}"
    );
    Ok(())
}

/// Pins that the memory store shared by two validators detects the replay, and `none` accepts it.
#[test]
fn memory_stops_a_replay_and_none_is_a_deliberate_opt_out() -> Result<(), TestError> {
    let keytab = keytab()?;
    let memory: Arc<dyn Store> = Arc::new(MemoryReplayStore::new());
    let mut first = validator_on(&keytab, Arc::clone(&memory))?;
    let mut second = validator_on(&keytab, memory)?;
    let accepted = first.validate_ap_req(AP_REQ).context("accepted once")?;
    assert_eq!(accepted.client().name(), "testuser1");
    assert!(matches!(second.validate_ap_req(AP_REQ), Err(Error::Replay)));

    let mut open = validator_on(&keytab, Arc::new(NoneReplayStore::opt_out()))?;
    let once = open.validate_ap_req(AP_REQ).context("none accepts")?;
    let twice = open.validate_ap_req(AP_REQ).context("none accepts again")?;
    assert_eq!(once.client().name(), twice.client().name());
    Ok(())
}

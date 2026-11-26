//! The tickets an IAKERB initiator acquired, written to a cache the caller
//! names (MIT's `out_ccache`, `iakerb.c:484-487`).

use std::{
    env, fs, process,
    time::{SystemTime, UNIX_EPOCH},
};

use rskrb5_ng::{
    ccache::CCache,
    error::{Gss, Iakerb},
    gss::CredStore,
};

use super::{
    context::TestError,
    kdc::Kdc,
    seal::{REALM, USER},
    support::{HOST, establish_ends, password_credential},
};

/// The acquired TGT and service ticket go to the named cache only; a failed
/// write is an error that leaves the context established, and a cache that
/// holds tickets is replaced only with `overwrite`.
#[test]
fn iakerb_updates_explicit_output_cache() -> Result<(), TestError> {
    let directory = env::temp_dir().join(format!(
        "iakerb-out-{}-{}",
        process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    fs::create_dir_all(&directory)?;
    let path = directory.join("acquired.ccache");
    let store = CredStore::new().with("ccache", &format!("FILE:{}", path.display()))?;
    // Given an initiator that acquired its tickets through the relay,
    let ends = establish_ends(&password_credential(true)?, &Kdc::new())?;
    assert!(!path.exists(), "nothing is written without the call");
    // when it stores them into the named cache,
    ends.initiator.store_acquired_into(&store, false)?;
    // then the cache holds the client's TGT and service ticket,
    let loaded = CCache::load(&path)?;
    assert_eq!(loaded.client_name(), USER);
    assert!(loaded.contains_server(&["krbtgt", REALM]));
    assert!(loaded.contains_server(&["HTTP", HOST]));
    // and a second store without overwrite is refused, with overwrite allowed,
    let again = ends.initiator.store_acquired_into(&store, false);
    assert!(
        matches!(
            again,
            Err(Iakerb::Gss(Gss::DuplicateElement))
        ),
        "{again:?}"
    );
    ends.initiator.store_acquired_into(&store, true)?;
    // and a write that fails is an error that leaves the context established.
    let unwritable = directory.join("absent").join("acquired.ccache");
    let elsewhere = CredStore::new().with("ccache", &format!("FILE:{}", unwritable.display()))?;
    assert!(
        ends.initiator
            .store_acquired_into(&elsewhere, false)
            .is_err()
    );
    assert!(ends.initiator.is_established());
    let mut context = ends.initiator.into_established()?;
    let mut acceptor = ends.acceptor;
    let sealed = context.wrap(b"still open", true)?;
    assert_eq!(acceptor.unwrap(&sealed)?.message(), b"still open");
    fs::remove_dir_all(&directory)?;
    Ok(())
}

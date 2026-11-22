//! Credential delegation (RFC 4121 section 4.1.1.1): the initiator forwards its
//! TGT in a KRB-CRED inside the authenticator checksum, the acceptor imports it
//! (MIT `init_sec_context.c:240-336,537-586`, `accept_sec_context.c:161-237,555-579`).
//!
//! `enforce_ok_as_delegate` turns a delegation request into the delegation
//! policy flag: the TGT is forwarded only when the service ticket carries
//! `OK-AS-DELEGATE`. A TGT that is not forwardable is not delegated, and the
//! context completes without the delegation flag, as MIT does.

use std::{
    env, fs, process,
    time::{SystemTime, UNIX_EPOCH},
};

use rskrb5_ng::{
    ccache::CCache,
    gss::{AcceptorOptions, ContextFlags, CredStore, Credential, InitiatorOptions},
};

use super::{
    context::{Context as _, TestError},
    support::{FORWARDABLE, HOST, OK_AS_DELEGATE, Pair, cache, cached, establish, tgt, ticket_for},
};

/// A context whose initiator holds a TGT with `tgt_flags` and a service ticket
/// with `ticket_flags`, asking for `flags`.
fn delegate(
    tgt_flags: &[usize],
    ticket_flags: &[usize],
    options: InitiatorOptions,
) -> Result<Pair, TestError> {
    let credential = Credential::from_ccache(cache(vec![
        tgt(tgt_flags)?,
        cached(&ticket_for(HOST, ticket_flags)?)?,
    ]))?;
    establish(
        &credential,
        options,
        (AcceptorOptions::new(), &[HOST], None),
    )
}

/// The default flags plus `extra`.
fn asking(extra: ContextFlags) -> InitiatorOptions {
    InitiatorOptions::new().with_flags(InitiatorOptions::new().flags() | extra)
}

/// A forwardable TGT is delegated and the acceptor holds it.
#[test]
fn a_forwardable_tgt_is_delegated() -> Result<(), TestError> {
    // Given a forwardable TGT and an initiator asking for delegation,
    let pair = delegate(&[FORWARDABLE], &[], asking(ContextFlags::DELEG))?;
    // then both ends report delegation and the acceptor holds the client's TGT.
    assert!(
        pair.initiator
            .inquire()
            .flags()
            .contains(ContextFlags::DELEG)
    );
    assert!(
        pair.acceptor
            .inquire()
            .flags()
            .contains(ContextFlags::DELEG)
    );
    let delegated = pair
        .acceptor
        .delegated_credential()
        .context("a delegated credential")?;
    let cache = delegated.ccache().context("the delegated cache")?;
    let entry = cache.credentials().first().context("the forwarded TGT")?;
    assert_eq!(entry.server().components, ["krbtgt", "EXAMPLE.COM"]);
    assert_eq!(entry.client().components, ["alice"]);
    assert_eq!(entry.key().value().as_slice(), [0x6d; 32]);
    assert_eq!(
        delegated.inquire().name().context("a name")?.display().0,
        "alice@EXAMPLE.COM"
    );
    Ok(())
}

/// A TGT that is not forwardable is not delegated; the context completes.
#[test]
fn a_tgt_that_is_not_forwardable_is_not_delegated() -> Result<(), TestError> {
    // Given a TGT without FORWARDABLE and an initiator asking for delegation,
    let pair = delegate(&[], &[], asking(ContextFlags::DELEG))?;
    // then the context completes without delegation.
    assert!(
        !pair
            .initiator
            .inquire()
            .flags()
            .contains(ContextFlags::DELEG)
    );
    assert!(
        !pair
            .acceptor
            .inquire()
            .flags()
            .contains(ContextFlags::DELEG)
    );
    assert!(pair.acceptor.delegated_credential().is_none());
    Ok(())
}

/// The delegation policy flag, and `enforce_ok_as_delegate`, delegate only to
/// services whose ticket carries OK-AS-DELEGATE.
#[test]
fn delegation_policy_follows_ok_as_delegate() -> Result<(), TestError> {
    for options in [
        asking(ContextFlags::DELEG_POLICY),
        asking(ContextFlags::DELEG).with_enforce_ok_as_delegate(true),
    ] {
        // Given a service ticket without OK-AS-DELEGATE, nothing is delegated.
        let plain = delegate(&[FORWARDABLE], &[], options.clone())?;
        assert!(plain.acceptor.delegated_credential().is_none());
        assert!(
            !plain
                .initiator
                .inquire()
                .flags()
                .contains(ContextFlags::DELEG)
        );
        // Given a service ticket with OK-AS-DELEGATE, the TGT is delegated.
        let trusted = delegate(&[FORWARDABLE], &[OK_AS_DELEGATE], options)?;
        assert!(trusted.acceptor.delegated_credential().is_some());
        assert!(
            trusted
                .initiator
                .inquire()
                .flags()
                .contains(ContextFlags::DELEG | ContextFlags::DELEG_POLICY)
        );
    }
    // Without the policy, an OK-AS-DELEGATE-less ticket still gets the TGT.
    let open = delegate(&[FORWARDABLE], &[], asking(ContextFlags::DELEG))?;
    assert!(open.acceptor.delegated_credential().is_some());
    Ok(())
}

/// A delegated credential stores into a file cache that loads back.
#[test]
fn a_delegated_credential_stores_into_a_cache() -> Result<(), TestError> {
    let pair = delegate(&[FORWARDABLE], &[], asking(ContextFlags::DELEG))?;
    let delegated = pair
        .acceptor
        .delegated_credential()
        .context("a delegated credential")?;
    let directory = env::temp_dir().join(format!(
        "gss-delegated-{}-{}",
        process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    fs::create_dir_all(&directory)?;
    let path = directory.join("delegated.ccache");
    let store = CredStore::new().with("ccache", &format!("FILE:{}", path.display()))?;
    // Given the delegated credential, when it is stored,
    delegated.store_cred_into(&store, false)?;
    // then the file holds the client's TGT,
    let loaded = CCache::load(&path)?;
    assert_eq!(loaded.client_name(), "alice");
    assert!(loaded.contains_server(&["krbtgt", "EXAMPLE.COM"]));
    // and a second store without overwrite is refused, with overwrite it is allowed.
    assert!(delegated.store_cred_into(&store, false).is_err());
    delegated.store_cred_into(&store, true)?;
    fs::remove_dir_all(&directory)?;
    Ok(())
}

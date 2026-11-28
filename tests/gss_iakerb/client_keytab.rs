//! An initiator credential of a client keytab: IAKERB starts its AS exchange
//! from the keytab's key (MIT `iakerb_get_initial_state`, `iakerb.c:713-772`).

use std::{
    env, fs, process,
    time::{SystemTime, UNIX_EPOCH},
};

use rskrb5_ng::{
    gss::{CredStore, Credential, CredentialUsage, Name, NameType},
    keytab::{self, Keytab},
};

use super::{
    context::TestError,
    kdc::Kdc,
    seal::{REALM, USER, user_key},
    support::establish,
};

/// A fresh scratch directory named after `label`.
fn scratch(label: &str) -> Result<std::path::PathBuf, TestError> {
    let directory = env::temp_dir().join(format!(
        "iakerb-{label}-{}-{}",
        process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    fs::create_dir_all(&directory)?;
    Ok(directory)
}

/// The initiator credential of a client keytab, written under `label`, that
/// holds the user's key; the directory goes with the returned path.
pub(super) fn keytab_credential(
    label: &str,
) -> Result<(Credential, std::path::PathBuf), TestError> {
    let directory = scratch(label)?;
    let path = directory.join("client.keytab");
    let mut keys = Keytab::new();
    keys.entries_mut().push(keytab::Entry::new(
        keytab::Principal::new(REALM, 1, [USER]),
        0,
        1,
        user_key()?,
        1,
    ));
    keys.save(&path)?;
    let name = Name::import(format!("{USER}@{REALM}").as_bytes(), NameType::User)?;
    let store = CredStore::new().with("client_keytab", &format!("FILE:{}", path.display()))?;
    let credential = Credential::acquire_cred_from(Some(&name), CredentialUsage::Initiate, &store)?;
    Ok((credential, directory))
}

/// A client keytab, and no password, acquires the TGT through the relay: the
/// AS exchange answers the preauthentication probe with the keytab's key.
#[test]
fn iakerb_acquires_from_a_client_keytab() -> Result<(), TestError> {
    // Given an initiator credential of a client keytab with the user's key,
    let (credential, directory) = keytab_credential("client-keytab")?;
    assert!(credential.keytab().is_none() && credential.ccache().is_none());
    let kdc = Kdc::new();
    // when a context is established through the relay,
    let pair = establish(&credential, &kdc)?;
    // then the relay carried the probe, the preauthenticated AS-REQ and the
    // TGS-REQ, and the acceptor sees the keytab's client.
    let kinds: Vec<&str> = kdc.log().iter().map(|(_realm, kind)| *kind).collect();
    assert_eq!(kinds, ["AS", "AS", "TGS"]);
    assert_eq!(pair.relayed.len(), 3);
    let inquiry = pair.acceptor.inquire();
    let source = inquiry.source().principal();
    assert_eq!(
        (source.realm.as_str(), source.components.as_slice()),
        (REALM, [USER.to_owned()].as_slice())
    );
    fs::remove_dir_all(&directory)?;
    Ok(())
}

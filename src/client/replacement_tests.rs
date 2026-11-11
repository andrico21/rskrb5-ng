//! Live-byte observations for replacement within a retained client owner.

#[cfg(feature = "tokio")]
use core::time::Duration;
use core::{cell::RefCell, error::Error};
use std::time::UNIX_EPOCH;

#[cfg(feature = "tokio")]
#[path = "replacement_login_tests.rs"]
mod login;

use super::{AsRepSession, BuiltApReq, KdcError, TgsFastRequestParts, principal::Principal};
#[cfg(feature = "spnego")]
use crate::spnego::InitiatorContextOptions;
use crate::{
    ccache, kadmin, keytab,
    keytab::{EncryptionKey, key_bytes::EVENTS as KEY_EVENTS},
    krb_priv, ticket,
};

std::thread_local! {
    static EVENTS: RefCell<Vec<(usize, bool)>> = const { RefCell::new(Vec::new()) };
}

pub(super) fn observe(bytes: &[u8]) {
    EVENTS
        .with_borrow_mut(|events| events.push((bytes.len(), bytes.iter().all(|byte| *byte == 0))));
}

/// Session and error setters wipe the original live allocations before assignment.
#[test]
fn session_and_error_replacements_erase_old_bytes() -> Result<(), Box<dyn Error>> {
    let key = EncryptionKey::new(17, hex::decode("4142434445464748494a4b4c4d4e4f50")?);
    let mut session = AsRepSession::new(
        Principal::user("EXAMPLE.COM", "alice"),
        Principal::tgt_service("EXAMPLE.COM"),
        key.clone(),
        vec![0x52; 17].into(),
        [0; 4],
        UNIX_EPOCH,
        UNIX_EPOCH,
    );
    let mut error = KdcError::new(UNIX_EPOCH, 0, 25, Principal::tgt_service("EXAMPLE.COM"))
        .with_e_data(Some(vec![0x63; 18].into()));
    EVENTS.with_borrow_mut(Vec::clear);
    KEY_EVENTS.with_borrow_mut(Vec::clear);
    session.set_ticket(vec![0x74; 19].into());
    session.set_session_key(key);
    error.set_e_data(None);
    EVENTS.with_borrow(|events| assert_eq!(events.as_slice(), [(17, true), (18, true)]));
    KEY_EVENTS.with_borrow(|events| assert_eq!(events.as_slice(), [(16, true)]));
    Ok(())
}

/// Admission replaces an expired service key and erases its live allocation.
#[cfg(feature = "tokio")]
#[test]
fn client_cache_insertion_erases_live_key_owner() -> Result<(), Box<dyn Error>> {
    let frame = kadmin::Request::parse(&hex::decode(
        include_str!("../../tests/fixtures/kpasswd-request.hex").trim(),
    )?)?;
    let principal = Principal::user("TEST.GOKRB5", "alice");
    let service = Principal::new("TEST.GOKRB5", 2, ["kadmin", "changepw"]);
    let old = AsRepSession::new(
        principal.clone(),
        service.clone(),
        EncryptionKey::new(18, vec![0x41; 32]),
        ticket::encode(&frame.ap_req().ticket)?.into(),
        [0; 4],
        UNIX_EPOCH,
        UNIX_EPOCH,
    );
    let new = AsRepSession::new(
        principal.clone(),
        service.clone(),
        EncryptionKey::new(18, vec![0x52; 32]),
        ticket::encode(&frame.ap_req().ticket)?.into(),
        [0; 4],
        UNIX_EPOCH,
        UNIX_EPOCH + Duration::from_secs(4_000_000_000),
    );
    let mut client = super::Tokio::new(
        crate::Config::new(),
        super::transport::KdcProtocol::Tcp,
        principal,
        None,
    );
    drop(
        client
            .service_tickets
            .insert(super::service_cache_key(&service), old),
    );
    KEY_EVENTS.with_borrow_mut(Vec::clear);
    client.cache_service_ticket(new)?;
    KEY_EVENTS.with_borrow(|events| assert_eq!(events.as_slice(), [(32, true)]));
    assert_eq!(
        client
            .cached_service_ticket(service)
            .ok_or("cached replacement")?
            .session_key()
            .value()
            .as_ref(),
        &[0x52; 32]
    );
    Ok(())
}

/// Built AP and FAST setters erase old frame and key allocations independently.
#[test]
fn built_request_replacements_erase_old_bytes() -> Result<(), Box<dyn Error>> {
    let frame = kadmin::Request::parse(&hex::decode(
        include_str!("../../tests/fixtures/kpasswd-request.hex").trim(),
    )?)?;
    let key = EncryptionKey::new(17, vec![0x41; 16]);
    let mut built = BuiltApReq {
        message: frame.ap_req().clone(),
        der: vec![0x52; 17].into(),
        client: Principal::user("EXAMPLE.COM", "alice"),
        service: Principal::tgt_service("EXAMPLE.COM"),
        session_key: key.clone(),
        subkey: Some(key.clone()),
        authenticator_ctime: UNIX_EPOCH,
        authenticator_cusec: 0,
        authenticator_time: UNIX_EPOCH,
        sequence_number: None,
    };
    let request = super::build_tgs_req_with_confounder(
        &AsRepSession::new(
            built.client.clone(),
            Principal::new("TEST.GOKRB5", 2, ["kadmin", "changepw"]),
            key.clone(),
            ticket::encode(&frame.ap_req().ticket)?.into(),
            [0; 4],
            UNIX_EPOCH,
            UNIX_EPOCH,
        ),
        built.service.clone(),
        super::options::TgsReq::new(UNIX_EPOCH, 42),
        UNIX_EPOCH,
        0,
        &[0; 16],
    )?;
    let mut fast = TgsFastRequestParts {
        request,
        ap_req_der: vec![0x63; 18].into(),
        authenticator_subkey: key.clone(),
    };
    EVENTS.with_borrow_mut(Vec::clear);
    KEY_EVENTS.with_borrow_mut(Vec::clear);
    built.set_der(vec![0x74; 19].into());
    built.set_session_key(key.clone());
    built.set_subkey(None);
    fast.set_ap_req_der(vec![0x85; 20].into());
    fast.set_authenticator_subkey(key);
    EVENTS.with_borrow(|events| assert_eq!(events.as_slice(), [(17, true), (18, true)]));
    KEY_EVENTS.with_borrow(|events| assert_eq!(events.as_slice(), [(16, true); 3]));
    Ok(())
}

/// Key-owner replacement through file entries and reply options erases live old bytes.
#[test]
fn nested_key_replacements_erase_old_bytes() -> Result<(), Box<dyn Error>> {
    let bytes = hex::decode("4142434445464748494a4b4c4d4e4f50")?;
    let entry = keytab::Entry::new(
        keytab::Principal::new("EXAMPLE.COM", 1, ["alice"]),
        1,
        1,
        EncryptionKey::new(17, bytes.clone()),
        1,
    );
    let credential = ccache::Credential::new(
        ccache::Principal::new("EXAMPLE.COM", 1, vec!["alice".to_owned()]),
        ccache::Principal::new(
            "EXAMPLE.COM",
            2,
            vec!["krbtgt".to_owned(), "EXAMPLE.COM".to_owned()],
        ),
        ccache::EncryptionKey::new(17, bytes.clone()),
        ccache::CredentialTimes::default(),
        [0; 4],
        vec![0x52; 16].into(),
    );
    let options =
        super::options::ApReq::new().with_subkey(Some(EncryptionKey::new(17, bytes.clone())));
    #[cfg(feature = "spnego")]
    let context =
        InitiatorContextOptions::new().with_subkey(Some(EncryptionKey::new(17, bytes.clone())));
    KEY_EVENTS.with_borrow_mut(Vec::clear);
    let entry_retained = entry.set_key(EncryptionKey::new(17, bytes.clone()));
    let credential_retained = credential.set_key(ccache::EncryptionKey::new(17, bytes));
    let retained = options.with_subkey(None);
    #[cfg(feature = "spnego")]
    let context_retained = context.with_subkey(None);
    KEY_EVENTS.with_borrow(|events| {
        assert_eq!(
            events.as_slice(),
            [(16, true); if cfg!(feature = "spnego") { 4 } else { 3 }]
        );
    });
    drop(retained);
    drop(entry_retained);
    drop(credential_retained);
    #[cfg(feature = "spnego")]
    drop(context_retained);
    Ok(())
}

/// A retained password request erases its previous reply key before replacement.
#[test]
fn password_key_replacements_erase_old_bytes() -> Result<(), Box<dyn Error>> {
    let frame = kadmin::Request::parse(&hex::decode(
        include_str!("../../tests/fixtures/kpasswd-request.hex").trim(),
    )?)?;
    let session = AsRepSession::new(
        Principal::user("TEST.GOKRB5", "alice"),
        Principal::new("TEST.GOKRB5", 2, ["kadmin", "changepw"]),
        EncryptionKey::new(17, vec![0x41; 16]),
        ticket::encode(&frame.ap_req().ticket)?.into(),
        [0; 4],
        UNIX_EPOCH,
        UNIX_EPOCH,
    );
    let options = super::kpasswd::RequestOptions::new(
        UNIX_EPOCH,
        0,
        42,
        krb_priv::ipv4_host_address([127, 0, 0, 1]),
    );
    let mut built = super::kpasswd::build_kpasswd_request_with_confounders(
        &session,
        &kadmin::ChangePasswdData::new(super::Password::from_vec(vec![0x52; 16])),
        EncryptionKey::new(17, vec![0x63; 16]),
        &options,
        &[0; 16],
        &[0; 16],
    )?;
    KEY_EVENTS.with_borrow_mut(Vec::clear);
    built.set_reply_key(EncryptionKey::new(17, vec![0x74; 16]));
    KEY_EVENTS.with_borrow(|events| assert_eq!(events.as_slice(), [(16, true)]));
    Ok(())
}

/// Cache clearing and destruction drop retained session-key owners immediately.
#[cfg(feature = "tokio")]
#[test]
fn client_cache_clear_erases_live_key_owners() -> Result<(), Box<dyn Error>> {
    let session = AsRepSession::new(
        Principal::user("EXAMPLE.COM", "alice"),
        Principal::tgt_service("EXAMPLE.COM"),
        EncryptionKey::new(17, hex::decode("4142434445464748494a4b4c4d4e4f50")?),
        vec![0x52; 16].into(),
        [0; 4],
        UNIX_EPOCH,
        UNIX_EPOCH,
    );
    let mut client = super::Tokio::new(
        crate::Config::new(),
        super::transport::KdcProtocol::Tcp,
        session.client.clone(),
        None,
    );
    drop(client.service_tickets.insert(
        ("EXAMPLE.COM".to_owned(), vec!["service".to_owned()]),
        session.clone(),
    ));
    KEY_EVENTS.with_borrow_mut(Vec::clear);
    client.clear_service_ticket_cache();
    KEY_EVENTS.with_borrow(|events| assert_eq!(events.as_slice(), [(16, true)]));
    drop(client.service_tickets.insert(
        ("EXAMPLE.COM".to_owned(), vec!["service".to_owned()]),
        session,
    ));
    KEY_EVENTS.with_borrow_mut(Vec::clear);
    client.destroy();
    KEY_EVENTS.with_borrow(|events| assert_eq!(events.as_slice(), [(16, true)]));
    Ok(())
}

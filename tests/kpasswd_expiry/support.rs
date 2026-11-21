//! Fixed sessions and requests: a client that already holds a `kadmin/changepw` ticket.

use core::time::Duration;
use std::{
    sync::{Mutex, MutexGuard, PoisonError},
    time::{SystemTime, UNIX_EPOCH},
};

use rskrb5_ng::{
    client::{
        AsRepSession, Password, TgsRepSession,
        kpasswd::{BuiltKpasswdRequest, RequestOptions, build_kpasswd_request_with_confounders},
        principal::Principal,
    },
    kadmin::{ChangePasswdData, Request},
    keytab::EncryptionKey,
    krb_priv::ipv4_host_address,
    ticket,
};

use super::TestError;

/// The realm of every fixture.
pub(super) const REALM: &str = "TEST.GOKRB5";

/// The `kadmin/changepw` principal.
pub(super) fn changepw_principal() -> Principal {
    Principal::new(REALM, 2, ["kadmin", "changepw"])
}

/// The key a fake server shares with the client for the changepw session.
pub(super) fn changepw_key() -> EncryptionKey {
    EncryptionKey::new(18, vec![0x5a; 32])
}

/// A DER ticket body to stand in for the opaque `kadmin/changepw` ticket.
fn opaque_ticket() -> Result<Vec<u8>, TestError> {
    let fixture = Request::parse(&hex::decode(
        include_str!("../fixtures/kpasswd-request.hex").trim(),
    )?)?;
    Ok(ticket::encode(&fixture.ap_req().ticket)?)
}

/// An opaque ticket naming `service`, for a session whose ticket the client never opens.
pub(super) fn ticket_for(service: &[&str]) -> Result<rasn_kerberos::Ticket, TestError> {
    let mut wire = ticket::decode(&opaque_ticket()?)?;
    wire.realm = rasn_kerberos::Realm::try_from(REALM.to_owned())?;
    wire.sname = rasn_kerberos::PrincipalName {
        r#type: 2,
        string: service
            .iter()
            .map(|part| rasn_kerberos::KerberosString::try_from((*part).to_owned()))
            .collect::<Result<_, _>>()?,
    };
    Ok(wire)
}

/// A TGT of `client`, valid for an hour from now.
pub(super) fn tgt(client: &Principal) -> Result<AsRepSession, TestError> {
    let now = SystemTime::now();
    Ok(AsRepSession::new(
        client.clone(),
        Principal::tgt_service(REALM),
        EncryptionKey::new(18, vec![0x11; 32]),
        ticket::encode(&ticket_for(&["krbtgt", REALM])?)?.into(),
        [0; 4],
        now,
        now.checked_add(Duration::from_hours(1)).ok_or("end time")?,
    ))
}

/// A `kadmin/changepw` ticket of `client`, valid from a minute ago for an hour.
pub(super) fn changepw_ticket(client: &Principal) -> Result<TgsRepSession, TestError> {
    let now = SystemTime::now();
    let mut session = TgsRepSession::new(
        client.clone(),
        changepw_principal(),
        changepw_key(),
        ticket::encode(&ticket_for(&["kadmin", "changepw"])?)?.into(),
        [0; 4],
        now.checked_sub(Duration::from_mins(1))
            .ok_or("start time")?,
        now.checked_add(Duration::from_hours(1)).ok_or("end time")?,
    );
    session.set_start_time(
        now.checked_sub(Duration::from_mins(1))
            .ok_or("start time")?,
    );
    Ok(session)
}

/// The epoch, for fixed request metadata.
pub(super) fn epoch_plus(seconds: u64) -> Result<SystemTime, TestError> {
    Ok(UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .ok_or("time")?)
}

/// A built kpasswd request with known service and reply keys, and its options.
pub(super) fn built_request() -> Result<(BuiltKpasswdRequest, RequestOptions), TestError> {
    let time = epoch_plus(1_893_553_452)?;
    let session = changepw_ticket(&Principal::user(REALM, "testuser1"))?;
    let options = RequestOptions::new(time, 456_789, 42, ipv4_host_address([127, 0, 0, 1]))
        .with_recipient_address(ipv4_host_address([127, 0, 0, 2]));
    let built = build_kpasswd_request_with_confounders(
        &session,
        &ChangePasswdData::new(Password::copy_from_str("reflection-password-canary")),
        EncryptionKey::new(18, vec![0x22; 32]),
        &options,
        &[0x33; 16],
        &[0x44; 16],
    )?;
    Ok((built, options))
}

/// The value of a mutex, whether or not a panicking test poisoned it.
pub(super) fn held<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

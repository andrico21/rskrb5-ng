//! Unsigned rejection classification regressions.

use core::{error::Error as StdError, time::Duration};
use std::time::UNIX_EPOCH;

use rasn::types::Integer;

use super::{RequestOptions, build_kpasswd_request_with_confounders, validated_result};
use crate::{
    client::{Password, TgsRepSession, kerberos_time_from_system_time, principal::Principal},
    error::{Client, Kadmin},
    kadmin::{ChangePasswdData, Reply, Request},
    keytab::EncryptionKey,
    krb_error,
    krb_priv::ipv4_host_address,
    ticket,
};

/// Build an unsigned refusal in either accepted wire profile and classify it.
fn unsigned_rejection(framed: bool) -> Result<(), Box<dyn StdError>> {
    let fixture = Request::parse(&hex::decode(
        include_str!("../../../tests/fixtures/kpasswd-request.hex").trim(),
    )?)?;
    let time = UNIX_EPOCH
        .checked_add(Duration::from_secs(1_893_553_452))
        .ok_or("fixture time overflow")?;
    let session = TgsRepSession::new(
        Principal::user("TEST.GOKRB5", "testuser1"),
        Principal::new("TEST.GOKRB5", 2, ["kadmin", "changepw"]),
        EncryptionKey::new(18, vec![0x11; 32]),
        ticket::encode(&fixture.ap_req.ticket)?.into(),
        [0; 4],
        time,
        time,
    );
    let options = RequestOptions::new(time, 456_789, 42, ipv4_host_address([127, 0, 0, 1]));
    let built = build_kpasswd_request_with_confounders(
        &session,
        &ChangePasswdData::new(Password::copy_from_str("dummy-password")),
        EncryptionKey::new(18, vec![0x22; 32]),
        &options,
        &[0x33; 16],
        &[0x44; 16],
    )?;
    let error = rasn_kerberos::KrbError {
        pvno: Integer::from(5_i32),
        msg_type: Integer::from(30_i32),
        ctime: None,
        cusec: None,
        stime: kerberos_time_from_system_time(time)?,
        susec: Integer::from(0_i32),
        error_code: 60,
        crealm: None,
        cname: None,
        realm: fixture.ap_req.ticket.realm,
        sname: fixture.ap_req.ticket.sname,
        e_text: None,
        e_data: Some(b"\x00\x04policy refused\xff".to_vec().into()),
    };
    let bare = krb_error::encode(&error)?;
    let bytes = if framed {
        let mut frame = Vec::new();
        frame.extend_from_slice(
            &u16::try_from(bare.len().checked_add(6).ok_or("frame overflow")?)?.to_be_bytes(),
        );
        frame.extend_from_slice(&[0, 1, 0, 0]);
        frame.extend_from_slice(&bare);
        frame
    } else {
        bare
    };
    let reply = Reply::parse(&bytes)?;
    // When the checked validator consumes an unauthenticated nonzero result.
    let result = validated_result(&reply, &built, &options);
    // Then it cannot produce a definitive password-change result.
    assert!(matches!(
        result,
        Err(Client::Kadmin(Kadmin::UnauthenticatedRejection { code: 4, text_raw }))
            if text_raw == b"policy refused\xff"
    ));
    Ok(())
}

/// A standalone unsigned error cannot confirm rejection after delivery.
#[test]
fn bare_unsigned_rejection_is_not_definitive() -> Result<(), Box<dyn StdError>> {
    // Given a bare application-30 reply.
    unsigned_rejection(false)
}

/// Legacy framing does not authenticate a nonzero KRB-ERROR result.
#[test]
fn framed_unsigned_rejection_is_not_definitive() -> Result<(), Box<dyn StdError>> {
    // Given a framed application-30 reply.
    unsigned_rejection(true)
}

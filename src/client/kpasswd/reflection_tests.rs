//! Reflected password ciphertext regressions.

use core::{error::Error as StdError, time::Duration};
use std::time::UNIX_EPOCH;

use rasn::types::Integer;

use super::{RequestOptions, build_kpasswd_request_with_confounders, validated_result};
use crate::{
    ap_rep,
    client::{Password, TgsRepSession, kerberos_time_from_system_time, principal::Principal},
    error::Client,
    kadmin::{ChangePasswdData, Reply, Request},
    keytab::EncryptionKey,
    krb_priv::{encode, ipv4_host_address},
    ticket,
};

/// The shared validator rejects ciphertext before interpreting password bytes as a result.
fn reflected_reply(ap_rep_valid: bool) -> Result<Client, Box<dyn StdError>> {
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
        ticket::encode(&fixture.ap_req().ticket)?.into(),
        [0; 4],
        time,
        time,
    );
    let options = RequestOptions::new(time, 456_789, 42, ipv4_host_address([127, 0, 0, 1]));
    let built = build_kpasswd_request_with_confounders(
        &session,
        &ChangePasswdData::new(Password::copy_from_str("reflection-password-canary")),
        EncryptionKey::new(18, vec![0x22; 32]),
        &options,
        &[0x33; 16],
        &[0x44; 16],
    )?;
    let mut ap_rep = ap_rep::build_ap_rep_with_confounder(
        &rasn_kerberos::EncApRepPart {
            ctime: kerberos_time_from_system_time(time)?,
            cusec: Integer::from(options.cusec),
            subkey: None,
            seq_number: None,
        },
        &session.session_key,
        None,
        &[0x55; 16],
    )?;
    if !ap_rep_valid {
        ap_rep.enc_part.cipher = vec![0].into();
    }
    let mut reflected = built.request.krb_priv().clone();
    reflected.enc_part.kvno = Some(999);
    let mut frame = vec![0; 6];
    let encoded_ap_rep = ap_rep::encode(&ap_rep)?;
    frame.extend_from_slice(&encoded_ap_rep);
    frame.extend_from_slice(&encode(&reflected)?);
    let length = u16::try_from(frame.len())?;
    frame
        .get_mut(..2)
        .ok_or("frame length")?
        .copy_from_slice(&length.to_be_bytes());
    frame
        .get_mut(2..4)
        .ok_or("frame version")?
        .copy_from_slice(&1_u16.to_be_bytes());
    frame
        .get_mut(4..6)
        .ok_or("AP-REP length")?
        .copy_from_slice(&u16::try_from(encoded_ap_rep.len())?.to_be_bytes());
    let reply = Reply::parse(&frame)?;
    // When the same ciphertext is returned with altered unauthenticated metadata.
    let outcome = validated_result(&reply, &built, &options, &built.crypto_policy);
    // Then the ciphertext cannot reach result parsing, even with a genuine AP-REP.
    Ok(match outcome {
        Err(error) => error,
        Ok(result) => result
            .ensure_success()
            .err()
            .ok_or("reflection accepted")?
            .into(),
    })
}

/// A valid timestamp-only AP-REP cannot turn the request password into failure text.
#[test]
fn genuine_ap_rep_cannot_authorize_reflected_ciphertext() -> Result<(), Box<dyn StdError>> {
    // Given a genuine AP-REP with no server subkey or sequence number.
    let error = reflected_reply(true)?;
    assert!(matches!(
        error,
        Client::KpasswdReplyControl("reflected ciphertext")
    ));
    assert!(!format!("{error} {error:?}").contains("reflection-password-canary"));
    Ok(())
}

/// Reflection is rejected before attempting to decrypt an invalid AP-REP.
#[test]
fn dummy_ap_rep_cannot_hide_reflected_ciphertext() -> Result<(), Box<dyn StdError>> {
    // Given a dummy AP-REP and a changed outer KRB-PRIV kvno.
    let error = reflected_reply(false)?;
    assert!(matches!(
        error,
        Client::KpasswdReplyControl("reflected ciphertext")
    ));
    Ok(())
}

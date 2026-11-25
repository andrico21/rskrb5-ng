//! Reply rechecks of a validated AP-REQ whose retained fields change.
//!
//! The fields have no public mutators (FU-GSS-P01), so these checks live
//! beside the type.

use core::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use super::{ApRepOptions, Error, Principal, ValidatedApReq};
use crate::{
    crypto::{CryptoPolicy, Use},
    error::{Crypto, Policy},
    keytab::EncryptionKey,
};

/// The authenticator time of the fixture.
fn ctime() -> Result<SystemTime, Error> {
    UNIX_EPOCH
        .checked_add(Duration::from_secs(1_893_553_447))
        .ok_or(Error::TimeOverflow)
}

/// A validated AP-REQ with an AES256 session key and `cusec` microseconds.
fn validated(cusec: u32) -> Result<ValidatedApReq, Error> {
    let at = ctime()?;
    Ok(ValidatedApReq {
        crypto_policy: CryptoPolicy::default(),
        client: Principal::new("EXAMPLE.COM".to_owned(), 1, vec!["alice".to_owned()]),
        service: Principal::new(
            "EXAMPLE.COM".to_owned(),
            3,
            vec!["HTTP".to_owned(), "www.example.com".to_owned()],
        ),
        session_key: EncryptionKey::new(18, vec![0x5a; 32]),
        subkey: None,
        sequence_number: Some(42),
        ticket_start: at,
        ticket_end: at,
        authenticator_ctime: at,
        authenticator_cusec: cusec,
        authenticator_time: at
            .checked_add(Duration::from_micros(cusec.into()))
            .ok_or(Error::TimeOverflow)?,
        pac: None,
        auth_indicators: Vec::new(),
    })
}

/// AP-REP construction rechecks the retained microseconds before encoding.
#[test]
fn microseconds_rejects_invalid_reply_construction() -> Result<(), Error> {
    let mut context = validated(0)?;
    context.set_authenticator_cusec(1_000_000);
    assert!(matches!(
        context.build_ap_rep_with_confounder(&[0x22; 16], &ApRepOptions::default()),
        Err(Error::IntegerOutOfRange {
            field: "authenticator.cusec",
            value: _
        })
    ));
    Ok(())
}

/// Both legal microsecond boundaries round-trip in mutual replies.
#[test]
fn microseconds_reply_boundaries_roundtrip() -> Result<(), Error> {
    for value in [0_u32, 999_999] {
        let context = validated(value)?;
        let reply = context.build_ap_rep_with_confounder(&[0x22; 16], &ApRepOptions::default())?;
        assert_eq!(context.verify_ap_rep(&reply)?.cusec(), value);
    }
    Ok(())
}

/// AP-REP construction refuses a fractional retained time rather than echoing it.
#[test]
fn fractional_time_rejects_reply_construction() -> Result<(), Error> {
    let mut context = validated(0)?;
    context.set_authenticator_ctime(
        ctime()?
            .checked_add(Duration::from_millis(500))
            .ok_or(Error::TimeOverflow)?,
    );
    assert!(matches!(
        context.build_ap_rep_with_confounder(&[0x22; 16], &ApRepOptions::default()),
        Err(Error::FractionalKerberosTime)
    ));
    Ok(())
}

/// A replaced session key stays under the retained policy, for building and
/// verifying replies alike.
#[test]
fn replaced_session_keys_stay_under_the_retained_policy() -> Result<(), Error> {
    let context = validated(0)?;
    let reply = context.build_ap_rep_with_confounder(&[0x22; 16], &ApRepOptions::default())?;
    let mut changed = validated(0)?;
    changed.set_session_key(EncryptionKey::new(23, vec![0x43; 16]));
    assert!(matches!(
        changed.verify_ap_rep(&reply),
        Err(Error::Crypto(Crypto::Policy(Policy::EnctypeNotPermitted {
            etype: 23_i32,
            usage: Use::SessionKey
        })))
    ));
    assert!(matches!(
        changed.build_ap_rep_with_confounder(&[0x22; 8], &ApRepOptions::default()),
        Err(Error::Crypto(Crypto::Policy(_)))
    ));
    Ok(())
}

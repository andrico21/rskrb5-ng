//! Password and account expiry as the KDC reports it in `last-req` and `key-expiration`.
//!
//! MIT `get_in_tkt.c:1473-1504` (`get_expiry_times`): the last-req types 6 and -6 are
//! the password expiry and 7 and -7 the account expiry; when none is present the
//! ambiguous `key-expiration` field stands for the password.

use core::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use rskrb5_ng::{
    client::{
        AsRepSession, KdcTransport, Password,
        kpasswd::last_req::ExpiryNotice,
        options::AsReq,
        stepwise::{Answer, InitCreds, InitCredsOptions, Prompt, Responder, drive},
    },
    error::Client as Error,
    extensions::ProviderError,
};

use super::{
    TestError,
    realm::{ExpiryFields, Realm},
    support::held,
};

/// A transport that hands every request to the fake realm.
struct Kdc<'realm>(&'realm Realm);

impl KdcTransport for Kdc<'_> {
    fn send(&mut self, _realm: &str, request: &[u8]) -> Result<Vec<u8>, Error> {
        self.0
            .answer(request)
            .map_err(|cause| Error::Transport(cause.to_string()))
    }
}

/// A responder that records the password expiries it is told about.
#[derive(Default)]
struct Recording {
    /// The expiries, in order.
    expiries: Vec<SystemTime>,
}

impl Responder for Recording {
    fn respond(&mut self, prompt: &Prompt) -> Result<Answer, ProviderError> {
        Err(format!("unexpected {prompt:?}").into())
    }

    fn password_expiry(&mut self, expires: SystemTime) {
        self.expiries.push(expires);
    }
}

/// `seconds` after the epoch.
fn at(seconds: u64) -> Result<SystemTime, TestError> {
    Ok(UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .ok_or("time")?)
}

/// Log in with the account's password against a realm reporting `fields`: the finished
/// session and the password expiries the responder heard.
fn login(fields: ExpiryFields) -> Result<(AsRepSession, Vec<SystemTime>), TestError> {
    let realm = Realm::new(b"old-password", false);
    *held(&realm.expiry) = fields;
    let mut exchange = InitCreds::with_password(
        Realm::account(),
        Some(Password::copy_from_str("old-password")),
        InitCredsOptions::new(AsReq::new(SystemTime::now(), 0x1122_3344).with_etypes(vec![18_i32])),
    );
    let mut responder = Recording::default();
    let session = drive(&mut Kdc(&realm), &mut exchange, &mut responder)?;
    Ok((session, responder.expiries))
}

/// The password expiries the responder heard.
fn login_hearing(fields: ExpiryFields) -> Result<Vec<SystemTime>, TestError> {
    Ok(login(fields)?.1)
}

/// A last-req password expiry wins over the ambiguous `key-expiration`.
#[test]
fn the_responder_hears_the_last_req_password_expiry_before_key_expiration() -> Result<(), TestError>
{
    let heard = login_hearing(ExpiryFields {
        key_expiration: Some(at(2_000_000_000)?),
        last_req_password: Some(at(1_900_000_000)?),
        last_req_account: Some(at(2_100_000_000)?),
    })?;
    assert_eq!(heard, [at(1_900_000_000)?]);
    Ok(())
}

/// Without a last-req entry `key-expiration` is the password expiry.
#[test]
fn key_expiration_stands_for_the_password_without_last_req() -> Result<(), TestError> {
    let heard = login_hearing(ExpiryFields {
        key_expiration: Some(at(2_000_000_000)?),
        ..ExpiryFields::default()
    })?;
    assert_eq!(heard, [at(2_000_000_000)?]);
    Ok(())
}

/// A last-req account expiry alone is not a password expiry, even beside `key-expiration`.
#[test]
fn an_account_expiry_alone_is_not_heard_as_a_password_expiry() -> Result<(), TestError> {
    let heard = login_hearing(ExpiryFields {
        key_expiration: Some(at(2_000_000_000)?),
        last_req_account: Some(at(2_100_000_000)?),
        ..ExpiryFields::default()
    })?;
    assert_eq!(heard, []);
    Ok(())
}

/// The session carries what the reply said, and where it came from.
#[test]
fn the_session_reports_what_the_kdc_said_and_where_it_came_from() -> Result<(), TestError> {
    let (both, _) = login(ExpiryFields {
        key_expiration: Some(at(2_000_000_000)?),
        last_req_password: Some(at(1_900_000_000)?),
        last_req_account: Some(at(2_100_000_000)?),
    })?;
    assert_eq!(both.expiry_notice().password(), Some(at(1_900_000_000)?));
    assert_eq!(both.expiry_notice().account(), Some(at(2_100_000_000)?));
    assert!(both.expiry_notice().is_last_req());

    let (key_only, _) = login(ExpiryFields {
        key_expiration: Some(at(2_000_000_000)?),
        ..ExpiryFields::default()
    })?;
    assert_eq!(
        key_only.expiry_notice().password(),
        Some(at(2_000_000_000)?)
    );
    assert_eq!(key_only.expiry_notice().account(), None);
    assert!(!key_only.expiry_notice().is_last_req());

    let (silent, _) = login(ExpiryFields::default())?;
    assert_eq!(silent.expiry_notice(), &ExpiryNotice::default());
    Ok(())
}

/// MIT's warning rules: a last-req expiry always warns, a `key-expiration` one only within a week.
#[test]
fn the_warning_follows_mit_rules_and_wording() -> Result<(), TestError> {
    let now = at(1_800_000_000)?;
    let after = |seconds: u64| at(1_800_000_000 + seconds);
    let reported = |fields: ExpiryFields| -> Result<ExpiryNotice, TestError> {
        Ok(*login(fields)?.0.expiry_notice())
    };
    let key_expiration = |seconds: u64| -> Result<ExpiryNotice, TestError> {
        reported(ExpiryFields {
            key_expiration: Some(after(seconds)?),
            ..ExpiryFields::default()
        })
    };
    let last_req = |seconds: u64| -> Result<ExpiryNotice, TestError> {
        reported(ExpiryFields {
            last_req_password: Some(after(seconds)?),
            ..ExpiryFields::default()
        })
    };
    let banner = |expiry: ExpiryNotice| expiry.warning(now).map(|warning| warning.to_string());

    // A week or more away through key-expiration: silent. Within the week: a banner.
    assert_eq!(banner(key_expiration(8 * 86_400)?), None);
    assert_eq!(banner(key_expiration(0)?), None);
    assert!(
        banner(key_expiration(3 * 86_400)?).is_some_and(
            |text| text.starts_with("Warning: Your password will expire in 3 days on ")
        )
    );
    assert!(
        banner(key_expiration(90 * 60)?).is_some_and(
            |text| text.starts_with("Warning: Your password will expire in 1 hour on ")
        )
    );
    assert!(
        banner(key_expiration(3 * 3600)?).is_some_and(
            |text| text.starts_with("Warning: Your password will expire in 3 hours on ")
        )
    );
    assert!(banner(key_expiration(600)?).is_some_and(|text| {
        text.starts_with("Warning: Your password will expire in less than one hour on ")
    }));
    // A last-req expiry always asks for a warning, however far away.
    assert!(
        banner(last_req(40 * 86_400)?).is_some_and(
            |text| text.starts_with("Warning: Your password will expire in 40 days on ")
        )
    );
    // No password expiry, no warning.
    assert_eq!(banner(ExpiryNotice::default()), None);
    Ok(())
}

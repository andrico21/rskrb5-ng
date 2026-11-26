//! `[plugins] clpreauth` `disable` and `enable_only` over the built-in
//! mechanisms of the exchange engine (MIT 1.22.2 `plugin.c:302-347`).

use rskrb5_ng::{
    Config,
    client::stepwise::{Exchange as _, InitCredsOptions},
    error::Client as ClientError,
    preauth::spake::PA_SPAKE,
};

use crate::{
    kdc::{Kdc, Offer, PA_ENC_TIMESTAMP, REALM, Script, TestError},
    scenarios::{Outcome, carries, configured, exchange, never_sent_timestamp, request, run},
};

/// A profile whose `[plugins] clpreauth` holds `lines`.
fn profile(lines: &str) -> Result<Config, TestError> {
    Ok(Config::parse(&format!(
        "[libdefaults]\n default_realm = {REALM}\n[realms]\n {REALM} = {{\n kdc = 127.0.0.1:1\n }}\n[plugins]\n clpreauth = {{\n{lines}\n }}\n"
    ))?)
}

/// A KDC that offers PA-ENC-TIMESTAMP alone.
fn timestamp_only() -> Script {
    Script {
        offer: Offer::TimestampOnly,
        ..Script::default()
    }
}

/// The request number of the first PA-DATA of `kind`, if any request has one.
fn first_with(kdc: &Kdc, kind: i32) -> Result<Option<usize>, TestError> {
    for index in 0..kdc.requests().len() {
        if carries(kdc, index, kind)? {
            return Ok(Some(index));
        }
    }
    Ok(None)
}

/// Excluding `encrypted_timestamp` never sends one, optimistically or in answer
/// to an offer, and the exchange fails closed when nothing else is offered.
#[test]
fn disabled_timestamp_is_never_sent() -> Result<(), TestError> {
    let disabled = profile(" disable = encrypted_timestamp")?;
    let mut kdc = Kdc::new(timestamp_only())?;
    let mut login = exchange(configured(&disabled)?);
    assert!(matches!(
        run(&mut login, &mut kdc)?,
        Outcome::Failed(ClientError::EncryptedTimestampDisabled { realm }) if realm == REALM
    ));
    assert!(never_sent_timestamp(&kdc));
    let mut optimistic_kdc = Kdc::new(timestamp_only())?;
    let mut optimistic = exchange(InitCredsOptions::new(
        request()?.with_assume_preauthentication(true),
    ));
    optimistic.configure(&disabled);
    drop(run(&mut optimistic, &mut optimistic_kdc)?);
    assert!(never_sent_timestamp(&optimistic_kdc));
    let mut allowed_kdc = Kdc::new(timestamp_only())?;
    let allowed = profile(" disable = pkinit")?;
    let mut allowed_login = exchange(configured(&allowed)?);
    assert!(matches!(
        run(&mut allowed_login, &mut allowed_kdc)?,
        Outcome::Complete
    ));
    assert_eq!(first_with(&allowed_kdc, PA_ENC_TIMESTAMP)?, Some(1));
    Ok(())
}

/// `enable_only` keeps only the named built-in mechanisms: with the timestamp
/// absent from it none is sent, with it alone PA-SPAKE is not answered.
#[test]
fn enable_only_applies_to_builtin_preauth() -> Result<(), TestError> {
    let spake_only = profile(" enable_only = spake")?;
    let mut kdc = Kdc::new(timestamp_only())?;
    let mut login = exchange(configured(&spake_only)?);
    assert!(matches!(
        run(&mut login, &mut kdc)?,
        Outcome::Failed(ClientError::EncryptedTimestampDisabled { realm: _ })
    ));
    assert!(never_sent_timestamp(&kdc));
    let keep_timestamp = profile(" enable_only = encrypted_timestamp")?;
    let mut offering_spake = Kdc::new(Script::default())?;
    let mut keeping = exchange(configured(&keep_timestamp)?);
    assert!(matches!(
        run(&mut keeping, &mut offering_spake)?,
        Outcome::Complete
    ));
    assert!(carries(&offering_spake, 1, PA_ENC_TIMESTAMP)?);
    assert_eq!(first_with(&offering_spake, PA_SPAKE)?, None);
    Ok(())
}

/// Names match exactly and an unlisted name leaves every mechanism in use.
#[test]
fn clpreauth_names_match_exactly() -> Result<(), TestError> {
    let wrong_case = profile(" disable = Encrypted_Timestamp\n enable_only = ENCRYPTED_TIMESTAMP")?;
    let mut kdc = Kdc::new(timestamp_only())?;
    let mut login = exchange(configured(&wrong_case)?);
    assert!(matches!(
        run(&mut login, &mut kdc)?,
        Outcome::Failed(ClientError::EncryptedTimestampDisabled { realm: _ })
    ));
    let unknown = profile(" disable = nothing_by_this_name")?;
    let mut offering_timestamp = Kdc::new(timestamp_only())?;
    let mut unaffected = exchange(configured(&unknown)?);
    assert!(matches!(
        run(&mut unaffected, &mut offering_timestamp)?,
        Outcome::Complete
    ));
    Ok(())
}

/// `sam2` is a built-in name of MIT with no mechanism here: naming it alone
/// leaves nothing that answers, and the exchange fails closed.
#[test]
fn enable_only_sam2_leaves_no_mechanism() -> Result<(), TestError> {
    let sam2 = profile(" enable_only = sam2")?;
    let mut kdc = Kdc::new(timestamp_only())?;
    let mut login = exchange(configured(&sam2)?);
    assert!(matches!(
        run(&mut login, &mut kdc)?,
        Outcome::Failed(ClientError::EncryptedTimestampDisabled { realm: _ })
    ));
    assert!(never_sent_timestamp(&kdc));
    Ok(())
}

/// Excluding `spake` leaves the encrypted timestamp to answer a PA-SPAKE offer.
#[test]
fn disabled_spake_is_never_answered() -> Result<(), TestError> {
    let disabled = profile(" disable = spake")?;
    let mut kdc = Kdc::new(Script::default())?;
    let mut login = exchange(configured(&disabled)?);
    assert!(matches!(run(&mut login, &mut kdc)?, Outcome::Complete));
    assert!(carries(&kdc, 1, PA_ENC_TIMESTAMP)?);
    assert_eq!(first_with(&kdc, PA_SPAKE)?, None);
    Ok(())
}

/// `Exchange::configure` (the Tokio route) adopts the control as well.
#[test]
fn configure_adopts_the_plugin_controls() -> Result<(), TestError> {
    let disabled = profile(" disable = encrypted_timestamp")?;
    let mut kdc = Kdc::new(timestamp_only())?;
    let mut login = exchange(InitCredsOptions::new(request()?));
    login.configure(&disabled);
    assert!(matches!(
        run(&mut login, &mut kdc)?,
        Outcome::Failed(ClientError::EncryptedTimestampDisabled { realm: _ })
    ));
    Ok(())
}

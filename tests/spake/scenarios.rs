//! The SPAKE scenarios against the fake KDC; without the leaf, the one that
//! shows the engine never answers PA-SPAKE.

use core::time::Duration;
use std::time::UNIX_EPOCH;

#[cfg(feature = "spake")]
use curve25519_dalek::edwards::CompressedEdwardsY;
use rskrb5_ng::{
    Config,
    client::{
        Password,
        options::AsReq,
        stepwise::{Exchange as _, ExchangeStep, InitCreds, InitCredsOptions, StepInput},
    },
    error::Client as ClientError,
    preauth::spake::Policy,
};
#[cfg(feature = "spake")]
use rskrb5_ng::{
    error::Spake,
    keytab::{Entry as KeytabEntry, Keytab, Principal as KeytabPrincipal},
    preauth::spake::{Group, Message, PA_SPAKE},
};

#[cfg(feature = "spake")]
use crate::kdc::{COOKIE, Fault, PREAUTH_FAILED, long_term_key};
use crate::kdc::{Kdc, Offer, PA_ENC_TIMESTAMP, PASSWORD, REALM, Script, TestError, client};

/// A check of the SPAKE error a scenario ends with.
#[cfg(feature = "spake")]
type Check = fn(&Spake) -> bool;

/// The request template: AES256 only, no FAST negotiation marker.
fn request() -> Result<AsReq, TestError> {
    let now = UNIX_EPOCH
        .checked_add(Duration::from_secs(1_893_553_447))
        .ok_or("time")?;
    Ok(AsReq::new(now, 0x1234_5678)
        .with_etypes(vec![18_i32])
        .with_fast_negotiation(false))
}

/// A password exchange with `options`.
fn exchange(options: InitCredsOptions) -> InitCreds<'static> {
    InitCreds::with_password(
        client(),
        Some(Password::from_vec(PASSWORD.to_vec())),
        options,
    )
}

/// A profile for the realm with extra realm relations and libdefaults lines.
fn config(realm_lines: &str, libdefaults_lines: &str) -> Result<Config, TestError> {
    Ok(Config::parse(&format!(
        "[libdefaults]\n default_realm = {REALM}\n{libdefaults_lines}\n[realms]\n {REALM} = {{\n kdc = 127.0.0.1:1\n{realm_lines}\n }}\n"
    ))?)
}

/// Options from `profile`, at the scenarios' request time.
fn configured(profile: &Config) -> Result<InitCredsOptions, TestError> {
    let now = UNIX_EPOCH
        .checked_add(Duration::from_secs(1_893_553_447))
        .ok_or("time")?;
    Ok(InitCredsOptions::from_config(profile, now, 0x1234_5678)?)
}

/// What a scripted exchange ended with.
enum Outcome {
    /// The exchange completed.
    Complete,
    /// The exchange failed.
    Failed(ClientError),
}

/// Drive `exchange` against `kdc` until it completes or fails, then check that
/// a failed exchange sends nothing more.
fn run(exchange: &mut InitCreds<'_>, kdc: &mut Kdc) -> Result<Outcome, TestError> {
    let mut input: Option<Vec<u8>> = None;
    for _ in 0_u8..8 {
        let step = match &input {
            None => exchange.step(StepInput::Start),
            Some(reply) => exchange.step(StepInput::Reply(reply)),
        };
        let next = match step {
            Ok(next) => next,
            Err(error) => {
                let again = exchange.step(StepInput::Reply(input.as_deref().unwrap_or_default()));
                assert!(
                    !matches!(again, Ok(ExchangeStep::Outbound(_))),
                    "a failed exchange sent another request"
                );
                return Ok(Outcome::Failed(error));
            }
        };
        if let ExchangeStep::Outbound(outbound) = &next {
            input = Some(kdc.answer(outbound.message())?);
        } else if let ExchangeStep::Complete(_) = next {
            return Ok(Outcome::Complete);
        } else {
            return Err(format!("unexpected step {next:?}").into());
        }
    }
    Err("the exchange did not finish".into())
}

#[cfg(feature = "spake")]
/// The PA-SPAKE message of request `index`, if it carries one.
fn spake_message(kdc: &Kdc, index: usize) -> Result<Option<Message>, TestError> {
    let request = kdc.requests().get(index).ok_or("request missing")?;
    request
        .iter()
        .find(|entry| entry.r#type == PA_SPAKE)
        .map(|entry| Message::decode(&entry.value))
        .transpose()
        .map_err(Into::into)
}

/// Whether request `index` carries `kind`.
fn carries(kdc: &Kdc, index: usize, kind: i32) -> Result<bool, TestError> {
    Ok(kdc
        .requests()
        .get(index)
        .ok_or("request missing")?
        .iter()
        .any(|entry| entry.r#type == kind))
}

/// No request of the exchange carried an encrypted timestamp.
fn never_sent_timestamp(kdc: &Kdc) -> bool {
    kdc.requests()
        .iter()
        .all(|request| request.iter().all(|entry| entry.r#type != PA_ENC_TIMESTAMP))
}

#[cfg(feature = "spake")]
/// The SPAKE error of `outcome`, if it is one.
fn spake_error(outcome: &Outcome) -> Option<&Spake> {
    match outcome {
        Outcome::Failed(ClientError::Spake(error)) => Some(error),
        Outcome::Complete | Outcome::Failed(_) => None,
    }
}

#[cfg(feature = "spake")]
/// The full exchange completes, and no encrypted timestamp is ever sent.
///
/// The support message carries the policy's group and the KDC cookie, the
/// challenge arrives in a `MORE_PREAUTH_DATA_REQUIRED` error, and the AS-REP is
/// encrypted in `K'[0]`.
#[test]
fn spake_exchange_completes_with_the_strengthened_reply_key() -> Result<(), TestError> {
    let mut kdc = Kdc::new(Script::default())?;
    let mut login = exchange(InitCredsOptions::new(request()?));
    assert!(matches!(run(&mut login, &mut kdc)?, Outcome::Complete));
    assert_eq!(kdc.requests().len(), 3, "probe, support, response");
    assert_eq!(
        spake_message(&kdc, 1)?,
        Some(Message::Support {
            groups: vec![1_i32]
        })
    );
    assert!(matches!(
        spake_message(&kdc, 2)?,
        Some(Message::Response { pubkey, factor }) if pubkey.len() == 32 && factor.etype == 18_i32 && factor.kvno.is_none()
    ));
    assert!(
        carries(&kdc, 1, 133)? && carries(&kdc, 2, 133)?,
        "cookie {COOKIE:?} echoed"
    );
    assert!(never_sent_timestamp(&kdc));
    Ok(())
}

#[cfg(feature = "spake")]
/// A keytab exchange runs SPAKE with the keytab's key.
#[test]
fn keytab_exchange_runs_spake() -> Result<(), TestError> {
    let key = long_term_key()?;
    let mut keytab = Keytab::new();
    keytab.entries_mut().push(KeytabEntry::new(
        KeytabPrincipal::new(REALM, 1, vec!["spakeuser".to_owned()]),
        1_893_553_440,
        1,
        key,
        1,
    ));
    let mut kdc = Kdc::new(Script::default())?;
    let mut login = InitCreds::with_keytab(client(), keytab, InitCredsOptions::new(request()?));
    assert!(matches!(run(&mut login, &mut kdc)?, Outcome::Complete));
    assert!(never_sent_timestamp(&kdc));
    Ok(())
}

#[cfg(feature = "spake")]
/// An optimistic challenge in a permitted group is answered at once, without a
/// support message (RFC 9588 section 4.6).
#[test]
fn optimistic_challenge_is_answered_without_support() -> Result<(), TestError> {
    let mut kdc = Kdc::new(Script {
        offer: Offer::Optimistic,
        ..Script::default()
    })?;
    let mut login = exchange(InitCredsOptions::new(request()?));
    assert!(matches!(run(&mut login, &mut kdc)?, Outcome::Complete));
    assert_eq!(kdc.requests().len(), 2);
    assert!(matches!(
        spake_message(&kdc, 1)?,
        Some(Message::Response {
            pubkey: _,
            factor: _
        })
    ));
    Ok(())
}

#[cfg(feature = "spake")]
/// QA failure scenario: a challenge naming a group outside `spake_preauth_groups` is rejected.
///
/// After the support message it fails the exchange; as an optimistic challenge
/// it is answered with a support message, never with a response.
#[test]
fn challenge_outside_the_policy_is_rejected() -> Result<(), TestError> {
    let mut kdc = Kdc::new(Script {
        group: Group::P256.id(),
        ..Script::default()
    })?;
    let mut login = exchange(InitCredsOptions::new(request()?));
    let outcome = run(&mut login, &mut kdc)?;
    assert!(matches!(
        spake_error(&outcome),
        Some(Spake::GroupNotPermitted { group: 2_i32 })
    ));
    assert_eq!(
        kdc.requests().len(),
        2,
        "no response after the refused challenge"
    );
    let mut optimistic = Kdc::new(Script {
        group: Group::P256.id(),
        offer: Offer::Optimistic,
        ..Script::default()
    })?;
    let mut second = exchange(InitCredsOptions::new(request()?));
    let refused = run(&mut second, &mut optimistic)?;
    assert_eq!(
        spake_message(&optimistic, 1)?,
        Some(Message::Support {
            groups: vec![1_i32]
        }),
        "the optimistic challenge got a support message"
    );
    assert!(matches!(
        spake_error(&refused),
        Some(Spake::GroupNotPermitted { group: 2_i32 })
    ));
    assert!(never_sent_timestamp(&kdc) && never_sent_timestamp(&optimistic));
    Ok(())
}

#[cfg(feature = "spake")]
/// Wrong factor: a challenge without `SF-NONE`, or with `SF-NONE` carrying data,
/// is rejected before any key is used.
#[test]
fn challenge_without_a_supported_factor_is_rejected() -> Result<(), TestError> {
    for (factors, expected_none) in [
        (vec![(2_i32, None)], true),
        (vec![(1_i32, Some(vec![1_u8]))], false),
    ] {
        let mut kdc = Kdc::new(Script {
            factors,
            ..Script::default()
        })?;
        let mut login = exchange(InitCredsOptions::new(request()?));
        let outcome = run(&mut login, &mut kdc)?;
        let error = spake_error(&outcome).ok_or("not a SPAKE error")?;
        if expected_none {
            assert!(matches!(error, Spake::NoSupportedFactor), "{error:?}");
        } else {
            assert!(
                matches!(error, Spake::Malformed { message: _ }),
                "{error:?}"
            );
        }
        assert_eq!(kdc.requests().len(), 2);
    }
    Ok(())
}

#[cfg(feature = "spake")]
/// Transcript tamper: a challenge altered in transit gives the client keys the KDC
/// does not share; the KDC refuses the factor and the client stops, with no
/// retry into another mechanism.
#[test]
fn tampered_transcript_fails_closed_without_fallback() -> Result<(), TestError> {
    let mut kdc = Kdc::new(Script {
        fault: Fault::Tamper,
        ..Script::default()
    })?;
    let mut login = exchange(InitCredsOptions::new(request()?));
    let outcome = run(&mut login, &mut kdc)?;
    assert!(matches!(
        &outcome,
        Outcome::Failed(ClientError::Kdc(error)) if error.error_code() == PREAUTH_FAILED
    ));
    assert_eq!(kdc.requests().len(), 3);
    assert!(never_sent_timestamp(&kdc));
    Ok(())
}

#[cfg(feature = "spake")]
/// Downgrade: a KDC failure answering the support message, even one offering
/// encrypted timestamp, ends the exchange.
#[test]
fn spake_failure_does_not_fall_back() -> Result<(), TestError> {
    let mut kdc = Kdc::new(Script {
        fault: Fault::FailSupport,
        ..Script::default()
    })?;
    let mut login = exchange(InitCredsOptions::new(request()?));
    let outcome = run(&mut login, &mut kdc)?;
    assert!(matches!(
        &outcome,
        Outcome::Failed(ClientError::Kdc(error)) if error.error_code() == PREAUTH_FAILED
    ));
    assert!(never_sent_timestamp(&kdc));
    Ok(())
}

#[cfg(feature = "spake")]
/// Malformed group elements: a wrong length, a point off the curve, a
/// non-canonical encoding and an element that makes the shared element the identity.
#[test]
fn invalid_kdc_elements_are_rejected() -> Result<(), TestError> {
    let off_curve = (2_u8..=u8::MAX)
        .map(|first| {
            let mut bytes = [0_u8; 32];
            bytes[0] = first;
            bytes
        })
        .find(|bytes| CompressedEdwardsY(*bytes).decompress().is_none())
        .ok_or("no off-curve encoding")?;
    let mut non_canonical = [0xff_u8; 32];
    non_canonical[0] = 0xed;
    non_canonical[31] = 0x7f;
    for script in [
        Script {
            element: Some(vec![0_u8; 31]),
            ..Script::default()
        },
        Script {
            element: Some(off_curve.to_vec()),
            ..Script::default()
        },
        Script {
            element: Some(non_canonical.to_vec()),
            ..Script::default()
        },
        Script {
            fault: Fault::Identity,
            ..Script::default()
        },
    ] {
        let mut kdc = Kdc::new(script.clone())?;
        let mut login = exchange(InitCredsOptions::new(request()?));
        let outcome = run(&mut login, &mut kdc)?;
        assert!(
            matches!(
                spake_error(&outcome),
                Some(Spake::InvalidElement { group: 1_i32 })
            ),
            "{script:?}"
        );
        assert_eq!(kdc.requests().len(), 2, "{script:?}");
    }
    Ok(())
}

#[cfg(feature = "spake")]
/// Malformed groups and messages: an unknown group after the support message,
/// non-DER bytes, an empty PA-SPAKE where the challenge belongs, and a
/// second-factor `encdata` message.
#[test]
fn malformed_challenges_are_rejected() -> Result<(), TestError> {
    let unknown = Script {
        group: 99,
        ..Script::default()
    };
    let cases: [(Script, Check); 4] = [
        (unknown, |error| {
            matches!(error, Spake::GroupNotPermitted { group: 99_i32 })
        }),
        (
            Script {
                raw_challenge: Some(vec![0xa1_u8, 0x03, 0x30, 0x01]),
                ..Script::default()
            },
            |error| matches!(error, Spake::Malformed { message: _ }),
        ),
        (
            Script {
                raw_challenge: Some(Vec::new()),
                ..Script::default()
            },
            |error| matches!(error, Spake::Unexpected { message: _ }),
        ),
        (
            Script {
                raw_challenge: Some(vec![
                    0xa3, 0x11, 0x30, 0x0f, 0xa0, 0x03, 0x02, 0x01, 0x12, 0xa2, 0x08, 0x04, 0x06,
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                ]),
                ..Script::default()
            },
            |error| matches!(error, Spake::SecondFactorUnsupported),
        ),
    ];
    for (script, expected) in cases {
        let mut kdc = Kdc::new(script.clone())?;
        let mut login = exchange(InitCredsOptions::new(request()?));
        let outcome = run(&mut login, &mut kdc)?;
        let error = spake_error(&outcome).ok_or("not a SPAKE error")?;
        assert!(expected(error), "{script:?}: {error:?}");
    }
    Ok(())
}

/// Downgrade protection: `disable_encrypted_timestamp` refuses a timestamp-only offer.
///
/// A KDC (or an attacker) that offers only encrypted timestamp gets no
/// timestamp, and an optimistic timestamp is suppressed; without the relation
/// the timestamp is used.
#[test]
fn disable_encrypted_timestamp() -> Result<(), TestError> {
    let stripped = Script::offering(Offer::TimestampOnly);
    let disabled = config(" disable_encrypted_timestamp = true", "")?;
    let mut kdc = Kdc::new(stripped.clone())?;
    let mut login = exchange(configured(&disabled)?);
    let outcome = run(&mut login, &mut kdc)?;
    assert!(matches!(
        &outcome,
        Outcome::Failed(ClientError::EncryptedTimestampDisabled { realm }) if realm == REALM
    ));
    assert!(never_sent_timestamp(&kdc));
    let mut optimistic_kdc = Kdc::new(stripped.clone())?;
    let mut optimistic = exchange(
        InitCredsOptions::new(request()?.with_assume_preauthentication(true))
            .with_spake_policy(Policy::default()),
    );
    optimistic.configure(&disabled);
    drop(run(&mut optimistic, &mut optimistic_kdc)?);
    assert!(
        !carries(&optimistic_kdc, 0, PA_ENC_TIMESTAMP)?,
        "optimistic timestamp sent"
    );
    let mut allowed_kdc = Kdc::new(stripped)?;
    let mut allowed = exchange(configured(&config("", "")?)?);
    assert!(matches!(
        run(&mut allowed, &mut allowed_kdc)?,
        Outcome::Complete
    ));
    assert!(carries(&allowed_kdc, 1, PA_ENC_TIMESTAMP)?);
    Ok(())
}

#[cfg(feature = "spake")]
/// MIT's order: when the KDC lists encrypted timestamp first, it is used; when
/// the realm disables it, the exchange moves on to SPAKE.
#[test]
fn disabled_timestamp_moves_on_to_spake() -> Result<(), TestError> {
    let first = Script {
        offer: Offer::TimestampFirst,
        ..Script::default()
    };
    let mut kdc = Kdc::new(first.clone())?;
    let mut login = exchange(configured(&config("", "")?)?);
    assert!(matches!(run(&mut login, &mut kdc)?, Outcome::Complete));
    assert!(carries(&kdc, 1, PA_ENC_TIMESTAMP)?);
    let mut spake_kdc = Kdc::new(first)?;
    let mut spake = exchange(configured(&config(
        " disable_encrypted_timestamp = true",
        "",
    )?)?);
    assert!(matches!(
        run(&mut spake, &mut spake_kdc)?,
        Outcome::Complete
    ));
    assert!(never_sent_timestamp(&spake_kdc));
    assert_eq!(spake_kdc.requests().len(), 3);
    Ok(())
}

#[cfg(feature = "spake")]
/// `Exchange::configure` (the `drive_tokio` route) adopts the profile:
/// `spake_preauth_groups` replaces the default policy and
/// `disable_encrypted_timestamp` removes the timestamp.
#[test]
fn configure_adopts_the_profile() -> Result<(), TestError> {
    let profile = config(
        " disable_encrypted_timestamp = true",
        " spake_preauth_groups = P-256 P-384",
    )?;
    let mut kdc = Kdc::new(Script::default())?;
    let mut login = exchange(InitCredsOptions::new(request()?));
    login.configure(&profile);
    let outcome = run(&mut login, &mut kdc)?;
    assert_eq!(
        spake_message(&kdc, 1)?,
        Some(Message::Support {
            groups: vec![2_i32, 3_i32]
        })
    );
    assert!(matches!(
        spake_error(&outcome),
        Some(Spake::GroupNotPermitted { group: 1_i32 })
    ));
    let mut stripped_kdc = Kdc::new(Script {
        offer: Offer::TimestampOnly,
        ..Script::default()
    })?;
    let mut stripped = exchange(InitCredsOptions::new(request()?));
    stripped.configure(&profile);
    assert!(matches!(
        run(&mut stripped, &mut stripped_kdc)?,
        Outcome::Failed(ClientError::EncryptedTimestampDisabled { realm: _ })
    ));
    Ok(())
}

#[cfg(feature = "spake")]
/// An empty `spake_preauth_groups` disables SPAKE (MIT `groups.c:235-239`): the
/// exchange answers with encrypted timestamp.
#[test]
fn empty_group_list_disables_spake() -> Result<(), TestError> {
    let profile = config("", " spake_preauth_groups =")?;
    let mut kdc = Kdc::new(Script::default())?;
    let mut login = exchange(configured(&profile)?);
    assert!(matches!(run(&mut login, &mut kdc)?, Outcome::Complete));
    assert!(carries(&kdc, 1, PA_ENC_TIMESTAMP)?);
    assert_eq!(spake_message(&kdc, 1)?, None);
    Ok(())
}

/// Without the `spake` leaf the engine never answers PA-SPAKE.
///
/// It answers the same KDC with encrypted timestamp.
#[cfg(not(feature = "spake"))]
#[test]
fn without_the_leaf_spake_is_never_answered() -> Result<(), TestError> {
    let mut kdc = Kdc::new(Script::default())?;
    let mut login = exchange(InitCredsOptions::new(request()?));
    assert!(matches!(run(&mut login, &mut kdc)?, Outcome::Complete));
    assert!(carries(&kdc, 1, PA_ENC_TIMESTAMP)?);
    assert_eq!(kdc.requests().len(), 2);
    Ok(())
}

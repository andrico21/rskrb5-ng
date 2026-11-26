//! FAST for TGS requests through the stepwise ticket engine against the fake TGS KDC.
//!
//! MIT 1.22.2 armors every TGS request implicitly (`send_tgs.c:178`,
//! `krb5int_fast_tgs_armor` `fast.c:110-142`, `krb5int_fast_prep_req`
//! `fast.c:253-357`). These tests hold the armored request to that wire form
//! and every reply to RFC 6113 section 5.4.3 and 5.4.4, and prove that no
//! failure to verify an armored reply ever turns into a plain exchange.

use std::time::SystemTime;

use rasn::der;
use rskrb5_ng::{
    client::{
        AsRepSession,
        options::TgsReq,
        principal::Principal,
        stepwise::{ExchangeStep, StepInput, TicketCreds, TicketOptions},
    },
    error::{Client as ClientError, Fast},
    messages::PaPacOptions,
    preauth::fast::{Outcome, PA_FX_FAST, Policy},
};

use super::{
    exchange::fast_cause,
    kdc::{Kdc, REALM, TestError, pa},
    tgs_kdc::{Tamper, TgsKdc},
};

/// A service of the test realm.
fn service(realm: &str) -> Principal {
    Principal::new(realm, 2, ["http", "svc.fast.test"])
}

/// The TGT the client holds.
fn tgt() -> Result<AsRepSession, TestError> {
    Kdc::new().armor_ticket()
}

/// Ticket options with the PAC options padata, which MIT repeats outside the armor.
fn options() -> Result<TicketOptions, TestError> {
    let bits = PaPacOptions::from_bits(0x8000_0000).encode_der()?;
    Ok(TicketOptions::new(
        TgsReq::new(SystemTime::now(), 0x2b2b_2b2b)
            .with_etypes(vec![18_i32])
            .with_padata(vec![pa(167_i32, bits)]),
    ))
}

/// What one run of the engine produced.
struct Run {
    /// The credential or the failure.
    result: Result<AsRepSession, ClientError>,
    /// The engine's FAST outcome after the run.
    outcome: Option<Outcome>,
}

/// Run a TGS exchange for `service` under `policy` against `kdc`.
fn attempt(kdc: &mut TgsKdc, policy: Option<Policy>, target: Principal) -> Result<Run, TestError> {
    let engine = TicketCreds::new(tgt()?, target, options()?)?;
    let mut engine = match policy {
        Some(policy) => engine.with_fast(policy),
        None => engine,
    };
    let result = drive(kdc, &mut engine);
    Ok(Run {
        result,
        outcome: engine.fast_outcome(),
    })
}

/// Feed the engine's requests to `kdc` until it finishes.
fn drive(kdc: &mut TgsKdc, engine: &mut TicketCreds) -> Result<AsRepSession, ClientError> {
    let mut step = engine.step(StepInput::Start)?;
    loop {
        match step {
            ExchangeStep::Outbound(outbound) => {
                let reply = kdc
                    .handle(outbound.message())
                    .map_err(|error| ClientError::Transport(error.to_string()))?;
                step = engine.step(StepInput::Reply(&reply))?;
            }
            ExchangeStep::Complete(session) => return Ok(*session),
            ExchangeStep::Prompt(_) | _ => {
                return Err(ClientError::Transport("unexpected step".to_owned()));
            }
        }
    }
}

/// The credential of a run, reported with the error's message when it failed.
fn credential(run: Run) -> Result<(AsRepSession, Option<Outcome>), TestError> {
    let outcome = run.outcome;
    let session = run.result.map_err(|error| format!("{error:?}: {error}"))?;
    Ok((session, outcome))
}

/// The failure of a run.
fn failure(run: Run) -> Result<ClientError, TestError> {
    run.result
        .err()
        .ok_or_else(|| "the exchange succeeded".into())
}

/// An armored TGS request has MIT's wire form and its reply verifies.
///
/// The outer request is `PA-TGS-REQ`, `PA-FX-FAST`, then a copy of the other
/// padata (`make_tgs_outer_padata`, `fast.c:231-251`); `PA-TGS-REQ` stays out of
/// the encrypted inner request; the armor field is absent because the TGT
/// armors implicitly (`armored_req->armor = state->armor`, NULL for TGS); the
/// request checksum covers the AP-REQ (`fast.c:300-303`, `to_be_checksummed`)
/// and is the armor key's mandatory type; the reply is encrypted in the
/// strengthened subkey (RFC 6113 section 5.4.3).
#[test]
fn tgs_fast_matches_mit() -> Result<(), TestError> {
    let mut kdc = TgsKdc::new(Tamper::None);
    let (session, outcome) =
        credential(attempt(&mut kdc, Some(Policy::Required), service(REALM))?)?;
    assert_eq!(outcome, Some(Outcome::Armored), "the outcome");
    assert_eq!(session.service(), &service(REALM), "the issued service");
    let seen = kdc.seen().ok_or("the KDC saw no request")?;
    assert_eq!(
        seen.outer_types,
        vec![1_i32, PA_FX_FAST, 167_i32],
        "outer padata"
    );
    assert_eq!(seen.inner_types, vec![167_i32], "inner padata");
    assert!(!seen.armor_field, "implicit armor carries no armor field");
    assert_eq!(seen.checksum_type, 16_i32, "hmac-sha1-96-aes256");
    assert_eq!(kdc.requests().len(), 1, "one request");
    Ok(())
}

/// With FAST off the request is the plain RFC 4120 request.
#[test]
fn tgs_fast_is_off_unless_asked_for() -> Result<(), TestError> {
    for policy in [None, Some(Policy::Off)] {
        let mut kdc = TgsKdc::new(Tamper::None);
        let run = attempt(&mut kdc, policy, service(REALM))?;
        assert!(run.result.is_err(), "the fake KDC wants armor: {policy:?}");
        let rasn_kerberos::TgsReq(request) =
            der::decode(kdc.requests().first().ok_or("the engine sent no request")?)?;
        let types: Vec<i32> = request
            .padata
            .unwrap_or_default()
            .iter()
            .map(|entry| entry.r#type)
            .collect();
        assert_eq!(types, vec![1_i32, 167_i32], "{policy:?}: unarmored padata");
        assert_eq!(run.outcome, None, "{policy:?}: no outcome");
    }
    Ok(())
}

/// A reply without the strengthen key is refused (RFC 6113 section 5.4.3).
///
/// MIT would decrypt such a reply in the plain subkey; the key a KDC adds is
/// what binds the reply to the armor, so it is required under every policy.
#[test]
fn tgs_fast_requires_strengthen_key() -> Result<(), TestError> {
    for policy in [Policy::Required, Policy::Opportunistic] {
        let mut kdc = TgsKdc::new(Tamper::DropStrengthenKey);
        let error = failure(attempt(&mut kdc, Some(policy), service(REALM))?)?;
        assert!(
            matches!(
                fast_cause(&error),
                Some(Fast::Malformed {
                    structure: "KrbFastResponse",
                    reason: _
                })
            ),
            "{policy:?}: {error}"
        );
        assert_eq!(kdc.requests().len(), 1, "{policy:?}: no retry");
    }
    Ok(())
}

/// A reply that fails any FAST check ends the exchange: nothing is retried, nothing falls back.
#[test]
fn tgs_fast_tamper_never_falls_back() -> Result<(), TestError> {
    /// What a case expects of the exchange error.
    type Expectation = fn(&ClientError) -> bool;
    let cases: [(Tamper, Expectation); 7] = [
        (Tamper::DropFinished, |error| {
            matches!(fast_cause(error), Some(Fast::MissingFinished))
        }),
        (Tamper::TicketChecksum, |error| {
            matches!(fast_cause(error), Some(Fast::TicketChecksum))
        }),
        (Tamper::TicketChecksumType, |error| {
            matches!(
                fast_cause(error),
                Some(Fast::ChecksumType {
                    expected: 16,
                    actual: 15
                })
            )
        }),
        (Tamper::Nonce, |error| {
            matches!(fast_cause(error), Some(Fast::NonceMismatch { .. }))
        }),
        // The reply is encrypted in another key than the one the client derives.
        (Tamper::WrongStrengthenKey, |error| {
            matches!(error, ClientError::Crypto(_))
        }),
        (Tamper::ReplyCiphertext, |error| fast_cause(error).is_some()),
        (Tamper::ErrorStrengthenKey, |error| {
            matches!(fast_cause(error), Some(Fast::Malformed { .. }))
        }),
    ];
    for policy in [Policy::Required, Policy::Opportunistic] {
        for (tamper, expected) in cases {
            let mut kdc = TgsKdc::new(tamper);
            let run = attempt(&mut kdc, Some(policy), service(REALM))?;
            assert_ne!(run.outcome, Some(Outcome::Armored), "{policy:?} {tamper:?}");
            let error = failure(run)?;
            assert!(expected(&error), "{policy:?} {tamper:?}: {error}");
            assert_eq!(
                kdc.requests().len(),
                1,
                "{policy:?} {tamper:?}: no second request"
            );
        }
    }
    Ok(())
}

/// A reply that lost its `PA-FX-FAST` cannot be decrypted: stripping the armor downgrades nothing.
#[test]
fn stripped_fast_is_no_downgrade() -> Result<(), TestError> {
    for policy in [Policy::Required, Policy::Opportunistic] {
        let mut kdc = TgsKdc::new(Tamper::StrippedFast);
        let run = attempt(&mut kdc, Some(policy), service(REALM))?;
        assert!(kdc.seen().is_some(), "{policy:?}: the request was armored");
        assert_ne!(run.outcome, Some(Outcome::Armored), "{policy:?}");
        assert!(run.result.is_err(), "{policy:?}: accepted a stripped reply");
        assert_eq!(kdc.requests().len(), 1, "{policy:?}: no second request");
    }
    Ok(())
}

/// An unarmored reply to an armored request is refused under `Required`.
#[test]
fn unarmored_reply_to_an_armored_request_is_refused() -> Result<(), TestError> {
    let mut kdc = TgsKdc::new(Tamper::NoFast);
    let run = attempt(&mut kdc, Some(Policy::Required), service(REALM))?;
    assert_eq!(run.outcome, None, "no outcome");
    let error = failure(run)?;
    assert!(
        matches!(fast_cause(&error), Some(Fast::Unarmored)),
        "{error}"
    );
    let mut kdc = TgsKdc::new(Tamper::UnarmoredError);
    let error = failure(run_required(&mut kdc)?)?;
    assert!(
        matches!(fast_cause(&error), Some(Fast::UnarmoredError { code: 7 })),
        "{error}"
    );
    assert_eq!(kdc.requests().len(), 1, "no retry");
    Ok(())
}

/// A `Required` run against `kdc`.
fn run_required(kdc: &mut TgsKdc) -> Result<Run, TestError> {
    attempt(kdc, Some(Policy::Required), service(REALM))
}

/// A KDC without FAST is served only by `Opportunistic`, as MIT does
/// (`krb5int_decode_tgs_rep` takes `KRB5_ERR_FAST_REQUIRED` as success), and
/// the outcome says it ran unarmored; its errors stay errors.
#[test]
fn a_kdc_without_fast_is_served_only_opportunistically() -> Result<(), TestError> {
    let mut kdc = TgsKdc::new(Tamper::NoFast);
    let (plain, outcome) = credential(attempt(
        &mut kdc,
        Some(Policy::Opportunistic),
        service(REALM),
    )?)?;
    assert_eq!(outcome, Some(Outcome::Unarmored), "the outcome");
    assert_eq!(plain.service(), &service(REALM), "the plain ticket");
    let mut kdc = TgsKdc::new(Tamper::UnarmoredError);
    let refused = attempt(&mut kdc, Some(Policy::Opportunistic), service(REALM))?;
    let error = failure(refused)?;
    assert!(
        matches!(&error, ClientError::Kdc(kdc_error) if kdc_error.error_code() == 7),
        "{error}"
    );
    assert_eq!(kdc.requests().len(), 1, "an unarmored error is not retried");
    Ok(())
}

/// An armored error is authenticated and surfaces as the KDC's own error.
#[test]
fn an_armored_error_surfaces_the_inner_kdc_error() -> Result<(), TestError> {
    for policy in [Policy::Required, Policy::Opportunistic] {
        let mut kdc = TgsKdc::new(Tamper::ArmoredError);
        let error = failure(attempt(&mut kdc, Some(policy), service(REALM))?)?;
        assert!(
            matches!(&error, ClientError::Kdc(kdc_error) if kdc_error.error_code() == 7),
            "{policy:?}: {error}"
        );
    }
    Ok(())
}

/// The client name FAST authenticated wins over the unauthenticated outer one.
#[test]
fn the_authenticated_client_wins_over_the_outer_name() -> Result<(), TestError> {
    let mut kdc = TgsKdc::new(Tamper::OuterClient);
    let (session, outcome) = credential(run_required(&mut kdc)?)?;
    assert_eq!(outcome, Some(Outcome::Armored), "the outcome");
    assert_eq!(
        session.client(),
        &Principal::new(REALM, 3, ["host", "armor.fast.test"]),
        "the finished client"
    );
    Ok(())
}

/// Every hop of a cross-realm exchange is armored with a key of its own.
#[test]
fn every_referral_hop_is_armored() -> Result<(), TestError> {
    let mut kdc = TgsKdc::new(Tamper::None);
    let run = attempt(&mut kdc, Some(Policy::Required), service("OTHER.TEST"))?;
    let session = run.result?;
    assert_eq!(
        session.service(),
        &service("OTHER.TEST"),
        "the final service"
    );
    assert_eq!(run.outcome, Some(Outcome::Armored), "the outcome");
    assert_eq!(
        kdc.requests().len(),
        2,
        "the referral hop and the service request"
    );
    Ok(())
}

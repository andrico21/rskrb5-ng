//! The PKINIT scenarios against the fake KDC: certificate login, anonymous
//! PKINIT, and every rejection the client owes (wrong EKU, wrong SAN,
//! untrusted chain, RSA key transport, wrong nonce, malformed CMS, a wrong
//! or missing anonymous key exchange).

use core::time::Duration;
use std::time::UNIX_EPOCH;

use rskrb5_ng::{
    client::{
        options::AsReq,
        principal::Principal,
        stepwise::{ExchangeStep, InitCreds, InitCredsOptions, StepInput},
    },
    error::{Client as ClientError, Pkinit},
    preauth::pkinit::{
        AnonymousOptions, CertificatePolicy, DhGroup, EkuChecking, Exchange, Identity, KdcTrust,
    },
};

use crate::kdc::{Behaviour, CA_EC, CLIENT_KEY, CLIENT_PEM, FRESHNESS, Kdc, REALM, TestError};

/// The request template: AES256 only.
fn request() -> Result<AsReq, TestError> {
    let now = UNIX_EPOCH
        .checked_add(Duration::from_secs(1_893_553_447))
        .ok_or("time")?;
    Ok(AsReq::new(now, 0x1234_5678)
        .with_etypes(vec![18_i32])
        .with_fast_negotiation(false))
}

/// The client principal.
fn client() -> Principal {
    Principal::user(REALM, "pkinituser")
}

/// A certificate exchange under `policy`.
fn exchange(policy: CertificatePolicy) -> Result<Exchange, TestError> {
    Ok(Exchange::new(
        Identity::from_pem(CLIENT_PEM, CLIENT_KEY)?,
        KdcTrust::from_pem(CA_EC)?,
        policy.with_group(DhGroup::P256),
    ))
}

/// Drive `engine` against `kdc` to its end.
fn run(
    engine: &mut InitCreds<'_>,
    kdc: &mut Kdc,
) -> Result<Result<Principal, ClientError>, TestError> {
    let mut input: Option<Vec<u8>> = None;
    for _ in 0_u8..6 {
        let step = match &input {
            None => engine.step(StepInput::Start),
            Some(reply) => engine.step(StepInput::Reply(reply)),
        };
        match step {
            Err(error) => return Ok(Err(error)),
            Ok(ExchangeStep::Outbound(outbound)) => input = Some(kdc.answer(outbound.message())?),
            Ok(ExchangeStep::Complete(session)) => return Ok(Ok(session.client().clone())),
            Ok(other) => return Err(format!("unexpected step {other:?}").into()),
        }
    }
    Err("the exchange did not finish".into())
}

/// The PKINIT error of an outcome.
fn pkinit_error(outcome: &Result<Principal, ClientError>) -> Option<&Pkinit> {
    match outcome {
        Err(ClientError::Pkinit(error)) => Some(error),
        _ => None,
    }
}

#[test]
fn certificate_login_completes_with_the_freshness_token() -> Result<(), TestError> {
    // Given a KDC that offers a freshness token and a client with a certificate.
    let mut kdc = Kdc::new(Behaviour::Honest, true);
    let mut engine = InitCreds::with_pkinit(
        client(),
        exchange(CertificatePolicy::default())?,
        InitCredsOptions::new(request()?),
    );
    // When the exchange runs.
    let outcome = run(&mut engine, &mut kdc)?;
    // Then it completes for the client, echoing the token and checksumming the body.
    assert_eq!(
        outcome.map_err(|error| error.to_string())?,
        client(),
        "client"
    );
    let pack = kdc.auth_packs().first().ok_or("no AuthPack")?;
    assert_eq!(
        pack.pk_authenticator.freshness_token.as_deref(),
        Some(FRESHNESS),
        "freshness token"
    );
    assert_eq!(pack.pk_authenticator.nonce, 0x1234_5678, "nonce");
    assert!(
        kdc.checksums_match(),
        "paChecksum and paChecksum2 bind the body"
    );
    Ok(())
}

#[test]
fn no_freshness_token_is_sent_when_none_is_offered() -> Result<(), TestError> {
    let mut kdc = Kdc::new(Behaviour::Honest, false);
    let mut engine = InitCreds::with_pkinit(
        client(),
        exchange(CertificatePolicy::default())?,
        InitCredsOptions::new(request()?),
    );
    let outcome = run(&mut engine, &mut kdc)?;
    assert!(outcome.is_ok(), "{outcome:?}");
    let pack = kdc.auth_packs().first().ok_or("no AuthPack")?;
    assert_eq!(pack.pk_authenticator.freshness_token, None, "no token");
    Ok(())
}

#[test]
fn kdc_certificate_without_the_kdc_eku_is_rejected_under_kp_kdc() -> Result<(), TestError> {
    // Given pkinit_eku_checking = kpKDC (the default) and a KDC certificate
    // that names the TGS but lacks id-pkinit-KPKdc.
    let mut kdc = Kdc::new(Behaviour::NoEku, true);
    let mut engine = InitCreds::with_pkinit(
        client(),
        exchange(CertificatePolicy::default().with_eku_checking(EkuChecking::KpKdc))?,
        InitCredsOptions::new(request()?),
    );
    // When the exchange runs, then the reply is refused for its key purpose.
    let outcome = run(&mut engine, &mut kdc)?;
    assert!(
        matches!(pkinit_error(&outcome), Some(Pkinit::KeyPurpose)),
        "{outcome:?}"
    );
    Ok(())
}

#[test]
fn kdc_certificate_without_the_eku_is_accepted_under_none() -> Result<(), TestError> {
    let mut kdc = Kdc::new(Behaviour::NoEku, true);
    let mut engine = InitCreds::with_pkinit(
        client(),
        exchange(CertificatePolicy::default().with_eku_checking(EkuChecking::None))?,
        InitCredsOptions::new(request()?),
    );
    let outcome = run(&mut engine, &mut kdc)?;
    assert!(outcome.is_ok(), "{outcome:?}");
    Ok(())
}

#[test]
fn rejections_of_the_kdc_reply() -> Result<(), TestError> {
    let cases: [(Behaviour, fn(&Pkinit) -> bool); 5] = [
        (Behaviour::WrongSan, |error| {
            matches!(error, Pkinit::KdcName { .. })
        }),
        (Behaviour::Untrusted, |error| {
            matches!(error, Pkinit::Certificate { .. })
        }),
        (Behaviour::EncKeyPack, |error| {
            matches!(error, Pkinit::Policy(_))
        }),
        (Behaviour::WrongNonce, |error| {
            matches!(error, Pkinit::NonceMismatch { .. })
        }),
        (Behaviour::MalformedCms, |error| {
            matches!(error, Pkinit::Malformed { .. })
        }),
    ];
    for (behaviour, check) in cases {
        let mut kdc = Kdc::new(behaviour, true);
        let mut engine = InitCreds::with_pkinit(
            client(),
            exchange(CertificatePolicy::default())?,
            InitCredsOptions::new(request()?),
        );
        let outcome = run(&mut engine, &mut kdc)?;
        assert!(
            pkinit_error(&outcome).is_some_and(check),
            "{behaviour:?}: {outcome:?}"
        );
    }
    Ok(())
}

/// An anonymous exchange against `kdc`.
fn anonymous(kdc: &mut Kdc) -> Result<Result<Principal, ClientError>, TestError> {
    let options = InitCredsOptions::new(request()?).with_anonymous(AnonymousOptions::Full);
    let mut engine = InitCreds::with_pkinit(
        AnonymousOptions::client(REALM),
        Exchange::anonymous(
            KdcTrust::from_pem(CA_EC)?,
            CertificatePolicy::default().with_group(DhGroup::P256),
        ),
        options,
    );
    run(&mut engine, kdc)
}

#[test]
fn anonymous_pkinit_yields_the_anonymous_principal() -> Result<(), TestError> {
    // Given a KDC that issues fully anonymous tickets with PA-PKINIT-KX.
    let mut kdc = Kdc::new(Behaviour::Honest, true);
    // When the client asks for anonymous credentials.
    let outcome = anonymous(&mut kdc)?;
    // Then the ticket names WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS and no
    // certificate was sent.
    assert_eq!(
        outcome.map_err(|error| error.to_string())?,
        AnonymousOptions::Full.expected_client(REALM),
        "anonymous client"
    );
    assert!(!kdc.auth_packs().is_empty(), "an AuthPack was sent");
    Ok(())
}

#[test]
fn anonymous_reply_without_the_key_exchange_is_rejected() -> Result<(), TestError> {
    for behaviour in [Behaviour::MissingKx, Behaviour::WrongKx] {
        let mut kdc = Kdc::new(behaviour, true);
        let outcome = anonymous(&mut kdc)?;
        assert!(
            matches!(pkinit_error(&outcome), Some(Pkinit::Anonymous { .. })),
            "{behaviour:?}: {outcome:?}"
        );
    }
    Ok(())
}

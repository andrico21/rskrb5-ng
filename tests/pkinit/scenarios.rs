//! The PKINIT scenarios against the fake KDC.
//!
//! Certificate login, anonymous PKINIT, and every rejection the client owes (wrong EKU, wrong SAN,
//! untrusted chain, RSA key transport, wrong nonce, malformed CMS, a wrong
//! or missing anonymous key exchange).

use std::time::SystemTime;

use rskrb5_ng::{
    client::{
        AsRepSession,
        options::AsReq,
        principal::Principal,
        stepwise::{ExchangeStep, InitCreds, InitCredsOptions, StepInput},
    },
    error::{Client as ClientError, Pkinit},
    keytab::{EncryptionKey, Entry as KeytabEntry, Keytab, Principal as KeytabPrincipal},
    preauth::{
        fast::AnonymousArmor as _,
        pkinit::{
            AnonymousArmorSource, AnonymousOptions, CertificatePolicy, DhGroup, EkuChecking,
            Exchange, Identity, KDC_OPTION_REQUEST_ANONYMOUS, KdcTrust,
        },
    },
};

use crate::kdc::{
    Behaviour, CA_EC, CLIENT_KEY, CLIENT_PEM, FRESHNESS, Kdc, Naming, REALM, TestError, Transport,
    plain_reply,
};

/// A check of the PKINIT error a scenario ends with.
type Check = fn(&Pkinit) -> bool;

/// The request template: AES256 only.
fn request() -> AsReq {
    AsReq::new(SystemTime::now(), 0x1234_5678)
        .with_etypes(vec![18_i32])
        .with_fast_negotiation(false)
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
        InitCredsOptions::new(request()),
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
        InitCredsOptions::new(request()),
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
        InitCredsOptions::new(request()),
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
        InitCredsOptions::new(request()),
    );
    let outcome = run(&mut engine, &mut kdc)?;
    assert!(outcome.is_ok(), "{outcome:?}");
    Ok(())
}

#[test]
fn rejections_of_the_kdc_reply() -> Result<(), TestError> {
    let cases: [(Behaviour, Check); 5] = [
        (Behaviour::WrongSan, |error| {
            matches!(error, Pkinit::KdcName { realm: _ })
        }),
        (Behaviour::Untrusted, |error| {
            matches!(error, Pkinit::Certificate { reason: _ })
        }),
        (Behaviour::EncKeyPack, |error| {
            matches!(error, Pkinit::Policy(_))
        }),
        (Behaviour::WrongNonce, |error| {
            matches!(
                error,
                Pkinit::NonceMismatch {
                    expected: _,
                    actual: _
                }
            )
        }),
        (Behaviour::MalformedCms, |error| {
            matches!(
                error,
                Pkinit::Malformed {
                    structure: _,
                    reason: _
                }
            )
        }),
    ];
    for (behaviour, check) in cases {
        let mut kdc = Kdc::new(behaviour, true);
        let mut engine = InitCreds::with_pkinit(
            client(),
            exchange(CertificatePolicy::default())?,
            InitCredsOptions::new(request()),
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
    let options = InitCredsOptions::new(request()).with_anonymous(AnonymousOptions::Full);
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
            matches!(
                pkinit_error(&outcome),
                Some(Pkinit::Anonymous { reason: _ })
            ),
            "{behaviour:?}: {outcome:?}"
        );
    }
    Ok(())
}

#[test]
fn realm_exposed_anonymity_requires_the_anonymous_name() -> Result<(), TestError> {
    // Given a keytab client that asks for realm-exposed anonymity.
    let key = EncryptionKey::new(18, vec![0x21_u8; 32]);
    let mut keytab = Keytab::new();
    keytab.entries_mut().push(KeytabEntry::new(
        KeytabPrincipal::new(REALM, 1, vec!["pkinituser".to_owned()]),
        0,
        3,
        key.clone(),
        3,
    ));
    let options = InitCredsOptions::new(request()).with_anonymous(AnonymousOptions::RealmExposed);
    assert_ne!(
        options.request().kdc_option_bits() & KDC_OPTION_REQUEST_ANONYMOUS,
        0,
        "request-anonymous is set"
    );
    for (naming, accepted) in [(Naming::RealmExposed, true), (Naming::Client, false)] {
        let mut engine = InitCreds::with_keytab(client(), keytab.clone(), options.clone());
        let Ok(ExchangeStep::Outbound(outbound)) = engine.step(StepInput::Start) else {
            return Err("no request".into());
        };
        let reply = plain_reply(outbound.message(), &key, naming)?;
        // When the KDC names the client as `naming`, then only the anonymous
        // name in the client's realm completes.
        match engine.step(StepInput::Reply(&reply)) {
            Ok(ExchangeStep::Complete(session)) => {
                assert!(accepted, "{naming:?} completed");
                assert_eq!(
                    session.client(),
                    &AnonymousOptions::RealmExposed.expected_client(REALM),
                    "anonymous client"
                );
            }
            Err(ClientError::PrincipalMismatch {
                expected: _,
                actual: _,
            }) => assert!(!accepted, "{naming:?}"),
            other => return Err(format!("{naming:?}: {other:?}").into()),
        }
    }
    Ok(())
}

#[test]
fn anonymous_armor_source_obtains_an_anonymous_tgt() -> Result<(), TestError> {
    // Given the anonymous-armor provider over a blocking transport to the KDC.
    let mut source = AnonymousArmorSource::new(
        Transport(Kdc::new(Behaviour::Honest, true)),
        KdcTrust::from_pem(CA_EC)?,
        CertificatePolicy::default().with_group(DhGroup::P256),
    );
    // When FAST asks it for the realm's armor ticket.
    let ticket: AsRepSession = source
        .armor_ticket(REALM)
        .map_err(|error| error.to_string())?;
    // Then it is an anonymous TGT of the realm's TGS.
    assert_eq!(
        ticket.client(),
        &AnonymousOptions::Full.expected_client(REALM),
        "client"
    );
    assert_eq!(ticket.service(), &Principal::tgt_service(REALM), "service");
    Ok(())
}

//! FAST through the stepwise AS engine against the fake KDC.
//!
//! The armored encrypted-challenge login, every tamper rejection, the policies and the
//! authenticated canonicalization.

use core::error::Error as _;
use std::time::{SystemTime, UNIX_EPOCH};

use rasn::der;
use rskrb5_ng::{
    ccache::{
        CCache, Credential, CredentialTimes, EncryptionKey as CacheKey, Principal as CachePrincipal,
    },
    client::{
        AsRepSession, KDC_OPTION_CANONICALIZE,
        options::AsReq,
        principal::Principal,
        stepwise::{ExchangeStep, InitCreds, InitCredsOptions, StepInput},
    },
    error::{Client as ClientError, Fast},
    extensions::ProviderError,
    keytab::{Entry, Keytab, Principal as KeytabPrincipal},
    preauth::fast::{
        AnonymousArmor, ArmorCache, ArmorSource, Exchange, MAX_COOKIE_BYTES, Outcome,
        PA_ENCRYPTED_CHALLENGE, PA_FX_FAST, Policy,
    },
};

use super::kdc::{CLIENT, Kdc, REALM, Tamper, TestError};

/// The client's keytab.
fn keytab(kdc: &Kdc) -> Keytab {
    let mut keys = Keytab::new();
    for realm in [REALM, OTHER] {
        keys.entries_mut().push(Entry::new(
            KeytabPrincipal::new(realm, 1, vec![CLIENT.to_owned()]),
            1_893_553_440,
            1,
            kdc.client_key().clone(),
            1,
        ));
    }
    keys
}

/// The realm the referral tests are referred to.
const OTHER: &str = "OTHER.TEST";

/// An anonymous-armor provider (the hook todo 8 fills with anonymous PKINIT)
/// that hands out the KDC's armor TGT of whichever realm is asked for.
struct PerRealm(Vec<AsRepSession>);

impl AnonymousArmor for PerRealm {
    fn armor_ticket(&mut self, realm: &str) -> Result<AsRepSession, ProviderError> {
        self.0
            .iter()
            .find(|ticket| ticket.service().realm == realm)
            .cloned()
            .ok_or_else(|| format!("no armor for {realm}").into())
    }
}

/// The realm each request of `kdc` went to.
fn request_realms(kdc: &Kdc) -> Result<Vec<String>, TestError> {
    kdc.requests()
        .iter()
        .map(|request| {
            let rasn_kerberos::AsReq(outer) = der::decode(request)?;
            Ok(String::from_utf8(outer.req_body.realm.as_bytes().to_vec())?)
        })
        .collect()
}

/// Exchange options; `canonicalize` sets the KDC option.
fn options(canonicalize: bool) -> InitCredsOptions {
    let request = AsReq::new(SystemTime::now(), 0x2a2a_2a2a).with_etypes(vec![18_i32]);
    InitCredsOptions::new(if canonicalize {
        request.with_kdc_option_bits(KDC_OPTION_CANONICALIZE)
    } else {
        request
    })
}

/// Run a keytab exchange armored by `fast` against `kdc`.
fn login(
    kdc: &mut Kdc,
    fast: &mut Exchange,
    canonicalize: bool,
) -> Result<AsRepSession, ClientError> {
    let mut exchange = InitCreds::with_keytab(
        Principal::user(REALM, CLIENT),
        keytab(kdc),
        options(canonicalize),
    )
    .with_armor(fast);
    let mut step = exchange.step(StepInput::Start)?;
    loop {
        match step {
            ExchangeStep::Outbound(outbound) => {
                let reply = kdc
                    .handle(outbound.message())
                    .map_err(|error| ClientError::Transport(error.to_string()))?;
                step = exchange.step(StepInput::Reply(&reply))?;
            }
            ExchangeStep::Complete(session) => return Ok(*session),
            ExchangeStep::Prompt(_) | _ => {
                return Err(ClientError::Transport("unexpected step".to_owned()));
            }
        }
    }
}

/// An exchange under `policy` armored with the KDC's armor TGT.
fn armored(kdc: &Kdc, policy: Policy) -> Result<Exchange, TestError> {
    Ok(Exchange::new(
        policy,
        ArmorSource::Ticket(Box::new(kdc.armor_ticket()?)),
    ))
}

/// What a tamper case expects of the FAST failure.
type Expectation = fn(&Fast) -> bool;

/// The FAST failure inside an exchange error.
pub(crate) fn fast_cause(error: &ClientError) -> Option<&Fast> {
    let mut source = error.source();
    while let Some(current) = source {
        if let Some(fast) = current.downcast_ref::<Fast>() {
            return Some(fast);
        }
        source = current.source();
    }
    None
}

/// The armored encrypted-challenge login.
///
/// Two armored requests, the second answering the challenge with the KDC's cookie, and an armored AS-REP whose
/// finished message, KDC challenge, strengthen key and enc-pa-rep checksum
/// over the armored request all verify.
#[test]
fn required_fast_logs_in_with_the_encrypted_challenge() -> Result<(), TestError> {
    let mut kdc = Kdc::new();
    let mut fast = armored(&kdc, Policy::Required)?;
    let session = login(&mut kdc, &mut fast, false)?;
    assert_eq!(
        session.client(),
        &Principal::user(REALM, CLIENT),
        "the client"
    );
    assert!(
        kdc.challenge_verified(),
        "the KDC verified the encrypted challenge"
    );
    assert_eq!(kdc.requests().len(), 2, "one challenge round");
    for request in kdc.requests() {
        let rasn_kerberos::AsReq(outer) = der::decode(request)?;
        let types: Vec<i32> = outer
            .padata
            .unwrap_or_default()
            .iter()
            .map(|entry| entry.r#type)
            .collect();
        assert_eq!(
            types,
            vec![PA_FX_FAST],
            "the outer request carries only PA-FX-FAST"
        );
    }
    assert_eq!(fast.outcome(), Some(Outcome::Armored), "the outcome");
    fast.require_armored()?;
    Ok(())
}

/// Each tamper switch makes the exchange fail with the FAST failure naming the
/// broken rule, before any credential is released.
#[test]
fn tampered_replies_are_rejected() -> Result<(), TestError> {
    let cases: [(Tamper, Expectation); 13] = [
        (Tamper::DropFinished, |fast| {
            matches!(fast, Fast::MissingFinished)
        }),
        (Tamper::TicketChecksum, |fast| {
            matches!(fast, Fast::TicketChecksum)
        }),
        (Tamper::TicketChecksumType, |fast| {
            matches!(
                fast,
                Fast::Crypto(_)
                    | Fast::ChecksumType {
                        expected: _,
                        actual: _
                    }
            )
        }),
        (Tamper::Nonce, |fast| {
            matches!(
                fast,
                Fast::NonceMismatch {
                    expected: _,
                    actual: _
                }
            )
        }),
        (Tamper::DropKdcChallenge, |fast| {
            matches!(fast, Fast::ChallengeReply { what: _ })
        }),
        (Tamper::KdcChallengeKey, |fast| {
            matches!(fast, Fast::ChallengeReply { what: _ })
        }),
        (Tamper::DropStrengthenKey, |fast| {
            matches!(fast, Fast::ChallengeReply { what: _ })
        }),
        (Tamper::ErrorStrengthenKey, |fast| {
            matches!(
                fast,
                Fast::Malformed {
                    structure: _,
                    reason: _
                }
            )
        }),
        (Tamper::ErrorWithoutFxError, |fast| {
            matches!(
                fast,
                Fast::Malformed {
                    structure: _,
                    reason: _
                }
            )
        }),
        (Tamper::UnarmoredError, |fast| {
            matches!(fast, Fast::UnarmoredError { code: 25_i32 })
        }),
        (Tamper::UnarmoredReply, |fast| {
            matches!(fast, Fast::Unarmored)
        }),
        (
            Tamper::OversizedCookie,
            |fast| matches!(fast, Fast::CookieTooLarge { limit } if *limit == MAX_COOKIE_BYTES),
        ),
        (Tamper::ErrorCiphertext, |fast| {
            matches!(fast, Fast::Crypto(_))
        }),
    ];
    for (tamper, expected) in cases {
        let mut kdc = Kdc::tampering(tamper);
        let mut fast = armored(&kdc, Policy::Required)?;
        let error = login(&mut kdc, &mut fast, false)
            .err()
            .ok_or("tampered reply accepted")?;
        let cause = fast_cause(&error);
        assert!(cause.is_some_and(expected), "{tamper:?}: {error}");
    }
    Ok(())
}

/// A tampered reply ciphertext or strengthen key never yields a credential.
#[test]
fn tampered_reply_keys_are_rejected() -> Result<(), TestError> {
    for tamper in [Tamper::ReplyCiphertext, Tamper::StrengthenKey] {
        let mut kdc = Kdc::tampering(tamper);
        let mut fast = armored(&kdc, Policy::Required)?;
        assert!(
            login(&mut kdc, &mut fast, false).is_err(),
            "{tamper:?} accepted"
        );
    }
    Ok(())
}

/// QA failure scenario: under `Required` a KDC reply without
/// `KrbFastFinished` is rejected.
#[test]
fn required_rejects_a_reply_without_finished() -> Result<(), TestError> {
    let mut kdc = Kdc::tampering(Tamper::DropFinished);
    let mut fast = armored(&kdc, Policy::Required)?;
    let error = login(&mut kdc, &mut fast, false).err().ok_or("accepted")?;
    assert!(
        matches!(fast_cause(&error), Some(Fast::MissingFinished)),
        "{error}"
    );
    Ok(())
}

/// `Required` without armor fails before anything is sent.
#[test]
fn required_without_armor_sends_nothing() -> Result<(), TestError> {
    let mut kdc = Kdc::new();
    let mut fast = Exchange::new(Policy::Required, ArmorSource::None);
    let error = login(&mut kdc, &mut fast, false)
        .err()
        .ok_or("sent unarmored")?;
    assert!(
        matches!(
            fast_cause(&error),
            Some(Fast::ArmorUnavailable { realm: _ })
        ),
        "{error}"
    );
    assert!(kdc.requests().is_empty(), "nothing reached the KDC");
    assert!(fast.require_armored().is_err(), "no armored outcome");
    Ok(())
}

/// `Opportunistic` and `Off` without armor send the plain request and report
/// it; such an exchange never satisfies a caller that requires FAST.
#[test]
fn unarmored_exchanges_report_their_outcome() -> Result<(), TestError> {
    for policy in [Policy::Opportunistic, Policy::Off] {
        let kdc = Kdc::new();
        let source = if policy == Policy::Off {
            ArmorSource::Ticket(Box::new(kdc.armor_ticket()?))
        } else {
            ArmorSource::None
        };
        let mut fast = Exchange::new(policy, source);
        let mut exchange =
            InitCreds::with_keytab(Principal::user(REALM, CLIENT), keytab(&kdc), options(false))
                .with_armor(&mut fast);
        let ExchangeStep::Outbound(outbound) = exchange.step(StepInput::Start)? else {
            return Err("expected a request".into());
        };
        let rasn_kerberos::AsReq(request) = der::decode(outbound.message())?;
        assert!(
            !request
                .padata
                .unwrap_or_default()
                .iter()
                .any(|entry| entry.r#type == PA_FX_FAST),
            "{policy:?}: unarmored request"
        );
        drop(exchange);
        assert_eq!(fast.outcome(), Some(Outcome::Unarmored), "{policy:?}");
        assert!(
            matches!(fast.require_armored(), Err(Fast::NotArmored)),
            "{policy:?}"
        );
    }
    Ok(())
}

/// `Opportunistic` with armor runs armored and is as strict as `Required`.
#[test]
fn opportunistic_with_armor_is_armored_and_strict() -> Result<(), TestError> {
    let mut kdc = Kdc::new();
    let mut fast = armored(&kdc, Policy::Opportunistic)?;
    drop(login(&mut kdc, &mut fast, false)?);
    assert_eq!(fast.outcome(), Some(Outcome::Armored), "armored");
    let mut tampered = Kdc::tampering(Tamper::UnarmoredReply);
    let mut strict = armored(&tampered, Policy::Opportunistic)?;
    assert!(
        login(&mut tampered, &mut strict, false).is_err(),
        "no downgrade after armoring"
    );
    Ok(())
}

/// A client name the KDC canonicalized is accepted only when the caller asked
/// for canonicalization and FAST authenticated it.
#[test]
fn canonicalization_is_accepted_only_under_fast() -> Result<(), TestError> {
    let mut kdc = Kdc::canonicalizing("alice.canonical");
    let mut fast = armored(&kdc, Policy::Required)?;
    let session = login(&mut kdc, &mut fast, true)?;
    assert_eq!(
        session.client(),
        &Principal::user(REALM, "alice.canonical"),
        "the canonical client"
    );
    let rasn_kerberos::AsReq(outer) = der::decode(kdc.requests().first().ok_or("no request")?)?;
    let options = u32::from_be_bytes(outer.req_body.kdc_options.0.as_raw_slice().try_into()?);
    assert_ne!(
        options & KDC_OPTION_CANONICALIZE,
        0,
        "the armored request asks for canonicalization"
    );
    let mut strict = Kdc::canonicalizing("alice.canonical");
    let mut unasked = armored(&strict, Policy::Required)?;
    let error = login(&mut strict, &mut unasked, false)
        .err()
        .ok_or("changed client accepted")?;
    assert!(
        matches!(
            error,
            ClientError::PrincipalMismatch {
                expected: _,
                actual: _
            }
        ),
        "{error}"
    );
    Ok(())
}

/// A client referral (RFC 6806 section 7) is followed only when asked for and armored.
///
/// The caller asked for canonicalization and the armor authenticated the
/// referral; the referred realm is armored again, and without armor for it the
/// exchange fails closed.
#[test]
fn client_referrals_are_followed_only_when_armored_and_asked_for() -> Result<(), TestError> {
    let mut kdc = Kdc::referring(OTHER);
    let mut fast = Exchange::new(
        Policy::Required,
        ArmorSource::Anonymous(Box::new(PerRealm(vec![
            kdc.armor_ticket_in(REALM)?,
            kdc.armor_ticket_in(OTHER)?,
        ]))),
    );
    let session = login(&mut kdc, &mut fast, true)?;
    assert_eq!(
        session.client(),
        &Principal::user(OTHER, CLIENT),
        "the referred client"
    );
    assert_eq!(
        request_realms(&kdc)?,
        vec![REALM.to_owned(), OTHER.to_owned(), OTHER.to_owned()],
        "the referral restarts in the referred realm"
    );
    let mut unasked = Kdc::referring(OTHER);
    let mut plain = armored(&unasked, Policy::Required)?;
    let error = login(&mut unasked, &mut plain, false)
        .err()
        .ok_or("referral followed without canonicalize")?;
    assert_eq!(
        request_realms(&unasked)?,
        vec![REALM.to_owned()],
        "no restart: {error}"
    );
    let mut stranded = Kdc::referring(OTHER);
    let mut single = armored(&stranded, Policy::Required)?;
    let refused = login(&mut stranded, &mut single, true)
        .err()
        .ok_or("referred realm used without its armor")?;
    assert!(
        matches!(
            fast_cause(&refused),
            Some(Fast::ArmorTicket {
                realm: _,
                actual: _
            })
        ),
        "{refused}"
    );
    Ok(())
}

/// The encrypted challenge is sent only inside FAST, as the KDC offers it.
#[test]
fn the_challenge_travels_only_inside_the_armor() -> Result<(), TestError> {
    let mut kdc = Kdc::new();
    let mut fast = armored(&kdc, Policy::Required)?;
    drop(login(&mut kdc, &mut fast, false)?);
    for request in kdc.requests() {
        let rasn_kerberos::AsReq(outer) = der::decode(request)?;
        assert!(
            !outer
                .padata
                .unwrap_or_default()
                .iter()
                .any(|entry| entry.r#type == PA_ENCRYPTED_CHALLENGE),
            "no outer challenge"
        );
    }
    Ok(())
}

/// The armor cache yields its unexpired TGT of the realm, nothing else.
#[test]
fn the_armor_cache_yields_the_realm_tgt() -> Result<(), TestError> {
    let kdc = Kdc::new();
    let ticket = kdc.armor_ticket()?;
    let now = SystemTime::now();
    let seconds = |offset: i64| -> Result<u32, TestError> {
        let base = i64::try_from(now.duration_since(UNIX_EPOCH)?.as_secs())?;
        Ok(u32::try_from(base.checked_add(offset).ok_or("time")?)?)
    };
    let host = || {
        CachePrincipal::new(
            REALM,
            3,
            vec!["host".to_owned(), "armor.fast.test".to_owned()],
        )
    };
    let times = |end: u32| -> Result<CredentialTimes, TestError> {
        let mut value = CredentialTimes::default();
        value.auth_time = seconds(-60)?;
        value.start_time = value.auth_time;
        value.end_time = end;
        Ok(value)
    };
    let cache = |end: u32| -> Result<CCache, TestError> {
        let mut cache = CCache::new(host());
        cache.credentials_mut().push(Credential::new(
            host(),
            CachePrincipal::new(REALM, 2, vec!["krbtgt".to_owned(), REALM.to_owned()]),
            CacheKey::new(18, ticket.session_key().value().to_vec()),
            times(end)?,
            [0x40, 0x60, 0, 0],
            ticket.ticket().clone(),
        ));
        Ok(cache)
    };
    let live = ArmorCache::new(cache(seconds(3600)?)?);
    let armor = live.armor_ticket(REALM, now).ok_or("no armor ticket")?;
    assert_eq!(
        armor.service(),
        &Principal::tgt_service(REALM),
        "the realm TGT"
    );
    assert!(
        live.armor_ticket("OTHER.TEST", now).is_none(),
        "another realm"
    );
    let expired = ArmorCache::new(cache(seconds(-1)?)?);
    assert!(expired.armor_ticket(REALM, now).is_none(), "expired");
    Ok(())
}

/// Debug output of the FAST owners names no key or ticket byte.
#[test]
fn debug_output_is_redacted() -> Result<(), TestError> {
    let kdc = Kdc::new();
    let ticket = kdc.armor_ticket()?;
    let key = format!("{:?}", ticket.session_key().value());
    let mut fast = armored(&kdc, Policy::Required)?;
    let text = format!("{fast:?} {:?}", ArmorSource::Ticket(Box::new(ticket)));
    assert!(!text.contains(&key), "{text}");
    let mut kdc_two = Kdc::new();
    drop(login(&mut kdc_two, &mut fast, false));
    assert!(!format!("{fast:?}").contains("0x33"), "no key bytes");
    Ok(())
}

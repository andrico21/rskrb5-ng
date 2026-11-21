//! OTP through the stepwise AS engine against the fake FAST KDC.
//!
//! The login, the explicit factor choice, the PIN, and every refusal that must
//! happen before a request is sent.

use core::error::Error as _;
use std::time::SystemTime;

use rasn::types::BitString;
use rasn_kerberos::otp::{OtpFlags, OtpTokenInfo, PaOtpChallenge};
use rskrb5_ng::{
    client::{
        AsRepSession, KdcTransport,
        options::AsReq,
        principal::Principal,
        stepwise::{
            Answer, ExchangeStep, InitCreds, InitCredsOptions, NoResponder, Prompt, Responder as _,
            StepInput, drive,
        },
    },
    error::{Client as ClientError, Fast, Otp},
    extensions::ProviderError,
    preauth::{
        fast::{ArmorSource, Exchange, Policy as FastPolicy},
        otp::{self, Challenge, Policy, Responders, Response, Token},
    },
};

use super::kdc::{CLIENT, Kdc, Offer, PREAUTH_FAILED, REALM, TestError};

/// The OTP value the KDC accepts.
const VALUE: &[u8] = b"123456";

/// A token with these flag bits.
fn token(bits: &[usize]) -> OtpTokenInfo {
    let mut flags = BitString::repeat(false, 32);
    for &bit in bits {
        flags.set(bit, true);
    }
    OtpTokenInfo::new(OtpFlags(flags))
}

/// A KDC that offers these tokens and accepts [`VALUE`].
fn kdc(tokens: Vec<OtpTokenInfo>) -> Kdc {
    Kdc::new(
        Offer::Of(PaOtpChallenge::new(Vec::new().into(), tokens)),
        VALUE,
    )
}

/// Exchange options.
fn options() -> InitCredsOptions {
    InitCredsOptions::new(
        AsReq::new(SystemTime::now(), 0x2a2a_2a2a)
            .with_etypes(vec![18_i32])
            .with_assume_preauthentication(false),
    )
}

/// The client; it has no password and no keytab, only a token.
fn engine<'registry>() -> InitCreds<'registry> {
    InitCreds::with_password(Principal::user(REALM, CLIENT), None, options())
}

/// An exchange armored under `policy` with the KDC's armor TGT.
fn armored(kdc: &Kdc, policy: FastPolicy) -> Result<Exchange, TestError> {
    Ok(Exchange::new(
        policy,
        ArmorSource::Ticket(Box::new(kdc.armor_ticket()?)),
    ))
}

/// The next request of `step`.
fn outbound(step: &ExchangeStep) -> Result<Vec<u8>, TestError> {
    match step {
        ExchangeStep::Outbound(outbound) => Ok(outbound.message().to_vec()),
        ExchangeStep::Prompt(_) | ExchangeStep::Complete(_) | _ => {
            Err(format!("expected a request, got {step:?}").into())
        }
    }
}

/// Run the exchange to the OTP prompt: the challenge the engine asks about.
fn prompted(
    exchange: &mut InitCreds<'_>,
    kdc: &mut Kdc,
) -> Result<(Principal, Challenge), TestError> {
    let first = outbound(&exchange.step(StepInput::Start)?)?;
    let reply = kdc.handle(&first)?;
    match exchange.step(StepInput::Reply(&reply))? {
        ExchangeStep::Prompt(Prompt::Otp { client, challenge }) => Ok((client, challenge)),
        step @ (ExchangeStep::Outbound(_) | ExchangeStep::Complete(_) | _) => {
            Err(format!("expected an OTP prompt, got {step:?}").into())
        }
    }
}

/// Answer the prompt with `response` and run to the end.
fn finish(
    exchange: &mut InitCreds<'_>,
    kdc: &mut Kdc,
    response: Response,
) -> Result<AsRepSession, ClientError> {
    let mut step = exchange.step(StepInput::Answer(Answer::Otp(response)))?;
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

/// The OTP failure inside an exchange error.
fn otp_cause(error: &ClientError) -> Option<&Otp> {
    if let ClientError::Otp(otp) = error {
        return Some(otp);
    }
    let mut source = error.source();
    while let Some(current) = source {
        if let Some(otp) = current.downcast_ref::<Otp>() {
            return Some(otp);
        }
        source = current.source();
    }
    None
}

/// Happy path: the OTP login inside FAST.
///
/// The engine asks about the challenge, never about a password, sends one OTP
/// request armored under the conversation's armor key, and decrypts the armored
/// AS-REP in that key (RFC 6560 section 3.6).
#[test]
fn otp_login_inside_fast_completes() -> Result<(), TestError> {
    let mut kdc = kdc(vec![token(&[])]);
    let mut fast = armored(&kdc, FastPolicy::Required)?;
    let mut exchange = engine().with_armor(&mut fast).with_otp(Policy::default());
    let (client, challenge) = prompted(&mut exchange, &mut kdc)?;
    assert_eq!(client, Principal::user(REALM, CLIENT));
    assert_eq!(challenge.tokens().len(), 1);
    let session = finish(&mut exchange, &mut kdc, Response::new(0, VALUE.to_vec()))?;
    assert_eq!(session.client(), &Principal::user(REALM, CLIENT));
    drop(exchange);
    assert!(kdc.accepted());
    assert_eq!(kdc.requests().len(), 2, "the probe and the OTP request");
    let seen = kdc.seen().ok_or("the KDC saw no OTP request")?;
    assert_eq!(seen.otp_value.as_deref(), Some(VALUE));
    fast.require_armored()?;
    Ok(())
}

/// A wrong value is the KDC's `PREAUTH_FAILED`: one attempt, no automatic retry
/// (a retry could lock the account), and nothing is cached.
#[test]
fn a_refused_value_ends_the_exchange() -> Result<(), TestError> {
    let mut kdc = kdc(vec![token(&[])]);
    let mut fast = armored(&kdc, FastPolicy::Required)?;
    let mut exchange = engine().with_armor(&mut fast).with_otp(Policy::default());
    drop(prompted(&mut exchange, &mut kdc)?);
    let error = finish(
        &mut exchange,
        &mut kdc,
        Response::new(0, b"654321".to_vec()),
    )
    .err()
    .ok_or("a wrong value was accepted")?;
    assert!(
        matches!(&error, ClientError::Kdc(kdc_error) if kdc_error.error_code() == PREAUTH_FAILED),
        "{error}"
    );
    assert!(!kdc.accepted());
    assert_eq!(kdc.requests().len(), 2);
    assert!(matches!(
        exchange.step(StepInput::Start),
        Err(ClientError::UnexpectedStepInput { expected: _ })
    ));
    Ok(())
}

/// The user chooses among several factors through the answer: the engine never
/// picks one, and the request names exactly the chosen token.
#[test]
fn the_answer_selects_the_token() -> Result<(), TestError> {
    let mut tokens = Vec::new();
    for vendor in ["First Corp", "Second Corp"] {
        let mut info = token(&[]);
        info.otp_vendor = Some(vendor.to_owned());
        tokens.push(info);
    }
    let mut kdc = kdc(tokens);
    let mut fast = armored(&kdc, FastPolicy::Required)?;
    let mut exchange = engine().with_armor(&mut fast).with_otp(Policy::default());
    let (_, challenge) = prompted(&mut exchange, &mut kdc)?;
    assert_eq!(
        challenge
            .tokens()
            .iter()
            .map(Token::vendor)
            .collect::<Vec<_>>(),
        [Some("First Corp"), Some("Second Corp")]
    );
    drop(finish(
        &mut exchange,
        &mut kdc,
        Response::new(1, VALUE.to_vec()),
    )?);
    let seen = kdc.seen().ok_or("no OTP request")?;
    assert_eq!(seen.otp_vendor.as_deref(), Some("Second Corp"));
    Ok(())
}

/// A separate PIN travels in `otp-pin`; the value alone is `otp-value`.
#[test]
fn a_separate_pin_is_sent_in_its_own_field() -> Result<(), TestError> {
    let mut kdc = kdc(vec![token(&[3, 6])]);
    let mut fast = armored(&kdc, FastPolicy::Required)?;
    let mut exchange = engine().with_armor(&mut fast).with_otp(Policy::default());
    drop(prompted(&mut exchange, &mut kdc)?);
    let response = Response::new(0, VALUE.to_vec()).with_pin("4242".to_owned());
    drop(finish(&mut exchange, &mut kdc, response)?);
    let seen = kdc.seen().ok_or("no OTP request")?;
    assert_eq!(seen.otp_pin.as_deref(), Some("4242"));
    assert_eq!(seen.otp_value.as_deref(), Some(VALUE));
    Ok(())
}

/// An answer the challenge does not allow ends the exchange before another request
/// is sent.
#[test]
fn an_invalid_answer_sends_nothing() -> Result<(), TestError> {
    let mut kdc = kdc(vec![token(&[4])]);
    let mut fast = armored(&kdc, FastPolicy::Required)?;
    let mut exchange = engine().with_armor(&mut fast).with_otp(Policy::default());
    drop(prompted(&mut exchange, &mut kdc)?);
    let response = Response::new(0, VALUE.to_vec()).with_pin("4242".to_owned());
    let error = exchange
        .step(StepInput::Answer(Answer::Otp(response)))
        .err()
        .ok_or("a PIN for a token that collects none was sent")?;
    assert!(
        matches!(otp_cause(&error), Some(Otp::PinNotCollected)),
        "{error}"
    );
    assert_eq!(kdc.requests().len(), 1);
    Ok(())
}

/// QA failure scenario: OTP requested without any FAST fails before anything is sent.
#[test]
fn otp_without_fast_fails_before_sending() -> Result<(), TestError> {
    let mut exchange = engine().with_otp(Policy::default());
    let error = exchange
        .step(StepInput::Start)
        .err()
        .ok_or("the first request went out unarmored")?;
    assert!(
        matches!(otp_cause(&error), Some(Otp::ArmorRequired)),
        "{error}"
    );
    Ok(())
}

/// QA failure scenario: OTP under a FAST policy that finds no armor fails before
/// anything is sent, with FAST's own refusal.
#[test]
fn otp_with_required_fast_and_no_armor_fails_before_sending() -> Result<(), TestError> {
    let mut fast = Exchange::new(FastPolicy::Required, ArmorSource::None);
    let mut exchange = engine().with_armor(&mut fast).with_otp(Policy::default());
    let error = exchange
        .step(StepInput::Start)
        .err()
        .ok_or("the first request went out unarmored")?;
    assert!(
        matches!(&error, ClientError::Armor(_)) && otp_cause(&error).is_none(),
        "{error}"
    );
    drop(exchange);
    assert!(matches!(fast.require_armored(), Err(Fast::NotArmored)));
    Ok(())
}

/// A challenge in a reply that no armor protected is never answered: an
/// opportunistic exchange that ran unarmored refuses it before the OTP request.
#[test]
fn an_unarmored_challenge_is_never_answered() -> Result<(), TestError> {
    let mut kdc = kdc(vec![token(&[])]);
    let mut fast = Exchange::new(FastPolicy::Opportunistic, ArmorSource::None);
    let mut exchange = engine().with_armor(&mut fast).with_otp(Policy::default());
    let first = outbound(&exchange.step(StepInput::Start)?)?;
    let reply = kdc.plain_challenge(&first)?;
    let error = exchange
        .step(StepInput::Reply(&reply))
        .err()
        .ok_or("an unarmored challenge was answered")?;
    assert!(
        matches!(otp_cause(&error), Some(Otp::ArmorRequired)),
        "{error}"
    );
    Ok(())
}

/// Without an OTP policy the offer is not answered: the engine falls back to the
/// password prompt instead of choosing OTP silently.
#[test]
fn otp_is_never_answered_unasked() -> Result<(), TestError> {
    let mut kdc = kdc(vec![token(&[])]);
    let mut fast = armored(&kdc, FastPolicy::Required)?;
    let mut exchange = engine().with_armor(&mut fast);
    let first = outbound(&exchange.step(StepInput::Start)?)?;
    let reply = kdc.handle(&first)?;
    assert!(matches!(
        exchange.step(StepInput::Reply(&reply))?,
        ExchangeStep::Prompt(Prompt::Password { client: _ })
    ));
    Ok(())
}

/// A challenge repeated in one reply is ambiguous and refused; an oversized one is
/// refused by the policy before it is decoded; bounds apply to the engine.
#[test]
fn bad_challenges_end_the_exchange() -> Result<(), TestError> {
    let cases = [
        (
            kdc(vec![token(&[])]).offering(2),
            Policy::default(),
            "repeated",
        ),
        (
            kdc(vec![token(&[]); 4]),
            Policy::default().with_max_tokens(3),
            "tokens",
        ),
        (
            Kdc::new(Offer::Raw(vec![0x30; 600]), VALUE),
            Policy::default().with_max_challenge_bytes(512),
            "size",
        ),
        (kdc(vec![token(&[1])]), Policy::default(), "unsupported"),
    ];
    for (mut kdc, policy, case) in cases {
        let mut fast = armored(&kdc, FastPolicy::Required)?;
        let mut exchange = engine().with_armor(&mut fast).with_otp(policy);
        let first = outbound(&exchange.step(StepInput::Start)?)?;
        let reply = kdc.handle(&first)?;
        let error = exchange
            .step(StepInput::Reply(&reply))
            .err()
            .ok_or("a bad challenge was accepted")?;
        let found = otp_cause(&error).ok_or("no OTP failure")?;
        let expected = match case {
            "repeated" => matches!(found, Otp::RepeatedChallenge),
            "tokens" => matches!(found, Otp::TooManyTokens { limit: 3 }),
            "size" => matches!(found, Otp::ChallengeTooLarge { limit: 512 }),
            _ => matches!(found, Otp::NoSupportedTokens { dropped: 1 }),
        };
        assert!(expected, "{case}: {found}");
        assert_eq!(kdc.requests().len(), 1, "{case}: nothing more was sent");
    }
    Ok(())
}

/// Answers from the wrong prompt or the wrong state are refused.
#[test]
fn an_unexpected_otp_answer_is_refused() -> Result<(), TestError> {
    let mut exchange = engine().with_otp(Policy::default());
    let error = exchange
        .step(StepInput::Answer(Answer::Otp(Response::new(
            0,
            VALUE.to_vec(),
        ))))
        .err()
        .ok_or("an answer to nothing was accepted")?;
    assert!(
        matches!(error, ClientError::UnexpectedStepInput { expected: _ }),
        "{error}"
    );
    Ok(())
}

/// A transport over the fake KDC.
struct Wire(Kdc);

impl KdcTransport for Wire {
    fn send(&mut self, _realm: &str, request: &[u8]) -> Result<Vec<u8>, ClientError> {
        self.0
            .handle(request)
            .map_err(|error| ClientError::Transport(error.to_string()))
    }
}

/// A user that picks the second token and types a value.
struct Typist {
    /// The challenges the user saw.
    saw: Vec<usize>,
}

impl otp::Responder for Typist {
    fn select(&mut self, challenge: &Challenge) -> Result<Response, ProviderError> {
        self.saw.push(challenge.tokens().len());
        Ok(Response::new(1, VALUE.to_vec()))
    }
}

/// [`Responders`] routes OTP prompts to the [`Responder`] and keeps every other
/// prompt with the wrapped responder; `drive` completes the login.
#[test]
fn the_responder_adapter_drives_a_login() -> Result<(), TestError> {
    let mut wire = Wire(kdc(vec![token(&[]), token(&[])]));
    let mut fast = armored(&wire.0, FastPolicy::Required)?;
    let mut exchange = engine().with_armor(&mut fast).with_otp(Policy::default());
    let mut responder = Responders::new(NoResponder::default(), Typist { saw: Vec::new() });
    let session = drive(&mut wire, &mut exchange, &mut responder)?;
    assert_eq!(session.client(), &Principal::user(REALM, CLIENT));
    assert_eq!(responder.otp().saw, [2]);
    let error = responder
        .respond(&Prompt::Password {
            client: Principal::user(REALM, CLIENT),
        })
        .err()
        .ok_or("the wrapped responder was bypassed")?;
    assert!(error.to_string().contains("no responder"), "{error}");
    Ok(())
}

/// The finished credential is the only thing the exchange keeps: its `Debug`
/// output names neither the value nor the PIN.
#[test]
fn the_exchange_keeps_no_secret() -> Result<(), TestError> {
    let mut kdc = kdc(vec![token(&[3, 6])]);
    let mut fast = armored(&kdc, FastPolicy::Required)?;
    let mut exchange = engine().with_armor(&mut fast).with_otp(Policy::default());
    drop(prompted(&mut exchange, &mut kdc)?);
    let response = Response::new(0, b"s3cr3t-value".to_vec()).with_pin("s3cr3t-pin".to_owned());
    let answer = Answer::Otp(response);
    assert_eq!(format!("{answer:?}"), "Answer::Otp([REDACTED])");
    let step = exchange.step(StepInput::Answer(answer));
    let text = format!("{exchange:?} {step:?}");
    for secret in ["s3cr3t-value", "s3cr3t-pin"] {
        assert!(!text.contains(secret), "{text}");
    }
    Ok(())
}

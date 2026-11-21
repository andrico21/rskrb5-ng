//! OTP against MIT krb5 1.22.2 and its RADIUS backend: the login inside FAST, the
//! `otp` indicator only that login earns, and the refusals.

use core::{error::Error, time::Duration};
use std::{
    io,
    time::{SystemTime, UNIX_EPOCH},
};

use rasn::der;
use rskrb5_ng::{
    client::{
        AsRepSession, Password,
        options::TgsReq,
        principal::Principal,
        stepwise::{
            Answer, ExchangeStep, InitCreds, InitCredsOptions, NoResponder, Prompt, Responder as _,
            StepInput, TicketCreds, TicketOptions, drive_tokio,
        },
        transport::{KdcProtocol, Tokio as KdcTransport},
    },
    config::Config,
    error::Client as ClientError,
    extensions::ProviderError,
    keytab::Keytab,
    preauth::{
        fast::{ArmorSource, Exchange, Outcome, PA_FX_FAST, Policy as FastPolicy},
        otp::{self, Challenge, Policy, Responders, Response},
    },
};
use tokio::runtime::{Builder, Runtime};

use crate::harness::{self, Fixture, assert_negotiated_padata};

/// The TEST.RSKRB5 KDC (fixture `mit-kdc`).
const MIT_KDC: Fixture = Fixture::new("mit-kdc", "INTEROP_MIT_KDC");

/// The current-thread Tokio runtime the scenarios run on.
fn runtime() -> io::Result<Runtime> {
    Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
}

/// A KDC transport with a ten-second timeout.
fn transport() -> KdcTransport {
    KdcTransport::new().with_timeout(Duration::from_secs(10))
}

/// A nonce unique to `sequence` and the current time.
fn nonce(sequence: u32) -> Result<u32, Box<dyn Error>> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH)?;
    Ok(u32::try_from(elapsed.as_nanos() & 0x00ff_ffff)? | sequence.wrapping_shl(24))
}

/// The TEST.RSKRB5 realm.
///
/// The realm also offers SPAKE (`krb5.conf.d/30-spake.conf`), which the client answers
/// before any other factor, so an empty group list keeps these scenarios on OTP, the only
/// factor that earns the `otp` indicator (the exchange and FAST suites do the same).
fn config() -> Result<Config, Box<dyn Error>> {
    let realm = harness::var("INTEROP_MIT_REALM")?;
    Ok(Config::parse(&format!(
        "[libdefaults]\n default_realm = {realm}\n dns_lookup_kdc = false\n spake_preauth_groups =\n\
         [realms]\n {realm} = {{\n  kdc = {}\n }}\n",
        harness::var("INTEROP_MIT_KDC")?,
    ))?)
}

/// The armor TGT: testuser1 from its keytab, unarmored.
async fn armor_tgt(config: &Config) -> Result<AsRepSession, Box<dyn Error>> {
    let client = Principal::user(
        harness::var("INTEROP_MIT_REALM")?,
        harness::var("INTEROP_MIT_USER")?,
    );
    let keytab = Keytab::load(harness::var("INTEROP_MIT_USER_KEYTAB")?)?;
    let options = InitCredsOptions::from_config(config, SystemTime::now(), nonce(1)?)?;
    let mut exchange = InitCreds::with_keytab(client, keytab, options);
    Ok(drive_tokio(
        &transport(),
        (config, KdcProtocol::Tcp),
        &mut exchange,
        &mut NoResponder::default(),
    )
    .await?)
}

/// A user that reads the token's value from the run's secret and records the choice
/// the KDC offered.
struct Token {
    /// The value to answer with.
    value: String,
    /// The number of tokens of each challenge this user was shown.
    shown: Vec<usize>,
}

impl otp::Responder for Token {
    fn select(&mut self, challenge: &Challenge) -> Result<Response, ProviderError> {
        self.shown.push(challenge.tokens().len());
        Ok(Response::new(0, self.value.clone().into_bytes()))
    }
}

/// otpuser's login armored by `fast`, answering the OTP challenge with `value`.
///
/// Returns the credential and the outer PA types of every request it sent. The
/// password responder is [`NoResponder`], so a password prompt (the encrypted
/// challenge or timestamp) fails the login instead of answering it.
async fn otpuser_login(
    config: &Config,
    fast: &mut Exchange,
    (value, sequence): (String, u32),
) -> Result<(AsRepSession, Vec<Vec<i32>>, Vec<usize>), Box<dyn Error>> {
    let client = Principal::user(
        harness::var("INTEROP_MIT_REALM")?,
        harness::var("INTEROP_MIT_OTP_USER")?,
    );
    let options = InitCredsOptions::from_config(config, SystemTime::now(), nonce(sequence)?)?;
    let mut exchange = InitCreds::with_password(client, None, options)
        .with_armor(fast)
        .with_otp(Policy::default());
    let mut responder = Responders::new(
        NoResponder::default(),
        Token {
            value,
            shown: Vec::new(),
        },
    );
    let mut requests = Vec::new();
    let mut reply: Option<Vec<u8>> = None;
    let mut answer: Option<Answer> = None;
    let session = loop {
        let input = match (answer.take(), reply.as_deref()) {
            (Some(pending), _) => StepInput::Answer(pending),
            (None, Some(bytes)) => StepInput::Reply(bytes),
            (None, None) => StepInput::Start,
        };
        match exchange.step(input)? {
            ExchangeStep::Outbound(outbound) => {
                let request: rasn_kerberos::AsReq = der::decode(outbound.message())?;
                requests.push(
                    request
                        .0
                        .padata
                        .iter()
                        .flatten()
                        .map(|entry| entry.r#type)
                        .collect(),
                );
                reply = Some(
                    transport()
                        .send_to_realm(
                            config,
                            KdcProtocol::Tcp,
                            outbound.realm(),
                            outbound.message(),
                        )
                        .await?,
                );
            }
            ExchangeStep::Prompt(prompt) => {
                answer = Some(responder.respond(&prompt).map_err(ClientError::Responder)?);
            }
            ExchangeStep::Complete(session) => break session,
            _ => return Err("unexpected exchange step".into()),
        }
    };
    Ok((*session, requests, responder.otp().shown.clone()))
}

/// A ticket for the service that requires the `otp` indicator.
async fn otp_required_ticket(
    config: &Config,
    tgt: AsRepSession,
    sequence: u32,
) -> Result<AsRepSession, Box<dyn Error>> {
    let service = Principal::new(
        harness::var("INTEROP_MIT_REALM")?,
        2,
        harness::var("INTEROP_MIT_OTP_REQUIRED_SERVICE")?.split('/'),
    );
    let options =
        TgsReq::from_libdefaults(SystemTime::now(), nonce(sequence)?, &config.libdefaults)?;
    let mut exchange = TicketCreds::new(tgt, service, TicketOptions::new(options))?;
    Ok(drive_tokio(
        &transport(),
        (config, KdcProtocol::Tcp),
        &mut exchange,
        &mut NoResponder::default(),
    )
    .await?)
}

/// An armor that is required and comes from testuser1's TGT.
async fn required_armor(config: &Config) -> Result<Exchange, Box<dyn Error>> {
    Ok(Exchange::new(
        FastPolicy::Required,
        ArmorSource::Ticket(Box::new(armor_tgt(config).await?)),
    ))
}

/// otpuser logs in with the token RADIUS accepts, inside `Required` FAST.
///
/// Every request carries only `PA-FX-FAST` outside the armor, the one OTP prompt is answered
/// by the user, no password is asked for, and the `otp` indicator the KDC adds after RADIUS
/// accepted the token earns the `require_auth = otp` service ticket: only the OTP factor can
/// have answered (the realm's SPAKE is off in the profile, and the password factors would
/// have prompted for a password this user does not have).
#[test]
fn otp_login_inside_fast_earns_the_otp_indicator() -> Result<(), Box<dyn Error>> {
    if !harness::require("otp_login_inside_fast_earns_the_otp_indicator", &[MIT_KDC])? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let config = config()?;
        let mut fast = required_armor(&config).await?;
        let token = harness::var("INTEROP_MIT_OTP_TOKEN")?;
        let (session, requests, shown) = otpuser_login(&config, &mut fast, (token, 2)).await?;
        assert_eq!(fast.outcome(), Some(Outcome::Armored));
        assert_eq!(shown, [1], "one OTP prompt with the KDC's single token");
        assert!(requests.len() >= 2, "a challenge round: {requests:?}");
        for request in &requests {
            assert_negotiated_padata("an armored AS-REQ", PA_FX_FAST, request)?;
            assert_eq!(
                request.len(),
                1,
                "only PA-FX-FAST outside the armor: {request:?}"
            );
        }
        assert_eq!(
            session.client().components,
            vec![harness::var("INTEROP_MIT_OTP_USER")?],
            "the authenticated client"
        );
        let ticket = otp_required_ticket(&config, session, 3).await?;
        assert_eq!(
            ticket.service().components.first().map(String::as_str),
            Some("otprequired"),
            "the otp-indicator service ticket"
        );
        Ok(())
    })
}

/// RADIUS refuses a wrong token and the exchange ends with the KDC's refusal.
///
/// The value is tried once (no retry), the KDC answers `KDC_ERR_PREAUTH_FAILED`
/// and no credential results.
#[test]
fn a_wrong_token_value_is_refused() -> Result<(), Box<dyn Error>> {
    if !harness::require("a_wrong_token_value_is_refused", &[MIT_KDC])? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let config = config()?;
        let mut fast = required_armor(&config).await?;
        let wrong = format!("{}x", harness::var("INTEROP_MIT_OTP_TOKEN")?);
        let error = otpuser_login(&config, &mut fast, (wrong, 4))
            .await
            .err()
            .ok_or("RADIUS accepted a wrong token")?;
        let text = error.to_string();
        assert!(
            error.downcast_ref::<ClientError>().is_some_and(
                |found| matches!(found, ClientError::Kdc(kdc) if kdc.error_code() == 24_i32)
            ),
            "the KDC's PREAUTH_FAILED, got: {text}"
        );
        Ok(())
    })
}

/// Without FAST the KDC never offers OTP and the user's keys are unknown, so a
/// password exchange fails with the KDC's error, not with an OTP prompt.
#[test]
fn without_fast_no_otp_is_offered() -> Result<(), Box<dyn Error>> {
    if !harness::require("without_fast_no_otp_is_offered", &[MIT_KDC])? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let config = config()?;
        let client = Principal::user(
            harness::var("INTEROP_MIT_REALM")?,
            harness::var("INTEROP_MIT_OTP_USER")?,
        );
        let token = Password::from_vec(harness::var("INTEROP_MIT_OTP_TOKEN")?.into_bytes());
        let options = InitCredsOptions::from_config(&config, SystemTime::now(), nonce(5)?)?;
        let mut exchange = InitCreds::with_password(client, Some(token), options);
        let mut prompts = 0_usize;
        let mut reply: Option<Vec<u8>> = None;
        let outcome = loop {
            let input = reply.as_deref().map_or(StepInput::Start, StepInput::Reply);
            match exchange.step(input) {
                Ok(ExchangeStep::Outbound(outbound)) => {
                    reply = Some(
                        transport()
                            .send_to_realm(
                                &config,
                                KdcProtocol::Tcp,
                                outbound.realm(),
                                outbound.message(),
                            )
                            .await?,
                    );
                }
                Ok(ExchangeStep::Prompt(Prompt::Otp {
                    client: _,
                    challenge: _,
                })) => {
                    return Err("OTP was offered without FAST".into());
                }
                Ok(ExchangeStep::Prompt(_)) => prompts += 1,
                Ok(ExchangeStep::Complete(_)) => {
                    return Err("an unarmored OTP login succeeded".into());
                }
                Ok(_) => return Err("unexpected exchange step".into()),
                Err(error) => break error,
            }
        };
        assert_eq!(prompts, 0);
        assert!(
            matches!(outcome, ClientError::Kdc(_)),
            "the KDC's refusal, got: {outcome}"
        );
        Ok(())
    })
}

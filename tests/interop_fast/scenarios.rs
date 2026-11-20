//! FAST against MIT krb5 1.22.2: an armored encrypted-challenge login and the
//! `fast-ec` indicator only that login earns.

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
            ExchangeStep, InitCreds, InitCredsOptions, NoResponder, StepInput, TicketCreds,
            TicketOptions, drive_tokio,
        },
        transport::{KdcProtocol, Tokio as KdcTransport},
    },
    config::Config,
    keytab::Keytab,
    preauth::fast::{ArmorSource, Exchange, Outcome, PA_FX_FAST, Policy},
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
/// The realm also offers SPAKE (`krb5.conf.d/30-spake.conf`), and the client answers SPAKE
/// before the encrypted challenge even inside FAST (as MIT's does), so an empty group list
/// keeps these scenarios on the encrypted challenge, the only factor that earns the `fast-ec`
/// indicator (the exchange suite does the same).
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

/// fastuser's password exchange, armored by `fast` when given, with the
/// outer PA types of every request it sent.
async fn fastuser_login(
    config: &Config,
    fast: Option<&mut Exchange>,
    sequence: u32,
) -> Result<(AsRepSession, Vec<Vec<i32>>), Box<dyn Error>> {
    let client = Principal::user(
        harness::var("INTEROP_MIT_REALM")?,
        harness::var("INTEROP_MIT_FAST_USER")?,
    );
    let password = Password::from_vec(harness::var("INTEROP_MIT_FAST_USER_PASSWORD")?.into_bytes());
    let options = InitCredsOptions::from_config(config, SystemTime::now(), nonce(sequence)?)?;
    let plain = InitCreds::with_password(client, Some(password), options);
    let mut exchange = match fast {
        Some(armor) => plain.with_armor(armor),
        None => plain,
    };
    let mut requests = Vec::new();
    let mut reply: Option<Vec<u8>> = None;
    let session = loop {
        let input = reply.as_deref().map_or(StepInput::Start, StepInput::Reply);
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
            ExchangeStep::Complete(session) => break session,
            ExchangeStep::Prompt(_) | _ => return Err("unexpected exchange step".into()),
        }
    };
    Ok((*session, requests))
}

/// A ticket for the service that requires the `fast-ec` indicator.
async fn fast_required_ticket(
    config: &Config,
    tgt: AsRepSession,
    sequence: u32,
) -> Result<AsRepSession, Box<dyn Error>> {
    let service = Principal::new(
        harness::var("INTEROP_MIT_REALM")?,
        2,
        harness::var("INTEROP_MIT_FAST_REQUIRED_SERVICE")?.split('/'),
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

/// fastuser logs in with `Required` FAST.
///
/// Every request carries only `PA-FX-FAST`, the KDC's armored `PREAUTH_REQUIRED` is answered with the
/// encrypted challenge, and the armored AS-REP's finished message, KDC
/// challenge and strengthened reply key verify.
#[test]
fn encrypted_challenge_login_is_armored() -> Result<(), Box<dyn Error>> {
    if !harness::require("encrypted_challenge_login_is_armored", &[MIT_KDC])? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let config = config()?;
        let mut fast = Exchange::new(
            Policy::Required,
            ArmorSource::Ticket(Box::new(armor_tgt(&config).await?)),
        );
        let (session, requests) = fastuser_login(&config, Some(&mut fast), 2).await?;
        assert_eq!(fast.outcome(), Some(Outcome::Armored), "the FAST outcome");
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
            vec![harness::var("INTEROP_MIT_FAST_USER")?],
            "the authenticated client"
        );
        Ok(())
    })
}

/// Only the TGT of the armored encrypted-challenge login carries `fast-ec`.
///
/// With it the KDC issues the `require_auth = fast-ec` service ticket, with
/// the TGT of an unarmored encrypted-timestamp login it refuses.
#[test]
fn fast_required_service_needs_the_fast_ec_indicator() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "fast_required_service_needs_the_fast_ec_indicator",
        &[MIT_KDC],
    )? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let config = config()?;
        let mut fast = Exchange::new(
            Policy::Required,
            ArmorSource::Ticket(Box::new(armor_tgt(&config).await?)),
        );
        let (armored, _) = fastuser_login(&config, Some(&mut fast), 3).await?;
        let ticket = fast_required_ticket(&config, armored, 4).await?;
        assert_eq!(
            ticket.service().components.first().map(String::as_str),
            Some("fastrequired"),
            "the fast-ec service ticket"
        );
        let (plain, requests) = fastuser_login(&config, None, 5).await?;
        assert!(
            requests
                .iter()
                .all(|request| !request.contains(&PA_FX_FAST)),
            "the comparison login is unarmored: {requests:?}"
        );
        assert!(
            fast_required_ticket(&config, plain, 6).await.is_err(),
            "an unarmored TGT must not earn the fast-ec indicator"
        );
        Ok(())
    })
}

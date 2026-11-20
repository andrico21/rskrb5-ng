//! SPAKE logins against MIT.
//!
//! The default group runs through the Tokio login function with encrypted
//! timestamp disabled, every NIST group through the stepwise engine, and the
//! controls run without SPAKE.

use core::{error::Error, time::Duration};
use std::{
    io,
    time::{SystemTime, UNIX_EPOCH},
};

use rskrb5_ng::{
    client::{
        AsRepSession, Password,
        options::{AsReq, TgsReq},
        principal::Principal,
        stepwise::{
            InitCreds, InitCredsOptions, NoResponder, TicketCreds, TicketOptions, drive_tokio,
        },
        transport::{KdcProtocol, Tokio as KdcTransport},
    },
    config::Config,
    error::Client as ClientError,
};
use tokio::runtime::{Builder, Runtime};

use crate::harness::{self, Fixture};

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

/// The realm profile with `libdefaults` lines and `realm` relations added.
fn config(libdefaults: &str, realm_lines: &str) -> Result<Config, Box<dyn Error>> {
    let realm = harness::var("INTEROP_MIT_REALM")?;
    Ok(Config::parse(&format!(
        "[libdefaults]\n default_realm = {realm}\n dns_lookup_kdc = false\n{libdefaults}\n\
         [realms]\n {realm} = {{\n  kdc = {}\n{realm_lines}\n }}\n",
        harness::var("INTEROP_MIT_KDC")?,
    ))?)
}

/// The SPAKE user and its per-run password.
fn spake_user() -> Result<(Principal, Password), Box<dyn Error>> {
    Ok((
        Principal::user(
            harness::var("INTEROP_MIT_REALM")?,
            harness::var("INTEROP_MIT_SPAKE_USER")?,
        ),
        Password::from_vec(harness::var("INTEROP_MIT_SPAKE_USER_PASSWORD")?.into_bytes()),
    ))
}

/// The service that requires the `spake` auth indicator.
fn spake_required() -> Result<Principal, Box<dyn Error>> {
    Ok(Principal::new(
        harness::var("INTEROP_MIT_REALM")?,
        2,
        harness::var("INTEROP_MIT_SPAKE_REQUIRED_SERVICE")?.split('/'),
    ))
}

/// The TGT of the SPAKE user through the stepwise engine under `config`.
async fn stepwise_tgt(config: &Config, sequence: u32) -> Result<AsRepSession, ClientError> {
    let options = InitCredsOptions::from_config(
        config,
        SystemTime::now(),
        nonce(sequence).map_err(|error| ClientError::Transport(error.to_string()))?,
    )?;
    let (principal, password) =
        spake_user().map_err(|error| ClientError::Transport(error.to_string()))?;
    let mut exchange = InitCreds::with_password(principal, Some(password), options);
    drive_tokio(
        &transport(),
        (config, KdcProtocol::Tcp),
        &mut exchange,
        &mut NoResponder::default(),
    )
    .await
}

/// A ticket for the SPAKE-required service with `tgt`.
async fn spake_service_ticket(
    config: &Config,
    tgt: &AsRepSession,
    sequence: u32,
) -> Result<(), Box<dyn Error>> {
    let options =
        TgsReq::from_libdefaults(SystemTime::now(), nonce(sequence)?, &config.libdefaults)?;
    let service = spake_required()?;
    let mut exchange = TicketCreds::new(tgt.clone(), service.clone(), TicketOptions::new(options))?;
    let ticket = drive_tokio(
        &transport(),
        (config, KdcProtocol::Tcp),
        &mut exchange,
        &mut NoResponder::default(),
    )
    .await?;
    assert_eq!(ticket.service(), &service, "service ticket name");
    Ok(())
}

/// The SPAKE login of MIT's default group (edwards25519) meets `require_auth = spake`.
///
/// It runs through the Tokio login function with `disable_encrypted_timestamp`
/// set, so no other mechanism can answer; the KDC then issues a ticket for the
/// service that requires `spake`.
#[test]
fn spake_login_meets_the_spake_requirement() -> Result<(), Box<dyn Error>> {
    if !harness::require("spake_login_meets_the_spake_requirement", &[MIT_KDC])? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let config = config("", "  disable_encrypted_timestamp = true")?;
        let (principal, password) = spake_user()?;
        let options = AsReq::from_libdefaults(SystemTime::now(), nonce(1)?, &config.libdefaults)?;
        let tgt = transport()
            .login_tgt_with_password_config(
                &config,
                KdcProtocol::Tcp,
                principal,
                password.as_bytes(),
                options,
            )
            .await
            .map_err(|error| format!("SPAKE login: {error}"))?;
        spake_service_ticket(&config, &tgt, 2).await
    })
}

/// SPAKE in each NIST group MIT supports, through the stepwise engine: the
/// profile permits only that group, so the KDC must use it.
#[test]
fn spake_login_in_each_nist_group() -> Result<(), Box<dyn Error>> {
    if !harness::require("spake_login_in_each_nist_group", &[MIT_KDC])? {
        return Ok(());
    }
    runtime()?.block_on(async {
        for (sequence, group) in [(3_u32, "P-256"), (5_u32, "P-384"), (7_u32, "P-521")] {
            let config = config(
                &format!(" spake_preauth_groups = {group}"),
                "  disable_encrypted_timestamp = true",
            )?;
            let tgt = stepwise_tgt(&config, sequence)
                .await
                .map_err(|error| format!("SPAKE login in {group}: {error}"))?;
            spake_service_ticket(&config, &tgt, sequence.saturating_add(1))
                .await
                .map_err(|error| format!("service ticket after {group}: {error}"))?;
        }
        Ok(())
    })
}

/// The controls: without SPAKE the service that requires it is refused.
///
/// With an empty group list the login falls back to encrypted timestamp and
/// that TGT does not get the service ticket; with encrypted timestamp disabled
/// as well, the login is refused before any timestamp is sent.
#[test]
fn without_spake_the_requirement_is_not_met() -> Result<(), Box<dyn Error>> {
    if !harness::require("without_spake_the_requirement_is_not_met", &[MIT_KDC])? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let fallback = config(" spake_preauth_groups =", "")?;
        let tgt = stepwise_tgt(&fallback, 9)
            .await
            .map_err(|error| format!("encrypted-timestamp login: {error}"))?;
        let refused = spake_service_ticket(&fallback, &tgt, 10).await;
        assert!(refused.is_err(), "a timestamp TGT met require_auth spake");
        let disabled = config(
            " spake_preauth_groups =",
            "  disable_encrypted_timestamp = true",
        )?;
        let outcome = stepwise_tgt(&disabled, 11).await;
        assert!(
            matches!(
                outcome,
                Err(ClientError::EncryptedTimestampDisabled { realm: _ })
            ),
            "{outcome:?}"
        );
        Ok(())
    })
}

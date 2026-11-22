//! The Samba PAC scenarios: a cross-trust ticket and a claims-less account.

use core::{error::Error, time::Duration};
use std::{
    io,
    time::{SystemTime, UNIX_EPOCH},
};

use rskrb5_ng::{
    client::{
        KDC_OPTION_CANONICALIZE, TgsRepSession, Tokio, build_ap_req_with_confounder,
        options::{ApReq, AsReq, TgsReq},
        principal::Principal,
        transport::{KdcProtocol, Tokio as TokioKdcTransport},
    },
    config::Config,
    crypto::KerberosEtype,
    keytab::Keytab,
    service::{ValidatedApReq, Validator},
};
use tokio::runtime::{Builder, Runtime};

use crate::harness::{self, Fixture};

/// The KDC of the user domain.
const SAMBA_USER: Fixture = Fixture::new("samba-user", "INTEROP_SAMBA_USER_KDC");

/// The KDC of the resource domain.
const SAMBA_RES: Fixture = Fixture::new("samba-res", "INTEROP_SAMBA_RES_KDC");

/// Enctype id of aes256-cts-hmac-sha1-96, the strongest key of every Samba account.
const AES256_SHA1: i32 = 18;

/// The current-thread Tokio runtime the scenarios run on.
fn runtime() -> io::Result<Runtime> {
    Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
}

/// A KDC transport with a ten-second timeout.
fn transport() -> TokioKdcTransport {
    TokioKdcTransport::new().with_timeout(Duration::from_secs(10))
}

/// Both domains with their KDCs, default realm USER.RSKRB5 and no `[domain_realm]`.
fn config() -> Result<Config, Box<dyn Error>> {
    let user_realm = harness::var("INTEROP_SAMBA_USER_REALM")?;
    let res_realm = harness::var("INTEROP_SAMBA_RES_REALM")?;
    Ok(Config::parse(&format!(
        "[libdefaults]\n default_realm = {user_realm}\n dns_lookup_kdc = false\n \
         dns_lookup_realm = false\n[realms]\n {user_realm} = {{\n  kdc = {}\n }}\n \
         {res_realm} = {{\n  kdc = {}\n }}\n",
        harness::var("INTEROP_SAMBA_USER_KDC")?,
        harness::var("INTEROP_SAMBA_RES_KDC")?,
    ))?)
}

/// A nonce unique to `sequence` and the current time.
fn nonce(sequence: u32) -> Result<u32, Box<dyn Error>> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH)?;
    Ok(u32::try_from(elapsed.as_nanos() & 0x00ff_ffff)? | sequence.wrapping_shl(24))
}

/// TGS-REQ options with a one-hour lifetime and AES256.
fn tgs_options(sequence: u32) -> Result<TgsReq, Box<dyn Error>> {
    Ok(TgsReq::new(SystemTime::now(), nonce(sequence)?)
        .with_ticket_lifetime(Duration::from_hours(1))
        .with_etypes(vec![AES256_SHA1]))
}

/// A user-domain principal named by the env-file key `key`.
fn user(key: &str) -> Result<Principal, Box<dyn Error>> {
    Ok(Principal::user(
        harness::var("INTEROP_SAMBA_USER_REALM")?,
        harness::var(key)?,
    ))
}

/// Replaces `error` by its `Display` text.
fn shown(error: Box<dyn Error>) -> Box<dyn Error> {
    let text = error.to_string();
    drop(error);
    text.into()
}

/// An AP-REQ for `ticket`, built with a fixed confounder at the current time.
fn ap_req(ticket: &TgsRepSession) -> Result<Vec<u8>, Box<dyn Error>> {
    let etype = KerberosEtype::from_etype_id(ticket.session_key().etype())
        .ok_or("ticket session key etype is supported")?;
    let confounder = vec![0x42_u8; etype.confounder_len()];
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH)?;
    let seconds = UNIX_EPOCH
        .checked_add(Duration::from_secs(elapsed.as_secs()))
        .ok_or("time overflow")?;
    let built = build_ap_req_with_confounder(
        ticket,
        ApReq::new(),
        seconds,
        elapsed.subsec_micros(),
        &confounder,
    )?;
    Ok(built.der().to_vec())
}

/// Validate `ticket` against the keytab file in the env-file key `keytab_key`.
fn accepted(ticket: &TgsRepSession, keytab_key: &str) -> Result<ValidatedApReq, Box<dyn Error>> {
    let keytab = Keytab::load(harness::var(keytab_key)?)?;
    let mut validator = Validator::new(&keytab).with_now(SystemTime::now());
    validator
        .validate_ap_req(&ap_req(ticket)?)
        .map_err(|error| format!("the acceptor refused the Samba-issued ticket: {error}").into())
}

/// FU-IOP-P14: testuser1 (user domain) gets a ticket for `HTTP/host.res.rskrb5` across the
/// forest trust; the ticket's PAC carries a zero-length client-claims buffer (claims do not cross
/// the trust) and the resource-domain acceptor accepts it.
#[test]
fn a_ticket_across_the_trust_with_an_empty_claims_buffer_is_accepted() -> Result<(), Box<dyn Error>>
{
    if !harness::require(
        "a_ticket_across_the_trust_with_an_empty_claims_buffer_is_accepted",
        &[SAMBA_USER, SAMBA_RES],
    )? {
        return Ok(());
    }
    runtime()?
        .block_on(async {
            let user_realm = harness::var("INTEROP_SAMBA_USER_REALM")?;
            let res_realm = harness::var("INTEROP_SAMBA_RES_REALM")?;
            let profile = config()?;
            let password = harness::var("INTEROP_SAMBA_USER_USER_PASSWORD")?.into_bytes();
            let tgt = transport()
                .login_tgt_with_password_config(
                    &profile,
                    KdcProtocol::Tcp,
                    user("INTEROP_SAMBA_USER_USER")?,
                    &password,
                    AsReq::new(SystemTime::now(), nonce(1)?).with_etypes(vec![AES256_SHA1]),
                )
                .await?;
            let host = harness::var("INTEROP_SAMBA_RES_HTTP_SERVICE")?;
            let options = tgs_options(2)?;
            let bits = options.kdc_option_bits() | KDC_OPTION_CANONICALIZE;
            let result = transport()
                .get_service_ticket_with_referral_trace(
                    &profile,
                    KdcProtocol::Tcp,
                    &tgt,
                    Principal::new("", 2, host.split('/')),
                    options.with_kdc_option_bits(bits),
                )
                .await?;
            assert_eq!(
                result.ticket().service().realm,
                res_realm,
                "the ticket is the resource domain's"
            );
            let validated = accepted(result.ticket(), "INTEROP_SAMBA_RES_HTTP_KEYTAB")?;
            let pac = validated.pac().ok_or("a Samba service ticket has a PAC")?;
            assert_eq!(
                pac.ad_credentials()
                    .ok_or("the PAC has validation info")?
                    .effective_name,
                harness::var("INTEROP_SAMBA_USER_USER")?,
                "the PAC names the user-domain client"
            );
            assert_eq!(
                validated.client().realm,
                user_realm,
                "the resource service sees the user-domain client"
            );
            Ok::<_, Box<dyn Error>>(())
        })
        .map_err(shown)
}

/// FU-IOP-P14: testuser3 has no claim, so Samba sends a zero-length client-claims buffer even
/// within its own domain; its service ticket for `HTTP/user2.user.rskrb5` is accepted.
#[test]
fn a_claims_less_account_ticket_is_accepted() -> Result<(), Box<dyn Error>> {
    if !harness::require("a_claims_less_account_ticket_is_accepted", &[SAMBA_USER])? {
        return Ok(());
    }
    runtime()?
        .block_on(async {
            let realm = harness::var("INTEROP_SAMBA_USER_REALM")?;
            let mut client = Tokio::with_keytab(
                config()?,
                KdcProtocol::Tcp,
                user("INTEROP_SAMBA_USER_NOPREAUTH_USER")?,
                Keytab::load(harness::var("INTEROP_SAMBA_USER_NOPREAUTH_USER_KEYTAB")?)?,
            )
            .with_transport(transport());
            let name = harness::var("INTEROP_SAMBA_USER_HTTP_SERVICE")?;
            let ticket = client
                .get_service_ticket(Principal::new(realm.as_str(), 2, name.split('/')))
                .await?;
            let keytab = Keytab::load(harness::var("INTEROP_SAMBA_USER_HTTP_ACCOUNT_KEYTAB")?)?;
            let account = harness::var("INTEROP_SAMBA_USER_HTTP_ACCOUNT")?;
            let mut validator = Validator::new(&keytab)
                .with_now(SystemTime::now())
                .with_keytab_principal([account.as_str()]);
            let validated = validator
                .validate_ap_req(&ap_req(&ticket)?)
                .map_err(|error| {
                    format!("the acceptor refused the Samba-issued ticket: {error}")
                })?;
            let pac = validated.pac().ok_or("a Samba service ticket has a PAC")?;
            assert_eq!(
                pac.ad_credentials()
                    .ok_or("the PAC has validation info")?
                    .effective_name,
                harness::var("INTEROP_SAMBA_USER_NOPREAUTH_USER")?,
                "the PAC names the claims-less account"
            );
            Ok::<_, Box<dyn Error>>(())
        })
        .map_err(shown)
}

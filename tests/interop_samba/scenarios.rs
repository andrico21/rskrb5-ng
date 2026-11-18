//! Shared setup of the Samba fixture scenarios.
//!
//! Env-file values, configuration and request options; the scenarios live in
//! `ad.rs`, `kdc.rs`, `services.rs` and `negotiate.rs`.

use core::{error::Error, time::Duration};
use std::{
    io,
    time::{SystemTime, UNIX_EPOCH},
};

use rskrb5_ng::{
    client::{
        options::{AsReq, TgsReq},
        principal::Principal,
        transport::{KdcProtocol, Tokio as TokioKdcTransport},
    },
    config::Config,
    ticket,
};
use tokio::runtime::{Builder, Runtime};

use crate::harness::{self, Fixture};

/// The Active Directory scenarios of `tests/client_ad_integration.rs`,
/// re-pointed at the Samba domains.
#[path = "ad.rs"]
mod ad;

/// AS, TGS, pre-authentication, cross-realm and error scenarios.
#[path = "kdc.rs"]
mod kdc;

/// kpasswd (FU-TST-06) and constrained-delegation scenarios.
#[path = "services.rs"]
mod services;

/// HTTP Negotiate scenarios with Samba-issued PACs.
#[cfg(feature = "spnego")]
#[path = "negotiate.rs"]
mod negotiate;

/// Enctype id of aes128-cts-hmac-sha1-96.
const AES128_SHA1: i32 = 17;

/// Enctype id of aes256-cts-hmac-sha1-96, the strongest key of every Samba
/// account, so every ticket is encrypted with it.
const AES256_SHA1: i32 = 18;

/// Enctype id of rc4-hmac (the opted-in trust scenario only).
const RC4_HMAC: i32 = 23;

/// RFC 4120 ticket flag bit `pre-authent`.
const FLAG_PRE_AUTHENT: u32 = 10;

/// The KDC of the user domain, reached on `INTEROP_SAMBA_USER_KDC`.
const SAMBA_USER: Fixture = Fixture::new("samba-user", "INTEROP_SAMBA_USER_KDC");

/// The KDC of the resource domain, reached on `INTEROP_SAMBA_RES_KDC`.
const SAMBA_RES: Fixture = Fixture::new("samba-res", "INTEROP_SAMBA_RES_KDC");

/// The kpasswd service of the user domain, on `INTEROP_SAMBA_USER_KPASSWD`.
const SAMBA_USER_KPASSWD: Fixture = Fixture::new("samba-user", "INTEROP_SAMBA_USER_KPASSWD");

/// The realm of the user domain.
fn user_realm() -> Result<String, Box<dyn Error>> {
    harness::var("INTEROP_SAMBA_USER_REALM")
}

/// The realm of the resource domain.
fn res_realm() -> Result<String, Box<dyn Error>> {
    harness::var("INTEROP_SAMBA_RES_REALM")
}

/// The KDC endpoint `host:port` of the user domain.
fn user_kdc() -> Result<String, Box<dyn Error>> {
    harness::var("INTEROP_SAMBA_USER_KDC")
}

/// The user-domain principal named by the env-file key `key`.
fn user(key: &str) -> Result<Principal, Box<dyn Error>> {
    Ok(Principal::user(user_realm()?, harness::var(key)?))
}

/// The service principal (`service/host`) named by the env-file key `key` in
/// the realm `realm`.
fn service(realm: String, key: &str) -> Result<Principal, Box<dyn Error>> {
    let name = harness::var(key)?;
    Ok(Principal::new(realm, 2, name.split('/')))
}

/// The password in the env-file key `key`.
fn password(key: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(harness::var(key)?.into_bytes())
}

/// A KDC transport with a ten-second timeout.
fn transport() -> TokioKdcTransport {
    TokioKdcTransport::new().with_timeout(Duration::from_secs(10))
}

/// The current-thread Tokio runtime the scenarios run on.
fn runtime() -> io::Result<Runtime> {
    Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
}

/// A configuration naming both domains' KDCs and kpasswd servers (default
/// realm `USER.RSKRB5`), with the `[libdefaults]` relations in `libdefaults`.
fn config(libdefaults: &str) -> Result<Config, Box<dyn Error>> {
    let user_realm = user_realm()?;
    let res_realm = res_realm()?;
    let user_kdc = user_kdc()?;
    let user_kpasswd = harness::var("INTEROP_SAMBA_USER_KPASSWD")?;
    let res_kdc = harness::var("INTEROP_SAMBA_RES_KDC")?;
    let res_kpasswd = harness::var("INTEROP_SAMBA_RES_KPASSWD")?;
    Ok(Config::parse(&format!(
        "
[libdefaults]
 default_realm = {user_realm}
 dns_lookup_kdc = false
 dns_lookup_realm = false
{libdefaults}

[realms]
 {user_realm} = {{
  kdc = {user_kdc}
  kpasswd_server = {user_kpasswd}
 }}
 {res_realm} = {{
  kdc = {res_kdc}
  kpasswd_server = {res_kpasswd}
 }}
"
    ))?)
}

/// Names a KDC transport protocol in progress messages.
const fn label(protocol: KdcProtocol) -> &'static str {
    match protocol {
        KdcProtocol::Udp => "UDP",
        KdcProtocol::Tcp => "TCP",
        KdcProtocol::Auto => "Auto",
        _ => "unknown protocol",
    }
}

/// A nonce unique to `protocol`, `sequence` and the current time.
fn nonce(protocol: KdcProtocol, sequence: u32) -> Result<u32, Box<dyn Error>> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH)?;
    let tag = match protocol {
        KdcProtocol::Udp => 0x1000_0000,
        KdcProtocol::Tcp => 0x2000_0000,
        KdcProtocol::Auto => 0x3000_0000,
        _ => return Err("unexpected non-exhaustive protocol variant".into()),
    };
    Ok(u32::try_from(elapsed.as_nanos() & 0x00ff_ffff)? | sequence.wrapping_shl(24) | tag)
}

/// AS-REQ options for `etypes` with a one-hour lifetime.
fn as_options(
    protocol: KdcProtocol,
    sequence: u32,
    etypes: Vec<i32>,
) -> Result<AsReq, Box<dyn Error>> {
    Ok(AsReq::new(SystemTime::now(), nonce(protocol, sequence)?)
        .with_ticket_lifetime(Duration::from_hours(1))
        .with_etypes(etypes))
}

/// TGS-REQ options for `etypes` with a one-hour lifetime.
fn tgs_options(
    protocol: KdcProtocol,
    sequence: u32,
    etypes: Vec<i32>,
) -> Result<TgsReq, Box<dyn Error>> {
    Ok(TgsReq::new(SystemTime::now(), nonce(protocol, sequence)?)
        .with_ticket_lifetime(Duration::from_hours(1))
        .with_etypes(etypes))
}

/// Replaces `error` by its `Display` text: libtest prints a returned error
/// through `Debug`, which for the client errors names only the variant.
fn shown(error: Box<dyn Error>) -> Box<dyn Error> {
    let text = error.to_string();
    drop(error);
    text.into()
}

/// The enctype of the encrypted part of the DER `ticket` (the service key).
fn ticket_etype(ticket: &[u8]) -> Result<i32, Box<dyn Error>> {
    Ok(ticket::decode(ticket)?.enc_part.etype)
}

//! Shared setup of the MIT fixture scenarios.
//!
//! Env-file values, configuration and request options; the scenarios live in
//! `kdc.rs`, `services.rs` and `negotiate.rs`.

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

/// AS, TGS, pre-authentication, discovery and renewal scenarios.
#[path = "kdc.rs"]
mod kdc;

/// kpasswd and MIT credential-cache scenarios.
#[path = "services.rs"]
mod services;

/// HTTP Negotiate scenarios.
#[cfg(feature = "spnego")]
#[path = "negotiate.rs"]
mod negotiate;

/// Enctype id of aes128-cts-hmac-sha1-96.
const AES128_SHA1: i32 = 17;

/// Enctype id of aes256-cts-hmac-sha1-96.
const AES256_SHA1: i32 = 18;

/// Enctype id of aes128-cts-hmac-sha256-128.
const AES128_SHA2: i32 = 19;

/// Enctype id of aes256-cts-hmac-sha384-192, the fixture's strongest key
/// (first in `supported_enctypes`), so every ticket is encrypted with it.
const AES256_SHA2: i32 = 20;

/// The fixture KDC, reached on `INTEROP_MIT_KDC` (TCP and UDP).
const MIT_KDC: Fixture = Fixture::new("mit-kdc", "INTEROP_MIT_KDC");

/// The fixture's kpasswd service (kadmind), on `INTEROP_MIT_KPASSWD`.
const MIT_KPASSWD: Fixture = Fixture::new("mit-kdc", "INTEROP_MIT_KPASSWD");

/// The realm of the fixture.
fn realm() -> Result<String, Box<dyn Error>> {
    harness::var("INTEROP_MIT_REALM")
}

/// The KDC endpoint `host:port`.
fn kdc() -> Result<String, Box<dyn Error>> {
    harness::var("INTEROP_MIT_KDC")
}

/// The user principal named by the env-file key `key`.
fn user(key: &str) -> Result<Principal, Box<dyn Error>> {
    Ok(Principal::user(realm()?, harness::var(key)?))
}

/// The service principal (`service/host`) named by the env-file key `key`.
fn service(key: &str) -> Result<Principal, Box<dyn Error>> {
    let name = harness::var(key)?;
    Ok(Principal::new(realm()?, 2, name.split('/')))
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

/// A configuration naming the fixture's KDC and kpasswd server, with the
/// `[libdefaults]` relations in `libdefaults` added.
fn config(libdefaults: &str) -> Result<Config, Box<dyn Error>> {
    let realm = realm()?;
    let kdc = kdc()?;
    let kpasswd = harness::var("INTEROP_MIT_KPASSWD")?;
    Ok(Config::parse(&format!(
        "
[libdefaults]
 default_realm = {realm}
 dns_lookup_kdc = false
{libdefaults}

[realms]
 {realm} = {{
  kdc = {kdc}
  kpasswd_server = {kpasswd}
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

/// The enctype of the encrypted part of the DER `ticket` (the service key).
fn ticket_etype(ticket: &[u8]) -> Result<i32, Box<dyn Error>> {
    Ok(ticket::decode(ticket)?.enc_part.etype)
}

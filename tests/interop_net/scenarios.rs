//! Shared setup and the KDC scenarios of the network fixtures: SRV discovery
//! through the `CoreDNS` zone and the cross-realm referral to `OTHER.RSKRB5`.
//! The HTTP Negotiate scenario against Apache is in `negotiate.rs`.

use core::{error::Error, time::Duration};
use std::{
    io,
    time::{SystemTime, UNIX_EPOCH},
};

use rskrb5_ng::{
    client::{
        options::{AsReq, TgsReq},
        principal::Principal,
        transport::{KdcEndpointSource, KdcProtocol, Tokio as TokioKdcTransport},
    },
    config::Config,
    keytab::Keytab,
    service::{Principal as ServicePrincipal, Validator},
    spnego::{self, oid::ObjectIdentifier},
    ticket,
};
use tokio::runtime::{Builder, Runtime};

use crate::harness::{self, Fixture, assert_negotiated_enctype, assert_negotiated_mechanism};

/// HTTP Negotiate against Apache `mod_auth_gssapi`.
#[cfg(feature = "http")]
#[path = "negotiate.rs"]
mod negotiate;

/// Enctype id of aes256-cts-hmac-sha384-192, the strongest key of both realms
/// (first in their `supported_enctypes`), so every ticket is encrypted with it.
const AES256_SHA2: i32 = 20;

/// The TEST.RSKRB5 KDC (fixture `mit-kdc`).
const MIT_KDC: Fixture = Fixture::new("mit-kdc", "INTEROP_MIT_KDC");

/// The OTHER.RSKRB5 KDC (fixture `mit-other`).
const MIT_OTHER_KDC: Fixture = Fixture::new("mit-other", "INTEROP_MIT_OTHER_KDC");

/// The `CoreDNS` server, host view (fixture `dns`), TCP endpoint.
const DNS: Fixture = Fixture::new("dns", "INTEROP_DNS");

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

/// The TEST.RSKRB5 test user and its password.
fn test_user() -> Result<(Principal, Vec<u8>), Box<dyn Error>> {
    Ok((
        Principal::user(
            harness::var("INTEROP_MIT_REALM")?,
            harness::var("INTEROP_MIT_USER")?,
        ),
        harness::var("INTEROP_MIT_USER_PASSWORD")?.into_bytes(),
    ))
}

/// A nonce unique to `sequence` and the current time.
fn nonce(sequence: u32) -> Result<u32, Box<dyn Error>> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH)?;
    Ok(u32::try_from(elapsed.as_nanos() & 0x00ff_ffff)? | sequence.wrapping_shl(24))
}

/// AS-REQ options with a one-hour lifetime and the AES-SHA2 enctype.
fn as_options(sequence: u32) -> Result<AsReq, Box<dyn Error>> {
    Ok(AsReq::new(SystemTime::now(), nonce(sequence)?)
        .with_ticket_lifetime(Duration::from_hours(1))
        .with_etypes(vec![AES256_SHA2]))
}

/// TGS-REQ options with a one-hour lifetime and the AES-SHA2 enctype.
fn tgs_options(sequence: u32) -> Result<TgsReq, Box<dyn Error>> {
    Ok(TgsReq::new(SystemTime::now(), nonce(sequence)?)
        .with_ticket_lifetime(Duration::from_hours(1))
        .with_etypes(vec![AES256_SHA2]))
}

/// The enctype of the encrypted part of the DER `ticket` (the service key).
fn ticket_etype(ticket: &[u8]) -> Result<i32, Box<dyn Error>> {
    Ok(ticket::decode(ticket)?.enc_part.etype)
}

/// Discovery through the `CoreDNS` host view finds the TEST KDC only by DNS SRV
/// (no `kdc` relation is configured), at the published fixture port, and a
/// password login through the discovered endpoint succeeds over UDP and TCP.
#[test]
fn srv_discovery_finds_the_test_kdc_through_coredns() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "srv_discovery_finds_the_test_kdc_through_coredns",
        &[DNS, MIT_KDC],
    )? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let (user, password) = test_user()?;
        let realm = user.realm.clone();
        let config = Config::parse(&format!(
            "[libdefaults]\n default_realm = {realm}\n dns_lookup_kdc = true\n"
        ))?;
        let transport = transport().with_dns_server(&harness::var("INTEROP_DNS_SERVER")?)?;
        let kdc_port: u16 = harness::var("INTEROP_MIT_KDC")?
            .rsplit_once(':')
            .ok_or("INTEROP_MIT_KDC has no port")?
            .1
            .parse()?;
        for (sequence, protocol) in [(1, KdcProtocol::Udp), (2, KdcProtocol::Tcp)] {
            let endpoints = transport.discover_kdcs(&config, &realm, protocol).await?;
            assert!(!endpoints.is_empty(), "DNS SRV discovery found no KDC");
            for endpoint in &endpoints {
                assert_eq!(
                    endpoint.source,
                    KdcEndpointSource::DnsSrv,
                    "every KDC comes from DNS SRV"
                );
                assert_eq!(endpoint.port, kdc_port, "the SRV record carries the published port");
            }
            let session = transport
                .login_tgt_with_password_config(
                    &config,
                    protocol,
                    user.clone(),
                    &password,
                    as_options(sequence)?,
                )
                .await?;
            assert_eq!(session.client(), &user, "the TGT names the test user");
            assert_negotiated_enctype(
                "TGT session key",
                AES256_SHA2,
                session.session_key().etype(),
            )?;
        }
        Ok::<_, Box<dyn Error>>(())
    })
}

/// A TEST.RSKRB5 user gets a ticket for `HTTP/http.other.rskrb5@OTHER.RSKRB5`
/// across the direct trust: the TEST KDC issues the cross-realm TGT
/// `krbtgt/OTHER.RSKRB5@TEST.RSKRB5` (the referral step), the OTHER KDC the
/// service ticket, and the OTHER service keytab accepts it as the TEST user.
#[test]
fn cross_realm_referral_reaches_the_other_realm_service() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "cross_realm_referral_reaches_the_other_realm_service",
        &[MIT_KDC, MIT_OTHER_KDC],
    )? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let (user, password) = test_user()?;
        let realm = user.realm.clone();
        let other = harness::var("INTEROP_MIT_OTHER_REALM")?;
        let config = Config::parse(&format!(
            "[libdefaults]\n default_realm = {realm}\n dns_lookup_kdc = false\n\
             [realms]\n {realm} = {{\n  kdc = {}\n }}\n {other} = {{\n  kdc = {}\n }}\n",
            harness::var("INTEROP_MIT_KDC")?,
            harness::var("INTEROP_MIT_OTHER_KDC")?,
        ))?;
        let http = harness::var("INTEROP_MIT_OTHER_HTTP_SERVICE")?;
        let service = Principal::new(other.clone(), 2, http.split('/'));
        let keytab = Keytab::load(harness::var("INTEROP_MIT_OTHER_HTTP_KEYTAB")?)?;
        for (sequence, protocol) in [(3, KdcProtocol::Udp), (4, KdcProtocol::Tcp)] {
            let tgt = transport()
                .login_tgt_with_password_config(
                    &config,
                    protocol,
                    user.clone(),
                    &password,
                    as_options(sequence)?,
                )
                .await?;
            let result = transport()
                .get_service_ticket_with_referral_trace(
                    &config,
                    protocol,
                    &tgt,
                    service.clone(),
                    tgs_options(sequence)?,
                )
                .await?;
            let referrals: Vec<_> = result
                .referral_tgts()
                .iter()
                .map(|referral| referral.service().clone())
                .collect();
            assert_eq!(
                referrals,
                vec![Principal::new(realm.clone(), 2, ["krbtgt", other.as_str()])],
                "one cross-realm TGT, krbtgt/{other}@{realm}"
            );
            let ticket = result.ticket();
            assert_eq!(ticket.client(), &user, "the service ticket names the TEST user");
            assert_eq!(ticket.service(), &service, "the service ticket is for the OTHER service");
            assert_negotiated_enctype(
                "OTHER service ticket",
                AES256_SHA2,
                ticket_etype(ticket.ticket().as_slice())?,
            )?;
            let context = spnego::init_sec_context(ticket, spnego::InitiatorContextOptions::new())
                .map_err(|error| format!("the initiator could not build the token: {error}"))?;
            let mut validator = Validator::new(&keytab).with_now(SystemTime::now());
            let accepted = spnego::accept_sec_context_header(&mut validator, context.header_ref())
                .map_err(|error| format!("the OTHER keytab refused the cross-realm ticket: {error}"))?;
            assert_negotiated_mechanism(
                ObjectIdentifier::krb5().arcs(),
                accepted.selected_mechanism().arcs(),
            )?;
            assert_eq!(
                accepted.ap_req().client().clone(),
                ServicePrincipal::new(realm.clone(), 1, vec![user.components.join("/")]),
                "the OTHER acceptor sees the TEST user"
            );
        }
        Ok::<_, Box<dyn Error>>(())
    })
}

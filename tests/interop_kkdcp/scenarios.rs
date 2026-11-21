//! MS-KKDCP scenarios: login, service ticket and kpasswd through the `kdcproxy`
//! fixture, and the refusal of an unrelated CA.

use core::{error::Error, net::Ipv4Addr, time::Duration};
use std::io;

use rskrb5_ng::{
    client::{
        Password, Tokio,
        principal::Principal,
        transport::{KdcProtocol, Tokio as KdcTransport},
    },
    config::Config,
    error::Client as ClientError,
    kadmin::KPASSWD_SUCCESS,
    krb_priv::ipv4_host_address,
    trace::{Guard, Options, capture::Memory},
};
use tokio::runtime::{Builder, Runtime};

use crate::harness::{self, Fixture, assert_ticket_flag};

/// The fixture KDC behind the proxy.
const MIT_KDC: Fixture = Fixture::new("mit-kdc", "INTEROP_MIT_KDC");

/// The HTTPS KDC proxy, on `INTEROP_KDCPROXY`.
const KDCPROXY: Fixture = Fixture::new("kdcproxy", "INTEROP_KDCPROXY");

/// RFC 4120 ticket flag bit `pre-authent`.
const FLAG_PRE_AUTHENT: u32 = 10;

/// The current-thread Tokio runtime the scenarios run on.
fn runtime() -> io::Result<Runtime> {
    Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
}

/// A KDC transport with a ten-second timeout and the built-in proxy transport.
fn transport() -> KdcTransport {
    KdcTransport::new().with_timeout(Duration::from_secs(10))
}

/// A profile whose realm reaches its KDC and kpasswd server only through the
/// proxy URL, anchored on the CA file in the env-file key `ca`.
fn config(ca: &str) -> Result<Config, Box<dyn Error>> {
    let realm = harness::var("INTEROP_KDCPROXY_REALM")?;
    let url = harness::var("INTEROP_KDCPROXY_URL")?;
    let anchor = harness::var(ca)?;
    Ok(Config::parse(&format!(
        "
[libdefaults]
 default_realm = {realm}
 dns_lookup_kdc = false

[realms]
 {realm} = {{
  kdc = {url}
  kpasswd_server = {url}
  http_anchors = FILE:{anchor}
 }}
"
    ))?)
}

/// A user of the proxy's realm named by the env-file key `key`.
fn user(key: &str) -> Result<Principal, Box<dyn Error>> {
    Ok(Principal::user(
        harness::var("INTEROP_KDCPROXY_REALM")?,
        harness::var(key)?,
    ))
}

/// A pre-authenticated password login (two AS rounds) and a service ticket go
/// through the proxy over HTTPS, and the transport traces each request as an
/// `https` send to the proxy URL.
#[test]
fn login_and_service_ticket_through_the_proxy() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "login_and_service_ticket_through_the_proxy",
        &[MIT_KDC, KDCPROXY],
    )? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let sink = Memory::new();
        let guard = Guard::new(sink.clone(), Options::new().with_identities(true));
        let mut client = Tokio::with_password(
            config("INTEROP_KDCPROXY_CA")?,
            KdcProtocol::Tcp,
            user("INTEROP_MIT_PREAUTH_USER")?,
            harness::var("INTEROP_MIT_PREAUTH_USER_PASSWORD")?.into_bytes(),
        )
        .with_transport(transport())
        .with_trace(guard);
        let tgt = client.login().await?.clone();
        assert_ticket_flag("pre-authent", FLAG_PRE_AUTHENT, tgt.ticket_flags())?;
        let service = Principal::parse_service(format!(
            "{}@{}",
            harness::var("INTEROP_MIT_HTTP_SERVICE")?,
            harness::var("INTEROP_KDCPROXY_REALM")?
        ))?;
        let ticket = client.get_service_ticket(service).await?;
        assert!(!ticket.ticket().is_empty(), "the service ticket is empty");
        let url = harness::var("INTEROP_KDCPROXY_URL")?;
        let text = sink.lines().join("\n");
        assert!(
            text.contains(&format!("transport step=answered wire=https target={url}")),
            "no HTTPS answer from the proxy in:\n{text}"
        );
        assert!(
            !text.contains("step=sending wire=tcp") && !text.contains("step=sending wire=udp"),
            "a request bypassed the proxy:\n{text}"
        );
        Ok::<_, Box<dyn Error>>(())
    })
}

/// The proxy's certificate does not verify against an unrelated CA: nothing is
/// sent and the login fails with the endpoint failure.
#[test]
fn unrelated_ca_is_refused() -> Result<(), Box<dyn Error>> {
    if !harness::require("unrelated_ca_is_refused", &[MIT_KDC, KDCPROXY])? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let mut client = Tokio::with_password(
            config("INTEROP_KDCPROXY_WRONG_CA")?,
            KdcProtocol::Tcp,
            user("INTEROP_MIT_USER")?,
            harness::var("INTEROP_MIT_USER_PASSWORD")?.into_bytes(),
        )
        .with_transport(transport());
        let outcome = client.login().await;
        let Err(ClientError::KdcEndpointFailures {
            failures,
            realm: _,
            protocol: _,
        }) = outcome
        else {
            return Err(format!("expected a refused proxy, got {outcome:?}").into());
        };
        assert!(
            failures
                .iter()
                .all(|failure| failure.contains("not delivered")),
            "{failures:?}"
        );
        Ok::<_, Box<dyn Error>>(())
    })
}

/// kpasswd through the proxy changes the disposable account's password, and a
/// second change through the proxy puts the fixture's password back.
#[test]
fn kpasswd_through_the_proxy() -> Result<(), Box<dyn Error>> {
    if !harness::require("kpasswd_through_the_proxy", &[MIT_KDC, KDCPROXY])? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let config = config("INTEROP_KDCPROXY_CA")?;
        let account = user("INTEROP_KDCPROXY_KPASSWD_USER")?;
        let current = harness::var("INTEROP_KDCPROXY_KPASSWD_USER_PASSWORD")?.into_bytes();
        let mut next = current.clone();
        next.extend_from_slice(b"-kkdcp");
        for (from, to) in [(current.clone(), next.clone()), (next, current)] {
            let mut client =
                Tokio::with_password(config.clone(), KdcProtocol::Tcp, account.clone(), from)
                    .with_transport(transport());
            let result = client
                .change_password(
                    Password::from_vec(to.clone()),
                    ipv4_host_address(Ipv4Addr::LOCALHOST.octets()),
                )
                .await?;
            assert_eq!(
                result.code, KPASSWD_SUCCESS,
                "kpasswd result code {}: {}",
                result.code, result.text
            );
            let mut changed =
                Tokio::with_password(config.clone(), KdcProtocol::Tcp, account.clone(), to)
                    .with_transport(transport());
            let session = changed.login().await?;
            assert_ticket_flag("pre-authent", FLAG_PRE_AUTHENT, session.ticket_flags())?;
        }
        Ok::<_, Box<dyn Error>>(())
    })
}

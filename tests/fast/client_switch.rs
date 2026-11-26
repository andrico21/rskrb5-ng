//! The explicit TGS FAST switch of the high-level client: a KDC proxy that is the
//! deterministic FAST KDC of `tgs_kdc` answers the requests of `client::Tokio`.

use core::fmt;
use std::sync::{Mutex, PoisonError};

use rskrb5_ng::{
    Config, Principal,
    client::{
        Tokio,
        transport::{KdcProtocol, Tokio as Transport},
    },
    error::{Client as ClientError, Fast, KdcProxy},
    preauth::fast::{PA_FX_FAST, Policy},
    transport::{
        kkdcp::ProxyMessage,
        proxy::{KdcProxyTransport, PostFuture, Request},
    },
};

use super::{
    exchange::fast_cause,
    kdc::{Kdc, REALM, TestError},
    tgs_kdc::{Tamper, TgsKdc},
};

/// The record mark that frames a Kerberos message in an MS-KKDCP body.
const MARK: usize = 4;

/// A KDC proxy that answers every TGS request with the FAST KDC.
struct Proxy(Mutex<TgsKdc>);

impl fmt::Debug for Proxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Proxy").finish_non_exhaustive()
    }
}

impl Proxy {
    /// A proxy in front of a KDC that breaks `tamper`.
    const fn new(tamper: Tamper) -> Self {
        Self(Mutex::new(TgsKdc::new(tamper)))
    }

    /// Whether every request the KDC saw was armored with `PA-FX-FAST`.
    fn armored(&self) -> Result<Vec<bool>, TestError> {
        let kdc = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        kdc.requests()
            .iter()
            .map(|request| names_fast(request))
            .collect()
    }
}

/// Whether the TGS-REQ `request` carries a `PA-FX-FAST` entry.
fn names_fast(request: &[u8]) -> Result<bool, TestError> {
    let rasn_kerberos::TgsReq(outer) = rasn::der::decode(request)?;
    Ok(outer
        .padata
        .unwrap_or_default()
        .iter()
        .any(|entry| entry.r#type == PA_FX_FAST))
}

impl KdcProxyTransport for Proxy {
    fn post<'request>(&'request self, request: Request<'request>) -> PostFuture<'request> {
        let answer = ProxyMessage::decode(request.body)
            .map_err(|_malformed| KdcProxy::NotDelivered("not a proxy message".into()))
            .and_then(|message| {
                let framed = message.kerb_message();
                let bytes = framed.get(MARK..).unwrap_or_default();
                self.0
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .handle(bytes)
                    .map_err(|refused| KdcProxy::NotDelivered(refused.to_string().into()))
            })
            .and_then(|reply| {
                let mut marked = u32::try_from(reply.len())
                    .map(u32::to_be_bytes)
                    .map(Vec::from)
                    .map_err(|_long| KdcProxy::NotDelivered("reply too long".into()))?;
                marked.extend_from_slice(&reply);
                ProxyMessage::new(&marked, None, None)
                    .encode()
                    .map(|encoded| encoded.to_vec())
                    .map_err(|_encode| KdcProxy::NotDelivered("reply does not encode".into()))
            });
        Box::pin(async move { answer })
    }
}

/// A client holding the realm's TGT, whose KDC is behind `proxy`.
fn client(proxy: &'static Proxy) -> Result<Tokio, TestError> {
    let config = Config::parse(&format!(
        "[libdefaults]\ndefault_realm = {REALM}\ndns_lookup_kdc = false\n\
         [realms]\n{REALM} = {{\nkdc = https://kdc.fast.test/\n\
         http_anchors = FILE:/etc/proxy-ca.pem\n}}\n"
    ))?;
    Ok(
        Tokio::from_tgt_session(config, KdcProtocol::Tcp, Kdc::new().armor_ticket()?)
            .with_transport(Transport::new().with_kdc_proxy(proxy)),
    )
}

/// The service the tests ask for.
fn service() -> Principal {
    Principal::new(REALM, 2, ["http", "svc.fast.test"])
}

/// A runtime for one scenario.
fn runtime() -> Result<tokio::runtime::Runtime, TestError> {
    Ok(tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?)
}

/// The default client sends the plain TGS request of RFC 4120.
#[test]
fn default_client_sends_plain_tgs_requests() -> Result<(), TestError> {
    static PROXY: Proxy = Proxy::new(Tamper::None);
    let result = runtime()?.block_on(client(&PROXY)?.get_service_ticket(service()));
    assert!(result.is_err(), "the FAST KDC refuses a plain request");
    let seen = PROXY.armored()?;
    assert!(!seen.is_empty(), "no request reached the KDC");
    assert!(seen.iter().all(|armored| !armored), "{seen:?}");
    Ok(())
}

/// An enabled client armors the TGS request and takes the armored reply.
#[test]
fn enabled_client_armors_tgs_requests() -> Result<(), TestError> {
    static PROXY: Proxy = Proxy::new(Tamper::None);
    for policy in [Policy::Opportunistic, Policy::Required] {
        let ticket = runtime()?.block_on(
            client(&PROXY)?
                .with_tgs_fast(policy)
                .get_service_ticket(service()),
        )?;
        assert_eq!(ticket.service(), &service(), "{policy:?}");
    }
    assert_eq!(PROXY.armored()?, [true, true]);
    Ok(())
}

/// Under `Required`, a KDC that answers the armored request with a plain error
/// is refused, never read as the KDC's own error; `Opportunistic` takes it.
#[test]
fn enabled_client_refuses_an_unarmored_reply_under_required() -> Result<(), TestError> {
    static REQUIRED: Proxy = Proxy::new(Tamper::UnarmoredError);
    static OPPORTUNISTIC: Proxy = Proxy::new(Tamper::UnarmoredError);
    let refused = runtime()?.block_on(
        client(&REQUIRED)?
            .with_tgs_fast(Policy::Required)
            .get_service_ticket(service()),
    );
    let cause = refused.as_ref().err().and_then(fast_cause);
    assert!(
        matches!(
            cause,
            Some(Fast::UnarmoredError { code: _ } | Fast::Unarmored)
        ),
        "{refused:?}"
    );
    let taken = runtime()?.block_on(
        client(&OPPORTUNISTIC)?
            .with_tgs_fast(Policy::Opportunistic)
            .get_service_ticket(service()),
    );
    assert!(matches!(taken, Err(ClientError::Kdc(_))), "{taken:?}");
    Ok(())
}

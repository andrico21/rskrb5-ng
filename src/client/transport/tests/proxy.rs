//! `https://` endpoints through a caller's KDC proxy transport (MS-KKDCP routing).

use core::error::Error as StdError;
use std::sync::{Mutex, PoisonError};

use super::{Error, KdcProtocol, Tokio};
use crate::{
    config::{Config, section_values::Location},
    error::KdcProxy,
    trace::{Guard, Options, capture::Memory},
    transport::{
        kkdcp::ProxyMessage,
        proxy::{KdcProxyTransport, PostFuture, Request},
    },
};

/// What a fake proxy answers.
#[derive(Clone, Copy, Debug)]
pub(super) enum Answer {
    /// The reply `[0x6b, 1, 2]` in a KDC-PROXY-MESSAGE.
    Reply,
    /// A failure before delivery.
    NotDelivered,
    /// A failure after possible delivery.
    MaybeDelivered,
    /// HTTP status 302.
    Redirect,
    /// A body that is not a KDC-PROXY-MESSAGE.
    Garbage,
}

/// URL, realm, anchors and the Kerberos message of one request a fake proxy saw.
pub(super) type Seen = (String, String, Vec<Location>, Vec<u8>);

/// A fake proxy that records each request and answers as told.
#[derive(Debug)]
pub(super) struct Fake {
    /// The answers, one per call; the last one repeats.
    answers: &'static [Answer],
    /// URL, realm, anchors and the Kerberos message of each request.
    seen: Mutex<Vec<Seen>>,
}

impl Fake {
    /// A fake that answers `answers` in turn.
    pub(super) const fn new(answers: &'static [Answer]) -> Self {
        Self {
            answers,
            seen: Mutex::new(Vec::new()),
        }
    }

    /// The requests seen so far.
    pub(super) fn seen(&self) -> Vec<Seen> {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl KdcProxyTransport for Fake {
    fn post<'request>(&'request self, request: Request<'request>) -> PostFuture<'request> {
        let message = ProxyMessage::decode(request.body).map_or_else(
            |_error| Vec::new(),
            |message| message.kerb_message().to_vec(),
        );
        let call = {
            let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
            seen.push((
                request.url.to_string(),
                request.realm.to_owned(),
                request.anchors.to_vec(),
                message,
            ));
            seen.len()
        };
        let answer = self
            .answers
            .get(call.saturating_sub(1))
            .or_else(|| self.answers.last())
            .copied()
            .unwrap_or(Answer::Reply);
        Box::pin(async move {
            match answer {
                Answer::Reply => Ok(ProxyMessage::new(&[0, 0, 0, 3, 0x6b, 1, 2], None, None)
                    .encode()?
                    .to_vec()),
                Answer::NotDelivered => Err(KdcProxy::NotDelivered("refused".into())),
                Answer::MaybeDelivered => Err(KdcProxy::MaybeDelivered("reset".into())),
                Answer::Redirect => Err(KdcProxy::Status { status: 302 }),
                Answer::Garbage => Ok(vec![0x30, 0x00]),
            }
        })
    }
}

/// A profile whose realm `R.TEST` names `servers` under `relation`, with one anchor.
pub(super) fn profile(relation: &str, servers: &[&str]) -> Result<Config, Box<dyn StdError>> {
    let lines = servers.iter().fold(String::new(), |mut lines, server| {
        lines.push_str(relation);
        lines.push_str(" = ");
        lines.push_str(server);
        lines.push('\n');
        lines
    });
    Ok(Config::parse(&format!(
        "[libdefaults]\ndns_lookup_kdc = false\n[realms]\nR.TEST = {{\n{lines}http_anchors = FILE:/etc/proxy-ca.pem\n}}\n"
    ))?)
}

/// A KDC request for a realm with an `https://` KDC goes through the proxy, framed
/// for the realm, with the realm's anchors, and the reply's message comes back.
#[tokio::test]
async fn kdc_requests_go_through_the_proxy() -> Result<(), Box<dyn StdError>> {
    static PROXY: Fake = Fake::new(&[Answer::Reply]);
    let config = profile("kdc", &["https://proxy.r.test/KdcProxy"])?;
    let transport = Tokio::new().with_kdc_proxy(&PROXY);
    for protocol in [KdcProtocol::Tcp, KdcProtocol::Auto] {
        let reply = transport
            .send_to_realm(&config, protocol, "R.TEST", &[0x6a, 7])
            .await?;
        assert_eq!(reply, [0x6b, 1, 2], "{protocol:?}");
    }
    let seen = PROXY.seen();
    assert_eq!(seen.len(), 2);
    for (url, realm, anchors, message) in seen {
        assert_eq!(url, "https://proxy.r.test:443/KdcProxy");
        assert_eq!(realm, "R.TEST");
        assert_eq!(anchors, [Location::File("/etc/proxy-ca.pem".to_owned())]);
        assert_eq!(message, [0, 0, 0, 2, 0x6a, 7]);
    }
    Ok(())
}

/// A UDP-only request skips `https://` entries, as MIT's UDP-only strategy does.
#[tokio::test]
async fn udp_only_requests_skip_proxy_entries() -> Result<(), Box<dyn StdError>> {
    static PROXY: Fake = Fake::new(&[Answer::Reply]);
    let config = profile("kdc", &["https://proxy.r.test/KdcProxy"])?;
    let outcome = Tokio::new()
        .with_kdc_proxy(&PROXY)
        .send_to_realm(&config, KdcProtocol::Udp, "R.TEST", &[0x6a])
        .await;
    assert!(
        matches!(
            outcome,
            Err(Error::NoKdcEndpoints {
                realm: _,
                protocol: KdcProtocol::Udp
            })
        ),
        "{outcome:?}"
    );
    assert_eq!(PROXY.seen().len(), 0, "no request reached the proxy");
    Ok(())
}

/// A failing proxy is an endpoint failure: the next entry is tried, and the
/// failures name each proxy URL.
#[tokio::test]
async fn failing_proxies_fail_over_and_are_named() -> Result<(), Box<dyn StdError>> {
    static PROXY: Fake = Fake::new(&[Answer::MaybeDelivered, Answer::Reply]);
    static BROKEN: Fake = Fake::new(&[Answer::NotDelivered, Answer::Redirect, Answer::Garbage]);
    let two = profile("kdc", &["https://a.r.test/p", "https://b.r.test:8443/q"])?;
    let reply = Tokio::new()
        .with_kdc_proxy(&PROXY)
        .send_to_realm(&two, KdcProtocol::Tcp, "R.TEST", &[0x6a])
        .await?;
    assert_eq!(reply, [0x6b, 1, 2]);
    let three = profile(
        "kdc",
        &[
            "https://a.r.test/p",
            "https://b.r.test:8443/q",
            "https://c.r.test/",
        ],
    )?;
    let outcome = Tokio::new()
        .with_kdc_proxy(&BROKEN)
        .send_to_realm(&three, KdcProtocol::Tcp, "R.TEST", &[0x6a])
        .await;
    let Err(Error::KdcEndpointFailures {
        failures,
        realm: _,
        protocol: _,
    }) = outcome
    else {
        return Err(format!("expected endpoint failures, got {outcome:?}").into());
    };
    assert_eq!(failures.len(), 3);
    for (failure, url) in failures.iter().zip([
        "https://a.r.test:443/p",
        "https://b.r.test:8443/q",
        "https://c.r.test:443/",
    ]) {
        assert!(failure.starts_with(&format!("{url}: ")), "{failure}");
    }
    Ok(())
}

/// A password change through the proxy keeps the outcome-unknown classification:
/// only a failure before delivery lets the next server be tried.
#[tokio::test]
async fn kpasswd_through_the_proxy_keeps_outcome_unknown() -> Result<(), Box<dyn StdError>> {
    static ANSWERING: Fake = Fake::new(&[Answer::NotDelivered, Answer::Reply]);
    static UNSURE: Fake = Fake::new(&[Answer::MaybeDelivered]);
    static REDIRECT: Fake = Fake::new(&[Answer::Redirect]);
    static GARBAGE: Fake = Fake::new(&[Answer::Garbage]);
    let config = profile(
        "kpasswd_server",
        &["https://a.r.test/p", "https://b.r.test/p"],
    )?;
    for protocol in [KdcProtocol::Auto, KdcProtocol::Tcp] {
        let reply = Tokio::new()
            .with_kdc_proxy(&ANSWERING)
            .send_to_kpasswd_realm(&config, protocol, "R.TEST", &[0, 1])
            .await?;
        assert_eq!(reply, [0x6b, 1, 2], "{protocol:?}");
    }
    assert_eq!(
        ANSWERING.seen().len(),
        3,
        "the failed proxy is tried once, the answer twice"
    );
    for proxy in [&UNSURE, &REDIRECT, &GARBAGE] {
        let outcome = Tokio::new()
            .with_kdc_proxy(proxy)
            .send_to_kpasswd_realm(&config, KdcProtocol::Auto, "R.TEST", &[0, 1])
            .await;
        assert!(
            matches!(outcome, Err(Error::KpasswdOutcomeUnknown(_))),
            "{proxy:?}: {outcome:?}"
        );
        assert_eq!(
            proxy.seen().len(),
            1,
            "an uncertain password change is never resent"
        );
    }
    Ok(())
}

/// Without a proxy transport an `https://` entry fails before anything is sent,
/// and a password change does not become outcome-unknown.
#[tokio::test]
async fn missing_proxy_transport_is_definite() -> Result<(), Box<dyn StdError>> {
    let transport = Tokio {
        proxy: None,
        ..Tokio::new()
    };
    let config = profile("kpasswd_server", &["https://a.r.test/p"])?;
    let outcome = transport
        .send_to_kpasswd_realm(&config, KdcProtocol::Tcp, "R.TEST", &[0, 1])
        .await;
    let Err(Error::KdcEndpointFailures {
        failures,
        realm: _,
        protocol: _,
    }) = outcome
    else {
        return Err(format!("expected a definite endpoint failure, got {outcome:?}").into());
    };
    assert_eq!(failures.len(), 1);
    assert!(
        failures
            .iter()
            .all(|failure| failure.contains("no KDC proxy transport")),
        "{failures:?}"
    );
    Ok(())
}

/// A reply longer than the TCP response limit is refused.
#[tokio::test]
async fn proxy_replies_obey_the_response_limit() -> Result<(), Box<dyn StdError>> {
    static PROXY: Fake = Fake::new(&[Answer::Reply]);
    let config = profile("kdc", &["https://a.r.test/p"])?;
    let outcome = Tokio::new()
        .with_kdc_proxy(&PROXY)
        .with_tcp_response_limit(2)
        .send_to_realm(&config, KdcProtocol::Tcp, "R.TEST", &[0x6a])
        .await;
    let Err(Error::KdcEndpointFailures {
        failures,
        realm: _,
        protocol: _,
    }) = outcome
    else {
        return Err(format!("expected endpoint failures, got {outcome:?}").into());
    };
    assert!(
        failures.iter().all(|failure| failure.contains("exceeds 2")),
        "{failures:?}"
    );
    Ok(())
}

/// A proxy send is traced with the `https` protocol and the URL as its endpoint.
#[tokio::test]
async fn proxy_sends_are_traced_as_https() -> Result<(), Box<dyn StdError>> {
    static PROXY: Fake = Fake::new(&[Answer::Reply]);
    let config = profile("kdc", &["https://a.r.test/p"])?;
    let sink = Memory::new();
    let guard = Guard::new(sink.clone(), Options::new().with_identities(true));
    let transport = Tokio::new().with_kdc_proxy(&PROXY);
    let reply = super::traced(
        guard,
        transport.send_to_realm(&config, KdcProtocol::Tcp, "R.TEST", &[0x6a]),
    )
    .await?;
    assert_eq!(reply, [0x6b, 1, 2]);
    assert_eq!(
        sink.lines(),
        [
            "transport step=located wire=tcp target=R.TEST size=1",
            "transport step=sending wire=https target=https://a.r.test:443/p size=1",
            "transport step=answered wire=https target=https://a.r.test:443/p size=3",
        ]
    );
    Ok(())
}

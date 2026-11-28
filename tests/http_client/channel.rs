//! RFC 5929 channel bindings of the client (plan 2 todo 28, FU-HTC-P07).
//!
//! The `tls-server-end-point` hash each signature algorithm selects, and the
//! token built for, and sent over, the connection whose TLS peer it binds.
//!
//! The certificates and their expected hashes come from OpenSSL
//! (`tests/http_client/cbt/gen.sh`, `expected.txt`), not from this crate.

use alloc::sync::Arc;
use core::{
    future::ready,
    sync::atomic::{AtomicUsize, Ordering},
};
use std::{
    fs,
    path::PathBuf,
    sync::{Mutex, PoisonError},
};

use http_types::{Request, Response, StatusCode, Uri, header::AUTHORIZATION};
use rskrb5_ng::{
    error::{HttpClient as ClientError, HttpExchange as ExchangeError},
    gss::{self, AcceptorOptions, ChannelBindings},
    http::{
        self,
        agent::{ChannelBindingPolicy, NegotiateHttpClient},
        wire::{ConnectFuture, ExchangeFuture, HttpExchange, PreparedConnection, TlsChannel},
    },
    service::Validator,
    spnego::{self, AcceptStep},
};

use super::{
    context::{Context as _, TestError},
    support::{Network, keytab, negotiate_client, run, status},
};

/// The host every scenario talks to.
const HOST: &str = "secure.example.com";
/// Its URI.
const URI: &str = "https://secure.example.com/";

/// A fixture of `tests/http_client/cbt/`.
fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/http_client/cbt")
        .join(name)
}

/// The DER certificate `<name>.der`.
fn certificate(name: &str) -> Result<Vec<u8>, TestError> {
    Ok(fs::read(fixture(&format!("{name}.der")))?)
}

/// The OpenSSL-computed `tls-server-end-point` bindings of `<name>.der`, `None`
/// where RFC 5929 defines none.
fn expected(name: &str) -> Result<Option<ChannelBindings>, TestError> {
    let table = fs::read_to_string(fixture("expected.txt"))?;
    let line = table
        .lines()
        .find(|line| line.split(' ').next() == Some(name))
        .context("the fixture is listed in expected.txt")?;
    let digest = line.split(' ').nth(2).context("a digest column")?;
    if digest == "-" {
        return Ok(None);
    }
    Ok(Some(ChannelBindings::tls_server_end_point(&hex::decode(
        digest,
    )?)?))
}

/// The channel of a peer presenting `<name>.der`.
fn peer(name: &str) -> Result<TlsChannel, TestError> {
    Ok(TlsChannel::from_end_entity(certificate(name)?)?)
}

/// Each fixture's bindings use the hash RFC 5929 section 4.1 selects.
///
/// SHA-256 for MD5 and SHA-1, the algorithm's own hash otherwise, and no
/// bindings for `EdDSA` or a two-hash RSASSA-PSS signature.
#[test]
fn tls_server_end_point_hash_follows_the_signature_algorithm() -> Result<(), TestError> {
    let table = fs::read_to_string(fixture("expected.txt"))?;
    let names: Vec<&str> = table
        .lines()
        .filter_map(|line| line.split(' ').next())
        .collect();
    assert_eq!(names.len(), 11, "every fixture of gen.sh is listed");
    for name in names {
        // Given the OpenSSL fixture `name`,
        let channel = peer(name)?;
        // then its bindings are the ones OpenSSL computed.
        assert_eq!(
            channel.server_end_point(),
            expected(name)?.as_ref(),
            "{name}"
        );
        assert_eq!(channel.certificate(), certificate(name)?.as_slice());
    }
    Ok(())
}

/// A peer certificate that is not one DER X.509 certificate is refused.
#[test]
fn a_certificate_that_does_not_parse_is_refused() -> Result<(), TestError> {
    let good = certificate("ecdsa-sha256")?;
    let mut trailing = good.clone();
    trailing.push(0);
    let cases: [(&str, Vec<u8>); 5] = [
        ("empty", Vec::new()),
        ("garbage", b"not a certificate".to_vec()),
        ("truncated", good.get(..100).context("a prefix")?.to_vec()),
        ("trailing", trailing),
        (
            "oversized",
            vec![0x30; TlsChannel::MAX_CERTIFICATE_BYTES + 1],
        ),
    ];
    for (what, bytes) in cases {
        let result = TlsChannel::from_end_entity(bytes);
        assert!(
            matches!(result, Err(ExchangeError::PeerCertificate { reason: _ })),
            "{what}: {result:?}"
        );
    }
    Ok(())
}

/// The in-process network, with connections whose TLS peers the test names.
struct Tls {
    /// The origins.
    network: Network,
    /// The peer of the n-th connection; the last one repeats.
    peers: Vec<TlsChannel>,
    /// The connections opened.
    opened: AtomicUsize,
}

impl Tls {
    /// `network`, reached over connections presenting `peers` in order.
    fn new(network: Network, peers: Vec<TlsChannel>) -> Self {
        Self {
            network,
            peers,
            opened: AtomicUsize::new(0),
        }
    }
}

impl HttpExchange for Tls {
    fn exchange(&self, request: Request<Vec<u8>>) -> ExchangeFuture<'_> {
        self.network.exchange(request)
    }

    fn connect(&self, _uri: &Uri) -> ConnectFuture<'_> {
        let index = self.opened.fetch_add(1, Ordering::SeqCst);
        let channel = self.peers.get(index).or_else(|| self.peers.last()).cloned();
        Box::pin(ready(Ok(PreparedConnection::new(channel, |request| {
            self.network.exchange(request)
        }))))
    }
}

/// An HTTPS origin whose SPNEGO acceptor requires the channel `held`: a
/// request without a token gets the challenge, an accepted one `200`, a
/// refused one the `401` rejection.
fn bound_origin(
    held: ChannelBindings,
) -> impl Fn(&Request<Vec<u8>>) -> Response<Vec<u8>> + Send + Sync + 'static {
    let acceptor = Arc::new(Mutex::new(spnego::Acceptor::new(
        gss::Acceptor::from_validator(
            Validator::from_keytab(keytab(&[HOST])),
            AcceptorOptions::new()
                .with_channel_bindings(held)
                .require_channel_bindings(true),
        ),
    )));
    move |request| {
        let Some(header) = request
            .headers()
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
        else {
            return http::challenge_response();
        };
        let accepted = spnego::parse_negotiate_header(header)
            .ok()
            .and_then(|token| token.encode().ok())
            .map(|bytes| {
                acceptor
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .accept_sec_context(&bytes)
            });
        match accepted {
            Some(Ok(AcceptStep::Complete(_))) => status(StatusCode::OK),
            _ => http::reject_response().unwrap_or_else(|_| status(StatusCode::UNAUTHORIZED)),
        }
    }
}

/// The client of every scenario.
fn client<X>(exchange: X) -> Result<NegotiateHttpClient<X>, TestError>
where
    X: HttpExchange,
{
    Ok(
        NegotiateHttpClient::new(negotiate_client(&[HOST])?, exchange)
            .with_service_realm("EXAMPLE.COM"),
    )
}

/// Whether each request the origin saw carried a token.
fn tokens(network: &Network) -> Result<Vec<bool>, TestError> {
    Ok(network
        .seen_by(URI)?
        .iter()
        .map(|seen| seen.authorization().is_some())
        .collect())
}

/// A token built for the connection that carries it matches the binding the
/// acceptor derives from its own certificate.
#[test]
fn https_http_negotiate_matches_peer_binding() -> Result<(), TestError> {
    run(async {
        // Given an origin that requires the bindings of its ECDSA certificate,
        let held = expected("ecdsa-sha256")?.context("ecdsa-sha256 has bindings")?;
        let network = Network::new().serve(URI, bound_origin(held))?;
        // when the client reaches it over a connection presenting that certificate,
        let mut client = client(Tls::new(network.clone(), vec![peer("ecdsa-sha256")?]))?;
        let response = client.get(URI).await?;
        // then the bound token is accepted.
        assert_eq!(response.response().status(), StatusCode::OK);
        assert_eq!(tokens(&network)?, [false, true]);
        Ok(())
    })?
}

/// An acceptor holding other bindings refuses the token bound to this connection.
#[test]
fn https_http_negotiate_rejects_wrong_binding() -> Result<(), TestError> {
    run(async {
        // Given an origin that requires the bindings of another certificate,
        let held = expected("rsa-sha256")?.context("rsa-sha256 has bindings")?;
        let network = Network::new().serve(URI, bound_origin(held))?;
        // when the client reaches it over a connection presenting the ECDSA one,
        let mut client = client(Tls::new(network.clone(), vec![peer("ecdsa-sha256")?]))?;
        let response = client.get(URI).await?;
        // then the token is refused.
        assert_eq!(response.response().status(), StatusCode::UNAUTHORIZED);
        assert_eq!(tokens(&network)?, [false, true]);
        Ok(())
    })?
}

/// With the policy off, a token carries no connection bindings, so an
/// acceptor that requires them refuses it.
#[test]
fn binding_policy_off_sends_an_unbound_token() -> Result<(), TestError> {
    run(async {
        let held = expected("ecdsa-sha256")?.context("ecdsa-sha256 has bindings")?;
        let network = Network::new().serve(URI, bound_origin(held))?;
        let mut client = client(Tls::new(network.clone(), vec![peer("ecdsa-sha256")?]))?
            .with_channel_binding_policy(ChannelBindingPolicy::Off);
        let response = client.get(URI).await?;
        assert_eq!(response.response().status(), StatusCode::UNAUTHORIZED);
        assert_eq!(tokens(&network)?, [false, true]);
        Ok(())
    })?
}

/// A retry connection that presents another certificate than the one that
/// carried the challenge is refused before a token is sent.
#[test]
fn certificate_change_is_checked_before_authorization_send() -> Result<(), TestError> {
    run(async {
        // Given an origin whose challenge arrives over the ECDSA certificate
        let held = expected("rsa-sha256")?.context("rsa-sha256 has bindings")?;
        let network = Network::new().serve(URI, bound_origin(held))?;
        // and whose retry connection presents an RSA one,
        let peers = vec![peer("ecdsa-sha256")?, peer("rsa-sha256")?];
        let mut client = client(Tls::new(network.clone(), peers))?;
        // when the client answers the challenge,
        let result = client.get(URI).await;
        // then it stops before sending any token.
        assert!(
            matches!(result, Err(ClientError::ChannelChanged)),
            "{result:?}"
        );
        assert_eq!(tokens(&network)?, [false]);
        Ok(())
    })?
}

/// With bindings required, a connection without them gets no token: an
/// exchange that reports no TLS channel, and a certificate whose signature
/// algorithm defines no `tls-server-end-point` hash.
#[test]
fn required_binding_unavailable_sends_no_token() -> Result<(), TestError> {
    run(async {
        let held = expected("ecdsa-sha256")?.context("ecdsa-sha256 has bindings")?;
        for unbound in [None, Some(peer("ed25519")?)] {
            let network = Network::new().serve(URI, bound_origin(held.clone()))?;
            let result = match unbound.clone() {
                None => {
                    client(network.clone())?
                        .with_channel_binding_policy(ChannelBindingPolicy::Required)
                        .get(URI)
                        .await
                }
                Some(channel) => {
                    client(Tls::new(network.clone(), vec![channel]))?
                        .with_channel_binding_policy(ChannelBindingPolicy::Required)
                        .get(URI)
                        .await
                }
            };
            assert!(
                matches!(
                    result,
                    Err(ClientError::ChannelBindingUnavailable { reason: _ })
                ),
                "{unbound:?}: {result:?}"
            );
            assert_eq!(tokens(&network)?, [false], "{unbound:?}");
        }
        Ok(())
    })?
}

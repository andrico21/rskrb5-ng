//! The HTTP client against an HTTPS service that requires channel bindings.

use alloc::sync::Arc;
use core::{error::Error, future::ready, str, time::Duration};
use std::{env, fs, io, path::PathBuf};

use http_types::{Request, StatusCode, Uri, uri::Authority};
use rskrb5_ng::{
    NegotiateClient,
    client::{
        Tokio,
        principal::Principal,
        transport::{KdcProtocol, Tokio as KdcTransport},
    },
    config::Config,
    error::HttpExchange as ExchangeError,
    gss::{self, AcceptorOptions, ChannelBindings, ContextFlags},
    http::{
        agent::{ChannelBindingPolicy, NegotiateHttpClient},
        wire::{ConnectFuture, ExchangeFuture, HttpExchange, PreparedConnection},
    },
    keytab::Keytab,
    service::Validator,
    spnego::{self, AcceptStep, oid::ObjectIdentifier},
    transport::rustls_proxy::RustlsTransport,
};
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _},
};
use sha2::{Digest as _, Sha256};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpListener,
    runtime::Builder,
};
use tokio_rustls::TlsAcceptor;

use crate::harness::{self, Fixture, assert_negotiated_mechanism};

/// The TEST.RSKRB5 KDC (fixture `mit-kdc`).
const MIT_KDC: Fixture = Fixture::new("mit-kdc", "INTEROP_MIT_KDC");

/// The virtual host of the service: its Kerberos name is `HTTP/<host>`.
const HOST: &str = "http.test.rskrb5";

/// The first port of the scenarios (todo 28's range 19780-19789);
/// `INTEROP_HTTP_CBT_PORT` moves it.
const PORT: u16 = 19_780;

/// The longest request head the service reads.
const MAX_HEAD: usize = 64 * 1024;

/// A file of the test PKI of `tests/kkdcp/` (provenance: `tests/kkdcp/gen.sh`).
fn pki(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/kkdcp")
        .join(name)
}

/// The certificate chain of the PKI identity `identity`.
fn chain(identity: &str) -> Result<Vec<CertificateDer<'static>>, Box<dyn Error>> {
    Ok(
        CertificateDer::pem_file_iter(pki(&format!("{identity}.pem")))?
            .collect::<Result<Vec<_>, _>>()?,
    )
}

/// The `tls-server-end-point` bindings of `identity`'s certificate.
///
/// They are derived here, not by the client: the signature is ECDSA with
/// SHA-256, so the hash is SHA-256 of the DER certificate (RFC 5929 section
/// 4.1).
fn end_point(identity: &str) -> Result<ChannelBindings, Box<dyn Error>> {
    let chain = chain(identity)?;
    let certificate = chain.first().ok_or("the PEM file holds a certificate")?;
    Ok(ChannelBindings::tls_server_end_point(&Sha256::digest(
        certificate.as_ref(),
    ))?)
}

/// The port of scenario `offset`.
fn port(offset: u16) -> Result<u16, Box<dyn Error>> {
    let first = match env::var("INTEROP_HTTP_CBT_PORT") {
        Ok(text) => text.parse()?,
        Err(_) => PORT,
    };
    Ok(first.checked_add(offset).ok_or("the port overflows")?)
}

/// A complete HTTP/1.1 response that closes the connection.
fn http(status: &str, headers: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// The service's answer to a request `head`: the challenge without a token,
/// `200` naming the client and the binding for an accepted token, `403` with
/// the acceptor's refusal otherwise.
fn respond(head: &str, acceptor: &mut spnego::Acceptor<'static>) -> Vec<u8> {
    let Some(value) = head.lines().find_map(|line| {
        line.split_once(':')
            .filter(|(name, _)| name.trim().eq_ignore_ascii_case("authorization"))
            .map(|(_, value)| value.trim())
    }) else {
        return http("401 Unauthorized", "WWW-Authenticate: Negotiate\r\n", "");
    };
    let token = match spnego::parse_negotiate_header(value).and_then(|token| token.encode()) {
        Ok(token) => token,
        Err(error) => return http("403 Forbidden", "", &format!("refused={error:?}\n")),
    };
    match acceptor.accept_sec_context(&token) {
        Ok(AcceptStep::Complete(accepted)) => {
            let context = accepted.context().inquire();
            let mechanism = context
                .mechanism()
                .arcs()
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(".");
            http(
                "200 OK",
                "",
                &format!(
                    "principal={}\nchannel-bound={}\nmechanism={mechanism}\n",
                    context.source().display().0,
                    context.flags().contains(ContextFlags::CHANNEL_BOUND),
                ),
            )
        }
        Ok(_continued) => http("403 Forbidden", "", "refused=continue\n"),
        Err(error) => http("403 Forbidden", "", &format!("refused={error:?}\n")),
    }
}

/// Serve HTTPS on `listener` with the `localhost` identity of the test PKI,
/// one request per connection, until the listener fails.
async fn serve(listener: TcpListener, mut acceptor: spnego::Acceptor<'static>) -> io::Error {
    let config = match chain("localhost").and_then(|chain| {
        let key = PrivateKeyDer::from_pem_file(pki("localhost.key"))?;
        Ok(
            ServerConfig::builder_with_provider(Arc::new(rustls_rustcrypto::provider()))
                .with_safe_default_protocol_versions()?
                .with_no_client_auth()
                .with_single_cert(chain, key)?,
        )
    }) {
        Ok(config) => config,
        Err(error) => return io::Error::other(error.to_string()),
    };
    let tls = TlsAcceptor::from(Arc::new(config));
    loop {
        let tcp = match listener.accept().await {
            Ok((tcp, _peer)) => tcp,
            Err(error) => return error,
        };
        let Ok(mut stream) = tls.accept(tcp).await else {
            continue;
        };
        let mut head = Vec::new();
        let mut chunk = [0_u8; 4096];
        while !head.windows(4).any(|window| window == b"\r\n\r\n") && head.len() < MAX_HEAD {
            match stream.read(&mut chunk).await {
                Ok(read) if read > 0 => {
                    head.extend_from_slice(chunk.get(..read).unwrap_or_default());
                }
                _ => break,
            }
        }
        let answer = respond(&String::from_utf8_lossy(&head), &mut acceptor);
        drop(stream.write_all(&answer).await);
        drop(stream.shutdown().await);
    }
}

/// The built-in rustls transport, reaching the virtual host on `localhost`.
///
/// The certificate names `localhost` and the port is kept: the URI keeps
/// naming the Kerberos service, the connection is real TLS.
struct Loopback(RustlsTransport);

/// `uri` with its host replaced by `localhost`.
fn loopback(uri: &Uri) -> Result<Uri, ExchangeError> {
    let refused = |reason| ExchangeError::InvalidRequest { reason };
    let port = uri
        .port_u16()
        .ok_or_else(|| refused("the scenario URI names its port"))?;
    let mut parts = uri.clone().into_parts();
    parts.authority = Some(
        Authority::try_from(format!("localhost:{port}"))
            .map_err(|_refused| refused("the loopback authority"))?,
    );
    Uri::from_parts(parts).map_err(|_refused| refused("the loopback URI"))
}

/// `request` sent to `localhost`.
fn to_loopback(mut request: Request<Vec<u8>>) -> Result<Request<Vec<u8>>, ExchangeError> {
    *request.uri_mut() = loopback(request.uri())?;
    Ok(request)
}

impl HttpExchange for Loopback {
    fn exchange(&self, request: Request<Vec<u8>>) -> ExchangeFuture<'_> {
        Box::pin(async move { self.0.exchange(to_loopback(request)?).await })
    }

    fn connect(&self, uri: &Uri) -> ConnectFuture<'_> {
        let target = loopback(uri);
        Box::pin(async move {
            let prepared = self.0.connect(&target?).await?;
            let channel = prepared.tls_channel().cloned();
            Ok(PreparedConnection::new(
                channel,
                move |request| match to_loopback(request) {
                    Ok(local) => prepared.send(local),
                    Err(error) => Box::pin(ready(Err(error))),
                },
            ))
        })
    }
}

/// The client profile: the test realm on the published KDC port, no DNS.
///
/// `spake_preauth_groups` is empty, because the realm offers SPAKE and the
/// client answers it first, so the exchange proved here is the encrypted
/// timestamp.
fn config(realm: &str) -> Result<Config, Box<dyn Error>> {
    Ok(Config::parse(&format!(
        "[libdefaults]\n default_realm = {realm}\n dns_lookup_kdc = false\n spake_preauth_groups =\n\
         [realms]\n {realm} = {{\n  kdc = {}\n }}\n",
        harness::var("INTEROP_MIT_KDC")?,
    ))?)
}

/// An HTTP client for the test user over the built-in transport that trusts
/// the test CA, binding its tokens under `policy`.
fn client(policy: ChannelBindingPolicy) -> Result<NegotiateHttpClient<Loopback>, Box<dyn Error>> {
    let realm = harness::var("INTEROP_MIT_REALM")?;
    let user = Principal::user(realm.clone(), harness::var("INTEROP_MIT_USER")?);
    let password = harness::var("INTEROP_MIT_USER_PASSWORD")?.into_bytes();
    let negotiate = NegotiateClient::from_tokio_client(
        Tokio::with_password(config(&realm)?, KdcProtocol::Auto, user, password)
            .with_transport(KdcTransport::new().with_timeout(Duration::from_secs(10))),
    );
    let transport = RustlsTransport::new().with_pem_roots(&fs::read(pki("ca.pem"))?)?;
    Ok(NegotiateHttpClient::new(negotiate, Loopback(transport))
        .with_service_realm(realm)
        .with_channel_binding_policy(policy))
}

/// The service's acceptor: the realm's `HTTP/http.test.rskrb5` keytab and the
/// required bindings `held`.
fn acceptor(held: ChannelBindings) -> Result<spnego::Acceptor<'static>, Box<dyn Error>> {
    let keytab = Keytab::load(harness::var("INTEROP_MIT_HTTP_KEYTAB")?)?;
    Ok(spnego::Acceptor::new(gss::Acceptor::from_validator(
        Validator::from_keytab(keytab),
        AcceptorOptions::new()
            .with_channel_bindings(held)
            .require_channel_bindings(true),
    )))
}

/// One `GET` of the service on port `offset` that requires `held`, by a
/// client under `policy`: the status and the body.
fn exchange(
    offset: u16,
    held: ChannelBindings,
    policy: ChannelBindingPolicy,
) -> Result<(StatusCode, String), Box<dyn Error>> {
    let port = port(offset)?;
    let acceptor = acceptor(held)?;
    let mut client = client(policy)?;
    Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async move {
            let listener = TcpListener::bind(("127.0.0.1", port)).await?;
            let uri = format!("https://{HOST}:{port}/whoami");
            let served = serve(listener, acceptor);
            tokio::select! {
                result = client.get(&uri) => {
                    let response = result?.into_response();
                    Ok((response.status(), String::from_utf8(response.body().clone())?))
                }
                failure = served => Err(failure.into()),
            }
        })
}

/// A body line `key=value`.
fn line<'body>(body: &'body str, key: &str) -> Option<&'body str> {
    body.lines()
        .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
}

/// The client binds its token to the TLS connection that carries it.
///
/// The service, which requires the bindings of its own certificate, accepts
/// the MIT-issued ticket as a channel-bound krb5 context of the test user.
#[test]
fn http_client_binds_its_token_to_the_tls_channel() -> Result<(), Box<dyn Error>> {
    if !harness::require("http_client_binds_its_token_to_the_tls_channel", &[MIT_KDC])? {
        return Ok(());
    }
    let (status, body) = exchange(
        0,
        end_point("localhost")?,
        ChannelBindingPolicy::WhenAvailable,
    )?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let expected = format!(
        "{}@{}",
        harness::var("INTEROP_MIT_USER")?,
        harness::var("INTEROP_MIT_REALM")?
    );
    assert_eq!(line(&body, "principal"), Some(expected.as_str()), "{body}");
    assert_eq!(line(&body, "channel-bound"), Some("true"), "{body}");
    let mechanism: Vec<u32> = line(&body, "mechanism")
        .ok_or("the service names the mechanism")?
        .split('.')
        .map(str::parse)
        .collect::<Result<_, _>>()?;
    assert_negotiated_mechanism(ObjectIdentifier::krb5().arcs(), &mechanism)?;
    Ok(())
}

/// A service that requires the bindings of another certificate refuses the
/// token bound to the connection's real certificate.
#[test]
fn a_token_bound_to_another_certificate_is_refused() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "a_token_bound_to_another_certificate_is_refused",
        &[MIT_KDC],
    )? {
        return Ok(());
    }
    let (status, body) = exchange(
        1,
        end_point("other-host")?,
        ChannelBindingPolicy::WhenAvailable,
    )?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(line(&body, "refused"), Some("BadBindings"), "{body}");
    Ok(())
}

/// With channel binding off, the client's token carries no bindings and the
/// service that requires them refuses it.
#[test]
fn an_unbound_token_is_refused() -> Result<(), Box<dyn Error>> {
    if !harness::require("an_unbound_token_is_refused", &[MIT_KDC])? {
        return Ok(());
    }
    let (status, body) = exchange(2, end_point("localhost")?, ChannelBindingPolicy::Off)?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(line(&body, "refused"), Some("MissingBindings"), "{body}");
    Ok(())
}

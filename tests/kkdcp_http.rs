//! The built-in HTTPS `HttpExchange` against a local TLS server (plan 2 todo 26,
//! the `kkdcp-rustls` leaf): the test PKI of `tests/kkdcp/` (provenance:
//! `tests/kkdcp/gen.sh`) and a loopback server that answers one request.
#![cfg(all(feature = "kkdcp-rustls", feature = "http", feature = "tokio"))]

extern crate alloc;

/// The exchange scenarios.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use alloc::sync::Arc;
    use core::{error::Error as StdError, time::Duration};
    use std::{fs, path::PathBuf};

    use http_types::{
        Method, Request, StatusCode,
        header::{AUTHORIZATION, WWW_AUTHENTICATE},
    };
    use rskrb5_ng::{
        error::HttpExchange as ExchangeError, gss::ChannelBindings, http::wire::HttpExchange as _,
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
        task::JoinHandle,
        time::timeout,
    };
    use tokio_rustls::TlsAcceptor;

    /// The fixture directory.
    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/kkdcp")
            .join(name)
    }

    /// The transport that trusts the test CA.
    fn trusting() -> Result<RustlsTransport, Box<dyn StdError>> {
        Ok(RustlsTransport::new().with_pem_roots(&fs::read(fixture("ca.pem"))?)?)
    }

    /// A one-connection TLS server presenting `identity` that answers `response`
    /// and returns the request head it read (`None` when TLS failed).
    async fn server(
        identity: &str,
        response: Vec<u8>,
    ) -> Result<(u16, JoinHandle<Option<String>>), Box<dyn StdError>> {
        let chain = CertificateDer::pem_file_iter(fixture(&format!("{identity}.pem")))?
            .collect::<Result<Vec<_>, _>>()?;
        let key = PrivateKeyDer::from_pem_file(fixture(&format!("{identity}.key")))?;
        let config = ServerConfig::builder_with_provider(Arc::new(rustls_rustcrypto::provider()))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(chain, key)?;
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.ok()?;
            let mut tls = acceptor.accept(tcp).await.ok()?;
            let mut bytes = Vec::new();
            let mut chunk = [0_u8; 4096];
            while !bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = tls.read(&mut chunk).await.ok()?;
                if read == 0 {
                    return None;
                }
                bytes.extend_from_slice(chunk.get(..read)?);
            }
            tls.write_all(&response).await.ok()?;
            tls.shutdown().await.ok()?;
            String::from_utf8(bytes).ok()
        });
        Ok((port, task))
    }

    /// An HTTP response.
    fn http(status: &str, headers: &str, body: &[u8]) -> Vec<u8> {
        let mut response = format!(
            "HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(body);
        response
    }

    /// The server task's result, bounded so a client that never connects fails here.
    async fn seen(task: JoinHandle<Option<String>>) -> Result<Option<String>, Box<dyn StdError>> {
        Ok(timeout(Duration::from_secs(10), task).await??)
    }

    /// A `GET` for `https://localhost:<port>/<path>` with an Authorization header.
    fn get(port: u16, path: &str) -> Result<Request<Vec<u8>>, Box<dyn StdError>> {
        Ok(Request::builder()
            .method(Method::GET)
            .uri(format!("https://localhost:{port}/{path}"))
            .header(AUTHORIZATION, "Negotiate dG9rZW4=")
            .body(Vec::new())?)
    }

    /// The response comes back whole: status, headers and body of a `401`, and
    /// the server saw the request line and the Authorization header.
    #[test]
    fn the_response_comes_back_whole() -> Result<(), Box<dyn StdError>> {
        Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                let challenge = http(
                    "401 Unauthorized",
                    "WWW-Authenticate: Negotiate\r\n",
                    b"denied",
                );
                let (port, task) = server("localhost", challenge).await?;
                let response = trusting()?.exchange(get(port, "whoami?x=1")?).await?;
                assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
                assert_eq!(
                    response
                        .headers()
                        .get(WWW_AUTHENTICATE)
                        .map(http_types::HeaderValue::as_bytes),
                    Some(&b"Negotiate"[..])
                );
                assert_eq!(response.body().as_slice(), b"denied");
                let head = seen(task).await?.ok_or("the server saw no request")?;
                assert!(head.starts_with("GET /whoami?x=1 HTTP/1.1\r\n"), "{head}");
                assert!(
                    head.to_ascii_lowercase()
                        .contains("authorization: negotiate dg9rzw4="),
                    "{head}"
                );
                Ok(())
            })
    }

    /// A redirect is a response, never followed: the server is asked once.
    #[test]
    fn a_redirect_is_returned_not_followed() -> Result<(), Box<dyn StdError>> {
        Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                let moved = http("302 Found", "Location: https://elsewhere.example/\r\n", b"");
                let (port, task) = server("localhost", moved).await?;
                let response = trusting()?.exchange(get(port, "")?).await?;
                assert_eq!(response.status(), StatusCode::FOUND);
                drop(seen(task).await?);
                Ok(())
            })
    }

    /// No configured root is a typed error before any connection; so is a
    /// cleartext URI, a server the roots do not vouch for and an oversized body.
    #[test]
    fn refusals_are_typed() -> Result<(), Box<dyn StdError>> {
        Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                let none = RustlsTransport::new().exchange(get(9, "")?).await;
                assert!(matches!(none, Err(ExchangeError::NoAnchors)), "{none:?}");

                let plain = Request::builder()
                    .uri("http://localhost:9/")
                    .body(Vec::new())?;
                let cleartext = trusting()?.exchange(plain).await;
                assert!(
                    matches!(
                        cleartext,
                        Err(ExchangeError::UnsupportedScheme { scheme: _ })
                    ),
                    "{cleartext:?}"
                );

                let (port, task) = server("untrusted", http("200 OK", "", b"x")).await?;
                let untrusted = trusting()?.exchange(get(port, "")?).await;
                assert!(
                    matches!(untrusted, Err(ExchangeError::NotDelivered(_))),
                    "{untrusted:?}"
                );
                drop(seen(task).await?);

                let big = vec![b'x'; 9 * 1024 * 1024];
                let (big_port, big_task) = server("localhost", http("200 OK", "", &big)).await?;
                let oversized = trusting()?.exchange(get(big_port, "")?).await;
                assert!(
                    matches!(oversized, Err(ExchangeError::TooLarge { limit: _ })),
                    "{oversized:?}"
                );
                drop(seen(big_task).await?);
                Ok(())
            })
    }

    /// The DER end-entity certificate of the identity `identity`.
    fn end_entity(identity: &str) -> Result<Vec<u8>, Box<dyn StdError>> {
        let first = CertificateDer::pem_file_iter(fixture(&format!("{identity}.pem")))?
            .next()
            .ok_or("the PEM file holds a certificate")??;
        Ok(first.to_vec())
    }

    /// `connect` reports the TLS peer of the connection that then sends.
    ///
    /// The certificate the server presented comes with its SHA-256
    /// `tls-server-end-point` bindings (ECDSA with SHA-256, RFC 5929 section
    /// 4.1); the request travels over that connection, the only one the
    /// server accepts.
    #[test]
    fn connect_reports_the_peer_of_the_connection_that_sends() -> Result<(), Box<dyn StdError>> {
        Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                let (port, task) = server("localhost", http("200 OK", "", b"bound")).await?;
                let transport = trusting()?;
                let request = get(port, "cbt")?;
                let connection = transport.connect(request.uri()).await?;
                let channel = connection
                    .tls_channel()
                    .ok_or("the built-in exchange reports its TLS peer")?;
                let der = end_entity("localhost")?;
                assert_eq!(channel.certificate(), der.as_slice());
                assert_eq!(
                    channel.server_end_point(),
                    Some(&ChannelBindings::tls_server_end_point(&Sha256::digest(
                        &der
                    ))?)
                );
                let response = connection.send(request).await?;
                assert_eq!(response.body().as_slice(), b"bound");
                let head = seen(task).await?.ok_or("the server saw no request")?;
                assert!(head.starts_with("GET /cbt HTTP/1.1\r\n"), "{head}");
                Ok(())
            })
    }

    /// A prepared connection carries a request for its own origin only.
    #[test]
    fn a_prepared_connection_refuses_another_origin() -> Result<(), Box<dyn StdError>> {
        Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                let (port, task) = server("localhost", http("200 OK", "", b"")).await?;
                let transport = trusting()?;
                let connection = transport.connect(get(port, "")?.uri()).await?;
                let elsewhere = Request::builder()
                    .uri(format!("https://other.example:{port}/"))
                    .body(Vec::new())?;
                let refused = connection.send(elsewhere).await;
                assert!(
                    matches!(refused, Err(ExchangeError::InvalidRequest { reason: _ })),
                    "{refused:?}"
                );
                drop(timeout(Duration::from_secs(10), task).await);
                Ok(())
            })
    }
}

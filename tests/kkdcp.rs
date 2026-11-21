//! The built-in KDC proxy transport against a local TLS proxy (plan 2 todo 16, the
//! `kkdcp-rustls` leaf).
//!
//! A loopback TLS server with the test PKI of `tests/kkdcp/` (provenance:
//! `tests/kkdcp/gen.sh`) plays the MS-KKDCP proxy. The scenarios cover the happy
//! path directly and through the Tokio transport's `https://` routing, and every
//! rejection the plan names: a wrong anchor, a certificate for another host, a
//! redirect, another status, an oversized body and missing anchors.
#![cfg(all(feature = "kkdcp-rustls", feature = "tokio"))]

extern crate alloc;

/// The proxy scenarios.
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

    use rskrb5_ng::{
        client::transport::{KdcProtocol, Tokio},
        config::{Config, section_values::Location},
        error::{Client as ClientError, KdcProxy},
        transport::{
            kkdcp::{MAX_MESSAGE, ProxyMessage},
            proxy::{KdcProxyTransport as _, Request, Url},
            rustls_proxy::RustlsTransport,
        },
    };
    use rustls::{
        ServerConfig,
        pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _},
    };
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::TcpListener,
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

    /// The trusted test CA as an `http_anchors` location.
    fn trusted() -> Location {
        Location::File(fixture("ca.pem").display().to_string())
    }

    /// What the proxy saw: its request head and body; `None` when TLS failed.
    type Seen = Option<(String, Vec<u8>)>;

    /// A one-connection TLS proxy presenting `identity` that answers `response`.
    async fn proxy(
        identity: &str,
        response: Vec<u8>,
    ) -> Result<(u16, JoinHandle<Seen>), Box<dyn StdError>> {
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
            let (head, length) = loop {
                let read = tls.read(&mut chunk).await.ok()?;
                bytes.extend_from_slice(chunk.get(..read)?);
                if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                    let head = String::from_utf8(bytes.get(..end)?.to_vec()).ok()?;
                    let length = head
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length: "))
                        .and_then(|value| value.parse::<usize>().ok())
                        .unwrap_or_default();
                    drop(bytes.drain(..end.saturating_add(4)));
                    break (head, length);
                }
                if read == 0 {
                    return None;
                }
            };
            while bytes.len() < length {
                let read = tls.read(&mut chunk).await.ok()?;
                if read == 0 {
                    return None;
                }
                bytes.extend_from_slice(chunk.get(..read)?);
            }
            tls.write_all(&response).await.ok()?;
            tls.shutdown().await.ok()?;
            Some((head, bytes))
        });
        Ok((port, task))
    }

    /// An HTTP response with `status` and `body`.
    fn http(status: &str, body: &[u8]) -> Vec<u8> {
        let mut response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/kerberos\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(body);
        response
    }

    /// A `200` response carrying the KDC reply `[0x6b, 1, 2]`.
    fn kdc_reply() -> Result<Vec<u8>, Box<dyn StdError>> {
        let message = ProxyMessage::new(&[0, 0, 0, 3, 0x6b, 1, 2], None, None).encode()?;
        Ok(http("200 OK", &message))
    }

    /// The proxy task's result, bounded so a client that never connects fails here.
    async fn seen(task: JoinHandle<Seen>) -> Result<Seen, Box<dyn StdError>> {
        Ok(timeout(Duration::from_secs(10), task).await??)
    }

    /// POST `body` to the proxy on `port` through the built-in transport.
    async fn post(
        transport: &RustlsTransport,
        (host, port): (&str, u16),
        anchors: &[Location],
        max_response: usize,
    ) -> Result<Vec<u8>, KdcProxy> {
        let url = Url::parse(&format!("https://{host}:{port}/KdcProxy"))?.ok_or(
            KdcProxy::InvalidUrl {
                reason: "not a proxy URL",
            },
        )?;
        let body = [0x30, 0x03, 0x02, 0x01, 0x05];
        let request = Request::new(&url, &body)
            .with_realm("R.TEST")
            .with_anchors(anchors)
            .with_max_response(max_response);
        timeout(Duration::from_secs(10), transport.post(request))
            .await
            .map_err(|elapsed| KdcProxy::NotDelivered(Box::new(elapsed)))?
    }

    /// The happy path: the anchor verifies the chain, the request carries the MIT
    /// headers on HTTP/1.1, and the body comes back.
    #[tokio::test]
    async fn posts_to_a_verified_proxy() -> Result<(), Box<dyn StdError>> {
        for (host, anchor) in [
            ("localhost", trusted()),
            (
                "127.0.0.1",
                Location::Directory(fixture("").display().to_string()),
            ),
        ] {
            let (port, task) = proxy("localhost", kdc_reply()?).await?;
            let body = post(
                &RustlsTransport::new(),
                (host, port),
                &[anchor],
                MAX_MESSAGE,
            )
            .await?;
            assert_eq!(
                body,
                ProxyMessage::new(&[0, 0, 0, 3, 0x6b, 1, 2], None, None)
                    .encode()?
                    .as_slice()
            );
            let (head, request) = seen(task).await?.ok_or("the proxy saw no request")?;
            assert!(head.starts_with("POST /KdcProxy HTTP/1.1\r\n"), "{head}");
            for line in [
                format!("host: {host}:{port}"),
                "content-type: application/kerberos".to_owned(),
                "content-length: 5".to_owned(),
                "cache-control: no-cache".to_owned(),
                "pragma: no-cache".to_owned(),
            ] {
                assert!(
                    head.lines().any(|found| found == line),
                    "{line} missing in {head}"
                );
            }
            assert_eq!(request, [0x30, 0x03, 0x02, 0x01, 0x05]);
        }
        Ok(())
    }

    /// A transport with configured PEM roots needs no `http_anchors`.
    #[tokio::test]
    async fn configured_roots_replace_missing_anchors() -> Result<(), Box<dyn StdError>> {
        let (port, task) = proxy("localhost", kdc_reply()?).await?;
        let transport = RustlsTransport::new().with_pem_roots(&fs::read(fixture("ca.pem"))?)?;
        drop(post(&transport, ("localhost", port), &[], MAX_MESSAGE).await?);
        assert!(seen(task).await?.is_some());
        Ok(())
    }

    /// No anchor and no configured root: refused before any connection.
    #[tokio::test]
    async fn missing_anchors_are_refused() -> Result<(), Box<dyn StdError>> {
        let none = post(&RustlsTransport::new(), ("localhost", 9), &[], MAX_MESSAGE).await;
        assert!(
            matches!(&none, Err(KdcProxy::NoAnchors { realm }) if realm == "R.TEST"),
            "{none:?}"
        );
        for location in [
            Location::File(fixture("missing.pem").display().to_string()),
            Location::File(fixture("gen.sh").display().to_string()),
            Location::Pkcs11("module_name=never".to_owned()),
        ] {
            let outcome = post(
                &RustlsTransport::new(),
                ("localhost", 9),
                &[location],
                MAX_MESSAGE,
            )
            .await;
            assert!(
                matches!(
                    outcome,
                    Err(KdcProxy::Anchor {
                        anchor: _,
                        reason: _
                    })
                ),
                "{outcome:?}"
            );
        }
        Ok(())
    }

    /// A chain from an untrusted CA is refused before the request is sent.
    #[tokio::test]
    async fn wrong_anchor_is_refused() -> Result<(), Box<dyn StdError>> {
        let (port, task) = proxy("untrusted", kdc_reply()?).await?;
        let outcome = post(
            &RustlsTransport::new(),
            ("localhost", port),
            &[trusted()],
            MAX_MESSAGE,
        )
        .await;
        assert!(
            matches!(outcome, Err(KdcProxy::NotDelivered(_))),
            "{outcome:?}"
        );
        assert!(
            seen(task).await?.is_none(),
            "the request reached an unverified proxy"
        );
        let (trusted_port, trusted_task) = proxy("localhost", kdc_reply()?).await?;
        let other = Location::File(fixture("other-ca.pem").display().to_string());
        let refused = post(
            &RustlsTransport::new(),
            ("localhost", trusted_port),
            &[other],
            MAX_MESSAGE,
        )
        .await;
        assert!(
            matches!(refused, Err(KdcProxy::NotDelivered(_))),
            "{refused:?}"
        );
        assert!(
            seen(trusted_task).await?.is_none(),
            "the request reached an unverified proxy"
        );
        Ok(())
    }

    /// A trusted certificate for another host is refused (QA failure scenario).
    #[tokio::test]
    async fn certificate_for_another_host_is_refused() -> Result<(), Box<dyn StdError>> {
        for host in ["localhost", "127.0.0.1"] {
            let (port, task) = proxy("other-host", kdc_reply()?).await?;
            let outcome = post(
                &RustlsTransport::new(),
                (host, port),
                &[trusted()],
                MAX_MESSAGE,
            )
            .await;
            assert!(
                matches!(outcome, Err(KdcProxy::NotDelivered(_))),
                "{host}: {outcome:?}"
            );
            assert!(
                seen(task).await?.is_none(),
                "the request reached the wrong host"
            );
        }
        Ok(())
    }

    /// A redirect is not followed, and any other status is refused.
    #[tokio::test]
    async fn redirects_and_other_statuses_are_refused() -> Result<(), Box<dyn StdError>> {
        for (status, code) in [
            (
                "302 Found\r\nLocation: https://localhost:9/elsewhere",
                302_u16,
            ),
            ("307 Temporary Redirect\r\nLocation: /elsewhere", 307),
            ("500 Internal Server Error", 500),
        ] {
            let (port, task) = proxy("localhost", http(status, b"")).await?;
            let outcome = post(
                &RustlsTransport::new(),
                ("localhost", port),
                &[trusted()],
                MAX_MESSAGE,
            )
            .await;
            assert!(
                matches!(outcome, Err(KdcProxy::Status { status: found }) if found == code),
                "{code}: {outcome:?}"
            );
            assert!(seen(task).await?.is_some());
        }
        Ok(())
    }

    /// A body longer than the bound is refused while it is read.
    #[tokio::test]
    async fn oversized_body_is_refused() -> Result<(), Box<dyn StdError>> {
        let (port, task) = proxy("localhost", http("200 OK", &[0x30; 65])).await?;
        let outcome = post(
            &RustlsTransport::new(),
            ("localhost", port),
            &[trusted()],
            64,
        )
        .await;
        assert!(
            matches!(
                outcome,
                Err(KdcProxy::TooLarge {
                    actual: 65,
                    limit: 64
                })
            ),
            "{outcome:?}"
        );
        drop(seen(task).await?);
        Ok(())
    }

    /// The Tokio transport sends an `https://` KDC's requests through the built-in
    /// transport with the realm's `http_anchors`, and refuses without them.
    #[tokio::test]
    async fn tokio_transport_uses_the_builtin_proxy() -> Result<(), Box<dyn StdError>> {
        let (port, task) = proxy("localhost", kdc_reply()?).await?;
        let ca = fixture("ca.pem").display().to_string();
        let config = Config::parse(&format!(
            "[libdefaults]\ndns_lookup_kdc = false\n[realms]\nR.TEST = {{\nkdc = https://localhost:{port}/KdcProxy\nhttp_anchors = FILE:{ca}\n}}\n"
        ))?;
        let transport = Tokio::new().with_timeout(Duration::from_secs(10));
        let reply = transport
            .send_to_realm(&config, KdcProtocol::Tcp, "R.TEST", &[0x6a, 7])
            .await?;
        assert_eq!(reply, [0x6b, 1, 2]);
        let (_, body) = seen(task).await?.ok_or("the proxy saw no request")?;
        let message = ProxyMessage::decode(&body)?;
        assert_eq!(message.kerb_message(), [0, 0, 0, 2, 0x6a, 7]);
        assert_eq!(message.target_domain(), Some(b"R.TEST".as_slice()));
        let without = Config::parse(&format!(
            "[libdefaults]\ndns_lookup_kdc = false\n[realms]\nR.TEST = {{\nkdc = https://localhost:{port}/KdcProxy\n}}\n"
        ))?;
        let outcome = transport
            .send_to_realm(&without, KdcProtocol::Tcp, "R.TEST", &[0x6a, 7])
            .await;
        let Err(ClientError::KdcEndpointFailures {
            failures,
            realm: _,
            protocol: _,
        }) = outcome
        else {
            return Err(format!("expected endpoint failures, got {outcome:?}").into());
        };
        assert!(
            failures
                .iter()
                .all(|failure| failure.contains("no trust anchors")),
            "{failures:?}"
        );
        Ok(())
    }
}

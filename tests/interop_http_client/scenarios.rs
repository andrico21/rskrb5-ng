//! The HTTP client against Apache `mod_auth_gssapi`, and the session manager
//! behind a Rust acceptor with Apache's keytab.

use core::{error::Error, fmt::Write as _, str, time::Duration};
use std::io;

use http_types::{
    Request, Response, StatusCode,
    header::{LOCATION, WWW_AUTHENTICATE},
    uri::PathAndQuery,
};
use rskrb5_ng::{
    NegotiateClient,
    client::{
        Tokio,
        principal::Principal,
        transport::{KdcProtocol, Tokio as KdcTransport},
    },
    config::Config,
    error::{Http as HttpError, HttpClient as ClientError, HttpExchange as ExchangeError},
    http::{
        ClientNegotiateResponse,
        agent::NegotiateHttpClient,
        cookies::CookieStore,
        wire::{ExchangeFuture, HttpExchange},
    },
    spnego::{self, Token, oid::ObjectIdentifier},
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpStream,
    runtime::{Builder, Runtime},
};

use crate::harness::{self, Fixture, assert_negotiated_mechanism};

/// The TEST.RSKRB5 KDC (fixture `mit-kdc`).
const MIT_KDC: Fixture = Fixture::new("mit-kdc", "INTEROP_MIT_KDC");

/// The Apache fixture, reached on `INTEROP_HTTPD`.
const HTTPD: Fixture = Fixture::new("httpd", "INTEROP_HTTPD");

/// Largest response the exchange reads from the fixture.
const RESPONSE_LIMIT: u64 = 64 * 1024;

/// The current-thread Tokio runtime the scenarios run on.
fn runtime() -> io::Result<Runtime> {
    Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
}

/// A plain-HTTP exchange that sends every request to one endpoint, whatever
/// the host of its URI (the URI names the virtual host and the Kerberos service,
/// the endpoint is the published fixture port).
///
/// The fixture's docroot denies everything outside `/whoami/` (so Apache's own
/// `mod_dir` redirect of `/whoami` is a `403`): a request for the path in field 1 is
/// answered here with a same-origin `302` to `/whoami/`, as an application in
/// front of Apache would, and every other request goes to Apache.
struct Endpoint(String, Option<&'static str>);

impl HttpExchange for Endpoint {
    fn exchange(&self, request: Request<Vec<u8>>) -> ExchangeFuture<'_> {
        Box::pin(async move {
            if self.1 == Some(request.uri().path()) {
                return Response::builder()
                    .status(StatusCode::FOUND)
                    .header(LOCATION, "/whoami/")
                    .body(Vec::new())
                    .map_err(|_refused| ExchangeError::InvalidRequest {
                        reason: "the redirect does not build",
                    });
            }
            let not_delivered = |error: io::Error| ExchangeError::NotDelivered(Box::new(error));
            let maybe = |error: io::Error| ExchangeError::MaybeDelivered(Box::new(error));
            let authority = request
                .uri()
                .authority()
                .ok_or(ExchangeError::InvalidRequest {
                    reason: "no authority",
                })?
                .to_string();
            let target = request
                .uri()
                .path_and_query()
                .map_or("/", PathAndQuery::as_str)
                .to_owned();
            let mut head = format!(
                "{} {target} HTTP/1.0\r\nHost: {authority}\r\n",
                request.method()
            );
            for (name, value) in request.headers() {
                let text = value
                    .to_str()
                    .map_err(|_refused| ExchangeError::InvalidRequest {
                        reason: "a header is not text",
                    })?;
                write!(head, "{name}: {text}\r\n").map_err(|_refused| {
                    ExchangeError::InvalidRequest {
                        reason: "a header does not format",
                    }
                })?;
            }
            head.push_str("\r\n");
            let mut stream = TcpStream::connect(&self.0).await.map_err(not_delivered)?;
            stream.write_all(head.as_bytes()).await.map_err(maybe)?;
            stream.write_all(request.body()).await.map_err(maybe)?;
            let mut raw = Vec::new();
            let _length = stream
                .take(RESPONSE_LIMIT)
                .read_to_end(&mut raw)
                .await
                .map_err(maybe)?;
            parse_response(&raw).map_err(maybe)
        })
    }
}

/// Parses a raw HTTP/1.x response (status line, headers, body).
fn parse_response(raw: &[u8]) -> io::Result<Response<Vec<u8>>> {
    let invalid = |what: &str| io::Error::new(io::ErrorKind::InvalidData, what.to_owned());
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| invalid("response has no header end"))?;
    let (head, rest) = raw
        .split_at_checked(split)
        .ok_or_else(|| invalid("response head out of range"))?;
    let body = rest
        .get(4..)
        .ok_or_else(|| invalid("response body out of range"))?;
    let text = str::from_utf8(head).map_err(io::Error::other)?;
    let mut lines = text.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split(' ').nth(1))
        .ok_or_else(|| invalid("response has no status line"))?;
    let mut response = Response::builder()
        .status(StatusCode::from_bytes(status.as_bytes()).map_err(io::Error::other)?);
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| invalid("malformed header"))?;
        response = response.header(name.trim(), value.trim());
    }
    response.body(body.to_vec()).map_err(io::Error::other)
}

/// The client profile: the test realm on the published KDC port, no DNS, and an
/// empty `spake_preauth_groups`, because the realm offers SPAKE and the client
/// answers it first, so the exchange proved here is the encrypted timestamp.
fn config(realm: &str) -> Result<Config, Box<dyn Error>> {
    Ok(Config::parse(&format!(
        "[libdefaults]\n default_realm = {realm}\n dns_lookup_kdc = false\n spake_preauth_groups =\n\
         [realms]\n {realm} = {{\n  kdc = {}\n }}\n",
        harness::var("INTEROP_MIT_KDC")?,
    ))?)
}

/// An HTTP client for the test user, sending to Apache's endpoint, with a
/// cookie jar and the options of `options`.
fn client(
    options: spnego::InitiatorContextOptions,
    redirect_from: Option<&'static str>,
) -> Result<NegotiateHttpClient<Endpoint>, Box<dyn Error>> {
    let realm = harness::var("INTEROP_MIT_REALM")?;
    let user = Principal::user(realm.clone(), harness::var("INTEROP_MIT_USER")?);
    let password = harness::var("INTEROP_MIT_USER_PASSWORD")?.into_bytes();
    let negotiate = NegotiateClient::from_tokio_client(
        Tokio::with_password(config(&realm)?, KdcProtocol::Auto, user, password)
            .with_transport(KdcTransport::new().with_timeout(Duration::from_secs(10))),
    );
    Ok(NegotiateHttpClient::new(
        negotiate,
        Endpoint(harness::var("INTEROP_HTTPD")?, redirect_from),
    )
    .with_options(options)
    .with_service_realm(realm)
    .with_cookie_jar(CookieStore::new()))
}

/// Initiator options that require mutual authentication.
fn mutual() -> spnego::InitiatorContextOptions {
    spnego::InitiatorContextOptions::new().with_context_flags([spnego::CONTEXT_FLAG_MUTUAL])
}

/// The page names the authenticated user and the mechanism Apache accepted.
fn assert_page(bytes: &[u8], user: &str, realm: &str) -> Result<(), Box<dyn Error>> {
    let body = str::from_utf8(bytes)?;
    let expected = format!("principal={user}@{realm}");
    assert!(
        body.lines().any(|line| line == expected),
        "the page names the authenticated user ({expected}): {body}"
    );
    assert!(
        body.lines().any(|line| line == "mechanism=Negotiate/krb5"),
        "mod_auth_gssapi accepted the krb5 mechanism through Negotiate: {body}"
    );
    Ok(())
}

/// The HTTP client answers Apache's bare Negotiate challenge with a krb5 SPNEGO
/// token for `HTTP/httpd.test.rskrb5`, requires mutual authentication, and the
/// AP-REP of the final response verifies and selects the krb5 mechanism.
#[test]
fn http_client_negotiates_with_apache_and_proves_the_server() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "http_client_negotiates_with_apache_and_proves_the_server",
        &[MIT_KDC, HTTPD],
    )? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let realm = harness::var("INTEROP_MIT_REALM")?;
        let user = harness::var("INTEROP_MIT_USER")?;
        let host = harness::var("INTEROP_HTTPD_HOST")?;
        let mut client = client(mutual(), None)?;
        let result = client.get(&format!("http://{host}/whoami/")).await?;
        let response = result.response();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(result.redirects(), 0);
        assert!(
            matches!(
                result.negotiation(),
                Some(ClientNegotiateResponse::Accepted { ap_rep: Some(_) })
            ),
            "Apache proved its identity with a verified AP-REP: {:?}",
            result.negotiation()
        );
        let reply = response
            .headers()
            .get(WWW_AUTHENTICATE)
            .ok_or("the 200 response carries no Negotiate reply token")?
            .to_str()?;
        let Token::Resp(reply_token) = spnego::parse_negotiate_header(reply)? else {
            return Err("the Negotiate reply is not a SPNEGO NegTokenResp".into());
        };
        let selected = reply_token
            .supported_mech()
            .ok_or("the SPNEGO reply names no mechanism")?;
        assert_negotiated_mechanism(ObjectIdentifier::krb5().arcs(), selected.arcs())?;
        assert_page(response.body(), &user, &realm)
    })
}

/// A same-origin redirect to `/whoami/`: the client follows it, answers
/// Apache's challenge there and proves the server on the final response.
#[test]
fn http_client_follows_a_same_origin_redirect_and_negotiates() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "http_client_follows_a_same_origin_redirect_and_negotiates",
        &[MIT_KDC, HTTPD],
    )? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let realm = harness::var("INTEROP_MIT_REALM")?;
        let user = harness::var("INTEROP_MIT_USER")?;
        let host = harness::var("INTEROP_HTTPD_HOST")?;
        let mut client = client(mutual(), Some("/start"))?;
        let result = client.get(&format!("http://{host}/start")).await?;
        assert_eq!(result.response().status(), StatusCode::OK);
        assert_eq!(result.redirects(), 1, "one redirect was followed");
        assert_eq!(result.uri().path(), "/whoami/");
        assert!(
            matches!(
                result.negotiation(),
                Some(ClientNegotiateResponse::Accepted { ap_rep: Some(_) })
            ),
            "the final response proves the server: {:?}",
            result.negotiation()
        );
        assert_page(result.response().body(), &user, &realm)
    })
}

/// A service the realm does not know is a typed Negotiate error from the KDC,
/// never a request to the server with a made-up token.
#[test]
fn http_client_refuses_a_service_the_realm_does_not_know() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "http_client_refuses_a_service_the_realm_does_not_know",
        &[MIT_KDC, HTTPD],
    )? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let mut client = client(mutual(), None)?;
        let refused = client.get("http://nosuchhost.test.rskrb5/whoami/").await;
        assert!(
            matches!(refused, Err(ClientError::Negotiate(HttpError::Client(_)))),
            "an unknown service principal is refused by the KDC: {refused:?}"
        );
        Ok::<_, Box<dyn Error>>(())
    })
}

/// A Rust acceptor behind the realm: the session manager continues a Negotiate
/// exchange that the MIT KDC's ticket opened.
#[cfg(feature = "tower")]
mod continuation {
    use alloc::sync::Arc;
    use core::{
        convert::Infallible,
        error::Error,
        future::{Future as _, Ready, ready},
        pin::pin,
        task::{Context, Poll, Waker},
    };

    use http_types::{
        HeaderValue, Request, Response, StatusCode,
        header::{AUTHORIZATION, COOKIE, SET_COOKIE},
    };
    use rskrb5_ng::{
        client::principal::Principal,
        gss::TransferKey,
        http::{
            NegotiateLayer,
            sessions::{SessionIdentity, SessionManager},
        },
        spnego::AcceptedContext,
    };
    use tower_layer::Layer as _;
    use tower_service::Service;

    use super::{
        Duration, HTTPD, KdcProtocol, KdcTransport, MIT_KDC, NegotiateClient, Tokio, config,
        runtime,
    };
    use crate::harness;

    /// A service that names how the request was authenticated.
    #[derive(Clone)]
    struct Echo;

    impl Service<Request<Vec<u8>>> for Echo {
        type Response = Response<Vec<u8>>;
        type Error = Infallible;
        type Future = Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: Request<Vec<u8>>) -> Self::Future {
            let who = req.extensions().get::<SessionIdentity>().map_or_else(
                || {
                    req.extensions()
                        .get::<AcceptedContext>()
                        .map_or_else(String::new, |accepted| {
                            format!("negotiate:{}", accepted.ap_req().client().name())
                        })
                },
                |session| format!("session:{}", session.principal().name()),
            );
            ready(Ok(Response::new(who.into_bytes())))
        }
    }

    /// Call `service` once; the service answers without waiting.
    fn answer<S>(
        service: &mut S,
        request: Request<Vec<u8>>,
    ) -> Result<Response<Vec<u8>>, Box<dyn Error>>
    where
        S: Service<Request<Vec<u8>>, Response = Response<Vec<u8>>>,
    {
        let mut context = Context::from_waker(Waker::noop());
        let mut future = pin!(service.call(request));
        match future.as_mut().poll(&mut context) {
            Poll::Ready(Ok(response)) => Ok(response),
            Poll::Ready(Err(_failed)) => Err("the service failed".into()),
            Poll::Pending => Err("the service did not answer at once".into()),
        }
    }

    /// A request with one header.
    fn with(name: http_types::HeaderName, value: &str) -> Result<Request<Vec<u8>>, Box<dyn Error>> {
        let mut request = Request::new(Vec::new());
        drop(
            request
                .headers_mut()
                .insert(name, HeaderValue::from_str(value)?),
        );
        Ok(request)
    }

    /// A ticket the MIT KDC issued for `HTTP/httpd.test.rskrb5` is accepted by a
    /// Rust acceptor that holds Apache's keytab; the `Set-Cookie` of that
    /// exchange then authenticates the next request alone, and a tampered
    /// cookie falls back to the Negotiate challenge.
    #[test]
    fn a_rust_acceptor_continues_the_kdc_ticket_through_a_session() -> Result<(), Box<dyn Error>> {
        if !harness::require(
            "a_rust_acceptor_continues_the_kdc_ticket_through_a_session",
            &[MIT_KDC, HTTPD],
        )? {
            return Ok(());
        }
        runtime()?.block_on(async {
            let realm = harness::var("INTEROP_MIT_REALM")?;
            let host = harness::var("INTEROP_HTTPD_HOST")?;
            let mut negotiate = NegotiateClient::from_tokio_client(
                Tokio::with_password(
                    config(&realm)?,
                    KdcProtocol::Auto,
                    Principal::user(realm.clone(), harness::var("INTEROP_MIT_USER")?),
                    harness::var("INTEROP_MIT_USER_PASSWORD")?.into_bytes(),
                )
                .with_transport(KdcTransport::new().with_timeout(Duration::from_secs(10))),
            );
            let header = negotiate
                .authorization_header(Principal::new(realm, 2, ["HTTP", host.as_str()]))
                .await?;
            let manager = Arc::new(SessionManager::new(TransferKey::generate()?));
            let mut service =
                NegotiateLayer::from_keytab_name(harness::var("INTEROP_HTTPD_KEYTAB")?)?
                    .with_session_manager(Arc::clone(&manager))
                    .layer(Echo);

            let first = answer(&mut service, with(AUTHORIZATION, &header)?)?;
            assert_eq!(first.status(), StatusCode::OK);
            assert_eq!(first.body().as_slice(), b"negotiate:testuser1");
            let set_cookie = first
                .headers()
                .get(SET_COOKIE)
                .ok_or("no session cookie")?
                .to_str()?;
            let cookie = set_cookie
                .split(';')
                .next()
                .ok_or("a name=value pair")?
                .to_owned();

            let resumed = answer(&mut service, with(COOKIE, &cookie)?)?;
            assert_eq!(resumed.status(), StatusCode::OK);
            assert_eq!(resumed.body().as_slice(), b"session:testuser1");

            let tampered = answer(&mut service, with(COOKIE, &format!("{cookie}x"))?)?;
            assert_eq!(tampered.status(), StatusCode::UNAUTHORIZED);
            Ok::<_, Box<dyn Error>>(())
        })
    }
}

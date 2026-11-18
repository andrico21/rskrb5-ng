//! HTTP Negotiate of the crate's `NegotiateClient` against Apache httpd with
//! `mod_auth_gssapi` (fixture `httpd`, service `HTTP/httpd.test.rskrb5`).

use core::{error::Error, fmt::Write as _, str};
use std::io;

use http_types::{Request, Response, StatusCode, header::WWW_AUTHENTICATE};
use rskrb5_ng::{
    NegotiateClient,
    client::{Tokio, principal::Principal, transport::KdcProtocol},
    config::Config,
    http::{self as negotiate_http, ClientNegotiateResponse},
    spnego::{self, Token, oid::ObjectIdentifier},
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpStream,
};

use super::{MIT_KDC, runtime, test_user, transport};
use crate::harness::{self, Fixture, assert_negotiated_mechanism};

/// The Apache fixture, reached on `INTEROP_HTTPD`.
const HTTPD: Fixture = Fixture::new("httpd", "INTEROP_HTTPD");

/// Largest response the scenario reads from the fixture.
const RESPONSE_LIMIT: u64 = 64 * 1024;

/// Sends `request` to the fixture over HTTP/1.0 (one response, no chunked
/// body, the server closes the connection) and parses the response.
async fn send(endpoint: String, request: Request<()>) -> io::Result<Response<Vec<u8>>> {
    let mut head = format!("GET {} HTTP/1.0\r\n", request.uri());
    for (name, value) in request.headers() {
        let text = value.to_str().map_err(io::Error::other)?;
        write!(head, "{name}: {text}\r\n").map_err(io::Error::other)?;
    }
    head.push_str("\r\n");
    let mut stream = TcpStream::connect(endpoint).await?;
    stream.write_all(head.as_bytes()).await?;
    let mut raw = Vec::new();
    let _length = stream.take(RESPONSE_LIMIT).read_to_end(&mut raw).await?;
    parse_response(&raw)
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
    let body = rest.get(4..).ok_or_else(|| invalid("response body out of range"))?;
    let text = str::from_utf8(head).map_err(io::Error::other)?;
    let mut lines = text.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split(' ').nth(1))
        .ok_or_else(|| invalid("response has no status line"))?;
    let mut response =
        Response::builder().status(StatusCode::from_bytes(status.as_bytes()).map_err(io::Error::other)?);
    for line in lines {
        let (name, value) = line.split_once(':').ok_or_else(|| invalid("malformed header"))?;
        response = response.header(name.trim(), value.trim());
    }
    response.body(body.to_vec()).map_err(io::Error::other)
}

/// A GET of the protected URL, addressed to the fixture's virtual host.
fn get(host: &str) -> Request<()> {
    Request::get("/whoami/")
        .header("Host", host)
        .body(())
        .unwrap_or_default()
}

/// Without credentials Apache answers 401 with a bare Negotiate challenge;
/// the `NegotiateClient` retry with a krb5 SPNEGO token (mutual
/// authentication required) gets 200, its AP-REP verifies, the server's
/// SPNEGO reply selects the krb5 mechanism, and the page names the test user
/// and the `Negotiate/krb5` mechanism `mod_auth_gssapi` accepted.
#[test]
fn negotiate_client_authenticates_to_apache_mod_auth_gssapi() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "negotiate_client_authenticates_to_apache_mod_auth_gssapi",
        &[MIT_KDC, HTTPD],
    )? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let (user, password) = test_user()?;
        let realm = user.realm.clone();
        let endpoint = harness::var("INTEROP_HTTPD")?;
        let host = harness::var("INTEROP_HTTPD_HOST")?;
        let config = Config::parse(&format!(
            "[libdefaults]\n default_realm = {realm}\n dns_lookup_kdc = false\n\
             [realms]\n {realm} = {{\n  kdc = {}\n }}\n",
            harness::var("INTEROP_MIT_KDC")?,
        ))?;

        let anonymous = send(endpoint.clone(), get(&host)).await?;
        assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            negotiate_http::www_authenticate_negotiate_header(&anonymous)?,
            "Negotiate",
            "an anonymous request gets a bare Negotiate challenge"
        );

        let service = Principal::new(
            realm.clone(),
            2,
            harness::var("INTEROP_HTTPD_SERVICE")?.split('/'),
        );
        let mut client = NegotiateClient::from_tokio_client(
            Tokio::with_password(config, KdcProtocol::Auto, user.clone(), password)
                .with_transport(transport()),
        );
        let options = spnego::InitiatorContextOptions::new()
            .with_context_flags([spnego::CONTEXT_FLAG_MUTUAL]);
        let authenticated = negotiate_http::send_with_negotiate_options(
            &mut client,
            service,
            options,
            || get(&host),
            |request| send(endpoint.clone(), request),
        )
        .await
        .map_err(|error| format!("Negotiate with Apache failed: {error}"))?;

        let response = authenticated.response();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            matches!(
                authenticated.negotiation(),
                Some(ClientNegotiateResponse::Accepted { ap_rep: Some(_) })
            ),
            "Apache proved its identity with a verified AP-REP: {:?}",
            authenticated.negotiation()
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

        let body = String::from_utf8(response.body().clone())?;
        let expected = format!("principal={}@{realm}", user.components.join("/"));
        assert!(
            body.lines().any(|line| line == expected),
            "the page names the authenticated user ({expected}): {body}"
        );
        assert!(
            body.lines().any(|line| line == "mechanism=Negotiate/krb5"),
            "mod_auth_gssapi accepted the krb5 mechanism through Negotiate: {body}"
        );
        Ok::<_, Box<dyn Error>>(())
    })
}

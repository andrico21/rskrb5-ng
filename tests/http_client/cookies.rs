//! The cookie jar inside the client (the `http-client` leaf): what a client
//! sends back to the origin that set a cookie, and to nobody else.
#![cfg(feature = "http-client")]

use alloc::sync::Arc;

use http_types::{
    HeaderValue, Request, Response, StatusCode,
    header::{COOKIE, SET_COOKIE},
};
use pretty_assertions::assert_eq;
use rskrb5_ng::http::{
    agent::{NegotiateHttpClient, RedirectPolicy},
    cookies::CookieStore,
};
use tokio::runtime::Builder;

use super::{
    context::{Context as _, TestError},
    support::{Kerberos, Network, REALM, negotiate_client, redirect, status},
};

/// A `200` response that sets the cookie `set_cookie`.
fn ok_setting(set_cookie: &'static str) -> Response<Vec<u8>> {
    let mut response = Response::new(b"ok".to_vec());
    drop(
        response
            .headers_mut()
            .insert(SET_COOKIE, HeaderValue::from_static(set_cookie)),
    );
    response
}

/// A client for `network` with a jar.
fn client(network: &Network, hosts: &[&str]) -> Result<NegotiateHttpClient<Network>, TestError> {
    Ok(
        NegotiateHttpClient::new(negotiate_client(hosts)?, network.clone())
            .with_service_realm(REALM)
            .with_cookie_jar(CookieStore::new()),
    )
}

/// Run `future` on a current-thread runtime.
fn run<F>(future: F) -> Result<F::Output, TestError>
where
    F: Future,
{
    Ok(Builder::new_current_thread()
        .enable_all()
        .build()
        .context("runtime")?
        .block_on(future))
}

/// A cookie set by the authenticated response comes back on the next request
/// to the same origin, merged with the caller's own `Cookie` header.
#[test]
fn a_cookie_comes_back_to_the_origin_that_set_it() -> Result<(), TestError> {
    let server = Arc::new(Kerberos::new(&["a.example.com"]));
    let network = Network::new().serve("https://a.example.com/", move |request| {
        server.respond(request, &|_| {
            ok_setting("sid=s3cret; Path=/; Secure; HttpOnly")
        })
    })?;
    let mut client = client(&network, &["a.example.com"])?;
    drop(run(async {
        client.get("https://a.example.com/one").await
    })??);
    let mut second = Request::new(Vec::new());
    *second.uri_mut() = "https://a.example.com/two".parse()?;
    drop(
        second
            .headers_mut()
            .insert(COOKIE, HeaderValue::from_static("caller=1")),
    );
    drop(run(async { client.send(second).await })??);
    let seen = network.seen_by("https://a.example.com/")?;
    let last = seen.last().context("last request")?;
    assert_eq!(
        last.headers
            .get(COOKIE)
            .and_then(|value| value.to_str().ok()),
        Some("caller=1; sid=s3cret")
    );
    let first = seen.first().context("first request")?;
    assert!(
        !first.headers.contains_key(COOKIE),
        "nothing was set before the first response"
    );
    Ok(())
}

/// A cookie of one origin is not sent to another origin a redirect leads to,
/// and the other origin's cookie stays with it.
#[test]
fn a_redirect_to_another_origin_leaves_the_cookies_behind() -> Result<(), TestError> {
    let server = Arc::new(Kerberos::new(&["a.example.com"]));
    let network = Network::new()
        .serve("https://a.example.com/", move |request| {
            server.respond(request, &|inner| {
                if inner.uri().path() == "/jump" {
                    redirect(StatusCode::FOUND, "https://b.example.com/landing")
                        .unwrap_or_else(|_refused| status(StatusCode::BAD_GATEWAY))
                } else {
                    ok_setting("sid=for-a; Path=/")
                }
            })
        })?
        .serve("https://b.example.com/", |_request| {
            ok_setting("other=for-b; Path=/")
        })?;
    let mut client = client(&network, &["a.example.com"])?
        .with_redirect_policy(RedirectPolicy::AnyOrigin { max: 3 });
    drop(run(async {
        client.get("https://a.example.com/set").await
    })??);
    drop(run(async {
        client.get("https://a.example.com/jump").await
    })??);
    let at_b = network.seen_by("https://b.example.com/")?;
    assert!(
        !at_b
            .first()
            .context("request at B")?
            .headers
            .contains_key(COOKIE),
        "the cookie of A was sent to B"
    );
    drop(run(async {
        client.get("https://b.example.com/again").await
    })??);
    let later = network.seen_by("https://b.example.com/")?;
    assert_eq!(
        later
            .last()
            .context("second request at B")?
            .headers
            .get(COOKIE)
            .and_then(|value| value.to_str().ok()),
        Some("other=for-b")
    );
    Ok(())
}

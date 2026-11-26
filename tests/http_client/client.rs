//! Negotiate rounds, redirects, mutual authentication and limits of the client.

use alloc::sync::Arc;
use std::sync::{Mutex, PoisonError};

use http_types::{
    HeaderValue, Method, Request, Response, StatusCode,
    header::{AUTHORIZATION, COOKIE, WWW_AUTHENTICATE},
};
use pretty_assertions::assert_eq;
use rskrb5_ng::{
    error::HttpClient as ClientError,
    http::{
        ClientNegotiateResponse,
        agent::{NegotiateHttpClient, RedirectPolicy},
        challenge_response,
    },
    spnego::{CONTEXT_FLAG_CONF, CONTEXT_FLAG_INTEG, CONTEXT_FLAG_MUTUAL, InitiatorContextOptions},
};

use super::{
    context::{Context as _, TestError},
    support::{Kerberos, Network, REALM, Seen, negotiate_client, redirect, run, status},
};

/// The host of the origin the caller asks for.
const HOST_A: &str = "a.example.com";
/// The host of another origin.
const HOST_B: &str = "b.example.com";

/// A `200` response with `body`.
fn ok(body: &[u8]) -> Response<Vec<u8>> {
    Response::new(body.to_vec())
}

/// Initiator options that ask for mutual authentication.
fn mutual() -> InitiatorContextOptions {
    InitiatorContextOptions::new().with_context_flags(vec![
        CONTEXT_FLAG_INTEG,
        CONTEXT_FLAG_CONF,
        CONTEXT_FLAG_MUTUAL,
    ])
}

/// A client for `network` holding tickets for `hosts`.
fn client(network: &Network, hosts: &[&str]) -> Result<NegotiateHttpClient<Network>, TestError> {
    Ok(
        NegotiateHttpClient::new(negotiate_client(hosts)?, network.clone())
            .with_service_realm(REALM),
    )
}

/// A Kerberos origin for `host` answering `body`.
fn kerberos_origin(
    network: Network,
    host: &str,
    body: &'static [u8],
) -> Result<Network, TestError> {
    let server = Arc::new(Kerberos::new(&[host]));
    network.serve(&format!("https://{host}/"), move |request| {
        server.respond(request, &|_| ok(body))
    })
}

/// A `get` is answered with a token after the `401` challenge, and the AP-REP of
/// the final response proves the server.
#[test]
fn get_negotiates_after_the_challenge_and_proves_the_server() -> Result<(), TestError> {
    let network = kerberos_origin(Network::new(), HOST_A, b"hello")?;
    let mut client = client(&network, &[HOST_A])?.with_options(mutual());
    let result = run(async { client.get("https://a.example.com/page").await })??;
    assert_eq!(result.response().status(), StatusCode::OK);
    assert_eq!(result.response().body().as_slice(), b"hello");
    assert!(matches!(
        result.negotiation(),
        Some(ClientNegotiateResponse::Accepted { ap_rep: Some(_) })
    ));
    let seen = network.seen_by("https://a.example.com/")?;
    assert_eq!(seen.len(), 2);
    assert!(seen.first().context("first")?.authorization().is_none());
    assert!(
        seen.get(1)
            .context("second")?
            .authorization()
            .is_some_and(|token| token.starts_with("Negotiate "))
    );
    Ok(())
}

/// A `post` body is sent again, unchanged, with the token.
#[test]
fn post_replays_its_body_on_the_authenticated_retry() -> Result<(), TestError> {
    let network = kerberos_origin(Network::new(), HOST_A, b"stored")?;
    let mut client = client(&network, &[HOST_A])?;
    let result = run(async {
        client
            .post(
                "https://a.example.com/form",
                "text/plain",
                b"payload".to_vec(),
            )
            .await
    })??;
    assert_eq!(result.response().status(), StatusCode::OK);
    let seen = network.seen_by("https://a.example.com/")?;
    assert_eq!(seen.len(), 2);
    for request in &seen {
        assert_eq!(request.method, Method::POST);
        assert_eq!(request.body.as_slice(), b"payload");
    }
    Ok(())
}

/// A same-origin redirect is followed with a fresh token, and the AP-REP of the
/// final response proves the server again.
#[test]
fn same_origin_redirects_carry_a_fresh_token_per_hop() -> Result<(), TestError> {
    let server = Arc::new(Kerberos::new(&[HOST_A]));
    let network = Network::new().serve("https://a.example.com/", move |request| {
        server.respond(request, &|inner| {
            if inner.uri().path() == "/start" {
                redirect(StatusCode::FOUND, "/final")
                    .unwrap_or_else(|_refused| status(StatusCode::BAD_GATEWAY))
            } else {
                ok(b"landed")
            }
        })
    })?;
    let mut client = client(&network, &[HOST_A])?.with_options(mutual());
    let result = run(async { client.get("https://a.example.com/start").await })??;
    assert_eq!(result.response().body().as_slice(), b"landed");
    assert_eq!(result.redirects(), 1);
    assert_eq!(result.uri().path(), "/final");
    let seen = network.seen_by("https://a.example.com/")?;
    assert_eq!(seen.last().context("last request")?.target, "/final");
    let tokens: Vec<_> = seen.iter().filter_map(Seen::authorization).collect();
    assert_eq!(
        tokens.len(),
        2,
        "the first hop and the redirect target each carry a token"
    );
    assert_ne!(tokens.first(), tokens.get(1), "a token is never reused");
    Ok(())
}

/// A redirect to another origin is returned, not followed, under the default
/// policy: the other origin is never contacted.
#[test]
fn the_default_policy_does_not_follow_a_cross_origin_redirect() -> Result<(), TestError> {
    let server = Arc::new(Kerberos::new(&[HOST_A]));
    let network = Network::new()
        .serve("https://a.example.com/", move |request| {
            server.respond(request, &|_| {
                redirect(StatusCode::FOUND, "https://b.example.com/landing")
                    .unwrap_or_else(|_refused| status(StatusCode::BAD_GATEWAY))
            })
        })?
        .serve("https://b.example.com/", |_request| {
            ok(b"must not be asked")
        })?;
    let mut client = client(&network, &[HOST_A])?;
    let result = run(async { client.get("https://a.example.com/start").await })??;
    assert_eq!(result.response().status(), StatusCode::FOUND);
    assert_eq!(result.redirects(), 0);
    assert!(
        network.seen_by("https://b.example.com/")?.is_empty(),
        "the other origin was contacted"
    );
    Ok(())
}

/// The QA failure scenario: a followed redirect to another origin carries no
/// Authorization header, no caller cookie and no Negotiate round.
#[test]
fn a_redirect_to_another_origin_drops_the_authorization_header() -> Result<(), TestError> {
    let server = Arc::new(Kerberos::new(&[HOST_A]));
    let network = Network::new()
        .serve("https://a.example.com/", move |request| {
            server.respond(request, &|_| {
                redirect(StatusCode::FOUND, "https://b.example.com/landing")
                    .unwrap_or_else(|_refused| status(StatusCode::BAD_GATEWAY))
            })
        })?
        .serve("https://b.example.com/", |_request| challenge_response())?;
    let mut client = client(&network, &[HOST_A, HOST_B])?
        .with_redirect_policy(RedirectPolicy::AnyOrigin { max: 3 });
    let mut request = Request::new(Vec::new());
    *request.uri_mut() = "https://a.example.com/start".parse()?;
    drop(
        request
            .headers_mut()
            .insert(COOKIE, HeaderValue::from_static("caller=secret")),
    );
    let result = run(async { client.send(request).await })??;
    assert_eq!(result.response().status(), StatusCode::UNAUTHORIZED);
    assert_eq!(result.redirects(), 1);
    let at_a = network.seen_by("https://a.example.com/")?;
    assert!(
        at_a.get(1)
            .context("second request at A")?
            .authorization()
            .is_some(),
        "the home origin was negotiated with"
    );
    let at_b = network.seen_by("https://b.example.com/")?;
    assert_eq!(at_b.len(), 1, "no Negotiate round at the other origin");
    let first = at_b.first().context("request at B")?;
    assert!(!first.headers.contains_key(AUTHORIZATION));
    assert!(!first.headers.contains_key(COOKIE));
    Ok(())
}

/// A caller's Negotiate header is stale after one use: a redirect drops it
/// even on the same origin.
#[test]
fn a_redirect_strips_a_stale_negotiate_token() -> Result<(), TestError> {
    let network = Network::new().serve("https://a.example.com/", |request| {
        if request.uri().path() == "/start" {
            redirect(StatusCode::FOUND, "/next")
                .unwrap_or_else(|_refused| status(StatusCode::BAD_GATEWAY))
        } else {
            ok(b"done")
        }
    })?;
    let mut client = client(&network, &[HOST_A])?;
    let mut request = Request::new(Vec::new());
    *request.uri_mut() = "https://a.example.com/start".parse()?;
    drop(request.headers_mut().insert(
        AUTHORIZATION,
        HeaderValue::from_static("Negotiate c3RhbGU="),
    ));
    let result = run(async { client.send(request).await })??;
    assert_eq!(result.response().body().as_slice(), b"done");
    let seen = network.seen_by("https://a.example.com/")?;
    assert!(seen.first().context("first")?.authorization().is_some());
    assert!(seen.get(1).context("second")?.authorization().is_none());
    Ok(())
}

/// An `https` to `http` redirect is refused under every following policy.
#[test]
fn a_downgrade_redirect_is_refused() -> Result<(), TestError> {
    for policy in [
        RedirectPolicy::SameOrigin { max: 3 },
        RedirectPolicy::AnyOrigin { max: 3 },
    ] {
        let network = Network::new()
            .serve("https://a.example.com/", |_request| {
                redirect(StatusCode::FOUND, "http://a.example.com/plain")
                    .unwrap_or_else(|_refused| status(StatusCode::BAD_GATEWAY))
            })?
            .serve("http://a.example.com/", |_request| ok(b"cleartext"))?;
        let mut client = client(&network, &[HOST_A])?.with_redirect_policy(policy);
        let refused = run(async { client.get("https://a.example.com/").await })?;
        assert!(
            matches!(refused, Err(ClientError::RedirectDowngrade)),
            "{policy:?}: {refused:?}"
        );
        assert!(
            network.seen_by("http://a.example.com/")?.is_empty(),
            "the cleartext origin was contacted"
        );
    }
    Ok(())
}

/// The redirect count is bounded, and `Never` returns the redirect.
#[test]
fn redirects_are_bounded() -> Result<(), TestError> {
    let network = Network::new().serve("https://a.example.com/", |_request| {
        redirect(StatusCode::TEMPORARY_REDIRECT, "/again")
            .unwrap_or_else(|_refused| status(StatusCode::BAD_GATEWAY))
    })?;
    let mut limited =
        client(&network, &[HOST_A])?.with_redirect_policy(RedirectPolicy::SameOrigin { max: 2 });
    let refused = run(async { limited.get("https://a.example.com/").await })?;
    assert!(
        matches!(refused, Err(ClientError::TooManyRedirects { limit: 2 })),
        "{refused:?}"
    );
    assert_eq!(network.seen_by("https://a.example.com/")?.len(), 3);
    let mut never = client(&network, &[HOST_A])?.with_redirect_policy(RedirectPolicy::Never);
    let result = run(async { never.get("https://a.example.com/").await })??;
    assert_eq!(result.response().status(), StatusCode::TEMPORARY_REDIRECT);
    Ok(())
}

/// A `303` turns a `POST` into a body-less `GET`; a `307` keeps method and body.
#[test]
fn redirect_statuses_decide_method_and_body() -> Result<(), TestError> {
    for (code, method, body) in [
        (StatusCode::SEE_OTHER, Method::GET, &b""[..]),
        (StatusCode::TEMPORARY_REDIRECT, Method::POST, &b"data"[..]),
    ] {
        let network = Network::new().serve("https://a.example.com/", move |request| {
            if request.uri().path() == "/submit" {
                redirect(code, "/result").unwrap_or_else(|_refused| status(StatusCode::BAD_GATEWAY))
            } else {
                ok(b"ok")
            }
        })?;
        let mut client = client(&network, &[HOST_A])?;
        drop(run(async {
            client
                .post(
                    "https://a.example.com/submit",
                    "text/plain",
                    b"data".to_vec(),
                )
                .await
        })??);
        let seen = network.seen_by("https://a.example.com/")?;
        let last = seen.last().context("last request")?;
        assert_eq!(
            (&last.method, last.body.as_slice()),
            (&method, body),
            "{code}"
        );
    }
    Ok(())
}

/// A server that keeps challenging is answered at most `max_challenges` times.
#[test]
fn the_challenge_rounds_are_bounded() -> Result<(), TestError> {
    let network =
        Network::new().serve("https://a.example.com/", |_request| challenge_response())?;
    let mut client = client(&network, &[HOST_A])?.with_max_challenges(2);
    let refused = run(async { client.get("https://a.example.com/").await })?;
    assert!(
        matches!(refused, Err(ClientError::ChallengeLimit { limit: 2 })),
        "{refused:?}"
    );
    assert_eq!(network.seen_by("https://a.example.com/")?.len(), 3);
    Ok(())
}

/// A `WWW-Authenticate` header past the byte limit is refused before a token is built.
#[test]
fn an_oversized_challenge_is_refused() -> Result<(), TestError> {
    let network = Network::new().serve("https://a.example.com/", |_request| {
        let mut response = challenge_response();
        let long = format!("Negotiate, Basic realm=\"{}\"", "x".repeat(300));
        if let Ok(value) = HeaderValue::from_str(&long) {
            let _added = response.headers_mut().append(WWW_AUTHENTICATE, value);
        }
        response
    })?;
    let mut client = client(&network, &[HOST_A])?.with_max_challenge_bytes(200);
    let refused = run(async { client.get("https://a.example.com/").await })?;
    assert!(
        matches!(
            refused,
            Err(ClientError::ChallengeTooLarge {
                limit: 200,
                actual: _
            })
        ),
        "{refused:?}"
    );
    assert_eq!(network.seen_by("https://a.example.com/")?.len(), 1);
    Ok(())
}

/// A request body past the replay limit is refused before anything is sent.
#[test]
fn an_oversized_body_is_refused() -> Result<(), TestError> {
    let network = kerberos_origin(Network::new(), HOST_A, b"x")?;
    let mut client = client(&network, &[HOST_A])?.with_max_body_bytes(4);
    let refused = run(async {
        client
            .post("https://a.example.com/", "text/plain", b"too long".to_vec())
            .await
    })?;
    assert!(
        matches!(
            refused,
            Err(ClientError::BodyTooLarge {
                limit: 4,
                actual: 8
            })
        ),
        "{refused:?}"
    );
    assert!(
        network.seen_by("https://a.example.com/")?.is_empty(),
        "something was sent"
    );
    Ok(())
}

/// A request URI with user information, or a relative one, is refused.
#[test]
fn request_uris_must_be_plain_absolute_http_uris() -> Result<(), TestError> {
    let network = Network::new();
    let mut client = client(&network, &[HOST_A])?;
    for uri in [
        "https://user:pass@a.example.com/",
        "/relative",
        "ftp://a.example.com/",
    ] {
        let refused = run(async { client.get(uri).await })?;
        assert!(
            matches!(refused, Err(ClientError::InvalidUri { reason: _ })),
            "{uri}: {refused:?}"
        );
    }
    Ok(())
}

/// Mutual authentication that is requested and not proven fails closed: a `200`
/// without an AP-REP, a first response without a challenge, and a response that
/// proves nothing about the server's identity.
#[test]
fn unproven_mutual_authentication_fails_closed() -> Result<(), TestError> {
    // The server accepts any token and answers without an AP-REP.
    let silent = Network::new().serve("https://a.example.com/", |request| {
        if request.headers().contains_key(AUTHORIZATION) {
            ok(b"unproven")
        } else {
            challenge_response()
        }
    })?;
    let mut client_one = client(&silent, &[HOST_A])?.with_options(mutual());
    let refused = run(async { client_one.get("https://a.example.com/").await })?;
    let Err(ClientError::MutualAuthenticationNotProven {
        negotiation,
        response,
    }) = refused
    else {
        return Err("a response without an AP-REP must not be accepted".into());
    };
    assert!(matches!(
        negotiation,
        Some(ClientNegotiateResponse::NoAuthenticateHeader)
    ));
    assert_eq!(response.body().as_slice(), b"unproven");

    // The server never challenges: nothing was authenticated at all.
    let open = Network::new().serve("https://a.example.com/", |_request| ok(b"open"))?;
    let mut client_two = client(&open, &[HOST_A])?.with_options(mutual());
    let unchallenged = run(async { client_two.get("https://a.example.com/").await })?;
    assert!(
        matches!(
            unchallenged,
            Err(ClientError::MutualAuthenticationNotProven {
                negotiation: None,
                response: _
            })
        ),
        "{unchallenged:?}"
    );

    // Without a mutual request the same answers are results.
    let mut relaxed = client(&silent, &[HOST_A])?;
    let result = run(async { relaxed.get("https://a.example.com/").await })??;
    assert_eq!(result.response().body().as_slice(), b"unproven");
    Ok(())
}

/// An AP-REP from a server that does not hold the service key does not prove it.
#[test]
fn an_ap_rep_of_another_server_does_not_prove_the_service() -> Result<(), TestError> {
    // Both servers accept the ticket; the "forger" answers with the AP-REP of a
    // different request (replayed from an earlier exchange).
    let real = Arc::new(Kerberos::new(&[HOST_A]));
    let stolen: Arc<Mutex<Option<HeaderValue>>> = Arc::new(Mutex::new(None));
    let record = Arc::clone(&stolen);
    let honest = Network::new().serve("https://a.example.com/", move |request| {
        let response = real.respond(request, &|_| ok(b"honest"));
        if let Some(value) = response.headers().get(WWW_AUTHENTICATE) {
            *record.lock().unwrap_or_else(PoisonError::into_inner) = Some(value.clone());
        }
        response
    })?;
    let mut first = client(&honest, &[HOST_A])?.with_options(mutual());
    drop(run(async { first.get("https://a.example.com/").await })??);
    let replayed = stolen
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
        .context("the honest server sent an AP-REP")?;
    let forger = Network::new().serve("https://a.example.com/", move |request| {
        if request.headers().contains_key(AUTHORIZATION) {
            let mut response = ok(b"forged");
            drop(
                response
                    .headers_mut()
                    .insert(WWW_AUTHENTICATE, replayed.clone()),
            );
            response
        } else {
            challenge_response()
        }
    })?;
    let mut second = client(&forger, &[HOST_A])?.with_options(mutual());
    let refused = run(async { second.get("https://a.example.com/").await })?;
    let Err(ClientError::MutualAuthenticationNotProven {
        negotiation,
        response: _,
    }) = refused
    else {
        return Err("a replayed AP-REP must not prove the server".into());
    };
    assert!(
        matches!(
            negotiation,
            Some(
                ClientNegotiateResponse::InvalidToken { message: _ }
                    | ClientNegotiateResponse::Rejected
            )
        ),
        "{negotiation:?}"
    );
    Ok(())
}

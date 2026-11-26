//! The HTTP session manager: sealed session cookies, expiry, rotation,
//! revocation, principal binding and the continuation of a Negotiate exchange.

use alloc::sync::Arc;
use core::{
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use std::time::{SystemTime, UNIX_EPOCH};

use http_types::{HeaderValue, Request, header::COOKIE};
use pretty_assertions::assert_eq;
use rskrb5_ng::{
    error::HttpSession as SessionError,
    gss::TransferKey,
    http::sessions::{SessionIdentity, SessionManager},
    service::Principal,
    trace::{Guard, Options, capture::Memory},
};

use super::context::{Context as _, TestError};

/// The start of the test clock, in seconds since the epoch.
const START: u64 = 1_800_000_000;

/// A manager with a test clock the caller can advance.
fn manager() -> (SessionManager, Arc<AtomicU64>) {
    let seconds = Arc::new(AtomicU64::new(START));
    let clock = Arc::clone(&seconds);
    let manager = SessionManager::new(TransferKey::new([7; 32])).with_clock(move || {
        UNIX_EPOCH
            .checked_add(Duration::from_secs(clock.load(Ordering::SeqCst)))
            .unwrap_or(UNIX_EPOCH)
    });
    (manager, seconds)
}

/// The cookie value of a `Set-Cookie` header.
fn value_of(set_cookie: &HeaderValue) -> Result<String, TestError> {
    let text = set_cookie.to_str().context("Set-Cookie is visible ASCII")?;
    let pair = text.split(';').next().context("a name=value pair")?;
    Ok(pair
        .split_once('=')
        .context("a name and a value")?
        .1
        .to_owned())
}

/// The principal of every test session.
fn alice() -> Principal {
    named("EXAMPLE.COM", "alice")
}

/// A user principal.
fn named(realm: &str, name: &str) -> Principal {
    Principal::new(realm.to_owned(), 1, vec![name.to_owned()])
}

/// A session is issued with a hardened cookie, resumes to the same principal and
/// lifetime, and its `Set-Cookie` carries no readable principal.
#[test]
fn a_session_round_trips_through_its_cookie() -> Result<(), TestError> {
    let (manager, _clock) = manager();
    let (identity, set_cookie) = manager.issue(&alice())?;
    let text = set_cookie.to_str().context("visible ASCII")?;
    for attribute in [
        "rskrb5_session=",
        "HttpOnly",
        "Secure",
        "SameSite=Strict",
        "Path=/",
        "Max-Age=3600",
    ] {
        assert!(text.contains(attribute), "{attribute} missing from {text}");
    }
    assert!(
        !text.contains("alice"),
        "the cookie shows the principal: {text}"
    );
    assert!(set_cookie.is_sensitive());
    let resumed = manager.resume(&value_of(&set_cookie)?)?;
    assert_eq!(resumed, identity);
    assert_eq!(resumed.principal(), &alice());
    assert_eq!(resumed.generation(), 0);
    assert_eq!(
        resumed.expires_at(),
        UNIX_EPOCH + Duration::from_secs(START + 3600)
    );
    Ok(())
}

/// A session issued for one principal never authenticates another.
#[test]
fn a_session_is_bound_to_its_principal() -> Result<(), TestError> {
    let (manager, _clock) = manager();
    let (_identity, set_cookie) = manager.issue(&alice())?;
    let value = value_of(&set_cookie)?;
    let bob = named("EXAMPLE.COM", "bob");
    let refused = manager.resume_for(&value, &bob);
    assert!(
        matches!(refused, Err(SessionError::PrincipalMismatch)),
        "{refused:?}"
    );
    let other_realm = named("OTHER.COM", "alice");
    let elsewhere = manager.resume_for(&value, &other_realm);
    assert!(
        matches!(elsewhere, Err(SessionError::PrincipalMismatch)),
        "{elsewhere:?}"
    );
    assert_eq!(manager.resume_for(&value, &alice())?.principal(), &alice());
    Ok(())
}

/// A session ends at its expiry, to the second.
#[test]
fn an_expired_session_is_refused() -> Result<(), TestError> {
    let (manager, clock) = manager();
    let (_identity, set_cookie) = manager.issue(&alice())?;
    let value = value_of(&set_cookie)?;
    clock.store(START + 3599, Ordering::SeqCst);
    drop(manager.resume(&value)?);
    clock.store(START + 3600, Ordering::SeqCst);
    let refused = manager.resume(&value);
    assert!(matches!(refused, Err(SessionError::Expired)), "{refused:?}");
    Ok(())
}

/// A rotated session has a new generation and cookie; the old cookie is refused.
#[test]
fn a_rotated_session_refuses_its_old_cookie() -> Result<(), TestError> {
    let (manager, clock) = manager();
    let (identity, old) = manager.issue(&alice())?;
    clock.store(START + 60, Ordering::SeqCst);
    let (rotated, new) = manager.rotate(&identity)?;
    assert_eq!(rotated.generation(), 1);
    assert_eq!(rotated.principal(), &alice());
    assert_ne!(value_of(&old)?, value_of(&new)?);
    let refused = manager.resume(&value_of(&old)?);
    assert!(matches!(refused, Err(SessionError::Rotated)), "{refused:?}");
    assert_eq!(manager.resume(&value_of(&new)?)?, rotated);
    let again = manager.rotate(&identity);
    assert!(matches!(again, Err(SessionError::Rotated)), "{again:?}");
    Ok(())
}

/// A revoked session is refused whatever its cookie says; revoking twice is harmless.
#[test]
fn a_revoked_session_is_refused() -> Result<(), TestError> {
    let (manager, _clock) = manager();
    let (identity, set_cookie) = manager.issue(&alice())?;
    manager.revoke(&identity)?;
    manager.revoke(&identity)?;
    let refused = manager.resume(&value_of(&set_cookie)?);
    assert!(matches!(refused, Err(SessionError::Revoked)), "{refused:?}");
    let rotate = manager.rotate(&identity);
    assert!(matches!(rotate, Err(SessionError::Revoked)), "{rotate:?}");
    Ok(())
}

/// A cookie of another manager (another key) is refused, as is a cookie this
/// manager's registry never held.
#[test]
fn a_foreign_cookie_is_refused() -> Result<(), TestError> {
    let (first, _clock) = manager();
    let (second, _other) = manager();
    let (_identity, set_cookie) = first.issue(&alice())?;
    let value = value_of(&set_cookie)?;
    let sealed_elsewhere = SessionManager::new(TransferKey::new([9; 32]));
    let refused = sealed_elsewhere.resume(&value);
    assert!(
        matches!(refused, Err(SessionError::Unauthentic)),
        "{refused:?}"
    );
    let unknown = second.resume(&value);
    assert!(matches!(unknown, Err(SessionError::Revoked)), "{unknown:?}");
    Ok(())
}

/// A cookie changed in any one character, or cut at any length, is never a session.
#[test]
fn a_tampered_or_truncated_cookie_is_refused() -> Result<(), TestError> {
    let (manager, _clock) = manager();
    let (_identity, set_cookie) = manager.issue(&alice())?;
    let value = value_of(&set_cookie)?;
    for index in 0..value.len() {
        let mut bytes = value.clone().into_bytes();
        let byte = bytes.get_mut(index).context("index in range")?;
        *byte = if *byte == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(bytes).context("ASCII")?;
        assert!(
            manager.resume(&tampered).is_err(),
            "a change at {index} was accepted"
        );
    }
    for length in 0..value.len() {
        let cut = value.get(..length).context("prefix")?;
        assert!(
            manager.resume(cut).is_err(),
            "a prefix of {length} bytes was accepted"
        );
    }
    for garbage in ["", "!!!", "not base64 at all", "AAAA"] {
        let refused = manager.resume(garbage);
        assert!(
            matches!(
                refused,
                Err(SessionError::Malformed { reason: _ } | SessionError::Unauthentic)
            ),
            "{garbage:?}: {refused:?}"
        );
    }
    Ok(())
}

/// A value past the size limit is refused before it is decoded.
#[test]
fn an_oversized_cookie_is_refused() -> Result<(), TestError> {
    let (manager, _clock) = manager();
    let (_identity, set_cookie) = manager.issue(&alice())?;
    assert!(
        value_of(&set_cookie)?.len() < 4096,
        "a real session fits the limit"
    );
    let refused = manager.resume(&"A".repeat(10_000));
    assert!(
        matches!(
            refused,
            Err(SessionError::TooLarge {
                limit: 4096,
                actual: 10_000
            })
        ),
        "{refused:?}"
    );
    Ok(())
}

/// The registry holds a bounded number of sessions; an expired session makes room.
#[test]
fn the_session_count_is_bounded() -> Result<(), TestError> {
    let (unbounded, clock) = manager();
    let manager = unbounded
        .with_max_sessions(2)
        .with_lifetime(Duration::from_secs(100));
    drop(manager.issue(&alice())?);
    drop(manager.issue(&named("EXAMPLE.COM", "bob"))?);
    let full = manager.issue(&named("EXAMPLE.COM", "carol"));
    assert!(
        matches!(full, Err(SessionError::CapacityExceeded { limit: 2 })),
        "{full:?}"
    );
    clock.store(START + 100, Ordering::SeqCst);
    drop(manager.issue(&named("EXAMPLE.COM", "carol"))?);
    Ok(())
}

/// A principal that does not fit the format is refused, not truncated.
#[test]
fn an_oversized_principal_is_refused() -> Result<(), TestError> {
    let (manager, _clock) = manager();
    drop(manager.issue(&named("EXAMPLE.COM", &"x".repeat(255)))?);
    let long = named("EXAMPLE.COM", &"x".repeat(256));
    let refused = manager.issue(&long);
    assert!(
        matches!(
            refused,
            Err(SessionError::UnsupportedPrincipal { reason: _ })
        ),
        "{refused:?}"
    );
    let many = Principal::new("EXAMPLE.COM".to_owned(), 1, vec!["a".to_owned(); 20]);
    let crowded = manager.issue(&many);
    assert!(
        matches!(
            crowded,
            Err(SessionError::UnsupportedPrincipal { reason: _ })
        ),
        "{crowded:?}"
    );
    Ok(())
}

/// `attach` finds the session cookie among others, puts the identity in the
/// request's extensions, ignores a request without one and refuses a duplicate.
#[test]
fn attach_places_the_identity_in_the_request_extensions() -> Result<(), TestError> {
    let (manager, _clock) = manager();
    let (identity, set_cookie) = manager.issue(&alice())?;
    let value = value_of(&set_cookie)?;
    let mut request = Request::new(());
    drop(
        request.headers_mut().insert(
            COOKIE,
            HeaderValue::from_str(&format!("theme=dark; rskrb5_session={value}; lang=en"))
                .context("header")?,
        ),
    );
    assert_eq!(manager.attach(&mut request)?, Some(identity.clone()));
    assert_eq!(
        request.extensions().get::<SessionIdentity>(),
        Some(&identity)
    );

    let mut without = Request::new(());
    drop(without.headers_mut().insert(
        COOKIE,
        HeaderValue::from_static("theme=dark; other_session=1"),
    ));
    assert_eq!(manager.attach(&mut without)?, None);
    assert!(
        without.extensions().get::<SessionIdentity>().is_none(),
        "an identity appeared"
    );

    let mut twice = Request::new(());
    drop(
        twice.headers_mut().insert(
            COOKIE,
            HeaderValue::from_str(&format!("rskrb5_session={value}; rskrb5_session={value}"))
                .context("header")?,
        ),
    );
    let refused = manager.attach(&mut twice);
    assert!(
        matches!(refused, Err(SessionError::Malformed { reason: _ })),
        "{refused:?}"
    );

    let mut bad = Request::new(());
    drop(
        bad.headers_mut()
            .insert(COOKIE, HeaderValue::from_static("rskrb5_session=AAAA")),
    );
    assert!(
        manager.attach(&mut bad).is_err(),
        "a bad cookie was accepted"
    );
    assert!(
        bad.extensions().get::<SessionIdentity>().is_none(),
        "an identity appeared"
    );
    Ok(())
}

/// The cookie name is a token, and a named cookie is the one that is read and set.
#[test]
fn the_cookie_name_is_configurable_and_validated() -> Result<(), TestError> {
    for bad in ["", "a b", "a;b", "a=b", "\u{e9}"] {
        let refused = SessionManager::new(TransferKey::new([1; 32])).with_cookie_name(bad);
        assert!(
            matches!(refused, Err(SessionError::InvalidCookie { reason: _ })),
            "{bad:?}"
        );
    }
    let manager = SessionManager::new(TransferKey::new([1; 32]))
        .with_cookie_name("__Host-sid")?
        .with_secure(false);
    let (_identity, set_cookie) = manager.issue(&alice())?;
    let text = set_cookie.to_str().context("visible ASCII")?;
    assert!(text.starts_with("__Host-sid="), "{text}");
    assert!(!text.contains("Secure"), "{text}");
    let expired = manager.expire_cookie();
    let deleting = expired.to_str().context("visible ASCII")?;
    assert!(
        deleting.starts_with("__Host-sid=;") && deleting.contains("Max-Age=0"),
        "{deleting}"
    );
    Ok(())
}

/// A refused session reaches the application's logger as a static reason; the
/// cookie value and the principal never do, and `Debug` hides the key.
#[test]
fn refusals_are_traced_without_secrets() -> Result<(), TestError> {
    let sink = Memory::new();
    let guard = Guard::new(sink.clone(), Options::default().with_identities(true));
    let (plain, clock) = manager();
    let manager = plain.with_trace(guard);
    let (identity, set_cookie) = manager.issue(&alice())?;
    let value = value_of(&set_cookie)?;
    clock.store(START + 7200, Ordering::SeqCst);
    assert!(
        manager.resume(&value).is_err(),
        "an expired session resumed"
    );
    let lines = sink.lines();
    assert_eq!(lines.len(), 1, "{lines:?}");
    let line = lines.first().context("one line")?;
    assert!(line.contains("http session expired"), "{line}");
    assert!(!line.contains(&value) && !line.contains("alice"), "{line}");
    let shown = format!("{manager:?} {identity:?}");
    assert!(
        !shown.contains(&value) && !shown.contains("alice"),
        "{shown}"
    );
    Ok(())
}

/// Sessions issued by one manager are independent: revoking one leaves another.
#[test]
fn sessions_are_independent() -> Result<(), TestError> {
    let (manager, _clock) = manager();
    let (first, first_cookie) = manager.issue(&alice())?;
    let (_second, second_cookie) = manager.issue(&alice())?;
    manager.revoke(&first)?;
    assert!(
        manager.resume(&value_of(&first_cookie)?).is_err(),
        "the revoked session resumed"
    );
    assert_eq!(
        manager.resume(&value_of(&second_cookie)?)?.principal(),
        &alice()
    );
    let _now: SystemTime = first.issued_at();
    Ok(())
}

/// The registry is per manager: a manager created after a restart refuses the
/// cookies of its predecessor, even under the same sealing key (FU-HTC-P06).
#[test]
fn restarted_manager_rejects_previous_sessions() -> Result<(), TestError> {
    let (before, _before_clock) = manager();
    let (_session, cookie) = before.issue(&alice())?;
    drop(before);
    let (after, _after_clock) = manager();
    assert!(
        matches!(
            after.resume(&value_of(&cookie)?),
            Err(SessionError::Revoked)
        ),
        "a session of the previous manager resumed"
    );
    Ok(())
}

/// The continuation of a Negotiate exchange through the Tower service.
#[cfg(feature = "tower")]
mod continuation {
    use core::{
        convert::Infallible,
        future::{Future as _, Ready, ready},
        pin::pin,
        task::{Context, Poll, Waker},
    };

    use http_types::{
        Response, StatusCode,
        header::{AUTHORIZATION, SET_COOKIE, WWW_AUTHENTICATE},
    };
    use rskrb5_ng::{
        client::principal::Principal as ClientPrincipal, http::NegotiateLayer,
        spnego::AcceptedContext,
    };
    use tokio::runtime::Builder;
    use tower_layer::Layer as _;
    use tower_service::Service;

    use super::{
        Arc, AtomicU64, COOKIE, HeaderValue, Ordering, Request, START, SessionIdentity,
        SessionManager, TestError, manager, value_of,
    };
    use crate::tests::{
        context::Context as _,
        support::{REALM, keytab, negotiate_client},
    };

    /// The host the service answers for.
    const HOST: &str = "www.example.com";

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
    fn answer<S>(service: &mut S, request: Request<Vec<u8>>) -> Result<Response<Vec<u8>>, TestError>
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

    /// A request carrying `cookie`.
    fn with_cookie(cookie: &str) -> Result<Request<Vec<u8>>, TestError> {
        let mut request = Request::new(Vec::new());
        drop(request.headers_mut().insert(
            COOKIE,
            HeaderValue::from_str(&format!("rskrb5_session={cookie}")).context("cookie")?,
        ));
        Ok(request)
    }

    /// A Negotiate-authenticated request for `HOST`.
    fn negotiated() -> Result<Request<Vec<u8>>, TestError> {
        let mut client = negotiate_client(&[HOST])?;
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .context("runtime")?;
        let header = runtime
            .block_on(client.authorization_header(ClientPrincipal::new(REALM, 3, ["HTTP", HOST])))
            .context("a token")?;
        let mut request = Request::new(Vec::new());
        drop(request.headers_mut().insert(
            AUTHORIZATION,
            HeaderValue::from_str(&header).context("Authorization")?,
        ));
        Ok(request)
    }

    /// A Negotiate request gets a session cookie that alone then authenticates.
    ///
    /// It stops doing so when tampered with, expired or revoked, and a service
    /// without a manager never trusts it.
    #[test]
    fn a_session_continues_the_negotiate_exchange() -> Result<(), TestError> {
        let (sessions, clock): (SessionManager, Arc<AtomicU64>) = manager();
        let manager = Arc::new(sessions);
        let mut service = NegotiateLayer::from_keytab(keytab(&[HOST]))
            .with_session_manager(Arc::clone(&manager))
            .layer(Echo);

        let challenged = answer(&mut service, Request::new(Vec::new()))?;
        assert_eq!(challenged.status(), StatusCode::UNAUTHORIZED);
        assert!(
            !challenged.headers().contains_key(SET_COOKIE),
            "a challenge set a cookie"
        );

        let first = answer(&mut service, negotiated()?)?;
        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(first.body().as_slice(), b"negotiate:alice");
        assert!(
            first.headers().contains_key(WWW_AUTHENTICATE),
            "the AP-REP is still sent"
        );
        let cookie = value_of(first.headers().get(SET_COOKIE).context("a Set-Cookie")?)?;

        let resumed = answer(&mut service, with_cookie(&cookie)?)?;
        assert_eq!(resumed.status(), StatusCode::OK);
        assert_eq!(resumed.body().as_slice(), b"session:alice");
        assert!(
            !resumed.headers().contains_key(SET_COOKIE),
            "a resumed session set a cookie"
        );
        assert!(
            !resumed.headers().contains_key(WWW_AUTHENTICATE),
            "a resumed session sent an AP-REP"
        );

        let tampered = format!("{}x", cookie.get(1..).context("cookie")?);
        let refused = answer(&mut service, with_cookie(&tampered)?)?;
        assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
        assert!(refused.body().is_empty(), "a refusal has a body");

        let mut plain = NegotiateLayer::from_keytab(keytab(&[HOST])).layer(Echo);
        assert_eq!(
            answer(&mut plain, with_cookie(&cookie)?)?.status(),
            StatusCode::UNAUTHORIZED
        );

        let identity = manager.resume(&cookie)?;
        manager.revoke(&identity)?;
        assert_eq!(
            answer(&mut service, with_cookie(&cookie)?)?.status(),
            StatusCode::UNAUTHORIZED
        );

        let second = answer(&mut service, negotiated()?)?;
        let fresh = value_of(second.headers().get(SET_COOKIE).context("a Set-Cookie")?)?;
        clock.store(START + 7200, Ordering::SeqCst);
        assert_eq!(
            answer(&mut service, with_cookie(&fresh)?)?.status(),
            StatusCode::UNAUTHORIZED
        );
        Ok(())
    }
}

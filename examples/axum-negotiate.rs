//! Axum server on `127.0.0.1:3000` whose middleware validates
//! `Authorization: Negotiate` headers against the service keytab named by
//! `KRB5_KTNAME` (default `http.keytab`) and answers with the authenticated client principal.
extern crate alloc;

use alloc::sync::Arc;
use core::error::Error;
use std::{env, sync::Mutex};

use axum::{
    Router,
    body::Body,
    extract::{Extension, State},
    http::{HeaderValue, Request, StatusCode, header::WWW_AUTHENTICATE},
    middleware::{self, Next},
    response::Response,
    routing::get,
};
use rskrb5_ng::{
    error::{
        Http as HttpError, Keytab as KeytabError, Service as ServiceError, Spnego as SpnegoError,
    },
    http as krb_http,
    keytab::Keytab,
    service::{ApRepOptions, Validator},
    spnego::AcceptedContext,
};
use tokio::net::TcpListener;

/// Shared state of the example server.
#[derive(Clone)]
struct AppState {
    /// The acceptor shared by every request; its replay cache must see all of them.
    validator: Arc<Mutex<Validator<'static>>>,
}

/// Runs the example server.
///
/// # Errors
/// Returns keytab loading, listener binding and serving errors.
///
/// # Panics
/// The Tokio entry-point macro panics if its runtime cannot be initialized.
///
/// # Cancel safety
/// The server future owns every resource; dropping it stops the server.
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let keytab = Box::leak(Box::new(load_keytab()?));
    let state = AppState {
        validator: Arc::new(Mutex::new(Validator::new(keytab))),
    };

    let app = Router::new()
        .route("/", get(index))
        .layer(middleware::from_fn_with_state(state.clone(), negotiate))
        .layer(middleware::map_response(security_response))
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:3000").await?;
    axum::serve(listener, app).await?;
    Ok(())
}

/// Answers with the authenticated client principal.
// cancel-safe: formats a string; there is no await point.
async fn index(Extension(context): Extension<AcceptedContext>) -> String {
    format!(
        "authenticated as {}@{}\n",
        context.ap_req.client.name(),
        context.ap_req.client.realm
    )
}

/// Validates the request's `Authorization: Negotiate` header before the inner
/// handler runs, and adds the mutual-authentication reply header.
///
/// A poisoned validator lock answers `500 Internal Server Error`: the replay
/// cache may be inconsistent, so the request is refused rather than accepted.
// cancel-safe: the ticket is validated before the only await point; dropping
// the future after it only drops the inner handler's response.
async fn negotiate(
    State(state): State<AppState>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let accepted = {
        let Ok(mut validator) = state.validator.lock() else {
            let mut response = Response::new(Body::empty());
            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            drop(response.extensions_mut().insert(Arc::new(HttpError::Spnego(
                SpnegoError::Service(ServiceError::ReplayCachePoisoned),
            ))));
            return response;
        };
        match krb_http::accept_request(&mut validator, &mut request) {
            Ok(accepted) => accepted,
            Err(HttpError::MissingAuthorization | HttpError::InvalidHeader(_)) => {
                return krb_http::challenge_response();
            }
            Err(HttpError::Spnego(source)) => {
                if matches!(
                    &source,
                    SpnegoError::Service(
                        ServiceError::ReplayCachePoisoned
                            | ServiceError::ReplayCacheSkewExceeded {
                                maximum: _,
                                requested: _
                            }
                            | ServiceError::ReplayCacheClockRollback
                            | ServiceError::ReplayCacheCapacityExceeded { capacity: _ }
                            | ServiceError::Keytab(KeytabError::Io(_))
                    )
                ) {
                    let mut response = Response::new(Body::empty());
                    *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                    drop(
                        response
                            .extensions_mut()
                            .insert(Arc::new(HttpError::Spnego(source))),
                    );
                    return response;
                }
                return krb_http::reject_response()
                    .unwrap_or_else(|_| krb_http::challenge_response());
            }
            Err(_) => return krb_http::challenge_response(),
        }
    };

    complete_response(
        accepted.ap_rep_response_header(&ApRepOptions::default()),
        request,
        next,
    )
    .await
}

/// Finish authentication before allowing the application handler to run.
// cancel-safe: header validation is synchronous; cancellation drops the inner response future.
async fn complete_response(
    reply: Result<String, SpnegoError>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let header_result = reply
        .map_err(HttpError::Spnego)
        .and_then(|header| HeaderValue::from_str(&header).map_err(HttpError::InvalidHeaderValue));
    let mut credential = match header_result {
        Ok(value) => value,
        Err(error) => {
            let mut response = Response::new(Body::empty());
            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            drop(response.extensions_mut().insert(Arc::new(error)));
            return harden_response(response);
        }
    };
    credential.set_sensitive(true);
    let mut response = next.run(request).await;
    drop(response.headers_mut().insert(WWW_AUTHENTICATE, credential));
    response
}

/// Reads the service keytab named by `KRB5_KTNAME`, or `http.keytab` when unset.
/// Bare paths, FILE and WRFILE names use the library's zeroizing file loader.
///
/// # Errors
///
/// Returns an error when the file cannot be read or is not a valid keytab.
fn load_keytab() -> Result<Keytab, Box<dyn Error>> {
    match env::var("KRB5_KTNAME") {
        Ok(name) => Ok(Keytab::load_name(name)?),
        Err(env::VarError::NotPresent) => Ok(Keytab::load_name("http.keytab")?),
        Err(error @ env::VarError::NotUnicode(_)) => Err(error.into()),
    }
}

/// Applies the example's response security policy.
fn harden_response(mut response: Response) -> Response {
    let headers = response.headers_mut();
    for name in [
        "server",
        "x-powered-by",
        "x-aspnet-version",
        "x-aspnetmvc-version",
    ] {
        drop(headers.remove(name));
    }
    for (name, value) in [
        (
            "strict-transport-security",
            "max-age=63072000; includeSubDomains",
        ),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "deny"),
        (
            "content-security-policy",
            "default-src 'self'; form-action 'self'; object-src 'none'; frame-ancestors 'none'; upgrade-insecure-requests",
        ),
        ("referrer-policy", "no-referrer"),
        (
            "permissions-policy",
            "accelerometer=(), camera=(), geolocation=(), microphone=()",
        ),
        ("cross-origin-embedder-policy", "require-corp"),
        ("cross-origin-opener-policy", "same-origin"),
        ("cross-origin-resource-policy", "same-origin"),
        ("cache-control", "no-store, max-age=0"),
        ("x-dns-prefetch-control", "off"),
        ("x-permitted-cross-domain-policies", "none"),
    ] {
        drop(headers.insert(name, HeaderValue::from_static(value)));
    }
    response
}

/// Adapts the security policy as the outer response middleware.
// cancel-safe: applies headers synchronously without an await point.
async fn security_response(response: Response) -> Response {
    harden_response(response)
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use std::{fs, panic::catch_unwind, process};

    use super::*;

    /// A poisoned validator returns a hardened infrastructure error with a local typed cause.
    #[cfg(feature = "tower")]
    #[tokio::test]
    async fn poisoned_validator_retains_cause() -> Result<(), Box<dyn Error>> {
        use tower_service::Service as _;
        let state = AppState {
            validator: Arc::new(Mutex::new(Validator::from_keytab(Keytab::parse(&[5, 2])?))),
        };
        let shared = Arc::clone(&state.validator);
        let _panic = catch_unwind(move || {
            let guard = shared.lock();
            assert_eq!(format!("{guard:?}"), "poison fixture");
            drop(guard);
        });
        let mut app = Router::new()
            .route("/", get(async || "protected handler reached"))
            .layer(middleware::from_fn_with_state(state, negotiate))
            .layer(middleware::map_response(security_response));
        let response = app.call(Request::new(Body::empty())).await?;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(response.extensions().get::<Arc<HttpError>>().is_some());
        assert_eq!(
            response
                .headers()
                .get("x-content-type-options")
                .ok_or("hardening")?,
            "nosniff"
        );
        Ok(())
    }

    /// Reply-generation failure never reaches the protected handler.
    #[cfg(feature = "tower")]
    #[tokio::test]
    async fn reply_failure_does_not_call_handler() -> Result<(), Box<dyn Error>> {
        use core::sync::atomic::{AtomicUsize, Ordering};

        use tower_service::Service as _;
        for malformed_header in [false, true] {
            let calls = Arc::new(AtomicUsize::new(0));
            let observed = Arc::clone(&calls);
            let mut app = Router::new()
                .route(
                    "/",
                    get(move || {
                        let counter = Arc::clone(&observed);
                        async move {
                            let _: usize = counter.fetch_add(1, Ordering::SeqCst);
                            "protected"
                        }
                    }),
                )
                .layer(middleware::from_fn(move |request, next| {
                    let reply = if malformed_header {
                        Ok("Negotiate invalid\r\nheader".to_owned())
                    } else {
                        Err(SpnegoError::MissingApRep)
                    };
                    complete_response(reply, request, next)
                }));
            let response = app.call(Request::new(Body::empty())).await?;
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert!(!response.headers().contains_key(WWW_AUTHENTICATE));
        }
        Ok(())
    }

    /// The example delegates WRFILE names to the zeroizing keytab loader.
    #[test]
    fn keytab_loader_accepts_wrfile() -> Result<(), Box<dyn Error>> {
        use std::process::Command;
        // Given a child process with an explicit WRFILE credential source.
        if env::var_os("TASK3_KEYTAB_CHILD").is_some() {
            assert_eq!(load_keytab()?.entries().len(), 0);
            return Ok(());
        }
        let path = env::temp_dir().join(format!("task3-http-{}.keytab", process::id()));
        fs::write(&path, [5, 2])?;
        // When the example loader runs, then it accepts the supported store prefix.
        let status = Command::new(env::current_exe()?)
            .args([
                "--exact",
                "tests::keytab_loader_accepts_wrfile",
                "--nocapture",
            ])
            .env("TASK3_KEYTAB_CHILD", "1")
            .env("KRB5_KTNAME", format!("WRFILE:{}", path.display()))
            .status()?;
        fs::remove_file(path)?;
        assert!(status.success());
        Ok(())
    }

    /// Security headers override insecure values on success, challenge, error and fallback responses.
    #[test]
    fn hardening_covers_all_response_statuses() -> Result<(), Box<dyn Error>> {
        for status in [
            StatusCode::OK,
            StatusCode::UNAUTHORIZED,
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::NOT_FOUND,
        ] {
            let mut response = Response::new(Body::empty());
            *response.status_mut() = status;
            drop(response.headers_mut().insert(
                "server",
                HeaderValue::from_static("internal-host/build-secret"),
            ));
            drop(
                response
                    .headers_mut()
                    .insert("x-powered-by", HeaderValue::from_static("framework-secret")),
            );
            drop(response.headers_mut().insert(
                "x-aspnet-version",
                HeaderValue::from_static("version-secret"),
            ));
            drop(response.headers_mut().insert(
                "x-aspnetmvc-version",
                HeaderValue::from_static("version-secret"),
            ));
            drop(
                response
                    .headers_mut()
                    .insert("x-content-type-options", HeaderValue::from_static("unsafe")),
            );
            let hardened = harden_response(response);
            assert_eq!(hardened.status(), status);
            for name in [
                "server",
                "x-powered-by",
                "x-aspnet-version",
                "x-aspnetmvc-version",
            ] {
                assert!(hardened.headers().get(name).is_none());
            }
            assert_eq!(
                hardened
                    .headers()
                    .get("x-content-type-options")
                    .ok_or("nosniff missing")?,
                "nosniff"
            );
            for name in [
                "strict-transport-security",
                "x-frame-options",
                "content-security-policy",
                "referrer-policy",
                "permissions-policy",
                "cross-origin-embedder-policy",
                "cross-origin-opener-policy",
                "cross-origin-resource-policy",
                "cache-control",
                "x-dns-prefetch-control",
                "x-permitted-cross-domain-policies",
            ] {
                assert!(hardened.headers().contains_key(name), "missing {name}");
            }
        }
        Ok(())
    }
}

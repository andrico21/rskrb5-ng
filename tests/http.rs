//! HTTP Negotiate helper, client wrapper and Tower layer tests against the gokrb5 vectors.
#![cfg(feature = "http")]

#[cfg(feature = "tokio")]
extern crate alloc;
#[path = "support/context.rs"]
mod context;
#[cfg(feature = "tower")]
#[path = "support/env.rs"]
mod env;

/// HTTP Negotiate tests.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    #[cfg(feature = "tokio")]
    use alloc::rc::Rc;
    #[cfg(feature = "tokio")]
    use core::cell::{Cell, RefCell};
    #[cfg(feature = "tokio")]
    use core::convert::Infallible;
    #[cfg(feature = "tower")]
    use core::future::Ready;
    #[cfg(any(feature = "tokio", feature = "tower"))]
    use core::future::ready;
    #[cfg(feature = "tower")]
    use core::pin::pin;
    #[cfg(feature = "tower")]
    use core::task::{Context, Poll, Waker};
    use core::time::Duration;
    use std::time::{SystemTime, UNIX_EPOCH};
    #[cfg(feature = "tower")]
    use std::{
        env::{temp_dir, var},
        fs,
        path::PathBuf,
    };

    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use hex::FromHexError;
    #[cfg(any(feature = "tokio", feature = "tower"))]
    use http_types::Method;
    #[cfg(feature = "tokio")]
    use http_types::Uri;
    use http_types::{
        Request, Response, StatusCode,
        header::{HeaderValue, WWW_AUTHENTICATE},
    };
    use pretty_assertions::assert_eq;
    use rasn::der;
    #[cfg(feature = "tokio")]
    use rskrb5_ng::client::{
        Tokio, negotiate::BlockingClient as BlockingNegotiateClient,
        negotiate::Client as NegotiateClient, transport::KdcProtocol,
    };
    #[cfg(any(feature = "tokio", feature = "tower"))]
    use rskrb5_ng::config::Config;
    #[cfg(feature = "tower")]
    use rskrb5_ng::error::Service as ServiceError;
    #[cfg(feature = "tokio")]
    use rskrb5_ng::service::ReplayCache;
    #[cfg(any(feature = "tokio", feature = "tower"))]
    use rskrb5_ng::service::SharedReplayCache;
    use rskrb5_ng::{
        ap_req,
        client::{AsRepSession, principal::Principal},
        error::{Http as HttpError, Spnego as SpnegoError},
        http as krb_http,
        keytab::{EncryptionKey, Keytab},
        service::{ApRepOptions, Validator},
        spnego::{
            self, AcceptedContext, InitiatorContextOptions, Krb5MechToken, NegTokenInit, Token,
        },
    };
    #[cfg(feature = "tokio")]
    use tokio::runtime::{Builder, Runtime};
    #[cfg(feature = "tower")]
    use tower_layer::Layer as _;
    #[cfg(feature = "tower")]
    use tower_service::Service;

    use super::context::{Context as _, TestError};
    #[cfg(feature = "tower")]
    use super::env;

    const HTTP_KEYTAB: &str = concat!(
        "0502000000440002000b544553542e474f4b5242350004485454500010686f73742e746573742e676f6b",
        "72623500000001590dc4dc010011001057a7754c70c4d85c155c718c2f1292b0000000540002000b",
        "544553542e474f4b5242350004485454500010686f73742e746573742e676f6b72623500000001590d",
        "c4dc01001200209cad00bbc72d703258e911dc18e6d5487cf737bf67fd111f0c2463ad6033bf51",
        "000000440002000b544553542e474f4b5242350004485454500010686f73742e746573742e676f6b",
        "72623500000001590dc4dc020011001057a7754c70c4d85c155c718c2f1292b0000000540002000b",
        "544553542e474f4b5242350004485454500010686f73742e746573742e676f6b72623500000001590d",
        "c4dc02001200209cad00bbc72d703258e911dc18e6d5487cf737bf67fd111f0c2463ad6033bf51",
    );
    const VALID_AP_REQ: &str = concat!(
        "6e8201f8308201f4a003020105a10302010ea20703050000000000a382012f6182012b30820127a0",
        "03020105a10d1b0b544553542e474f4b524235a2233021a003020101a11a30181b04485454501b",
        "10686f73742e746573742e676f6b726235a381eb3081e8a003020112a103020101a281db0481d8",
        "5e7242bdf5331825046b4692f2f850f62dedee984e72a490ac48fc3375f5bc1a50c07ff766338",
        "cbb1486cd8f9974b0865f3fd3ecb4e72b6dc556bb73a1cea8f4579983e625676b43854ff9910",
        "a0b60996f148ee1b6a49a1896d41afde6e82d2d8ed9f7304ac0ded7a74f88694dc69ab532",
        "ff51f5e7ba7fce87f4ba19885fc915e6d83f11f2152bd64f3fd63cb8b160148fed6fa9b01",
        "d86acd337d20c3b99622b166b6b283cd3704f36147972015c3a750ce9c855ae58ec598929ed",
        "953b4008dbad1ca6f0a715eb07ee19f5124ff7354ded3928fccd6cc7e8a481ab3081a8a0",
        "03020112a103020101a2819b04819882e028aad111ace518b36bd7305f9ff06545036b2214916",
        "00d07509d4e1bbcacb5a6bde72ec8812c2ef087cb64dcd905d7eba708d7a7c1a782e7bc",
        "cc3d46bfc503e5075bd6ca1d2f27b218ebb907483b6b0b8bac5137fa15fb59b1df434371",
        "e041c817d652e3068912e55203ec6ea5ce374a20e5b9b5ed9dfb6bdb06137b90b2db2a",
        "db192d415375581bdf9a2bfe73d19c13ba1d983bf513",
    );
    const VALID_SESSION_KEY: &str =
        "8845cbaccbf11cb9f467fd577ba51c70d73de6554980a05395bf319e18bdda07";
    const AP_REP_CONFOUNDER: &str = "000102030405060708090a0b0c0d0e0f";

    /// Every response generated by the library has the complete hardening policy.
    #[test]
    fn generated_responses_have_security_headers() -> Result<(), TestError> {
        // Given challenge and rejection responses from public constructors.
        for response in [
            krb_http::challenge_response::<()>(),
            krb_http::reject_response::<()>()?,
        ] {
            // When inspected at the HTTP boundary, then all policy headers are present.
            for name in [
                "strict-transport-security",
                "x-content-type-options",
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
                assert!(response.headers().contains_key(name), "missing {name}");
            }
        }
        Ok(())
    }

    /// Tower applies the same policy on challenge, reject and authenticated success paths.
    #[cfg(feature = "tower")]
    #[test]
    fn tower_hardening_covers_response_paths() -> Result<(), TestError> {
        let keytab = keytab()?;
        for header in [
            None,
            Some("Negotiate invalid".to_owned()),
            Some(valid_authorization_header()?),
        ] {
            // Given an actual layer with an application-specific CSP and fingerprint.
            let mut service = krb_http::NegotiateLayer::new(&keytab)
                .with_now(timestamp(1_893_553_447)?)
                .layer(PolicyService);
            let mut request = Request::new(());
            if let Some(value) = &header {
                krb_http::set_authorization_header(&mut request, value)?;
            }
            // When the request traverses middleware, then all twelve headers are present.
            let response = run_ready(service.call(request))??;
            for name in [
                "strict-transport-security",
                "x-content-type-options",
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
                assert!(response.headers().contains_key(name), "missing {name}");
            }
            assert!(!response.headers().contains_key("server"));
            if response.status() == StatusCode::OK {
                assert_eq!(
                    response
                        .headers()
                        .get("content-security-policy")
                        .context("CSP")?,
                    "default-src 'none'"
                );
                assert!(
                    response
                        .headers()
                        .get(WWW_AUTHENTICATE)
                        .context("AP-REP")?
                        .is_sensitive()
                );
            }
        }
        Ok(())
    }

    /// Inner response with explicit application policy and a fingerprint to remove.
    #[cfg(feature = "tower")]
    #[derive(Clone)]
    struct PolicyService;

    /// Disabling optional AP-REP cannot discard required reciprocal mechanism integrity.
    #[cfg(feature = "tower")]
    #[test]
    fn ap_rep_disabled_completes_required_mic() -> Result<(), TestError> {
        use rskrb5_ng::{
            crypto::AesSha1Etype,
            spnego::{MicToken, oid::ObjectIdentifier},
        };
        let Token::Init(mut init) =
            spnego::parse_negotiate_header(initiator_context()?.header_ref())?
        else {
            return Err("initial token".into());
        };
        init.mech_types_mut().insert(
            0,
            ObjectIdentifier::from_arcs(vec![1, 3, 6, 1, 4, 1, 311, 2, 2, 10])?,
        );
        let list = decode_hex("3017060a2b06010401823702020a06092a864886f712010202")?;
        let key = decode_hex(VALID_SESSION_KEY)?;
        let mut mic = vec![4, 4, 0, 255, 255, 255, 255, 255];
        mic.extend_from_slice(&42_u64.to_be_bytes());
        let mut signed = list.clone();
        signed.extend_from_slice(&mic);
        mic.extend_from_slice(&AesSha1Etype::Aes256.checksum(&key, &signed, 25)?);
        init.set_mech_list_mic(Some(mic.into()));
        let keytab = keytab()?;
        let mut service = krb_http::NegotiateLayer::new(&keytab)
            .with_now(timestamp(1_893_553_447)?)
            .with_ap_rep(false)
            .layer(PolicyService);
        let mut request = Request::new(());
        krb_http::set_authorization_header(
            &mut request,
            &spnego::negotiate_header(&Token::Init(init))?,
        )?;
        let response = run_ready(service.call(request))??;
        let header = response
            .headers()
            .get(WWW_AUTHENTICATE)
            .context("required completion")?
            .to_str()?;
        let Token::Resp(completion) = spnego::parse_negotiate_header(header)? else {
            return Err("completion token".into());
        };
        MicToken::decode(completion.mech_list_mic().context("reciprocal MIC")?, true)?
            .with_payload(list)
            .verify(&EncryptionKey::new(18, key), 23)?;
        Ok(())
    }

    /// Cache replacement checks the shared validator rather than stale clone settings.
    #[cfg(feature = "tower")]
    #[test]
    fn cloned_service_rejects_incompatible_cache() -> Result<(), TestError> {
        let keytab = keytab()?;
        let service = krb_http::NegotiateLayer::new(&keytab)
            .with_now(timestamp(1_893_553_447)?)
            .layer(PolicyService);
        let clone = service.clone();
        let mut configured = service.with_max_clock_skew(Duration::from_mins(15))?;
        assert!(matches!(
            clone.with_shared_replay_cache(SharedReplayCache::new()),
            Err(HttpError::Spnego(SpnegoError::Service(
                ServiceError::ReplayCacheSkewExceeded {
                    maximum: _,
                    requested: _
                }
            )))
        ));
        let mut request = Request::new(());
        krb_http::set_authorization_header(&mut request, &valid_authorization_header()?)?;
        assert_eq!(
            run_ready(configured.call(request))??.status(),
            StatusCode::OK
        );
        Ok(())
    }

    /// Lowering one layer's window does not shorten retention for its siblings.
    #[cfg(feature = "tower")]
    #[test]
    fn cloned_layer_preserves_shared_cache_ceiling() -> Result<(), TestError> {
        let keytab = keytab()?;
        let layer = krb_http::NegotiateLayer::new(&keytab)
            .with_now(timestamp(1_893_553_447)?)
            .with_max_clock_skew(Duration::from_mins(15))?;
        drop(layer.clone().with_max_clock_skew(Duration::from_mins(5))?);
        let mut service = layer.layer(PolicyService);
        let mut request = Request::new(());
        krb_http::set_authorization_header(&mut request, &valid_authorization_header()?)?;
        assert_eq!(run_ready(service.call(request))??.status(), StatusCode::OK);
        Ok(())
    }

    /// A pending authenticated response never formats its retained AP-REP credential.
    #[cfg(feature = "tower")]
    #[test]
    fn pending_response_debug_redacts_credentials() -> Result<(), TestError> {
        let keytab = keytab()?;
        let mut service = krb_http::NegotiateLayer::new(&keytab)
            .with_now(timestamp(1_893_553_447)?)
            .layer(PolicyService);
        let mut request = Request::new(());
        krb_http::set_authorization_header(&mut request, &valid_authorization_header()?)?;
        let future = service.call(request);
        let diagnostic = format!("{future:?}");
        let response = run_ready(future)??;
        let credential = response
            .headers()
            .get(WWW_AUTHENTICATE)
            .context("AP-REP")?
            .to_str()?;
        assert!(!diagnostic.contains(credential));
        assert!(diagnostic.contains("header_len"));
        Ok(())
    }

    /// Replay-cache incompatibility is rejected before serving requests.
    #[cfg(feature = "tower")]
    #[test]
    fn internal_validation_failure_returns_500() -> Result<(), TestError> {
        let keytab = keytab()?;
        let service = krb_http::NegotiateLayer::new(&keytab)
            .with_now(timestamp(1_893_553_447)?)
            .with_max_clock_skew(Duration::from_secs(301))?
            .with_shared_replay_cache(SharedReplayCache::new());
        assert!(matches!(
            service,
            Err(HttpError::Spnego(SpnegoError::Service(
                ServiceError::ReplayCacheSkewExceeded {
                    maximum: _,
                    requested: _
                }
            )))
        ));
        Ok(())
    }

    /// An owned layer cache follows a configured 301-second acceptance window.
    #[cfg(feature = "tower")]
    #[test]
    fn configured_skew_accepts_fresh_http_request() -> Result<(), TestError> {
        let keytab = keytab()?;
        let mut service = krb_http::NegotiateLayer::new(&keytab)
            .with_now(timestamp(1_893_553_447)?)
            .with_max_clock_skew(Duration::from_secs(301))?
            .layer(PolicyService);
        let mut request = Request::new(());
        krb_http::set_authorization_header(&mut request, &valid_authorization_header()?)?;
        assert_eq!(run_ready(service.call(request))??.status(), StatusCode::OK);
        Ok(())
    }

    /// Clones share replay evidence from the same validator.
    #[cfg(feature = "tower")]
    #[test]
    fn cloned_services_share_replay_state() -> Result<(), TestError> {
        let keytab = keytab()?;
        let mut service = krb_http::NegotiateLayer::new(&keytab)
            .with_now(timestamp(1_893_553_447)?)
            .layer(PolicyService);
        let mut cloned = service.clone();
        let mut request = Request::new(());
        krb_http::set_authorization_header(&mut request, &valid_authorization_header()?)?;
        assert_eq!(
            run_ready(service.call(request.clone()))??.status(),
            StatusCode::OK
        );
        assert_eq!(
            run_ready(cloned.call(request))??.status(),
            StatusCode::UNAUTHORIZED
        );
        Ok(())
    }

    /// Changing the clock after admission preserves the validator's local replay evidence.
    #[cfg(feature = "tower")]
    #[test]
    fn service_clock_builder_preserves_local_replays() -> Result<(), TestError> {
        let keytab = keytab()?;
        let now = timestamp(1_893_553_447)?;
        let mut service = krb_http::NegotiateLayer::new(&keytab)
            .without_shared_replay_cache()
            .with_now(now)
            .layer(PolicyService);
        let mut request = Request::new(());
        krb_http::set_authorization_header(&mut request, &valid_authorization_header()?)?;
        assert_eq!(
            run_ready(service.call(request.clone()))??.status(),
            StatusCode::OK
        );
        let mut configured = service.with_now(now);
        assert_eq!(
            run_ready(configured.call(request))??.status(),
            StatusCode::UNAUTHORIZED
        );
        Ok(())
    }

    /// Opting out affects inner responses, never library-generated challenges.
    #[cfg(feature = "tower")]
    #[test]
    fn hardening_opt_out_preserves_application_response() -> Result<(), TestError> {
        let keytab = keytab()?;
        let mut service = krb_http::NegotiateLayer::new(&keytab)
            .with_response_hardening(false)
            .with_now(timestamp(1_893_553_447)?)
            .layer(PolicyService);
        let challenge = run_ready(service.call(Request::new(())))??;
        assert!(
            challenge
                .headers()
                .contains_key("strict-transport-security")
        );
        let mut request = Request::new(());
        krb_http::set_authorization_header(&mut request, &valid_authorization_header()?)?;
        let response = run_ready(service.call(request))??;
        assert_eq!(
            response
                .headers()
                .get("server")
                .context("application fingerprint")?,
            "secret-host"
        );
        assert!(!response.headers().contains_key("strict-transport-security"));
        Ok(())
    }

    /// The real Axum Router accepts the layer's Clone service and Send future.
    #[cfg(feature = "tower")]
    #[test]
    fn negotiate_layer_integrates_with_axum_router() -> Result<(), TestError> {
        use core::convert::Infallible;

        use axum::{Router, body::Body, error_handling::HandleError, routing::get};
        let layer = krb_http::NegotiateLayer::from_keytab(keytab()?);
        let service = layer.layer(Router::new().route("/", get(async || "protected")));
        let mut router = Router::new().fallback_service(HandleError::new(
            service,
            async |_error: krb_http::TowerError<Infallible>| StatusCode::INTERNAL_SERVER_ERROR,
        ));
        let response = run_ready(router.call(Request::new(Body::empty())))??;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    /// A Send inner future remains movable onto an executor worker thread.
    #[cfg(feature = "tower")]
    #[test]
    fn tower_future_is_send() -> Result<(), TestError> {
        fn require_send<T>(value: T) -> T
        where
            T: Send,
        {
            value
        }
        // Given a service whose future and response body are Send.
        let keytab = keytab()?;
        let mut service = krb_http::NegotiateLayer::new(&keytab).layer(PolicyService);
        // When wrapped, then the returned future still satisfies Send.
        let response = run_ready(require_send(service.call(Request::new(()))))??;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    #[cfg(feature = "tower")]
    impl Service<Request<()>> for PolicyService {
        type Response = Response<()>;
        type Error = HttpError;
        type Future = Ready<Result<Response<()>, HttpError>>;
        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
        fn call(&mut self, _req: Request<()>) -> Self::Future {
            let mut response = Response::new(());
            drop(
                response
                    .headers_mut()
                    .insert("server", HeaderValue::from_static("secret-host")),
            );
            drop(response.headers_mut().insert(
                "content-security-policy",
                HeaderValue::from_static("default-src 'none'"),
            ));
            ready(Ok(response))
        }
    }

    /// A genuine AP-REP cannot authenticate unfinished or unbound SPNEGO metadata.
    #[test]
    fn completion_rejects_invalid_metadata() -> Result<(), TestError> {
        // Given an AP-REP that genuinely matches the retained initiator.
        let context = initiator_context()?;
        let Token::Resp(response) =
            spnego::parse_negotiate_header(&ap_rep_response_header(&context)?)?
        else {
            return Err("expected response".into());
        };
        let mut incomplete = response.clone();
        incomplete.set_neg_state(Some(spnego::NegState::AcceptIncomplete));
        let mut request_mic = response.clone();
        request_mic.set_neg_state(Some(spnego::NegState::RequestMic));
        let mut absent_state = response.clone();
        absent_state.set_neg_state(None);
        let mut absent_mechanism = response.clone();
        absent_mechanism.set_supported_mech(None);
        let mut wrong_mech = response.clone();
        wrong_mech.set_supported_mech(Some(spnego::oid::ObjectIdentifier::from_arcs(vec![
            1, 2, 3,
        ])?));
        let mut mic = response;
        mic.set_mech_list_mic(Some(vec![0; 28].into()));
        for altered in [
            incomplete,
            request_mic,
            absent_state,
            absent_mechanism,
            wrong_mech,
            mic,
        ] {
            // When only unauthenticated negotiation metadata changes.
            let header = spnego::negotiate_header(&Token::Resp(altered))?;
            let mut http_response = Response::new(());
            drop(
                http_response
                    .headers_mut()
                    .insert(WWW_AUTHENTICATE, HeaderValue::from_str(&header)?),
            );
            // Then neither the direct verifier nor HTTP classification accepts it.
            assert!(matches!(
                context.verify_ap_rep_response_header(&header),
                Err(SpnegoError::NegotiationRequiresState
                    | SpnegoError::UnsupportedMechanism(_)
                    | SpnegoError::MechListMicRequiresState
                    | SpnegoError::InvalidMechListMic)
            ));
            assert!(matches!(
                krb_http::classify_negotiate_response(&context, &http_response),
                krb_http::ClientNegotiateResponse::InvalidToken { message: _ }
            ));
        }
        Ok(())
    }

    /// A valid acceptor MIC binds completion to the initiator's actual mechanism offer.
    #[test]
    fn completion_verifies_acceptor_mic() -> Result<(), TestError> {
        for initiator_subkey in [None, Some(EncryptionKey::new(18, vec![0x34; 32]))] {
            for acceptor_subkey in [None, Some(EncryptionKey::new(18, vec![0x56; 32]))] {
                let context = initiator_context_with_options(
                    InitiatorContextOptions::new()
                        .with_sequence_number(Some(42))
                        .with_subkey(initiator_subkey.clone()),
                )?;
                let keytab = keytab()?;
                let mut validator = Validator::new(&keytab).with_now(timestamp(1_893_553_447)?);
                let mut accepted =
                    spnego::accept_sec_context_header(&mut validator, context.header_ref())?;
                accepted.mech_types_der = Some(hex::decode("300b06092a864886f712010202")?);
                let header = accepted.ap_rep_response_header_with_confounder(
                    &decode_hex(AP_REP_CONFOUNDER)?,
                    &ApRepOptions::default()
                        .with_sequence_number(Some(77))
                        .with_subkey(acceptor_subkey),
                )?;
                let verified = context.verify_ap_rep_response_header(&header)?;
                assert_eq!(verified.sequence_number(), Some(77));
                assert!(matches!(
                    krb_http::classify_negotiate_response(
                        &context,
                        &response_with_www_authenticate(&header)?
                    ),
                    krb_http::ClientNegotiateResponse::Accepted { ap_rep: Some(_) }
                ));
                let Token::Resp(mut altered) = spnego::parse_negotiate_header(&header)? else {
                    return Err("response expected".into());
                };
                let mut damaged = altered.mech_list_mic().context("MIC")?.to_vec();
                *damaged.last_mut().context("MIC checksum")? ^= 1;
                altered.set_mech_list_mic(Some(damaged.into()));
                assert!(matches!(
                    context.verify_ap_rep_response_header(&spnego::negotiate_header(
                        &Token::Resp(altered)
                    )?),
                    Err(SpnegoError::InvalidMechListMic)
                ));
            }
        }
        Ok(())
    }

    /// Generated and forwarded credentials are sensitive before request diagnostics run.
    #[test]
    fn credential_headers_are_sensitive() -> Result<(), TestError> {
        // Given an outgoing credential and an incoming raw header.
        let mut request = Request::new(());
        krb_http::set_authorization_header(&mut request, "Negotiate distinctive-secret")?;
        // When formatted, then the sensitive value is withheld.
        assert!(
            request
                .headers()
                .get("authorization")
                .context("header")?
                .is_sensitive()
        );
        assert!(!format!("{request:?}").contains("distinctive-secret"));
        let incoming = valid_authorization_header()?;
        drop(
            request
                .headers_mut()
                .insert("authorization", HeaderValue::from_str(&incoming)?),
        );
        let keytab = keytab()?;
        let mut validator = Validator::new(&keytab).with_now(timestamp(1_893_553_447)?);
        drop(krb_http::accept_request(&mut validator, &mut request)?);
        assert!(
            request
                .headers()
                .get("authorization")
                .context("incoming header")?
                .is_sensitive()
        );
        assert!(
            krb_http::reject_response::<()>()?
                .headers()
                .get(WWW_AUTHENTICATE)
                .context("reply")?
                .is_sensitive()
        );
        Ok(())
    }

    /// Context debugging must not expose a usable Authorization token or AP-REQ bytes.
    #[test]
    fn initiator_debug_redacts_credentials() -> Result<(), TestError> {
        // Given a live initiator context.
        let context = initiator_context()?;
        // When formatted for diagnostics, then both credential representations are absent.
        let rendered = format!("{context:?}");
        assert!(!rendered.contains(context.header_ref()));
        assert!(!rendered.contains(&format!("{:?}", context.ap_req_der_ref())));
        #[cfg(feature = "tokio")]
        {
            let header = context.header_ref().to_owned();
            let mut client = negotiate_client_with_cached_service_ticket()?;
            let calls = Cell::new(0_u32);
            let result = runtime()?.block_on(krb_http::send_with_negotiate(
                &mut client,
                context.service().clone(),
                || Request::new(()),
                |_| {
                    calls.set(calls.get().saturating_add(1));
                    ready(Ok::<_, Infallible>(if calls.get() == 1 {
                        krb_http::challenge_response::<()>()
                    } else {
                        Response::new(())
                    }))
                },
            ))?;
            assert!(!format!("{result:?}").contains(header.as_str()));
            assert!(
                !format!("{result:?}")
                    .contains(result.context().context("retry context")?.header_ref())
            );
        }
        Ok(())
    }

    /// Pins that the HTTP helpers set and read the Negotiate headers and build the 401 challenge.
    #[test]
    fn http_helpers_set_headers_and_challenge() -> Result<(), TestError> {
        let mut request = Request::new(());
        assert!(matches!(
            krb_http::authorization_header(&request),
            Err(HttpError::MissingAuthorization)
        ));

        krb_http::set_authorization_header(&mut request, "Negotiate token")
            .context("header sets")?;
        assert_eq!(
            krb_http::authorization_header(&request).context("header reads")?,
            "Negotiate token"
        );

        let response = krb_http::challenge_response::<()>();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response
                .headers()
                .get(WWW_AUTHENTICATE)
                .context("challenge header exists")?
                .to_str()
                .context("challenge header is a string")?,
            "Negotiate"
        );
        Ok(())
    }

    /// Pins that accepting a request validates its SPNEGO header and attaches the accepted context.
    #[test]
    fn accept_request_validates_spnego_header_and_adds_extension() -> Result<(), TestError> {
        let keytab = keytab()?;
        let mut validator = Validator::new(&keytab).with_now(timestamp(1_893_553_447)?);
        let mut request = Request::new(());
        krb_http::set_authorization_header(&mut request, &valid_authorization_header()?)
            .context("authorization header sets")?;

        let accepted =
            krb_http::accept_request(&mut validator, &mut request).context("request validates")?;

        assert_eq!(accepted.ap_req.client().name(), "testuser1");
        assert_eq!(accepted.ap_req.service().name(), "HTTP/host.test.gokrb5");
        assert!(
            request.extensions().get::<AcceptedContext>().is_some(),
            "accepted context is attached to request extensions"
        );
        Ok(())
    }

    /// Pins that accepting a request also validates a raw KRB5 Negotiate header.
    #[test]
    fn accept_request_validates_raw_krb5_header() -> Result<(), TestError> {
        let keytab = keytab()?;
        let mut validator = Validator::new(&keytab).with_now(timestamp(1_893_553_447)?);
        let mut request = Request::new(());
        krb_http::set_authorization_header(&mut request, &raw_krb5_authorization_header()?)
            .context("authorization header sets")?;

        let accepted =
            krb_http::accept_request(&mut validator, &mut request).context("request validates")?;

        assert_eq!(accepted.ap_req.client().name(), "testuser1");
        assert_eq!(accepted.ap_req.service().name(), "HTTP/host.test.gokrb5");
        Ok(())
    }

    /// Pins that the Negotiate challenge is found among several `WWW-Authenticate` values.
    #[test]
    fn http_helpers_scan_www_authenticate_negotiate_challenges() -> Result<(), TestError> {
        let mut missing = Response::new(());
        assert!(matches!(
            krb_http::www_authenticate_negotiate_header(&missing),
            Err(HttpError::MissingWwwAuthenticate)
        ));

        let _: bool = missing.headers_mut().append(
            WWW_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=\"test, local\""),
        );
        assert!(matches!(
            krb_http::www_authenticate_negotiate_header(&missing),
            Err(HttpError::MissingNegotiateChallenge)
        ));

        let challenge = krb_http::challenge_response::<()>();
        assert_eq!(
            krb_http::www_authenticate_negotiate_header(&challenge)
                .context("bare challenge is found")?,
            "Negotiate"
        );

        let mut response = Response::new(());
        let _: bool = response.headers_mut().append(
            WWW_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=\"test, local\""),
        );
        let _: bool = response.headers_mut().append(
            WWW_AUTHENTICATE,
            HeaderValue::from_static("negotiate response-token"),
        );
        assert_eq!(
            krb_http::www_authenticate_negotiate_header(&response)
                .context("Negotiate challenge is found")?,
            "negotiate response-token"
        );
        Ok(())
    }

    /// Pins that authorizing a request sets its header and returns the initiator context.
    #[cfg(feature = "tokio")]
    #[test]
    fn authorize_request_context_sets_header_and_returns_context() -> Result<(), TestError> {
        runtime()?.block_on(async {
            let service_ticket = current_service_ticket_session()?;
            let service = service_ticket.service().clone();
            let mut client = Tokio::with_password(
                Config::new(),
                KdcProtocol::Auto,
                Principal::user("TEST.GOKRB5", "testuser1"),
                b"unused".to_vec(),
            );
            client
                .cache_service_ticket(service_ticket)
                .context("fixture service ticket matches the client identity")?;
            let mut request = Request::new(());

            let context = krb_http::authorize_request_context_with_options(
                &mut client,
                &mut request,
                service,
                InitiatorContextOptions::new().with_sequence_number(Some(42)),
            )
            .await
            .context("request is authorized")?;

            assert_eq!(context.sequence_number(), Some(42));
            assert_eq!(
                krb_http::authorization_header(&request).context("Authorization header exists")?,
                context.header_ref()
            );
            Ok(())
        })
    }

    /// The unit-returning authorization helper installs a sensitive decodable header.
    #[cfg(feature = "tokio")]
    #[test]
    fn authorize_request_installs_header() -> Result<(), TestError> {
        runtime()?.block_on(async {
            let ticket = current_service_ticket_session()?;
            let service = ticket.service().clone();
            let mut client = Tokio::with_password(
                Config::new(),
                KdcProtocol::Auto,
                ticket.client().clone(),
                b"unused".to_vec(),
            );
            client.cache_service_ticket(ticket)?;
            let mut request = Request::new(());
            krb_http::authorize_request(&mut client, &mut request, service).await?;
            let header =
                krb_http::authorization_header(&request).context("authorization header")?;
            assert!(matches!(
                spnego::parse_negotiate_header(header)?,
                Token::Init(_)
            ));
            Ok(())
        })
    }

    /// Pins that the Negotiate client wrapper authorizes a request with its own session key copy.
    #[cfg(feature = "tokio")]
    #[test]
    fn authorize_request_context_supports_negotiate_client_wrapper() -> Result<(), TestError> {
        runtime()?.block_on(async {
            let mut service_ticket = current_service_ticket_session()?;
            let service = service_ticket.service().clone();
            let mut tokio_client = Tokio::with_password(
                Config::new(),
                KdcProtocol::Auto,
                Principal::user("TEST.GOKRB5", "testuser1"),
                b"unused".to_vec(),
            );
            tokio_client
                .cache_service_ticket(service_ticket.clone())
                .context("fixture service ticket matches the client identity")?;
            let mut client = NegotiateClient::from_tokio_client(tokio_client);
            let mut request = Request::new(());

            let context = krb_http::authorize_request_context_with_negotiate_client_options(
                &mut client,
                &mut request,
                service,
                InitiatorContextOptions::new().with_sequence_number(Some(7)),
            )
            .await
            .context("request is authorized")?;

            assert_eq!(context.sequence_number(), Some(7));
            assert_eq!(
                krb_http::authorization_header(&request).context("Authorization header exists")?,
                context.header_ref()
            );

            service_ticket.set_session_key(EncryptionKey::new(18, vec![0x55; 32]));
            assert_ne!(context.session_key_ref(), service_ticket.session_key());
            Ok(())
        })
    }

    /// Pins that the async wrapper rebuilds and retries the request after a Negotiate challenge.
    #[cfg(feature = "tokio")]
    #[test]
    fn negotiate_http_client_retries_challenge_with_replayable_request() -> Result<(), TestError> {
        runtime()?.block_on(async {
            let service_ticket = current_service_ticket_session()?;
            let service = service_ticket.service().clone();
            let mut tokio_client = Tokio::with_password(
                Config::new(),
                KdcProtocol::Auto,
                Principal::user("TEST.GOKRB5", "testuser1"),
                b"unused".to_vec(),
            );
            tokio_client
                .cache_service_ticket(service_ticket)
                .context("fixture service ticket matches the client identity")?;
            let mut client = NegotiateClient::from_tokio_client(tokio_client);
            let make_calls = Rc::new(Cell::new(0_usize));
            let make_calls_for_factory = Rc::clone(&make_calls);
            let sent = Rc::new(RefCell::new(Vec::<(Option<String>, Vec<u8>)>::new()));
            let sent_for_sender = Rc::clone(&sent);
            let accept_completed = www_authenticate(
                &spnego::accept_completed_header().context("accept-completed header")?,
            )?;

            let result = krb_http::send_with_negotiate_options(
                &mut client,
                service,
                InitiatorContextOptions::new().with_sequence_number(Some(99)),
                move || {
                    let call = make_calls_for_factory.get().saturating_add(1);
                    make_calls_for_factory.set(call);
                    let mut request = Request::new(format!("payload-{call}").into_bytes());
                    *request.method_mut() = Method::POST;
                    *request.uri_mut() = Uri::from_static("/protected");
                    request
                },
                move |request: Request<Vec<u8>>| {
                    let authorization = krb_http::authorization_header(&request)
                        .ok()
                        .map(str::to_owned);
                    let body = request.body().clone();
                    let call = {
                        let mut sent_log = sent_for_sender.borrow_mut();
                        sent_log.push((authorization.clone(), body));
                        sent_log.len()
                    };
                    let response = if call == 1 {
                        krb_http::challenge_response::<Vec<u8>>()
                    } else {
                        let Some(header) = authorization else {
                            return ready(Err::<_, TestError>(
                                "retry request has authorization".into(),
                            ));
                        };
                        assert!(
                            header.starts_with("Negotiate "),
                            "retry Authorization uses Negotiate"
                        );
                        response_with_www_authenticate_body(
                            accept_completed.clone(),
                            b"ok".to_vec(),
                        )
                    };
                    ready(Ok::<_, TestError>(response))
                },
            )
            .await
            .context("Negotiate send succeeds")?;

            assert!(result.did_negotiate());
            assert_eq!(
                result
                    .context()
                    .context("context is retained")?
                    .sequence_number(),
                Some(99)
            );
            assert!(matches!(
                result.negotiation(),
                Some(krb_http::ClientNegotiateResponse::Accepted { ap_rep: None })
            ));
            assert_eq!(result.response().status(), StatusCode::OK);
            assert_eq!(result.response().body().as_slice(), b"ok");
            assert_eq!(make_calls.get(), 2);

            let sent_requests = sent.borrow();
            assert_eq!(sent_requests.len(), 2);
            let initial = sent_requests.first().context("initial request was sent")?;
            assert!(initial.0.is_none(), "initial request is unauthenticated");
            assert_eq!(initial.1.as_slice(), b"payload-1");
            let retry = sent_requests.get(1).context("retry request was sent")?;
            assert!(
                retry
                    .0
                    .as_deref()
                    .context("retry has Authorization")?
                    .starts_with("Negotiate ")
            );
            assert_eq!(retry.1.as_slice(), b"payload-2");
            Ok(())
        })
    }

    /// Pins that the async wrapper returns an unchallenged first response without negotiating.
    #[cfg(feature = "tokio")]
    #[test]
    fn negotiate_http_client_returns_first_response_without_challenge() -> Result<(), TestError> {
        runtime()?.block_on(async {
            let mut client = NegotiateClient::with_password(
                Config::new(),
                Principal::user("TEST.GOKRB5", "testuser1"),
                b"unused".to_vec(),
            );
            let make_calls = Cell::new(0_usize);
            let send_calls = Cell::new(0_usize);

            let result = krb_http::send_with_negotiate(
                &mut client,
                Principal::new("TEST.GOKRB5", 1, ["HTTP", "host.test.gokrb5"]),
                || {
                    make_calls.set(make_calls.get() + 1);
                    Request::new(())
                },
                |request| {
                    assert!(
                        krb_http::authorization_header(&request).is_err(),
                        "unchallenged request should not be preauthenticated"
                    );
                    send_calls.set(send_calls.get() + 1);
                    ready(Ok::<_, Infallible>(Response::new("public")))
                },
            )
            .await
            .context("send succeeds")?;

            assert!(!result.did_negotiate());
            assert!(result.context().is_none());
            assert!(result.negotiation().is_none());
            assert_eq!(*result.response().body(), "public");
            assert_eq!(make_calls.get(), 1);
            assert_eq!(send_calls.get(), 1);
            Ok(())
        })
    }

    /// Pins that the blocking wrapper returns an unchallenged first response without negotiating.
    #[cfg(feature = "tokio")]
    #[test]
    fn blocking_negotiate_http_client_returns_first_response_without_challenge()
    -> Result<(), TestError> {
        let mut client = BlockingNegotiateClient::with_password(
            Config::new(),
            Principal::user("TEST.GOKRB5", "testuser1"),
            b"unused".to_vec(),
        )
        .context("blocking client builds")?;
        let make_calls = Cell::new(0_usize);
        let send_calls = Cell::new(0_usize);

        let result = krb_http::send_with_blocking_negotiate(
            &mut client,
            Principal::new("TEST.GOKRB5", 1, ["HTTP", "host.test.gokrb5"]),
            || {
                make_calls.set(make_calls.get() + 1);
                Request::new(())
            },
            |request| {
                assert!(
                    krb_http::authorization_header(&request).is_err(),
                    "unchallenged request should not be preauthenticated"
                );
                send_calls.set(send_calls.get() + 1);
                Ok::<_, Infallible>(Response::new("public"))
            },
        )
        .context("send succeeds")?;

        assert!(!result.did_negotiate());
        assert!(result.context().is_none());
        assert!(result.negotiation().is_none());
        assert_eq!(*result.response().body(), "public");
        assert_eq!(make_calls.get(), 1);
        assert_eq!(send_calls.get(), 1);
        Ok(())
    }

    /// Pins that AP-REP verification reads the Negotiate `WWW-Authenticate` header.
    #[test]
    fn verify_ap_rep_response_uses_negotiate_www_authenticate_header() -> Result<(), TestError> {
        let context = initiator_context()?;
        let response_header = ap_rep_response_header(&context)?;
        let mut response = Response::new(());
        let _: bool = response.headers_mut().append(
            WWW_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=\"test\""),
        );
        let _: bool = response.headers_mut().append(
            WWW_AUTHENTICATE,
            HeaderValue::from_str(&response_header).context("AP-REP header value")?,
        );

        let verified =
            krb_http::verify_ap_rep_response(&context, &response).context("AP-REP verifies")?;

        assert_eq!(verified.ctime(), context.authenticator_ctime());
        assert_eq!(verified.cusec(), context.authenticator_cusec());
        assert_eq!(verified.authenticator_time(), context.authenticator_time());
        Ok(())
    }

    /// Pins how the client classifies accepted, rejected, AP-REP and invalid responses.
    #[test]
    fn classify_negotiate_response_reports_client_state() -> Result<(), TestError> {
        let context = initiator_context()?;
        assert_eq!(
            krb_http::classify_negotiate_response(&context, &Response::new(())),
            krb_http::ClientNegotiateResponse::NoAuthenticateHeader
        );

        let mut basic = Response::new(());
        let _: bool = basic.headers_mut().append(
            WWW_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=\"test\""),
        );
        assert_eq!(
            krb_http::classify_negotiate_response(&context, &basic),
            krb_http::ClientNegotiateResponse::NoNegotiateChallenge
        );

        assert_eq!(
            krb_http::classify_negotiate_response(&context, &krb_http::challenge_response::<()>()),
            krb_http::ClientNegotiateResponse::Challenge
        );

        let mut later_challenge = Response::new(());
        let _: bool = later_challenge.headers_mut().append(
            WWW_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=\"test\""),
        );
        let _: bool = later_challenge
            .headers_mut()
            .append(WWW_AUTHENTICATE, HeaderValue::from_static("Negotiate"));
        assert_eq!(
            krb_http::classify_negotiate_response(&context, &later_challenge),
            krb_http::ClientNegotiateResponse::Challenge
        );

        let accepted_without_ap_rep = response_with_www_authenticate(
            &spnego::accept_completed_header().context("accept-completed header")?,
        )?;
        assert_eq!(
            krb_http::classify_negotiate_response(&context, &accepted_without_ap_rep),
            krb_http::ClientNegotiateResponse::Accepted { ap_rep: None }
        );

        let rejected =
            response_with_www_authenticate(&spnego::reject_header().context("reject header")?)?;
        assert_eq!(
            krb_http::classify_negotiate_response(&context, &rejected),
            krb_http::ClientNegotiateResponse::Rejected
        );

        let ap_rep = response_with_www_authenticate(&ap_rep_response_header(&context)?)?;
        let classified = krb_http::classify_negotiate_response(&context, &ap_rep);
        let krb_http::ClientNegotiateResponse::Accepted {
            ap_rep: Some(verified),
        } = classified
        else {
            return Err(format!("expected verified AP-REP, got {classified:?}").into());
        };
        assert_eq!(verified.ctime(), context.authenticator_ctime());
        assert_eq!(verified.cusec(), context.authenticator_cusec());

        let malformed = response_with_www_authenticate("Negotiate not-base64")?;
        assert!(matches!(
            krb_http::classify_negotiate_response(&context, &malformed),
            krb_http::ClientNegotiateResponse::InvalidToken { message: _ }
        ));

        let wrong_mechanism = response_with_www_authenticate(&valid_authorization_header()?)?;
        assert!(matches!(
            krb_http::classify_negotiate_response(&context, &wrong_mechanism),
            krb_http::ClientNegotiateResponse::InvalidToken { message: _ }
        ));
        Ok(())
    }

    /// Pins that AP-REP verification rejects a malformed token and a token of the wrong kind.
    #[test]
    fn verify_ap_rep_response_rejects_malformed_and_wrong_tokens() -> Result<(), TestError> {
        let context = initiator_context()?;
        let mut malformed = Response::new(());
        let _: bool = malformed.headers_mut().append(
            WWW_AUTHENTICATE,
            HeaderValue::from_static("Negotiate not-base64"),
        );
        assert!(
            krb_http::verify_ap_rep_response(&context, &malformed)
                .err()
                .is_some()
        );

        let mut wrong_mechanism = Response::new(());
        let _: bool = wrong_mechanism.headers_mut().append(
            WWW_AUTHENTICATE,
            HeaderValue::from_str(&valid_authorization_header()?)
                .context("SPNEGO init header value")?,
        );
        assert!(
            krb_http::verify_ap_rep_response(&context, &wrong_mechanism)
                .err()
                .is_some()
        );

        Ok(())
    }

    /// Pins that the Tower layer answers a request without credentials with a 401 challenge.
    #[cfg(feature = "tower")]
    #[test]
    fn tower_layer_challenges_missing_authorization() -> Result<(), TestError> {
        let keytab = keytab()?;
        let mut service = krb_http::NegotiateLayer::new(&keytab).layer(PanicService);

        let response = run_ready(service.call(Request::new(())))?.context("challenge response")?;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response
                .headers()
                .get(WWW_AUTHENTICATE)
                .context("challenge header exists")?
                .to_str()
                .context("challenge header is a string")?,
            "Negotiate"
        );
        Ok(())
    }

    /// Pins that the Tower layer validates the request and adds the AP-REP response header.
    #[cfg(feature = "tower")]
    #[test]
    fn tower_layer_validates_request_and_adds_ap_rep_response_header() -> Result<(), TestError> {
        let keytab = keytab()?;
        let mut service = krb_http::NegotiateLayer::new(&keytab)
            .with_now(timestamp(1_893_553_447)?)
            .layer(AssertAcceptedService);
        let mut request = Request::new(());
        krb_http::set_authorization_header(&mut request, &valid_authorization_header()?)
            .context("authorization header sets")?;

        let response = run_ready(service.call(request))?.context("inner response succeeds")?;

        assert_eq!(response.status(), StatusCode::OK);
        let ap_rep_header = response
            .headers()
            .get(WWW_AUTHENTICATE)
            .context("AP-REP response header exists")?
            .to_str()
            .context("AP-REP header is a string")?;
        assert!(matches!(
            spnego::parse_negotiate_header(ap_rep_header).context("AP-REP header parses")?,
            Token::Resp(_)
        ));
        Ok(())
    }

    /// Pins that the Tower layer forwards an authenticated request body unchanged.
    #[cfg(feature = "tower")]
    #[test]
    fn tower_layer_forwards_authenticated_post_body() -> Result<(), TestError> {
        let keytab = keytab()?;
        let payload = b"authenticated upload payload".to_vec();
        let mut service = krb_http::NegotiateLayer::new(&keytab)
            .with_now(timestamp(1_893_553_447)?)
            .layer(AssertBodyService {
                expected: payload.clone(),
            });
        let mut request = Request::builder()
            .method("POST")
            .uri("/upload")
            .body(payload)
            .context("request builds")?;
        krb_http::set_authorization_header(&mut request, &valid_authorization_header()?)
            .context("authorization header sets")?;

        let response = run_ready(service.call(request))?.context("inner response succeeds")?;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(*response.body(), b"authenticated upload payload".len());
        Ok(())
    }

    /// Pins that the Tower layer loads its keytab from an owned keytab name.
    #[cfg(feature = "tower")]
    #[test]
    fn tower_layer_loads_owned_keytab_name() -> Result<(), TestError> {
        let path = temp_file("http-keytab-name")?;
        let name = format!("FILE:{}", path.display());
        keytab()?.save(&path).context("keytab saves")?;

        let layer = krb_http::NegotiateLayer::from_keytab_name(&name)
            .context("layer loads keytab name")?
            .with_now(timestamp(1_893_553_447)?)
            .with_ap_rep(false);
        fs::remove_file(&path).context("temporary keytab is removed")?;

        let mut service = layer.layer(AssertAcceptedService);
        let mut request = Request::new(());
        krb_http::set_authorization_header(&mut request, &valid_authorization_header()?)
            .context("authorization header sets")?;

        let response = run_ready(service.call(request))?.context("inner response succeeds")?;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response.headers().get(WWW_AUTHENTICATE).is_none(),
            "AP-REP header is disabled"
        );
        Ok(())
    }

    /// Pins that `NegotiateService::from_keytab_env` loads the `KRB5_KTNAME` keytab.
    #[cfg(feature = "tower")]
    #[test]
    fn tower_service_loads_keytab_env() -> Result<(), TestError> {
        const TEST_PATH: &str = "tests::tower_service_loads_keytab_env";
        if !env::in_child(TEST_PATH) {
            let path = temp_file("http-keytab-env")?;
            let name = format!("FILE:{}", path.display());
            env::run_in_child(TEST_PATH, &[("KRB5_KTNAME", Some(name.as_ref()))]);
            return Ok(());
        }
        let name = var("KRB5_KTNAME")
            .map_err(|cause| format!("the parent test sets KRB5_KTNAME: {cause}"))?;
        let path = PathBuf::from(
            name.strip_prefix("FILE:")
                .ok_or("KRB5_KTNAME names a FILE: path")?,
        );
        keytab()?
            .save(&path)
            .map_err(|cause| format!("keytab saves: {cause}"))?;

        let mut service = krb_http::NegotiateService::from_keytab_env(AssertAcceptedService)
            .map_err(|cause| format!("service loads keytab env: {cause}"))?
            .with_now(timestamp(1_893_553_447)?)
            .with_ap_rep(false);
        fs::remove_file(&path).context("temporary keytab is removed")?;
        let mut request = Request::new(());
        krb_http::set_authorization_header(&mut request, &valid_authorization_header()?)
            .map_err(|cause| format!("authorization header sets: {cause}"))?;

        let response = run_ready(service.call(request))?
            .map_err(|cause| format!("inner response succeeds: {cause}"))?;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response.headers().get(WWW_AUTHENTICATE).is_none(),
            "AP-REP header is disabled"
        );
        Ok(())
    }

    /// Pins that `NegotiateLayer::from_keytab_env` loads the `KRB5_KTNAME` keytab.
    #[cfg(feature = "tower")]
    #[test]
    fn tower_layer_loads_keytab_env() -> Result<(), TestError> {
        const TEST_PATH: &str = "tests::tower_layer_loads_keytab_env";
        if !env::in_child(TEST_PATH) {
            let path = temp_file("http-layer-keytab-env")?;
            let name = format!("FILE:{}", path.display());
            env::run_in_child(TEST_PATH, &[("KRB5_KTNAME", Some(name.as_ref()))]);
            return Ok(());
        }
        let name = var("KRB5_KTNAME")
            .map_err(|cause| format!("the parent test sets KRB5_KTNAME: {cause}"))?;
        let path = PathBuf::from(
            name.strip_prefix("FILE:")
                .ok_or("KRB5_KTNAME names a FILE: path")?,
        );
        keytab()?
            .save(&path)
            .map_err(|cause| format!("keytab saves: {cause}"))?;

        let layer = krb_http::NegotiateLayer::from_keytab_env()
            .map_err(|cause| format!("layer loads keytab env: {cause}"))?
            .with_now(timestamp(1_893_553_447)?)
            .with_ap_rep(false);
        fs::remove_file(&path).context("temporary keytab is removed")?;
        let mut service = layer.layer(AssertAcceptedService);
        let mut request = Request::new(());
        krb_http::set_authorization_header(&mut request, &valid_authorization_header()?)
            .map_err(|cause| format!("authorization header sets: {cause}"))?;

        let response = run_ready(service.call(request))?
            .map_err(|cause| format!("inner response succeeds: {cause}"))?;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response.headers().get(WWW_AUTHENTICATE).is_none(),
            "AP-REP header is disabled"
        );
        Ok(())
    }

    /// Pins that the Tower layer loads the config default keytab name.
    #[cfg(feature = "tower")]
    #[test]
    fn tower_layer_loads_config_default_keytab_name() -> Result<(), TestError> {
        let path = temp_file("http-default-keytab-name")?;
        let name = format!("FILE:{}", path.display());
        keytab()?.save(&path).context("keytab saves")?;
        let config = config_with_default_keytab_name(&name)?;

        let layer = krb_http::NegotiateLayer::from_default_keytab_name(&config)
            .context("layer loads default keytab name")?
            .with_now(timestamp(1_893_553_447)?)
            .with_ap_rep(false);
        fs::remove_file(&path).context("temporary keytab is removed")?;

        let mut service = layer.layer(AssertAcceptedService);
        let mut request = Request::new(());
        krb_http::set_authorization_header(&mut request, &valid_authorization_header()?)
            .context("authorization header sets")?;

        let response = run_ready(service.call(request))?.context("inner response succeeds")?;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response.headers().get(WWW_AUTHENTICATE).is_none(),
            "AP-REP header is disabled"
        );
        Ok(())
    }

    /// Pins that the layer falls back to the config default keytab without `KRB5_KTNAME`.
    #[cfg(feature = "tower")]
    #[test]
    fn tower_layer_loads_default_keytab_when_env_is_absent() -> Result<(), TestError> {
        const TEST_PATH: &str = "tests::tower_layer_loads_default_keytab_when_env_is_absent";
        if !env::in_child(TEST_PATH) {
            env::run_in_child(TEST_PATH, &[("KRB5_KTNAME", None)]);
            return Ok(());
        }
        let path = temp_file("http-default-keytab-env-fallback")?;
        let name = format!("FILE:{}", path.display());
        keytab()?
            .save(&path)
            .map_err(|cause| format!("keytab saves: {cause}"))?;
        let config = config_with_default_keytab_name(&name)?;

        let layer = krb_http::NegotiateLayer::from_default_keytab(&config)
            .map_err(|cause| format!("layer loads default keytab: {cause}"))?
            .with_now(timestamp(1_893_553_447)?)
            .with_ap_rep(false);
        fs::remove_file(&path).context("temporary keytab is removed")?;

        let mut service = layer.layer(AssertAcceptedService);
        let mut request = Request::new(());
        krb_http::set_authorization_header(&mut request, &valid_authorization_header()?)
            .map_err(|cause| format!("authorization header sets: {cause}"))?;

        let response = run_ready(service.call(request))?
            .map_err(|cause| format!("inner response succeeds: {cause}"))?;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response.headers().get(WWW_AUTHENTICATE).is_none(),
            "AP-REP header is disabled"
        );
        Ok(())
    }

    /// Pins that the service prefers `KRB5_KTNAME` over the config default keytab.
    #[cfg(feature = "tower")]
    #[test]
    fn tower_service_prefers_env_keytab_over_config_default() -> Result<(), TestError> {
        const TEST_PATH: &str = "tests::tower_service_prefers_env_keytab_over_config_default";
        if !env::in_child(TEST_PATH) {
            let path = temp_file("http-env-keytab-precedence")?;
            let env_name = format!("FILE:{}", path.display());
            env::run_in_child(TEST_PATH, &[("KRB5_KTNAME", Some(env_name.as_ref()))]);
            return Ok(());
        }
        let env_name = var("KRB5_KTNAME")
            .map_err(|cause| format!("the parent test sets KRB5_KTNAME: {cause}"))?;
        let path = PathBuf::from(
            env_name
                .strip_prefix("FILE:")
                .ok_or("KRB5_KTNAME names a FILE: path")?,
        );
        keytab()?
            .save(&path)
            .map_err(|cause| format!("keytab saves: {cause}"))?;
        let missing_config_name = format!(
            "FILE:{}",
            temp_file("missing-http-config-default")?.display()
        );
        let config = config_with_default_keytab_name(&missing_config_name)?;
        let mut service =
            krb_http::NegotiateService::from_default_keytab(AssertAcceptedService, &config)
                .map_err(|cause| {
                    format!("service loads env keytab before config default: {cause}")
                })?
                .with_now(timestamp(1_893_553_447)?)
                .with_ap_rep(false);
        fs::remove_file(&path).context("temporary keytab is removed")?;
        let mut request = Request::new(());
        krb_http::set_authorization_header(&mut request, &valid_authorization_header()?)
            .map_err(|cause| format!("authorization header sets: {cause}"))?;

        let response = run_ready(service.call(request))?
            .map_err(|cause| format!("inner response succeeds: {cause}"))?;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response.headers().get(WWW_AUTHENTICATE).is_none(),
            "AP-REP header is disabled"
        );
        Ok(())
    }

    /// Pins that the Tower layer rejects a replayed request.
    #[cfg(feature = "tower")]
    #[test]
    fn tower_layer_rejects_replayed_request() -> Result<(), TestError> {
        let keytab = keytab()?;
        let mut service = krb_http::NegotiateLayer::new(&keytab)
            .with_now(timestamp(1_893_553_447)?)
            .layer(AssertAcceptedService);
        let header = valid_authorization_header()?;
        let mut first = Request::new(());
        krb_http::set_authorization_header(&mut first, &header)
            .context("authorization header sets")?;
        let mut replay = Request::new(());
        krb_http::set_authorization_header(&mut replay, &header)
            .context("authorization header sets")?;

        let first_response = run_ready(service.call(first))?.context("first response succeeds")?;
        let replay_response =
            run_ready(service.call(replay))?.context("replay returns reject response")?;

        assert_eq!(first_response.status(), StatusCode::OK);
        assert_eq!(replay_response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            replay_response
                .headers()
                .get(WWW_AUTHENTICATE)
                .context("reject header exists")?
                .to_str()
                .context("reject header is a string")?,
            spnego::reject_header().context("reject header encodes")?
        );
        Ok(())
    }

    /// Pins that Tower services sharing a replay cache reject each other's replays.
    #[cfg(feature = "tower")]
    #[test]
    fn tower_layer_rejects_replay_across_services() -> Result<(), TestError> {
        let keytab = keytab()?;
        let layer = krb_http::NegotiateLayer::new(&keytab)
            .with_now(timestamp(1_893_553_447)?)
            .with_ap_rep(false);
        let mut first_service = layer.clone().layer(AssertAcceptedService);
        let mut second_service = layer.layer(AssertAcceptedService);
        let header = valid_authorization_header()?;
        let mut first = Request::new(());
        krb_http::set_authorization_header(&mut first, &header)
            .context("authorization header sets")?;
        let mut replay = Request::new(());
        krb_http::set_authorization_header(&mut replay, &header)
            .context("authorization header sets")?;

        let first_response =
            run_ready(first_service.call(first))?.context("first response succeeds")?;
        let replay_response =
            run_ready(second_service.call(replay))?.context("replay returns reject response")?;

        assert_eq!(first_response.status(), StatusCode::OK);
        assert_eq!(replay_response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            replay_response
                .headers()
                .get(WWW_AUTHENTICATE)
                .context("reject header exists")?
                .to_str()
                .context("reject header is a string")?,
            spnego::reject_header().context("reject header encodes")?
        );
        Ok(())
    }

    /// Explicit cache sharing rejects cross-request replays across independent layer constructions.
    #[cfg(feature = "tower")]
    #[test]
    fn replay_scope_independent_layers_share_explicit_cache() -> Result<(), TestError> {
        let keytab = keytab()?;
        let cache = SharedReplayCache::new();
        let mut first_service = krb_http::NegotiateLayer::new(&keytab)
            .with_now(timestamp(1_893_553_447)?)
            .with_shared_replay_cache(cache.clone())?
            .with_ap_rep(false)
            .layer(AssertAcceptedService);
        let mut second_service = krb_http::NegotiateLayer::new(&keytab)
            .with_now(timestamp(1_893_553_447)?)
            .with_shared_replay_cache(cache)?
            .with_ap_rep(false)
            .layer(AssertAcceptedService);
        let header = valid_authorization_header()?;
        let mut first = Request::new(());
        *first.uri_mut() = "/account".parse()?;
        krb_http::set_authorization_header(&mut first, &header)?;
        let mut replay = Request::new(());
        *replay.method_mut() = Method::POST;
        *replay.uri_mut() = "/transfer".parse()?;
        krb_http::set_authorization_header(&mut replay, &header)?;
        assert_eq!(
            run_ready(first_service.call(first))??.status(),
            StatusCode::OK
        );
        assert_eq!(
            run_ready(second_service.call(replay))??.status(),
            StatusCode::UNAUTHORIZED
        );
        Ok(())
    }

    /// Independent default caches each accept a first presentation, documenting the topology limit.
    #[cfg(feature = "tower")]
    #[test]
    fn replay_scope_independent_caches_do_not_coordinate() -> Result<(), TestError> {
        let keytab = keytab()?;
        let header = valid_authorization_header()?;
        for path in ["/account", "/transfer"] {
            let mut service = krb_http::NegotiateLayer::new(&keytab)
                .with_now(timestamp(1_893_553_447)?)
                .with_ap_rep(false)
                .layer(AssertAcceptedService);
            let mut request = Request::new(());
            *request.uri_mut() = path.parse()?;
            krb_http::set_authorization_header(&mut request, &header)?;
            assert_eq!(run_ready(service.call(request))??.status(), StatusCode::OK);
        }
        Ok(())
    }

    /// Challenge and reject response bodies contain no internal parser or validation detail.
    #[test]
    fn rejection_helpers_have_opaque_bodies() -> Result<(), TestError> {
        let challenge: Response<String> = krb_http::challenge_response();
        let reject: Response<String> = krb_http::reject_response()?;
        assert_eq!(challenge.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(reject.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(challenge.body(), "");
        assert_eq!(reject.body(), "");
        Ok(())
    }

    fn valid_authorization_header() -> Result<String, TestError> {
        let ap_req_token = Krb5MechToken::ap_req(gss_ap_req_fixture()?)
            .encode()
            .context("KRB5 AP-REQ token encodes")?;
        let spnego_token = Token::Init(NegTokenInit::krb5(ap_req_token));
        spnego::negotiate_header(&spnego_token).context("Negotiate header encodes")
    }

    fn raw_krb5_authorization_header() -> Result<String, TestError> {
        let ap_req_token = Krb5MechToken::ap_req(gss_ap_req_fixture()?)
            .encode()
            .context("KRB5 AP-REQ token encodes")?;
        Ok(format!("Negotiate {}", base64_encode(&ap_req_token)))
    }

    fn gss_ap_req_fixture() -> Result<Vec<u8>, TestError> {
        let original = ap_req::decode(&decode_hex(VALID_AP_REQ)?)?;
        let key = service_ticket_session_from_valid_ap_req()?
            .session_key()
            .clone();
        let mut authenticator = ap_req::decrypt_ap_req_authenticator(&original, &key, 11)?;
        authenticator.cksum = Some(rasn_kerberos::Checksum {
            r#type: 0x8003,
            checksum: spnego::authenticator_checksum(&[]).into(),
        });
        authenticator.seq_number = Some(42);
        let message = ap_req::build_ap_req_with_confounder(
            original.ticket,
            original.ap_options,
            &authenticator,
            &key,
            11,
            original.authenticator.kvno,
            &decode_hex(AP_REP_CONFOUNDER)?,
        )?;
        Ok(ap_req::encode(&message)?)
    }

    fn initiator_context() -> Result<spnego::InitiatorContext, TestError> {
        initiator_context_with_options(
            InitiatorContextOptions::new().with_sequence_number(Some(42)),
        )
    }

    /// Builds the fixture initiator context with `options`.
    fn initiator_context_with_options(
        options: InitiatorContextOptions,
    ) -> Result<spnego::InitiatorContext, TestError> {
        spnego::init_sec_context_with_confounder(
            &service_ticket_session_from_valid_ap_req()?,
            options,
            timestamp(1_893_553_447)?,
            123_456,
            &decode_hex(AP_REP_CONFOUNDER)?,
        )
        .context("client SPNEGO context builds")
    }

    fn ap_rep_response_header(context: &spnego::InitiatorContext) -> Result<String, TestError> {
        let keytab = keytab()?;
        let mut validator = Validator::new(&keytab).with_now(timestamp(1_893_553_447)?);
        let accepted = spnego::accept_sec_context_header(&mut validator, context.header_ref())
            .context("client SPNEGO header validates")?;
        accepted
            .ap_rep_response_header_with_confounder(
                &decode_hex(AP_REP_CONFOUNDER)?,
                &ApRepOptions::default(),
            )
            .context("AP-REP response header builds")
    }

    fn service_ticket_session_from_valid_ap_req() -> Result<AsRepSession, TestError> {
        let ap_req: rasn_kerberos::ApReq =
            der::decode(&decode_hex(VALID_AP_REQ)?).context("AP-REQ fixture decodes")?;
        Ok(AsRepSession::new(
            Principal::user("TEST.GOKRB5", "testuser1"),
            Principal::new("TEST.GOKRB5", 1, ["HTTP", "host.test.gokrb5"]),
            EncryptionKey::new(18, decode_hex(VALID_SESSION_KEY)?),
            der::encode(&ap_req.ticket)
                .context("ticket encodes")?
                .into(),
            [0; 4],
            timestamp(1_893_553_445)?,
            timestamp(1_893_639_845)?,
        )
        .with_start_time(timestamp(1_893_553_445)?)
        .with_renew_till(None)
        .with_key_expiration(None))
    }

    /// Returns an empty response that carries `header` as its `WWW-Authenticate` value.
    fn response_with_www_authenticate(header: &str) -> Result<Response<()>, TestError> {
        Ok(response_with_www_authenticate_body(
            www_authenticate(header)?,
            (),
        ))
    }

    /// Parses `header` as a `WWW-Authenticate` header value.
    fn www_authenticate(header: &str) -> Result<HeaderValue, TestError> {
        HeaderValue::from_str(header).context("WWW-Authenticate header value")
    }

    /// Returns a response with `body` that carries `value` as its `WWW-Authenticate` header.
    fn response_with_www_authenticate_body<B>(value: HeaderValue, body: B) -> Response<B> {
        let mut response = Response::new(());
        let _: bool = response.headers_mut().append(WWW_AUTHENTICATE, value);
        response.map(|()| body)
    }

    #[cfg(feature = "tokio")]
    fn current_service_ticket_session() -> Result<AsRepSession, TestError> {
        let mut service_ticket = service_ticket_session_from_valid_ap_req()?;
        let now = SystemTime::now();
        let earlier = now
            .checked_sub(Duration::from_secs(1))
            .context("one second ago is representable")?;
        service_ticket.set_auth_time(earlier);
        service_ticket.set_start_time(earlier);
        service_ticket.set_end_time(
            now.checked_add(Duration::from_mins(1))
                .context("one minute ahead is representable")?,
        );
        Ok(service_ticket)
    }

    fn keytab() -> Result<Keytab, TestError> {
        Keytab::parse(&decode_hex(HTTP_KEYTAB)?).context("HTTP keytab parses")
    }

    #[cfg(feature = "tower")]
    fn config_with_default_keytab_name(keytab_name: &str) -> Result<Config, TestError> {
        let input = format!(
            "
[libdefaults]
 default_keytab_name = {keytab_name}
",
        );
        Config::parse(&input).context("config parses")
    }

    /// Encodes bytes as standard padded base64.
    fn base64_encode(bytes: &[u8]) -> String {
        STANDARD.encode(bytes)
    }

    /// Returns the instant `seconds` after the Unix epoch.
    fn timestamp(seconds: u64) -> Result<SystemTime, TestError> {
        UNIX_EPOCH
            .checked_add(Duration::from_secs(seconds))
            .context("timestamp is representable")
    }

    #[cfg(feature = "tokio")]
    fn runtime() -> Result<Runtime, TestError> {
        Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .context("runtime")
    }

    #[cfg(feature = "tower")]
    fn temp_file(label: &str) -> Result<PathBuf, TestError> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system time after epoch")?
            .as_nanos();
        Ok(temp_dir().join(format!("rskrb5-{label}-{nanos}.keytab")))
    }

    #[cfg(feature = "tower")]
    struct PanicService;

    #[cfg(feature = "tower")]
    impl Service<Request<()>> for PanicService {
        type Response = Response<()>;
        type Error = TestError;
        type Future = Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: Request<()>) -> Self::Future {
            ready(Err(
                "inner service must not be called without credentials".into()
            ))
        }
    }

    #[cfg(feature = "tower")]
    struct AssertAcceptedService;

    #[cfg(feature = "tower")]
    impl Service<Request<()>> for AssertAcceptedService {
        type Response = Response<()>;
        type Error = TestError;
        type Future = Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: Request<()>) -> Self::Future {
            let Some(accepted) = req.extensions().get::<AcceptedContext>() else {
                return ready(Err("accepted context exists".into()));
            };
            assert_eq!(accepted.ap_req.client().name(), "testuser1");
            assert_eq!(accepted.ap_req.service().name(), "HTTP/host.test.gokrb5");
            ready(Ok(Response::new(())))
        }
    }

    #[cfg(feature = "tower")]
    struct AssertBodyService {
        expected: Vec<u8>,
    }

    #[cfg(feature = "tower")]
    impl Service<Request<Vec<u8>>> for AssertBodyService {
        type Response = Response<usize>;
        type Error = TestError;
        type Future = Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: Request<Vec<u8>>) -> Self::Future {
            let Some(accepted) = req.extensions().get::<AcceptedContext>() else {
                return ready(Err("accepted context exists".into()));
            };
            assert_eq!(accepted.ap_req.client().name(), "testuser1");
            assert_eq!(accepted.ap_req.service().name(), "HTTP/host.test.gokrb5");
            assert_eq!(req.method().as_str(), "POST");
            assert_eq!(req.uri().path(), "/upload");
            assert_eq!(req.body(), &self.expected);
            ready(Ok(Response::new(req.body().len())))
        }
    }

    #[cfg(feature = "tower")]
    /// Polls `future` once and returns its output.
    fn run_ready<F>(future: F) -> Result<F::Output, TestError>
    where
        F: Future,
    {
        let mut cx = Context::from_waker(Waker::noop());
        let mut pinned = pin!(future);
        match pinned.as_mut().poll(&mut cx) {
            Poll::Ready(output) => Ok(output),
            Poll::Pending => Err("test future unexpectedly pending".into()),
        }
    }

    /// Result of [`send_mutual_negotiate`].
    #[cfg(feature = "tokio")]
    type MutualSendResult = Result<
        krb_http::NegotiateHttpResponse<Vec<u8>>,
        krb_http::NegotiateHttpError<Infallible, Vec<u8>>,
    >;

    /// Pins that an AP-option mutual request classifies a completion without an AP-REP as a failure.
    #[cfg(feature = "tokio")]
    #[test]
    fn negotiate_http_client_classifies_missing_ap_rep_as_failure_when_mutual_requested()
    -> Result<(), TestError> {
        let accept_completed = www_authenticate(
            &spnego::accept_completed_header()
                .map_err(|cause| format!("accept-completed header: {cause}"))?,
        )?;
        let (result, calls) = send_mutual_negotiate(
            InitiatorContextOptions::new().with_ap_option_bits(0x2000_0000),
            |_retry| response_with_www_authenticate_body(accept_completed.clone(), b"ok".to_vec()),
        )?;

        let Err(krb_http::NegotiateHttpError::MutualAuthenticationNotProven {
            negotiation,
            response,
        }) = result
        else {
            return Err(format!("expected MutualAuthenticationNotProven, got {result:?}").into());
        };
        assert!(matches!(
            negotiation,
            Some(krb_http::ClientNegotiateResponse::InvalidToken { message: _ })
        ));
        assert_eq!(response.body().as_slice(), b"ok");
        assert_eq!(calls, 2);
        Ok(())
    }

    /// Pins that a mutual request fails closed on a final response without `WWW-Authenticate`.
    #[cfg(feature = "tokio")]
    #[test]
    fn mutual_wrapper_rejects_final_response_without_www_authenticate() -> Result<(), TestError> {
        let (result, calls) = send_mutual_negotiate(mutual_context_flag_options(), |_retry| {
            Response::new(b"ok".to_vec())
        })?;

        let Err(krb_http::NegotiateHttpError::MutualAuthenticationNotProven {
            negotiation,
            response,
        }) = result
        else {
            return Err(format!("expected MutualAuthenticationNotProven, got {result:?}").into());
        };
        assert_eq!(
            negotiation,
            Some(krb_http::ClientNegotiateResponse::NoAuthenticateHeader)
        );
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.body().as_slice(), b"ok");
        assert_eq!(calls, 2);
        Ok(())
    }

    /// Pins that a mutual request fails closed on a final non-Negotiate challenge.
    #[cfg(feature = "tokio")]
    #[test]
    fn mutual_wrapper_rejects_a_non_negotiate_challenge() -> Result<(), TestError> {
        let (result, calls) = send_mutual_negotiate(
            InitiatorContextOptions::new().with_ap_option_bits(0x2000_0000),
            |_retry| {
                response_with_www_authenticate_body(
                    HeaderValue::from_static("Basic realm=\"test\""),
                    b"ok".to_vec(),
                )
            },
        )?;

        let Err(krb_http::NegotiateHttpError::MutualAuthenticationNotProven {
            negotiation,
            response,
        }) = result
        else {
            return Err(format!("expected MutualAuthenticationNotProven, got {result:?}").into());
        };
        assert_eq!(
            negotiation,
            Some(krb_http::ClientNegotiateResponse::NoNegotiateChallenge)
        );
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(calls, 2);
        Ok(())
    }

    /// Pins that a mutual request fails closed when the first response is never challenged.
    #[cfg(feature = "tokio")]
    #[test]
    fn mutual_wrapper_rejects_unchallenged_first_response() -> Result<(), TestError> {
        runtime()?.block_on(async {
            let mut client = negotiate_client_with_cached_service_ticket()?;
            let send_calls = Cell::new(0_usize);

            let result = krb_http::send_with_negotiate_options(
                &mut client,
                Principal::new("TEST.GOKRB5", 1, ["HTTP", "host.test.gokrb5"]),
                mutual_context_flag_options(),
                || Request::new(()),
                |_request| {
                    send_calls.set(send_calls.get().saturating_add(1));
                    ready(Ok::<_, Infallible>(Response::new("public")))
                },
            )
            .await;

            let Err(krb_http::NegotiateHttpError::MutualAuthenticationNotProven {
                negotiation,
                response,
            }) = result
            else {
                return Err(
                    format!("expected MutualAuthenticationNotProven, got {result:?}").into(),
                );
            };
            assert_eq!(negotiation, None);
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(*response.body(), "public");
            assert_eq!(send_calls.get(), 1);
            Ok(())
        })
    }

    /// Pins that a mutual request accepts a verified AP-REP that matches the authenticator.
    #[cfg(feature = "tokio")]
    #[test]
    fn mutual_wrapper_accepts_a_verified_ap_rep() -> Result<(), TestError> {
        let (result, calls) = send_mutual_negotiate(
            InitiatorContextOptions::new().with_ap_option_bits(0x2000_0000),
            |retry| {
                let built = krb_http::authorization_header(retry)
                    .map_err(|cause| {
                        TestError::from(format!("retry carries Authorization: {cause}"))
                    })
                    .and_then(ap_rep_response_header_for_live_authorization)
                    .and_then(|header| www_authenticate(&header));
                match built {
                    Ok(header) => response_with_www_authenticate_body(header, b"ok".to_vec()),
                    Err(cause) => Response::new(format!("no AP-REP header: {cause}").into_bytes()),
                }
            },
        )?;

        let negotiated = result
            .map_err(|cause| format!("verified AP-REP proves mutual authentication: {cause}"))?;
        let context = negotiated.context().ok_or("context is retained")?;
        let Some(krb_http::ClientNegotiateResponse::Accepted {
            ap_rep: Some(verified),
        }) = negotiated.negotiation()
        else {
            return Err(format!(
                "expected verified AP-REP, got {:?}",
                negotiated.negotiation()
            )
            .into());
        };
        assert_eq!(verified.ctime(), context.authenticator_ctime());
        assert_eq!(verified.cusec(), context.authenticator_cusec());
        assert_eq!(negotiated.response().body().as_slice(), b"ok");
        assert_eq!(calls, 2);
        Ok(())
    }

    /// Pins that the default async and blocking wrappers still accept a completion without an AP-REP.
    #[cfg(feature = "tokio")]
    #[test]
    fn default_wrapper_still_accepts_a_missing_ap_rep() -> Result<(), TestError> {
        let accept_header = www_authenticate(
            &spnego::accept_completed_header()
                .map_err(|cause| format!("accept-completed header: {cause}"))?,
        )?;
        let challenge_then_accept = |call: usize| {
            if call == 1 {
                krb_http::challenge_response::<Vec<u8>>()
            } else {
                response_with_www_authenticate_body(accept_header.clone(), b"ok".to_vec())
            }
        };

        let async_calls = Cell::new(0_usize);
        let mut async_client = negotiate_client_with_cached_service_ticket()?;
        let async_result = runtime()?
            .block_on(async {
                krb_http::send_with_negotiate(
                    &mut async_client,
                    Principal::new("TEST.GOKRB5", 1, ["HTTP", "host.test.gokrb5"]),
                    || Request::new(Vec::<u8>::new()),
                    |_request| {
                        async_calls.set(async_calls.get().saturating_add(1));
                        ready(Ok::<_, Infallible>(challenge_then_accept(
                            async_calls.get(),
                        )))
                    },
                )
                .await
            })
            .map_err(|cause| {
                format!("default async wrapper accepts a completion without an AP-REP: {cause}")
            })?;
        assert_eq!(
            async_result.negotiation(),
            Some(&krb_http::ClientNegotiateResponse::Accepted { ap_rep: None })
        );
        assert_eq!(async_calls.get(), 2);

        let mut blocking_client =
            BlockingNegotiateClient::new(negotiate_client_with_cached_service_ticket()?)
                .map_err(|cause| format!("blocking client builds: {cause}"))?;
        let blocking_calls = Cell::new(0_usize);
        let blocking_result = krb_http::send_with_blocking_negotiate(
            &mut blocking_client,
            Principal::new("TEST.GOKRB5", 1, ["HTTP", "host.test.gokrb5"]),
            || Request::new(Vec::<u8>::new()),
            |_request| {
                blocking_calls.set(blocking_calls.get().saturating_add(1));
                Ok::<_, Infallible>(challenge_then_accept(blocking_calls.get()))
            },
        )
        .map_err(|cause| {
            format!("default blocking wrapper accepts a completion without an AP-REP: {cause}")
        })?;
        assert_eq!(
            blocking_result.negotiation(),
            Some(&krb_http::ClientNegotiateResponse::Accepted { ap_rep: None })
        );
        assert_eq!(blocking_calls.get(), 2);
        Ok(())
    }

    /// Pins that the blocking mutual wrapper fails closed on a completion without an AP-REP.
    #[cfg(feature = "tokio")]
    #[test]
    fn blocking_mutual_wrapper_rejects_a_missing_ap_rep() -> Result<(), TestError> {
        let accept_header = www_authenticate(
            &spnego::accept_completed_header()
                .map_err(|cause| format!("accept-completed header: {cause}"))?,
        )?;
        let mut client =
            BlockingNegotiateClient::new(negotiate_client_with_cached_service_ticket()?)
                .map_err(|cause| format!("blocking client builds: {cause}"))?;
        let calls = Cell::new(0_usize);

        let result = krb_http::send_with_blocking_negotiate_options(
            &mut client,
            Principal::new("TEST.GOKRB5", 1, ["HTTP", "host.test.gokrb5"]),
            mutual_context_flag_options(),
            || Request::new(Vec::<u8>::new()),
            |_request| {
                calls.set(calls.get().saturating_add(1));
                let response = if calls.get() == 1 {
                    krb_http::challenge_response::<Vec<u8>>()
                } else {
                    response_with_www_authenticate_body(accept_header.clone(), b"ok".to_vec())
                };
                Ok::<_, Infallible>(response)
            },
        );

        let Err(krb_http::NegotiateHttpError::MutualAuthenticationNotProven {
            negotiation,
            response,
        }) = result
        else {
            return Err(format!("expected MutualAuthenticationNotProven, got {result:?}").into());
        };
        assert!(matches!(
            negotiation,
            Some(krb_http::ClientNegotiateResponse::InvalidToken { message: _ })
        ));
        assert_eq!(response.body().as_slice(), b"ok");
        assert_eq!(calls.get(), 2);
        Ok(())
    }

    /// Pins that classification rejects a completion without an AP-REP for both mutual request forms.
    #[test]
    fn classify_rejects_missing_ap_rep_when_mutual_requested() -> Result<(), TestError> {
        let variants = [
            InitiatorContextOptions::new().with_ap_option_bits(0x2000_0000),
            InitiatorContextOptions::new().with_context_flags(vec![
                spnego::CONTEXT_FLAG_INTEG,
                spnego::CONTEXT_FLAG_MUTUAL,
            ]),
        ];
        let accept_header = www_authenticate(
            &spnego::accept_completed_header()
                .map_err(|cause| format!("accept-completed header: {cause}"))?,
        )?;
        for options in variants {
            let context = initiator_context_with_options(options.with_sequence_number(Some(42)))?;
            let response = response_with_www_authenticate_body(accept_header.clone(), ());

            assert!(
                matches!(
                    krb_http::classify_negotiate_response(&context, &response),
                    krb_http::ClientNegotiateResponse::InvalidToken { message: _ }
                ),
                "requested mutual authentication must not accept a completion without an AP-REP"
            );
        }
        Ok(())
    }

    /// Pins that the tower layer honours the config `clockskew` and rejects a stale authenticator.
    #[cfg(feature = "tower")]
    #[test]
    fn tower_layer_config_clockskew_rejects_stale_authenticator() -> Result<(), TestError> {
        let path = temp_file("http-config-clockskew")?;
        let name = format!("FILE:{}", path.display());
        keytab()?
            .save(&path)
            .map_err(|cause| format!("keytab saves: {cause}"))?;
        let config = config_with_default_keytab_name_and_clockskew(&name, "1s")?;

        let layer = krb_http::NegotiateLayer::from_default_keytab_name(&config)
            .map_err(|cause| format!("layer loads default keytab name: {cause}"))?
            .with_now(timestamp(1_893_553_447 + 2)?)
            .with_ap_rep(false);
        fs::remove_file(&path).map_err(|cause| format!("keytab file is removed: {cause}"))?;

        let mut service = layer.layer(AssertAcceptedService);
        let mut request = Request::new(());
        krb_http::set_authorization_header(&mut request, &valid_authorization_header()?)
            .map_err(|cause| format!("authorization header sets: {cause}"))?;

        let response = run_ready(service.call(request))?
            .map_err(|cause| format!("reject response returned: {cause}"))?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    /// Run the async options wrapper against a sender that challenges first and
    /// answers the authenticated retry with `final_response`.
    #[cfg(feature = "tokio")]
    fn send_mutual_negotiate(
        options: InitiatorContextOptions,
        mut final_response: impl FnMut(&Request<Vec<u8>>) -> Response<Vec<u8>>,
    ) -> Result<(MutualSendResult, usize), TestError> {
        let mut client = negotiate_client_with_cached_service_ticket()?;
        Ok(runtime()?.block_on(async {
            let calls = Cell::new(0_usize);
            let result = krb_http::send_with_negotiate_options(
                &mut client,
                Principal::new("TEST.GOKRB5", 1, ["HTTP", "host.test.gokrb5"]),
                options,
                || {
                    let mut request = Request::new(Vec::new());
                    *request.uri_mut() = Uri::from_static("/protected");
                    request
                },
                |request: Request<Vec<u8>>| {
                    calls.set(calls.get().saturating_add(1));
                    let response = if calls.get() == 1 {
                        krb_http::challenge_response::<Vec<u8>>()
                    } else {
                        final_response(&request)
                    };
                    ready(Ok::<_, Infallible>(response))
                },
            )
            .await;
            (result, calls.get())
        }))
    }

    /// Split and combined flag masks fail closed in both wrappers for every missing-proof path.
    #[cfg(feature = "tokio")]
    #[test]
    fn mutual_mask_matrix_rejects_unproven_responses() -> Result<(), TestError> {
        for flags in [
            vec![spnego::CONTEXT_FLAG_MUTUAL, spnego::CONTEXT_FLAG_INTEG],
            vec![spnego::CONTEXT_FLAG_MUTUAL | spnego::CONTEXT_FLAG_INTEG],
        ] {
            for challenged in [false, true] {
                for completed in [false, true] {
                    // Given either representation of the same wire mask.
                    let options = InitiatorContextOptions::new().with_context_flags(flags.clone());
                    let final_header = www_authenticate(&spnego::accept_completed_header()?)?;
                    let response_for = |call: usize| {
                        if challenged && call == 1 {
                            krb_http::challenge_response::<Vec<u8>>()
                        } else if completed {
                            response_with_www_authenticate_body(final_header.clone(), Vec::new())
                        } else {
                            Response::new(Vec::new())
                        }
                    };
                    let service = Principal::new("TEST.GOKRB5", 1, ["HTTP", "host.test.gokrb5"]);
                    let mut client = negotiate_client_with_cached_service_ticket()?;
                    let calls = Cell::new(0_usize);
                    // When the peer never proves its identity.
                    let result = runtime()?.block_on(krb_http::send_with_negotiate_options(
                        &mut client,
                        service.clone(),
                        options.clone(),
                        || Request::new(()),
                        |_| {
                            calls.set(calls.get().saturating_add(1));
                            ready(Ok::<_, Infallible>(response_for(calls.get())))
                        },
                    ));
                    // Then async and blocking entry points reject, not merely classify.
                    assert!(matches!(
                        result,
                        Err(
                            krb_http::NegotiateHttpError::MutualAuthenticationNotProven {
                                negotiation: _,
                                response: _
                            }
                        )
                    ));
                    let mut blocking = BlockingNegotiateClient::new(
                        negotiate_client_with_cached_service_ticket()?,
                    )?;
                    calls.set(0);
                    let blocking_result = krb_http::send_with_blocking_negotiate_options(
                        &mut blocking,
                        service,
                        options,
                        || Request::new(()),
                        |_| {
                            calls.set(calls.get().saturating_add(1));
                            Ok::<_, Infallible>(response_for(calls.get()))
                        },
                    );
                    assert!(matches!(
                        blocking_result,
                        Err(
                            krb_http::NegotiateHttpError::MutualAuthenticationNotProven {
                                negotiation: _,
                                response: _
                            }
                        )
                    ));
                }
            }
        }
        Ok(())
    }

    /// Initiator options that request mutual authentication through the context flags.
    #[cfg(feature = "tokio")]
    fn mutual_context_flag_options() -> InitiatorContextOptions {
        InitiatorContextOptions::new().with_context_flags(vec![
            spnego::CONTEXT_FLAG_INTEG,
            spnego::CONTEXT_FLAG_MUTUAL,
        ])
    }

    /// A Negotiate client whose cache already holds the fixture service ticket.
    #[cfg(feature = "tokio")]
    fn negotiate_client_with_cached_service_ticket() -> Result<NegotiateClient, TestError> {
        let mut tokio_client = Tokio::with_password(
            Config::new(),
            KdcProtocol::Auto,
            Principal::user("TEST.GOKRB5", "testuser1"),
            b"unused".to_vec(),
        );
        tokio_client
            .cache_service_ticket(current_service_ticket_session()?)
            .context("fixture service ticket matches the client identity")?;
        Ok(NegotiateClient::from_tokio_client(tokio_client))
    }

    /// Accept a wrapper-built Authorization header and answer with a genuine AP-REP.
    ///
    /// The fixture ticket is valid at `1_893_553_447` while the wrapper stamps the
    /// authenticator with the wall clock, so the validator allows a wide skew.
    #[cfg(feature = "tokio")]
    fn ap_rep_response_header_for_live_authorization(
        authorization: &str,
    ) -> Result<String, TestError> {
        let keytab = keytab()?;
        let wide_skew = Duration::from_hours(100 * 365 * 24);
        let mut validator = Validator::new(&keytab)
            .with_now(timestamp(1_893_553_447)?)
            .with_max_clock_skew(wide_skew)?
            .with_shared_replay_cache(SharedReplayCache::from_cache(ReplayCache::with_limits(
                wide_skew, 16,
            )))?;
        let accepted = spnego::accept_sec_context_header(&mut validator, authorization)
            .map_err(|cause| format!("wrapper Authorization header validates: {cause}"))?;
        Ok(accepted
            .ap_rep_response_header_with_confounder(
                &decode_hex(AP_REP_CONFOUNDER)?,
                &ApRepOptions::default(),
            )
            .map_err(|cause| format!("AP-REP response header builds: {cause}"))?)
    }

    /// A config naming `keytab_name` as the default keytab, with `clockskew`.
    #[cfg(feature = "tower")]
    fn config_with_default_keytab_name_and_clockskew(
        keytab_name: &str,
        clockskew: &str,
    ) -> Result<Config, TestError> {
        let input = format!(
            "
[libdefaults]
 default_keytab_name = {keytab_name}
 clockskew = {clockskew}
",
        );
        Ok(Config::parse(&input).map_err(|cause| format!("config parses: {cause}"))?)
    }

    /// Decodes a hex fixture.
    fn decode_hex(input: &str) -> Result<Vec<u8>, FromHexError> {
        hex::decode(input)
    }
}

use core::error::Error;
#[cfg(feature = "tower")]
use core::{
    cell::Cell,
    convert::Infallible,
    future::{Ready, ready},
    task::{Context, Poll},
};

#[cfg(feature = "tower")]
use http_types::{Request, Response};
use rskrb5_ng::{
    Config,
    crypto::CryptoPolicy,
    keytab::EncryptionKey,
    service::{ApRepOptions, Validator},
    spnego::{self, Krb5MechToken, NegTokenInit, Token},
};
#[cfg(feature = "tower")]
use tower_service::Service;

use super::{acceptor::fixture, client::policy_cause};

/// Counts protected handler entry independently of its response.
#[cfg(feature = "tower")]
struct Counted<'calls>(&'calls Cell<u32>);

#[cfg(feature = "tower")]
impl Service<Request<()>> for Counted<'_> {
    type Response = Response<()>;
    type Error = Infallible;
    type Future = Ready<Result<Self::Response, Self::Error>>;
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, _request: Request<()>) -> Self::Future {
        self.0.set(self.0.get().saturating_add(1));
        ready(Ok(Response::new(())))
    }
}

/// Accepted contexts enforce retained policy on outgoing subkeys and mutable session keys.
#[test]
fn accepted_reply_enforces_retained_policy() -> Result<(), Box<dyn Error>> {
    let (keys, bytes, now) = fixture(18, 18, None)?;
    let header = spnego::negotiate_header(&Token::Init(NegTokenInit::krb5(
        Krb5MechToken::ap_req(bytes).encode()?,
    )))?;
    for (profile, subkey_id, permitted) in [
        ("", 1_i32, false),
        ("", 16_i32, false),
        ("", 23_i32, false),
        ("permitted_enctypes = aes256-cts", 17_i32, false),
        ("allow_rc4 = true", 23_i32, false),
        ("allow_des3 = true", 16_i32, false),
        (
            "allow_rc4 = true\npermitted_enctypes = DEFAULT rc4",
            23_i32,
            true,
        ),
        (
            "allow_des3 = true\npermitted_enctypes = DEFAULT des3",
            16_i32,
            true,
        ),
        ("", 18_i32, true),
    ] {
        let config = Config::parse(&format!("[libdefaults]\n{profile}"))?;
        let mut validator = Validator::new(&keys)
            .with_now(now)
            .with_crypto_policy(CryptoPolicy::from_libdefaults(&config.libdefaults)?);
        let accepted = spnego::accept_sec_context_header(&mut validator, &header)?;
        let options = ApRepOptions::default()
            .with_subkey(Some(EncryptionKey::new(subkey_id, vec![0x42; 32])));
        let reply = accepted.ap_rep_response_header_with_confounder(&[0x22; 16], &options);
        if permitted {
            let encoded = reply?;
            drop(spnego::parse_negotiate_header(&encoded)?);
        } else {
            let error = reply.err().ok_or("forbidden reply subkey emitted")?;
            assert!(
                policy_cause(&error).is_some(),
                "typed policy refusal required"
            );
        }
    }
    let mut accepted = Validator::new(&keys)
        .with_now(now)
        .validate_ap_req(&spnego::parse_negotiate_header(&header)?.krb5_ap_req()?)?;
    accepted.session_key = EncryptionKey::new(23, vec![0x33; 16]);
    let error = accepted
        .build_ap_rep_with_confounder(&[0x22; 8], &ApRepOptions::default())
        .err()
        .ok_or("mutated session key escaped retained policy")?;
    assert!(policy_cause(&error).is_some(), "session key policy cause");
    Ok(())
}

/// A forbidden outgoing subkey fails before the protected Tower handler is called.
#[cfg(feature = "tower")]
#[test]
fn forbidden_reply_precedes_handler() -> Result<(), Box<dyn Error>> {
    use rskrb5_ng::http::NegotiateService;
    use tokio::runtime::Builder;

    let (keys, bytes, now) = fixture(18, 18, None)?;
    let header = spnego::negotiate_header(&Token::Init(NegTokenInit::krb5(
        Krb5MechToken::ap_req(bytes).encode()?,
    )))?;
    let calls = Cell::new(0_u32);
    let inner = Counted(&calls);
    let mut service = NegotiateService::new(inner, &keys)
        .with_now(now)
        .with_ap_rep_options(
            ApRepOptions::default().with_subkey(Some(EncryptionKey::new(1, vec![0x42; 8]))),
        );
    let runtime = Builder::new_current_thread().enable_all().build()?;
    let result = runtime.block_on(
        service.call(
            Request::builder()
                .header("Authorization", header)
                .body(())?,
        ),
    );
    assert_eq!(
        calls.get(),
        0,
        "protected handler ran before reply policy admission"
    );
    let error = result.err().ok_or("forbidden reply succeeded")?;
    assert!(
        policy_cause(&error).is_some(),
        "typed outgoing policy refusal"
    );
    Ok(())
}

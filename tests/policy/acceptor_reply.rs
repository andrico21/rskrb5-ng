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
    Config, ap_rep, ap_req,
    crypto::{CryptoPolicy, KerberosEtype, Use},
    error::Policy,
    keytab::EncryptionKey,
    service::{ApRepOptions, Validator},
    spnego::{self, Krb5MechToken, NegTokenInit, Token},
};
#[cfg(feature = "tower")]
use tower_service::Service;

use super::{acceptor::fixture, client::policy_cause};

/// Configured HTTP constructors preserve permanent rejections before keytab I/O.
#[cfg(feature = "tower")]
#[test]
fn http_configuration_retains_permanent_refusal() -> Result<(), Box<dyn Error>> {
    use rskrb5_ng::http::NegotiateLayer;

    let mut config = Config::parse("")?;
    config.libdefaults.permitted_enctypes = vec!["des-cbc-crc".to_owned()];
    for result in [
        NegotiateLayer::from_default_keytab_name(&config),
        NegotiateLayer::from_default_keytab(&config),
    ] {
        let error = result.err().ok_or("permanent configuration admitted")?;
        assert!(
            matches!(
                policy_cause(&error),
                Some(Policy::RejectedFeature {
                    feature: _,
                    reason: _
                })
            ),
            "HTTP helper lost permanent refusal: {error:?}"
        );
    }
    Ok(())
}

/// Random and deterministic reply helpers retain permanent policy refusals.
#[test]
fn random_reply_retains_permanent_refusal() -> Result<(), Box<dyn Error>> {
    let (keys, bytes, now) = fixture(18, 18, None)?;
    let header = spnego::negotiate_header(&Token::Init(NegTokenInit::krb5(
        Krb5MechToken::ap_req(bytes).encode()?,
    )))?;
    let mut validator = Validator::new(&keys).with_now(now);
    let mut accepted = spnego::accept_sec_context_header(&mut validator, &header)?;
    for id in [1_i32, 24_i32] {
        accepted
            .ap_req
            .set_session_key(EncryptionKey::new(id, vec![0x42; 16]));
        for reply in [
            accepted.ap_rep_response_header_with_confounder(&[0x22; 16], &ApRepOptions::default()),
            accepted.ap_rep_response_header(&ApRepOptions::default()),
        ] {
            let error = reply.err().ok_or("permanently forbidden reply emitted")?;
            assert!(
                matches!(
                    policy_cause(&error),
                    Some(Policy::RejectedFeature {
                        feature: _,
                        reason: _
                    })
                ),
                "reply helper lost permanent policy refusal: {error:?}"
            );
        }
    }
    Ok(())
}

/// Service reply verification admits wrapping and embedded keys independently.
#[test]
fn service_reply_verifier_admits_all_keys() -> Result<(), Box<dyn Error>> {
    let (keys, bytes, now) = fixture(18, 18, None)?;
    let accepted = Validator::new(&keys)
        .with_now(now)
        .validate_ap_req(&bytes)?;
    let auth =
        ap_req::decrypt_ap_req_authenticator(&ap_req::decode(&bytes)?, accepted.session_key(), 11)?;
    for (profile, id, permitted) in [
        ("", 1_i32, false),
        ("", 23_i32, false),
        ("", 16_i32, false),
        ("permitted_enctypes = aes256-cts", 17_i32, false),
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
        let mut context = accepted.clone();
        context.set_crypto_policy(CryptoPolicy::from_libdefaults(&config.libdefaults)?);
        let part = rasn_kerberos::EncApRepPart {
            ctime: auth.ctime.clone(),
            cusec: auth.cusec.clone(),
            subkey: Some(rasn_kerberos::EncryptionKey {
                r#type: id,
                value: vec![
                    0x42_u8;
                    KerberosEtype::from_etype_id(id).map_or(8, KerberosEtype::key_len)
                ]
                .into(),
            }),
            seq_number: Some(42),
        };
        let reply =
            ap_rep::build_ap_rep_with_confounder(&part, context.session_key(), None, &[0x22; 16])?;
        let result = context.verify_ap_rep(&ap_rep::encode(&reply)?);
        if permitted {
            assert_eq!(
                result?
                    .subkey()
                    .as_ref()
                    .ok_or("missing verified subkey")?
                    .etype(),
                id
            );
        } else {
            let error = result
                .err()
                .ok_or("service verifier admitted excluded reply subkey")?;
            assert!(policy_cause(&error).is_some(), "typed policy refusal");
        }
    }
    let reply = accepted.build_ap_rep_with_confounder(&[0x22; 16], &ApRepOptions::default())?;
    let mut changed = accepted;
    changed.set_session_key(EncryptionKey::new(23, vec![0x43; 16]));
    let error = changed
        .verify_ap_rep(&reply)
        .err()
        .ok_or("wrapping key admitted")?;
    assert!(matches!(
        policy_cause(&error),
        Some(Policy::EnctypeNotPermitted {
            etype: 23_i32,
            usage: Use::SessionKey
        })
    ));
    Ok(())
}

/// Reciprocal MICs admit the selected key, including mutable initiator fallbacks.
#[test]
fn reciprocal_mic_admits_selected_key() -> Result<(), Box<dyn Error>> {
    let (keys, bytes, now) = fixture(18, 18, None)?;
    let header = spnego::negotiate_header(&Token::Init(NegTokenInit::krb5(
        Krb5MechToken::ap_req(bytes).encode()?,
    )))?;
    for (profile, initiator, acceptor, permitted) in [
        ("", Some(23_i32), None, false),
        ("", Some(16_i32), None, false),
        ("permitted_enctypes = aes256-cts", Some(17_i32), None, false),
        ("allow_rc4 = true", Some(23_i32), None, false),
        (
            "allow_rc4 = true\npermitted_enctypes = DEFAULT rc4",
            Some(23_i32),
            None,
            true,
        ),
        (
            "allow_des3 = true\npermitted_enctypes = DEFAULT des3",
            Some(16_i32),
            None,
            true,
        ),
        ("", Some(18_i32), None, true),
        ("", Some(23_i32), Some(18_i32), true),
        ("", None, None, true),
    ] {
        let config = Config::parse(&format!("[libdefaults]\n{profile}"))?;
        let mut validator = Validator::new(&keys).with_now(now);
        let mut accepted = spnego::accept_sec_context_header(&mut validator, &header)?;
        accepted
            .ap_req
            .set_crypto_policy(CryptoPolicy::from_libdefaults(&config.libdefaults)?);
        accepted.ap_req.set_subkey(initiator.map(|id| {
            EncryptionKey::new(
                id,
                vec![0x51; KerberosEtype::from_etype_id(id).map_or(8, KerberosEtype::key_len)],
            )
        }));
        accepted.mech_types_der = Some(vec![0x30, 0]);
        let options = ApRepOptions::default()
            .with_subkey(acceptor.map(|id| EncryptionKey::new(id, vec![0x52; 32])));
        let result = accepted.ap_rep_response_header_with_confounder(&[0x22; 16], &options);
        if permitted {
            let response = spnego::parse_negotiate_header(&result?)?;
            assert!(matches!(response, Token::Resp(reply) if reply.mech_list_mic().is_some()));
        } else {
            let error = result
                .err()
                .ok_or("excluded initiator subkey signed reciprocal MIC")?;
            assert!(matches!(
                policy_cause(&error),
                Some(Policy::EnctypeNotPermitted {
                    usage: Use::AcceptorSubkey,
                    etype: _,
                })
            ));
        }
    }
    Ok(())
}

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
    accepted.set_session_key(EncryptionKey::new(23, vec![0x33; 16]));
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

//! Reply policy regressions that change an accepted context's retained state.
//!
//! The state is reached through the private fields of `AcceptedContext`, because the public
//! API gives an application no way to replace it.

use core::{error::Error as StdError, time::Duration};
use std::time::{SystemTime, UNIX_EPOCH};

use super::{
    AcceptedContext, Krb5MechToken, NegTokenInit, Token, accept_sec_context_header,
    authenticator_checksum, negotiate_header, parse_negotiate_header,
};
use crate::{
    ap_req,
    config::Config,
    crypto::{CryptoPolicy, KerberosEtype, Use},
    error::Policy,
    keytab::{EncryptionKey, Entry, Keytab, Principal},
    service::{ApRepOptions, Validator},
};

/// Locate the policy cause without depending on wrapper depth.
fn policy_cause<'error>(mut error: &'error (dyn StdError + 'static)) -> Option<&'error Policy> {
    loop {
        if let Some(policy) = error.downcast_ref::<Policy>() {
            return Some(policy);
        }
        error = error.source()?;
    }
}

/// A keytab, a SPNEGO request header and a clock for the gokrb5 AES256 service ticket.
fn request() -> Result<(Keytab, String, SystemTime), Box<dyn StdError>> {
    let mut keys = Keytab::new();
    keys.entries_mut().push(Entry::new(
        Principal::new(
            "TEST.GOKRB5",
            1,
            vec!["HTTP".to_owned(), "host.test.gokrb5".to_owned()],
        ),
        0,
        1,
        EncryptionKey::new(
            18,
            hex::decode("9cad00bbc72d703258e911dc18e6d5487cf737bf67fd111f0c2463ad6033bf51")?,
        ),
        1,
    ));
    let original = ap_req::decode(include_bytes!("../../tests/fixtures/valid_ap_req.der"))?;
    let session = EncryptionKey::new(
        18,
        hex::decode("8845cbaccbf11cb9f467fd577ba51c70d73de6554980a05395bf319e18bdda07")?,
    );
    let mut authenticator = ap_req::decrypt_ap_req_authenticator(&original, &session, 11)?;
    authenticator.cksum = Some(rasn_kerberos::Checksum {
        r#type: 0x8003,
        checksum: authenticator_checksum(&[]).into(),
    });
    authenticator.seq_number = Some(42);
    let message = ap_req::build_ap_req_with_confounder(
        original.ticket,
        original.ap_options,
        &authenticator,
        &session,
        11,
        None,
        &[0; 16],
    )?;
    let header = negotiate_header(&Token::Init(NegTokenInit::krb5(
        Krb5MechToken::ap_req(ap_req::encode(&message)?).encode()?,
    )))?;
    let now = UNIX_EPOCH
        .checked_add(Duration::from_secs(1_893_553_447))
        .ok_or("clock")?;
    Ok((keys, header, now))
}

/// The context a service accepts for [`request`], validated under the default policy.
fn accepted(
    keys: &Keytab,
    header: &str,
    now: SystemTime,
) -> Result<AcceptedContext, Box<dyn StdError>> {
    let mut validator = Validator::new(keys).with_now(now);
    Ok(accept_sec_context_header(&mut validator, header)?)
}

/// Random and deterministic reply helpers retain permanent policy refusals.
#[test]
fn random_reply_retains_permanent_refusal() -> Result<(), Box<dyn StdError>> {
    let (keys, header, now) = request()?;
    let mut context = accepted(&keys, &header, now)?;
    for id in [1_i32, 24_i32] {
        context
            .ap_req
            .set_session_key(EncryptionKey::new(id, vec![0x42; 16]));
        for reply in [
            context.ap_rep_response_header_with_confounder(&[0x22; 16], &ApRepOptions::default()),
            context.ap_rep_response_header(&ApRepOptions::default()),
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

/// Reciprocal MICs admit the selected key, including mutable initiator fallbacks.
#[test]
fn reciprocal_mic_admits_selected_key() -> Result<(), Box<dyn StdError>> {
    let (keys, header, now) = request()?;
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
        let mut context = accepted(&keys, &header, now)?;
        context
            .ap_req
            .set_crypto_policy(CryptoPolicy::from_libdefaults(&config.libdefaults)?);
        context.ap_req.set_subkey(initiator.map(|id| {
            EncryptionKey::new(
                id,
                vec![0x51; KerberosEtype::from_etype_id(id).map_or(8, KerberosEtype::key_len)],
            )
        }));
        context.mech_types_der = Some(vec![0x30, 0]);
        let options = ApRepOptions::default()
            .with_subkey(acceptor.map(|id| EncryptionKey::new(id, vec![0x52; 32])));
        let result = context.ap_rep_response_header_with_confounder(&[0x22; 16], &options);
        if permitted {
            let response = parse_negotiate_header(&result?)?;
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

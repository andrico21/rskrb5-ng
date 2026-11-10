use core::{error::Error, time::Duration};
use std::time::SystemTime;

use rasn::{
    der,
    types::{GeneralString, Integer},
};
use rasn_kerberos::{EncryptedData, PrincipalName, Ticket};
use rskrb5_ng::{
    Config,
    client::{
        self, AsRepSession, Tokio,
        options::{AsReq, TgsReq},
        principal::Principal,
        transport::KdcProtocol,
    },
    crypto::Use,
    error::Policy,
    keytab::{EncryptionKey, Keytab},
};

/// Locate the policy cause without depending on wrapper depth.
pub(super) fn policy_cause<'error>(
    mut error: &'error (dyn Error + 'static),
) -> Option<&'error Policy> {
    loop {
        if let Some(policy) = error.downcast_ref::<Policy>() {
            return Some(policy);
        }
        error = error.source()?;
    }
}

/// Build a structurally valid but opaque service ticket for cache admission checks.
pub(super) fn session(
    session_etype: i32,
    ticket_etype: i32,
) -> Result<AsRepSession, Box<dyn Error>> {
    let ticket = Ticket {
        tkt_vno: Integer::from(5_i32),
        realm: GeneralString::try_from("EXAMPLE.COM")?,
        sname: PrincipalName {
            r#type: 2,
            string: vec![
                GeneralString::try_from("HTTP")?,
                GeneralString::try_from("host")?,
            ],
        },
        enc_part: EncryptedData {
            etype: ticket_etype,
            kvno: None,
            cipher: vec![0_u8].into(),
        },
    };
    let seconds = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs();
    let now = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .ok_or("time overflow")?;
    Ok(AsRepSession::new(
        Principal::user("EXAMPLE.COM", "alice"),
        Principal::new("EXAMPLE.COM", 2, ["HTTP", "host"]),
        EncryptionKey::new(session_etype, vec![0; 32]),
        der::encode(&ticket)?.into(),
        [0; 4],
        now,
        now.checked_add(Duration::from_secs(3600))
            .ok_or("time overflow")?,
    ))
}

/// Mutated request lists cannot escape the policy captured from configuration.
#[test]
fn as_request_rejects_excluded_list() -> Result<(), Box<dyn Error>> {
    // Given AES128-only config and a subsequently overridden request list.
    let config = Config::parse("[libdefaults]\npermitted_enctypes = aes128-cts")?;
    let options = AsReq::from_libdefaults(SystemTime::now(), 1, &config.libdefaults)?
        .with_etypes(vec![18_i32]);
    // When building before any exchange.
    let error = client::build_tgt_as_req(Principal::user("EXAMPLE.COM", "alice"), options)
        .err()
        .ok_or("request escaped policy")?;
    // Then request-list rejection is typed.
    assert!(matches!(
        policy_cause(&error),
        Some(Policy::EnctypeNotPermitted {
            etype: 18_i32,
            usage: Use::RequestList
        })
    ));
    Ok(())
}

/// Cache admission independently checks session keys and ticket encryption types.
#[test]
fn cache_rejects_excluded_session_and_ticket() -> Result<(), Box<dyn Error>> {
    // Given AES128-only policy and otherwise matching client credentials.
    for (session_etype, ticket_etype) in [
        (18_i32, 17_i32),
        (17_i32, 18_i32),
        (23_i32, 17_i32),
        (16_i32, 17_i32),
    ] {
        let config = Config::parse("[libdefaults]\npermitted_enctypes = aes128-cts")?;
        let mut kerberos = Tokio::with_keytab(
            config,
            KdcProtocol::Tcp,
            Principal::user("EXAMPLE.COM", "alice"),
            Keytab::new(),
        );
        // When attempting cache insertion with one excluded component.
        let error = kerberos
            .cache_service_ticket(session(session_etype, ticket_etype)?)
            .err()
            .ok_or("excluded cache accepted")?;
        // Then no credential is admitted.
        assert!(matches!(
            policy_cause(&error),
            Some(Policy::EnctypeNotPermitted {
                etype: _,
                usage: Use::ImportedCredential
            })
        ));
        assert_eq!(kerberos.cached_service_ticket_count(), 0);
    }
    Ok(())
}

/// TGS session-key checks precede authenticator encryption.
#[test]
fn tgs_request_rejects_excluded_session() -> Result<(), Box<dyn Error>> {
    // Given an AES256 TGT-like session under AES128-only request policy.
    let config = Config::parse("[libdefaults]\npermitted_enctypes = aes128-cts")?;
    let options = TgsReq::from_libdefaults(SystemTime::now(), 1, &config.libdefaults)?;
    // When building a deterministic TGS request.
    let error = client::build_tgs_req_with_confounder(
        &session(18, 17)?,
        Principal::new("EXAMPLE.COM", 2, ["HTTP", "other"]),
        options,
        SystemTime::UNIX_EPOCH,
        0,
        &[],
    )
    .err()
    .ok_or("excluded TGT used")?;
    // Then policy wins over confounder/key-length failures.
    assert!(matches!(
        policy_cause(&error),
        Some(Policy::EnctypeNotPermitted {
            etype: 18_i32,
            usage: Use::SessionKey
        })
    ));
    Ok(())
}

/// Reply keys are rejected before even attempting to decode malformed reply bytes.
#[test]
fn as_reply_rejects_excluded_key_before_crypto() -> Result<(), Box<dyn Error>> {
    // Given a request bound to AES128-only configuration.
    let config = Config::parse("[libdefaults]\npermitted_enctypes = aes128-cts")?;
    let request = client::build_tgt_as_req(
        Principal::user("EXAMPLE.COM", "alice"),
        AsReq::from_libdefaults(SystemTime::now(), 1, &config.libdefaults)?,
    )?;
    // When processing bytes with an excluded reply key.
    let error = client::process_as_rep(&request, &[], &EncryptionKey::new(18, Vec::new()))
        .err()
        .ok_or("excluded reply accepted")?;
    // Then policy precedes decoding and crypto.
    assert!(matches!(
        policy_cause(&error),
        Some(Policy::EnctypeNotPermitted {
            etype: 18_i32,
            usage: Use::ReplyKey
        })
    ));
    Ok(())
}

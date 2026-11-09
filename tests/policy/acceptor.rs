use core::{error::Error, str, time::Duration};
use std::time::SystemTime;

use rasn::der;
use rskrb5_ng::{
    Config, ap_rep, ap_req,
    crypto::{CryptoPolicy, KerberosEtype, Use},
    error::Policy,
    keytab::{EncryptionKey, Entry, Keytab, Principal},
    service::Validator,
    spnego::{self, InitiatorContextOptions},
    ticket,
};

use super::client::policy_cause;

/// Re-encrypt a valid gokrb5 fixture under independently selected key enctypes.
pub(super) fn fixture(
    ticket_id: i32,
    session_id: i32,
    subkey: Option<i32>,
) -> Result<(Keytab, Vec<u8>, SystemTime), Box<dyn Error>> {
    let mut request = ap_req::decode(include_bytes!("../fixtures/valid_ap_req.der"))?;
    let original = EncryptionKey::new(
        18,
        hex::decode("9cad00bbc72d703258e911dc18e6d5487cf737bf67fd111f0c2463ad6033bf51")?,
    );
    let mut part = ticket::decrypt_ticket_enc_part(&request.ticket, &original)?;
    let old_session = EncryptionKey::new(part.key.r#type, part.key.value.as_ref().to_vec());
    let mut auth = ap_req::decrypt_ap_req_authenticator(&request, &old_session, 11)?;
    auth.cksum = Some(rasn_kerberos::Checksum {
        r#type: 0x8003,
        checksum: spnego::authenticator_checksum(&[]).into(),
    });
    auth.seq_number = Some(42);
    let ticket_type = KerberosEtype::from_etype_id(ticket_id).ok_or("ticket enctype")?;
    let session_type = KerberosEtype::from_etype_id(session_id).ok_or("session enctype")?;
    let ticket_key = EncryptionKey::new(ticket_id, vec![0x45; ticket_type.key_len()]);
    let session_key = EncryptionKey::new(session_id, vec![0x46; session_type.key_len()]);
    part.key = rasn_kerberos::EncryptionKey {
        r#type: session_id,
        value: session_key.value().to_vec().into(),
    };
    auth.subkey = subkey.map(|id| rasn_kerberos::EncryptionKey {
        r#type: id,
        value: vec![0x47_u8; 32].into(),
    });
    request.ticket = ticket::build_ticket_with_confounder(
        request.ticket.realm.clone(),
        request.ticket.sname.clone(),
        &part,
        &ticket_key,
        None,
        &vec![0x22; ticket_type.confounder_len()],
    )?;
    request.authenticator = rasn_kerberos::EncryptedData {
        etype: session_id,
        kvno: None,
        cipher: session_type
            .encrypt_message_with_confounder(
                session_key.value(),
                &der::encode(&auth)?,
                11,
                &vec![0x23; session_type.confounder_len()],
            )?
            .into(),
    };
    let realm = str::from_utf8(request.ticket.realm.as_bytes())?;
    let names = request
        .ticket
        .sname
        .string
        .iter()
        .map(|name| str::from_utf8(name.as_bytes()).map(str::to_owned))
        .collect::<Result<Vec<_>, _>>()?;
    let mut keys = Keytab::new();
    keys.entries_mut().push(Entry::new(
        Principal::new(realm, 2, names),
        0,
        1,
        ticket_key,
        1,
    ));
    let seconds = u64::try_from(auth.ctime.0.timestamp())?;
    let now = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .ok_or("time")?;
    Ok((keys, der::encode(&request)?, now))
}

/// A default acceptor rejects RC4 even when an RC4-only keytab can decrypt it.
#[test]
fn default_acceptor_rejects_rc4_ticket() -> Result<(), Box<dyn Error>> {
    // Given a valid RC4 ticket and matching keytab, not malformed crypto.
    let (keys, bytes, now) = fixture(23, 23, None)?;
    // When validating with the default policy.
    let error = Validator::new(&keys)
        .with_now(now)
        .validate_ap_req(&bytes)
        .err()
        .ok_or("RC4 accepted by default")?;
    // Then policy, not key lookup or integrity, is the cause.
    assert!(matches!(
        policy_cause(&error),
        Some(Policy::EnctypeNotPermitted {
            etype: 23_i32,
            usage: Use::AcceptorTicket
        })
    ));
    Ok(())
}

/// Explicit opt-in and membership permit RC4 while narrow AES policy rejects AES256.
#[test]
fn acceptor_applies_explicit_policy() -> Result<(), Box<dyn Error>> {
    // Given valid RC4 and AES256 tickets under explicit policies.
    let (keys, bytes, now) = fixture(23, 23, None)?;
    let config =
        Config::parse("[libdefaults]\nallow_rc4 = true\npermitted_enctypes = DEFAULT rc4")?;
    // When permission is explicitly supplied.
    let accepted = Validator::new(&keys)
        .with_now(now)
        .with_crypto_policy(CryptoPolicy::from_libdefaults(&config.libdefaults)?)
        .validate_ap_req(&bytes)?;
    // Then RC4 remains usable only under that permission.
    assert_eq!(accepted.session_key().etype(), 23_i32);
    let (aes_keys, aes_bytes, aes_now) = fixture(18, 18, None)?;
    let narrow = Config::parse("[libdefaults]\npermitted_enctypes = aes128-cts")?;
    let error = Validator::new(&aes_keys)
        .with_now(aes_now)
        .with_crypto_policy(CryptoPolicy::from_libdefaults(&narrow.libdefaults)?)
        .validate_ap_req(&aes_bytes)
        .err()
        .ok_or("excluded AES accepted")?;
    assert!(matches!(
        policy_cause(&error),
        Some(Policy::EnctypeNotPermitted {
            etype: 18_i32,
            usage: Use::AcceptorTicket
        })
    ));
    Ok(())
}

/// Authenticated ticket session keys and authenticator subkeys are independently constrained.
#[test]
fn acceptor_checks_inner_keys_before_replay() -> Result<(), Box<dyn Error>> {
    // Given allowed ticket encryption with one excluded inner key at a time.
    let config = Config::parse("[libdefaults]\npermitted_enctypes = aes128-cts")?;
    for (session_id, subkey, usage) in [
        (18_i32, None, Use::AcceptorTicket),
        (17_i32, Some(18_i32), Use::AcceptorSubkey),
    ] {
        let (keys, bytes, now) = fixture(17, session_id, subkey)?;
        let mut request = ap_req::decode(&bytes)?;
        request.authenticator.etype = 17_i32;
        let encoded = ap_req::encode(&request)?;
        if session_id == 18_i32 {
            let broad_error = Validator::new(&keys)
                .with_now(now)
                .validate_ap_req(&encoded)
                .err()
                .ok_or("mismatched envelope accepted")?;
            assert!(policy_cause(&broad_error).is_none());
        }
        let mut validator = Validator::new(&keys)
            .with_now(now)
            .with_crypto_policy(CryptoPolicy::from_libdefaults(&config.libdefaults)?);
        // When authenticated plaintext exposes the excluded key.
        let error = validator
            .validate_ap_req(&encoded)
            .err()
            .ok_or("excluded inner key accepted")?;
        // Then rejection precedes replay admission.
        assert!(
            matches!(policy_cause(&error), Some(Policy::EnctypeNotPermitted { etype: 18_i32, usage: actual }) if *actual == usage)
        );
        assert_eq!(validator.replay_cache_mut().len(), 0);
    }
    Ok(())
}

/// Initiator policy rejects an authenticated AP-REP subkey outside its permitted set.
#[test]
fn initiator_rejects_excluded_ap_rep_subkey() -> Result<(), Box<dyn Error>> {
    // Given an AES128 context and valid reply encrypted by its accepted session key.
    let config = Config::parse("[libdefaults]\npermitted_enctypes = aes128-cts")?;
    let mut session = super::client::session(17, 17)?;
    session.set_session_key(EncryptionKey::new(
        session.session_key().etype(),
        vec![0x11; 16],
    ));
    let context = spnego::init_sec_context(
        &session,
        InitiatorContextOptions::new()
            .with_crypto_policy(CryptoPolicy::from_libdefaults(&config.libdefaults)?),
    )?;
    let auth =
        ap_req::decrypt_ap_req_authenticator(context.ap_req_ref(), session.session_key(), 11)?;
    let part = rasn_kerberos::EncApRepPart {
        ctime: auth.ctime,
        cusec: auth.cusec,
        subkey: Some(rasn_kerberos::EncryptionKey {
            r#type: 18,
            value: vec![0x42_u8; 32].into(),
        }),
        seq_number: Some(42),
    };
    let reply =
        ap_rep::build_ap_rep_with_confounder(&part, session.session_key(), None, &[0x22_u8; 16])?;
    // When accepting an otherwise correctly bound encrypted reply.
    let error = context
        .verify_ap_rep(&ap_rep::encode(&reply)?)
        .err()
        .ok_or("excluded AP-REP subkey accepted")?;
    // Then the exact SessionKey policy cause survives.
    assert!(matches!(
        policy_cause(&error),
        Some(Policy::EnctypeNotPermitted {
            etype: 18_i32,
            usage: Use::SessionKey
        })
    ));
    let mut permitted_part = part;
    permitted_part.subkey = Some(rasn_kerberos::EncryptionKey {
        r#type: 17,
        value: vec![0x42_u8; 16].into(),
    });
    let permitted_reply = ap_rep::build_ap_rep_with_confounder(
        &permitted_part,
        session.session_key(),
        None,
        &[0x22_u8; 16],
    )?;
    let accepted = context.verify_ap_rep(&ap_rep::encode(&permitted_reply)?)?;
    assert_eq!(
        accepted
            .subkey()
            .as_ref()
            .ok_or("accepted subkey missing")?
            .etype(),
        17_i32
    );
    Ok(())
}

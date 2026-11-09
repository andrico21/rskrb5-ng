use core::{error::Error, time::Duration};
use std::time::SystemTime;

use chrono::{DateTime, FixedOffset, Utc};
use rasn::{
    der,
    types::{GeneralString, Integer},
};
use rasn_kerberos::{
    AsRep, EncAsRepPart, EncKdcRepPart, EncTgsRepPart, EncryptedData, EncryptionKey as WireKey,
    KdcRep, KerberosFlags, KerberosTime, PrincipalName, TgsRep, Ticket, TicketFlags,
};
use rskrb5_ng::{
    Config,
    client::{
        self,
        options::{AsReq, TgsReq},
    },
    crypto::{CryptoPolicy, KerberosEtype, Use},
    error::Policy,
    keytab::EncryptionKey,
};

use super::client::{policy_cause, session};

/// Independent fixed UTC seconds, without platform nanosecond assumptions.
fn time(seconds: i64) -> Result<KerberosTime, Box<dyn Error>> {
    let utc = DateTime::<Utc>::from_timestamp(seconds, 0).ok_or("timestamp")?;
    Ok(KerberosTime(
        utc.with_timezone(&FixedOffset::east_opt(0).ok_or("UTC")?),
    ))
}

/// Build a valid reply independently of production reply builders and fixture helpers.
fn encrypted_reply(
    is_as: bool,
    session_id: i32,
    ticket_id: i32,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let realm = GeneralString::try_from("EXAMPLE.COM")?;
    let service = PrincipalName {
        r#type: 2,
        string: vec![
            GeneralString::try_from("HTTP")?,
            GeneralString::try_from("host")?,
        ],
    };
    let part = EncKdcRepPart {
        key: WireKey {
            r#type: session_id,
            value: vec![0x42_u8; if session_id == 17_i32 { 16 } else { 32 }].into(),
        },
        last_req: Vec::new(),
        nonce: 42,
        key_expiration: None,
        flags: TicketFlags(KerberosFlags::from_slice(&[0_u8; 4])),
        auth_time: time(1_800_000_000)?,
        start_time: Some(time(1_800_000_000)?),
        end_time: time(1_800_000_060)?,
        renew_till: None,
        srealm: realm.clone(),
        sname: service.clone(),
        caddr: None,
        encrypted_pa_data: None,
    };
    let plaintext = if is_as {
        der::encode(&EncAsRepPart(part))?
    } else {
        der::encode(&EncTgsRepPart(part))?
    };
    let etype = KerberosEtype::from_etype_id(17).ok_or("AES128")?;
    let cipher = etype.encrypt_message_with_confounder(
        &[0x11_u8; 16],
        &plaintext,
        if is_as { 3 } else { 8 },
        &[0x22_u8; 16],
    )?;
    let reply = KdcRep {
        pvno: Integer::from(5_i32),
        msg_type: Integer::from(if is_as { 11_i32 } else { 13_i32 }),
        padata: None,
        crealm: realm.clone(),
        cname: PrincipalName {
            r#type: 1,
            string: vec![GeneralString::try_from("alice")?],
        },
        ticket: Ticket {
            tkt_vno: Integer::from(5_i32),
            realm,
            sname: service,
            enc_part: EncryptedData {
                etype: ticket_id,
                kvno: None,
                cipher: vec![0x33_u8; 32].into(),
            },
        },
        enc_part: EncryptedData {
            etype: 17,
            kvno: None,
            cipher: cipher.into(),
        },
    };
    Ok(if is_as {
        der::encode(&AsRep(reply))?
    } else {
        der::encode(&TgsRep(reply))?
    })
}

/// Process otherwise valid ciphertext with a broad requested list but a narrow policy.
fn reject(is_as: bool, usage: Use) -> Result<(), Box<dyn Error>> {
    // Given independently encrypted valid fixtures; only one enctype is excluded.
    let config = Config::parse("[libdefaults]\npermitted_enctypes = aes128-cts")?;
    let policy = CryptoPolicy::from_libdefaults(&config.libdefaults)?;
    let now = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_hours(500_000))
        .ok_or("time")?;
    let base = session(17, 17)?;
    let key = EncryptionKey::new(17, vec![0x11; 16]);
    let (session_id, ticket_id) = match usage {
        Use::SessionKey => (18_i32, 17_i32),
        Use::TicketKey => (17_i32, 18_i32),
        Use::RequestList
        | Use::ReplyKey
        | Use::AcceptorTicket
        | Use::AcceptorSubkey
        | Use::ImportedCredential
        | Use::CheckedLowLevel => return Err("fixture use".into()),
        _ => return Err("future fixture use".into()),
    };
    let bytes = encrypted_reply(is_as, session_id, ticket_id)?;
    // When processing, request binding intentionally allows both AES types.
    let failure = if is_as {
        let mut request = client::build_as_req(
            base.client().clone(),
            base.service().clone(),
            AsReq::new(now, 42).with_etypes(vec![17_i32, 18_i32]),
        )?;
        drop(client::process_as_rep(&request, &bytes, &key)?);
        request.set_crypto_policy(policy);
        client::process_as_rep(&request, &bytes, &key)
            .err()
            .ok_or("excluded AS reply accepted")?
    } else {
        let mut tgt = base;
        tgt.set_session_key(key.clone());
        let mut request = client::build_tgs_req_with_confounder(
            &tgt,
            tgt.service().clone(),
            TgsReq::new(now, 42).with_etypes(vec![17_i32, 18_i32]),
            now,
            0,
            &[0x22_u8; 16],
        )?;
        drop(client::process_tgs_rep(&request, &bytes, &key)?);
        request.set_crypto_policy(policy);
        client::process_tgs_rep(&request, &bytes, &key)
            .err()
            .ok_or("excluded TGS reply accepted")?
    };
    // Then only the precise policy use rejects; the broad-policy control succeeded.
    assert!(
        matches!(policy_cause(&failure), Some(Policy::EnctypeNotPermitted { etype: 18_i32, usage: actual }) if *actual == usage)
    );
    Ok(())
}

/// AS reply session-key policy is independent of request binding.
#[test]
fn as_session_policy_isolated() -> Result<(), Box<dyn Error>> {
    reject(true, Use::SessionKey)
}
/// AS reply ticket-key policy is independent of successful reply decryption.
#[test]
fn as_ticket_policy_isolated() -> Result<(), Box<dyn Error>> {
    reject(true, Use::TicketKey)
}
/// TGS reply session-key policy is independent of request binding.
#[test]
fn tgs_session_policy_isolated() -> Result<(), Box<dyn Error>> {
    reject(false, Use::SessionKey)
}
/// TGS reply ticket-key policy is independent of successful reply decryption.
#[test]
fn tgs_ticket_policy_isolated() -> Result<(), Box<dyn Error>> {
    reject(false, Use::TicketKey)
}

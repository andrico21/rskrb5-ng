//! Authenticated kpasswd reply fixtures with independently altered controls.

use core::time::Duration;
use std::time::UNIX_EPOCH;

use rasn::{der, types::Integer};
use rskrb5_ng::{
    ap_rep,
    client::{
        Password, TgsRepSession,
        kpasswd::{BuiltKpasswdRequest, RequestOptions, build_kpasswd_request_with_confounders},
        principal::Principal,
    },
    crypto::{AesSha1Etype, KerberosEtype},
    kadmin::{self, ChangePasswdData, Request},
    keytab::EncryptionKey,
    krb_priv::{EncKrbPrivPartOptions, ipv4_host_address},
    ticket,
};
use tokio::net::ToSocketAddrs;

use super::{TestError, kerberos_time};

/// Compile both password address APIs with only their actual resolver bound.
pub(super) fn address_contract<A>(addr: A) -> Result<(), TestError>
where
    A: ToSocketAddrs,
{
    let (built, options) = request()?;
    let transport = super::Tokio::new();
    drop(transport.exchange_kpasswd_request(super::KdcProtocol::Tcp, &addr, &built.request));
    drop(transport.exchange_kpasswd_result(super::KdcProtocol::Tcp, addr, &built, &options));
    Ok(())
}

/// Build a request with known service and reply keys.
pub(super) fn request() -> Result<(BuiltKpasswdRequest, RequestOptions), TestError> {
    let fixture = Request::parse(&hex::decode(
        include_str!("../../fixtures/kpasswd-request.hex").trim(),
    )?)?;
    let time = UNIX_EPOCH
        .checked_add(Duration::from_secs(1_893_553_452))
        .ok_or("fixture timestamp")?;
    let session = TgsRepSession::new(
        Principal::user("TEST.GOKRB5", "testuser1"),
        Principal::new("TEST.GOKRB5", 2, ["kadmin", "changepw"]),
        EncryptionKey::new(18, vec![0x11; 32]),
        ticket::encode(&fixture.ap_req.ticket)?.into(),
        [0; 4],
        time,
        time,
    );
    let options = RequestOptions::new(time, 456_789, 42, ipv4_host_address([127, 0, 0, 1]))
        .with_recipient_address(ipv4_host_address([127, 0, 0, 2]));
    let built = build_kpasswd_request_with_confounders(
        &session,
        &ChangePasswdData::new(Password::copy_from_str("reflection-password-canary")),
        EncryptionKey::new(18, vec![0x22; 32]),
        &options,
        &[0x33; 16],
        &[0x44; 16],
    )?;
    Ok((built, options))
}

/// Select the protected reply control to alter.
#[derive(Clone, Copy)]
pub(super) enum ReplyCase {
    /// Invalid AP-REP ciphertext.
    BadApRep,
    /// AP-REP does not echo request time.
    WrongApRepTime,
    /// KRB-PRIV has no freshness mechanism.
    MissingFreshness,
    /// Sequence does not match the AP-REP selection.
    WrongSequence,
    /// Sender differs from the pinned recipient.
    WrongAddress,
    /// KRB-PRIV timestamp is outside the permitted skew.
    StaleTime,
    /// Timestamp exactly at the accepted five-minute skew boundary.
    SkewBoundary,
    /// Largest valid microsecond field.
    MaximumUsec,
    /// Authenticated microseconds exceed the protocol range.
    ExcessiveUsec,
    /// Ciphertext encrypted with an unrelated key.
    WrongKey,
    /// Password ciphertext reflected with modified outer metadata.
    Reflection,
    /// Successful reply using a server-selected subkey.
    Subkey,
    /// Authenticated server selection of a legacy reply key.
    LegacySubkey(i32),
    /// Authenticated contextual rejection.
    Rejected,
}

/// Encode a reply under real keys, corrupting only the selected control.
pub(super) fn reply(request: &BuiltKpasswdRequest, case: ReplyCase) -> Result<Vec<u8>, TestError> {
    let mut response_key = request.reply_key.clone();
    let mut sequence = Some(99);
    let mut cusec = 456_789_u32;
    let mut subkey = None;
    let mut options = EncKrbPrivPartOptions::new(ipv4_host_address([127, 0, 0, 2]))
        .with_recipient_address(ipv4_host_address([127, 0, 0, 1]))
        .with_timestamp(kerberos_time(1_893_553_452)?, 456_789)
        .with_sequence_number(99);
    let mut data: &[u8] = b"\x00\x00changed";
    match case {
        ReplyCase::BadApRep | ReplyCase::ExcessiveUsec => {}
        ReplyCase::WrongApRepTime => cusec = 456_788,
        ReplyCase::MissingFreshness => {
            sequence = None;
            options.timestamp = None;
            options.usec = None;
            options.seq_number = None;
        }
        ReplyCase::WrongSequence => options.seq_number = Some(100),
        ReplyCase::WrongAddress => options.sender_address = ipv4_host_address([127, 0, 0, 9]),
        ReplyCase::StaleTime => options.timestamp = Some(kerberos_time(1_893_550_000)?),
        ReplyCase::SkewBoundary => options.timestamp = Some(kerberos_time(1_893_553_752)?),
        ReplyCase::MaximumUsec => options.usec = Some(999_999_u32.into()),
        ReplyCase::WrongKey => response_key = EncryptionKey::new(18, vec![0x66; 32]),
        ReplyCase::Reflection => sequence = None,
        ReplyCase::Subkey | ReplyCase::LegacySubkey(_) => {
            let id = if let ReplyCase::LegacySubkey(id) = case {
                id
            } else {
                18_i32
            };
            let etype = KerberosEtype::from_etype_id(id).ok_or("enctype")?;
            response_key = EncryptionKey::new(id, vec![0x66; etype.key_len()]);
            subkey = Some(rasn_kerberos::EncryptionKey {
                r#type: id,
                value: response_key.value.to_vec().into(),
            });
        }
        ReplyCase::Rejected => data = b"\x00\x04policy refused",
    }
    let mut ap_rep = ap_rep::build_ap_rep_with_confounder(
        &rasn_kerberos::EncApRepPart {
            ctime: kerberos_time(1_893_553_452)?,
            cusec: Integer::from(cusec),
            subkey,
            seq_number: sequence,
        },
        &request.ap_req.session_key,
        None,
        &[0x55; 16],
    )?;
    if matches!(case, ReplyCase::BadApRep) {
        ap_rep.enc_part.cipher = vec![0].into();
    }
    let mut private = match case {
        ReplyCase::Reflection => request.request.krb_priv.clone(),
        ReplyCase::BadApRep
        | ReplyCase::WrongApRepTime
        | ReplyCase::MissingFreshness
        | ReplyCase::WrongSequence
        | ReplyCase::WrongAddress
        | ReplyCase::StaleTime
        | ReplyCase::SkewBoundary
        | ReplyCase::MaximumUsec
        | ReplyCase::ExcessiveUsec
        | ReplyCase::WrongKey
        | ReplyCase::Subkey
        | ReplyCase::LegacySubkey(_)
        | ReplyCase::Rejected => {
            let etype = KerberosEtype::from_etype_id(response_key.etype).ok_or("enctype")?;
            kadmin::build_krb_priv_with_confounder(
                data,
                options,
                &response_key,
                &vec![0x77; etype.confounder_len()],
            )?
        }
    };
    if matches!(case, ReplyCase::ExcessiveUsec) {
        let mut part = kadmin::decrypt_krb_priv_enc_part(&private, &response_key)?;
        part.usec = Some(1_000_001_u32.into());
        private.enc_part.cipher = AesSha1Etype::from_etype_id(18)
            .ok_or("AES-SHA1")?
            .encrypt_message_with_confounder(
                &response_key.value,
                &der::encode(&part)?,
                13,
                &[0x77; 16],
            )?
            .into();
    }
    private.enc_part.kvno = Some(999);
    frame(&ap_rep, &private)
}

/// Frame independently encoded authenticated reply sections.
fn frame(
    ap_rep: &rasn_kerberos::ApRep,
    private: &rasn_kerberos::KrbPriv,
) -> Result<Vec<u8>, TestError> {
    let ap_bytes = ap_rep::encode(ap_rep)?;
    let private_bytes = kadmin::encode_krb_priv(private)?;
    let length = 6_usize
        .checked_add(ap_bytes.len())
        .and_then(|len| len.checked_add(private_bytes.len()))
        .ok_or("frame size")?;
    let mut frame = Vec::new();
    frame.extend_from_slice(&u16::try_from(length)?.to_be_bytes());
    frame.extend_from_slice(&1_u16.to_be_bytes());
    frame.extend_from_slice(&u16::try_from(ap_bytes.len())?.to_be_bytes());
    frame.extend_from_slice(&ap_bytes);
    frame.extend_from_slice(&private_bytes);
    Ok(frame)
}

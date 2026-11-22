//! A fake KDC for the client routing tests.
//!
//! It answers the TGS-REQs of the sans-I/O `TicketCreds` engine with a TGS-REP
//! for a chosen ticket principal, encrypted in the session key of the TGT the
//! request was made with, or with a KRB-ERROR.

use core::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, FixedOffset, Utc};
use rasn::der;
use rskrb5_ng::{
    client::{
        AsRepSession,
        principal::Principal,
        stepwise::{ExchangeStep, StepInput, TicketCreds},
    },
    crypto::AesSha1Etype,
    error::Client as ClientError,
    keytab::EncryptionKey,
};
use zeroize::Zeroizing;

use crate::TestError;

/// The service-name type of a TGS principal.
const SRV_INST: i32 = 2;

/// The enctype of every key (aes256-cts-hmac-sha1-96).
const ETYPE: i32 = 18;

/// The client every TGT names.
pub(crate) fn client() -> Principal {
    Principal::new("USER.TEST", 1, ["alice"])
}

/// The TGS principal `krbtgt/<to>@<from>`.
pub(crate) fn tgs(from: &str, to: &str) -> Principal {
    Principal::new(from, SRV_INST, ["krbtgt", to])
}

/// The session key of the TGT for realm `to` (distinct per realm).
pub(crate) fn key_for(to: &str) -> EncryptionKey {
    EncryptionKey::new(ETYPE, vec![u8::try_from(to.len()).unwrap_or(0x7f); 32])
}

/// A TGT `krbtgt/<realm>@<realm>` for the client, valid for an hour.
pub(crate) fn tgt(realm: &str) -> Result<AsRepSession, TestError> {
    let now = SystemTime::now();
    let end = now
        .checked_add(Duration::from_secs(3_600))
        .ok_or("end time")?;
    let service = tgs(realm, realm);
    Ok(AsRepSession::new(
        client(),
        service.clone(),
        key_for(realm),
        Zeroizing::new(ticket(&service)?),
        [0; 4],
        now,
        end,
    ))
}

/// The realm and the requested principal of the next outbound request.
pub(crate) fn request_of(step: &ExchangeStep) -> Result<(String, Principal, Vec<u8>), TestError> {
    let ExchangeStep::Outbound(outbound) = step else {
        return Err(format!("expected an outbound request, got {step:?}").into());
    };
    let request: rasn_kerberos::TgsReq = der::decode(outbound.message())?;
    let body = &request.0.req_body;
    let sname = body.sname.as_ref().ok_or("sname")?;
    let realm = string(&body.realm)?;
    let components = sname
        .string
        .iter()
        .map(string)
        .collect::<Result<Vec<_>, _>>()?;
    Ok((
        outbound.realm().to_owned(),
        Principal::new(realm, sname.r#type, components),
        outbound.message().to_vec(),
    ))
}

/// Answer the request in `step` with a ticket for `issued`, encrypted in `key`
/// (the session key of the TGT the request used), and step the engine.
pub(crate) fn answer(
    exchange: &mut TicketCreds,
    step: &ExchangeStep,
    key: &EncryptionKey,
    issued: &Principal,
) -> Result<ExchangeStep, TestError> {
    let (_, _, wire) = request_of(step)?;
    let reply = tgs_rep(&wire, key, issued)?;
    Ok(exchange.step(StepInput::Reply(&reply))?)
}

/// Answer the request in `step` with a KRB-ERROR of `code` and step the engine.
pub(crate) fn refuse(
    exchange: &mut TicketCreds,
    step: &ExchangeStep,
    code: i32,
) -> Result<Result<ExchangeStep, ClientError>, TestError> {
    let (realm, service, _) = request_of(step)?;
    let error = rasn_kerberos::KrbError {
        pvno: 5_i32.into(),
        msg_type: 30_i32.into(),
        ctime: None,
        cusec: None,
        stime: time(SystemTime::now())?,
        susec: 0_i32.into(),
        error_code: code,
        crealm: None,
        cname: None,
        realm: text(&realm)?,
        sname: name(&service)?,
        e_text: None,
        e_data: None,
    };
    Ok(exchange.step(StepInput::Reply(&der::encode(&error)?)))
}

/// A TGS-REP answering the DER TGS-REQ `wire` with a ticket for `issued`.
fn tgs_rep(wire: &[u8], key: &EncryptionKey, issued: &Principal) -> Result<Vec<u8>, TestError> {
    let request: rasn_kerberos::TgsReq = der::decode(wire)?;
    let body = &request.0.req_body;
    let now = time(SystemTime::now())?;
    let next_key = key_for(issued.components.last().map_or("", String::as_str));
    let part = rasn_kerberos::EncTgsRepPart(rasn_kerberos::EncKdcRepPart {
        key: rasn_kerberos::EncryptionKey {
            r#type: ETYPE,
            value: next_key.value().to_vec().into(),
        },
        last_req: Vec::new(),
        nonce: body.nonce,
        key_expiration: None,
        flags: rasn_kerberos::TicketFlags(rasn_kerberos::KerberosFlags::repeat(false, 32)),
        auth_time: now.clone(),
        start_time: Some(now),
        end_time: body.till.clone(),
        renew_till: None,
        srealm: text(&issued.realm)?,
        sname: name(issued)?,
        caddr: None,
        encrypted_pa_data: None,
    });
    let etype = AesSha1Etype::from_etype_id(ETYPE).ok_or("AES256")?;
    let cipher =
        etype.encrypt_message_with_confounder(key.value(), &der::encode(&part)?, 8, &[0x33; 16])?;
    let client = client();
    let reply = rasn_kerberos::TgsRep(rasn_kerberos::KdcRep {
        pvno: 5_i32.into(),
        msg_type: 13_i32.into(),
        padata: None,
        crealm: text(&client.realm)?,
        cname: name(&client)?,
        ticket: der::decode(&ticket(issued)?)?,
        enc_part: rasn_kerberos::EncryptedData {
            etype: ETYPE,
            kvno: None,
            cipher: cipher.into(),
        },
    });
    Ok(der::encode(&reply)?)
}

/// A DER ticket for `service` whose encrypted part the client cannot read.
fn ticket(service: &Principal) -> Result<Vec<u8>, TestError> {
    Ok(der::encode(&rasn_kerberos::Ticket {
        tkt_vno: 5_i32.into(),
        realm: text(&service.realm)?,
        sname: name(service)?,
        enc_part: rasn_kerberos::EncryptedData {
            etype: ETYPE,
            kvno: Some(1),
            cipher: vec![0xca; 48].into(),
        },
    })?)
}

/// A Kerberos string.
fn text(value: &str) -> Result<rasn_kerberos::KerberosString, TestError> {
    rasn_kerberos::KerberosString::from_bytes(value.as_bytes())
        .map_err(|cause| format!("Kerberos string: {cause:?}").into())
}

/// The decoded text of a Kerberos string.
fn string(value: &rasn_kerberos::KerberosString) -> Result<String, TestError> {
    Ok(String::from_utf8(value.as_bytes().to_vec())?)
}

/// The principal name of `principal`.
fn name(principal: &Principal) -> Result<rasn_kerberos::PrincipalName, TestError> {
    Ok(rasn_kerberos::PrincipalName {
        r#type: principal.name_type,
        string: principal
            .components
            .iter()
            .map(|component| text(component))
            .collect::<Result<_, _>>()?,
    })
}

/// A whole-second Kerberos time.
fn time(at: SystemTime) -> Result<rasn_kerberos::KerberosTime, TestError> {
    let seconds = at.duration_since(UNIX_EPOCH)?.as_secs();
    let utc = DateTime::<Utc>::from_timestamp(i64::try_from(seconds)?, 0).ok_or("time")?;
    Ok(rasn_kerberos::KerberosTime(
        utc.with_timezone(&FixedOffset::east_opt(0).ok_or("UTC")?),
    ))
}

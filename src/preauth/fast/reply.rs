//! Replies to armored requests (MIT `fast.c:359-567`).

use rasn::der;
use rasn_kerberos::{KrbError, PaData, PrincipalName, Realm};
use zeroize::Zeroizing;

use super::{
    KEY_USAGE_FAST_FINISHED, KEY_USAGE_FAST_REP, MAX_COOKIE_BYTES, PA_FX_COOKIE, PA_FX_ERROR,
    PA_FX_FAST,
    armor::Armor,
    asn1::{KrbFastResponse, PaFxFastReply},
    keys::{self, codec, encode},
};
use crate::{
    client::{principal::Principal, stepwise::ArmoredReply},
    error::Fast as Error,
    keytab::EncryptionKey,
    ticket,
};

/// Unwrap the reply to the armored request with `nonce`.
///
/// An AS-REP becomes the AS-REP with the authenticated client and the inner
/// padata; a KRB-ERROR becomes the inner `PA-FX-ERROR` with the inner padata
/// as its METHOD-DATA.
///
/// # Errors
/// Returns the FAST failure of the reply; nothing unauthenticated is passed on.
pub(super) fn unwrap(armor: &Armor, nonce: u32, bytes: &[u8]) -> Result<ArmoredReply, Error> {
    if let Ok(outer) = der::decode::<KrbError>(bytes) {
        return error_reply(armor, nonce, &outer);
    }
    let rasn_kerberos::AsRep(mut reply) = keys::decode("AS-REP", bytes)?;
    let response = fast_response(armor, nonce, reply.padata.as_deref().unwrap_or_default())?;
    let finished = response.finished.ok_or(Error::MissingFinished)?;
    let ticket_der = Zeroizing::new(
        ticket::encode(&reply.ticket).map_err(|error| codec("encode", "ticket", &error))?,
    );
    keys::verify(
        (armor.key(), KEY_USAGE_FAST_FINISHED),
        &ticket_der,
        &finished.ticket_checksum,
        Error::TicketChecksum,
    )?;
    let client = principal(&finished.crealm, &finished.cname)?;
    reply.crealm = finished.crealm;
    reply.cname = finished.cname;
    reply.padata = (!response.padata.is_empty()).then_some(response.padata);
    let strengthen_key = response
        .strengthen_key
        .map(|key| EncryptionKey::new(key.r#type, key.value.to_vec()));
    Ok(ArmoredReply::new(
        encode("AS-REP", &rasn_kerberos::AsRep(reply))?,
        strengthen_key,
        None,
    )
    .with_authenticated_client(client))
}

/// The inner error of an armored KRB-ERROR (RFC 6113 section 5.4.4).
///
/// # Errors
/// Returns [`Error::UnarmoredError`] for an error without `PA-FX-FAST`, and
/// the FAST failure of an armored one.
fn error_reply(armor: &Armor, nonce: u32, outer: &KrbError) -> Result<ArmoredReply, Error> {
    let unarmored = Error::UnarmoredError {
        code: outer.error_code,
    };
    let Some(e_data) = &outer.e_data else {
        return Err(unarmored);
    };
    let Ok(method_data) = der::decode::<Vec<PaData>>(e_data) else {
        return Err(unarmored);
    };
    if !method_data.iter().any(|entry| entry.r#type == PA_FX_FAST) {
        return Err(unarmored);
    }
    let response = fast_response(armor, nonce, &method_data)?;
    if response.strengthen_key.is_some() || response.finished.is_some() {
        return Err(Error::Malformed {
            structure: "KrbFastResponse",
            reason: "an error reply carries a strengthen key or a finished message",
        });
    }
    let fx_error = single(&response.padata, PA_FX_ERROR)?.ok_or(Error::Malformed {
        structure: "KrbFastResponse",
        reason: "an error reply carries no PA-FX-ERROR",
    })?;
    let mut inner: KrbError = keys::decode("PA-FX-ERROR", &fx_error.value)?;
    if inner.e_data.is_some() {
        return Err(Error::Malformed {
            structure: "PA-FX-ERROR",
            reason: "the inner error carries e-data",
        });
    }
    let cookie = cookie(&response.padata)?;
    let rest: Vec<PaData> = response
        .padata
        .into_iter()
        .filter(|entry| entry.r#type != PA_FX_ERROR)
        .collect();
    if !rest.is_empty() {
        inner.e_data = Some(encode("METHOD-DATA", &rest)?.to_vec().into());
    }
    Ok(ArmoredReply::new(
        encode("KRB-ERROR", &inner)?,
        None,
        cookie,
    ))
}

/// Decrypt the single `PA-FX-FAST` of `padata` and bind it to `nonce`.
///
/// # Errors
/// Returns [`Error::Unarmored`] without one, and the decryption, decoding,
/// nonce and cookie failures.
fn fast_response(armor: &Armor, nonce: u32, padata: &[PaData]) -> Result<KrbFastResponse, Error> {
    let entry = single(padata, PA_FX_FAST)?.ok_or(Error::Unarmored)?;
    let PaFxFastReply::ArmoredData(armored) = keys::decode("PA-FX-FAST-REPLY", &entry.value)?;
    let plain = keys::open(armor.key(), KEY_USAGE_FAST_REP, &armored.enc_fast_rep)?;
    let response: KrbFastResponse = keys::decode("KrbFastResponse", &plain)?;
    if response.nonce != nonce {
        return Err(Error::NonceMismatch {
            expected: nonce,
            actual: response.nonce,
        });
    }
    Ok(response)
}

/// The one entry of `pa_type` in `padata`, if any.
///
/// # Errors
/// Returns [`Error::Malformed`] when `pa_type` occurs twice.
fn single(padata: &[PaData], pa_type: i32) -> Result<Option<&PaData>, Error> {
    let mut entries = padata.iter().filter(|entry| entry.r#type == pa_type);
    let first = entries.next();
    if entries.next().is_some() {
        return Err(Error::Malformed {
            structure: "padata",
            reason: "a FAST padata type occurs twice",
        });
    }
    Ok(first)
}

/// The KDC's cookie, bounded.
///
/// # Errors
/// Returns [`Error::CookieTooLarge`] above [`MAX_COOKIE_BYTES`].
fn cookie(padata: &[PaData]) -> Result<Option<Vec<u8>>, Error> {
    let Some(entry) = single(padata, PA_FX_COOKIE)? else {
        return Ok(None);
    };
    if entry.value.len() > MAX_COOKIE_BYTES {
        return Err(Error::CookieTooLarge {
            limit: MAX_COOKIE_BYTES,
        });
    }
    Ok(Some(entry.value.to_vec()))
}

/// The authenticated client of a finished message.
///
/// # Errors
/// Returns [`Error::Codec`] for a name that is not UTF-8.
fn principal(realm: &Realm, name: &PrincipalName) -> Result<Principal, Error> {
    let text = |value: &rasn_kerberos::KerberosString| {
        String::from_utf8(value.as_bytes().to_vec())
            .map_err(|error| codec("decode", "KrbFastFinished client", &error))
    };
    Ok(Principal::new(
        text(realm)?,
        name.r#type,
        name.string
            .iter()
            .map(text)
            .collect::<Result<Vec<_>, _>>()?,
    ))
}

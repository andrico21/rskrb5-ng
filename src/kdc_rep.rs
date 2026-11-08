//! AS-REP/TGS-REP decoding and encrypted-part helpers.

use rasn::{der, types::Integer};

use crate::messages::secret_der::SecretDer;

/// Mapping of ticket validation errors into reply errors.
mod ticket_error;
use ticket_error::ticket_error;

use crate::{
    crypto::selection,
    der::{decode_complete, encrypted_der},
    error::Ticket as TicketError,
    keytab::EncryptionKey,
    ticket::validate as validate_ticket,
};

/// Kerberos protocol version number carried in every message (RFC 4120).
const KRB5_PVNO: i32 = 5;

/// AS-REP message type.
pub const KRB_AS_REP_MSG_TYPE: i32 = 11;

/// TGS-REP message type.
pub const KRB_TGS_REP_MSG_TYPE: i32 = 13;

/// Key usage for AS-REP encrypted parts.
pub const AS_REP_ENCPART_USAGE: u32 = 3;

/// Key usage for TGS-REP encrypted parts encrypted with the TGT session key.
pub const TGS_REP_ENCPART_SESSION_KEY_USAGE: u32 = 8;

/// Decode and validate a DER-encoded AS-REP message.
///
/// # Errors
///
/// Returns [`Error::Decode`] when `bytes` is not a DER AS-REP, and
/// [`Error::InvalidMessage`] when its protocol version, message type or ticket
/// version is wrong.
#[inline]
pub fn decode_as_rep(bytes: &[u8]) -> Result<rasn_kerberos::AsRep, Error> {
    let as_rep = decode::<rasn_kerberos::AsRep>("AS-REP", bytes)?;
    validate_as_rep(&as_rep)?;
    Ok(as_rep)
}

/// Validate AS-REP protocol version and message type on an already decoded value.
///
/// # Errors
///
/// Returns [`Error::InvalidMessage`] when the protocol version, message type
/// or ticket version is wrong.
#[inline]
pub fn validate_as_rep(as_rep: &rasn_kerberos::AsRep) -> Result<(), Error> {
    validate_kdc_rep(&as_rep.0, KRB_AS_REP_MSG_TYPE)
}

/// Encode an AS-REP message as DER.
///
/// # Errors
///
/// Returns [`Error::Encode`] when the DER encoder fails.
#[inline]
pub fn encode_as_rep(as_rep: &rasn_kerberos::AsRep) -> Result<Vec<u8>, Error> {
    encode("AS-REP", as_rep)
}

/// Decode and validate a DER-encoded TGS-REP message.
///
/// # Errors
///
/// Returns [`Error::Decode`] when `bytes` is not a DER TGS-REP, and
/// [`Error::InvalidMessage`] when its protocol version, message type or ticket
/// version is wrong.
#[inline]
pub fn decode_tgs_rep(bytes: &[u8]) -> Result<rasn_kerberos::TgsRep, Error> {
    let tgs_rep = decode::<rasn_kerberos::TgsRep>("TGS-REP", bytes)?;
    validate_tgs_rep(&tgs_rep)?;
    Ok(tgs_rep)
}

/// Validate TGS-REP protocol version and message type on an already decoded value.
///
/// # Errors
///
/// Returns [`Error::InvalidMessage`] when the protocol version, message type
/// or ticket version is wrong.
#[inline]
pub fn validate_tgs_rep(tgs_rep: &rasn_kerberos::TgsRep) -> Result<(), Error> {
    validate_kdc_rep(&tgs_rep.0, KRB_TGS_REP_MSG_TYPE)
}

/// Encode a TGS-REP message as DER.
///
/// # Errors
///
/// Returns [`Error::Encode`] when the DER encoder fails.
#[inline]
pub fn encode_tgs_rep(tgs_rep: &rasn_kerberos::TgsRep) -> Result<Vec<u8>, Error> {
    encode("TGS-REP", tgs_rep)
}

/// Decode a DER-encoded encrypted KDC reply part.
///
/// RFC 4120 defines separate application tags for AS-REP and TGS-REP
/// encrypted parts, but deployed KDCs sometimes use the TGS tag for both.
/// This accepts either tag, matching gokrb5's `EncKDCRepPart.Unmarshal`.
///
/// # Errors
///
/// Returns the AS-tag [`Error::Decode`] when `bytes` decodes under neither tag.
#[inline]
pub fn decode_enc_kdc_rep_part(bytes: &[u8]) -> Result<rasn_kerberos::EncKdcRepPart, Error> {
    match decode::<rasn_kerberos::EncAsRepPart>("EncAsRepPart", bytes) {
        Ok(enc_part) => Ok(enc_part.0),
        Err(as_rep_error) => match decode::<rasn_kerberos::EncTgsRepPart>("EncTgsRepPart", bytes) {
            Ok(enc_part) => Ok(enc_part.0),
            // Neither tag decodes: report the AS-tag failure.
            Err(_tgs_tag_error) => Err(as_rep_error),
        },
    }
}

/// Encode an encrypted KDC reply part with the AS-REP application tag.
///
/// # Errors
///
/// Returns [`Error::Encode`] when the DER encoder fails.
#[inline]
pub fn encode_enc_as_rep_part(enc_part: &rasn_kerberos::EncKdcRepPart) -> Result<Vec<u8>, Error> {
    encode(
        "EncAsRepPart",
        &rasn_kerberos::EncAsRepPart(enc_part.clone()),
    )
}

/// Encode an encrypted KDC reply part with the TGS-REP application tag.
///
/// # Errors
///
/// Returns [`Error::Encode`] when the DER encoder fails.
#[inline]
pub fn encode_enc_tgs_rep_part(enc_part: &rasn_kerberos::EncKdcRepPart) -> Result<Vec<u8>, Error> {
    encode(
        "EncTgsRepPart",
        &rasn_kerberos::EncTgsRepPart(enc_part.clone()),
    )
}

/// Decrypt and decode an AS-REP encrypted part.
///
/// # Errors
///
/// Returns [`Error::KeyEtypeMismatch`] when the key's enctype differs from the
/// encrypted part's, [`Error::UnsupportedEtype`] for an enctype that is not
/// implemented, [`Error::Crypto`] when decryption fails, and [`Error::Decode`]
/// when the plaintext is not a DER encrypted KDC reply part.
#[inline]
pub fn decrypt_as_rep_enc_part(
    as_rep: &rasn_kerberos::AsRep,
    key: &EncryptionKey,
) -> Result<rasn_kerberos::EncKdcRepPart, Error> {
    decrypt_kdc_rep_enc_part(&as_rep.0.enc_part, key, AS_REP_ENCPART_USAGE)
}

/// Decrypt and decode a TGS-REP encrypted part.
///
/// # Errors
///
/// Returns [`Error::KeyEtypeMismatch`] when the key's enctype differs from the
/// encrypted part's, [`Error::UnsupportedEtype`] for an enctype that is not
/// implemented, [`Error::Crypto`] when decryption fails, and [`Error::Decode`]
/// when the plaintext is not a DER encrypted KDC reply part.
#[inline]
pub fn decrypt_tgs_rep_enc_part(
    tgs_rep: &rasn_kerberos::TgsRep,
    key: &EncryptionKey,
) -> Result<rasn_kerberos::EncKdcRepPart, Error> {
    decrypt_kdc_rep_enc_part(&tgs_rep.0.enc_part, key, TGS_REP_ENCPART_SESSION_KEY_USAGE)
}

/// Encrypt an AS-REP encrypted part using a random confounder.
///
/// # Errors
///
/// Returns [`Error::UnsupportedEtype`] for a key whose enctype is not
/// implemented, [`Error::Random`] when the confounder cannot be generated, and
/// the errors of [`encrypt_as_rep_enc_part_with_confounder`].
#[inline]
pub fn encrypt_as_rep_enc_part(
    enc_part: &rasn_kerberos::EncKdcRepPart,
    key: &EncryptionKey,
    kvno: Option<u32>,
) -> Result<rasn_kerberos::EncryptedData, Error> {
    let etype = selection::enctype(key.etype)?.ok_or(Error::UnsupportedEtype(key.etype))?;
    let mut confounder = vec![0; etype.confounder_len()];
    getrandom::fill(&mut confounder)?;
    encrypt_as_rep_enc_part_with_confounder(enc_part, key, kvno, &confounder)
}

/// Encrypt an AS-REP encrypted part using an explicit confounder.
///
/// # Errors
///
/// Returns [`Error::Encode`] when the encrypted part cannot be encoded,
/// [`Error::UnsupportedEtype`] for a key whose enctype is not implemented, and
/// [`Error::Crypto`] when encryption fails.
#[inline]
pub fn encrypt_as_rep_enc_part_with_confounder(
    enc_part: &rasn_kerberos::EncKdcRepPart,
    key: &EncryptionKey,
    kvno: Option<u32>,
    confounder: &[u8],
) -> Result<rasn_kerberos::EncryptedData, Error> {
    selection::reject_enctype(key.etype)?;
    encrypt_kdc_rep_enc_part(
        &SecretDer::new(encode_enc_as_rep_part(enc_part)?, "as-rep encode"),
        key,
        kvno,
        AS_REP_ENCPART_USAGE,
        confounder,
    )
}

/// Encrypt a TGS-REP encrypted part using a random confounder.
///
/// # Errors
///
/// Returns [`Error::UnsupportedEtype`] for a key whose enctype is not
/// implemented, [`Error::Random`] when the confounder cannot be generated, and
/// the errors of [`encrypt_tgs_rep_enc_part_with_confounder`].
#[inline]
pub fn encrypt_tgs_rep_enc_part(
    enc_part: &rasn_kerberos::EncKdcRepPart,
    key: &EncryptionKey,
    kvno: Option<u32>,
) -> Result<rasn_kerberos::EncryptedData, Error> {
    let etype = selection::enctype(key.etype)?.ok_or(Error::UnsupportedEtype(key.etype))?;
    let mut confounder = vec![0; etype.confounder_len()];
    getrandom::fill(&mut confounder)?;
    encrypt_tgs_rep_enc_part_with_confounder(enc_part, key, kvno, &confounder)
}

/// Encrypt a TGS-REP encrypted part using an explicit confounder.
///
/// # Errors
///
/// Returns [`Error::Encode`] when the encrypted part cannot be encoded,
/// [`Error::UnsupportedEtype`] for a key whose enctype is not implemented, and
/// [`Error::Crypto`] when encryption fails.
#[inline]
pub fn encrypt_tgs_rep_enc_part_with_confounder(
    enc_part: &rasn_kerberos::EncKdcRepPart,
    key: &EncryptionKey,
    kvno: Option<u32>,
    confounder: &[u8],
) -> Result<rasn_kerberos::EncryptedData, Error> {
    selection::reject_enctype(key.etype)?;
    encrypt_kdc_rep_enc_part(
        &SecretDer::new(encode_enc_tgs_rep_part(enc_part)?, "tgs-rep encode"),
        key,
        kvno,
        TGS_REP_ENCPART_SESSION_KEY_USAGE,
        confounder,
    )
}

/// Check a KDC reply's protocol version, message type and ticket version.
///
/// # Errors
///
/// Returns [`Error::InvalidMessage`] when the protocol version, message type
/// or ticket version is wrong.
fn validate_kdc_rep(kdc_rep: &rasn_kerberos::KdcRep, msg_type: i32) -> Result<(), Error> {
    validate_integer("pvno", &kdc_rep.pvno, KRB5_PVNO)?;
    validate_integer("msg-type", &kdc_rep.msg_type, msg_type)?;
    validate_ticket(&kdc_rep.ticket).map_err(ticket_error)
}

/// Decrypt an encrypted KDC reply part with `key` and decode it under either tag.
///
/// # Errors
///
/// Returns [`Error::KeyEtypeMismatch`] when the key's enctype differs from the
/// encrypted part's, [`Error::UnsupportedEtype`] for an enctype that is not
/// implemented, [`Error::Crypto`] when decryption fails, and [`Error::Decode`]
/// when the plaintext is not a DER encrypted KDC reply part.
pub(crate) fn decrypt_kdc_rep_enc_part(
    encrypted_data: &rasn_kerberos::EncryptedData,
    key: &EncryptionKey,
    usage: u32,
) -> Result<rasn_kerberos::EncKdcRepPart, Error> {
    if key.etype != encrypted_data.etype {
        return Err(Error::KeyEtypeMismatch {
            key_etype: key.etype,
            encrypted_data_etype: encrypted_data.etype,
        });
    }
    let etype = selection::enctype(key.etype)?.ok_or(Error::UnsupportedEtype(key.etype))?;
    let plaintext = SecretDer::new(
        etype.decrypt_message(&key.value, encrypted_data.cipher.as_ref(), usage)?,
        "kdc-rep decrypt",
    );
    decode_enc_kdc_rep_part(encrypted_der(&plaintext, key.etype))
}

/// Encrypt an encoded KDC reply part into `EncryptedData` with `key`.
///
/// # Errors
///
/// Returns [`Error::UnsupportedEtype`] for a key whose enctype is not
/// implemented, and [`Error::Crypto`] when encryption fails.
fn encrypt_kdc_rep_enc_part(
    plaintext: &[u8],
    key: &EncryptionKey,
    kvno: Option<u32>,
    usage: u32,
    confounder: &[u8],
) -> Result<rasn_kerberos::EncryptedData, Error> {
    let etype = selection::enctype(key.etype)?.ok_or(Error::UnsupportedEtype(key.etype))?;
    let cipher = etype.encrypt_message_with_confounder(&key.value, plaintext, usage, confounder)?;
    Ok(rasn_kerberos::EncryptedData {
        etype: key.etype,
        kvno,
        cipher: cipher.into(),
    })
}

/// Decode a DER value with a typed error.
///
/// # Errors
///
/// Returns [`Error::Decode`] naming `target` when `bytes` is not valid DER for
/// `T`.
fn decode<T>(target: &'static str, bytes: &[u8]) -> Result<T, Error>
where
    T: rasn::Decode,
{
    decode_complete(bytes).map_err(|source| Error::Decode {
        target,
        message: source,
    })
}

/// Encode a value to DER with a typed error.
///
/// # Errors
///
/// Returns [`Error::Encode`] naming `target` when the DER encoder fails.
fn encode<T>(target: &'static str, value: &T) -> Result<Vec<u8>, Error>
where
    T: rasn::Encode,
{
    der::encode(value).map_err(|source| Error::Encode {
        target,
        message: source.to_string(),
    })
}

/// Check that a decoded protocol integer such as `pvno` equals `expected`.
///
/// # Errors
///
/// Returns [`Error::InvalidMessage`] naming `field` when the value differs.
fn validate_integer(field: &'static str, actual: &Integer, expected: i32) -> Result<(), Error> {
    if actual != &Integer::from(expected) {
        return Err(Error::InvalidMessage {
            field,
            expected,
            actual: actual.to_string(),
        });
    }
    Ok(())
}

use crate::error::KdcRep as Error;

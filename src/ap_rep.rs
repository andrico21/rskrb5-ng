//! AP-REP decoding and encrypted-part helpers.

use rasn::{der, types::Integer};
use zeroize::Zeroizing;

use crate::{
    crypto::selection,
    der::{decode_complete, encrypted_der},
    keytab::EncryptionKey,
    messages::secret_der::SecretDer,
};

/// Kerberos protocol version number carried in every message (RFC 4120).
const KRB5_PVNO: i32 = 5;

/// AP-REP message type.
pub const KRB_AP_REP_MSG_TYPE: i32 = 15;

/// Key usage for AP-REP encrypted parts.
pub const AP_REP_ENCPART_USAGE: u32 = 12;

/// Decode and validate a DER-encoded AP-REP message.
///
/// # Errors
///
/// Returns [`Error::Decode`] when `bytes` is not a DER AP-REP, and
/// [`Error::InvalidMessage`] when its protocol version or message type is wrong.
#[inline]
pub fn decode(bytes: &[u8]) -> Result<rasn_kerberos::ApRep, Error> {
    let ap_rep = decode_der::<rasn_kerberos::ApRep>("AP-REP", bytes)?;
    validate(&ap_rep)?;
    Ok(ap_rep)
}

/// Validate AP-REP protocol version and message type on an already decoded value.
///
/// # Errors
///
/// Returns [`Error::InvalidMessage`] when the protocol version or message type
/// is wrong.
#[inline]
pub fn validate(ap_rep: &rasn_kerberos::ApRep) -> Result<(), Error> {
    validate_integer("pvno", &ap_rep.pvno, KRB5_PVNO)?;
    validate_integer("msg-type", &ap_rep.msg_type, KRB_AP_REP_MSG_TYPE)
}

/// Encode an AP-REP message as DER.
///
/// # Errors
///
/// Returns [`Error::Encode`] when the DER encoder fails.
#[inline]
pub fn encode(ap_rep: &rasn_kerberos::ApRep) -> Result<Vec<u8>, Error> {
    encode_der("AP-REP", ap_rep)
}

/// Decode a DER-encoded `EncAPRepPart`.
///
/// # Errors
///
/// Returns [`Error::Decode`] when `bytes` is not a DER `EncAPRepPart`.
#[inline]
pub fn decode_enc_ap_rep_part(bytes: &[u8]) -> Result<rasn_kerberos::EncApRepPart, Error> {
    decode_der::<rasn_kerberos::EncApRepPart>("EncApRepPart", bytes)
}

/// Decrypt and decode an AP-REP encrypted part.
///
/// # Errors
///
/// Returns [`Error::KeyEtypeMismatch`] when the key's enctype differs from the
/// encrypted part's, [`Error::UnsupportedEtype`] for an enctype that is not
/// implemented, [`Error::Crypto`] when decryption fails, and [`Error::Decode`]
/// when the plaintext is not a DER `EncAPRepPart`.
#[inline]
pub fn decrypt_ap_rep_enc_part(
    ap_rep: &rasn_kerberos::ApRep,
    key: &EncryptionKey,
) -> Result<rasn_kerberos::EncApRepPart, Error> {
    if key.etype() != ap_rep.enc_part.etype {
        return Err(Error::KeyEtypeMismatch {
            key_etype: key.etype(),
            encrypted_data_etype: ap_rep.enc_part.etype,
        });
    }
    let etype =
        selection::enctype(key.etype())?.ok_or_else(|| Error::UnsupportedEtype(key.etype()))?;
    let plaintext = SecretDer::new(
        etype.decrypt_message(
            key.value(),
            ap_rep.enc_part.cipher.as_ref(),
            AP_REP_ENCPART_USAGE,
        )?,
        "ap-rep decrypt",
    );
    decode_enc_ap_rep_part(encrypted_der(&plaintext, key.etype()))
}

/// Build an AP-REP message using a random confounder.
///
/// # Errors
///
/// Returns [`Error::UnsupportedEtype`] for a key whose enctype is not
/// implemented, [`Error::Random`] when the confounder cannot be generated, and
/// the errors of [`build_ap_rep_with_confounder`].
#[inline]
pub fn build(
    enc_part: &rasn_kerberos::EncApRepPart,
    key: &EncryptionKey,
    kvno: Option<u32>,
) -> Result<rasn_kerberos::ApRep, Error> {
    let etype =
        selection::enctype(key.etype())?.ok_or_else(|| Error::UnsupportedEtype(key.etype()))?;
    let mut confounder = Zeroizing::new(vec![0; etype.confounder_len()]);
    getrandom::fill(&mut confounder)?;
    build_ap_rep_with_confounder(enc_part, key, kvno, &confounder)
}

/// Build an AP-REP message using an explicit confounder.
///
/// # Errors
///
/// Returns [`Error::Encode`] when the encrypted part cannot be encoded,
/// [`Error::UnsupportedEtype`] for a key whose enctype is not implemented, and
/// [`Error::Crypto`] when encryption fails.
#[inline]
pub fn build_ap_rep_with_confounder(
    enc_part: &rasn_kerberos::EncApRepPart,
    key: &EncryptionKey,
    kvno: Option<u32>,
    confounder: &[u8],
) -> Result<rasn_kerberos::ApRep, Error> {
    let etype =
        selection::enctype(key.etype())?.ok_or_else(|| Error::UnsupportedEtype(key.etype()))?;
    let plaintext = SecretDer::new(encode_der("EncApRepPart", enc_part)?, "ap-rep encode");
    let cipher = etype.encrypt_message_with_confounder(
        key.value(),
        &plaintext,
        AP_REP_ENCPART_USAGE,
        confounder,
    )?;
    Ok(rasn_kerberos::ApRep {
        pvno: Integer::from(KRB5_PVNO),
        msg_type: Integer::from(KRB_AP_REP_MSG_TYPE),
        enc_part: rasn_kerberos::EncryptedData {
            etype: key.etype(),
            kvno,
            cipher: cipher.into(),
        },
    })
}

/// Encode an AP-REP message built using a random confounder.
///
/// # Errors
///
/// Returns the errors of [`build`] and [`Error::Encode`] when the AP-REP
/// cannot be encoded.
#[inline]
pub fn build_encoded(
    enc_part: &rasn_kerberos::EncApRepPart,
    key: &EncryptionKey,
    kvno: Option<u32>,
) -> Result<Vec<u8>, Error> {
    let ap_rep = build(enc_part, key, kvno)?;
    encode(&ap_rep)
}

/// Encode an AP-REP message built using an explicit confounder.
///
/// # Errors
///
/// Returns the errors of [`build_ap_rep_with_confounder`] and
/// [`Error::Encode`] when the AP-REP cannot be encoded.
#[inline]
pub fn encode_build_ap_rep_with_confounder(
    enc_part: &rasn_kerberos::EncApRepPart,
    key: &EncryptionKey,
    kvno: Option<u32>,
    confounder: &[u8],
) -> Result<Vec<u8>, Error> {
    let ap_rep = build_ap_rep_with_confounder(enc_part, key, kvno, confounder)?;
    encode(&ap_rep)
}

/// Decode a DER value with a typed error.
///
/// # Errors
///
/// Returns [`Error::Decode`] naming `target` when `bytes` is not valid DER for
/// `T`.
fn decode_der<T>(target: &'static str, bytes: &[u8]) -> Result<T, Error>
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
fn encode_der<T>(target: &'static str, value: &T) -> Result<Vec<u8>, Error>
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

use crate::error::ApRep as Error;

//! KRB-SAFE decoding and checksum helpers.

use rasn::{der, types::Integer};

use crate::{crypto::selection, der::decode_complete, keytab::EncryptionKey};

/// Kerberos protocol version number carried in every message (RFC 4120).
const KRB5_PVNO: i32 = 5;

/// KRB-SAFE message type.
pub const KRB_SAFE_MSG_TYPE: i32 = 20;

/// Key usage for KRB-SAFE checksums.
pub const KRB_SAFE_CHECKSUM_USAGE: u32 = 15;

/// Decode and validate a DER-encoded KRB-SAFE message.
///
/// # Errors
///
/// Returns [`Error::Decode`] when `bytes` is not a DER KRB-SAFE, and
/// [`Error::InvalidMessage`] when its protocol version or message type is wrong.
#[inline]
pub fn decode(bytes: &[u8]) -> Result<rasn_kerberos::KrbSafe, Error> {
    let krb_safe = decode_der::<rasn_kerberos::KrbSafe>("KRB-SAFE", bytes)?;
    validate_integer("pvno", &krb_safe.pvno, KRB5_PVNO)?;
    validate_integer("msg-type", &krb_safe.msg_type, KRB_SAFE_MSG_TYPE)?;
    Ok(krb_safe)
}

/// Encode a KRB-SAFE message as DER.
///
/// # Errors
///
/// Returns [`Error::Encode`] when the DER encoder fails.
#[inline]
pub fn encode(krb_safe: &rasn_kerberos::KrbSafe) -> Result<Vec<u8>, Error> {
    encode_der("KRB-SAFE", krb_safe)
}

/// Build a KRB-SAFE message with the RFC 4120 whole-message keyed checksum.
///
/// # Errors
///
/// Returns the errors of [`checksum`].
#[inline]
pub fn build(
    body: rasn_kerberos::KrbSafeBody,
    key: &EncryptionKey,
) -> Result<rasn_kerberos::KrbSafe, Error> {
    let cksum = checksum(&body, key)?;
    Ok(rasn_kerberos::KrbSafe {
        pvno: Integer::from(KRB5_PVNO),
        msg_type: Integer::from(KRB_SAFE_MSG_TYPE),
        body,
        cksum,
    })
}

/// Compute the RFC 4120 checksum for a body in a version-5 KRB-SAFE message.
///
/// # Errors
///
/// Returns [`Error::UnsupportedEtype`] for a key whose enctype is not
/// implemented, [`Error::Encode`] when the body cannot be encoded, and
/// [`Error::Crypto`] when the checksum cannot be computed.
#[inline]
pub fn checksum(
    body: &rasn_kerberos::KrbSafeBody,
    key: &EncryptionKey,
) -> Result<rasn_kerberos::Checksum, Error> {
    let etype =
        selection::enctype(key.etype())?.ok_or_else(|| Error::UnsupportedEtype(key.etype()))?;
    let input = checksum_input(
        body,
        &Integer::from(KRB5_PVNO),
        &Integer::from(KRB_SAFE_MSG_TYPE),
    )?;
    Ok(rasn_kerberos::Checksum {
        r#type: etype.checksum_type_id(),
        checksum: etype
            .checksum(key.value(), &input, KRB_SAFE_CHECKSUM_USAGE)?
            .into(),
    })
}

/// Verify the keyed checksum in a KRB-SAFE message.
///
/// # Errors
///
/// Returns [`Error::UnsupportedChecksumType`] for a checksum type that is not
/// implemented, [`Error::KeyChecksumTypeMismatch`] when the key's enctype does
/// not match the checksum type, [`Error::Encode`] when the body cannot be
/// encoded, and [`Error::ChecksumMismatch`] when the checksum does not verify.
#[inline]
pub fn verify_krb_safe_checksum(
    krb_safe: &rasn_kerberos::KrbSafe,
    key: &EncryptionKey,
) -> Result<(), Error> {
    let etype = selection::checksum(krb_safe.cksum.r#type)?
        .ok_or(Error::UnsupportedChecksumType(krb_safe.cksum.r#type))?;
    if etype.etype_id() != key.etype() {
        return Err(Error::KeyChecksumTypeMismatch {
            key_etype: key.etype(),
            checksum_type: krb_safe.cksum.r#type,
        });
    }
    let input = checksum_input(&krb_safe.body, &krb_safe.pvno, &krb_safe.msg_type)?;
    if !etype.verify_checksum(
        key.value(),
        &input,
        krb_safe.cksum.checksum.as_ref(),
        KRB_SAFE_CHECKSUM_USAGE,
    ) {
        return Err(Error::ChecksumMismatch);
    }
    Ok(())
}

/// Encode the whole message with the RFC 4120 section 5.6.1 checksum placeholder.
///
/// # Errors
///
/// Returns [`Error::Encode`] when the message cannot be DER-encoded.
fn checksum_input(
    body: &rasn_kerberos::KrbSafeBody,
    pvno: &Integer,
    msg_type: &Integer,
) -> Result<Vec<u8>, Error> {
    encode_der(
        "KRB-SAFE",
        &rasn_kerberos::KrbSafe {
            pvno: pvno.clone(),
            msg_type: msg_type.clone(),
            body: body.clone(),
            cksum: rasn_kerberos::Checksum {
                r#type: 0,
                checksum: Vec::new().into(),
            },
        },
    )
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

use crate::error::KrbSafe as Error;

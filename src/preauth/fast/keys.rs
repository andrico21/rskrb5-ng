//! Key combination, encryption and checksums under FAST keys.

use core::fmt::Display;

use rasn::der;
use rasn_kerberos::{Checksum, EncryptedData};
use zeroize::Zeroizing;

use crate::{
    crypto::{KerberosEtype, prf, selection},
    error::{Crypto, Fast as Error},
    keytab::EncryptionKey,
};

/// The implemented enctype `id`, refusing permanently forbidden ones.
///
/// # Errors
/// Returns the D2 refusal or [`Error::UnsupportedEtype`].
pub(crate) fn etype(id: i32) -> Result<KerberosEtype, Error> {
    selection::enctype(id)
        .map_err(Crypto::from)?
        .ok_or(Error::UnsupportedEtype(id))
}

/// `KRB-FX-CF2(first, second, first_pepper, second_pepper)` (RFC 6113
/// section 5.1); the result has `first`'s enctype.
///
/// # Errors
/// Returns the enctype and PRF errors.
pub(crate) fn cf2(
    (first, first_pepper): (&EncryptionKey, &[u8]),
    (second, second_pepper): (&EncryptionKey, &[u8]),
) -> Result<EncryptionKey, Error> {
    let combined = prf::krb_fx_cf2(
        &prf::CfInput::new(
            prf::Key::new(etype(first.etype())?, first.value()),
            first_pepper,
        ),
        &prf::CfInput::new(
            prf::Key::new(etype(second.etype())?, second.value()),
            second_pepper,
        ),
    )?;
    Ok(EncryptionKey::new(first.etype(), combined.to_vec()))
}

/// Encrypt `plaintext` in `key` for `usage` with a fresh confounder.
///
/// # Errors
/// Returns the enctype, random-source and cipher errors.
pub(crate) fn seal(
    key: &EncryptionKey,
    usage: u32,
    plaintext: &[u8],
) -> Result<EncryptedData, Error> {
    let cipher = etype(key.etype())?;
    let mut confounder = Zeroizing::new(vec![0; cipher.confounder_len()]);
    getrandom::fill(&mut confounder).map_err(Error::Random)?;
    let sealed =
        cipher.encrypt_message_with_confounder(key.value(), plaintext, usage, &confounder)?;
    Ok(EncryptedData {
        etype: key.etype(),
        kvno: None,
        cipher: sealed.into(),
    })
}

/// Decrypt and authenticate `encrypted` in `key` for `usage`.
///
/// # Errors
/// Returns [`Error::Malformed`] for another enctype, and the cipher errors.
pub(crate) fn open(
    key: &EncryptionKey,
    usage: u32,
    encrypted: &EncryptedData,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if encrypted.etype != key.etype() {
        return Err(Error::Malformed {
            structure: "EncryptedData",
            reason: "the enctype is not the key's",
        });
    }
    let cipher = etype(key.etype())?;
    Ok(Zeroizing::new(cipher.decrypt_message(
        key.value(),
        &encrypted.cipher,
        usage,
    )?))
}

/// The keyed checksum of `data` in `key`'s mandatory checksum type.
///
/// # Errors
/// Returns the enctype and checksum errors.
pub(crate) fn checksum(key: &EncryptionKey, usage: u32, data: &[u8]) -> Result<Checksum, Error> {
    let cipher = etype(key.etype())?;
    Ok(Checksum {
        r#type: cipher.checksum_type_id(),
        checksum: cipher.checksum(key.value(), data, usage)?.into(),
    })
}

/// Verify `checksum` over `data`: it must have `key`'s mandatory checksum type
/// (as the A7 rule demands of the enc-pa-rep checksum) and match.
///
/// # Errors
/// Returns [`Error::ChecksumType`] for another type and `mismatch` when it fails.
pub(crate) fn verify(
    (key, usage): (&EncryptionKey, u32),
    data: &[u8],
    checksum: &Checksum,
    mismatch: Error,
) -> Result<(), Error> {
    let cipher = etype(key.etype())?;
    selection::reject_checksum(checksum.r#type).map_err(Crypto::from)?;
    if checksum.r#type != cipher.checksum_type_id() {
        return Err(Error::ChecksumType {
            expected: cipher.checksum_type_id(),
            actual: checksum.r#type,
        });
    }
    if cipher.verify_checksum(key.value(), data, &checksum.checksum, usage) {
        Ok(())
    } else {
        Err(mismatch)
    }
}

/// A codec failure.
pub(crate) fn codec(action: &'static str, target: &'static str, error: &dyn Display) -> Error {
    Error::Codec {
        action,
        target,
        message: error.to_string(),
    }
}

/// The DER encoding of `value`, owned by an erasing buffer.
///
/// # Errors
/// Returns [`Error::Codec`] for the encoder's failure.
pub(crate) fn encode<T>(target: &'static str, value: &T) -> Result<Zeroizing<Vec<u8>>, Error>
where
    T: rasn::Encode,
{
    der::encode(value)
        .map(Zeroizing::new)
        .map_err(|error| codec("encode", target, &error))
}

/// Decode `target` from DER `bytes`.
///
/// # Errors
/// Returns [`Error::Codec`] for the decoder's failure.
pub(crate) fn decode<T>(target: &'static str, bytes: &[u8]) -> Result<T, Error>
where
    T: rasn::Decode,
{
    der::decode(bytes).map_err(|error| codec("decode", target, &error))
}

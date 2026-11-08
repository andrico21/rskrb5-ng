//! AP-REQ decoding and authenticator helpers.

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

/// AP-REQ message type.
pub const KRB_AP_REQ_MSG_TYPE: i32 = 14;

/// Key usage for TGS-REQ AP-REQ authenticators.
pub const TGS_REQ_AP_REQ_AUTHENTICATOR_USAGE: u32 = 7;

/// Key usage for normal AP-REQ authenticators.
pub const AP_REQ_AUTHENTICATOR_USAGE: u32 = 11;

/// Decode and validate a DER-encoded AP-REQ message.
///
/// # Errors
///
/// Returns [`Error::Decode`] when `bytes` is not a DER AP-REQ, and
/// [`Error::InvalidMessage`] when its protocol version or message type is wrong.
#[inline]
pub fn decode(bytes: &[u8]) -> Result<rasn_kerberos::ApReq, Error> {
    let ap_req = decode_der::<rasn_kerberos::ApReq>("AP-REQ", bytes)?;
    validate(&ap_req)?;
    Ok(ap_req)
}

/// Validate AP-REQ protocol version and message type on an already decoded value.
///
/// # Errors
///
/// Returns [`Error::InvalidMessage`] when the protocol version or message type
/// is wrong.
#[inline]
pub fn validate(ap_req: &rasn_kerberos::ApReq) -> Result<(), Error> {
    validate_integer("pvno", &ap_req.pvno, KRB5_PVNO)?;
    validate_integer("msg-type", &ap_req.msg_type, KRB_AP_REQ_MSG_TYPE)
}

/// Encode an AP-REQ message as DER.
///
/// # Errors
///
/// Returns [`Error::Encode`] when the DER encoder fails.
#[inline]
pub fn encode(ap_req: &rasn_kerberos::ApReq) -> Result<Vec<u8>, Error> {
    encode_der("AP-REQ", ap_req)
}

/// Decode a DER-encoded Authenticator.
///
/// # Errors
///
/// Returns [`Error::Decode`] when `bytes` is not a DER Authenticator, and
/// [`Error::InvalidMessage`] when its authenticator version is not 5.
#[inline]
pub fn decode_authenticator(bytes: &[u8]) -> Result<rasn_kerberos::Authenticator, Error> {
    let authenticator = decode_der::<rasn_kerberos::Authenticator>("Authenticator", bytes)?;
    validate_integer(
        "authenticator-vno",
        &authenticator.authenticator_vno,
        KRB5_PVNO,
    )?;
    Ok(authenticator)
}

/// Encode an Authenticator as DER.
///
/// # Errors
///
/// Returns [`Error::Encode`] when the DER encoder fails.
#[inline]
pub fn encode_authenticator(
    authenticator: &rasn_kerberos::Authenticator,
) -> Result<Vec<u8>, Error> {
    encode_der("Authenticator", authenticator)
}

/// Decrypt and decode an AP-REQ authenticator with an explicit key usage.
///
/// # Errors
///
/// Returns [`Error::KeyEtypeMismatch`] when the key's enctype differs from the
/// authenticator's, [`Error::UnsupportedEtype`] for an enctype that is not
/// implemented, [`Error::Crypto`] when decryption fails, and [`Error::Decode`]
/// when the plaintext is not a DER Authenticator.
#[inline]
pub fn decrypt_ap_req_authenticator(
    ap_req: &rasn_kerberos::ApReq,
    key: &EncryptionKey,
    usage: u32,
) -> Result<rasn_kerberos::Authenticator, Error> {
    if key.etype != ap_req.authenticator.etype {
        return Err(Error::KeyEtypeMismatch {
            key_etype: key.etype,
            encrypted_data_etype: ap_req.authenticator.etype,
        });
    }
    let etype = selection::enctype(key.etype)?.ok_or(Error::UnsupportedEtype(key.etype))?;
    let plaintext = SecretDer::new(
        etype.decrypt_message(&key.value, ap_req.authenticator.cipher.as_ref(), usage)?,
        "ap-req decrypt",
    );
    decode_authenticator(encrypted_der(&plaintext, key.etype))
}

/// Return the AP-REQ authenticator key usage implied by the ticket service.
#[inline]
pub fn authenticator_usage_for_ticket(ticket: &rasn_kerberos::Ticket) -> u32 {
    if ticket
        .sname
        .string
        .first()
        .is_some_and(|component| component.as_bytes() == b"krbtgt")
    {
        TGS_REQ_AP_REQ_AUTHENTICATOR_USAGE
    } else {
        AP_REQ_AUTHENTICATOR_USAGE
    }
}

#[must_use]
/// Convert a raw AP option bit mask into Kerberos AP options.
#[inline]
pub fn ap_options_from_bits(bits: u32) -> rasn_kerberos::ApOptions {
    rasn_kerberos::ApOptions(rasn_kerberos::KerberosFlags::from_slice(
        &bits.to_be_bytes(),
    ))
}

#[must_use]
/// Convert Kerberos AP options into a raw 32-bit mask.
#[inline]
pub fn ap_options_to_bits(ap_options: &rasn_kerberos::ApOptions) -> u32 {
    let raw = ap_options.0.as_raw_slice();
    u32::from_be_bytes([
        raw.first().copied().unwrap_or_default(),
        raw.get(1).copied().unwrap_or_default(),
        raw.get(2).copied().unwrap_or_default(),
        raw.get(3).copied().unwrap_or_default(),
    ])
}

/// Build an AP-REQ message using a random confounder.
///
/// # Errors
///
/// Returns [`Error::UnsupportedEtype`] for a key whose enctype is not
/// implemented, [`Error::Random`] when the confounder cannot be generated, and
/// the errors of [`build_ap_req_with_confounder`].
#[inline]
pub fn build(
    ticket: rasn_kerberos::Ticket,
    ap_options: rasn_kerberos::ApOptions,
    authenticator: &rasn_kerberos::Authenticator,
    key: &EncryptionKey,
    usage: u32,
    kvno: Option<u32>,
) -> Result<rasn_kerberos::ApReq, Error> {
    let etype = selection::enctype(key.etype)?.ok_or(Error::UnsupportedEtype(key.etype))?;
    let mut confounder = Zeroizing::new(vec![0; etype.confounder_len()]);
    getrandom::fill(&mut confounder)?;
    build_ap_req_with_confounder(
        ticket,
        ap_options,
        authenticator,
        key,
        usage,
        kvno,
        &confounder,
    )
}

/// Build an AP-REQ message using an explicit confounder.
///
/// # Errors
///
/// Returns [`Error::Encode`] when the authenticator cannot be encoded,
/// [`Error::UnsupportedEtype`] for a key whose enctype is not implemented, and
/// [`Error::Crypto`] when encryption fails.
#[inline]
pub fn build_ap_req_with_confounder(
    ticket: rasn_kerberos::Ticket,
    ap_options: rasn_kerberos::ApOptions,
    authenticator: &rasn_kerberos::Authenticator,
    key: &EncryptionKey,
    usage: u32,
    kvno: Option<u32>,
    confounder: &[u8],
) -> Result<rasn_kerberos::ApReq, Error> {
    let etype = selection::enctype(key.etype)?.ok_or(Error::UnsupportedEtype(key.etype))?;
    let plaintext = SecretDer::new(encode_authenticator(authenticator)?, "ap-req encode");
    let cipher =
        etype.encrypt_message_with_confounder(&key.value, &plaintext, usage, confounder)?;
    Ok(rasn_kerberos::ApReq {
        pvno: Integer::from(KRB5_PVNO),
        msg_type: Integer::from(KRB_AP_REQ_MSG_TYPE),
        ap_options,
        ticket,
        authenticator: rasn_kerberos::EncryptedData {
            etype: key.etype,
            kvno,
            cipher: cipher.into(),
        },
    })
}

/// Encode an AP-REQ message built using a random confounder.
///
/// # Errors
///
/// Returns the errors of [`build`] and [`Error::Encode`] when the AP-REQ
/// cannot be encoded.
#[inline]
pub fn build_encoded(
    ticket: rasn_kerberos::Ticket,
    ap_options: rasn_kerberos::ApOptions,
    authenticator: &rasn_kerberos::Authenticator,
    key: &EncryptionKey,
    usage: u32,
    kvno: Option<u32>,
) -> Result<Vec<u8>, Error> {
    let ap_req = build(ticket, ap_options, authenticator, key, usage, kvno)?;
    encode(&ap_req)
}

/// Encode an AP-REQ message built using an explicit confounder.
///
/// # Errors
///
/// Returns the errors of [`build_ap_req_with_confounder`] and
/// [`Error::Encode`] when the AP-REQ cannot be encoded.
#[inline]
pub fn encode_build_ap_req_with_confounder(
    ticket: rasn_kerberos::Ticket,
    ap_options: rasn_kerberos::ApOptions,
    authenticator: &rasn_kerberos::Authenticator,
    key: &EncryptionKey,
    usage: u32,
    kvno: Option<u32>,
    confounder: &[u8],
) -> Result<Vec<u8>, Error> {
    let ap_req = build_ap_req_with_confounder(
        ticket,
        ap_options,
        authenticator,
        key,
        usage,
        kvno,
        confounder,
    )?;
    encode(&ap_req)
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

use crate::error::ApReq as Error;

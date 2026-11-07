//! KRB-ERROR decoding and METHOD-DATA helpers.

use rasn::der;

use crate::{der::decode_complete, error::Messages as MessagesError, messages::KrbErrorInfo};

/// Kerberos protocol version.
pub const KRB5_PVNO: i32 = 5;

/// KRB-ERROR message type.
pub const KRB_ERROR_MSG_TYPE: i32 = 30;

/// Decode and validate a DER-encoded KRB-ERROR message.
///
/// # Errors
///
/// Returns [`Error::Decode`] when `bytes` is not a DER KRB-ERROR, and the
/// errors of [`validate`].
#[inline]
pub fn decode(bytes: &[u8]) -> Result<rasn_kerberos::KrbError, Error> {
    let krb_error = decode_der::<rasn_kerberos::KrbError>("KRB-ERROR", bytes)?;
    validate(&krb_error)?;
    Ok(krb_error)
}

/// Validate KRB-ERROR protocol version, message type, and diagnostic fields.
///
/// # Errors
///
/// Returns [`Error::InvalidMessage`] when the protocol version or message type
/// is wrong or a Kerberos time is fractional, [`Error::IntegerOutOfRange`] when
/// `cusec` or `susec` is outside `0..=999_999`, and [`Error::InvalidString`]
/// when a name, realm or `e-text` is not UTF-8,
/// and [`Error::TimeOverflow`] when `ctime` or `stime` does not fit a
/// `SystemTime`.
#[inline]
pub fn validate(krb_error: &rasn_kerberos::KrbError) -> Result<(), Error> {
    info(krb_error).map(|_| ())
}

/// Encode a KRB-ERROR message as DER.
///
/// # Errors
///
/// Returns [`Error::Encode`] when the DER encoder fails.
#[inline]
pub fn encode(krb_error: &rasn_kerberos::KrbError) -> Result<Vec<u8>, Error> {
    encode_der("KRB-ERROR", krb_error)
}

/// Decode a DER-encoded KRB-ERROR directly into diagnostic fields.
///
/// # Errors
///
/// Returns the errors of [`decode`].
#[inline]
pub fn decode_krb_error_info(bytes: &[u8]) -> Result<KrbErrorInfo, Error> {
    let krb_error = decode(bytes)?;
    info(&krb_error)
}

/// Build diagnostic fields from a decoded KRB-ERROR.
///
/// # Errors
///
/// Returns [`Error::InvalidMessage`] when the protocol version or message type
/// is wrong or a Kerberos time is fractional, [`Error::IntegerOutOfRange`] when
/// `cusec` or `susec` is outside `0..=999_999`, and [`Error::InvalidString`]
/// when a name, realm or `e-text` is not UTF-8,
/// and [`Error::TimeOverflow`] when `ctime` or `stime` does not fit a
/// `SystemTime`.
#[inline]
pub fn info(krb_error: &rasn_kerberos::KrbError) -> Result<KrbErrorInfo, Error> {
    KrbErrorInfo::from_rasn(krb_error).map_err(message_error)
}

/// Decode DER-encoded METHOD-DATA from a KRB-ERROR `e-data` value.
///
/// # Errors
///
/// Returns [`Error::Decode`] when `bytes` is not DER METHOD-DATA.
#[inline]
pub fn decode_method_data(bytes: &[u8]) -> Result<rasn_kerberos::MethodData, Error> {
    decode_der::<rasn_kerberos::MethodData>("METHOD-DATA", bytes)
}

/// Encode METHOD-DATA as DER for use in KRB-ERROR `e-data`.
///
/// # Errors
///
/// Returns [`Error::Encode`] when the DER encoder fails.
#[inline]
pub fn encode_method_data(method_data: &rasn_kerberos::MethodData) -> Result<Vec<u8>, Error> {
    encode_der("METHOD-DATA", method_data)
}

/// Decode preauthentication METHOD-DATA for a challenge or failed attempt.
///
/// The caller supplies `KDC_ERR_PREAUTH_REQUIRED`; RFC 6113 section 2 also
/// defines METHOD-DATA on `KDC_ERR_PREAUTH_FAILED` (24). Unrelated error data
/// stays opaque. Missing data returns an empty hint list.
///
/// # Errors
///
/// Returns the errors of [`info`], and [`Error::Decode`] when the
/// error is a preauthentication error but `e-data` is not DER METHOD-DATA.
#[inline]
pub fn preauth_method_data(
    krb_error: &rasn_kerberos::KrbError,
    preauth_required_error_code: i32,
) -> Result<rasn_kerberos::MethodData, Error> {
    let info = info(krb_error)?;
    if info.error_code != preauth_required_error_code && info.error_code != 24_i32 {
        return Ok(Vec::new());
    }
    info.e_data
        .as_deref()
        .map(decode_method_data)
        .transpose()
        .map(Option::unwrap_or_default)
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

/// Map a shared message-layer error to the KRB-ERROR module error.
fn message_error(error: MessagesError) -> Error {
    match error {
        MessagesError::Policy(policy) => policy.into(),
        MessagesError::Decode { target, message } => Error::Decode { target, message },
        MessagesError::Encode { target, message } => Error::Encode { target, message },
        MessagesError::InvalidString(source) => Error::InvalidString(source),
        MessagesError::IntegerOutOfRange { field, value } => {
            Error::IntegerOutOfRange { field, value }
        }
        MessagesError::InvalidMessage {
            field,
            expected,
            actual,
        } => Error::InvalidMessage {
            field,
            expected,
            actual,
        },
        MessagesError::KvnoOutOfRange { target, kvno } => Error::KvnoOutOfRange { target, kvno },
        MessagesError::TimeOverflow => Error::TimeOverflow,
    }
}

use crate::error::KrbErrorCodec as Error;

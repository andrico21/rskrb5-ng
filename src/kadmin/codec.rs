//! Wire codecs and protocol error conversion.

use rasn::{Decode, Encode, der};

use super::{Error, Frame, HEADER_LEN};
use crate::{der::decode_complete, error, file_name::SecretBytes, keytab::EncryptionKey};

/// Decode one DER value, naming `target` in the error.
///
/// # Errors
///
/// Returns [`Error::Decode`] when `bytes` is not a DER `T`.
pub(super) fn decode<T>(target: &'static str, bytes: &[u8]) -> Result<T, Error>
where
    T: Decode,
{
    decode_complete(bytes).map_err(|source| Error::Decode {
        target,
        message: source,
    })
}

/// Encode one value as DER, naming `target` in the error.
///
/// # Errors
///
/// Returns [`Error::Encode`] when the DER encoder fails.
pub(super) fn encode<T>(target: &'static str, value: &T) -> Result<Vec<u8>, Error>
where
    T: Encode,
{
    der::encode(value).map_err(|source| Error::Encode {
        target,
        message: source.to_string(),
    })
}

/// Map an AP-REQ error onto the kadmin [`Error`].
pub(super) fn ap_req_error(error: error::ApReq) -> Error {
    match error {
        error::ApReq::Crypto(source) => Error::Crypto(source),
        error::ApReq::Random(source) => Error::Random(source),
        error::ApReq::Decode { target, message } => Error::Decode { target, message },
        error::ApReq::Encode { target, message } => Error::Encode { target, message },
        error::ApReq::InvalidMessage {
            field,
            expected,
            actual,
        } => Error::InvalidKerberosMessage {
            field,
            expected,
            actual,
        },
        other @ (error::ApReq::UnsupportedEtype(_)
        | error::ApReq::KeyEtypeMismatch {
            key_etype: _,
            encrypted_data_etype: _,
        }) => Error::Decode {
            target: "AP-REQ",
            message: other.to_string(),
        },
    }
}

/// Map an AP-REP error onto the kadmin [`Error`].
pub(super) fn ap_rep_error(error: error::ApRep) -> Error {
    match error {
        error::ApRep::Crypto(source) => Error::Crypto(source),
        error::ApRep::Random(source) => Error::Random(source),
        error::ApRep::Decode { target, message } => Error::Decode { target, message },
        error::ApRep::Encode { target, message } => Error::Encode { target, message },
        error::ApRep::InvalidMessage {
            field,
            expected,
            actual,
        } => Error::InvalidKerberosMessage {
            field,
            expected,
            actual,
        },
        other @ (error::ApRep::UnsupportedEtype(_)
        | error::ApRep::KeyEtypeMismatch {
            key_etype: _,
            encrypted_data_etype: _,
        }) => Error::Decode {
            target: "AP-REP",
            message: other.to_string(),
        },
    }
}

/// Map a KRB-ERROR error onto the kadmin [`Error`].
pub(super) fn krb_error_error(error: error::KrbErrorCodec) -> Error {
    match error {
        error::KrbErrorCodec::Policy(policy) => policy.into(),
        error::KrbErrorCodec::Decode { target, message } => Error::Decode { target, message },
        error::KrbErrorCodec::Encode { target, message } => Error::Encode { target, message },
        error::KrbErrorCodec::InvalidMessage {
            field,
            expected,
            actual,
        } => Error::InvalidKerberosMessage {
            field,
            expected,
            actual,
        },
        other @ (error::KrbErrorCodec::InvalidString(_)
        | error::KrbErrorCodec::IntegerOutOfRange { field: _, value: _ }
        | error::KrbErrorCodec::KvnoOutOfRange { target: _, kvno: _ }
        | error::KrbErrorCodec::TimeOverflow) => Error::Decode {
            target: "KRB-ERROR",
            message: other.to_string(),
        },
    }
}

/// Map a KRB-PRIV error onto the kadmin [`Error`].
pub(super) fn krb_priv_error(error: error::KrbPriv) -> Error {
    match error {
        error::KrbPriv::Decode { target, message } => Error::Decode { target, message },
        error::KrbPriv::Encode { target, message } => Error::Encode { target, message },
        error::KrbPriv::InvalidMessage {
            field,
            expected,
            actual,
        } => Error::InvalidKerberosMessage {
            field,
            expected,
            actual,
        },
        error::KrbPriv::UnsupportedEtype(etype) => Error::UnsupportedEtype(etype),
        error::KrbPriv::KeyEtypeMismatch {
            key_etype,
            encrypted_data_etype,
        } => Error::KeyEtypeMismatch {
            key_etype,
            encrypted_data_etype,
        },
        error::KrbPriv::Crypto(source) => Error::Crypto(source),
        error::KrbPriv::Random(source) => Error::Random(source),
    }
}

/// A principal name of `name_type` made of `components`.
///
/// # Errors
///
/// Returns [`Error::InvalidKerberosString`] for a component that is not a valid
/// Kerberos string.
pub(super) fn principal_name<I, S>(
    name_type: i32,
    components: I,
) -> Result<rasn_kerberos::PrincipalName, Error>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    Ok(rasn_kerberos::PrincipalName {
        r#type: name_type,
        string: components
            .into_iter()
            .map(|component| kerberos_string(component.as_ref()))
            .collect::<Result<Vec<_>, _>>()?,
    })
}

/// `value` as a Kerberos string.
///
/// # Errors
///
/// Returns [`Error::InvalidKerberosString`] when `value` is not a valid
/// Kerberos string.
pub(super) fn kerberos_string(value: &str) -> Result<rasn_kerberos::KerberosString, Error> {
    rasn_kerberos::KerberosString::from_bytes(value.as_bytes())
        .map_err(|source| Error::InvalidKerberosString(source.to_string()))
}

/// Split a kpasswd frame into its header fields and body.
///
/// # Errors
///
/// Returns [`Error::FrameTooShort`] when `bytes` is shorter than the header,
/// [`Error::InvalidMessageLength`] when the declared length is shorter than the
/// header, and [`Error::TruncatedFrame`] when it is longer than `bytes`.
pub(super) fn parse_header(bytes: &[u8]) -> Result<Frame<'_>, Error> {
    let [
        length_high,
        length_low,
        version_high,
        version_low,
        payload_high,
        payload_low,
        ..,
    ] = *bytes
    else {
        return Err(Error::FrameTooShort {
            actual: bytes.len(),
        });
    };

    let message_length = u16::from_be_bytes([length_high, length_low]);
    let frame_len = usize::from(message_length);
    if frame_len < HEADER_LEN {
        return Err(Error::InvalidMessageLength(message_length));
    }
    if frame_len < bytes.len() {
        return Err(Error::InvalidMessageLength(message_length));
    }
    let Some(body) = bytes.get(HEADER_LEN..frame_len) else {
        return Err(Error::TruncatedFrame {
            expected: frame_len,
            actual: bytes.len(),
        });
    };

    Ok(Frame {
        message_length,
        version: u16::from_be_bytes([version_high, version_low]),
        payload_length: u16::from_be_bytes([payload_high, payload_low]),
        body,
    })
}

/// `size` bytes from the operating system's random source.
///
/// # Errors
///
/// Returns [`Error::Random`] when the random source fails.
pub(super) fn random_key_material(size: usize) -> Result<SecretBytes, Error> {
    random_key_material_with(size, getrandom::fill)
}

/// Fill key storage with the supplied entropy source.
/// # Errors
/// Returns the source's randomness error, including partial fills.
fn random_key_material_with<F>(size: usize, fill: F) -> Result<SecretBytes, Error>
where
    F: FnOnce(&mut [u8]) -> Result<(), getrandom::Error>,
{
    let mut value = SecretBytes::new(vec![0_u8; size]);
    fill(&mut value)?;
    Ok(value)
}

/// `value` as the `rasn` Kerberos `EncryptionKey`.
pub(super) fn encryption_key_to_rasn(value: &EncryptionKey) -> rasn_kerberos::EncryptionKey {
    rasn_kerberos::EncryptionKey {
        r#type: value.etype,
        value: value.value.to_vec().into(),
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use super::{Error, random_key_material_with};
    use crate::file_name::tests::ERASED_BYTES;

    /// A partial entropy failure erases the live allocation before returning its cause.
    #[test]
    fn partial_entropy_failure_erases_key_material() -> Result<(), Error> {
        ERASED_BYTES.with(|count| count.set(0));
        let failed = random_key_material_with(32, |bytes| {
            bytes.fill(0x57);
            Err(getrandom::Error::UNSUPPORTED)
        });
        assert!(matches!(failed, Err(Error::Random(_))));
        ERASED_BYTES
            .with(|count| assert_eq!(count.get(), 32, "partial entropy allocation was not erased"));
        let success = random_key_material_with(32, |bytes| {
            bytes.fill(0x57);
            Ok(())
        })?;
        assert_eq!(success.as_slice(), &[0x57; 32]);
        Ok(())
    }
}

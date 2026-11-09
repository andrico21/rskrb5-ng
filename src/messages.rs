//! Kerberos message/type wrappers that need gokrb5-compatible DER behavior.

mod credential_debug;
/// Signed key-version conversion for encrypted data.
mod encrypted_data;
/// Owning boundary for secret-bearing message DER staging.
pub(crate) mod secret_der;

use core::{
    str::{self},
    time::Duration,
};
use std::time::{SystemTime, UNIX_EPOCH};

use rasn::{
    AsnType, Decode, Decoder as _, Encode, Encoder as _, der,
    types::{Integer, OctetString},
};

/// Kerberos protocol version number carried in every message (RFC 4120).
const KRB5_PVNO: i32 = 5;
/// `msg-type` of a KRB-ERROR message (RFC 4120 section 5.9.1).
const KRB_ERROR_MSG_TYPE: i32 = 30;

/// RFC 4120 `EncryptedData` with a signed/raw ASN.1 `kvno`.
///
/// `rasn_kerberos::EncryptedData` models `kvno` as `u32`, which is appropriate
/// for normal Kerberos messages but normalizes gokrb5's signed edge-case
/// fixtures on re-encode. This wrapper preserves those DER fixtures exactly.
#[derive(AsnType, Clone, Decode, Encode, Eq, PartialEq)]
#[non_exhaustive]
pub struct EncryptedData {
    /// Identifies the encryption algorithm used to encipher `cipher`.
    #[rasn(tag(explicit(0)))]
    etype: i32,
    /// Key version number, kept as ASN.1 INTEGER for gokrb5 signed edge cases.
    #[rasn(tag(explicit(1)))]
    kvno: Option<Integer>,
    /// Enciphered text.
    #[rasn(tag(explicit(2)))]
    cipher: OctetString,
}

/// MS-SFU `PA-FOR-USER` padata value used by `S4U2Self`.
#[derive(AsnType, Clone, Decode, Encode, Eq, PartialEq)]
#[non_exhaustive]
pub struct PaForUser {
    /// User principal name.
    #[rasn(tag(explicit(0)))]
    user_name: rasn_kerberos::PrincipalName,
    /// User realm.
    #[rasn(tag(explicit(1)))]
    user_realm: rasn_kerberos::Realm,
    /// Checksum over the MS-SFU S4U byte array.
    #[rasn(tag(explicit(2)))]
    cksum: rasn_kerberos::Checksum,
    /// Authentication package name, normally `Kerberos`.
    #[rasn(tag(explicit(3)))]
    auth_package: rasn_kerberos::KerberosString,
}

/// MS-KILE `PA-PAC-OPTIONS` padata value.
#[derive(AsnType, Clone, Debug, Decode, Encode, Eq, PartialEq)]
#[non_exhaustive]
pub struct PaPacOptions {
    /// PAC option flags.
    #[rasn(tag(explicit(0)))]
    pub flags: rasn_kerberos::KerberosFlags,
}

/// RFC 6806 `PA-REQ-ENC-PA-REP` encrypted padata value.
#[derive(AsnType, Clone, Decode, Encode, Eq, PartialEq)]
#[non_exhaustive]
pub struct PaReqEncPaRep {
    /// Checksum type used to protect the original AS-REQ bytes.
    #[rasn(tag(explicit(0)))]
    checksum_type: i32,
    /// Checksum over the DER-encoded AS-REQ.
    #[rasn(tag(explicit(1)))]
    checksum: OctetString,
}

impl PaForUser {
    /// Adopt dependency-owned padata; ASN.1 residual copies are not erased by this wrapper.
    #[inline]
    #[must_use]
    pub const fn new(
        user_name: rasn_kerberos::PrincipalName,
        user_realm: rasn_kerberos::Realm,
        cksum: rasn_kerberos::Checksum,
        auth_package: rasn_kerberos::KerberosString,
    ) -> Self {
        Self {
            user_name,
            user_realm,
            cksum,
            auth_package,
        }
    }
    /// Borrow the user principal.
    #[inline]
    #[must_use]
    pub const fn user_name(&self) -> &rasn_kerberos::PrincipalName {
        &self.user_name
    }
    /// Borrow the user realm.
    #[inline]
    #[must_use]
    pub const fn user_realm(&self) -> &rasn_kerberos::Realm {
        &self.user_realm
    }
    /// Borrow the authentication checksum without exposing mutable storage.
    #[inline]
    #[must_use]
    pub const fn cksum(&self) -> &rasn_kerberos::Checksum {
        &self.cksum
    }
    /// Borrow the authentication package name.
    #[inline]
    #[must_use]
    pub const fn auth_package(&self) -> &rasn_kerberos::KerberosString {
        &self.auth_package
    }
    /// Decode a DER-encoded `PA-FOR-USER` value.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Decode`] when `bytes` is not a DER `PA-FOR-USER`.
    #[inline]
    pub fn decode_der(bytes: &[u8]) -> Result<Self, Error> {
        decode_named("PA-FOR-USER", bytes)
    }

    /// Encode the value as DER.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Encode`] when the DER encoder fails.
    #[inline]
    pub fn encode_der(&self) -> Result<Vec<u8>, Error> {
        encode_der("PA-FOR-USER", self)
    }
}

impl PaPacOptions {
    #[must_use]
    /// Build PAC options from a raw `KerberosFlags` bit mask.
    #[inline]
    pub fn from_bits(bits: u32) -> Self {
        Self {
            flags: rasn_kerberos::KerberosFlags::from_slice(&bits.to_be_bytes()),
        }
    }

    #[must_use]
    /// Return the first 32 PAC option bits as a raw bit mask.
    #[inline]
    pub fn bits(&self) -> u32 {
        let raw = self.flags.as_raw_slice();
        u32::from_be_bytes([
            raw.first().copied().unwrap_or_default(),
            raw.get(1).copied().unwrap_or_default(),
            raw.get(2).copied().unwrap_or_default(),
            raw.get(3).copied().unwrap_or_default(),
        ])
    }

    /// Decode a DER-encoded `PA-PAC-OPTIONS` value.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Decode`] when `bytes` is not a DER `PA-PAC-OPTIONS`.
    #[inline]
    pub fn decode_der(bytes: &[u8]) -> Result<Self, Error> {
        decode_named("PA-PAC-OPTIONS", bytes)
    }

    /// Encode the value as DER.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Encode`] when the DER encoder fails.
    #[inline]
    pub fn encode_der(&self) -> Result<Vec<u8>, Error> {
        encode_der("PA-PAC-OPTIONS", self)
    }
}

impl PaReqEncPaRep {
    /// Return the checksum algorithm identifier.
    #[inline]
    #[must_use]
    pub const fn checksum_type(&self) -> i32 {
        self.checksum_type
    }
    /// Borrow checksum bytes; dependency-owned copies are not erased.
    #[inline]
    #[must_use]
    pub fn checksum(&self) -> &[u8] {
        self.checksum.as_ref()
    }
    /// Creates a `PaReqEncPaRep` from its required fields.
    #[must_use]
    #[inline]
    pub const fn new(checksum_type: i32, checksum: OctetString) -> Self {
        Self {
            checksum_type,
            checksum,
        }
    }

    /// Build the value from a Kerberos checksum.
    #[inline]
    pub fn from_checksum(checksum: rasn_kerberos::Checksum) -> Self {
        Self {
            checksum_type: checksum.r#type,
            checksum: checksum.checksum,
        }
    }

    /// Convert the value to a Kerberos checksum.
    #[inline]
    pub fn to_checksum(&self) -> rasn_kerberos::Checksum {
        rasn_kerberos::Checksum {
            r#type: self.checksum_type,
            checksum: self.checksum.clone(),
        }
    }

    /// Decode a DER-encoded `PA-REQ-ENC-PA-REP` value.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Decode`] when `bytes` is not a DER `PA-REQ-ENC-PA-REP`.
    #[inline]
    pub fn decode_der(bytes: &[u8]) -> Result<Self, Error> {
        decode_named("PA-REQ-ENC-PA-REP", bytes)
    }

    /// Encode the value as DER.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Encode`] when the DER encoder fails.
    #[inline]
    pub fn encode_der(&self) -> Result<Vec<u8>, Error> {
        encode_der("PA-REQ-ENC-PA-REP", self)
    }
}

/// Principal summary decoded from a Kerberos message.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct PrincipalNameInfo {
    /// Principal realm.
    pub realm: String,
    /// Kerberos name type. Name type is advisory and not used for matching.
    pub name_type: i32,
    /// Principal name components.
    pub components: Vec<String>,
}

impl PrincipalNameInfo {
    #[must_use]
    /// Principal components joined with `/`.
    #[inline]
    pub fn name(&self) -> String {
        self.components.join("/")
    }
}

/// Decoded KRB-ERROR fields useful for diagnostics.
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub struct KrbErrorInfo {
    /// Client time, when present.
    ctime: Option<SystemTime>,
    /// Client microseconds, when present.
    cusec: Option<u32>,
    /// KDC/server time.
    stime: SystemTime,
    /// KDC/server microseconds.
    susec: u32,
    /// Kerberos error code.
    error_code: i32,
    /// Client principal carried by the error, when present.
    client: Option<PrincipalNameInfo>,
    /// Service principal that issued the error.
    service: PrincipalNameInfo,
    /// Optional human-readable error text.
    e_text: Option<String>,
    /// Raw e-data bytes, when present.
    e_data: Option<zeroize::Zeroizing<Vec<u8>>>,
}

impl KrbErrorInfo {
    /// Return the optional client clock.
    #[inline]
    #[must_use]
    pub const fn ctime(&self) -> Option<SystemTime> {
        self.ctime
    }
    /// Return optional client microseconds.
    #[inline]
    #[must_use]
    pub const fn cusec(&self) -> Option<u32> {
        self.cusec
    }
    /// Return the server clock.
    #[inline]
    #[must_use]
    pub const fn stime(&self) -> SystemTime {
        self.stime
    }
    /// Return server microseconds.
    #[inline]
    #[must_use]
    pub const fn susec(&self) -> u32 {
        self.susec
    }
    /// Return the protocol error code.
    #[inline]
    #[must_use]
    pub const fn error_code(&self) -> i32 {
        self.error_code
    }
    /// Borrow the optional client identity.
    #[inline]
    #[must_use]
    pub const fn client(&self) -> Option<&PrincipalNameInfo> {
        self.client.as_ref()
    }
    /// Borrow the server identity.
    #[inline]
    #[must_use]
    pub const fn service(&self) -> &PrincipalNameInfo {
        &self.service
    }
    /// Borrow diagnostic text.
    #[inline]
    #[must_use]
    pub fn e_text(&self) -> Option<&str> {
        self.e_text.as_deref()
    }
    /// Transfer the retained zeroizing payload without making another copy.
    pub(crate) const fn take_e_data(&mut self) -> Option<zeroize::Zeroizing<Vec<u8>>> {
        self.e_data.take()
    }
    /// Borrow opaque error payload bytes; callers must erase copies they create.
    #[inline]
    #[must_use]
    pub fn e_data(&self) -> Option<&[u8]> {
        self.e_data.as_ref().map(|bytes| bytes.as_slice())
    }
    /// Decode and validate a DER-encoded KRB-ERROR.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Decode`] when `bytes` is not a DER KRB-ERROR, and the
    /// errors of [`Self::from_rasn`].
    #[inline]
    pub fn decode_der(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_rasn(&decode_named("KRB-ERROR", bytes)?)
    }

    /// Build a diagnostic summary from a decoded KRB-ERROR.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidMessage`] when the protocol version or message type
    /// is wrong or a Kerberos time is fractional, [`Error::IntegerOutOfRange`]
    /// when `cusec` or `susec` is outside `0..=999_999`, [`Error::InvalidString`]
    /// when a name, realm or `e-text` is not
    /// UTF-8, and [`Error::TimeOverflow`] when `ctime` or `stime` does not fit a
    /// `SystemTime`.
    #[inline]
    pub fn from_rasn(error: &rasn_kerberos::KrbError) -> Result<Self, Error> {
        validate_integer("pvno", &error.pvno, KRB5_PVNO)?;
        validate_integer("msg-type", &error.msg_type, KRB_ERROR_MSG_TYPE)?;
        let client = match (&error.crealm, &error.cname) {
            (Some(realm), Some(name)) => Some(principal_from_parts(realm, name)?),
            _ => None,
        };
        Ok(Self {
            ctime: error
                .ctime
                .as_ref()
                .map(system_time_from_kerberos_time)
                .transpose()?,
            cusec: error
                .cusec
                .as_ref()
                .map(|value| microseconds("cusec", value))
                .transpose()?,
            stime: system_time_from_kerberos_time(&error.stime)?,
            susec: microseconds("susec", &error.susec)?,
            error_code: error.error_code,
            client,
            service: principal_from_parts(&error.realm, &error.sname)?,
            e_text: error
                .e_text
                .as_ref()
                .map(kerberos_string_to_string)
                .transpose()?,
            e_data: error
                .e_data
                .as_ref()
                .map(|data| zeroize::Zeroizing::new(data.as_ref().to_vec())),
        })
    }
}

/// Decode the first DER value with a typed error, leaving any suffix unchecked.
///
/// This raw prefix codec is for fixture and framing work. Named message decoders
/// require the entire input to contain exactly one value instead.
///
/// # Errors
///
/// Returns [`Error::Decode`] naming `target` when `bytes` is not valid DER for
/// `T`.
#[inline]
pub fn decode_der<T>(target: &'static str, bytes: &[u8]) -> Result<T, Error>
where
    T: Decode,
{
    der::decode(bytes).map_err(|source| Error::Decode {
        target,
        message: source.to_string(),
    })
}

/// Encode a value to DER with a typed error.
///
/// # Errors
///
/// Returns [`Error::Encode`] naming `target` when the DER encoder fails.
#[inline]
pub fn encode_der<T>(target: &'static str, value: &T) -> Result<Vec<u8>, Error>
where
    T: Encode,
{
    der::encode(value).map_err(|source| Error::Encode {
        target,
        message: source.to_string(),
    })
}

use crate::{der::decode_complete, error::Messages as Error};

/// Decode one complete value at a named message boundary.
///
/// # Errors
/// Returns [`Error::Decode`] when decoding fails or trailing bytes remain.
fn decode_named<T>(target: &'static str, bytes: &[u8]) -> Result<T, Error>
where
    T: Decode,
{
    decode_complete(bytes).map_err(|message| Error::Decode { target, message })
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

/// Convert an RFC 4120 Microseconds field in the inclusive 0..=999999 range.
///
/// # Errors
///
/// Returns [`Error::IntegerOutOfRange`] naming `field` when the value is
/// outside the protocol range.
pub(crate) fn microseconds(field: &'static str, value: &Integer) -> Result<u32, Error> {
    u32::try_from(value)
        .ok()
        .filter(|micros| *micros <= 999_999)
        .ok_or_else(|| Error::IntegerOutOfRange {
            field,
            value: value.to_string(),
        })
}

/// Build a principal summary from a Kerberos realm and principal name.
///
/// # Errors
///
/// Returns [`Error::InvalidString`] when the realm or a name component is not
/// UTF-8.
fn principal_from_parts(
    realm: &rasn_kerberos::Realm,
    name: &rasn_kerberos::PrincipalName,
) -> Result<PrincipalNameInfo, Error> {
    Ok(PrincipalNameInfo {
        realm: kerberos_string_to_string(realm)?,
        name_type: name.r#type,
        components: name
            .string
            .iter()
            .map(kerberos_string_to_string)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

/// Convert a Kerberos string to an owned UTF-8 string.
///
/// # Errors
///
/// Returns [`Error::InvalidString`] when the bytes are not UTF-8.
fn kerberos_string_to_string(value: &rasn_kerberos::KerberosString) -> Result<String, Error> {
    Ok(str::from_utf8(value.as_bytes())?.to_owned())
}

/// Convert a whole-second Kerberos time to a `SystemTime`.
///
/// # Errors
///
/// Returns [`Error::TimeOverflow`] when the time is outside the `SystemTime`
/// range, or [`Error::InvalidMessage`] when the time is fractional.
fn system_time_from_kerberos_time(time: &rasn_kerberos::KerberosTime) -> Result<SystemTime, Error> {
    whole_seconds(time)?;
    let seconds = time.0.timestamp();
    let nanos = time.0.timestamp_subsec_nanos();
    match u64::try_from(seconds) {
        Ok(after_epoch) => UNIX_EPOCH
            .checked_add(Duration::new(after_epoch, nanos))
            .ok_or(Error::TimeOverflow),
        Err(_before_epoch) => UNIX_EPOCH
            .checked_sub(Duration::new(seconds.unsigned_abs(), nanos))
            .ok_or(Error::TimeOverflow),
    }
}

/// Enforce RFC 4120's whole-second `KerberosTime` domain without normalization.
///
/// # Errors
/// Returns [`Error::InvalidMessage`] when a fractional component is present.
pub(crate) fn whole_seconds(time: &rasn_kerberos::KerberosTime) -> Result<(), Error> {
    if time.0.timestamp_subsec_nanos() != 0 {
        return Err(Error::InvalidMessage {
            field: "KerberosTime fraction",
            expected: 0,
            actual: time.0.timestamp_subsec_nanos().to_string(),
        });
    }
    Ok(())
}

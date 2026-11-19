//! The redacted gokrb5-style JSON snapshot of a parsed configuration.

#[cfg(feature = "serde")]
use alloc::collections::BTreeMap;
#[cfg(feature = "serde")]
use core::net::IpAddr;
#[cfg(feature = "serde")]
use core::time::Duration;

#[cfg(feature = "serde")]
use super::Config;
#[cfg(feature = "serde")]
use super::Realm;
#[cfg(feature = "serde")]
use super::serde_libdefaults::LibDefaultsJson;

/// Render a gokrb5-style JSON snapshot of the parsed configuration.
///
/// # Errors
/// Returns [`serde_json::Error`] when the snapshot cannot be serialized.
#[cfg(feature = "serde")]
pub(super) fn json(this: &Config) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(&ConfigJson::from(this))
}

/// The gokrb5 JSON snapshot of a [`Config`], borrowing from it.
#[cfg(feature = "serde")]
#[derive(serde::Serialize)]
pub(super) struct ConfigJson<'config> {
    /// [`Config::libdefaults`], as gokrb5's `LibDefaults`.
    #[serde(rename = "LibDefaults")]
    libdefaults: LibDefaultsJson<'config>,
    /// [`Config::realms`], as gokrb5's `Realms`.
    #[serde(rename = "Realms")]
    realms: Vec<RealmJson<'config>>,
    /// [`Config::domain_realm`], as gokrb5's `DomainRealm`.
    #[serde(rename = "DomainRealm")]
    domain_realm: &'config BTreeMap<String, String>,
}

#[cfg(feature = "serde")]
impl<'config> From<&'config Config> for ConfigJson<'config> {
    fn from(config: &'config Config) -> Self {
        Self {
            libdefaults: LibDefaultsJson::from(&config.libdefaults),
            realms: config.realms.iter().map(RealmJson::from).collect(),
            domain_realm: &config.domain_realm,
        }
    }
}

/// The gokrb5 JSON snapshot of a [`Realm`], borrowing from it.
#[cfg(feature = "serde")]
#[derive(serde::Serialize)]
pub(super) struct RealmJson<'config> {
    /// [`Realm::realm`], as gokrb5's `Realm`.
    #[serde(rename = "Realm")]
    realm: &'config str,
    /// [`Realm::admin_server`], or `None` when empty, as gokrb5's `AdminServer`.
    #[serde(rename = "AdminServer")]
    admin_server: Option<&'config [String]>,
    /// [`Realm::default_domain`], as gokrb5's `DefaultDomain`.
    #[serde(rename = "DefaultDomain")]
    default_domain: &'config str,
    /// [`Realm::kdc`], or `None` when empty, as gokrb5's `KDC`.
    #[serde(rename = "KDC")]
    kdc: Option<&'config [String]>,
    /// [`Realm::kpasswd_server`], or `None` when empty, as gokrb5's `KPasswdServer`.
    #[serde(rename = "KPasswdServer")]
    kpasswd_server: Option<&'config [String]>,
    /// [`Realm::master_kdc`], or `None` when empty, as gokrb5's `MasterKDC`.
    #[serde(rename = "MasterKDC")]
    master_kdc: Option<&'config [String]>,
}

#[cfg(feature = "serde")]
impl<'config> From<&'config Realm> for RealmJson<'config> {
    fn from(realm: &'config Realm) -> Self {
        Self {
            realm: &realm.name,
            admin_server: optional_slice(&realm.admin_server),
            default_domain: &realm.default_domain,
            kdc: optional_slice(&realm.kdc),
            kpasswd_server: optional_slice(&realm.kpasswd_server),
            master_kdc: optional_slice(&realm.master_kdc),
        }
    }
}

/// A gokrb5 `asn1.BitString` JSON snapshot.
#[cfg(feature = "serde")]
#[derive(serde::Serialize)]
pub(super) struct KerberosBitStringJson {
    /// The standard base64 of the big-endian bytes, as gokrb5's `Bytes`.
    #[serde(rename = "Bytes")]
    bytes: String,
    /// The number of bits, as gokrb5's `BitLength`.
    #[serde(rename = "BitLength")]
    bit_length: usize,
}

#[cfg(feature = "serde")]
impl KerberosBitStringJson {
    /// The 32-bit string whose bits are `value`, most significant first.
    pub(super) fn from_u32(value: u32) -> Self {
        let bytes = value.to_be_bytes();
        Self {
            bytes: base64_standard(&bytes),
            // Saturating: four bytes are 32 bits.
            bit_length: bytes.len().saturating_mul(8),
        }
    }
}

/// `values`, or `None` when it is empty (gokrb5 renders an empty list as
/// `null`).
#[cfg(feature = "serde")]
pub(super) const fn optional_slice<T>(values: &[T]) -> Option<&[T]> {
    if values.is_empty() {
        None
    } else {
        Some(values)
    }
}

/// `values` rendered as strings, or `None` when it is empty.
#[cfg(feature = "serde")]
pub(super) fn optional_ip_addresses(values: &[IpAddr]) -> Option<Vec<String>> {
    if values.is_empty() {
        None
    } else {
        Some(values.iter().map(ToString::to_string).collect())
    }
}

/// `duration` in nanoseconds, as Go's `time.Duration` serializes.
#[cfg(feature = "serde")]
pub(super) const fn duration_nanos(duration: Duration) -> u128 {
    duration.as_nanos()
}

/// The standard (RFC 4648, padded) base64 encoding of `bytes`.
#[cfg(feature = "serde")]
pub(super) fn base64_standard(bytes: &[u8]) -> String {
    // Saturating: a capacity hint; the length of a real slice cannot reach it.
    let mut output = String::with_capacity(bytes.len().div_ceil(3).saturating_mul(4));

    for chunk in bytes.chunks(3) {
        let (first, second, third) = match *chunk {
            [first] => (first, 0_u8, 0_u8),
            [first, second] => (first, second, 0_u8),
            [first, second, third, ..] => (first, second, third),
            [] => continue,
        };
        let value = (u32::from(first) << 16_u32) | (u32::from(second) << 8_u32) | u32::from(third);

        output.push(base64_char(value >> 18_u32));
        output.push(base64_char(value >> 12_u32));
        if chunk.len() > 1 {
            output.push(base64_char(value >> 6_u32));
        } else {
            output.push('=');
        }
        if chunk.len() > 2 {
            output.push(base64_char(value));
        } else {
            output.push('=');
        }
    }

    output
}

/// The standard base64 alphabet character for the low six bits of `value`.
#[cfg(feature = "serde")]
pub(super) fn base64_char(value: u32) -> char {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    // The six-bit index is always within the 64-entry table; the padding
    // character stands in for the impossible miss.
    usize::try_from(value & 0x3f_u32)
        .ok()
        .and_then(|index| TABLE.get(index))
        .map_or('=', |byte| char::from(*byte))
}

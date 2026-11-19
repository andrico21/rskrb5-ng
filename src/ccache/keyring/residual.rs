//! Residual names, key descriptions and key payloads (`cc_keyring.c`).

use core::str;

use super::{Fault, backend::Serial};
use crate::ccache::{Error, Principal};

/// The keyring of a persistent collection (`KRCC_PERSISTENT_KEYRING_NAME`).
pub(super) const PERSISTENT_KEYRING: &str = "_krb";
/// The user key naming the primary cache of a collection.
pub(super) const PRIMARY_KEY: &str = "krb_ccache:primary";
/// The user key holding the default principal of a cache.
pub(super) const PRINCIPAL_KEY: &str = "__krb5_princ__";
/// The user key holding the KDC time offsets of a cache.
pub(super) const TIME_OFFSETS_KEY: &str = "__krb5_time_offsets__";
/// The prefix of the keyring names of unique caches.
pub(super) const UNIQUE_PREFIX: &str = "krb_ccache_";

/// Where the collection keyrings of an anchor live.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Anchor {
    /// The persistent keyring of a user.
    Persistent,
    /// The process keyring.
    Process,
    /// The thread keyring.
    Thread,
    /// The session keyring.
    Session,
    /// The user keyring.
    User,
    /// The session keyring, with the first cache also linked to it for old
    /// code.
    Legacy,
}

/// A parsed residual.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Residual {
    /// The anchor.
    pub anchor: Anchor,
    /// The collection name (a user id for `persistent`).
    pub collection: String,
    /// The subsidiary cache, when the residual names one.
    pub subsidiary: Option<String>,
}

impl Anchor {
    /// The anchor a name selects, case-sensitively as MIT `strcmp` does.
    fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "persistent" => Self::Persistent,
            "process" => Self::Process,
            "thread" => Self::Thread,
            "session" => Self::Session,
            "user" => Self::User,
            "legacy" => Self::Legacy,
            _ => return None,
        })
    }

    /// The name of the anchor in a residual.
    pub(super) const fn name(self) -> &'static str {
        match self {
            Self::Persistent => "persistent",
            Self::Process => "process",
            Self::Thread => "thread",
            Self::Session => "session",
            Self::User => "user",
            Self::Legacy => "legacy",
        }
    }
}

impl Residual {
    /// Parse a residual: `anchor:collection:subsidiary`,
    /// `anchor:collection` or `collection` (`cc_keyring.c:285-322`). The
    /// subsidiary is everything after the second colon.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidCacheName`] for a NUL or an empty subsidiary, and
    /// [`Fault::InvalidAnchor`] for an unknown anchor (`cc_keyring.c:520-522`).
    pub(super) fn parse(text: &str) -> Result<Self, Error> {
        if text.contains('\0') {
            return Err(Error::InvalidCacheName);
        }
        let (anchor, rest) = match text.split_once(':') {
            Some((name, rest)) => (
                Anchor::from_name(name).ok_or_else(|| Fault::InvalidAnchor {
                    anchor: name.to_owned(),
                })?,
                rest,
            ),
            None => (Anchor::Legacy, text),
        };
        let (collection, subsidiary) = match rest.split_once(':') {
            Some((_, "")) => return Err(Error::InvalidCacheName),
            Some((collection, subsidiary)) => (collection, Some(subsidiary.to_owned())),
            None => (rest, None),
        };
        Ok(Self {
            anchor,
            collection: collection.to_owned(),
            subsidiary,
        })
    }

    /// The full residual of a cache of this collection (`cc_keyring.c:408-417`).
    pub(super) fn cache_name(&self, subsidiary: &str) -> String {
        format!("{}:{}:{subsidiary}", self.anchor.name(), self.collection)
    }

    /// Whether `subsidiary` is the legacy cache that old code finds in the
    /// session keyring: the legacy anchor and a cache named like its
    /// collection (`cc_keyring.c:325-350`).
    pub(super) fn is_legacy_cache(&self, subsidiary: &str) -> bool {
        self.anchor == Anchor::Legacy && self.collection == subsidiary
    }
}

/// Append `text` to `out`, quoting as MIT `krb5_unparse_name`
/// (`src/lib/krb5/krb/unparse.c:74-130`).
fn quote_into(out: &mut String, text: &str) {
    for character in text.chars() {
        match character {
            '@' | '/' | '\\' => {
                out.push('\\');
                out.push(character);
            }
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{8}' => out.push_str("\\b"),
            '\0' => out.push_str("\\0"),
            other => out.push(other),
        }
    }
}

/// The key description of a service principal, as MIT `krb5_unparse_name`
/// prints it: no key description holds a NUL, `/` or `@` inside a component.
pub(super) fn unparse(principal: &Principal) -> String {
    let mut out = String::new();
    for (index, component) in principal.components.iter().enumerate() {
        if index > 0 {
            out.push('/');
        }
        quote_into(&mut out, component);
    }
    out.push('@');
    quote_into(&mut out, &principal.realm);
    out
}

/// The collection format version (`KRCC_COLLECTION_VERSION`).
const COLLECTION_VERSION: i32 = 1;

/// The payload of the primary-name key: version 1 and the length as
/// big-endian 32-bit numbers, then the name (`cc_keyring.c:541-553`).
pub(super) fn primary_payload(name: &str) -> Vec<u8> {
    let mut payload = Vec::with_capacity(name.len().saturating_add(8));
    payload.extend_from_slice(&COLLECTION_VERSION.to_be_bytes());
    payload.extend_from_slice(&u32::try_from(name.len()).unwrap_or(u32::MAX).to_be_bytes());
    payload.extend_from_slice(name.as_bytes());
    payload
}

/// The primary cache name in a primary-name payload. Bytes after the name
/// are ignored, as MIT does (`cc_keyring.c:556-571`).
///
/// # Errors
///
/// [`Fault::MalformedPrimary`] for a payload shorter than its length field or
/// a name that is empty, holds a NUL or is not UTF-8, and
/// [`Fault::UnknownCollectionVersion`] for a version other than 1.
pub(super) fn parse_primary(payload: &[u8]) -> Result<String, Error> {
    let Some((version_bytes, after_version)) = payload.split_first_chunk::<4>() else {
        return Err(Fault::MalformedPrimary.into());
    };
    let Some((length_bytes, body)) = after_version.split_first_chunk::<4>() else {
        return Err(Fault::MalformedPrimary.into());
    };
    let length = usize::try_from(u32::from_be_bytes(*length_bytes)).unwrap_or(usize::MAX);
    let name = body
        .get(..length)
        .and_then(|raw| str::from_utf8(raw).ok())
        .filter(|candidate| !candidate.is_empty() && !candidate.contains('\0'))
        .ok_or(Fault::MalformedPrimary)?;
    let version = i32::from_be_bytes(*version_bytes);
    if version != COLLECTION_VERSION {
        return Err(Fault::UnknownCollectionVersion { version }.into());
    }
    Ok(name.to_owned())
}

/// The type and description of a `keyctl_describe` string,
/// `type;uid;gid;permissions;description`; the description is everything
/// after the fourth semicolon.
pub(super) fn parse_description(text: &str) -> Option<(&str, &str)> {
    let mut fields = text.splitn(5, ';');
    let kind = fields.next()?;
    let description = fields.nth(3)?;
    Some((kind, description))
}

/// The serial number of four bytes in the kernel's native byte order.
pub(super) const fn native_serial(raw: [u8; 4]) -> i32 {
    if cfg!(target_endian = "little") {
        i32::from_le_bytes(raw)
    } else {
        i32::from_be_bytes(raw)
    }
}

/// The serial numbers a keyring read returns; a partial tail is dropped.
pub(super) fn parse_serials(bytes: &[u8]) -> Vec<Serial> {
    bytes
        .as_chunks::<4>()
        .0
        .iter()
        .filter_map(|chunk| Serial::new(native_serial(*chunk)))
        .collect()
}

/// The owner user id of a `keyctl_describe` string.
pub(super) fn parse_owner(text: &str) -> Option<u32> {
    text.split(';').nth(1)?.parse().ok()
}

//! The collection index: the user key `krb_ccache:primary` that names the
//! primary cache of a keyring collection (MIT 1.22.2
//! `src/lib/krb5/ccache/cc_keyring.c:541-571`).
//!
//! The payload is the version, 1, and the length of the name as big-endian
//! 32-bit numbers, then the name. The key is writable by every process of the
//! user, so [`parse()`](crate::ccache::keyring::index::parse) treats it as untrusted bytes.

use super::Fault;
use crate::ccache::Error;

/// The collection format version (`KRCC_COLLECTION_VERSION`).
const VERSION: i32 = 1;

/// The payload of the primary-name key for `name` (MIT `set_primary_name`).
#[must_use]
#[inline]
pub fn encode(name: &str) -> Vec<u8> {
    let mut payload = Vec::with_capacity(name.len().saturating_add(8));
    payload.extend_from_slice(&VERSION.to_be_bytes());
    payload.extend_from_slice(&u32::try_from(name.len()).unwrap_or(u32::MAX).to_be_bytes());
    payload.extend_from_slice(name.as_bytes());
    payload
}

/// The primary cache name in a primary-name payload. Bytes after the name
/// are ignored, as MIT does (`parse_index`).
///
/// # Errors
///
/// [`Fault::MalformedPrimary`] for a payload shorter than its length field or
/// a name that is empty, holds a NUL or is not UTF-8, and
/// [`Fault::UnknownCollectionVersion`] for a version other than 1; both as
/// [`Error::Keyring`].
#[inline]
pub fn parse(payload: &[u8]) -> Result<String, Error> {
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
    if version != VERSION {
        return Err(Fault::UnknownCollectionVersion { version }.into());
    }
    Ok(name.to_owned())
}

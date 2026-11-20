//! The key payloads: credentials and principals in the version 4 file
//! encoding (`cc_keyring.c:1331-1371`, `k5_marshal_cred`), and credential
//! expiry.

use std::time::{SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

use super::Fault;
use crate::ccache::{Credential, Endian, Error, Principal};

/// The version of the file encoding of every key payload.
const VERSION: u8 = 4;

/// A credential in the version 4 encoding, in a zeroizing buffer.
///
/// # Errors
///
/// Serialization errors.
pub(super) fn credential_bytes(credential: &Credential) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut payload = Zeroizing::new(Vec::with_capacity(credential.encoded_len(VERSION)));
    credential.write_to(&mut payload, VERSION, Endian::Big)?;
    Ok(payload)
}

/// A principal in the version 4 encoding.
///
/// # Errors
///
/// Serialization errors.
pub(super) fn principal_bytes(principal: &Principal) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut payload = Zeroizing::new(Vec::new());
    principal.write_to(&mut payload, VERSION, Endian::Big)?;
    Ok(payload)
}

/// The seconds from now until `end_time`, when it lies ahead and fits.
pub(super) fn seconds_until(end_time: u32) -> Option<u32> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    u32::try_from(u64::from(end_time).checked_sub(now)?)
        .ok()
        .filter(|seconds| *seconds > 0)
}

/// A credential from a key payload.
///
/// # Errors
///
/// Parse errors and [`Fault::MalformedPayload`] for bytes after the credential.
pub(super) fn parse_credential(payload: &[u8]) -> Result<Credential, Error> {
    let mut offset = 0;
    let credential = Credential::parse(payload, &mut offset, VERSION, Endian::Big)?;
    if offset == payload.len() {
        Ok(credential)
    } else {
        Err(Fault::MalformedPayload.into())
    }
}

/// A principal from a key payload.
///
/// # Errors
///
/// Parse errors and [`Fault::MalformedPayload`] for bytes after the principal.
pub(super) fn parse_principal(payload: &[u8]) -> Result<Principal, Error> {
    let mut offset = 0;
    let principal = Principal::parse(payload, &mut offset, VERSION, Endian::Big)?;
    if offset == payload.len() {
        Ok(principal)
    } else {
        Err(Fault::MalformedPayload.into())
    }
}

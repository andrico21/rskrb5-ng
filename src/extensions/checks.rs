//! Registration and output validation shared by every driver.

use alloc::sync::Arc;

use super::{
    Error, GssMechanism, Interface, MAX_ID_BYTES, MAX_NAME_BYTES, MAX_NAMES, MAX_OID_BYTES,
};
use crate::ccache::Principal;
#[cfg(feature = "messages")]
use crate::crypto::selection;

/// Object identifiers of the built-in mechanisms, as DER content octets.
///
/// Kerberos 1.2.840.113554.1.2.2, its Microsoft alias 1.2.840.48018.1.2.2,
/// SPNEGO 1.3.6.1.5.5.2, IAKERB 1.3.6.1.5.2.5 and `NegoEx` 1.3.6.1.4.1.311.2.2.30.
const RESERVED_OIDS: [&[u8]; 5] = [
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02],
    &[0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02],
    &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x02],
    &[0x2b, 0x06, 0x01, 0x05, 0x02, 0x05],
    &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x1e],
];

/// Admit a provider id: 1..=`MAX_ID_BYTES` bytes of `[A-Za-z0-9_.-]`, so it
/// can never contain the `:` that ends a `module` name or profile whitespace.
/// # Errors
/// Returns `InvalidId`.
pub(super) fn id(interface: Interface, value: &str) -> Result<(), Error> {
    let valid = (1..=MAX_ID_BYTES).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'));
    if valid {
        Ok(())
    } else {
        Err(Error::InvalidId {
            interface,
            id: value.to_owned(),
        })
    }
}

/// Admit a preauthentication mechanism's PA types: at least one, at most
/// `MAX_NAMES`, no repeats, and none that the permanent policy rejects.
/// # Errors
/// Returns `InvalidRegistration`.
#[cfg(feature = "messages")]
pub(super) fn preauth_types(provider: &str, types: &[i32]) -> Result<(), Error> {
    let refusal = |reason: &'static str| Error::InvalidRegistration {
        interface: Interface::ClientPreauth,
        id: provider.to_owned(),
        reason,
    };
    if types.is_empty() || types.len() > MAX_NAMES {
        return Err(refusal("PA type list is empty or too long"));
    }
    for (index, pa_type) in types.iter().enumerate() {
        if types
            .get(..index)
            .is_some_and(|earlier| earlier.contains(pa_type))
        {
            return Err(refusal("PA type listed twice"));
        }
        if selection::preauth(*pa_type).is_err() {
            return Err(refusal("PA type rejected by the security policy"));
        }
    }
    Ok(())
}

/// Admit a mechanism object identifier: well-formed minimal DER content octets,
/// bounded, not reserved by a built-in mechanism and not taken.
/// # Errors
/// Returns `InvalidRegistration`.
pub(super) fn mechanism(
    registered: &[Arc<dyn GssMechanism>],
    provider: &str,
    oid: &[u8],
) -> Result<(), Error> {
    let refusal = |reason: &'static str| Error::InvalidRegistration {
        interface: Interface::GssMechanism,
        id: provider.to_owned(),
        reason,
    };
    if !oid_well_formed(oid) {
        return Err(refusal("object identifier is malformed or too long"));
    }
    if RESERVED_OIDS.contains(&oid) {
        return Err(refusal("object identifier belongs to a built-in mechanism"));
    }
    if registered.iter().any(|entry| entry.oid() == oid) {
        return Err(refusal("object identifier is already registered"));
    }
    Ok(())
}

/// DER object-identifier content octets: non-empty, bounded, every
/// subidentifier minimally encoded and terminated.
fn oid_well_formed(oid: &[u8]) -> bool {
    let mut starts = true;
    for byte in oid {
        if starts && *byte == 0x80 {
            return false;
        }
        starts = *byte < 0x80;
    }
    (1..=MAX_OID_BYTES).contains(&oid.len()) && starts
}

/// A realm, principal component, local name or host: bounded, no control bytes.
pub(super) fn name(value: &str) -> bool {
    (1..=MAX_NAME_BYTES).contains(&value.len()) && !value.chars().any(char::is_control)
}

/// A local account name: a valid name without a path separator.
pub(super) fn local_name(value: &str) -> bool {
    name(value) && !value.contains('/')
}

/// A host name: a valid name without whitespace or a path separator.
pub(super) fn host(value: &str) -> bool {
    name(value) && !value.contains(|ch: char| ch.is_whitespace() || ch == '/')
}

/// A principal a provider names: a valid realm and 1..=`MAX_NAMES` valid components.
pub(super) fn principal(value: &Principal) -> bool {
    name(&value.realm)
        && (1..=MAX_NAMES).contains(&value.components.len())
        && value.components.iter().all(|component| name(component))
}

/// The id of an output-refusal error.
pub(super) fn malformed(interface: Interface, id: &str, reason: &'static str) -> Error {
    Error::MalformedOutput {
        interface,
        id: id.to_owned(),
        reason,
    }
}

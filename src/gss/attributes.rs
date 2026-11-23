//! Name attributes from the verified PAC.
//!
//! RFC 6680 name attributes of the initiator's name, as MIT 1.22.2's `mspac`
//! authorization-data module exposes them (`pac.c:880-1060`,
//! `naming_exts.c:253-380`): `urn:mspac:` names the whole PAC and
//! `urn:mspac:<buffer>` or `urn:mspac:<type>` one buffer. Only a PAC the
//! acceptor verified is read; its values are authenticated when the KDC
//! signature verified.

use super::{Error, EstablishedContext, NameAttribute};

/// The attribute prefix of the PAC.
const PREFIX: &str = "urn:mspac:";

/// The PAC buffers MIT names (`pac.c:885-909`).
const NAMED: [(u32, &str); 7] = [
    (1, "logon-info"),
    (2, "credentials-info"),
    (6, "server-checksum"),
    (7, "privsvr-checksum"),
    (10, "client-info"),
    (11, "delegation-info"),
    (12, "upn-dns-info"),
];

/// The attribute name of buffer `kind`.
fn name_of(kind: u32) -> String {
    NAMED
        .iter()
        .find(|(known, _)| *known == kind)
        .map_or_else(
            || format!("{PREFIX}{kind}"),
            |(_, suffix)| format!("{PREFIX}{suffix}"),
        )
}

/// What an attribute names.
enum Target {
    /// The whole PAC.
    Whole,
    /// One PAC buffer.
    Buffer(u32),
}

/// The target of an attribute (`mspac_attr2type`, `pac.c:928-950`).
fn target_of(attribute: &str) -> Option<Target> {
    let lower = attribute.to_ascii_lowercase();
    let suffix = lower.strip_prefix(PREFIX)?;
    if suffix.is_empty() {
        return Some(Target::Whole);
    }
    if let Some((kind, _)) = NAMED.iter().find(|(_, known)| *known == suffix) {
        return Some(Target::Buffer(*kind));
    }
    if !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    suffix
        .parse::<u32>()
        .ok()
        .filter(|kind| *kind != 0)
        .map(Target::Buffer)
}

/// `gss_inquire_name`'s attributes of the initiator's name.
pub(super) fn names(context: &EstablishedContext) -> Vec<String> {
    let Some(verified) = &context.pac else {
        return Vec::new();
    };
    let mut out = vec![PREFIX.to_owned()];
    out.extend(verified.pac().buffer_types().into_iter().map(name_of));
    out
}

/// `gss_get_name_attribute` of the initiator's name.
///
/// # Errors
///
/// Returns [`Error::NameAttributeUnavailable`] for an unknown or absent
/// attribute.
pub(super) fn get(context: &EstablishedContext, attribute: &str) -> Result<NameAttribute, Error> {
    let unavailable = || Error::NameAttributeUnavailable(attribute.to_owned());
    let verified = context.pac.as_ref().ok_or_else(unavailable)?;
    let pac = verified.pac();
    let value = match target_of(attribute).ok_or_else(unavailable)? {
        Target::Whole => pac.data().to_vec(),
        Target::Buffer(kind) => {
            let buffer = pac.buffer(kind).ok_or_else(unavailable)?;
            pac.buffer_bytes(buffer)
                .map_err(|_bounds| unavailable())?
                .to_vec()
        }
    };
    let checks = verified.checks();
    Ok(NameAttribute {
        value,
        authenticated: checks.server() && checks.kdc(),
        complete: true,
    })
}

//! Name parsing, display and the RFC 2743 exported-name token.
//!
//! Principal strings follow MIT 1.22.2 `krb5_parse_name` (`parse.c:30-210`)
//! and `krb5_unparse_name` (`unparse.c:60-135`); host-based names follow
//! `parse_hostbased` (`import_name.c:84-121`) without the local-host and DNS
//! lookups of `krb5_sname_to_principal`; exported names follow
//! `import_name.c:264-318` and `export_name.c:28-88`.

use core::str;

use super::{Error, Name, NameKind, NameType, ObjectIdentifier, Principal};

/// The longest principal string or exported name body, in bytes.
pub(super) const MAX_NAME_LEN: usize = 0x1000;
/// The longest certificate of a certificate name, in bytes.
const MAX_CERTIFICATE_LEN: usize = 0x1_0000;
/// The longest attribute block of a composite exported name, in bytes.
const MAX_ATTRIBUTES_LEN: usize = 0x1_0000;
/// The most components a principal string may have.
const MAX_COMPONENTS: usize = 64;
/// The DER of the krb5 mechanism OID `1.2.840.113554.1.2.2`.
const KRB5_OID_DER: [u8; 11] = [
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02,
];
/// `KRB5_NT_PRINCIPAL`.
const NT_PRINCIPAL: i32 = 1;
/// `KRB5_NT_SRV_INST`.
const NT_SRV_INST: i32 = 2;
/// `KRB5_NT_SRV_HST`.
const NT_SRV_HST: i32 = 3;
/// `KRB5_NT_X500_PRINCIPAL`.
const NT_X500_PRINCIPAL: i32 = 6;
/// `KRB5_NT_ENTERPRISE_PRINCIPAL`.
const NT_ENTERPRISE: i32 = 10;
/// `KRB5_NT_WELLKNOWN`.
const NT_WELLKNOWN: i32 = 11;
/// The anonymous principal's components (RFC 8062 section 3).
const ANONYMOUS: [&str; 2] = ["WELLKNOWN", "ANONYMOUS"];
/// The anonymous principal's realm.
const ANONYMOUS_REALM: &str = "WELLKNOWN:ANONYMOUS";

/// The arcs of every name type.
const NAME_TYPES: [(NameType, &[u32]); 10] = [
    (NameType::User, &[1, 2, 840, 113_554, 1, 2, 1, 1]),
    (NameType::MachineUid, &[1, 2, 840, 113_554, 1, 2, 1, 2]),
    (NameType::StringUid, &[1, 2, 840, 113_554, 1, 2, 1, 3]),
    (
        NameType::HostbasedService,
        &[1, 2, 840, 113_554, 1, 2, 1, 4],
    ),
    (NameType::Anonymous, &[1, 3, 6, 1, 5, 6, 3]),
    (NameType::Export, &[1, 3, 6, 1, 5, 6, 4]),
    (NameType::CompositeExport, &[1, 3, 6, 1, 5, 6, 6]),
    (NameType::Principal, &[1, 2, 840, 113_554, 1, 2, 2, 1]),
    (NameType::Enterprise, &[1, 2, 840, 113_554, 1, 2, 2, 6]),
    (NameType::X509Cert, &[1, 2, 840, 113_554, 1, 2, 2, 7]),
];

/// The RFC 2743 `GSS_C_NT_HOSTBASED_SERVICE_X` arcs.
const HOSTBASED_V2: [u32; 7] = [1, 3, 6, 1, 5, 6, 2];

/// The object identifier of `name_type`.
pub(super) fn oid(name_type: NameType) -> ObjectIdentifier {
    let arcs = NAME_TYPES
        .iter()
        .find(|(kind, _)| *kind == name_type)
        .map_or(&[][..], |(_, arcs)| *arcs);
    ObjectIdentifier::from_static(arcs)
}

/// The name types of `mechanism`.
pub(super) fn types_for(mechanism: &ObjectIdentifier) -> Vec<NameType> {
    if mechanism.is_kerberos_mechanism() {
        NAME_TYPES.iter().map(|(kind, _)| *kind).collect()
    } else {
        Vec::new()
    }
}

/// The name type of `oid`.
pub(super) fn from_oid(oid: &ObjectIdentifier) -> Option<NameType> {
    if oid.arcs() == HOSTBASED_V2 {
        return Some(NameType::HostbasedService);
    }
    NAME_TYPES
        .iter()
        .find(|(_, arcs)| oid.arcs() == *arcs)
        .map(|(kind, _)| *kind)
}

/// Import `bytes` as `name_type`.
///
/// # Errors
///
/// Returns the errors of [`super::Name::import`].
pub(super) fn import(bytes: &[u8], name_type: NameType) -> Result<Name, Error> {
    match name_type {
        NameType::HostbasedService => hostbased(text(bytes)?),
        NameType::User | NameType::Principal => principal(text(bytes)?, false, name_type),
        NameType::Enterprise => principal(text(bytes)?, true, name_type),
        NameType::Anonymous => Ok(Name {
            principal: Principal::new(ANONYMOUS_REALM, NT_WELLKNOWN, ANONYMOUS),
            imported_as: name_type,
            kind: NameKind::Principal,
            attributes: None,
        }),
        NameType::Export | NameType::CompositeExport => exported(bytes, name_type),
        NameType::X509Cert => {
            bounded(bytes.len(), MAX_CERTIFICATE_LEN)?;
            Ok(Name {
                principal: Principal::new("", NT_X500_PRINCIPAL, Vec::<String>::new()),
                imported_as: name_type,
                kind: NameKind::Certificate(bytes.to_vec()),
                attributes: None,
            })
        }
        NameType::MachineUid | NameType::StringUid => Err(Error::BadNameType(oid(name_type))),
    }
}

/// Import a user-id name through `resolve`.
///
/// # Errors
///
/// Returns the errors of [`super::Name::import_uid`].
pub(super) fn import_uid<F>(bytes: &[u8], name_type: NameType, resolve: F) -> Result<Name, Error>
where
    F: FnOnce(u32) -> Option<String>,
{
    let uid = match name_type {
        NameType::MachineUid => {
            let raw: [u8; 4] = bytes
                .try_into()
                .map_err(|_length| Error::BadName("a binary user id is four bytes"))?;
            if cfg!(target_endian = "big") {
                u32::from_be_bytes(raw)
            } else {
                u32::from_le_bytes(raw)
            }
        }
        NameType::StringUid => {
            let digits = text(bytes)?;
            if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(Error::BadName("a string user id is decimal digits"));
            }
            digits
                .parse::<u32>()
                .map_err(|_range| Error::BadName("a string user id is decimal digits"))?
        }
        NameType::HostbasedService
        | NameType::User
        | NameType::Anonymous
        | NameType::Export
        | NameType::CompositeExport
        | NameType::Principal
        | NameType::Enterprise
        | NameType::X509Cert => return Err(Error::BadNameType(oid(name_type))),
    };
    let account = resolve(uid).ok_or(Error::UnresolvedUid(uid))?;
    principal(&account, false, name_type)
}

/// Refuse a length above `maximum`.
///
/// # Errors
///
/// Returns [`Error::NameTooLong`].
const fn bounded(actual: usize, maximum: usize) -> Result<(), Error> {
    if actual > maximum {
        return Err(Error::NameTooLong { maximum, actual });
    }
    Ok(())
}

/// `bytes` as bounded UTF-8.
///
/// # Errors
///
/// Returns [`Error::NameTooLong`] or [`Error::BadName`].
fn text(bytes: &[u8]) -> Result<&str, Error> {
    bounded(bytes.len(), MAX_NAME_LEN)?;
    str::from_utf8(bytes).map_err(|_invalid| Error::BadName("a name is UTF-8"))
}

/// A host-based name: `service@host`, or `service` for any host.
///
/// # Errors
///
/// Returns [`Error::BadName`] for an empty service.
fn hostbased(value: &str) -> Result<Name, Error> {
    let (service, host) = value.split_once('@').unwrap_or((value, ""));
    if service.is_empty() {
        return Err(Error::BadName("a host-based name needs a service"));
    }
    Ok(Name {
        principal: Principal::new(
            "",
            NT_SRV_HST,
            [service.to_owned(), host.to_ascii_lowercase()],
        ),
        imported_as: NameType::HostbasedService,
        kind: NameKind::Hostbased,
        attributes: None,
    })
}

/// A principal name from MIT's string form.
///
/// # Errors
///
/// Returns [`Error::BadName`] for an empty or malformed string.
fn principal(value: &str, enterprise: bool, name_type: NameType) -> Result<Name, Error> {
    if value.is_empty() {
        return Err(Error::BadName("a principal name cannot be empty"));
    }
    let (components, realm) = parse(value, enterprise)?;
    let kind = if enterprise {
        NT_ENTERPRISE
    } else if components.len() == 2 && components.first().is_some_and(|first| first == "krbtgt") {
        NT_SRV_INST
    } else if components == ANONYMOUS && realm.as_deref() == Some(ANONYMOUS_REALM) {
        NT_WELLKNOWN
    } else {
        NT_PRINCIPAL
    };
    Ok(Name {
        principal: Principal::new(realm.unwrap_or_default(), kind, components),
        imported_as: name_type,
        kind: NameKind::Principal,
        attributes: None,
    })
}

/// Split a principal string into its components and its realm, if it names one.
///
/// # Errors
///
/// Returns [`Error::BadName`] for a separator in the realm, a second realm, a
/// trailing escape or more than 64 components.
fn parse(value: &str, enterprise: bool) -> Result<(Vec<String>, Option<String>), Error> {
    let mut components = vec![String::new()];
    let mut realm: Option<String> = None;
    let mut first_at = true;
    let mut chars = value.chars();
    while let Some(next) = chars.next() {
        if next == '/' && !enterprise {
            if realm.is_some() {
                return Err(Error::BadName("a realm cannot hold a component separator"));
            }
            if components.len() >= MAX_COMPONENTS {
                return Err(Error::BadName("a principal has at most 64 components"));
            }
            components.push(String::new());
            continue;
        }
        if next == '@' && (!enterprise || !first_at) {
            if realm.is_some() {
                return Err(Error::BadName("a principal names one realm"));
            }
            realm = Some(String::new());
            continue;
        }
        if next == '@' {
            first_at = false;
        }
        let literal = if next == '\\' {
            match chars.next() {
                None => return Err(Error::BadName("a principal cannot end with an escape")),
                Some('n') => '\n',
                Some('t') => '\t',
                Some('b') => '\u{8}',
                Some('0') => '\0',
                Some(other) => other,
            }
        } else {
            next
        };
        let target = match realm.as_mut() {
            Some(text) => text,
            None => components
                .last_mut()
                .ok_or(Error::BadName("a principal has a component"))?,
        };
        target.push(literal);
    }
    Ok((components, realm))
}

/// Append `value` to `out` in MIT's quoting.
fn quote(value: &str, out: &mut String) {
    for next in value.chars() {
        match next {
            '@' | '/' | '\\' => {
                out.push('\\');
                out.push(next);
            }
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{8}' => out.push_str("\\b"),
            '\0' => out.push_str("\\0"),
            _ => out.push(next),
        }
    }
}

/// The principal string of `principal` in MIT's quoting, realm included.
pub(super) fn unparse(principal: &Principal) -> String {
    let mut out = String::new();
    for (index, component) in principal.components.iter().enumerate() {
        if index > 0 {
            out.push('/');
        }
        quote(component, &mut out);
    }
    out.push('@');
    quote(&principal.realm, &mut out);
    out
}

/// Whether `principal` is the anonymous principal.
pub(super) fn is_anonymous(principal: &Principal) -> bool {
    principal.components == ANONYMOUS && principal.realm == ANONYMOUS_REALM
}

/// The displayed form of `name`.
pub(super) fn display(name: &Name) -> (String, NameType) {
    match &name.kind {
        NameKind::Certificate(_) => (String::new(), NameType::X509Cert),
        NameKind::Principal | NameKind::Hostbased => {
            let kind = if is_anonymous(&name.principal) {
                NameType::Anonymous
            } else {
                NameType::Principal
            };
            (unparse(&name.principal), kind)
        }
    }
}

/// The RFC 2743 exported name of `name`.
///
/// # Errors
///
/// Returns the errors of [`super::Name::export`].
pub(super) fn export(name: &Name) -> Result<Vec<u8>, Error> {
    if name.certificate().is_some() {
        return Err(Error::BadName("a certificate name has no exported form"));
    }
    let shown = unparse(&name.principal);
    bounded(shown.len(), MAX_NAME_LEN)?;
    let length = u32::try_from(shown.len()).map_err(|_range| Error::NameTooLong {
        maximum: MAX_NAME_LEN,
        actual: shown.len(),
    })?;
    let mut out = Vec::with_capacity(shown.len().saturating_add(19));
    out.extend_from_slice(&[0x04, 0x01, 0x00, 0x0b]);
    out.extend_from_slice(&KRB5_OID_DER);
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(shown.as_bytes());
    Ok(out)
}

/// Split a big-endian length-prefixed field off `bytes`, bounded by `maximum`.
///
/// # Errors
///
/// Returns [`Error::BadName`] for a truncated field and [`Error::NameTooLong`]
/// above `maximum`.
fn field(bytes: &[u8], maximum: usize) -> Result<(&[u8], &[u8]), Error> {
    let (prefix, rest) = bytes
        .split_first_chunk::<4>()
        .ok_or(Error::BadName("an exported name is truncated"))?;
    let length = usize::try_from(u32::from_be_bytes(*prefix))
        .map_err(|_range| Error::BadName("an exported name is truncated"))?;
    bounded(length, maximum)?;
    rest.split_at_checked(length)
        .ok_or(Error::BadName("an exported name is truncated"))
}

/// Import an exported or composite exported name.
///
/// # Errors
///
/// Returns [`Error::BadName`] for a malformed token or another mechanism's name
/// and [`Error::NameTooLong`] for an oversized field.
fn exported(bytes: &[u8], name_type: NameType) -> Result<Name, Error> {
    let malformed = Error::BadName("malformed exported name");
    let (header, after_header) = bytes.split_first_chunk::<4>().ok_or(malformed)?;
    let composite = match *header {
        [0x04, 0x01, 0x00, 0x0b] => false,
        [0x04, 0x02, 0x00, 0x0b] => true,
        _ => return Err(Error::BadName("malformed exported name")),
    };
    let (mechanism, after_mechanism) = after_header
        .split_first_chunk::<11>()
        .ok_or(Error::BadName("malformed exported name"))?;
    if *mechanism != KRB5_OID_DER {
        return Err(Error::BadName("an exported name of another mechanism"));
    }
    let (body, after_body) = field(after_mechanism, MAX_NAME_LEN)?;
    let (attributes, trailing) = if composite {
        let (block, after) = field(after_body, MAX_ATTRIBUTES_LEN)?;
        (Some(block.to_vec()), after)
    } else {
        (None, after_body)
    };
    if !trailing.is_empty() {
        return Err(Error::BadName("an exported name has trailing bytes"));
    }
    let mut imported = principal(text(body)?, false, name_type)?;
    imported.attributes = attributes;
    Ok(imported)
}

//! The `pkinit_*` relations of a realm.
//!
//! MIT 1.22.2 `pkinit_clnt.c:646-716` `pkinit_client_profile` reads them from
//! a realm subsection of `[libdefaults]` or from `[realms]`; this client reads
//! `[realms]`.
//!
//! Locations are opened here, never earlier: `FILE:` and `DIR:` name files,
//! `ENV:` names a variable that holds another location (read through the
//! secure-environment guard, so a set-id process never reads it). `PKCS11:`
//! and `PKCS12:` are refused with a typed error (D8), never skipped.

use std::{
    env, fs,
    io::Read as _,
    path::{Path, PathBuf},
};

use super::{
    CertificatePolicy, DhGroup, EkuChecking, KdcTrust, MAX_CRL_BYTES, MAX_IDENTITIES, ops,
};
use crate::{
    config::{
        Config, Toggle,
        section_values::{Location, Value},
    },
    error::Pkinit as Error,
    secure_env,
};

/// The most files one `DIR:` location contributes.
const MAX_DIRECTORY_FILES: usize = 64;

/// The relation `name` of `realm`, if set.
fn relation<'config>(config: &'config Config, realm: &str, name: &str) -> Option<&'config Value> {
    config
        .realms
        .iter()
        .filter(|entry| entry.name == realm)
        .find_map(|entry| entry.relations.get(name))
}

/// Read at most `limit` bytes of `path`.
///
/// # Errors
/// Returns [`Error::Io`] for an unreadable file and [`Error::TooLarge`] past `limit`.
pub(super) fn read(path: &Path, limit: usize) -> Result<Vec<u8>, Error> {
    let io = |source| Error::Io {
        path: path.to_path_buf(),
        source,
    };
    let file = fs::File::open(path).map_err(io)?;
    let mut bytes = Vec::new();
    let bound = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
    let count = file.take(bound).read_to_end(&mut bytes).map_err(io)?;
    if count > limit {
        return Err(Error::TooLarge {
            structure: "file",
            limit,
        });
    }
    Ok(bytes)
}

/// The location an `ENV:` variable names (MIT `pkinit_identity.c`), read
/// through the secure-environment guard.
///
/// # Errors
/// Returns [`Error::UnsupportedLocation`] for an unset variable or a value
/// that is not a `FILE:` or `DIR:` location.
fn pkinit_env_location(relation: &'static str, name: &str) -> Result<Location, Error> {
    let value =
        secure_env::ambient(|| env::var(name)).map_err(|_unset| Error::UnsupportedLocation {
            relation,
            location: "ENV (unset or unreadable)".to_owned(),
        })?;
    match value.split_once(':') {
        Some(("FILE", path)) if !path.is_empty() => Ok(Location::File(path.to_owned())),
        Some(("DIR", path)) if !path.is_empty() => Ok(Location::Directory(path.to_owned())),
        _ => Err(Error::UnsupportedLocation {
            relation,
            location: "ENV (not a FILE or DIR location)".to_owned(),
        }),
    }
}

/// The files of `relation` in `realm`: `FILE:` paths, the files of `DIR:`
/// directories with `suffix` (sorted), through `ENV:` references.
///
/// # Errors
/// Returns [`Error::UnsupportedLocation`] and [`Error::Io`].
fn pkinit_location_files(
    config: &Config,
    realm: &str,
    relation: &'static str,
    suffix: &str,
) -> Result<Vec<String>, Error> {
    let Some(Value::Locations(locations)) = self::relation(config, realm, relation) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for location in locations {
        let resolved = pkinit_resolved_location(relation, location)?;
        match resolved {
            Location::File(path) => out.push(path),
            Location::Directory(path) => out.extend(directory(Path::new(&path), suffix)?),
            Location::Pkcs11(_) => return Err(unsupported(relation, "PKCS11")),
            Location::Pkcs12(_) => return Err(unsupported(relation, "PKCS12")),
            Location::Environment(_) => return Err(unsupported(relation, "nested ENV")),
        }
    }
    Ok(out)
}

/// `location`, with an `ENV:` reference replaced by the location it names.
///
/// # Errors
/// Returns the errors of [`pkinit_env_location`].
fn pkinit_resolved_location(
    relation: &'static str,
    location: &Location,
) -> Result<Location, Error> {
    if let Location::Environment(name) = location {
        pkinit_env_location(relation, name)
    } else {
        Ok(location.clone())
    }
}

/// A refused location type.
fn unsupported(relation: &'static str, location: &str) -> Error {
    Error::UnsupportedLocation {
        relation,
        location: location.to_owned(),
    }
}

/// The regular files of `path` ending in `suffix` (any file when empty), sorted.
///
/// # Errors
/// Returns [`Error::Io`] and [`Error::TooLarge`] past [`MAX_DIRECTORY_FILES`].
fn directory(path: &Path, suffix: &str) -> Result<Vec<String>, Error> {
    let io = |source| Error::Io {
        path: path.to_path_buf(),
        source,
    };
    let mut names = Vec::new();
    for listed in fs::read_dir(path).map_err(io)? {
        let name = listed.map_err(io)?.path();
        let regular = fs::metadata(&name).is_ok_and(|metadata| metadata.is_file());
        let matches = name.to_str().is_some_and(|text| text.ends_with(suffix));
        if regular && matches {
            names.push(name.to_string_lossy().into_owned());
        }
        if names.len() > MAX_DIRECTORY_FILES {
            return Err(Error::TooLarge {
                structure: "directory",
                limit: MAX_DIRECTORY_FILES,
            });
        }
    }
    names.sort_unstable();
    Ok(names)
}

/// The DER items of the PEM files of `relation`.
///
/// # Errors
/// Returns the location, file and PEM errors.
fn pkinit_pem_files(
    config: &Config,
    realm: &str,
    relation: &'static str,
    crls: bool,
) -> Result<Vec<Vec<u8>>, Error> {
    let mut out = Vec::new();
    for path in pkinit_location_files(config, realm, relation, "")? {
        let bytes = read(Path::new(&path), MAX_CRL_BYTES)?;
        out.extend(if crls {
            ops::pem_crls(&bytes)?
        } else {
            ops::pem_certificates(&bytes)?
        });
    }
    Ok(out)
}

/// `pkinit_anchors`, `pkinit_pool` and `pkinit_revoke` of `realm`.
///
/// # Errors
/// Returns [`Error::NoAnchors`] and the location, file and PEM errors.
pub(super) fn pkinit_trust(config: &Config, realm: &str) -> Result<KdcTrust, Error> {
    let anchors = pkinit_pem_files(config, realm, "pkinit_anchors", false)?;
    if anchors.is_empty() {
        return Err(Error::NoAnchors {
            realm: realm.to_owned(),
        });
    }
    Ok(KdcTrust::new(anchors)
        .with_intermediates(pkinit_pem_files(config, realm, "pkinit_pool", false)?)
        .with_crls(pkinit_pem_files(config, realm, "pkinit_revoke", true)?))
}

/// The `pkinit_cert_match` rule texts of `realm`, when configured.
pub(super) fn pkinit_cert_rules(config: &Config, realm: &str) -> Option<Vec<String>> {
    match relation(config, realm, "pkinit_cert_match") {
        Some(Value::List(rules)) => Some(rules.clone()),
        _ => None,
    }
}

/// `pkinit_identities` of `realm` as `(certificate, key)` pairs: `FILE:cert[,key]`,
/// and for `DIR:` each `*.crt` with its `*.key` (MIT `pkinit_get_certs_dir`).
///
/// # Errors
/// Returns the location and directory errors and [`Error::TooLarge`] for more
/// than [`MAX_IDENTITIES`] identities.
pub(super) fn pkinit_identity_files(
    config: &Config,
    realm: &str,
) -> Result<Vec<(PathBuf, Option<PathBuf>)>, Error> {
    let Some(Value::Locations(locations)) = relation(config, realm, "pkinit_identities") else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for location in locations {
        let resolved = pkinit_resolved_location("pkinit_identities", location)?;
        match resolved {
            Location::File(text) => out.push(match text.split_once(',') {
                Some((certificate, key)) => (PathBuf::from(certificate), Some(PathBuf::from(key))),
                None => (PathBuf::from(text), None),
            }),
            Location::Directory(path) => {
                for certificate in directory(Path::new(&path), ".crt")? {
                    let key = certificate
                        .strip_suffix(".crt")
                        .map(|stem| PathBuf::from(format!("{stem}.key")));
                    if key.as_deref().is_some_and(Path::is_file) {
                        out.push((PathBuf::from(certificate), key));
                    }
                }
            }
            Location::Pkcs11(_) => return Err(unsupported("pkinit_identities", "PKCS11")),
            Location::Pkcs12(_) => return Err(unsupported("pkinit_identities", "PKCS12")),
            Location::Environment(_) => return Err(unsupported("pkinit_identities", "nested ENV")),
        }
    }
    if out.len() > MAX_IDENTITIES {
        return Err(Error::TooLarge {
            structure: "pkinit_identities",
            limit: MAX_IDENTITIES,
        });
    }
    Ok(out)
}

/// The certificate policy of `realm`.
///
/// # Errors
/// Returns the errors of [`dh_group`].
pub(super) fn policy(config: &Config, realm: &str) -> Result<CertificatePolicy, Error> {
    let eku = match relation(config, realm, "pkinit_eku_checking") {
        Some(Value::Choice(value)) if value.eq_ignore_ascii_case("kpServerAuth") => {
            EkuChecking::KpServerAuth
        }
        Some(Value::Choice(value)) if value.eq_ignore_ascii_case("none") => EkuChecking::None,
        _ => EkuChecking::KpKdc,
    };
    let group = match relation(config, realm, "pkinit_dh_min_bits") {
        Some(Value::Choice(value) | Value::Text(value)) => dh_group(value)?,
        _ => DhGroup::default(),
    };
    let hostnames = match relation(config, realm, "pkinit_kdc_hostname") {
        Some(Value::List(names)) => names.clone(),
        _ => Vec::new(),
    };
    let crl = relation(config, realm, "pkinit_require_crl_checking")
        .is_some_and(|value| !matches!(value, Value::Boolean(Toggle::Disabled)));
    Ok(CertificatePolicy::default()
        .with_eku_checking(eku)
        .with_group(group)
        .with_kdc_hostnames(hostnames)
        .with_crl_checking(crl))
}

/// The group of a `pkinit_dh_min_bits` value (MIT `parse_dh_min_bits`).
///
/// # Errors
/// Returns [`Error::DhGroupTooSmall`] up to 1024 bits and
/// [`Error::InvalidDhGroup`] for an unknown value.
pub(super) fn dh_group(value: &str) -> Result<DhGroup, Error> {
    let curves = [
        ("P-256", DhGroup::P256),
        ("P-384", DhGroup::P384),
        ("P-521", DhGroup::P521),
    ];
    if let Some((_, group)) = curves
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(value))
    {
        return Ok(*group);
    }
    match value.parse::<u32>() {
        Ok(bits) if bits <= 1024 => Err(Error::DhGroupTooSmall { bits }),
        Ok(1025..=2048) => Ok(DhGroup::Modp2048),
        Ok(2049..=4096) => Ok(DhGroup::Modp4096),
        _ => Err(Error::InvalidDhGroup {
            value: value.to_owned(),
        }),
    }
}

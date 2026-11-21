//! Trust anchors from `http_anchors` locations (MIT k5tls `load_anchor`,
//! `src/plugins/tls/k5tls/openssl.c:343-408`) and from configured PEM roots.
//!
//! `FILE:path` is a PEM file whose `CERTIFICATE` blocks are anchors; `DIR:path` is a
//! directory whose files not starting with `.` are such PEM files, at least one of
//! which must load. Reads are bounded in bytes per file and in files per directory.
//! `ENV:name` is refused: the crate reads the environment only through its explicit
//! `*_from_env` entry points, never inside a request, so the caller resolves the
//! variable and passes `FILE:`/`DIR:` or [`RustlsTransport::with_pem_roots`]
//! (MIT reads it with `secure_getenv`).
//!
//! [`RustlsTransport::with_pem_roots`]: super::RustlsTransport::with_pem_roots

use std::{fs, io::Read as _, path::Path};

use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, pem::PemObject as _},
};

use crate::{config::section_values::Location, error::KdcProxy as Error};

/// The largest anchor file read, in bytes.
const MAX_FILE: u64 = 1024 * 1024;
/// The most directory entries examined for one `DIR:` location.
const MAX_ENTRIES: usize = 1024;

/// The anchor error for `anchor`.
fn refused(anchor: &str, reason: &'static str) -> Error {
    Error::Anchor {
        anchor: anchor.to_owned(),
        reason,
    }
}

/// The certificates of PEM text, in order.
///
/// # Errors
///
/// Returns [`Error::Anchor`] naming `anchor` when a block does not parse or there is
/// no certificate.
pub(super) fn pem_certificates(
    pem: &[u8],
    anchor: &str,
) -> Result<Vec<CertificateDer<'static>>, Error> {
    let certificates = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_pem| refused(anchor, "a PEM block does not parse"))?;
    if certificates.is_empty() {
        return Err(refused(anchor, "it holds no certificate"));
    }
    Ok(certificates)
}

/// Add `certificates` to `roots`.
///
/// # Errors
///
/// Returns [`Error::Anchor`] naming `anchor` for a certificate that is not a usable
/// trust anchor.
pub(super) fn add<I>(roots: &mut RootCertStore, certificates: I, anchor: &str) -> Result<(), Error>
where
    I: IntoIterator<Item = CertificateDer<'static>>,
{
    for certificate in certificates {
        roots
            .add(certificate)
            .map_err(|_unusable| refused(anchor, "a certificate is not a usable trust anchor"))?;
    }
    Ok(())
}

/// Add the anchors of one PEM file.
///
/// # Errors
///
/// Returns [`Error::Anchor`] naming `anchor` when the file cannot be read, is larger
/// than [`MAX_FILE`] or holds no usable certificate.
fn file(roots: &mut RootCertStore, path: &Path, anchor: &str) -> Result<(), Error> {
    let mut pem = Vec::new();
    let _read: usize = fs::File::open(path)
        .and_then(|opened| {
            opened
                .take(MAX_FILE.saturating_add(1))
                .read_to_end(&mut pem)
        })
        .map_err(|_io| refused(anchor, "the file cannot be read"))?;
    if u64::try_from(pem.len()).map_or(true, |length| length > MAX_FILE) {
        return Err(refused(anchor, "the file is larger than 1 MiB"));
    }
    add(roots, pem_certificates(&pem, anchor)?, anchor)
}

/// Add the anchors of every file in a directory whose name does not start with `.`.
///
/// # Errors
///
/// Returns [`Error::Anchor`] naming `anchor` when the directory cannot be read, has
/// more than [`MAX_ENTRIES`] entries, or no file in it loads (MIT `load_anchor_dir`).
fn directory(roots: &mut RootCertStore, path: &Path, anchor: &str) -> Result<(), Error> {
    let entries =
        fs::read_dir(path).map_err(|_io| refused(anchor, "the directory cannot be read"))?;
    let mut loaded = false;
    for (count, entry) in entries.enumerate() {
        if count >= MAX_ENTRIES {
            return Err(refused(anchor, "the directory has more than 1024 entries"));
        }
        let found = entry.map_err(|_io| refused(anchor, "the directory cannot be read"))?;
        if found.file_name().as_encoded_bytes().starts_with(b".") {
            continue;
        }
        loaded |= file(roots, &found.path(), anchor).is_ok();
    }
    if loaded {
        Ok(())
    } else {
        Err(refused(
            anchor,
            "no file in the directory holds a usable certificate",
        ))
    }
}

/// Add the anchors of one `http_anchors` location.
///
/// # Errors
///
/// Returns [`Error::Anchor`] for a location that does not load, an `ENV:` location
/// (no environment read happens inside a request), and a PKCS#11 or PKCS#12
/// location, which is no trust anchor.
pub(super) fn load(roots: &mut RootCertStore, location: &Location) -> Result<(), Error> {
    match location {
        Location::File(path) => file(roots, Path::new(path), &format!("FILE:{path}")),
        Location::Directory(path) => directory(roots, Path::new(path), &format!("DIR:{path}")),
        Location::Environment(name) => Err(refused(
            &format!("ENV:{name}"),
            "an ENV: location is not read; resolve it and pass FILE:, DIR: or PEM roots",
        )),
        Location::Pkcs12(_) | Location::Pkcs11(_) => Err(refused(
            "PKCS",
            "a PKCS#11 or PKCS#12 location is not a trust anchor",
        )),
    }
}

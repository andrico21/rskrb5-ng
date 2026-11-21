//! The operations without the leaf: every call is [`Error::Unavailable`].
//!
//! Without the `pkinit` feature nothing is parsed, signed or agreed, so the
//! engine never sends a PA-PK-AS-REQ and no configured identity or anchor is
//! silently ignored.

use alloc::sync::Arc;

use zeroize::Zeroizing;

use super::{
    CertificatePolicy, DhGroup, Identity, KdcTrust, Signer,
    exchange::{ReplyInput, RequestInput},
};
use crate::{error::Pkinit as Error, keytab::EncryptionKey};

/// Unavailable.
///
/// # Errors
/// Always [`Error::Unavailable`].
pub(super) const fn pem_certificates(_text: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    Err(Error::Unavailable)
}

/// Unavailable.
///
/// # Errors
/// Always [`Error::Unavailable`].
pub(super) const fn pem_crls(_text: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    Err(Error::Unavailable)
}

/// Unavailable.
///
/// # Errors
/// Always [`Error::Unavailable`].
pub(super) const fn software_signer(
    _key: &[u8],
    _certificate: Option<&Vec<u8>>,
) -> Result<Arc<dyn Signer>, Error> {
    Err(Error::Unavailable)
}

/// Unavailable.
///
/// # Errors
/// Always [`Error::Unavailable`].
pub(super) const fn request(
    _identity: Option<&Identity>,
    _group: DhGroup,
    _input: &RequestInput<'_>,
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), Error> {
    Err(Error::Unavailable)
}

/// Unavailable.
///
/// # Errors
/// Always [`Error::Unavailable`].
pub(super) const fn outgoing(_value: &[u8]) -> Result<(), Error> {
    Err(Error::Unavailable)
}

/// Unavailable.
///
/// # Errors
/// Always [`Error::Unavailable`].
pub(super) const fn reply(
    _ephemeral: (DhGroup, &[u8]),
    _nonce: u32,
    _context: (&KdcTrust, &CertificatePolicy),
    _input: &ReplyInput<'_>,
) -> Result<EncryptionKey, Error> {
    Err(Error::Unavailable)
}

/// Unavailable.
///
/// # Errors
/// Always [`Error::Unavailable`].
pub(super) const fn verify_anonymous(
    _kx: &[u8],
    _reply_key: &EncryptionKey,
    _session_key: &EncryptionKey,
) -> Result<(), Error> {
    Err(Error::Unavailable)
}

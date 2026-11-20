//! Version-4 marshalling of single principals and credentials.
//!
//! This is the encoding the KCM protocol carries (MIT 1.22.2
//! `src/lib/krb5/ccache/cc_kcm.c` `k5_marshal_princ`/`k5_marshal_cred` with
//! version 4, `ccmarshal.c`). It reuses the file codec of `rskrb5-ng` by
//! framing the item as a cache file.

use rskrb5_ng::{
    ccache::{CCache, Credential, Principal, stores::CacheVersion},
    error::Ccache as Error,
};

use crate::Secret;

/// The version-4 file prefix: magic, version, and an empty header.
const FILE_PREFIX: [u8; 4] = [0x05, 0x04, 0x00, 0x00];

/// The default principal of the frames that carry one credential.
fn placeholder() -> Principal {
    Principal::new("RSKRB5-NG-OS", 1, vec!["frame".to_owned()])
}

/// A version-4 cache file of `cache`.
/// # Errors
/// Returns the serialization errors of [`CCache::to_bytes`].
fn file(mut cache: CCache) -> Result<Secret, Error> {
    cache.set_version(CacheVersion::V4);
    Ok(Secret::from(cache.to_bytes()?))
}

/// The bytes of `file` after its first `skip` bytes.
/// # Errors
/// Returns [`Error::TooShort`] when the file is shorter.
fn tail(file: &[u8], skip: usize) -> Result<Secret, Error> {
    file.get(skip..)
        .map(|rest| Secret::from(rest.to_vec()))
        .ok_or(Error::TooShort { actual: file.len() })
}

/// The version-4 encoding of a principal.
/// # Errors
/// Returns the serialization errors of [`CCache::to_bytes`].
pub(crate) fn principal(principal: &Principal) -> Result<Secret, Error> {
    tail(&file(CCache::new(principal.clone()))?, FILE_PREFIX.len())
}

/// The version-4 encoding of a credential.
/// # Errors
/// Returns the serialization errors of [`CCache::to_bytes`].
pub(crate) fn credential(credential: &Credential) -> Result<Secret, Error> {
    let skip = principal(&placeholder())?
        .len()
        .saturating_add(FILE_PREFIX.len());
    let mut cache = CCache::new(placeholder());
    cache.credentials_mut().push(credential.clone());
    tail(&file(cache)?, skip)
}

/// Parse a framed cache file.
/// # Errors
/// Returns the errors of [`CCache::parse`].
fn parse(parts: &[&[u8]]) -> Result<CCache, Error> {
    let length = parts
        .iter()
        .map(|part| part.len())
        .fold(FILE_PREFIX.len(), usize::saturating_add);
    let mut input = Vec::with_capacity(length);
    input.extend_from_slice(&FILE_PREFIX);
    for part in parts {
        input.extend_from_slice(part);
    }
    CCache::parse(&Secret::from(input))
}

/// Decode exactly one version-4 principal.
/// # Errors
/// Returns the errors of [`CCache::parse`], and [`Error::InvalidCacheName`]
/// when bytes follow the principal.
pub(crate) fn parse_principal(bytes: &[u8]) -> Result<Principal, Error> {
    let cache = parse(&[bytes])?;
    if cache.credentials().is_empty() {
        Ok(cache.default_principal().clone())
    } else {
        Err(Error::InvalidCacheName)
    }
}

/// Decode exactly one version-4 credential.
/// # Errors
/// Returns the errors of [`CCache::parse`], and [`Error::InvalidCacheName`]
/// when the bytes hold no credential or more than one.
pub(crate) fn parse_credential(bytes: &[u8]) -> Result<Credential, Error> {
    let frame = principal(&placeholder())?;
    let mut cache = parse(&[&frame, bytes])?;
    let credentials = cache.credentials_mut();
    match (credentials.pop(), credentials.is_empty()) {
        (Some(credential), true) => Ok(credential),
        (_, _) => Err(Error::InvalidCacheName),
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use rskrb5_ng::{
        ccache::{Credential, CredentialTimes, EncryptionKey, Principal},
        error::Ccache,
    };

    use super::{credential, parse_credential, parse_principal, principal};

    /// A credential with every field the store paths carry.
    fn sample() -> Credential {
        let client = Principal::new("EXAMPLE.ORG", 1, vec!["alice".to_owned()]);
        let server = Principal::new(
            "EXAMPLE.ORG",
            2,
            vec!["krbtgt".to_owned(), "EXAMPLE.ORG".to_owned()],
        );
        let mut times = CredentialTimes::default();
        times.auth_time = 1;
        times.start_time = 2;
        times.end_time = 3;
        times.renew_till = 4;
        Credential::new(
            client,
            server,
            EncryptionKey::new(18, vec![7; 32]),
            times,
            [0x40, 0xe1, 0, 0],
            vec![0x61, 0x03, 0x02, 0x01, 0x05].into(),
        )
    }

    /// Principals round-trip and match the version-4 layout of MIT.
    #[test]
    fn principal_round_trip_and_layout() -> Result<(), Ccache> {
        // Given a two-component principal.
        let value = Principal::new("R", 2, vec!["a".to_owned(), "bc".to_owned()]);
        // When it is encoded and decoded.
        let bytes = principal(&value)?;
        // Then the bytes are name type, count, realm and components, big-endian.
        assert_eq!(
            bytes.as_slice(),
            [
                0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 1, b'R', 0, 0, 0, 1, b'a', 0, 0, 0, 2, b'b', b'c'
            ]
        );
        assert_eq!(parse_principal(&bytes)?, value);
        Ok(())
    }

    /// Credentials round-trip; trailing or missing credentials are refused.
    #[test]
    fn credential_round_trip_and_refusals() -> Result<(), Ccache> {
        // Given a credential and its encoding.
        let value = sample();
        let bytes = credential(&value)?;
        // When it is decoded, doubled or emptied.
        // Then only the exact single credential decodes.
        assert_eq!(parse_credential(&bytes)?, value);
        let doubled = [bytes.as_slice(), bytes.as_slice()].concat();
        assert!(parse_credential(&doubled).is_err(), "two credentials");
        assert!(parse_credential(&[]).is_err(), "no credential");
        assert!(parse_principal(&[0, 0]).is_err(), "truncated principal");
        Ok(())
    }
}

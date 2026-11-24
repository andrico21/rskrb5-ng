//! The sealed session format.
//!
//! ```text
//! value      = base64url (no padding) of blob
//! blob       = "HSES" | version (1 byte, 1) | ciphertext
//! ciphertext = aes256-cts-hmac-sha384-192 (RFC 8009) encryption, key usage
//!              0x48534553, of  "HSES" | version | id (16 bytes)
//!              | generation (u32) | issued (u64) | expires (u64)
//!              | name type (i32) | realm | component count (1 byte) | components
//! realm, component = length (u16) | bytes
//! ```
//!
//! All integers are big-endian. The clear prefix only lets a foreign value be
//! refused cheaply; the sealed copy of it is compared after decryption, so the
//! prefix is authenticated too.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use zeroize::Zeroizing;

use crate::{
    crypto::AesSha2Etype, error::HttpSession as Error, gss::TransferKey, service::Principal,
};

/// The longest cookie value the manager decodes, in bytes.
pub(super) const MAX_VALUE_BYTES: usize = 4096;
/// The magic of a session blob.
const MAGIC: [u8; 4] = *b"HSES";
/// The format version.
const VERSION: u8 = 1;
/// The key usage of the RFC 8009 encryption ("HSES").
const USAGE: u32 = 0x4853_4553;
/// The profile that seals sessions.
const PROFILE: AesSha2Etype = AesSha2Etype::Aes256;
/// The most name components of a principal.
const MAX_COMPONENTS: usize = 8;
/// The longest realm or component, in bytes.
const MAX_PART_BYTES: usize = 255;

/// What a sealed session holds besides the principal.
pub(super) struct Fields {
    /// The session id.
    pub id: [u8; 16],
    /// The generation.
    pub generation: u32,
    /// When it was issued, in seconds since the epoch.
    pub issued: u64,
    /// When it ends, in seconds since the epoch.
    pub expires: u64,
}

/// A malformed-blob error.
const fn malformed(reason: &'static str) -> Error {
    Error::Malformed { reason }
}

/// Append a length-prefixed part.
///
/// # Errors
///
/// Returns [`Error::UnsupportedPrincipal`] for a part over 255 bytes.
fn put(out: &mut Vec<u8>, part: &str) -> Result<(), Error> {
    if part.len() > MAX_PART_BYTES {
        return Err(Error::UnsupportedPrincipal {
            reason: "a name part is longer than 255 bytes",
        });
    }
    out.extend_from_slice(&u16::try_from(part.len()).unwrap_or(u16::MAX).to_be_bytes());
    out.extend_from_slice(part.as_bytes());
    Ok(())
}

/// Seal `principal` and `fields` under `key` into a cookie value.
///
/// # Errors
///
/// Returns [`Error::UnsupportedPrincipal`] for a principal that does not fit,
/// and the random-source and sealing errors.
pub(super) fn seal(
    key: &TransferKey,
    principal: &Principal,
    fields: &Fields,
) -> Result<String, Error> {
    if principal.components.len() > MAX_COMPONENTS {
        return Err(Error::UnsupportedPrincipal {
            reason: "more than 8 name components",
        });
    }
    let mut plain = Zeroizing::new(Vec::with_capacity(256));
    plain.extend_from_slice(&MAGIC);
    plain.push(VERSION);
    plain.extend_from_slice(&fields.id);
    plain.extend_from_slice(&fields.generation.to_be_bytes());
    plain.extend_from_slice(&fields.issued.to_be_bytes());
    plain.extend_from_slice(&fields.expires.to_be_bytes());
    plain.extend_from_slice(&principal.name_type.to_be_bytes());
    put(&mut plain, &principal.realm)?;
    plain.push(u8::try_from(principal.components.len()).unwrap_or(u8::MAX));
    for component in &principal.components {
        put(&mut plain, component)?;
    }
    let mut confounder = Zeroizing::new([0_u8; 16]);
    getrandom::fill(confounder.as_mut_slice())?;
    let ciphertext = PROFILE.encrypt_message_with_confounder(
        key.bytes(),
        &plain,
        USAGE,
        confounder.as_slice(),
    )?;
    let mut blob = Vec::with_capacity(ciphertext.len().saturating_add(5));
    blob.extend_from_slice(&MAGIC);
    blob.push(VERSION);
    blob.extend_from_slice(&ciphertext);
    Ok(URL_SAFE_NO_PAD.encode(blob))
}

/// A cursor over the decrypted body.
struct Reader<'bytes>(&'bytes [u8]);

impl<'bytes> Reader<'bytes> {
    /// The next `count` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Malformed`] when fewer bytes remain.
    fn take(&mut self, count: usize) -> Result<&'bytes [u8], Error> {
        let (head, tail) = self
            .0
            .split_at_checked(count)
            .ok_or(malformed("a session shorter than its fields"))?;
        self.0 = tail;
        Ok(head)
    }

    /// The next `N` bytes as an array.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Malformed`] when fewer bytes remain.
    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        <[u8; N]>::try_from(self.take(N)?)
            .map_err(|_length| malformed("a field of the wrong length"))
    }

    /// The next length-prefixed text.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Malformed`] for a part that is too long, too short or not UTF-8.
    fn text(&mut self) -> Result<String, Error> {
        let length = usize::from(u16::from_be_bytes(self.array()?));
        if length > MAX_PART_BYTES {
            return Err(malformed("a name part longer than 255 bytes"));
        }
        String::from_utf8(self.take(length)?.to_vec())
            .map_err(|_text| malformed("a name part that is not UTF-8"))
    }
}

/// Open a cookie value under `key`.
///
/// # Errors
///
/// Returns [`Error::TooLarge`] for a value over 4096 bytes, [`Error::Malformed`]
/// for one that is not a session of this format and [`Error::Unauthentic`] for
/// one that does not authenticate under `key`.
pub(super) fn open(key: &TransferKey, value: &str) -> Result<(Fields, Principal), Error> {
    if value.len() > MAX_VALUE_BYTES {
        return Err(Error::TooLarge {
            limit: MAX_VALUE_BYTES,
            actual: value.len(),
        });
    }
    let blob = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_decode| malformed("the value is not base64url"))?;
    let (prefix, ciphertext) = blob
        .split_at_checked(5)
        .ok_or(malformed("a value shorter than its prefix"))?;
    if prefix.get(..4) != Some(&MAGIC[..]) || prefix.get(4) != Some(&VERSION) {
        return Err(malformed("not a session of this format"));
    }
    let plain = Zeroizing::new(
        PROFILE
            .decrypt_message(key.bytes(), ciphertext, USAGE)
            .map_err(|_failure| Error::Unauthentic)?,
    );
    let mut reader = Reader(&plain);
    if reader.take(5)? != prefix {
        return Err(malformed("the sealed prefix differs"));
    }
    let fields = Fields {
        id: reader.array()?,
        generation: u32::from_be_bytes(reader.array()?),
        issued: u64::from_be_bytes(reader.array()?),
        expires: u64::from_be_bytes(reader.array()?),
    };
    let name_type = i32::from_be_bytes(reader.array()?);
    let realm = reader.text()?;
    let count = usize::from(u8::from_be_bytes(reader.array()?));
    if count > MAX_COMPONENTS {
        return Err(malformed("more than 8 name components"));
    }
    let mut components = Vec::with_capacity(count);
    for _component in 0..count {
        components.push(reader.text()?);
    }
    if !reader.0.is_empty() {
        return Err(malformed("bytes after the session"));
    }
    Ok((fields, Principal::new(realm, name_type, components)))
}

//! The DOMAIN-X500-COMPRESS transited encoding (RFC 4120 section 3.3.3.2).
//!
//! [`decode`] expands an encoding into the realms it names, the realms an empty
//! component stands for included, exactly as MIT 1.22.2 `foreach_realm` does
//! (`src/lib/krb5/krb/chk_trans.c:45-286`), with these refusals MIT does not
//! make: a trailing escape, a NUL byte other than one trailing NUL (which MIT
//! strips, `chk_trans.c:319-320`), a realm name that is not UTF-8, and the
//! bounds below. [`encode`] writes the compressed form a decoder expands back
//! to the same list.
//!
//! # Security
//!
//! The input is untrusted ticket plaintext. An encoding longer than
//! [`MAX_ENCODED_BYTES`] is refused before it is read, a realm name grows to at
//! most [`MAX_REALM_BYTES`] bytes (MIT's buffer, `chk_trans.c:43`), and at most
//! [`MAX_REALMS`] realms are kept, the expanded ones included.

use core::{mem, str};

use crate::error::Routing as Error;

/// RFC 4120 `tr-type` of DOMAIN-X500-COMPRESS.
pub const DOMAIN_X500_COMPRESS: i32 = 1;
/// Largest encoding decoded, in bytes.
pub const MAX_ENCODED_BYTES: usize = 4_096;
/// Largest realm name, in bytes, after its compressed form is expanded.
pub const MAX_REALM_BYTES: usize = 512;
/// Most realms one encoding names, the expanded ones included.
pub const MAX_REALMS: usize = 64;

/// Expand a DOMAIN-X500-COMPRESS encoding between `client_realm` and
/// `server_realm` into the realms it names, in MIT's order.
///
/// # Errors
///
/// Returns [`Error::TransitedTooLong`], [`Error::TransitedRealmTooLong`] or
/// [`Error::TransitedTooManyRealms`] past a bound, and
/// [`Error::MalformedTransited`] for an encoding MIT refuses (names of two
/// styles or with different suffixes around an expanded component) or this
/// crate refuses (see the module documentation).
#[inline]
pub fn decode(
    contents: &[u8],
    client_realm: &str,
    server_realm: &str,
) -> Result<Vec<String>, Error> {
    let encoding = match contents.split_last() {
        Some((&0, rest)) => rest,
        _ => contents,
    };
    if encoding.len() > MAX_ENCODED_BYTES {
        return Err(Error::TransitedTooLong {
            max: MAX_ENCODED_BYTES,
        });
    }
    if encoding.is_empty() {
        return Ok(Vec::new());
    }
    if encoding.contains(&0) {
        return Err(malformed("a NUL byte inside the encoding"));
    }
    let mut out = Realms(Vec::new());
    let mut component = Vec::new();
    let mut last = Vec::new();
    let mut escaped = false;
    let mut expand = false;
    for (index, &byte) in encoding.iter().enumerate() {
        if escaped {
            bounded_push(&mut component, byte)?;
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == b',' && component.is_empty() {
            expand = true;
            if index == 0 {
                last = client_realm.as_bytes().to_vec();
            }
        } else if byte == b',' {
            let realm = join(&last, mem::take(&mut component))?;
            out.push(&realm)?;
            if mem::take(&mut expand) {
                between(&mut out, &realm, &last)?;
            }
            last = realm;
        } else if byte == b' ' && component.is_empty() {
            last.clear();
        } else {
            bounded_push(&mut component, byte)?;
        }
    }
    if escaped {
        return Err(malformed("a trailing escape"));
    }
    if component.is_empty() {
        between(&mut out, &last, server_realm.as_bytes())?;
    } else {
        let realm = join(&last, component)?;
        out.push(&realm)?;
        if expand {
            between(&mut out, &realm, &last)?;
        }
    }
    Ok(out.0)
}

/// Encode `realms` in the compressed DOMAIN-X500-COMPRESS form.
///
/// A realm that extends the previous one by a leading domain component or a
/// trailing X.500 component is written as that component, and the characters
/// the decoder treats specially are escaped or protected.
///
/// # Errors
///
/// Returns [`Error::MalformedTransited`] for an empty realm or one holding a
/// NUL byte, [`Error::TransitedRealmTooLong`] for a realm past
/// [`MAX_REALM_BYTES`], [`Error::TransitedTooManyRealms`] for more than
/// [`MAX_REALMS`] realms, and [`Error::TransitedTooLong`] for an encoding past
/// [`MAX_ENCODED_BYTES`].
#[inline]
pub fn encode<S>(realms: &[S]) -> Result<Vec<u8>, Error>
where
    S: AsRef<str>,
{
    if realms.len() > MAX_REALMS {
        return Err(Error::TransitedTooManyRealms { max: MAX_REALMS });
    }
    let mut out = Vec::new();
    let mut previous: Option<&str> = None;
    for realm in realms.iter().map(AsRef::as_ref) {
        if realm.is_empty() || realm.contains('\0') {
            return Err(malformed("an empty realm or one holding a NUL byte"));
        }
        if realm.len() > MAX_REALM_BYTES {
            return Err(Error::TransitedRealmTooLong {
                max: MAX_REALM_BYTES,
            });
        }
        let written = previous.map_or(realm, |before| {
            out.push(b',');
            domain_head(realm, before)
                .or_else(|| x500_rest(realm, before))
                .unwrap_or_else(|| {
                    if realm.starts_with('/') || realm.ends_with('.') {
                        out.push(b' ');
                    }
                    realm
                })
        });
        for (index, byte) in written.bytes().enumerate() {
            if matches!(byte, b',' | b'\\') || (index == 0 && byte == b' ') {
                out.push(b'\\');
            }
            out.push(byte);
        }
        previous = Some(realm);
    }
    if out.len() > MAX_ENCODED_BYTES {
        return Err(Error::TransitedTooLong {
            max: MAX_ENCODED_BYTES,
        });
    }
    Ok(out)
}

/// The leading components of `realm` when it is `before` with domain components
/// prepended, the joining dot included (`EDU`, `MIT.EDU` -> `MIT.`).
fn domain_head<'realm>(realm: &'realm str, before: &str) -> Option<&'realm str> {
    let head = realm.strip_suffix(before)?;
    (!realm.starts_with('/') && !before.starts_with('/') && head.ends_with('.')).then_some(head)
}

/// The trailing components of `realm` when it is `before` with X.500
/// components appended, the joining slash included (`/COM`, `/COM/HP` -> `/HP`).
fn x500_rest<'realm>(realm: &'realm str, before: &str) -> Option<&'realm str> {
    let rest = realm.strip_prefix(before)?;
    (before.starts_with('/') && rest.starts_with('/')).then_some(rest)
}

/// The realms an encoding names, bounded.
struct Realms(Vec<String>);

impl Realms {
    /// Keep one realm.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TransitedTooManyRealms`] past the bound and
    /// [`Error::MalformedTransited`] for a name that is not UTF-8.
    fn push(&mut self, realm: &[u8]) -> Result<(), Error> {
        if self.0.len() >= MAX_REALMS {
            return Err(Error::TransitedTooManyRealms { max: MAX_REALMS });
        }
        let name =
            str::from_utf8(realm).map_err(|_utf8| malformed("a realm name that is not UTF-8"))?;
        self.0.push(name.to_owned());
        Ok(())
    }
}

/// Append one byte to a component, bounded.
///
/// # Errors
///
/// Returns [`Error::TransitedRealmTooLong`] past [`MAX_REALM_BYTES`].
fn bounded_push(component: &mut Vec<u8>, byte: u8) -> Result<(), Error> {
    if component.len() >= MAX_REALM_BYTES {
        return Err(Error::TransitedRealmTooLong {
            max: MAX_REALM_BYTES,
        });
    }
    component.push(byte);
    Ok(())
}

/// Expand a compressed component against the previous realm (MIT `maybe_join`,
/// `chk_trans.c:137-163`): a leading `/` appends it to the previous X.500
/// name, a trailing `.` prepends it to the previous domain name.
///
/// # Errors
///
/// Returns [`Error::TransitedRealmTooLong`] past [`MAX_REALM_BYTES`].
fn join(last: &[u8], mut component: Vec<u8>) -> Result<Vec<u8>, Error> {
    let joined = if component.first() == Some(&b'/') {
        let mut name = last.to_vec();
        name.append(&mut component);
        name
    } else if component.last() == Some(&b'.') {
        component.extend_from_slice(last);
        component
    } else {
        return Ok(component);
    };
    if joined.len() > MAX_REALM_BYTES {
        return Err(Error::TransitedRealmTooLong {
            max: MAX_REALM_BYTES,
        });
    }
    Ok(joined)
}

/// Keep the realms strictly between two names of one style, one a suffix
/// (domain) or prefix (X.500) of the other (MIT `process_intermediates`,
/// `chk_trans.c:45-135`).
///
/// # Errors
///
/// Returns [`Error::MalformedTransited`] for names of two styles, unrelated
/// names, an empty name, and the errors of [`Realms::push`].
fn between(out: &mut Realms, first: &[u8], second: &[u8]) -> Result<(), Error> {
    let (short, long) = if first.len() > second.len() {
        (second, first)
    } else {
        (first, second)
    };
    if short.len() == long.len() {
        return if short == long {
            Ok(())
        } else {
            Err(malformed(
                "different names of equal length around an expansion",
            ))
        };
    }
    if short.is_empty() {
        return Err(malformed("an empty name next to an expansion"));
    }
    let short_x500 = short.first() == Some(&b'/');
    if short_x500 != (long.first() == Some(&b'/')) {
        return Err(malformed("domain and X.500 names around an expansion"));
    }
    if short_x500 {
        if !long.starts_with(short) {
            return Err(malformed("X.500 names with different prefixes"));
        }
        for (index, &byte) in long.iter().enumerate().skip(short.len().saturating_add(1)) {
            if byte == b'/' {
                out.push(long.get(..index).unwrap_or_default())?;
            }
        }
    } else {
        if !long.ends_with(short) {
            return Err(malformed("domain names with different suffixes"));
        }
        let last_start = long.len().saturating_sub(short.len()).saturating_sub(1);
        for start in (1..=last_start).rev() {
            if long.get(start.saturating_sub(1)) == Some(&b'.') {
                out.push(long.get(start..).unwrap_or_default())?;
            }
        }
    }
    Ok(())
}

/// A malformed-encoding error.
const fn malformed(reason: &'static str) -> Error {
    Error::MalformedTransited { reason }
}

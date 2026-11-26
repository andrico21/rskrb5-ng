//! The cookie jar of the HTTP client (the `http-client` leaf).
//!
//! `CookieStore` keeps the cookies of the servers a [`NegotiateHttpClient`]
//! talks to, under the RFC 6265 storage model (`cookie_store`), in memory.
//!
//! [`NegotiateHttpClient`]: super::agent::NegotiateHttpClient
//!
//! # Security
//!
//! A cookie is a credential. The jar sends a cookie only to the host, path and
//! scheme that RFC 6265 matches it to (`Secure` cookies only over `https`,
//! `HttpOnly` ones only to HTTP requests) and never to another origin. On top
//! of `cookie_store` it refuses what the crate would accept: a `Secure` cookie
//! from a cleartext response, a `Domain` attribute while no public-suffix list
//! is configured (a host-only cookie needs none), a `Set-Cookie` value of more
//! than `CookieStore::MAX_SET_COOKIE_BYTES` bytes and more than
//! `CookieStore::DEFAULT_MAX_COOKIES` cookies, and a value with a byte outside
//! visible ASCII. The public-suffix list is
//! never compiled in: the application supplies the text of the list it trusts.
//! Values are never shown by `Debug`.
//!
//! Residual copies and limits (register row FU-HTC-P06): `cookie_store` holds
//! cookie values in ordinary heap strings and does not erase them when a
//! cookie is replaced or expires or the jar is dropped
//! (`docs/dependency-admission.md#cookie_store`), so a cookie value can stay in
//! freed memory. The jar lives in memory only and is never written to disk; an
//! application that needs persistent cookies implements
//! [`CookieJar`](super::wire::CookieJar) itself
//! and owns the protection of what it stores.
#[cfg(feature = "http-client")]
use core::fmt;

#[cfg(feature = "http-client")]
use cookie_store::{CookieError, RawCookie, StoreAction};
#[cfg(feature = "http-client")]
use http_types::{HeaderMap, HeaderValue, Uri, header::SET_COOKIE};
#[cfg(feature = "http-client")]
use publicsuffix::List;
#[cfg(feature = "http-client")]
use url::Url;

#[cfg(feature = "http-client")]
use super::{origin::Origin, wire::CookieJar};
#[cfg(feature = "http-client")]
use crate::error::HttpCookie as Error;

/// The longest public-suffix list text the jar parses, in bytes.
#[cfg(feature = "http-client")]
const MAX_SUFFIX_LIST_BYTES: usize = 1024 * 1024;

/// A cookie's domain, path and name: its place in the jar.
#[cfg(feature = "http-client")]
type Key = (String, String, String);

/// An in-memory cookie jar.
#[cfg(feature = "http-client")]
pub struct CookieStore {
    /// The cookies.
    jar: cookie_store::CookieStore,
    /// Whether a public-suffix list is configured.
    has_suffix_list: bool,
    /// The most cookies the jar holds.
    max_cookies: usize,
    /// The `Set-Cookie` values [`CookieJar::store`] refused.
    rejected: u64,
}

#[cfg(feature = "http-client")]
impl fmt::Debug for CookieStore {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CookieStore")
            .field("cookies", &self.len())
            .field("rejected", &self.rejected)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "http-client")]
impl Default for CookieStore {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

/// The `Url` and security of a request URI.
///
/// # Errors
///
/// Returns [`Error::InvalidUrl`] unless `uri` is an absolute `http` or `https`
/// URI with a host and no user information.
#[cfg(feature = "http-client")]
fn url_of(uri: &Uri) -> Result<(Url, bool), Error> {
    let origin = Origin::of(uri).map_err(|_refused| Error::InvalidUrl)?;
    let url = Url::parse(&uri.to_string()).map_err(|_refused| Error::InvalidUrl)?;
    Ok((url, origin.is_secure()))
}

/// Why `cookie_store` refused a cookie.
#[cfg(feature = "http-client")]
const fn reason(error: &CookieError) -> &'static str {
    match error {
        CookieError::NonHttpScheme => "an HttpOnly cookie came from a non-HTTP scheme",
        CookieError::DomainMismatch => "the Domain attribute does not match the request host",
        CookieError::PublicSuffix => "the Domain attribute is a public suffix",
        CookieError::NonRelativeScheme
        | CookieError::UnspecifiedDomain
        | CookieError::Parse
        | CookieError::Expired => "the cookie has no usable domain",
    }
}

#[cfg(feature = "http-client")]
impl CookieStore {
    /// The longest `Set-Cookie` value the jar parses, in bytes.
    pub const MAX_SET_COOKIE_BYTES: usize = 4096;
    /// The default most cookies the jar holds.
    pub const DEFAULT_MAX_COOKIES: usize = 256;

    /// An empty jar without a public-suffix list.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self {
            jar: cookie_store::CookieStore::new(),
            has_suffix_list: false,
            max_cookies: Self::DEFAULT_MAX_COOKIES,
            rejected: 0,
        }
    }

    /// This jar with the public-suffix list `list` (the text of the list).
    ///
    /// # Errors
    ///
    /// Returns [`Error::SuffixList`] when the text is longer than 1 MiB or does
    /// not parse.
    #[inline]
    pub fn with_public_suffix_list(mut self, list: &str) -> Result<Self, Error> {
        if list.len() > MAX_SUFFIX_LIST_BYTES {
            return Err(Error::SuffixList);
        }
        let parsed = List::from_bytes(list.as_bytes()).map_err(|_refused| Error::SuffixList)?;
        self.jar = self.jar.with_suffix_list(parsed);
        self.has_suffix_list = true;
        Ok(self)
    }

    /// Hold at most `max` cookies.
    #[inline]
    #[must_use]
    pub const fn with_max_cookies(mut self, max: usize) -> Self {
        self.max_cookies = max;
        self
    }

    /// Store one `Set-Cookie` value received in response to a request for `uri`.
    ///
    /// A cookie that is already expired removes the cookie it names, if any.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidUrl`] for a URI that is not plain `http` or
    /// `https`, [`Error::TooLarge`] and [`Error::Malformed`] for the value,
    /// [`Error::SecureOverCleartext`] and [`Error::DomainNeedsSuffixList`] for
    /// the refusals of the module documentation, [`Error::Rejected`] for a
    /// cookie the RFC 6265 storage model refuses and [`Error::JarFull`] when
    /// the jar holds its limit.
    #[inline]
    pub fn store_set_cookie(&mut self, uri: &Uri, value: &str) -> Result<(), Error> {
        let (url, secure) = url_of(uri)?;
        if value.len() > Self::MAX_SET_COOKIE_BYTES {
            return Err(Error::TooLarge {
                limit: Self::MAX_SET_COOKIE_BYTES,
                actual: value.len(),
            });
        }
        if !value
            .bytes()
            .all(|byte| byte == b'\t' || (0x20..0x7f).contains(&byte))
        {
            return Err(Error::Malformed);
        }
        let raw = RawCookie::parse(value.to_owned()).map_err(|_refused| Error::Malformed)?;
        if raw.secure() == Some(true) && !secure {
            return Err(Error::SecureOverCleartext);
        }
        if raw.domain().is_some() && !self.has_suffix_list {
            return Err(Error::DomainNeedsSuffixList);
        }
        if self.len() >= self.max_cookies {
            self.evict_expired();
        }
        let before = (self.len() >= self.max_cookies).then(|| self.keys());
        match self.jar.insert_raw(&raw, &url) {
            Ok(
                StoreAction::Inserted | StoreAction::UpdatedExisting | StoreAction::ExpiredExisting,
            )
            | Err(CookieError::Expired) => {}
            Err(CookieError::Parse) => return Err(Error::Malformed),
            Err(refused) => {
                return Err(Error::Rejected {
                    reason: reason(&refused),
                });
            }
        }
        if let Some(known) = before
            && self.len() > self.max_cookies
        {
            for (domain, path, name) in self.keys() {
                if !known.contains(&(domain.clone(), path.clone(), name.clone())) {
                    let _removed = self.jar.remove(&domain, &path, &name);
                }
            }
            return Err(Error::JarFull {
                limit: self.max_cookies,
            });
        }
        Ok(())
    }

    /// The place of every cookie held.
    fn keys(&self) -> Vec<Key> {
        self.jar
            .iter_any()
            .map(|held| {
                (
                    String::from(&held.domain),
                    String::from(&held.path),
                    held.name().to_owned(),
                )
            })
            .collect()
    }

    /// Drop every expired cookie.
    fn evict_expired(&mut self) {
        let expired: Vec<Key> = self
            .jar
            .iter_any()
            .filter(|held| held.is_expired())
            .map(|held| {
                (
                    String::from(&held.domain),
                    String::from(&held.path),
                    held.name().to_owned(),
                )
            })
            .collect();
        for (domain, path, name) in expired {
            let _removed = self.jar.remove(&domain, &path, &name);
        }
    }

    /// The cookies held.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.jar.iter_any().count()
    }

    /// Whether the jar is empty.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The `Set-Cookie` values refused so far by [`CookieJar::store`].
    #[inline]
    #[must_use]
    pub const fn rejected(&self) -> u64 {
        self.rejected
    }
}

#[cfg(feature = "http-client")]
impl CookieJar for CookieStore {
    #[inline]
    fn cookie_header(&self, uri: &Uri) -> Option<HeaderValue> {
        let (url, _secure) = url_of(uri).ok()?;
        let mut matched = self.jar.matches(&url);
        matched.sort_by(|left, right| {
            right
                .path
                .len()
                .cmp(&left.path.len())
                .then_with(|| left.name().cmp(right.name()))
        });
        if matched.is_empty() {
            return None;
        }
        let text = matched
            .iter()
            .map(|held| format!("{}={}", held.name(), held.value()))
            .collect::<Vec<_>>()
            .join("; ");
        let mut value = HeaderValue::from_str(&text).ok()?;
        value.set_sensitive(true);
        Some(value)
    }

    #[inline]
    fn store(&mut self, uri: &Uri, headers: &HeaderMap) {
        for value in headers.get_all(SET_COOKIE) {
            let stored = value
                .to_str()
                .map_err(|_refused| Error::Malformed)
                .and_then(|text| self.store_set_cookie(uri, text));
            if stored.is_err() {
                self.rejected = self.rejected.saturating_add(1);
            }
        }
    }
}

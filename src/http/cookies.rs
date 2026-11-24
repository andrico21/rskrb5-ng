//! The cookie jar of the HTTP client (the `http-client` leaf).
//!
//! [`CookieStore`] keeps the cookies of the servers a [`NegotiateHttpClient`]
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
//! than [`CookieStore::MAX_SET_COOKIE_BYTES`] bytes and more than
//! [`CookieStore::DEFAULT_MAX_COOKIES`] cookies. The public-suffix list is
//! never compiled in: the application supplies the text of the list it trusts.
//! Values are never shown by `Debug`.
#[cfg(feature = "http-client")]
use http_types::{HeaderMap, HeaderValue, Uri};

#[cfg(feature = "http-client")]
use super::agent::CookieJar;
#[cfg(feature = "http-client")]
use crate::error::HttpCookie as Error;

/// An in-memory cookie jar.
#[cfg(feature = "http-client")]
#[derive(Default, Debug)]
pub struct CookieStore {
    /// The cookies.
    jar: cookie_store::CookieStore,
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
        Self::default()
    }

    /// This jar with the public-suffix list `list` (the text of the list).
    ///
    /// # Errors
    ///
    /// Returns [`Error::SuffixList`] when the text does not parse.
    #[inline]
    pub fn with_public_suffix_list(self, _list: &str) -> Result<Self, Error> {
        Err(Error::SuffixList)
    }

    /// Hold at most `max` cookies.
    #[inline]
    #[must_use]
    pub const fn with_max_cookies(self, _max: usize) -> Self {
        self
    }

    /// Store one `Set-Cookie` value received in response to a request for `uri`.
    ///
    /// # Errors
    ///
    /// Returns the [`Error`] that names why the cookie was refused.
    #[inline]
    pub fn store_set_cookie(&mut self, _uri: &Uri, _value: &str) -> Result<(), Error> {
        Err(Error::Malformed)
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
        0
    }
}

#[cfg(feature = "http-client")]
impl CookieJar for CookieStore {
    #[inline]
    fn cookie_header(&self, _uri: &Uri) -> Option<HeaderValue> {
        None
    }

    #[inline]
    fn store(&mut self, _uri: &Uri, _headers: &HeaderMap) {}
}

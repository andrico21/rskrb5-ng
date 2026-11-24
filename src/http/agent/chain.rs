//! The request chain of one client call: the request as it is replayed, the
//! hop it is on, and the redirect rules that decide what a hop may carry.

use http_types::{
    HeaderMap, Method, Request, Response, StatusCode, Uri,
    header::{
        AUTHORIZATION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, HeaderValue,
        LOCATION, PROXY_AUTHORIZATION, TRANSFER_ENCODING,
    },
};

use super::RedirectPolicy;
use crate::{
    error::HttpClient as Error,
    http::origin::{Origin, resolve_location},
};

/// The request being sent, replayable for every challenge retry and redirect.
pub(super) struct Chain {
    /// The method of the current hop.
    method: Method,
    /// The URI of the current hop.
    uri: Uri,
    /// The headers every attempt carries (no cookie jar header, no token).
    headers: HeaderMap,
    /// The body every attempt carries.
    body: Vec<u8>,
    /// The origin of the current hop.
    origin: Origin,
    /// The origin the caller asked for: the only one that may be negotiated with.
    home: Origin,
    /// Whether the current origin has authenticated this chain already.
    authenticated: bool,
    /// The redirects followed.
    redirects: u8,
}

/// Whether `value` is a Negotiate credential.
fn is_negotiate(value: &HeaderValue) -> bool {
    value
        .as_bytes()
        .get(..9)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case(b"negotiate"))
}

impl Chain {
    /// Start a chain with `request`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidUri`] for a URI [`Origin::of`] refuses and
    /// [`Error::BodyTooLarge`] for a body past `max_body`.
    pub(super) fn start(request: Request<Vec<u8>>, max_body: usize) -> Result<Self, Error> {
        let (parts, body) = request.into_parts();
        if body.len() > max_body {
            return Err(Error::BodyTooLarge {
                limit: max_body,
                actual: body.len(),
            });
        }
        let origin = Origin::of(&parts.uri)?;
        Ok(Self {
            method: parts.method,
            uri: parts.uri,
            headers: parts.headers,
            body,
            home: origin.clone(),
            origin,
            authenticated: false,
            redirects: 0,
        })
    }

    /// The URI of the current hop.
    pub(super) const fn uri(&self) -> &Uri {
        &self.uri
    }

    /// The origin of the current hop.
    pub(super) const fn origin(&self) -> &Origin {
        &self.origin
    }

    /// The redirects followed so far.
    pub(super) const fn redirects(&self) -> u8 {
        self.redirects
    }

    /// Whether the current hop is on the origin the caller asked for.
    pub(super) fn on_home(&self) -> bool {
        self.origin == self.home
    }

    /// Whether a fresh token goes on the first request of this hop.
    pub(super) fn is_authenticated(&self) -> bool {
        self.authenticated && self.on_home()
    }

    /// Record that this origin authenticated the chain.
    pub(super) const fn authenticate(&mut self) {
        self.authenticated = true;
    }

    /// The request of the current hop, with `authorization` and `cookie` added.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidUri`] when the request cannot be built.
    pub(super) fn request(
        &self,
        authorization: Option<HeaderValue>,
        cookie: Option<HeaderValue>,
    ) -> Result<Request<Vec<u8>>, Error> {
        let mut request = Request::new(self.body.clone());
        *request.method_mut() = self.method.clone();
        *request.uri_mut() = self.uri.clone();
        *request.headers_mut() = self.headers.clone();
        if let Some(value) = authorization {
            drop(request.headers_mut().insert(AUTHORIZATION, value));
        }
        if let Some(value) = cookie {
            let text = request.headers().get(COOKIE).map_or_else(
                || value.as_bytes().to_vec(),
                |own| [own.as_bytes(), b"; ", value.as_bytes()].concat(),
            );
            let mut joined = HeaderValue::from_bytes(&text).map_err(|_text| Error::InvalidUri {
                reason: "the Cookie header does not fit a header value",
            })?;
            joined.set_sensitive(true);
            drop(request.headers_mut().insert(COOKIE, joined));
        }
        Ok(request)
    }

    /// Move to the redirect target of `response`, if the policy follows it.
    ///
    /// Returns `false` when the response is not a followed redirect.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLocation`] for an unusable target,
    /// [`Error::RedirectDowngrade`] for an `https` to `http` redirect and
    /// [`Error::TooManyRedirects`] past the policy's limit.
    pub(super) fn follow(
        &mut self,
        policy: RedirectPolicy,
        response: &Response<Vec<u8>>,
    ) -> Result<bool, Error> {
        let status = response.status();
        let Some(location) = response.headers().get(LOCATION) else {
            return Ok(false);
        };
        let moved = matches!(
            status,
            StatusCode::MOVED_PERMANENTLY
                | StatusCode::FOUND
                | StatusCode::SEE_OTHER
                | StatusCode::TEMPORARY_REDIRECT
                | StatusCode::PERMANENT_REDIRECT
        );
        let Some((limit, any_origin)) = policy.limit().filter(|_limit| moved) else {
            return Ok(false);
        };
        let target = resolve_location(
            &self.uri,
            location.to_str().map_err(|_text| Error::InvalidLocation {
                reason: "the Location value is not visible ASCII",
            })?,
        )?;
        let target_origin = Origin::of(&target).map_err(|_target| Error::InvalidLocation {
            reason: "the target is not an http or https URI",
        })?;
        if self.origin.is_secure() && !target_origin.is_secure() {
            return Err(Error::RedirectDowngrade);
        }
        let same_origin = target_origin == self.origin;
        if !same_origin && !any_origin {
            return Ok(false);
        }
        if self.redirects >= limit {
            return Err(Error::TooManyRedirects { limit });
        }
        self.redirects = self.redirects.saturating_add(1);
        self.switch_method(status);
        self.strip_credentials(same_origin);
        self.uri = target;
        self.origin = target_origin;
        self.authenticated = self.authenticated && same_origin;
        Ok(true)
    }

    /// Apply the method and body change of a redirect status.
    fn switch_method(&mut self, status: StatusCode) {
        let to_get = match status {
            StatusCode::SEE_OTHER => self.method != Method::HEAD,
            StatusCode::MOVED_PERMANENTLY | StatusCode::FOUND => self.method == Method::POST,
            _ => false,
        };
        if to_get {
            self.method = Method::GET;
            self.body = Vec::new();
            for name in [
                CONTENT_LENGTH,
                CONTENT_TYPE,
                CONTENT_ENCODING,
                TRANSFER_ENCODING,
            ] {
                drop(self.headers.remove(name));
            }
        }
    }

    /// Drop what a redirect must not carry: a Negotiate token is stale after
    /// one use, and credentials never leave their origin.
    fn strip_credentials(&mut self, same_origin: bool) {
        let stale = self.headers.get(AUTHORIZATION).is_some_and(is_negotiate);
        if stale || !same_origin {
            drop(self.headers.remove(AUTHORIZATION));
        }
        if !same_origin {
            drop(self.headers.remove(PROXY_AUTHORIZATION));
            drop(self.headers.remove(COOKIE));
        }
    }
}

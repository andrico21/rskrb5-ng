//! Origins and redirect targets.
//!
//! An origin is scheme, host and port (RFC 6454). [`resolve_location`] turns the
//! `Location` header of a response into the absolute URI the client may follow:
//! it accepts absolute, scheme-relative, path-absolute and path-relative
//! references (RFC 3986 section 5.2), removes dot segments and drops the
//! fragment, and refuses everything that is not plain `http` or `https` without
//! user information.

use http_types::{Uri, uri::Authority};

use crate::error::HttpClient as Error;

/// The longest `Location` value the client resolves, in bytes.
pub const MAX_LOCATION_BYTES: usize = 8192;

/// Scheme, host and port of a URI: the unit of credential scope.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Origin {
    /// Whether the scheme is `https`.
    secure: bool,
    /// The host in lower case; an IPv6 literal keeps its brackets.
    host: String,
    /// The port, defaulted from the scheme.
    port: u16,
}

impl Origin {
    /// The origin of `uri`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidUri`] unless `uri` is an absolute `http` or `https`
    /// URI with a host and no user information.
    #[inline]
    pub fn of(uri: &Uri) -> Result<Self, Error> {
        let secure = match uri.scheme_str() {
            Some(scheme) if scheme.eq_ignore_ascii_case("https") => true,
            Some(scheme) if scheme.eq_ignore_ascii_case("http") => false,
            _ => {
                return Err(Error::InvalidUri {
                    reason: "the scheme is not http or https",
                });
            }
        };
        let authority = uri.authority().ok_or(Error::InvalidUri {
            reason: "the URI has no authority",
        })?;
        if authority.as_str().contains('@') {
            return Err(Error::InvalidUri {
                reason: "the URI carries user information",
            });
        }
        if authority.host().is_empty() {
            return Err(Error::InvalidUri {
                reason: "the URI has no host",
            });
        }
        Ok(Self {
            secure,
            host: authority.host().to_ascii_lowercase(),
            port: authority
                .port_u16()
                .unwrap_or(if secure { 443 } else { 80 }),
        })
    }

    /// Whether the scheme is `https`.
    #[inline]
    #[must_use]
    pub const fn is_secure(&self) -> bool {
        self.secure
    }

    /// The host name, in lower case.
    #[inline]
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port.
    #[inline]
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }
}

/// Whether `text` starts with a URI scheme and a colon (RFC 3986 section 3.1).
fn has_scheme(text: &str) -> bool {
    let Some((scheme, _)) = text.split_once(':') else {
        return false;
    };
    let mut bytes = scheme.bytes();
    bytes
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
}

/// Remove the dot segments of an absolute path (RFC 3986 section 5.2.4).
fn remove_dot_segments(path: &str) -> String {
    let parts: Vec<&str> = path.split('/').collect();
    let last = parts.len().saturating_sub(1);
    let mut kept: Vec<&str> = Vec::new();
    for (index, part) in parts.iter().enumerate().skip(1) {
        match *part {
            "." => {
                if index == last {
                    kept.push("");
                }
            }
            ".." => {
                let _parent = kept.pop();
                if index == last {
                    kept.push("");
                }
            }
            other => kept.push(other),
        }
    }
    format!("/{}", kept.join("/"))
}

/// The reference text of `location` against `base`, before normalization.
fn reference(base: &Uri, scheme: &str, location: &str) -> String {
    let authority = base.authority().map_or("", Authority::as_str);
    if let Some(rest) = location.strip_prefix("//") {
        return format!("{scheme}://{rest}");
    }
    if has_scheme(location) {
        return location.to_owned();
    }
    if location.is_empty() {
        return base.to_string();
    }
    if location.starts_with('/') {
        return format!("{scheme}://{authority}{location}");
    }
    if location.starts_with('?') {
        return format!("{scheme}://{authority}{}{location}", base.path());
    }
    let directory =
        base.path().rsplit_once('/').map_or(
            "/",
            |(before, _)| if before.is_empty() { "/" } else { before },
        );
    let slash = if directory.ends_with('/') { "" } else { "/" };
    format!("{scheme}://{authority}{directory}{slash}{location}")
}

/// Resolve the `Location` value `location` of a response to `base`.
///
/// # Errors
///
/// Returns [`Error::InvalidLocation`] for an empty or oversized value, one
/// with a control, space, non-ASCII or backslash byte, a scheme other than
/// `http` or `https`, user information, or a reference that does not parse.
#[inline]
pub fn resolve_location(base: &Uri, location: &str) -> Result<Uri, Error> {
    let refuse = |reason| Error::InvalidLocation { reason };
    if location.is_empty() {
        return Err(refuse("the Location value is empty"));
    }
    if location.len() > MAX_LOCATION_BYTES {
        return Err(refuse("the Location value is too long"));
    }
    if location
        .bytes()
        .any(|byte| byte <= 0x20 || byte >= 0x7f || byte == b'\\')
    {
        return Err(refuse("the Location value has a forbidden character"));
    }
    let origin = Origin::of(base).map_err(|_base| refuse("the base URI is not usable"))?;
    let base_scheme = if origin.is_secure() { "https" } else { "http" };
    let text = reference(
        base,
        base_scheme,
        location.split('#').next().unwrap_or_default(),
    );
    let parsed: Uri = text
        .parse()
        .map_err(|_parse| refuse("the Location value does not parse"))?;
    let target = Origin::of(&parsed)
        .map_err(|_target| refuse("the target is not an http or https URI with a host"))?;
    let target_scheme = if target.is_secure() { "https" } else { "http" };
    let port = parsed
        .authority()
        .and_then(Authority::port_u16)
        .map_or_else(String::new, |port| format!(":{port}"));
    let path = remove_dot_segments(if parsed.path().is_empty() {
        "/"
    } else {
        parsed.path()
    });
    let query = parsed
        .query()
        .map_or_else(String::new, |query| format!("?{query}"));
    format!("{target_scheme}://{}{port}{path}{query}", target.host())
        .parse()
        .map_err(|_parse| refuse("the resolved URI does not parse"))
}

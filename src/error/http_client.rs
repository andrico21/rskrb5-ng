/// Error of an [`HttpExchange`](crate::http::wire::HttpExchange): one request
/// that could not be turned into a response.
///
/// Whether the server may have received the request is part of the type, as for
/// the KDC proxy transport: a replay-unsafe retry is the caller's decision.
#[cfg(feature = "http")]
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HttpExchange {
    /// The request is not one this exchange can send.
    #[error("the HTTP request cannot be sent: {reason}")]
    InvalidRequest {
        /// Why the request was refused.
        reason: &'static str,
    },
    /// The URI scheme is not served by this exchange (the built-in exchange
    /// speaks HTTPS only).
    #[error("the URI scheme {scheme:?} is not supported by this exchange")]
    UnsupportedScheme {
        /// The scheme as written.
        scheme: String,
    },
    /// No trust anchor is configured: there is no implicit trust store.
    #[error("no trust anchor is configured for HTTPS")]
    NoAnchors,
    /// A configured trust anchor does not load.
    #[error("a trust anchor does not load: {reason}")]
    Anchor {
        /// What is wrong with it.
        reason: &'static str,
    },
    /// The failure happened before any byte of the request could have been
    /// delivered.
    #[error("the HTTP request was not delivered: {0}")]
    NotDelivered(#[source] Box<dyn StdError + Send + Sync>),
    /// The failure happened after the request may have been delivered.
    #[error("the HTTP request may have been delivered: {0}")]
    MaybeDelivered(#[source] Box<dyn StdError + Send + Sync>),
    /// The response body is longer than the exchange's limit.
    #[error("the HTTP response is larger than {limit} bytes")]
    TooLarge {
        /// The limit in bytes.
        limit: usize,
    },
}

/// Error of the HTTP Negotiate client ([`crate::http::agent`]): every variant
/// fails closed.
#[cfg(feature = "http")]
#[derive(thiserror::Error)]
#[non_exhaustive]
pub enum HttpClient {
    /// The exchange failed.
    #[error("{0}")]
    Exchange(#[from] HttpExchange),
    /// Negotiate token processing failed.
    #[error("{0}")]
    Negotiate(#[from] Http),
    /// The request URI is not an absolute `http` or `https` URI without
    /// credentials.
    #[error("invalid request URI: {reason}")]
    InvalidUri {
        /// What is wrong with it.
        reason: &'static str,
    },
    /// A `Location` header is not a usable redirect target.
    #[error("invalid redirect location: {reason}")]
    InvalidLocation {
        /// What is wrong with it.
        reason: &'static str,
    },
    /// The redirect chain is longer than the policy allows.
    #[error("more than {limit} redirects")]
    TooManyRedirects {
        /// The policy's limit.
        limit: u8,
    },
    /// A redirect leads from `https` to `http`; it is never followed.
    #[error("a redirect from https to http is refused")]
    RedirectDowngrade,
    /// The server kept challenging after the allowed number of Negotiate rounds.
    #[error("more than {limit} Negotiate challenge rounds")]
    ChallengeLimit {
        /// The client's limit.
        limit: u8,
    },
    /// The `WWW-Authenticate` headers of a response are longer than allowed.
    #[error("WWW-Authenticate headers of {actual} bytes exceed the limit of {limit}")]
    ChallengeTooLarge {
        /// The client's limit in bytes.
        limit: usize,
        /// The bytes received.
        actual: usize,
    },
    /// The request body is longer than the replay limit: it could not be sent again.
    #[error("request body of {actual} bytes exceeds the replay limit of {limit}")]
    BodyTooLarge {
        /// The client's limit in bytes.
        limit: usize,
        /// The body length.
        actual: usize,
    },
    /// Mutual authentication was requested, but no response to an authenticated
    /// request carried an AP-REP that verified.
    ///
    /// The response must not be treated as coming from an authenticated server.
    #[error("mutual authentication was requested but the server did not prove its identity")]
    MutualAuthenticationNotProven {
        /// Classification of the response, `None` when no request was authenticated.
        negotiation: Option<ClientNegotiateResponse>,
        /// The response, kept for diagnostics.
        response: Box<HttpResponse<Vec<u8>>>,
    },
}

#[cfg(feature = "http")]
impl fmt::Debug for HttpClient {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exchange(source) => f.debug_tuple("Exchange").field(source).finish(),
            Self::Negotiate(_) => f.write_str("Negotiate"),
            Self::InvalidUri { reason } => f
                .debug_struct("InvalidUri")
                .field("reason", reason)
                .finish(),
            Self::InvalidLocation { reason } => f
                .debug_struct("InvalidLocation")
                .field("reason", reason)
                .finish(),
            Self::TooManyRedirects { limit } => f
                .debug_struct("TooManyRedirects")
                .field("limit", limit)
                .finish(),
            Self::RedirectDowngrade => f.write_str("RedirectDowngrade"),
            Self::ChallengeLimit { limit } => f
                .debug_struct("ChallengeLimit")
                .field("limit", limit)
                .finish(),
            Self::ChallengeTooLarge { limit, actual } => f
                .debug_struct("ChallengeTooLarge")
                .field("limit", limit)
                .field("actual", actual)
                .finish(),
            Self::BodyTooLarge { limit, actual } => f
                .debug_struct("BodyTooLarge")
                .field("limit", limit)
                .field("actual", actual)
                .finish(),
            Self::MutualAuthenticationNotProven {
                negotiation,
                response,
            } => f
                .debug_struct("MutualAuthenticationNotProven")
                .field("negotiation", negotiation)
                .field("status", &response.status())
                .finish(),
        }
    }
}

/// Error of the HTTP session manager ([`crate::http::sessions`]): every variant
/// refuses the session.
#[cfg(feature = "http")]
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HttpSession {
    /// The session blob is not of the supported format.
    #[error("malformed HTTP session blob: {reason}")]
    Malformed {
        /// What is wrong with it.
        reason: &'static str,
    },
    /// The session blob is longer than the manager accepts.
    #[error("HTTP session blob of {actual} bytes exceeds the limit of {limit}")]
    TooLarge {
        /// The manager's limit in bytes.
        limit: usize,
        /// The bytes received.
        actual: usize,
    },
    /// The blob does not authenticate under the manager's key.
    #[error("HTTP session blob does not authenticate")]
    Unauthentic,
    /// The session's lifetime is over.
    #[error("HTTP session has expired")]
    Expired,
    /// The session was revoked, or this manager never issued it.
    #[error("HTTP session is revoked or unknown")]
    Revoked,
    /// A newer generation of the session exists: this blob was rotated away.
    #[error("HTTP session was rotated")]
    Rotated,
    /// The session belongs to another principal than the one authenticated now.
    #[error("HTTP session is bound to another principal")]
    PrincipalMismatch,
    /// The manager holds as many live sessions as it may.
    #[error("the HTTP session manager holds its limit of {limit} live sessions")]
    CapacityExceeded {
        /// The limit.
        limit: usize,
    },
    /// The principal does not fit the session format.
    #[error("the principal does not fit an HTTP session: {reason}")]
    UnsupportedPrincipal {
        /// What does not fit.
        reason: &'static str,
    },
    /// The cookie name or attribute text is not valid.
    #[error("invalid session cookie setting: {reason}")]
    InvalidCookie {
        /// What is wrong with it.
        reason: &'static str,
    },
    /// The manager's registry lock was poisoned by a panic.
    #[error("the HTTP session registry is poisoned")]
    Poisoned,
    /// The system random source failed.
    #[error("system random source failed: {0}")]
    Random(#[from] getrandom::Error),
    /// Sealing the blob failed.
    #[error("session sealing failed: {0}")]
    Crypto(#[from] Crypto),
}

/// Error of the cookie jar ([`crate::http::cookies`], the `http-client` leaf):
/// a cookie the jar refuses to store.
#[cfg(feature = "http")]
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HttpCookie {
    /// The URL is not an absolute `http` or `https` URL.
    #[error("the cookie URL is not an absolute http or https URL")]
    InvalidUrl,
    /// The `Set-Cookie` value is longer than the jar accepts.
    #[error("Set-Cookie value of {actual} bytes exceeds the limit of {limit}")]
    TooLarge {
        /// The jar's limit in bytes.
        limit: usize,
        /// The bytes received.
        actual: usize,
    },
    /// The `Set-Cookie` value does not parse.
    #[error("Set-Cookie value does not parse")]
    Malformed,
    /// A `Secure` cookie was offered over a cleartext connection.
    #[error("a Secure cookie was received over a cleartext connection")]
    SecureOverCleartext,
    /// The cookie has a `Domain` attribute and no public-suffix list is configured.
    #[error("a Domain attribute needs a configured public-suffix list")]
    DomainNeedsSuffixList,
    /// The jar rejected the cookie under the RFC 6265 storage model.
    #[error("the cookie was rejected: {reason}")]
    Rejected {
        /// The jar's reason.
        reason: &'static str,
    },
    /// The jar holds as many cookies as it may.
    #[error("the cookie jar holds its limit of {limit} cookies")]
    JarFull {
        /// The limit.
        limit: usize,
    },
    /// The public-suffix list text does not parse.
    #[error("the public-suffix list does not parse")]
    SuffixList,
}

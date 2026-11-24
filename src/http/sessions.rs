//! The HTTP session manager: server-side continuation of a Negotiate exchange
//! through an opaque, sealed session cookie.
//!
//! After a `401`/Negotiate round authenticates a client, the server can issue a
//! cookie instead of asking for a new Kerberos token on every request.
//! [`SessionManager`] seals the session (its id, the client principal, its
//! generation and its lifetime) under a 256-bit key with the RFC 8009
//! `aes256-cts-hmac-sha384-192` profile that [`gss::TransferKey`] drives, so the
//! cookie is both unreadable and unforgeable; the manager also keeps a registry
//! of live session ids, which is what makes revocation and rotation possible.
//!
//! [`gss::TransferKey`]: crate::gss::TransferKey
//!
//! # Security
//!
//! * A session is refused when it is tampered with, truncated, longer than the
//!   limit, expired, revoked, rotated away, unknown to this manager, or bound
//!   to another principal than the one now authenticated.
//! * The cookie is `HttpOnly`, `Secure` and `SameSite=Strict` unless the
//!   application relaxes `Secure` for a development server.
//! * The registry is in memory: a restart revokes every session, and a manager
//!   holds at most [`SessionManager::DEFAULT_MAX_SESSIONS`] live sessions.
//! * No PAC and no ticket is ever put in a session: it holds the client name
//!   the KDC authenticated and nothing else.
//! * The key is erased when dropped and never shown by `Debug`.
//! * The application's logger hook is a [`Guard`](crate::trace::Guard): every
//!   refusal is a [`ApReqRejected`](crate::trace::Event::ApReqRejected) event
//!   with a static reason; no cookie value is ever traced and nothing is
//!   printed.
//!
//! # Cancel safety
//!
//! Every function is synchronous and finishes before it returns.

use alloc::sync::Arc;
use core::{fmt, time::Duration};
use std::{collections::HashMap, sync::Mutex, time::SystemTime};

use http_types::{HeaderValue, Request};

use crate::{
    client::principal::Principal, error::HttpSession as Error, gss::TransferKey, trace::Guard,
};

/// What a valid session cookie proves, placed in the request's extensions next
/// to [`AcceptedContext`](crate::spnego::AcceptedContext) by
/// [`SessionManager::attach`].
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub struct SessionIdentity {
    /// The session id.
    id: [u8; 16],
    /// The authenticated client.
    principal: Principal,
    /// The generation: it grows with every rotation.
    generation: u32,
    /// When the session was issued.
    issued: SystemTime,
    /// When the session ends.
    expires: SystemTime,
}

impl fmt::Debug for SessionIdentity {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionIdentity")
            .field("generation", &self.generation)
            .field("expires", &self.expires)
            .finish_non_exhaustive()
    }
}

impl SessionIdentity {
    /// The authenticated client principal.
    #[inline]
    #[must_use]
    pub const fn principal(&self) -> &Principal {
        &self.principal
    }

    /// The generation: 0 when issued, one more after every rotation.
    #[inline]
    #[must_use]
    pub const fn generation(&self) -> u32 {
        self.generation
    }

    /// When the session was issued.
    #[inline]
    #[must_use]
    pub const fn issued_at(&self) -> SystemTime {
        self.issued
    }

    /// When the session ends.
    #[inline]
    #[must_use]
    pub const fn expires_at(&self) -> SystemTime {
        self.expires
    }
}

/// The clock of a manager.
type Clock = Arc<dyn Fn() -> SystemTime + Send + Sync>;

/// Issues, resumes, rotates and revokes HTTP sessions.
pub struct SessionManager {
    /// The sealing key.
    key: TransferKey,
    /// How long a session lives.
    lifetime: Duration,
    /// The most live sessions.
    max_sessions: usize,
    /// The live sessions.
    registry: Mutex<HashMap<[u8; 16], SystemTime>>,
    /// The name of the session cookie.
    cookie_name: String,
    /// Whether the cookie is `Secure`.
    secure: bool,
    /// The time source.
    clock: Clock,
    /// The trace guard.
    trace: Guard,
}

impl fmt::Debug for SessionManager {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionManager")
            .field("lifetime", &self.lifetime)
            .field("max_sessions", &self.max_sessions)
            .field("trace", &self.trace.is_enabled())
            .finish_non_exhaustive()
    }
}

impl SessionManager {
    /// The default most live sessions.
    pub const DEFAULT_MAX_SESSIONS: usize = 10_000;
    /// The default session lifetime.
    pub const DEFAULT_LIFETIME: Duration = Duration::from_hours(1);

    /// A manager that seals sessions under `key`.
    #[inline]
    #[must_use]
    pub fn new(key: TransferKey) -> Self {
        Self {
            key,
            lifetime: Self::DEFAULT_LIFETIME,
            max_sessions: Self::DEFAULT_MAX_SESSIONS,
            registry: Mutex::new(HashMap::new()),
            cookie_name: "rskrb5_session".to_owned(),
            secure: true,
            clock: Arc::new(SystemTime::now),
            trace: Guard::disabled(),
        }
    }

    /// Let sessions live for `lifetime` after they are issued or rotated.
    #[inline]
    #[must_use]
    pub const fn with_lifetime(mut self, lifetime: Duration) -> Self {
        self.lifetime = lifetime;
        self
    }

    /// Hold at most `max` live sessions.
    #[inline]
    #[must_use]
    pub const fn with_max_sessions(mut self, max: usize) -> Self {
        self.max_sessions = max;
        self
    }

    /// Name the session cookie `name` (an RFC 6265 token).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidCookie`] for an empty name or one with a byte
    /// that is not a token character.
    #[inline]
    pub fn with_cookie_name(mut self, name: &str) -> Result<Self, Error> {
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
        {
            return Err(Error::InvalidCookie {
                reason: "the cookie name is not an RFC 6265 token",
            });
        }
        name.clone_into(&mut self.cookie_name);
        Ok(self)
    }

    /// Whether the cookie carries the `Secure` attribute (the default).
    #[inline]
    #[must_use]
    pub const fn with_secure(mut self, secure: bool) -> Self {
        self.secure = secure;
        self
    }

    /// Read the time from `clock` instead of the system clock.
    #[inline]
    #[must_use]
    pub fn with_clock<C>(mut self, clock: C) -> Self
    where
        C: Fn() -> SystemTime + Send + Sync + 'static,
    {
        self.clock = Arc::new(clock);
        self
    }

    /// Emit an event through `guard` for every refused session.
    #[inline]
    #[must_use]
    pub fn with_trace(mut self, guard: Guard) -> Self {
        self.trace = guard;
        self
    }

    /// The `Set-Cookie` value that deletes the session cookie in the browser.
    #[inline]
    #[must_use]
    pub fn expire_cookie(&self) -> HeaderValue {
        let _unused = (&self.cookie_name, self.secure, &self.clock);
        HeaderValue::from_static("")
    }

    /// Issue a session for `principal`: its identity and the `Set-Cookie` value.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedPrincipal`], [`Error::CapacityExceeded`],
    /// [`Error::Poisoned`] and the random-source and sealing errors.
    #[inline]
    pub fn issue(&self, _principal: &Principal) -> Result<(SessionIdentity, HeaderValue), Error> {
        let _unused = (&self.key, &self.registry);
        Err(Error::Malformed {
            reason: "not implemented",
        })
    }

    /// Resume the session of the cookie value `value`.
    ///
    /// # Errors
    ///
    /// Returns the refusals of the module documentation.
    #[inline]
    pub fn resume(&self, _value: &str) -> Result<SessionIdentity, Error> {
        Err(Error::Malformed {
            reason: "not implemented",
        })
    }

    /// Resume the session of `value` and require it to belong to `principal`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PrincipalMismatch`] and the errors of [`Self::resume`].
    #[inline]
    pub fn resume_for(
        &self,
        _value: &str,
        _principal: &Principal,
    ) -> Result<SessionIdentity, Error> {
        Err(Error::Malformed {
            reason: "not implemented",
        })
    }

    /// Rotate `identity`: a new generation and cookie; the old cookie is refused.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::issue`], [`Error::Rotated`] and [`Error::Revoked`].
    #[inline]
    pub fn rotate(
        &self,
        _identity: &SessionIdentity,
    ) -> Result<(SessionIdentity, HeaderValue), Error> {
        Err(Error::Malformed {
            reason: "not implemented",
        })
    }

    /// Revoke `identity`: every cookie of the session is refused from now on.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Poisoned`].
    #[inline]
    pub fn revoke(&self, _identity: &SessionIdentity) -> Result<(), Error> {
        Err(Error::Poisoned)
    }

    /// Find the session cookie in the `Cookie` headers of `request`, resume it
    /// and put its [`SessionIdentity`] in the request's extensions.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Malformed`] for a duplicated session cookie and the
    /// errors of [`Self::resume`].
    #[inline]
    pub fn attach<B>(&self, _request: &mut Request<B>) -> Result<Option<SessionIdentity>, Error> {
        Ok(None)
    }
}

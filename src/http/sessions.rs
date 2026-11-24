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
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use http_types::{HeaderMap, HeaderValue, Request, header::COOKIE};

use self::blob::Fields;
use crate::{
    error::HttpSession as Error,
    gss::TransferKey,
    service::Principal,
    trace::{Event, Guard},
};

/// The sealed session format.
mod blob;

/// A live session as the registry knows it.
struct Entry {
    /// The newest generation issued.
    generation: u32,
    /// When the session ends, in seconds since the epoch.
    expires: u64,
}

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

    /// The identity of a session's fields and principal.
    fn from_fields(fields: &Fields, principal: Principal) -> Self {
        let at = |seconds: u64| {
            UNIX_EPOCH
                .checked_add(Duration::from_secs(seconds))
                .unwrap_or(UNIX_EPOCH)
        };
        Self {
            id: fields.id,
            principal,
            generation: fields.generation,
            issued: at(fields.issued),
            expires: at(fields.expires),
        }
    }
}

/// A time source of a manager.
trait Clock: Send + Sync {
    /// The current time.
    fn now(&self) -> SystemTime;
}

impl<F> Clock for F
where
    F: Fn() -> SystemTime + Send + Sync,
{
    fn now(&self) -> SystemTime {
        self()
    }
}

/// Issues, resumes, rotates and revokes HTTP sessions.
pub struct SessionManager {
    /// The sealing key.
    key: TransferKey,
    /// How long a session lives.
    lifetime: Duration,
    /// The most live sessions.
    max_sessions: usize,
    /// The live sessions.
    registry: Mutex<HashMap<[u8; 16], Entry>>,
    /// The name of the session cookie.
    cookie_name: String,
    /// Whether the cookie is `Secure`.
    secure: bool,
    /// The time source.
    clock: Arc<dyn Clock>,
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
        let token = |byte: u8| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte);
        if name.is_empty() || !name.bytes().all(token) {
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
        self.header(&format!("{}=", self.cookie_name), "Max-Age=0")
    }

    /// The current time, in seconds since the epoch.
    fn now(&self) -> u64 {
        self.clock
            .now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs())
    }

    /// Run `operation` on the registry under its lock.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Poisoned`] and the errors of `operation`.
    fn with_registry<T, F>(&self, operation: F) -> Result<T, Error>
    where
        F: FnOnce(&mut HashMap<[u8; 16], Entry>) -> Result<T, Error>,
    {
        let mut registry = self.registry.lock().map_err(|_poisoned| Error::Poisoned)?;
        operation(&mut registry)
    }

    /// A `Set-Cookie` header: `start`, then the fixed attributes and `tail`.
    fn header(&self, start: &str, tail: &str) -> HeaderValue {
        let secure = if self.secure { "; Secure" } else { "" };
        let mut value = HeaderValue::from_str(&format!(
            "{start}; Path=/; HttpOnly; SameSite=Strict{secure}; {tail}"
        ))
        .unwrap_or_else(|_unencodable| HeaderValue::from_static(""));
        value.set_sensitive(true);
        value
    }

    /// Record a refusal in the trace and hand the error back.
    fn refuse(&self, error: Error) -> Error {
        let reason = match &error {
            Error::Malformed { reason: _ } => "http session malformed",
            Error::TooLarge {
                limit: _,
                actual: _,
            } => "http session too large",
            Error::Unauthentic => "http session unauthentic",
            Error::Expired => "http session expired",
            Error::Revoked => "http session revoked",
            Error::Rotated => "http session rotated",
            Error::PrincipalMismatch => "http session principal mismatch",
            Error::CapacityExceeded { limit: _ }
            | Error::UnsupportedPrincipal { reason: _ }
            | Error::InvalidCookie { reason: _ }
            | Error::Poisoned
            | Error::Random(_)
            | Error::Crypto(_) => "http session refused",
        };
        self.trace.emit(&Event::ApReqRejected { reason });
        error
    }

    /// Seal a session and its `Set-Cookie` value.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`blob::seal`].
    fn cookie(&self, principal: &Principal, fields: &Fields) -> Result<HeaderValue, Error> {
        let value = blob::seal(&self.key, principal, fields)?;
        Ok(self.header(
            &format!("{}={value}", self.cookie_name),
            &format!("Max-Age={}", self.lifetime.as_secs()),
        ))
    }

    /// Issue a session for `principal`: its identity and the `Set-Cookie` value.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedPrincipal`], [`Error::CapacityExceeded`],
    /// [`Error::Poisoned`] and the random-source and sealing errors.
    #[inline]
    pub fn issue(&self, principal: &Principal) -> Result<(SessionIdentity, HeaderValue), Error> {
        let now = self.now();
        let mut id = [0_u8; 16];
        getrandom::fill(&mut id).map_err(Error::Random)?;
        let fields = Fields {
            id,
            generation: 0,
            issued: now,
            expires: now.saturating_add(self.lifetime.as_secs()),
        };
        let set_cookie = self.cookie(principal, &fields)?;
        self.with_registry(|registry| {
            if registry.len() >= self.max_sessions {
                registry.retain(|_id, entry| entry.expires > now);
            }
            if registry.len() >= self.max_sessions {
                return Err(Error::CapacityExceeded {
                    limit: self.max_sessions,
                });
            }
            let _previous = registry.insert(
                id,
                Entry {
                    generation: 0,
                    expires: fields.expires,
                },
            );
            Ok(())
        })?;
        Ok((
            SessionIdentity::from_fields(&fields, principal.clone()),
            set_cookie,
        ))
    }

    /// Resume the session of the cookie value `value`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TooLarge`], [`Error::Malformed`] and
    /// [`Error::Unauthentic`] for a value that is not a session of this
    /// manager's key, [`Error::Expired`], [`Error::Revoked`] for a session this
    /// manager does not hold and [`Error::Rotated`] for a replaced generation.
    #[inline]
    pub fn resume(&self, value: &str) -> Result<SessionIdentity, Error> {
        self.resume_inner(value).map_err(|error| self.refuse(error))
    }

    /// [`Self::resume`] without the trace.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::resume`].
    fn resume_inner(&self, value: &str) -> Result<SessionIdentity, Error> {
        let (fields, principal) = blob::open(&self.key, value)?;
        let now = self.now();
        self.with_registry(|registry| {
            if now >= fields.expires {
                let _ended = registry.remove(&fields.id);
                return Err(Error::Expired);
            }
            let entry = registry.get(&fields.id).ok_or(Error::Revoked)?;
            if now >= entry.expires {
                return Err(Error::Expired);
            }
            if entry.generation > fields.generation {
                return Err(Error::Rotated);
            }
            if entry.generation < fields.generation {
                return Err(Error::Unauthentic);
            }
            Ok(())
        })?;
        Ok(SessionIdentity::from_fields(&fields, principal))
    }

    /// Resume the session of `value` and require it to belong to `principal`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PrincipalMismatch`] and the errors of [`Self::resume`].
    #[inline]
    pub fn resume_for(&self, value: &str, principal: &Principal) -> Result<SessionIdentity, Error> {
        let identity = self.resume(value)?;
        if identity.principal().realm != principal.realm
            || identity.principal().components != principal.components
        {
            return Err(self.refuse(Error::PrincipalMismatch));
        }
        Ok(identity)
    }

    /// Rotate `identity`: a new generation and cookie; the old cookie is refused.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::issue`], [`Error::Rotated`] when a newer
    /// generation exists, [`Error::Revoked`] and [`Error::Expired`].
    #[inline]
    pub fn rotate(
        &self,
        identity: &SessionIdentity,
    ) -> Result<(SessionIdentity, HeaderValue), Error> {
        let now = self.now();
        self.with_registry(|registry| {
            let entry = registry.get_mut(&identity.id).ok_or(Error::Revoked)?;
            if now >= entry.expires {
                return Err(Error::Expired);
            }
            if entry.generation != identity.generation {
                return Err(Error::Rotated);
            }
            let fields = Fields {
                id: identity.id,
                generation: entry.generation.checked_add(1).ok_or(Error::Malformed {
                    reason: "the session was rotated too often",
                })?,
                issued: now,
                expires: now.saturating_add(self.lifetime.as_secs()),
            };
            let set_cookie = self.cookie(&identity.principal, &fields)?;
            entry.generation = fields.generation;
            entry.expires = fields.expires;
            Ok((
                SessionIdentity::from_fields(&fields, identity.principal.clone()),
                set_cookie,
            ))
        })
    }

    /// Revoke `identity`: every cookie of the session is refused from now on.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Poisoned`].
    #[inline]
    pub fn revoke(&self, identity: &SessionIdentity) -> Result<(), Error> {
        self.with_registry(|registry| {
            let _ended = registry.remove(&identity.id);
            Ok(())
        })
    }

    /// The value of the session cookie in `headers`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Malformed`] for a `Cookie` header that is not visible
    /// ASCII or a session cookie that appears twice.
    fn cookie_value<'headers>(
        &self,
        headers: &'headers HeaderMap,
    ) -> Result<Option<&'headers str>, Error> {
        let mut found = None;
        for header in headers.get_all(COOKIE) {
            let text = header.to_str().map_err(|_text| Error::Malformed {
                reason: "a Cookie header that is not visible ASCII",
            })?;
            for pair in text.split(';') {
                if let Some((name, value)) = pair.trim().split_once('=')
                    && name == self.cookie_name
                    && found.replace(value.trim()).is_some()
                {
                    return Err(self.refuse(Error::Malformed {
                        reason: "the session cookie appears twice",
                    }));
                }
            }
        }
        Ok(found)
    }

    /// Find the session cookie in the `Cookie` headers of `request`, resume it
    /// and put its [`SessionIdentity`] in the request's extensions.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Malformed`] for a duplicated session cookie and the
    /// errors of [`Self::resume`].
    #[inline]
    pub fn attach<B>(&self, request: &mut Request<B>) -> Result<Option<SessionIdentity>, Error> {
        let Some(value) = self.cookie_value(request.headers())? else {
            return Ok(None);
        };
        let identity = self.resume(value)?;
        drop(request.extensions_mut().insert(identity.clone()));
        Ok(Some(identity))
    }
}

//! Trace and logging diagnostics: redacted events, sinks and the `KRB5_TRACE` opt-in.
//!
//! This is the Rust form of MIT krb5's trace facility (`krb5_set_trace_callback`,
//! `krb5_set_trace_filename` and the `KRB5_TRACE` variable, MIT 1.22.2
//! `src/lib/krb5/os/trace.c:385-464`). A [`Guard`] couples one
//! [`Sink`] with the caps of its [`Options`]; the library hands it
//! [`Event`]s at the points where an exchange or a provider call happens.
//!
//! # Security
//!
//! An event never carries a password, key, ticket, OTP or authorization
//! header: its fields are counts, numeric codes, static names and the
//! [`Identity`] values below, and no constructor takes free text. Principals,
//! realms and endpoints are sensitive (the MIT docs warn that traces name
//! them), so a guard withholds every [`Identity`] unless
//! [`Options::with_identities`] opts in. `Debug` output of an event never
//! prints an identity, and rendered identity text is escaped (MIT
//! `trace.c:60-72` prints bytes outside the printable range as `\xNN`) so a
//! hostile name cannot forge a line or a field. Output is bounded: events,
//! bytes per event and total bytes have caps, and an event past a cap is
//! dropped and counted. A sink failure is counted and never reaches the
//! caller, so tracing cannot change a credential, a cache or an exchange. The
//! library never installs a global subscriber or logger.
//!
//! # Cancel safety
//!
//! Every function here is synchronous and finishes before it returns.

use alloc::sync::Arc;
use core::fmt;
use std::{
    env,
    path::{Path, PathBuf},
};

use crate::{error::Trace as Error, extensions::Event as ProviderEvent, secure_env};

/// Test and capture sinks that keep the rendered lines in memory.
pub mod capture;
/// The `err_fmt` relation: MIT's error-message template.
pub mod err_fmt;
/// Event rendering, escaping and the name table.
mod event;
/// The file sink `KRB5_TRACE` selects.
pub mod file;
/// The guard: caps, counters and sink isolation.
mod guard;

/// The adapter to the application's `tracing` subscriber (the `tracing` leaf).
pub mod adapter;

#[cfg(test)]
#[path = "trace/tests.rs"]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests;

/// Default most events one guard delivers.
pub const DEFAULT_MAX_EVENTS: usize = 100_000;
/// Default most bytes of one rendered event.
pub const DEFAULT_MAX_EVENT_BYTES: usize = 1024;
/// Default most bytes one guard delivers in total.
pub const DEFAULT_MAX_TOTAL_BYTES: usize = 64 * 1024 * 1024;
/// Largest destination path `KRB5_TRACE` or a caller may name, in bytes.
pub const MAX_DESTINATION_BYTES: usize = 4096;

/// Which exchange an event belongs to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ExchangeKind {
    /// An AS exchange: initial credentials.
    Initial,
    /// A TGS exchange: a service ticket.
    Ticket,
}

/// A principal, realm or endpoint name. It is sensitive: a guard withholds it
/// unless [`Options::with_identities`] opts in, `Debug` never prints it,
/// and `Display` escapes it.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Identity<'text> {
    /// The name, or `None` when withheld.
    text: Option<&'text str>,
}

/// One redacted event of the library.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Event<'event> {
    /// An exchange began.
    ExchangeStarted {
        /// The exchange.
        kind: ExchangeKind,
        /// The requesting client.
        client: Identity<'event>,
        /// The requested service.
        service: Identity<'event>,
    },
    /// A request went out toward a realm's KDC.
    RequestSent {
        /// The exchange.
        kind: ExchangeKind,
        /// The request count of the exchange, from 1.
        round: u32,
        /// The realm whose KDC receives the request.
        realm: Identity<'event>,
        /// The encoded request size.
        bytes: usize,
    },
    /// A KDC reply came in.
    ReplyReceived {
        /// The exchange.
        kind: ExchangeKind,
        /// The reply size.
        bytes: usize,
    },
    /// The exchange asked the application for a secret (the answer is never traced).
    Prompted {
        /// The exchange.
        kind: ExchangeKind,
    },
    /// The exchange finished with a credential.
    Completed {
        /// The exchange.
        kind: ExchangeKind,
        /// The session key's enctype number (never its value).
        enctype: i32,
    },
    /// The exchange failed.
    Failed {
        /// The exchange.
        kind: ExchangeKind,
        /// The KDC's KRB-ERROR number, when the KDC refused.
        kdc_error: Option<i32>,
        /// A static name of the failure class.
        reason: &'static str,
    },
    /// An extension provider was consulted or answered (redacted by its own type).
    Provider(ProviderEvent<'event>),
    /// A service accepted an AP-REQ.
    ApReqAccepted {
        /// The service principal the ticket was for.
        service: Identity<'event>,
    },
    /// A service rejected an AP-REQ.
    ApReqRejected {
        /// A static name of the rejection class.
        reason: &'static str,
    },
}

/// Where rendered events go.
///
/// Implementations are trusted code; a failure is counted by the guard and
/// never changes an exchange. `text` is the bounded rendering of `event`.
pub trait Sink: Send + Sync {
    /// Write one event.
    ///
    /// # Errors
    ///
    /// Returns the sink's failure; the guard counts it and goes on.
    fn write(&self, event: &Event<'_>, text: &str) -> Result<(), Error>;

    /// Flush buffered output, when the guard's last handle is dropped.
    ///
    /// # Errors
    ///
    /// Returns the sink's failure; the guard drops it.
    #[inline]
    fn flush(&self) -> Result<(), Error> {
        Ok(())
    }
}

/// What a guard has done so far.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct Stats {
    /// Events the sink accepted.
    pub emitted: u64,
    /// Events dropped past a cap.
    pub dropped: u64,
    /// Events the sink failed to write.
    pub failed: u64,
}

/// A sink with the caps of its options. Cloning shares the sink and counters.
#[derive(Clone)]
pub struct Guard {
    /// The shared state; `None` for a disabled guard.
    inner: Option<Arc<guard::Inner>>,
}

/// What to trace, how much, and where `KRB5_TRACE` points.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Options {
    /// The file a guard built from these options appends to.
    destination: Option<PathBuf>,
    /// Whether identities are delivered.
    include_identities: bool,
    /// The event cap.
    max_events: usize,
    /// The per-event byte cap.
    max_event_bytes: usize,
    /// The total byte cap.
    max_total_bytes: usize,
}

impl fmt::Debug for Guard {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Guard")
            .field("enabled", &self.is_enabled())
            .field("stats", &self.stats())
            .finish()
    }
}

/// The environment variable that names the trace file (MIT 1.22.2
/// `src/lib/krb5/os/trace.c:389`).
const KRB5_TRACE_ENV: &str = "KRB5_TRACE";
/// The smallest per-event cap: room for an event name and its first fields.
const MIN_EVENT_BYTES: usize = 32;
/// The largest per-event cap.
const MAX_EVENT_BYTES: usize = 64 * 1024;

impl Options {
    /// Options with no destination, identities withheld and the default caps.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            destination: None,
            include_identities: false,
            max_events: DEFAULT_MAX_EVENTS,
            max_event_bytes: DEFAULT_MAX_EVENT_BYTES,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
        }
    }

    /// Options whose destination is the file `KRB5_TRACE` names.
    ///
    /// Unset, empty, or ignored in a process running with elevated privilege
    /// (MIT reads it with `secure_getenv`, `trace.c:389`), it gives the
    /// options of [`Self::new`]. Nothing is opened until
    /// [`Guard::from_options`].
    ///
    /// # Ambient input
    ///
    /// Reads `KRB5_TRACE`. Library code never calls this: an application that
    /// wants MIT's behaviour opts in by calling it. The explicit alternative
    /// that reads no variable is [`Self::with_file`], and [`Self::new`] with no
    /// destination traces nowhere.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidDestination`] for a value longer than
    /// [`MAX_DESTINATION_BYTES`] or one with a NUL byte.
    #[inline]
    pub fn from_env() -> Result<Self, Error> {
        match secure_env::ambient(|| env::var_os(KRB5_TRACE_ENV)) {
            Some(value) if !value.is_empty() => Self::new().with_file(PathBuf::from(value)),
            Some(_) | None => Ok(Self::new()),
        }
    }

    /// Name the file a guard appends to (created with mode 0600 on Unix).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidDestination`] for an empty path, one longer than
    /// [`MAX_DESTINATION_BYTES`] or one with a NUL byte.
    #[inline]
    pub fn with_file<P>(mut self, path: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let bytes = path.as_ref().as_os_str().as_encoded_bytes();
        let reason = if bytes.is_empty() {
            "the path is empty"
        } else if bytes.len() > MAX_DESTINATION_BYTES {
            "the path is longer than MAX_DESTINATION_BYTES"
        } else if bytes.contains(&0) {
            "the path contains a NUL byte"
        } else {
            self.destination = Some(path.as_ref().to_path_buf());
            return Ok(self);
        };
        Err(Error::InvalidDestination { reason })
    }

    /// Deliver principals, realms and endpoints too (they are withheld by default).
    #[inline]
    #[must_use]
    pub const fn with_identities(mut self, include: bool) -> Self {
        self.include_identities = include;
        self
    }

    /// Deliver at most `max` events.
    #[inline]
    #[must_use]
    pub const fn with_max_events(mut self, max: usize) -> Self {
        self.max_events = max;
        self
    }

    /// Render at most `max` bytes of one event (clamped to 32..=65536).
    #[inline]
    #[must_use]
    pub fn with_max_event_bytes(mut self, max: usize) -> Self {
        self.max_event_bytes = max.clamp(MIN_EVENT_BYTES, MAX_EVENT_BYTES);
        self
    }

    /// Deliver at most `max` bytes in total.
    #[inline]
    #[must_use]
    pub const fn with_max_total_bytes(mut self, max: usize) -> Self {
        self.max_total_bytes = max;
        self
    }

    /// The file a guard built from these options appends to.
    #[inline]
    #[must_use]
    pub fn destination(&self) -> Option<&Path> {
        self.destination.as_deref()
    }

    /// Whether identities are delivered.
    #[inline]
    #[must_use]
    pub const fn include_identities(&self) -> bool {
        self.include_identities
    }

    /// The event cap.
    #[inline]
    #[must_use]
    pub const fn max_events(&self) -> usize {
        self.max_events
    }

    /// The per-event byte cap.
    #[inline]
    #[must_use]
    pub const fn max_event_bytes(&self) -> usize {
        self.max_event_bytes
    }

    /// The total byte cap.
    #[inline]
    #[must_use]
    pub const fn max_total_bytes(&self) -> usize {
        self.max_total_bytes
    }
}

impl Default for Options {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

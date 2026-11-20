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
use std::path::PathBuf;

use crate::{error::Trace as Error, extensions::Event as ProviderEvent};

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
/// Options, caps and the one reader of `KRB5_TRACE`.
mod options;

/// The adapter to the application's `tracing` subscriber (the `tracing` leaf).
pub mod adapter;

#[cfg(test)]
#[path = "trace/tests.rs"]
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
    /// A renewal of a ticket-granting ticket.
    Renewal,
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

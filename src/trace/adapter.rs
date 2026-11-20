//! The adapter from trace events to the `tracing` crate (the `tracing` leaf).
//!
//! [`Forward`] is a [`Sink`](super::Sink) that emits each event to whatever
//! `tracing` subscriber the application has set. It never sets one: the
//! application owns its subscriber, and with none every call is a no-op.
//!
//! # Security
//!
//! It forwards the guard's bounded text, which already has its identities
//! withheld (unless the application opted in) and its names escaped, so the
//! subscriber sees what a file sink would see: no password, key, ticket, OTP or
//! authorization header.

#[cfg(feature = "tracing")]
use tracing::Level;

#[cfg(feature = "tracing")]
use super::{Event, Sink};
#[cfg(feature = "tracing")]
use crate::error::Trace as Error;

/// Emits trace events to the application's `tracing` subscriber, with the target
/// `rskrb5_ng::trace::adapter`: failures and rejections at `WARN`, everything else
/// at `DEBUG`.
#[cfg(feature = "tracing")]
#[derive(Clone, Copy, Debug, Default)]
#[non_exhaustive]
pub struct Forward;

#[cfg(feature = "tracing")]
impl Forward {
    /// The adapter; it holds no state.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[cfg(feature = "tracing")]
impl Sink for Forward {
    #[inline]
    fn write(&self, event: &Event<'_>, text: &str) -> Result<(), Error> {
        let name = event.name();
        if matches!(name, "failed" | "ap-req-rejected" | "provider-refused") {
            tracing::event!(Level::WARN, event = name, "{text}");
        } else {
            tracing::event!(Level::DEBUG, event = name, "{text}");
        }
        Ok(())
    }
}

//! Trace options: the caps, the identity rule and the one reader of `KRB5_TRACE`.

use std::{
    env,
    path::{Path, PathBuf},
};

use super::{
    DEFAULT_MAX_EVENT_BYTES, DEFAULT_MAX_EVENTS, DEFAULT_MAX_TOTAL_BYTES, MAX_DESTINATION_BYTES,
};
use crate::{error::Trace as Error, secure_env};

/// The environment variable that names the trace file (MIT 1.22.2
/// `src/lib/krb5/os/trace.c:389`).
const KRB5_TRACE_ENV: &str = "KRB5_TRACE";
/// The smallest per-event cap: room for an event name and its first fields.
const MIN_EVENT_BYTES: usize = 32;
/// The largest per-event cap.
const MAX_EVENT_BYTES: usize = 64 * 1024;

impl super::Options {
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
    /// [`Guard::from_options`](super::Guard::from_options).
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

impl Default for super::Options {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

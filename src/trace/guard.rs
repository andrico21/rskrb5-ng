//! The guard: caps, counters and sink isolation.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

use super::{Event, Guard, Options, Sink, Stats};
use crate::{
    error::Trace as Error,
    extensions::{Event as ProviderEvent, LibraryObserver},
};

/// The state every clone of one guard shares.
pub(super) struct Inner {
    /// Where the bounded text goes.
    sink: Box<dyn Sink>,
    /// The caps and the identity rule.
    options: Options,
    /// Events admitted so far, counted before the sink runs.
    admitted: AtomicU64,
    /// Bytes admitted so far.
    bytes: AtomicU64,
    /// Events the sink accepted.
    emitted: AtomicU64,
    /// Events dropped past a cap.
    dropped: AtomicU64,
    /// Events the sink failed on.
    failed: AtomicU64,
}

impl Drop for Inner {
    fn drop(&mut self) {
        drop(self.sink.flush());
    }
}

impl Guard {
    /// A guard that accepts events and does nothing.
    #[inline]
    #[must_use]
    pub const fn disabled() -> Self {
        Self { inner: None }
    }

    /// A guard delivering to `sink` under the caps of `options`.
    ///
    /// The options' destination is not opened here; see [`Self::from_options`].
    #[inline]
    #[must_use]
    pub fn new<S>(sink: S, options: Options) -> Self
    where
        S: Sink + 'static,
    {
        Self {
            inner: Some(Arc::new(Inner {
                sink: Box::new(sink),
                options,
                admitted: AtomicU64::new(0),
                bytes: AtomicU64::new(0),
                emitted: AtomicU64::new(0),
                dropped: AtomicU64::new(0),
                failed: AtomicU64::new(0),
            })),
        }
    }

    /// A guard appending to the destination of `options`, or a disabled guard
    /// when it names none.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Open`] when the destination cannot be opened.
    #[inline]
    pub fn from_options(options: &Options) -> Result<Self, Error> {
        match options.destination() {
            Some(path) => Ok(Self::new(super::file::Append::open(path)?, options.clone())),
            None => Ok(Self::disabled()),
        }
    }

    /// Whether events reach a sink.
    #[inline]
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.inner.is_some()
    }

    /// What this guard has done so far.
    #[inline]
    #[must_use]
    pub fn stats(&self) -> Stats {
        self.inner
            .as_ref()
            .map_or_else(Stats::default, |inner| Stats {
                emitted: inner.emitted.load(Ordering::Relaxed),
                dropped: inner.dropped.load(Ordering::Relaxed),
                failed: inner.failed.load(Ordering::Relaxed),
            })
    }

    /// Deliver `event`: withhold identities unless allowed, render it within
    /// the per-event cap, then hand it to the sink unless a count or byte cap
    /// is spent. A sink failure is counted and not reported.
    #[inline]
    pub fn emit(&self, event: &Event<'_>) {
        let Some(inner) = &self.inner else {
            return;
        };
        let options = &inner.options;
        let shown = if options.include_identities() {
            *event
        } else {
            event.withheld()
        };
        let admitted = inner.admitted.fetch_add(1, Ordering::Relaxed);
        let events = u64::try_from(options.max_events()).unwrap_or(u64::MAX);
        if admitted >= events {
            let _previous = inner.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let mut text = shown.to_string();
        let mut end = text.len().min(options.max_event_bytes());
        while !text.is_char_boundary(end) {
            end = end.saturating_sub(1);
        }
        text.truncate(end);
        let length = u64::try_from(text.len()).unwrap_or(u64::MAX);
        let room = u64::try_from(options.max_total_bytes()).unwrap_or(u64::MAX);
        let within_bytes = inner
            .bytes
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |total| {
                total.checked_add(length).filter(|sum| *sum <= room)
            })
            .is_ok();
        if !within_bytes {
            let _previous = inner.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let counter = if inner.sink.write(&shown, &text).is_ok() {
            &inner.emitted
        } else {
            &inner.failed
        };
        let _previous = counter.fetch_add(1, Ordering::Relaxed);
    }
}

impl PartialEq for Guard {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        match (&self.inner, &other.inner) {
            (Some(left), Some(right)) => Arc::ptr_eq(left, right),
            (None, None) => true,
            (Some(_), None) | (None, Some(_)) => false,
        }
    }
}

impl Eq for Guard {}

impl LibraryObserver for Guard {
    #[inline]
    fn id(&self) -> &'static str {
        "trace"
    }

    #[inline]
    fn observe(&self, event: &ProviderEvent<'_>) {
        self.emit(&Event::Provider(*event));
    }
}

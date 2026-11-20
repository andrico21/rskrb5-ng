//! A sink that keeps the rendered lines in memory.

use alloc::sync::Arc;
use std::sync::{Mutex, PoisonError};

use super::{Event, Sink};
use crate::error::Trace as Error;

/// Collects the bounded text of every event; clones share the lines.
#[derive(Clone, Debug, Default)]
pub struct Memory {
    /// The lines, oldest first.
    lines: Arc<Mutex<Vec<String>>>,
}

impl Memory {
    /// An empty sink.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The lines captured so far, oldest first.
    #[inline]
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        self.lines
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl Sink for Memory {
    #[inline]
    fn write(&self, _event: &Event<'_>, text: &str) -> Result<(), Error> {
        self.lines
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(text.to_owned());
        Ok(())
    }
}

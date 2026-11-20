//! The adapter from trace events to the `tracing` crate (the `tracing` leaf).

#[cfg(feature = "tracing")]
use tracing as _;

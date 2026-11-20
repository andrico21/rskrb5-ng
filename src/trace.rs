//! Trace and logging diagnostics: redacted events, sinks and the `KRB5_TRACE` opt-in.

/// The adapter to the application's `tracing` subscriber (the `tracing` leaf).
pub mod adapter;

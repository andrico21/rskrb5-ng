//! The module tree of the `NegoEx` scenarios.

/// Turns `Option` and `Result` failures into test errors.
use super::context;

/// Message encoding, parsing and the conversation rules.
#[path = "wire.rs"]
mod wire;

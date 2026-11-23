//! The module tree of the `NegoEx` scenarios.

/// Turns `Option` and `Result` failures into test errors.
use super::context;

/// Message encoding, parsing and the conversation rules.
#[path = "wire.rs"]
mod wire;

/// The test-only Rust implementation of MIT's `negoextest` mechanism.
#[path = "negoextest.rs"]
mod negoextest;

/// Tokens captured from MIT krb5 1.22.2.
#[path = "captures.rs"]
mod captures;

/// The exchange between two contexts (MIT's `t_negoex.py`).
#[path = "flow.rs"]
mod flow;

/// The `VERIFY` binding, replay and reorder refusals, and the mechanism and key policy.
#[path = "security.rs"]
mod security;

/// `NegoEx` under SPNEGO.
#[path = "spnego.rs"]
mod spnego;

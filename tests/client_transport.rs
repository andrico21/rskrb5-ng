//! Tokio transport integration tests.
#![cfg(feature = "tokio")]

/// Shared ambient classifier and its own adversarial regression suite.
#[path = "ambient_guard.rs"]
mod ambient_guard;

/// Transport scenarios and their loopback fixtures.
#[path = "client_transport/cases.rs"]
mod cases;

/// Port numbers from a reserved range that tests need refused.
#[path = "support/closed_port.rs"]
mod closed_port;

/// A loopback TCP listener and UDP socket on one port number, retried on a collision.
#[path = "support/loopback_pair.rs"]
mod loopback_pair;

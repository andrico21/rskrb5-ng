//! The module tree of the HTTP client scenarios.

/// Turns `Option` and `Result` failures into test errors.
use super::context;

/// In-process origins, tickets and Kerberos servers.
#[path = "support.rs"]
mod support;

/// `Location` resolution and origins.
#[path = "location.rs"]
mod location;

/// Negotiate rounds, redirects, mutual authentication and limits.
#[path = "client.rs"]
mod client;

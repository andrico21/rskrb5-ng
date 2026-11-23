/// Turns `Option` and `Result` failures into test errors.
use super::context;

/// An in-process KDC and the relay in front of it.
#[path = "kdc.rs"]
mod kdc;

/// Keytabs, credentials, tickets and the token loop.
#[path = "support.rs"]
mod support;

/// The token framing and the `IAKERB-HEADER`.
#[path = "token.rs"]
mod token;

/// The relay policy: realms, requests, rounds and bytes.
#[path = "policy.rs"]
mod policy;

/// Context establishment through the relay.
#[path = "flow.rs"]
mod flow;

/// The transcript checksum.
#[path = "finished.rs"]
mod finished;

/// Malformed, reordered and replayed tokens.
#[path = "malformed.rs"]
mod malformed;

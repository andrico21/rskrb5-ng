/// Turns `Option` and `Result` failures into test errors.
use super::context;

/// The keys, names, times and tickets of the in-process KDC.
#[path = "seal.rs"]
mod seal;

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

/// The AP exchange shared with the krb5 mechanism.
#[path = "shared.rs"]
mod shared;

/// The mechanism an IAKERB context reports.
#[path = "inquiry.rs"]
mod inquiry;

/// Delegation over IAKERB.
#[path = "delegation.rs"]
mod delegation;

/// The acquired tickets in a cache the caller names.
#[path = "output.rs"]
mod output;

/// Prompts answered through the responder.
#[path = "responder.rs"]
mod responder;

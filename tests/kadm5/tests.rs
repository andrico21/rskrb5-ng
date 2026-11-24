//! The module tree of the kadm5 scenarios.

/// Turns `Option` and `Result` failures into test errors.
use super::context;

/// Tickets, keytabs and the admin credential made in process.
#[path = "support.rs"]
mod support;

/// The test's own XDR writer and reader, independent of the crate's codec.
#[path = "wire.rs"]
mod wire;

/// The test-only loopback `RPCSEC_GSS` kadmind of the scenarios.
#[path = "server.rs"]
mod server;

/// Record marking and the RPC and kadm5 XDR layouts against hand-built bytes.
#[path = "codec.rs"]
mod codec;

/// `RPCSEC_GSS` establishment, integrity, privacy, sequence and verifier checks.
#[path = "rpc.rs"]
mod rpc;

/// Every remote operation of MIT's client library and the version negotiation.
#[path = "operations.rs"]
mod operations;

/// Key/salt tuples under the encryption policy (D2).
#[path = "keysalts.rs"]
mod keysalts;

/// Mutations whose outcome is unknown after a possible delivery.
#[path = "outcome.rs"]
mod outcome;

/// `[realms] admin_server` selects the administration server.
#[path = "relations.rs"]
mod relations;

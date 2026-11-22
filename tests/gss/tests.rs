//! The module tree of the GSS core scenarios.

/// Turns `Option` and `Result` failures into test errors.
#[path = "../support/context.rs"]
mod context;

/// Tickets, keytabs and credential caches made in process.
#[path = "support.rs"]
mod support;

/// Name import, display, export, comparison and canonicalization.
#[path = "names.rs"]
mod names;

/// The RFC 4121 channel-binding digest and its constructors.
#[path = "bindings.rs"]
mod bindings;

/// Context establishment between the crate's initiator and acceptor.
#[path = "contexts.rs"]
mod contexts;

/// Per-message tokens, sequence and replay windows, reflection.
#[path = "messages.rs"]
mod messages;

/// Channel-binding policy of the acceptor.
#[path = "channel.rs"]
mod channel;

/// Credential delegation and `enforce_ok_as_delegate`.
#[path = "delegation.rs"]
mod delegation;

/// Credential acquisition from stores and `store_cred_into`.
#[path = "credentials.rs"]
mod credentials;

/// The configuration relations the mechanism consumes.
#[path = "relations.rs"]
mod relations;

/// SPNEGO over the GSS Kerberos mechanism.
#[path = "spnego.rs"]
mod spnego;

//! The module tree of the GSS extension scenarios.

/// Turns `Option` and `Result` failures into test errors.
use super::context;

/// Tickets, keytabs and contexts made in process.
#[path = "support.rs"]
mod support;

/// The RFC 4402 pseudo-random function.
#[path = "prf.rs"]
mod prf;

/// IOV and AEAD per-message tokens.
#[path = "iov.rs"]
mod iov;

/// DCE-style three-leg establishment and its token rules.
#[path = "dce.rs"]
mod dce;

/// Context and credential transfer under a transfer key and a ledger.
#[path = "transfer.rs"]
mod transfer;

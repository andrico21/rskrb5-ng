//! ONC RPC over TCP with `RPCSEC_GSS`, in pure Rust.
//!
//! RFC 5531 (ONC RPC version 2 and record marking), RFC 4506 (XDR) and
//! RFC 2203 (`RPCSEC_GSS`) over the crate's own GSS-API Kerberos contexts
//! ([`crate::gss`]), as MIT krb5 1.22.2's `gssrpc` client speaks them
//! (`src/lib/rpc/auth_gss.c`, `authgss_prot.c`, `clnt_tcp.c`):
//!
//! - an [`RpcClient`] creates the `RPCSEC_GSS` context with `NULLPROC` calls
//!   carrying the initiator's tokens, then verifies the server's MIC over the
//!   granted sequence window before it calls anything;
//! - each [`ProtectedCall`] carries a fresh sequence number, a credential and
//!   a verifier MIC over the RPC header, and its arguments under the
//!   [`Protection`] the context was created with;
//! - [`RpcClient::reply`] accepts exactly one reply per call: the reply must
//!   answer the call's XID, carry an `RPCSEC_GSS` verifier that is a MIC over the
//!   call's sequence number, and protect a body that names that number again.
//!
//! The client is sans-I/O: it builds and checks RPC messages, and
//! [`encode_record`] and [`decode_record`] frame them; the administration
//! client in [`crate::kadm5`] moves them over TCP.
//!
//! # Security
//!
//! - Only `RPCSEC_GSS` is ever sent: no `AUTH_SYS`, `AUTH_NONE` or old
//!   `AUTH_GSSAPI` fallback exists (MIT falls back to `AUTH_GSSAPI` unless told
//!   not to, `client_init.c` `rpc_auth`), and the unprotected `rpc_gss_svc_none`
//!   service is not offered.
//! - A reply with another XID, a verifier of another flavor, a verifier MIC over
//!   another sequence number (a reused or replayed sequence number), a body
//!   naming another number, or a body MIC or wrap token that does not verify is
//!   rejected, and the client sends nothing more after it.
//! - Records are bounded by [`MAX_RECORD_SIZE`] and [`MAX_FRAGMENTS`] before
//!   their bodies are read; every XDR length and count is checked against the
//!   bytes that hold it before allocation; credentials and verifiers are bounded
//!   by [`MAX_AUTH_BYTES`].
//! - Arguments and results live in zeroizing buffers: they may carry passwords
//!   and keys.

use core::fmt;

use zeroize::Zeroizing;

use crate::{
    error::Rpc as Error,
    gss::{Credential, EstablishedContext, Initiator, InitiatorOptions, Name},
};

/// The `RPCSEC_GSS` context state machine.
mod client;
/// RPC call headers and reply decoding.
mod message;
/// Record marking.
pub(crate) mod record;
/// The bounded XDR codec.
pub(crate) mod xdr;

include!("rpcsec_gss/types.rs");

//! RPC call headers and reply decoding (RFC 5531 sections 8-9, RFC 2203
//! section 5).

use zeroize::Zeroizing;

use super::{
    MAX_AUTH_BYTES, Outcome, Program, Reply, Verifier,
    xdr::{Decoder, Encoder},
};
use crate::error::Rpc as Error;

/// The `RPCSEC_GSS` authentication flavor (RFC 2203 section 5).
pub(super) const RPCSEC_GSS: u32 = 6;

/// The `rpc_gss_cred_vers_1_t` version (RFC 2203 section 5).
const RPCSEC_GSS_VERSION: u32 = 1;

/// The largest context handle: MIT's `MAX_NETOBJ_SZ` (`xdr.h`), the bound of
/// `xdr_rpc_gss_init_res` (`authgss_prot.c`).
pub(super) const MAX_HANDLE: usize = 2048;

/// A call message (`msg_type` CALL).
const CALL: u32 = 0;

/// A reply message (`msg_type` REPLY).
const REPLY: u32 = 1;

/// The RPC protocol version.
const RPC_VERSION: u32 = 2;

/// The `RPCSEC_GSS` credential of one call (`rpc_gss_cred_vers_1_t`).
pub(super) struct Credential<'handle> {
    /// `rpc_gss_proc_t`: 0 data, 1 init, 2 continue init, 3 destroy.
    procedure: u32,
    /// The sequence number.
    sequence: u32,
    /// `rpc_gss_service_t`: 2 integrity, 3 privacy.
    service: u32,
    /// The server's context handle.
    handle: &'handle [u8],
}

impl<'handle> Credential<'handle> {
    /// The credential of `procedure` with `sequence` under `service` for `handle`.
    pub(super) const fn new(
        procedure: u32,
        sequence: u32,
        service: u32,
        handle: &'handle [u8],
    ) -> Self {
        Self {
            procedure,
            sequence,
            service,
            handle,
        }
    }
}

/// The call header through the credential: the bytes the verifier signs
/// (`authgss_marshal`, `auth_gss.c`).
///
/// # Errors
///
/// Returns [`Error::TooLarge`] for a handle above [`MAX_HANDLE`] or a
/// credential above [`MAX_AUTH_BYTES`].
pub(super) fn header(
    xid: u32,
    program: Program,
    procedure: u32,
    credential: &Credential<'_>,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let body = Encoder::new()
        .u32(RPCSEC_GSS_VERSION)
        .u32(credential.procedure)
        .u32(credential.sequence)
        .u32(credential.service)
        .opaque("context handle", credential.handle, MAX_HANDLE)?
        .finish();
    Ok(Encoder::new()
        .u32(xid)
        .u32(CALL)
        .u32(RPC_VERSION)
        .u32(program.number())
        .u32(program.version())
        .u32(procedure)
        .u32(RPCSEC_GSS)
        .opaque("credential", &body, MAX_AUTH_BYTES)?
        .finish())
}

/// Append a verifier of flavor `flavor` and body `body`.
///
/// # Errors
///
/// Returns [`Error::TooLarge`] above [`MAX_AUTH_BYTES`].
pub(super) fn verifier(encoder: Encoder, flavor: u32, body: &[u8]) -> Result<Encoder, Error> {
    encoder.u32(flavor).opaque("verifier", body, MAX_AUTH_BYTES)
}

/// Two versions, the lowest and the highest.
///
/// # Errors
///
/// Returns [`Error::Malformed`] for a truncated message.
fn versions(decoder: &mut Decoder<'_>) -> Result<(u32, u32), Error> {
    Ok((decoder.u32()?, decoder.u32()?))
}

/// Decode a reply message.
///
/// # Errors
///
/// Returns [`Error::Malformed`] and [`Error::TooLarge`] as [`Reply::decode`] says.
pub(super) fn decode_reply(message: &[u8]) -> Result<Reply, Error> {
    let mut decoder = Decoder::new(message);
    let xid = decoder.u32()?;
    if decoder.u32()? != REPLY {
        return Err(Error::Malformed("not a reply"));
    }
    let (verifier, outcome) = match decoder.u32()? {
        0 => {
            let flavor = decoder.u32()?;
            let body = decoder.opaque("verifier", MAX_AUTH_BYTES)?.to_vec();
            let outcome = match decoder.u32()? {
                0 => Outcome::Success,
                1 => Outcome::ProgramUnavailable,
                2 => {
                    let (low, high) = versions(&mut decoder)?;
                    Outcome::ProgramMismatch { low, high }
                }
                3 => Outcome::ProcedureUnavailable,
                4 => Outcome::GarbageArguments,
                5 => Outcome::SystemError,
                _ => return Err(Error::Malformed("unknown accept_stat")),
            };
            (Some(Verifier { flavor, body }), outcome)
        }
        1 => {
            let outcome = match decoder.u32()? {
                0 => {
                    let (low, high) = versions(&mut decoder)?;
                    Outcome::RpcMismatch { low, high }
                }
                1 => Outcome::AuthError(decoder.u32()?),
                _ => return Err(Error::Malformed("unknown reject_stat")),
            };
            (None, outcome)
        }
        _ => return Err(Error::Malformed("unknown reply_stat")),
    };
    let results = Zeroizing::new(decoder.rest().to_vec());
    if outcome != Outcome::Success && !results.is_empty() {
        return Err(Error::Malformed("bytes after an unsuccessful reply"));
    }
    Ok(Reply {
        xid,
        verifier,
        outcome,
        results,
    })
}

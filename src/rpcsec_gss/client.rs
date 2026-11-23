//! The `RPCSEC_GSS` context state machine (RFC 2203 section 5).
//!
//! MIT's client: `auth_gss.c` `authgss_refresh`, `authgss_marshal`,
//! `authgss_validate` and `authgss_prot.c` `xdr_rpc_gss_wrap_data` and
//! `xdr_rpc_gss_unwrap_data`.

use core::mem;
use std::io;

use zeroize::Zeroizing;

use super::{
    CallKind, InitStep, Outcome, Phase, Program, ProtectedCall, Protection, Reply, RpcClient,
    message::{self, Credential as GssCredential, MAX_HANDLE, RPCSEC_GSS},
    xdr::{Decoder, Encoder},
};
use crate::{
    error::Rpc as Error,
    gss::{
        ContextFlags, Credential, EstablishedContext, InitStep as GssStep, Initiator,
        InitiatorOptions, Name,
    },
};

/// `RPCSEC_GSS_DATA`.
const DATA: u32 = 0;

/// `RPCSEC_GSS_INIT`.
const INIT: u32 = 1;

/// `RPCSEC_GSS_CONTINUE_INIT`.
const CONTINUE_INIT: u32 = 2;

/// `RPCSEC_GSS_DESTROY`.
const DESTROY: u32 = 3;

/// `NULLPROC`, the procedure of the control calls.
const NULLPROC: u32 = 0;

/// `MAXSEQ` (RFC 2203 section 5.3.3.1, MIT `auth_gss.h:118`): the server
/// refuses a sequence number above it.
const MAXSEQ: u32 = 0x8000_0000;

/// The largest context token exchanged: the crate's GSS token bound.
const MAX_TOKEN: usize = 0x0004_0000;

/// GSS major status `GSS_S_COMPLETE`.
const GSS_S_COMPLETE: u32 = 0;

/// GSS major status `GSS_S_CONTINUE_NEEDED`.
const GSS_S_CONTINUE_NEEDED: u32 = 1;

/// The `RPCSEC_GSS` service number of `protection`.
const fn service(protection: Protection) -> u32 {
    match protection {
        Protection::Integrity => 2,
        Protection::Privacy => 3,
    }
}

/// See [`RpcClient::new`].
///
/// # Errors
///
/// Returns the RPC and GSS errors of the step.
pub(super) fn new(
    program: Program,
    protection: Protection,
    initiator: Initiator,
) -> Result<RpcClient, Error> {
    let mut seed = [0_u8; 4];
    getrandom::fill(&mut seed).map_err(|error| Error::Io(io::Error::other(error)))?;
    Ok(RpcClient {
        program,
        protection,
        phase: Phase::Start(Box::new(initiator)),
        handle: Vec::new(),
        window: 0,
        sequence: 0,
        next_xid: u32::from_be_bytes(seed),
        outstanding: None,
    })
}

/// See [`RpcClient::initiator`].
pub(super) fn initiator(target: Name, options: InitiatorOptions) -> Initiator {
    let flags =
        ContextFlags::MUTUAL | ContextFlags::REPLAY | ContextFlags::CONF | ContextFlags::INTEG;
    Initiator::new(target, options.with_flags(flags))
}

/// The next XID.
const fn next_xid(client: &mut RpcClient) -> u32 {
    let xid = client.next_xid;
    client.next_xid = xid.wrapping_add(1);
    xid
}

/// A context-creation call carrying `token`.
///
/// # Errors
///
/// Returns the RPC and GSS errors of the step.
fn init_call(client: &mut RpcClient, procedure: u32, token: &[u8]) -> Result<ProtectedCall, Error> {
    let xid = next_xid(client);
    let credential = GssCredential::new(procedure, 0, service(client.protection), &client.handle);
    let header = message::header(xid, client.program, NULLPROC, &credential)?;
    let encoder = message::verifier(Encoder::new().raw(&header), 0, &[])?;
    let message = encoder.opaque("context token", token, MAX_TOKEN)?.finish();
    Ok(ProtectedCall {
        xid,
        sequence: 0,
        procedure: NULLPROC,
        kind: CallKind::Init,
        message,
    })
}

/// See [`RpcClient::start`].
///
/// # Errors
///
/// Returns the RPC and GSS errors of the step.
pub(super) fn start(
    client: &mut RpcClient,
    credential: &Credential,
) -> Result<ProtectedCall, Error> {
    let Phase::Start(mut initiator) = mem::replace(&mut client.phase, Phase::Closed) else {
        return Err(Error::UnexpectedStep("the context creation has started"));
    };
    let token = match initiator.init_sec_context(credential, None)? {
        GssStep::Continue(token) | GssStep::Complete(Some(token)) => token,
        GssStep::Complete(None) => {
            return Err(Error::UnexpectedStep("the initiator sent no first token"));
        }
    };
    let call = init_call(client, INIT, &token)?;
    client.phase = Phase::Creating {
        initiator,
        xid: call.xid,
    };
    Ok(call)
}

/// The decoded reply to the call with `xid`, its outcome a success.
///
/// # Errors
///
/// Returns the RPC and GSS errors of the step.
fn accepted(message: &[u8], xid: u32) -> Result<Reply, Error> {
    let reply = Reply::decode(message)?;
    if reply.xid != xid {
        return Err(Error::XidMismatch {
            expected: xid,
            actual: reply.xid,
        });
    }
    match reply.outcome {
        Outcome::Success => Ok(reply),
        Outcome::AuthError(status) => Err(Error::AuthenticationRejected(status)),
        Outcome::RpcMismatch { low, high } => Err(Error::VersionMismatch { low, high }),
        Outcome::ProgramUnavailable => Err(Error::NotAccepted(1)),
        Outcome::ProgramMismatch { low: _, high: _ } => Err(Error::NotAccepted(2)),
        Outcome::ProcedureUnavailable => Err(Error::NotAccepted(3)),
        Outcome::GarbageArguments => Err(Error::NotAccepted(4)),
        Outcome::SystemError => Err(Error::NotAccepted(5)),
    }
}

/// Verify that `reply` carries an `RPCSEC_GSS` verifier that is a MIC over `number`.
///
/// # Errors
///
/// Returns the RPC and GSS errors of the step.
fn verify(context: &mut EstablishedContext, reply: &Reply, number: u32) -> Result<(), Error> {
    let verifier = reply
        .verifier
        .as_ref()
        .ok_or(Error::Malformed("an accepted reply has a verifier"))?;
    if verifier.flavor != RPCSEC_GSS {
        return Err(Error::UnexpectedVerifier(verifier.flavor));
    }
    context
        .verify_mic(&number.to_be_bytes(), &verifier.body)
        .map_err(Error::BadVerifier)
}

/// The fields of `rpc_gss_init_res` (RFC 2203 section 5.2.3.1).
struct InitResult<'bytes> {
    /// The context handle.
    handle: &'bytes [u8],
    /// The GSS major status.
    major: u32,
    /// The GSS minor status.
    minor: u32,
    /// The sequence window.
    window: u32,
    /// The acceptor's token.
    token: &'bytes [u8],
}

/// Decode `rpc_gss_init_res` (MIT `xdr_rpc_gss_init_res`, `authgss_prot.c`).
///
/// # Errors
///
/// Returns the RPC and GSS errors of the step.
fn init_result(results: &[u8]) -> Result<InitResult<'_>, Error> {
    let mut decoder = Decoder::new(results);
    let result = InitResult {
        handle: decoder.opaque("context handle", MAX_HANDLE)?,
        major: decoder.u32()?,
        minor: decoder.u32()?,
        window: decoder.u32()?,
        token: decoder.opaque("context token", MAX_TOKEN)?,
    };
    decoder.end()?;
    Ok(result)
}

/// See [`RpcClient::continue_init`].
///
/// # Errors
///
/// Returns the RPC and GSS errors of the step.
pub(super) fn continue_init(
    client: &mut RpcClient,
    credential: &Credential,
    message: &[u8],
) -> Result<InitStep, Error> {
    let Phase::Creating { mut initiator, xid } =
        mem::replace(&mut client.phase, Phase::Closed)
    else {
        return Err(Error::UnexpectedStep(
            "no context-creation call is outstanding",
        ));
    };
    let reply = accepted(message, xid)?;
    let result = init_result(&reply.results)?;
    if result.major != GSS_S_COMPLETE && result.major != GSS_S_CONTINUE_NEEDED {
        return Err(Error::ContextCreation {
            major: result.major,
            minor: result.minor,
        });
    }
    if !result.handle.is_empty() {
        result.handle.clone_into(&mut client.handle);
    }
    let next = if result.token.is_empty() {
        None
    } else {
        match initiator.init_sec_context(credential, Some(result.token))? {
            GssStep::Continue(token) | GssStep::Complete(Some(token)) => Some(token),
            GssStep::Complete(None) => None,
        }
    };
    if result.major == GSS_S_CONTINUE_NEEDED || !initiator.is_established() {
        let token = next.ok_or(Error::UnexpectedStep(
            "the context needs a token neither side sent",
        ))?;
        let call = init_call(client, CONTINUE_INIT, &token)?;
        client.phase = Phase::Creating {
            initiator,
            xid: call.xid,
        };
        return Ok(InitStep::Call(call));
    }
    if next.is_some() {
        return Err(Error::UnexpectedStep(
            "the server completed before the initiator's last token",
        ));
    }
    let mut context = initiator.into_established()?;
    verify(&mut context, &reply, result.window)?;
    if result.window == 0 {
        return Err(Error::BadWindow(0));
    }
    client.window = result.window;
    client.sequence = 0;
    client.phase = Phase::Established(Box::new(context));
    Ok(InitStep::Established)
}

/// The established context of `client`.
///
/// # Errors
///
/// Returns the RPC and GSS errors of the step.
fn established(client: &mut RpcClient) -> Result<&mut EstablishedContext, Error> {
    match &mut client.phase {
        Phase::Established(context) => Ok(context),
        Phase::Closed => Err(Error::ConnectionClosed),
        Phase::Start(_) | Phase::Creating { initiator: _, xid: _ } => {
            Err(Error::UnexpectedStep("the context is not established"))
        }
    }
}

/// A data or destroy call under the context.
///
/// # Errors
///
/// Returns the RPC and GSS errors of the step.
fn protected_call(
    client: &mut RpcClient,
    kind: CallKind,
    procedure: u32,
    arguments: &[u8],
) -> Result<ProtectedCall, Error> {
    if !matches!(client.phase, Phase::Established(_)) {
        return Err(established(client).err().unwrap_or(Error::ConnectionClosed));
    }
    if client.outstanding.is_some() {
        return Err(Error::UnexpectedStep("a call is outstanding"));
    }
    let sequence = client
        .sequence
        .checked_add(1)
        .filter(|next| *next < MAXSEQ)
        .ok_or(Error::SequenceExhausted)?;
    let xid = next_xid(client);
    let gss_procedure = if kind == CallKind::Destroy {
        DESTROY
    } else {
        DATA
    };
    let credential = GssCredential::new(gss_procedure, sequence, service(client.protection), &client.handle);
    let header = message::header(xid, client.program, procedure, &credential)?;
    let protection = client.protection;
    let context = established(client)?;
    let mic = context.get_mic(&header)?;
    let mut encoder = message::verifier(Encoder::new().raw(&header), RPCSEC_GSS, &mic)?;
    if kind == CallKind::Data {
        let body = Encoder::new().u32(sequence).raw(arguments).finish();
        encoder = match protection {
            Protection::Integrity => {
                let checksum = context.get_mic(&body)?;
                encoder
                    .opaque("integrity body", &body, usize::MAX)?
                    .opaque("integrity checksum", &checksum, usize::MAX)?
            }
            Protection::Privacy => {
                let token = context.wrap(&body, true)?;
                encoder.opaque("privacy body", &token, usize::MAX)?
            }
        };
    }
    client.sequence = sequence;
    client.outstanding = Some(xid);
    Ok(ProtectedCall {
        xid,
        sequence,
        procedure,
        kind,
        message: encoder.finish(),
    })
}

/// See [`RpcClient::call`].
///
/// # Errors
///
/// Returns the RPC and GSS errors of the step.
pub(super) fn call(
    client: &mut RpcClient,
    procedure: u32,
    arguments: &[u8],
) -> Result<ProtectedCall, Error> {
    protected_call(client, CallKind::Data, procedure, arguments)
}

/// See [`RpcClient::destroy_call`].
///
/// # Errors
///
/// Returns the RPC and GSS errors of the step.
pub(super) fn destroy_call(client: &mut RpcClient) -> Result<ProtectedCall, Error> {
    protected_call(client, CallKind::Destroy, NULLPROC, &[])
}

/// The unprotected body of a data reply: its sequence number checked.
///
/// # Errors
///
/// Returns the RPC and GSS errors of the step.
fn unprotect(
    context: &mut EstablishedContext,
    protection: Protection,
    sequence: u32,
    results: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut decoder = Decoder::new(results);
    let body: Zeroizing<Vec<u8>> = match protection {
        Protection::Integrity => {
            let body = decoder.opaque("integrity body", usize::MAX)?;
            let checksum = decoder.opaque("integrity checksum", usize::MAX)?;
            context.verify_mic(body, checksum)?;
            Zeroizing::new(body.to_vec())
        }
        Protection::Privacy => {
            let unwrapped = context.unwrap(decoder.opaque("privacy body", usize::MAX)?)?;
            if !unwrapped.confidential() {
                return Err(Error::Malformed("a privacy body was not sealed"));
            }
            Zeroizing::new(unwrapped.message().to_vec())
        }
    };
    decoder.end()?;
    let mut inner = Decoder::new(&body);
    let actual = inner.u32()?;
    if actual != sequence {
        return Err(Error::SequenceMismatch {
            expected: sequence,
            actual,
        });
    }
    Ok(Zeroizing::new(inner.rest().to_vec()))
}

/// Check the reply to `call`.
///
/// # Errors
///
/// Returns the RPC and GSS errors of the step.
fn checked_reply(
    client: &mut RpcClient,
    call: &ProtectedCall,
    message: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if client.outstanding != Some(call.xid) || call.kind == CallKind::Init {
        return Err(Error::UnexpectedStep("the call is not outstanding"));
    }
    let protection = client.protection;
    let context = established(client)?;
    let reply = accepted(message, call.xid)?;
    verify(context, &reply, call.sequence)?;
    let results = if call.kind == CallKind::Destroy {
        if !reply.results.is_empty() {
            return Err(Error::Malformed("bytes after the destroy reply"));
        }
        Zeroizing::new(Vec::new())
    } else {
        unprotect(context, protection, call.sequence, &reply.results)?
    };
    client.outstanding = None;
    if call.kind == CallKind::Destroy {
        client.close();
    }
    Ok(results)
}

/// See [`RpcClient::reply`].
///
/// # Errors
///
/// Returns the RPC and GSS errors of the step.
pub(super) fn reply(
    client: &mut RpcClient,
    call: &ProtectedCall,
    message: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    checked_reply(client, call, message).inspect_err(|_error| client.close())
}

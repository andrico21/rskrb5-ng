//! A test-only loopback RPCSEC_GSS server in the shape of MIT's kadmind.
//!
//! It is never part of the library (plan 2 todo 24: no kadmind). It reads
//! RFC 5531 records from one end of an in-memory duplex stream, accepts the
//! RPCSEC_GSS context with the crate's own GSS acceptor and the
//! `kadmin/admin` keytab, signs the window twice as MIT's
//! `svc_auth_gss.c:262-275,503-506` does (so the client sees a gap in the
//! acceptor's GSS sequence), checks every call's header MIC and body sequence
//! number, and answers each data call with the bytes the scenario's handler
//! returns, protected as RFC 2203 section 5.3.3 says. A scenario can script
//! one fault per data call to prove the client rejects it.

use std::collections::VecDeque;

use rskrb5_ng::gss::{Acceptor, AcceptorOptions, Credential, EstablishedContext};
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, DuplexStream, duplex},
    task::JoinHandle,
};

use super::{
    context::{Context as _, TestError},
    support,
    wire::{Reader, Writer},
};

/// The RPCSEC_GSS authentication flavor (RFC 2203 section 5).
pub(super) const RPCSEC_GSS: u32 = 6;

/// The kadm5 program (MIT `kadm_rpc.h`, `KADM`).
const KADM: u32 = 2112;

/// The window the server grants by default: MIT's `sizeof(seqmask) * 8`.
const WINDOW: u32 = 32;

/// What the server answers to a data call.
pub(super) type Handler = Box<dyn FnMut(u32, &[u8]) -> Vec<u8> + Send>;

/// A fault the server commits on one data call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Fault {
    /// Answer correctly.
    None,
    /// Answer with a fresh reply whose verifier and body carry the previous
    /// call's sequence number (a reused sequence number).
    ReusedSequence,
    /// Answer with the previous reply's record, its XID rewritten to this call's.
    ReplayPrevious,
    /// A correct verifier, but a body that names the previous sequence number.
    StaleBodySequence,
    /// Flip a byte of the verifier's MIC.
    WrongVerifier,
    /// Flip a byte of the body's MIC or wrap token.
    CorruptBody,
    /// An `AUTH_NONE` verifier on a data reply.
    NoneVerifier,
    /// Another XID.
    WrongXid,
    /// Send the reply in fragments of this many bytes.
    Fragments(usize),
    /// A last-fragment header announcing 2 GiB less one byte.
    OversizedFragment,
    /// One-byte fragments that never end.
    EndlessFragments,
    /// Close the connection without an answer.
    Close,
    /// Read the call and never answer, until the client hangs up.
    Stall,
    /// Deny the call with `AUTH_ERROR` and this status.
    Deny(u32),
}

/// How the server answers the context creation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Init {
    /// Accept, as kadmind does.
    Accept,
    /// Accept, granting this window.
    Window(u32),
    /// Deny every RPCSEC_GSS call with `AUTH_ERROR` and this status: a server
    /// that offers only `AUTH_SYS`.
    AuthSysOnly(u32),
    /// Answer with an `AUTH_NONE` verifier instead of the window's MIC.
    NoneVerifier,
}

/// The script of one connection.
#[derive(Debug)]
pub(super) struct Script {
    /// The answer to the context creation.
    pub init: Init,
    /// One fault per data call, in order; `Fault::None` after the last.
    pub faults: VecDeque<Fault>,
}

impl Script {
    /// A server without faults.
    pub(super) const fn plain() -> Self {
        Self {
            init: Init::Accept,
            faults: VecDeque::new(),
        }
    }

    /// A server committing `faults` on the data calls, in order.
    pub(super) fn faults(faults: &[Fault]) -> Self {
        Self {
            init: Init::Accept,
            faults: faults.iter().copied().collect(),
        }
    }
}

/// What the server saw.
#[derive(Debug, Default)]
pub(super) struct Seen {
    /// The credential flavor of every call, in order.
    pub flavors: Vec<u32>,
    /// The RPCSEC_GSS service of the context (2 integrity, 3 privacy).
    pub service: u32,
    /// Every data call's procedure and unprotected arguments.
    pub calls: Vec<(u32, Vec<u8>)>,
    /// Whether the client destroyed the context.
    pub destroyed: bool,
}

/// Start a server on one end of a duplex stream; the client gets the other.
pub(super) fn spawn(
    handler: Handler,
    script: Script,
) -> (DuplexStream, JoinHandle<Result<Seen, TestError>>) {
    let (client, server) = duplex(1 << 16);
    (client, spawn_on(server, handler, script))
}

/// Start a server on `stream`.
pub(super) fn spawn_on<S>(
    stream: S,
    handler: Handler,
    script: Script,
) -> JoinHandle<Result<Seen, TestError>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(serve(stream, handler, script))
}

/// Read one RFC 5531 record; `None` at a clean end of stream.
async fn read_record<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Option<Vec<u8>>, TestError> {
    let mut record = Vec::new();
    loop {
        let mut header = [0_u8; 4];
        match stream.read_exact(&mut header).await {
            Ok(_) => {}
            Err(error)
                if error.kind() == std::io::ErrorKind::UnexpectedEof && record.is_empty() =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error.into()),
        }
        let word = u32::from_be_bytes(header);
        let mut fragment = vec![0; usize::try_from(word & 0x7fff_ffff)?];
        stream.read_exact(&mut fragment).await?;
        record.extend_from_slice(&fragment);
        if word & 0x8000_0000 != 0 {
            return Ok(Some(record));
        }
    }
}

/// Write `record` as fragments of at most `size` bytes.
async fn write_fragments<S: AsyncWrite + Unpin>(
    stream: &mut S,
    record: &[u8],
    size: usize,
) -> Result<(), TestError> {
    let mut chunks = record.chunks(size.max(1)).peekable();
    while let Some(chunk) = chunks.next() {
        let mut word = u32::try_from(chunk.len())?;
        if chunks.peek().is_none() {
            word |= 0x8000_0000;
        }
        stream.write_all(&word.to_be_bytes()).await?;
        stream.write_all(chunk).await?;
    }
    stream.flush().await?;
    Ok(())
}

/// One parsed call.
struct Call {
    /// The XID.
    xid: u32,
    /// The procedure.
    procedure: u32,
    /// The credential flavor.
    flavor: u32,
    /// The credential body.
    credential: Vec<u8>,
    /// The header bytes the verifier signs: XID through credential.
    header: Vec<u8>,
    /// The verifier body.
    verifier: Vec<u8>,
    /// The arguments.
    arguments: Vec<u8>,
}

/// Parse an RPC call (RFC 5531 section 9).
fn parse_call(record: &[u8]) -> Result<Call, TestError> {
    let mut reader = Reader::new(record);
    let xid = reader.u32()?;
    if reader.u32()? != 0 || reader.u32()? != 2 || reader.u32()? != KADM || reader.u32()? != 2 {
        return Err("not a kadm5 version 2 call".into());
    }
    let procedure = reader.u32()?;
    let flavor = reader.u32()?;
    let credential = reader.opaque()?.to_vec();
    let consumed = record.len() - reader.rest().len();
    let header = record.get(..consumed).context("header")?.to_vec();
    let _verifier_flavor = reader.u32()?;
    let verifier = reader.opaque()?.to_vec();
    Ok(Call {
        xid,
        procedure,
        flavor,
        credential,
        header,
        verifier,
        arguments: reader.rest().to_vec(),
    })
}

/// An accepted reply with verifier `verifier` (flavor RPCSEC_GSS unless
/// `None`) and `results`.
fn accepted(xid: u32, verifier: Option<&[u8]>, results: &[u8]) -> Vec<u8> {
    let writer = Writer::new().u32(xid).u32(1).u32(0);
    let writer = match verifier {
        Some(mic) => writer.u32(RPCSEC_GSS).opaque(mic),
        None => writer.u32(0).opaque(&[]),
    };
    writer.u32(0).raw(results).finish()
}

/// An `AUTH_ERROR` denial (RFC 5531 section 9, `reject_stat` 1).
fn denied(xid: u32, status: u32) -> Vec<u8> {
    Writer::new()
        .u32(xid)
        .u32(1)
        .u32(1)
        .u32(1)
        .u32(status)
        .finish()
}

/// Flip the last byte of `bytes`.
fn flip(mut bytes: Vec<u8>) -> Vec<u8> {
    if let Some(last) = bytes.last_mut() {
        *last ^= 0x01;
    }
    bytes
}

/// The protected body of `results` under `service` for `sequence`.
fn protect(
    context: &mut EstablishedContext,
    service: u32,
    sequence: u32,
    results: &[u8],
    corrupt: bool,
) -> Result<Vec<u8>, TestError> {
    let body = Writer::new().u32(sequence).raw(results).finish();
    if service == 2 {
        let mic = context.get_mic(&body)?;
        let mic = if corrupt { flip(mic) } else { mic };
        Ok(Writer::new().opaque(&body).opaque(&mic).finish())
    } else {
        let token = context.wrap(&body, true)?;
        let token = if corrupt { flip(token) } else { token };
        Ok(Writer::new().opaque(&token).finish())
    }
}

/// The unprotected arguments of a data call.
fn unprotect(
    context: &mut EstablishedContext,
    service: u32,
    sequence: u32,
    arguments: &[u8],
) -> Result<Vec<u8>, TestError> {
    let mut reader = Reader::new(arguments);
    let body = if service == 2 {
        let body = reader.opaque()?.to_vec();
        let mic = reader.opaque()?;
        context.verify_mic(&body, mic)?;
        body
    } else {
        let unwrapped = context.unwrap(reader.opaque()?)?;
        if !unwrapped.confidential() {
            return Err("privacy arguments must be sealed".into());
        }
        unwrapped.message().to_vec()
    };
    let mut body_reader = Reader::new(&body);
    if body_reader.u32()? != sequence {
        return Err("the argument body names another sequence number".into());
    }
    Ok(body_reader.rest().to_vec())
}

/// The server's state over one connection.
struct State {
    /// The established context.
    context: Option<EstablishedContext>,
    /// The context's service.
    service: u32,
    /// The previous data reply and its sequence number.
    previous: Option<(Vec<u8>, u32, Vec<u8>)>,
}

/// Accept the context creation call.
fn init(
    state: &mut State,
    acceptor_credential: &Credential,
    call: &Call,
    script: &Script,
) -> Result<Vec<u8>, TestError> {
    let mut reader = Reader::new(&call.credential);
    let (_version, _proc, _sequence, service) =
        (reader.u32()?, reader.u32()?, reader.u32()?, reader.u32()?);
    let token = Reader::new(&call.arguments).opaque()?.to_vec();
    let mut acceptor = Acceptor::new(acceptor_credential, AcceptorOptions::new())?;
    let accepted_context = acceptor.accept_sec_context(&token)?;
    let reply_token = accepted_context.output_token().unwrap_or_default().to_vec();
    let mut context = accepted_context.into_context();
    let window = match script.init {
        Init::Window(window) => window,
        Init::Accept | Init::AuthSysOnly(_) | Init::NoneVerifier => WINDOW,
    };
    // MIT signs the window in accept_sec_context and again in nextverf.
    drop(context.get_mic(&window.to_be_bytes())?);
    let mic = context.get_mic(&window.to_be_bytes())?;
    let results = Writer::new()
        .opaque(b"hndl")
        .u32(0)
        .u32(0)
        .u32(window)
        .opaque(&reply_token)
        .finish();
    state.context = Some(context);
    state.service = service;
    let verifier = (script.init != Init::NoneVerifier).then_some(mic.as_slice());
    Ok(accepted(call.xid, verifier, &results))
}

/// Answer one data call under `fault`.
fn data(
    state: &mut State,
    handler: &mut Handler,
    call: &Call,
    fault: Fault,
    seen: &mut Seen,
) -> Result<Vec<u8>, TestError> {
    let service = state.service;
    let context = state.context.as_mut().context("an established context")?;
    context.verify_mic(&call.header, &call.verifier)?;
    let mut reader = Reader::new(&call.credential);
    let (_version, gss_proc, sequence) = (reader.u32()?, reader.u32()?, reader.u32()?);
    if gss_proc == 3 {
        seen.destroyed = true;
        let mic = context.get_mic(&sequence.to_be_bytes())?;
        return Ok(accepted(call.xid, Some(&mic), &[]));
    }
    let arguments = unprotect(context, service, sequence, &call.arguments)?;
    seen.calls.push((call.procedure, arguments.clone()));
    let results = handler(call.procedure, &arguments);
    let (verified, body_sequence) = match fault {
        Fault::ReusedSequence => {
            let old = state.previous.as_ref().context("a previous reply")?.1;
            (old, old)
        }
        Fault::StaleBodySequence => (sequence, sequence.wrapping_sub(1)),
        _ => (sequence, sequence),
    };
    let mic = context.get_mic(&verified.to_be_bytes())?;
    let mic = if fault == Fault::WrongVerifier {
        flip(mic)
    } else {
        mic
    };
    let body = protect(
        context,
        service,
        body_sequence,
        &results,
        fault == Fault::CorruptBody,
    )?;
    let xid = if fault == Fault::WrongXid {
        call.xid ^ 1
    } else {
        call.xid
    };
    let verifier = (fault != Fault::NoneVerifier).then_some(mic.as_slice());
    let mut reply = accepted(xid, verifier, &body);
    if fault == Fault::ReplayPrevious {
        let previous = state.previous.as_ref().context("a previous reply")?;
        reply.clone_from(&previous.0);
        reply
            .get_mut(..4)
            .context("an XID")?
            .copy_from_slice(&call.xid.to_be_bytes());
    }
    state.previous = Some((reply.clone(), sequence, results));
    Ok(reply)
}

/// Serve one connection until the client closes it.
async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    mut handler: Handler,
    mut script: Script,
) -> Result<Seen, TestError> {
    let acceptor_credential = Credential::from_keytab(support::keytab());
    let mut state = State {
        context: None,
        service: 0,
        previous: None,
    };
    let mut seen = Seen::default();
    while let Some(record) = read_record(&mut stream).await? {
        let call = parse_call(&record)?;
        seen.flavors.push(call.flavor);
        if call.flavor != RPCSEC_GSS {
            write_fragments(&mut stream, &denied(call.xid, 1), usize::MAX).await?;
            continue;
        }
        if let Init::AuthSysOnly(status) = script.init {
            write_fragments(&mut stream, &denied(call.xid, status), usize::MAX).await?;
            continue;
        }
        if state.context.is_none() {
            let reply = init(&mut state, &acceptor_credential, &call, &script)?;
            seen.service = state.service;
            write_fragments(&mut stream, &reply, usize::MAX).await?;
            continue;
        }
        // The version negotiation (INIT, 13) and the context destruction
        // (RPCSEC_GSS_DESTROY, 3) are answered plainly; the faults are the
        // scenario's calls'.
        let destroy = call.credential.get(4..8) == Some(&3_u32.to_be_bytes()[..]);
        let fault = if call.procedure == 13 || destroy {
            Fault::None
        } else {
            script.faults.pop_front().unwrap_or(Fault::None)
        };
        match fault {
            Fault::Close => return Ok(seen),
            Fault::Deny(status) => {
                write_fragments(&mut stream, &denied(call.xid, status), usize::MAX).await?;
                continue;
            }
            Fault::OversizedFragment => {
                stream.write_all(&u32::MAX.to_be_bytes()).await?;
                stream.write_all(&[0; 64]).await?;
                stream.flush().await?;
                return Ok(seen);
            }
            Fault::EndlessFragments => {
                // Stop once the client hangs up.
                while stream.write_all(&[0, 0, 0, 1, 0]).await.is_ok() {}
                return Ok(seen);
            }
            _ => {}
        }
        let reply = data(&mut state, &mut handler, &call, fault, &mut seen)?;
        if fault == Fault::Stall {
            while read_record(&mut stream).await?.is_some() {}
            return Ok(seen);
        }
        let size = match fault {
            Fault::Fragments(size) => size,
            _ => usize::MAX,
        };
        write_fragments(&mut stream, &reply, size).await?;
    }
    Ok(seen)
}

/// A handler answering every call with `generic_ret` { version, code 0 }.
pub(super) fn generic_success(version: u32) -> Handler {
    Box::new(move |_procedure, _arguments| Writer::new().u32(version).u32(0).finish())
}

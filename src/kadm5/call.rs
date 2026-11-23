//! One kadm5 call: the RPC exchange under the timeout, the outcome rule for
//! mutations, and the result decoding.

use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt as _},
    time,
};
use zeroize::Zeroizing;

use super::{Procedure, RemoteAdminClient, Response};
use crate::{
    error::{Kadm5 as Error, Rpc},
    rpcsec_gss::{ProtectedCall, record},
};

/// Send `call` and return its unprotected results.
///
/// From here the request may reach the server: any failure closes the
/// connection. While the exchange runs the client is marked interrupted, so a
/// caller that drops this future leaves a client that refuses every later
/// call before sending it.
///
/// # Errors
///
/// Returns the RPC errors of the exchange.
///
/// # Cancel safety
///
/// The client is marked interrupted before the request is written and the mark
/// is cleared only when the exchange ends: a dropped future leaves it set, so
/// every later call is refused before anything is sent.
async fn exchange<S>(
    client: &mut RemoteAdminClient<S>,
    procedure: Procedure,
    call: &ProtectedCall,
) -> Result<Zeroizing<Vec<u8>>, Rpc>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    client.interrupted = Some(procedure);
    let timeout = client.options.timeout;
    let stream = &mut client.stream;
    let answer = time::timeout(timeout, async {
        record::write(stream, call.message()).await?;
        record::read(stream).await
    })
    .await
    .unwrap_or(Err(Rpc::TimedOut));
    let results = answer.and_then(|message| client.rpc.reply(call, &message));
    client.interrupted = None;
    if results.is_err() {
        client.rpc.close();
    }
    results
}

/// Call `procedure` with `arguments` and decode its result.
///
/// # Errors
///
/// Returns [`Error::Interrupted`] when an earlier call did not finish and
/// the RPC errors of building the call, with nothing sent;
/// [`Error::Server`] for kadmind's refusal; and for a mutation that may have
/// been delivered and has no decodable authenticated answer
/// [`Error::OutcomeUnknown`], the RPC and decoding errors otherwise.
///
/// # Cancel safety
///
/// Not cancel-safe for a mutation: a future dropped after the request was
/// written leaves the client interrupted (see `exchange`), so the change is
/// never sent again and every later call is refused.
pub(super) async fn run<S>(
    client: &mut RemoteAdminClient<S>,
    procedure: Procedure,
    arguments: &[u8],
) -> Result<Response, Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if let Some(previous) = client.interrupted {
        return Err(Error::Interrupted(previous.name()));
    }
    let call = client.rpc.call(procedure.number(), arguments)?;
    let unknown = |cause: Error| {
        if procedure.is_mutation() {
            Error::OutcomeUnknown {
                procedure: procedure.name(),
                cause: Box::new(cause),
            }
        } else {
            cause
        }
    };
    let results = exchange(client, procedure, &call)
        .await
        .map_err(|error| unknown(Error::Rpc(error)))?;
    match Response::decode(procedure, client.version, &results) {
        Ok(response) => Ok(response),
        Err(
            error @ Error::Server {
                procedure: _,
                code: _,
            },
        ) => Err(error),
        Err(error) => Err(unknown(error)),
    }
}

/// End the context with `RPCSEC_GSS_DESTROY` and close the stream.
///
/// # Errors
///
/// Returns [`Error::Interrupted`] after an unfinished call and the RPC
/// errors of the exchange.
///
/// # Cancel safety
///
/// Cancel-safe: the caller consumes the client, so nothing runs after a
/// dropped future; the connection closes with it.
pub(super) async fn destroy<S>(client: &mut RemoteAdminClient<S>) -> Result<(), Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if let Some(previous) = client.interrupted {
        return Err(Error::Interrupted(previous.name()));
    }
    let call = client.rpc.destroy_call()?;
    let timeout = client.options.timeout;
    let stream = &mut client.stream;
    let answer = time::timeout(timeout, async {
        record::write(stream, call.message()).await?;
        record::read(stream).await
    })
    .await
    .unwrap_or(Err(Rpc::TimedOut))?;
    let empty = client.rpc.reply(&call, &answer)?;
    drop(empty);
    client.stream.shutdown().await.map_err(Rpc::Io)?;
    Ok(())
}

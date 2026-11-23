//! The admin server, the connection, the context and the version negotiation.
//!
//! MIT's client: `client_init.c` `init_any`, `connect_to_server` and
//! `setup_gss`; `alt_prof.c` for the admin server.

use std::io;

use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{self, TcpStream},
    time,
};

use super::{
    AdminServer, DEFAULT_PORT, Options, PROGRAM, Procedure, RemoteAdminClient, Response, call,
    service_principal, wire,
};
use crate::{
    config::Config,
    error::{Kadm5 as Error, Rpc},
    gss::{Credential, Name},
    rpcsec_gss::{InitStep, RpcClient, record},
};

/// `KADM5_NEW_SERVER_API_VERSION` (`kadm_err.et`: the ovk table base
/// 43787520 plus 39).
const NEW_SERVER_API_VERSION: u32 = 43_787_559;

/// The most context-creation round trips: the krb5 mechanism needs one.
const MAX_ROUNDS: usize = 8;

/// A port of 1 to 65535.
///
/// # Errors
///
/// Returns the configuration, connection, RPC and GSS errors of its steps.
fn port(text: &str, value: &str) -> Result<u16, Error> {
    text.parse::<u16>()
        .ok()
        .filter(|number| *number != 0)
        .ok_or_else(|| Error::BadAdminServer(value.to_owned()))
}

/// See [`super::admin_server`].
///
/// # Errors
///
/// Returns the configuration, connection, RPC and GSS errors of its steps.
pub(super) fn admin_server(config: &Config, realm: &str) -> Result<AdminServer, Error> {
    let value = config
        .realm(realm)
        .and_then(|entry| entry.admin_server.first())
        .ok_or_else(|| Error::NoAdminServer(realm.to_owned()))?;
    let bad = || Error::BadAdminServer(value.clone());
    let (host, port_text) = if let Some(bracketed) = value.strip_prefix('[') {
        let (address, rest) = bracketed.split_once(']').ok_or_else(bad)?;
        let port_text = match rest {
            "" => None,
            _ => Some(rest.strip_prefix(':').ok_or_else(bad)?),
        };
        (address, port_text)
    } else {
        match value.split_once(':') {
            Some((name, rest)) => (name, Some(rest)),
            None => (value.as_str(), None),
        }
    };
    if host.is_empty() {
        return Err(bad());
    }
    Ok(AdminServer {
        host: host.to_owned(),
        port: port_text.map_or(Ok(DEFAULT_PORT), |text| port(text, value))?,
    })
}

/// A TCP connection to the first address of `server` that accepts one
/// within the timeout (MIT `connect_to_server`).
///
/// # Errors
///
/// Returns the configuration, connection, RPC and GSS errors of its steps.
pub(super) async fn tcp(server: &AdminServer, options: &Options) -> Result<TcpStream, Error> {
    let target = format!("{}:{}", server.host, server.port);
    let failure = |source| Error::Connect {
        server: target.clone(),
        source,
    };
    let addresses = time::timeout(
        options.timeout,
        net::lookup_host((server.host.as_str(), server.port)),
    )
    .await
    .map_err(|elapsed| failure(elapsed.into()))?
    .map_err(failure)?;
    let mut last = io::Error::from(io::ErrorKind::NotFound);
    for address in addresses {
        match time::timeout(options.timeout, TcpStream::connect(address)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(error)) => last = error,
            Err(elapsed) => last = elapsed.into(),
        }
    }
    Err(failure(last))
}

/// Create the `RPCSEC_GSS` context on `stream`.
///
/// # Errors
///
/// Returns the configuration, connection, RPC and GSS errors of its steps.
async fn establish<S>(
    stream: &mut S,
    credential: &Credential,
    options: &Options,
) -> Result<RpcClient, Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let target = Name::from_principal(&service_principal(&options.realm));
    let initiator_options = options
        .initiator
        .clone()
        .with_crypto_policy(options.crypto_policy.clone());
    let initiator = RpcClient::initiator(target, initiator_options);
    let mut rpc = RpcClient::new(PROGRAM, options.protection, initiator)?;
    let mut call = rpc.start(credential)?;
    for _ in 0..MAX_ROUNDS {
        let reply = time::timeout(options.timeout, async {
            record::write(stream, call.message()).await?;
            record::read(stream).await
        })
        .await
        .unwrap_or(Err(Rpc::TimedOut))?;
        match rpc.continue_init(credential, &reply)? {
            InitStep::Established => return Ok(rpc),
            InitStep::Call(next) => call = next,
        }
    }
    Err(Error::Rpc(Rpc::UnexpectedStep(
        "the context needs too many round trips",
    )))
}

/// See [`RemoteAdminClient::over_stream`].
///
/// The context, then `INIT` from the newest offered version down to v2 while
/// the server answers `KADM5_NEW_SERVER_API_VERSION`.
///
/// # Errors
///
/// Returns the configuration, connection, RPC and GSS errors of its steps.
pub(super) async fn over_stream<S>(
    mut stream: S,
    credential: &Credential,
    options: Options,
) -> Result<RemoteAdminClient<S>, Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let rpc = establish(&mut stream, credential, &options).await?;
    let mut version = options.api_version;
    let mut client = RemoteAdminClient {
        stream,
        rpc,
        version,
        options,
        interrupted: None,
    };
    loop {
        let arguments = wire::begin(version).finish();
        match call::run(&mut client, Procedure::Init, &arguments).await {
            Ok(Response::Done) => {
                client.version = version;
                return Ok(client);
            }
            Err(Error::Server {
                code: NEW_SERVER_API_VERSION,
                procedure,
            }) => {
                version = version.older().ok_or(Error::Server {
                    procedure,
                    code: NEW_SERVER_API_VERSION,
                })?;
                client.version = version;
            }
            Ok(unexpected) => {
                drop(unexpected);
                return Err(Error::Malformed("an INIT result carries a payload"));
            }
            Err(error) => return Err(error),
        }
    }
}

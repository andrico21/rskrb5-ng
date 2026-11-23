//! Remote kadm5 administration over `RPCSEC_GSS`, in pure Rust.
//!
//! The client half of MIT krb5 1.22.2's `kadm5` library
//! (`src/lib/kadm5/clnt/`): a [`RemoteAdminClient`] reaches kadmind over TCP,
//! creates an `RPCSEC_GSS` context ([`crate::rpcsec_gss`]) with a ticket for
//! `kadmin/admin`, negotiates the kadm5 API version (v4, then v3, then v2, as
//! `client_init.c` `init_any` does) and offers every remote operation of MIT's
//! client library: principals and policies (create, modify, delete, rename,
//! get, list), password changes, random and supplied keys, key purges, string
//! attributes, key extraction, aliases and the caller's privileges.
//!
//! The kadmind server, its database, its ACL and the command-line tools are
//! not part of this crate.
//!
//! ```no_run
//! # async fn admin(config: &rskrb5_ng::Config, ticket: &rskrb5_ng::client::TgsRepSession)
//! # -> Result<(), rskrb5_ng::error::Kadm5> {
//! use rskrb5_ng::{gss::Credential, kadm5::{Options, PrincipalMask, RemoteAdminClient}};
//!
//! // A service ticket for kadmin/admin@REALM, from an AS exchange with the
//! // administrator's password or keytab, or from a TGS exchange.
//! let credential = Credential::from_service_ticket(ticket);
//! let mut admin = RemoteAdminClient::connect(config, &credential, Options::new("EXAMPLE.COM")).await?;
//! let record = admin
//!     .get_principal(ticket.client(), PrincipalMask::NORMAL)
//!     .await?;
//! drop(record);
//! admin.destroy().await?;
//! # Ok(()) }
//! ```
//!
//! # Security
//!
//! - Every call runs under the `RPCSEC_GSS` privacy service by default (integrity
//!   on request); no unauthenticated or `AUTH_SYS` call is ever sent.
//! - Key/salt tuples and supplied keys pass the runtime encryption policy:
//!   single DES and RC4-EXP are refused by name, DES3 and RC4 only with
//!   `allow_des3`/`allow_rc4`, and the Kerberos V4 and AFS salts never. With no
//!   tuples the client sends none and kadmind's own defaults apply, as with
//!   MIT's client.
//! - A mutation that may have reached kadmind and has no authenticated answer
//!   (a closed connection, a timeout, a reply that does not verify, an
//!   unauthenticated denial, a cancelled call) returns
//!   [`crate::error::Kadm5::OutcomeUnknown`]; it is never repeated, and the
//!   client sends nothing more.
//! - Passwords, keys and results travel in zeroizing buffers; [`KeyData`] and
//!   the keys of [`RemoteAdminClient::randomize_keys`] never show their bytes
//!   in `Debug`.
//! - Every result is decoded with bounded lengths and counts.

use core::{fmt, ops::BitOr, time::Duration};

use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use zeroize::Zeroizing;

use crate::{
    client::{Password, principal::Principal},
    config::Config,
    crypto::{CryptoPolicy, Use},
    error::{
        Client as ClientError, Kadm5 as Error, Policy as PolicyError, RejectedFeature,
        RejectionReason,
    },
    gss::{Credential, InitiatorOptions},
    keytab::EncryptionKey,
    rpcsec_gss::{Program, Protection, RpcClient},
};

/// The calls, their timeout and the outcome rule.
mod call;
/// The admin server and the connection.
mod connect;
/// Principal names in MIT's string form.
mod name;
/// The kadm5 XDR layouts of `kadm_rpc_xdr.c`.
mod wire;

include!("kadm5/types.rs");
include!("kadm5/records.rs");
include!("kadm5/response.rs");
include!("kadm5/client.rs");

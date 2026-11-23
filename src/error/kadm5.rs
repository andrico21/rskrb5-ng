/// ONC RPC over TCP and RPCSEC_GSS error ([`crate::rpcsec_gss`]).
///
/// Every failure after a call was written leaves its connection closed; the
/// administration client above it reports the outcome of a mutation as
/// unknown then.
#[cfg(feature = "spnego")]
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Rpc {
    /// Reading or writing the connection failed.
    #[error("RPC connection I/O failed: {0}")]
    Io(#[from] io::Error),
    /// The server did not answer within the call's timeout.
    #[error("the RPC reply did not arrive in time")]
    TimedOut,
    /// A record or its fragments exceed the record bound.
    #[error("RPC record of at least {actual} bytes exceeds the {maximum}-byte bound")]
    RecordTooLarge {
        /// The bound.
        maximum: usize,
        /// The size the fragments announce.
        actual: u64,
    },
    /// A record has more fragments than the fragment bound.
    #[error("RPC record has more than {0} fragments")]
    TooManyFragments(usize),
    /// A field exceeds its bound.
    #[error("{field} of {actual} bytes exceeds the {maximum}-byte bound")]
    TooLarge {
        /// The field.
        field: &'static str,
        /// The bound.
        maximum: usize,
        /// The size offered.
        actual: usize,
    },
    /// A message does not follow the XDR or RPC layout.
    #[error("malformed RPC message: {0}")]
    Malformed(&'static str),
    /// A reply answers another call.
    #[error("RPC reply XID {actual} does not answer call {expected}")]
    XidMismatch {
        /// The XID of the outstanding call.
        expected: u32,
        /// The XID of the reply.
        actual: u32,
    },
    /// The server speaks other RPC versions (`RPC_MISMATCH`).
    #[error("the server speaks RPC versions {low} to {high}")]
    RpcMismatch {
        /// The lowest version.
        low: u32,
        /// The highest version.
        high: u32,
    },
    /// The server refused the credential (`AUTH_ERROR` and its `auth_stat`,
    /// RFC 5531 section 9 and RFC 2203 section 5.3.3.3).
    #[error("the server rejected the RPCSEC_GSS credential (auth_stat {0})")]
    AuthenticationRejected(u32),
    /// The server did not run the call (`accept_stat`, RFC 5531 section 9).
    #[error("the server did not accept the call (accept_stat {0})")]
    NotAccepted(u32),
    /// A reply carries a verifier that is not RPCSEC_GSS.
    #[error("the reply verifier has flavor {0}, not RPCSEC_GSS")]
    UnexpectedVerifier(u32),
    /// A reply verifier is not this call's sequence number (or window) under
    /// the context.
    #[error("the reply verifier does not verify: {0}")]
    BadVerifier(#[source] Gss),
    /// A protected reply body names another sequence number.
    #[error("the reply body names sequence number {actual}, not {expected}")]
    SequenceMismatch {
        /// The call's sequence number.
        expected: u32,
        /// The number in the body.
        actual: u32,
    },
    /// The context has used every sequence number below `MAXSEQ`.
    #[error("the RPCSEC_GSS context has no sequence number left")]
    SequenceExhausted,
    /// The server's context creation failed with a GSS major status.
    #[error("the server failed the context creation (GSS major {major:#x}, minor {minor:#x})")]
    ContextCreation {
        /// The major status.
        major: u32,
        /// The minor status.
        minor: u32,
    },
    /// The server granted no sequence window.
    #[error("the server granted the sequence window {0}")]
    BadWindow(u32),
    /// A step came out of order.
    #[error("RPCSEC_GSS step out of order: {0}")]
    UnexpectedStep(&'static str),
    /// A per-message GSS operation failed.
    #[error("RPCSEC_GSS protection failed: {0}")]
    Gss(#[from] Gss),
    /// An earlier failure closed the connection; nothing was sent.
    #[error("the RPC connection is closed after an earlier failure")]
    ConnectionClosed,
}

/// Remote kadm5 administration error ([`crate::kadm5`]).
#[cfg(all(feature = "spnego", feature = "tokio"))]
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Kadm5 {
    /// The RPC layer failed.
    #[error("kadm5 RPC failed: {0}")]
    Rpc(#[from] Rpc),
    /// The GSS context could not be established.
    #[error("kadm5 GSS context failed: {0}")]
    Gss(#[from] Gss),
    /// The admin service ticket could not be acquired.
    #[error("kadm5 ticket acquisition failed: {0}")]
    Client(#[from] Client),
    /// A key/salt tuple or key is refused by the encryption policy.
    #[error("kadm5 request refused by policy: {0}")]
    Policy(#[from] Policy),
    /// kadmind answered with a kadm5 error code (`kadm_err.et`).
    #[error("kadmind refused {procedure}: kadm5 error {code}")]
    Server {
        /// The operation.
        procedure: &'static str,
        /// The `kadm5_ret_t` code.
        code: u32,
    },
    /// A mutation may have reached kadmind and has no authenticated answer;
    /// it is never repeated.
    #[error("the outcome of {procedure} is unknown: {cause}")]
    OutcomeUnknown {
        /// The operation.
        procedure: &'static str,
        /// What ended the call.
        #[source]
        cause: Box<Kadm5>,
    },
    /// An earlier call on this client ended before its answer; nothing was sent.
    #[error("an earlier {0} call did not finish; this client sends nothing more")]
    Interrupted(&'static str),
    /// The realm has no `admin_server` (MIT `KADM5_MISSING_KRB5_CONF_PARAMS`).
    #[error("realm {0} has no admin_server")]
    NoAdminServer(String),
    /// An `admin_server` value does not parse.
    #[error("admin_server {0:?} is not host, host:port or [address]:port")]
    BadAdminServer(String),
    /// No address of the admin server accepted a connection.
    #[error("cannot connect to admin server {server}: {source}")]
    Connect {
        /// The server.
        server: String,
        /// The last failure.
        #[source]
        source: io::Error,
    },
    /// A result does not follow the kadm5 XDR layout.
    #[error("malformed kadm5 result: {0}")]
    Malformed(&'static str),
    /// A field exceeds its bound.
    #[error("kadm5 {field} of {actual} exceeds the bound {maximum}")]
    TooLarge {
        /// The field.
        field: &'static str,
        /// The bound.
        maximum: usize,
        /// The size offered.
        actual: usize,
    },
    /// An argument MIT's client refuses with `EINVAL`, or one XDR cannot carry.
    #[error("invalid kadm5 argument: {0}")]
    InvalidArgument(&'static str),
}

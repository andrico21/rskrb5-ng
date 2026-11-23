/// The largest record a reply may reassemble into: 16 MiB.
pub const MAX_RECORD_SIZE: usize = 0x0100_0000;

/// The most fragments a record may have.
pub const MAX_FRAGMENTS: usize = 16_384;

/// The largest credential or verifier body (RFC 5531 section 8.2).
pub const MAX_AUTH_BYTES: usize = 400;

/// The RPCSEC_GSS service of a context (RFC 2203 section 5.3.1).
///
/// `rpc_gss_svc_none`, which leaves the arguments and results unprotected, is
/// not offered.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum Protection {
    /// `rpc_gss_svc_integrity`: a MIC over each body.
    Integrity,
    /// `rpc_gss_svc_privacy`: each body sealed, MIT kadmin's choice.
    #[default]
    Privacy,
}

/// An ONC RPC program and version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Program {
    /// The program number.
    number: u32,
    /// The version.
    version: u32,
}

impl Program {
    /// Program `number`, version `version`.
    #[inline]
    #[must_use]
    pub const fn new(number: u32, version: u32) -> Self {
        Self { number, version }
    }

    /// The program number.
    #[inline]
    #[must_use]
    pub const fn number(&self) -> u32 {
        self.number
    }

    /// The version.
    #[inline]
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }
}

/// An `opaque_auth` verifier of a reply (RFC 5531 section 8.2).
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Verifier {
    /// The authentication flavor.
    flavor: u32,
    /// The body, at most [`MAX_AUTH_BYTES`].
    body: Vec<u8>,
}

impl Verifier {
    /// The authentication flavor: 6 for RPCSEC_GSS.
    #[inline]
    #[must_use]
    pub const fn flavor(&self) -> u32 {
        self.flavor
    }

    /// The body: for RPCSEC_GSS a MIC token.
    #[inline]
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

/// What a server did with a call (RFC 5531 section 9).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Outcome {
    /// `SUCCESS`: the results follow.
    Success,
    /// `PROG_UNAVAIL`.
    ProgramUnavailable,
    /// `PROG_MISMATCH` and the versions the server supports.
    ProgramMismatch {
        /// The lowest version.
        low: u32,
        /// The highest version.
        high: u32,
    },
    /// `PROC_UNAVAIL`.
    ProcedureUnavailable,
    /// `GARBAGE_ARGS`.
    GarbageArguments,
    /// `SYSTEM_ERR`.
    SystemError,
    /// Denied with `RPC_MISMATCH` and the RPC versions the server supports.
    RpcMismatch {
        /// The lowest version.
        low: u32,
        /// The highest version.
        high: u32,
    },
    /// Denied with `AUTH_ERROR` and its `auth_stat`.
    AuthError(u32),
}

/// A decoded RPC reply message: its XID, verifier, outcome and result bytes.
///
/// The results are still protected; [`RpcClient::reply`] checks and unwraps
/// them.
#[non_exhaustive]
pub struct Reply {
    /// The XID.
    xid: u32,
    /// The verifier of an accepted reply.
    verifier: Option<Verifier>,
    /// The outcome.
    outcome: Outcome,
    /// The bytes after the outcome.
    results: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for Reply {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Reply")
            .field("xid", &self.xid)
            .field("verifier", &self.verifier)
            .field("outcome", &self.outcome)
            .field("results_len", &self.results.len())
            .finish()
    }
}

impl Reply {
    /// Decode an RPC reply message (RFC 5531 section 9), without its record marks.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Malformed`] for a call, an unknown status or a
    /// truncated message, and [`Error::TooLarge`] for a verifier above
    /// [`MAX_AUTH_BYTES`].
    #[inline]
    pub fn decode(message: &[u8]) -> Result<Self, Error> {
        message::decode_reply(message)
    }

    /// The XID.
    #[inline]
    #[must_use]
    pub const fn xid(&self) -> u32 {
        self.xid
    }

    /// The verifier of an accepted reply; `None` for a denial.
    #[inline]
    #[must_use]
    pub const fn verifier(&self) -> Option<&Verifier> {
        self.verifier.as_ref()
    }

    /// What the server did with the call.
    #[inline]
    #[must_use]
    pub const fn outcome(&self) -> &Outcome {
        &self.outcome
    }

    /// The bytes after the outcome: the protected results of a success.
    #[inline]
    #[must_use]
    pub fn results(&self) -> &[u8] {
        &self.results
    }
}

/// What a [`ProtectedCall`] is.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CallKind {
    /// `RPCSEC_GSS_INIT` or `RPCSEC_GSS_CONTINUE_INIT` on `NULLPROC`.
    Init,
    /// `RPCSEC_GSS_DATA`.
    Data,
    /// `RPCSEC_GSS_DESTROY` on `NULLPROC`.
    Destroy,
}

/// One call message, built by an [`RpcClient`] and answered once.
#[non_exhaustive]
pub struct ProtectedCall {
    /// The XID.
    xid: u32,
    /// The RPCSEC_GSS sequence number; 0 for a context creation call.
    sequence: u32,
    /// The procedure.
    procedure: u32,
    /// What the call is.
    kind: CallKind,
    /// The RPC message, without record marks.
    message: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for ProtectedCall {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProtectedCall")
            .field("xid", &self.xid)
            .field("sequence", &self.sequence)
            .field("procedure", &self.procedure)
            .field("kind", &self.kind)
            .field("message_len", &self.message.len())
            .finish()
    }
}

impl ProtectedCall {
    /// The XID the reply must carry.
    #[inline]
    #[must_use]
    pub const fn xid(&self) -> u32 {
        self.xid
    }

    /// The RPCSEC_GSS sequence number; 0 for a context creation call.
    #[inline]
    #[must_use]
    pub const fn sequence(&self) -> u32 {
        self.sequence
    }

    /// The procedure.
    #[inline]
    #[must_use]
    pub const fn procedure(&self) -> u32 {
        self.procedure
    }

    /// The RPC message to send, without record marks ([`encode_record`] adds them).
    #[inline]
    #[must_use]
    pub fn message(&self) -> &[u8] {
        &self.message
    }
}

/// The result of one context-creation step.
#[derive(Debug)]
#[non_exhaustive]
pub enum InitStep {
    /// Send this call and pass its reply to [`RpcClient::continue_init`].
    Call(ProtectedCall),
    /// The context is established and its window verified.
    Established,
}

/// Where an [`RpcClient`] is.
enum Phase {
    /// Nothing sent yet.
    Start(Box<Initiator>),
    /// A context-creation call is outstanding.
    Creating {
        /// The initiator.
        initiator: Box<Initiator>,
        /// The outstanding call's XID.
        xid: u32,
    },
    /// The context is established.
    Established(Box<EstablishedContext>),
    /// A step failed or the context was destroyed: nothing more is sent.
    Closed,
}

/// The client side of one RPCSEC_GSS context on one connection.
///
/// Calls are answered one at a time, in order; the window the server grants
/// is never exceeded because no second call is built before the first is
/// answered.
#[non_exhaustive]
pub struct RpcClient {
    /// The program called.
    program: Program,
    /// The service of the context.
    protection: Protection,
    /// The state.
    phase: Phase,
    /// The server's context handle.
    handle: Vec<u8>,
    /// The sequence window the server granted.
    window: u32,
    /// The last sequence number used.
    sequence: u32,
    /// The next XID.
    next_xid: u32,
    /// The XID of the data call awaiting its reply.
    outstanding: Option<u32>,
}

impl fmt::Debug for RpcClient {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let phase = match self.phase {
            Phase::Start(_) => "start",
            Phase::Creating { .. } => "creating",
            Phase::Established(_) => "established",
            Phase::Closed => "closed",
        };
        f.debug_struct("RpcClient")
            .field("program", &self.program)
            .field("protection", &self.protection)
            .field("phase", &phase)
            .field("window", &self.window)
            .field("sequence", &self.sequence)
            .finish_non_exhaustive()
    }
}

impl RpcClient {
    /// A client of `program` that will create an RPCSEC_GSS context with
    /// `protection` for the acceptor `target`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] when no random XID can be drawn.
    #[inline]
    pub fn new(
        program: Program,
        protection: Protection,
        initiator: Initiator,
    ) -> Result<Self, Error> {
        client::new(program, protection, initiator)
    }

    /// The initiator of an RPCSEC_GSS context for `target`: mutual
    /// authentication, replay detection, confidentiality and integrity, and no
    /// sequencing, as MIT's `rpc_auth` asks (`client_init.c`): the server signs
    /// the window twice, so its first MIC the client sees follows a gap.
    #[inline]
    #[must_use]
    pub fn initiator(target: Name, options: InitiatorOptions) -> Initiator {
        client::initiator(target, options)
    }

    /// The first context-creation call: `RPCSEC_GSS_INIT` with the
    /// initiator's first token.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedStep`] after the first call and the GSS
    /// errors of the first token.
    #[inline]
    pub fn start(&mut self, credential: &Credential) -> Result<ProtectedCall, Error> {
        client::start(self, credential)
    }

    /// Process the reply to the outstanding context-creation call: either the
    /// next `RPCSEC_GSS_CONTINUE_INIT` call or the established context.
    ///
    /// # Errors
    ///
    /// Returns the reply errors of [`Self::reply`],
    /// [`Error::ContextCreation`] for a failed server status,
    /// [`Error::UnexpectedVerifier`] or [`Error::BadVerifier`] when the window
    /// is not signed, and [`Error::BadWindow`] for a zero window. A failure
    /// closes the client.
    #[inline]
    pub fn continue_init(
        &mut self,
        credential: &Credential,
        message: &[u8],
    ) -> Result<InitStep, Error> {
        client::continue_init(self, credential, message)
    }

    /// A data call of `procedure` with the XDR-encoded `arguments`, protected
    /// under the context.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConnectionClosed`] after a failure,
    /// [`Error::UnexpectedStep`] before the context is established or while a
    /// call is outstanding, [`Error::SequenceExhausted`] past `MAXSEQ`, and the
    /// GSS errors of protecting it.
    #[inline]
    pub fn call(&mut self, procedure: u32, arguments: &[u8]) -> Result<ProtectedCall, Error> {
        client::call(self, procedure, arguments)
    }

    /// Check the reply to `call` and return its unprotected results.
    ///
    /// # Errors
    ///
    /// Returns [`Error::XidMismatch`], [`Error::AuthenticationRejected`],
    /// [`Error::RpcMismatch`], [`Error::NotAccepted`],
    /// [`Error::UnexpectedVerifier`], [`Error::BadVerifier`],
    /// [`Error::SequenceMismatch`], the GSS errors of the body and the decoding
    /// errors. Every failure closes the client.
    #[inline]
    pub fn reply(
        &mut self,
        call: &ProtectedCall,
        message: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        client::reply(self, call, message)
    }

    /// The `RPCSEC_GSS_DESTROY` call that ends the context; its reply goes to
    /// [`Self::reply`].
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::call`].
    #[inline]
    pub fn destroy_call(&mut self) -> Result<ProtectedCall, Error> {
        client::destroy_call(self)
    }

    /// Whether the context is established and usable.
    #[inline]
    #[must_use]
    pub const fn is_established(&self) -> bool {
        matches!(self.phase, Phase::Established(_))
    }

    /// The sequence window the server granted; 0 before establishment.
    #[inline]
    #[must_use]
    pub const fn window(&self) -> u32 {
        self.window
    }

    /// Stop the client: nothing more is sent.
    #[inline]
    pub fn close(&mut self) {
        self.phase = Phase::Closed;
        self.outstanding = None;
    }
}

/// Frame `message` as one RFC 5531 record (one last fragment, or more for a
/// message above 2 GiB).
#[inline]
#[must_use]
pub fn encode_record(message: &[u8]) -> Zeroizing<Vec<u8>> {
    record::encode(message)
}

/// Reassemble the record at the start of `bytes`: its message and how many
/// bytes it took, or `None` while the last fragment is incomplete.
///
/// # Errors
///
/// Returns [`Error::RecordTooLarge`] for fragments that would pass
/// [`MAX_RECORD_SIZE`], decided from their headers alone, and
/// [`Error::TooManyFragments`] past [`MAX_FRAGMENTS`].
#[inline]
pub fn decode_record(bytes: &[u8]) -> Result<Option<(Zeroizing<Vec<u8>>, usize)>, Error> {
    record::decode(bytes)
}

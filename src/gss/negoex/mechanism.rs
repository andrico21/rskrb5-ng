/// A failure of a `NegoEx` mechanism, with the error token it wants sent.
///
/// MIT's acceptor sends the failing mechanism's error token to the initiator
/// (`negoex_ctx.c:600-606`), so the initiator reports the mechanism's own
/// error; a mechanism hands that token over with [`ProviderFailure::with_output_token`].
/// The text must not hold secrets.
#[derive(Clone, Eq, PartialEq)]
pub struct ProviderFailure {
    /// What failed.
    reason: String,
    /// The error token to send to the peer.
    output_token: Option<Vec<u8>>,
}

impl ProviderFailure {
    /// A failure with no token for the peer.
    #[inline]
    #[must_use]
    pub fn new<R>(reason: R) -> Self
    where
        R: Into<String>,
    {
        Self {
            reason: reason.into(),
            output_token: None,
        }
    }

    /// The same failure, with an error token for the peer.
    #[inline]
    #[must_use]
    pub fn with_output_token(mut self, token: Vec<u8>) -> Self {
        self.output_token = Some(token);
        self
    }

    /// What failed.
    #[inline]
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// The error token for the peer, if any.
    #[inline]
    #[must_use]
    pub fn output_token(&self) -> Option<&[u8]> {
        self.output_token.as_deref()
    }
}

impl fmt::Debug for ProviderFailure {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderFailure")
            .field("reason", &self.reason)
            .field("output_token_len", &self.output_token.as_ref().map(Vec::len))
            .finish()
    }
}

impl fmt::Display for ProviderFailure {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.reason)
    }
}

impl StdError for ProviderFailure {}

/// Which end of the exchange a session plays.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum Role {
    /// The context initiator.
    Initiator,
    /// The context acceptor.
    Acceptor,
}

/// What the application asked for, passed to every mechanism call
/// (MIT passes the target name, flags and channel bindings the same way).
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct Request {
    /// The target name; an initiator only.
    target: Option<Name>,
    /// The requested context flags.
    flags: ContextFlags,
    /// The channel bindings.
    bindings: Option<ChannelBindings>,
}

impl Request {
    /// A request with no target, flags or bindings (an acceptor's).
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The same request for `target`.
    #[inline]
    #[must_use]
    pub fn with_target(mut self, target: Name) -> Self {
        self.target = Some(target);
        self
    }

    /// The same request with context `flags`.
    #[inline]
    #[must_use]
    pub const fn with_flags(mut self, flags: ContextFlags) -> Self {
        self.flags = flags;
        self
    }

    /// The same request with channel `bindings`.
    #[inline]
    #[must_use]
    pub fn with_bindings(mut self, bindings: ChannelBindings) -> Self {
        self.bindings = Some(bindings);
        self
    }

    /// The target name.
    #[inline]
    #[must_use]
    pub const fn target(&self) -> Option<&Name> {
        self.target.as_ref()
    }

    /// The requested context flags.
    #[inline]
    #[must_use]
    pub const fn flags(&self) -> ContextFlags {
        self.flags
    }

    /// The channel bindings.
    #[inline]
    #[must_use]
    pub const fn bindings(&self) -> Option<&ChannelBindings> {
        self.bindings.as_ref()
    }
}

/// The result of one `init_sec_context` or `accept_sec_context` step of a mechanism.
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub struct MechanismStep {
    /// The token for the peer, if any.
    output: Option<Vec<u8>>,
    /// Whether the mechanism's context is established.
    complete: bool,
}

impl fmt::Debug for MechanismStep {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MechanismStep")
            .field("output_len", &self.output.as_ref().map(Vec::len))
            .field("complete", &self.complete)
            .finish()
    }
}

impl MechanismStep {
    /// The mechanism needs the peer's answer (`GSS_S_CONTINUE_NEEDED`).
    #[inline]
    #[must_use]
    pub const fn continue_needed(output: Option<Vec<u8>>) -> Self {
        Self {
            output,
            complete: false,
        }
    }

    /// The mechanism's context is established (`GSS_S_COMPLETE`).
    #[inline]
    #[must_use]
    pub const fn complete(output: Option<Vec<u8>>) -> Self {
        Self {
            output,
            complete: true,
        }
    }

    /// The token for the peer, if any.
    #[inline]
    #[must_use]
    pub fn output(&self) -> Option<&[u8]> {
        self.output.as_deref()
    }

    /// Whether the mechanism's context is established.
    #[inline]
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.complete
    }
}

/// One negotiation of a mechanism.
///
/// The methods are the `gssspi_*` meta-data calls, the context steps and the
/// `GSS_C_INQ_NEGOEX_KEY` and `GSS_C_INQ_NEGOEX_VERIFY_KEY` inquiries of MIT's
/// mechanism interface (`g_negoex.c`; draft-zhu-negoex-04).
pub trait Session: Send {
    /// `gssspi_query_meta_data`: the meta-data to offer, empty for none.
    ///
    /// # Errors
    ///
    /// A failure removes the mechanism from the negotiation.
    fn query_meta_data(&mut self, request: &Request) -> Result<Vec<u8>, ProviderFailure>;

    /// `gssspi_exchange_meta_data`: the peer's meta-data.
    ///
    /// # Errors
    ///
    /// A failure removes the mechanism from the negotiation.
    fn exchange_meta_data(
        &mut self,
        request: &Request,
        metadata: &[u8],
    ) -> Result<(), ProviderFailure>;

    /// `gss_init_sec_context`: one initiator step.
    ///
    /// # Errors
    ///
    /// A failure removes the mechanism from a negotiation that can still fall back.
    fn init_sec_context(
        &mut self,
        request: &Request,
        input: Option<&[u8]>,
    ) -> Result<MechanismStep, ProviderFailure>;

    /// `gss_accept_sec_context`: one acceptor step.
    ///
    /// # Errors
    ///
    /// A failure carrying an output token is told to the peer.
    fn accept_sec_context(
        &mut self,
        request: &Request,
        input: &[u8],
    ) -> Result<MechanismStep, ProviderFailure>;

    /// The key the `VERIFY` message this side sends is made with, once the
    /// mechanism has one (`GSS_C_INQ_NEGOEX_KEY`).
    fn checksum_key(&self) -> Option<EncryptionKey>;

    /// The key the peer's `VERIFY` message is checked with, once the mechanism
    /// has one (`GSS_C_INQ_NEGOEX_VERIFY_KEY`).
    fn verify_key(&self) -> Option<EncryptionKey>;

    /// The flags of the established context (`ret_flags`); none by default.
    ///
    /// `GSS_C_INTEG_FLAG` makes SPNEGO exchange a `mechListMIC` when it is required.
    #[inline]
    fn context_flags(&self) -> ContextFlags {
        ContextFlags::default()
    }
}

/// A mechanism that `NegoEx` can negotiate (the `gssspi_query_mechanism_info` side).
///
/// A mechanism is offered only when its object identifier is also registered as
/// an [`extensions::GssMechanism`](crate::extensions::GssMechanism).
pub trait Mechanism: Send + Sync {
    /// The DER content octets of the mechanism's object identifier.
    fn oid(&self) -> &[u8];

    /// The authentication scheme GUID (`gssspi_query_mechanism_info`).
    fn auth_scheme(&self) -> AuthScheme;

    /// A session for one negotiation as `role`.
    fn session(&self, role: Role) -> Box<dyn Session>;
}

/// One mechanism of a negotiation as the context sees it.
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub struct MechanismMetadata {
    /// The mechanism's object identifier.
    oid: ObjectIdentifier,
    /// Its authentication scheme.
    scheme: AuthScheme,
    /// The meta-data it offered, empty for none.
    metadata: Vec<u8>,
}

impl fmt::Debug for MechanismMetadata {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MechanismMetadata")
            .field("oid", &self.oid)
            .field("scheme", &self.scheme)
            .field("metadata_len", &self.metadata.len())
            .finish()
    }
}

impl MechanismMetadata {
    /// The mechanism's object identifier.
    #[inline]
    #[must_use]
    pub const fn oid(&self) -> &ObjectIdentifier {
        &self.oid
    }

    /// The mechanism's authentication scheme.
    #[inline]
    #[must_use]
    pub const fn scheme(&self) -> AuthScheme {
        self.scheme
    }

    /// The meta-data the mechanism offered, empty for none.
    #[inline]
    #[must_use]
    pub fn metadata(&self) -> &[u8] {
        &self.metadata
    }
}

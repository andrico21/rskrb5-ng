/// How an [`Initiator`] starts its context.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct InitiatorOptions {
    /// The requested context flags.
    flags: ContextFlags,
    /// The channel bindings to send.
    bindings: Option<ChannelBindings>,
    /// `client_aware_channel_bindings`: assert MS-KILE `KERB_AP_OPTIONS_CBT`.
    client_aware_channel_bindings: bool,
    /// `enforce_ok_as_delegate`: delegate only to `OK-AS-DELEGATE` services.
    enforce_ok_as_delegate: bool,
    /// The runtime enctype policy.
    crypto_policy: CryptoPolicy,
}

impl Default for InitiatorOptions {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl InitiatorOptions {
    /// Mutual authentication, replay detection, sequencing, confidentiality
    /// and integrity, no channel bindings, the secure default enctype policy.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self {
            flags: ContextFlags::MUTUAL
                | ContextFlags::REPLAY
                | ContextFlags::SEQUENCE
                | ContextFlags::CONF
                | ContextFlags::INTEG,
            bindings: None,
            client_aware_channel_bindings: false,
            enforce_ok_as_delegate: false,
            crypto_policy: CryptoPolicy::default(),
        }
    }

    /// The defaults with the `[libdefaults]` relations
    /// `client_aware_channel_bindings` and `enforce_ok_as_delegate` of `config`.
    #[inline]
    #[must_use]
    pub fn from_config(config: &Config) -> Self {
        let defaults = &config.libdefaults;
        Self::new()
            .with_client_aware_channel_bindings(defaults.client_aware_channel_bindings.is_enabled())
            .with_enforce_ok_as_delegate(defaults.enforce_ok_as_delegate.is_enabled())
    }

    /// Request `flags`. Confidentiality and integrity are always offered, as
    /// MIT's initiator adds them (`init_sec_context.c:546-553`).
    #[inline]
    #[must_use]
    pub const fn with_flags(mut self, flags: ContextFlags) -> Self {
        self.flags = flags;
        self
    }

    /// The requested flags.
    #[inline]
    #[must_use]
    pub const fn flags(&self) -> ContextFlags {
        self.flags
    }

    /// Send `bindings`.
    #[inline]
    #[must_use]
    pub fn with_channel_bindings(mut self, bindings: ChannelBindings) -> Self {
        self.bindings = Some(bindings);
        self
    }

    /// Assert MS-KILE `KERB_AP_OPTIONS_CBT`, which makes an acceptor that has
    /// channel bindings refuse a token without matching ones.
    #[inline]
    #[must_use]
    pub const fn with_client_aware_channel_bindings(mut self, aware: bool) -> Self {
        self.client_aware_channel_bindings = aware;
        self
    }

    /// Whether `KERB_AP_OPTIONS_CBT` is asserted.
    #[inline]
    #[must_use]
    pub const fn client_aware_channel_bindings(&self) -> bool {
        self.client_aware_channel_bindings
    }

    /// Treat a delegation request as a delegation-policy request
    /// (MIT `init_sec_context.c:537-541`).
    #[inline]
    #[must_use]
    pub const fn with_enforce_ok_as_delegate(mut self, enforce: bool) -> Self {
        self.enforce_ok_as_delegate = enforce;
        self
    }

    /// Whether delegation needs `OK-AS-DELEGATE`.
    #[inline]
    #[must_use]
    pub const fn enforce_ok_as_delegate(&self) -> bool {
        self.enforce_ok_as_delegate
    }

    /// Use `policy` for the context's keys.
    #[inline]
    #[must_use]
    pub fn with_crypto_policy(mut self, policy: CryptoPolicy) -> Self {
        self.crypto_policy = policy;
        self
    }
}

/// The outcome of an [`Initiator::init_sec_context`] step.
#[derive(Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum InitStep {
    /// Send this token and pass the acceptor's reply to the next step
    /// (`GSS_S_CONTINUE_NEEDED`).
    Continue(Vec<u8>),
    /// The context is established; send this token, if any
    /// (`GSS_S_COMPLETE`); [`Initiator::into_established`] yields it.
    Complete(Option<Vec<u8>>),
}

/// Where an [`Initiator`] is.
enum InitState {
    /// No token sent yet.
    Start,
    /// The AP-REQ is sent; the AP-REP is awaited.
    AwaitingReply(Box<initiator::Pending>),
    /// The context is established.
    Established(Box<EstablishedContext>),
    /// A step failed or the context was taken.
    Finished,
}

/// The initiator of one Kerberos security context (`gss_init_sec_context`).
#[non_exhaustive]
pub struct Initiator {
    /// The target.
    target: Name,
    /// The options.
    options: InitiatorOptions,
    /// The state.
    state: InitState,
}

impl fmt::Debug for Initiator {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = match &self.state {
            InitState::Start => "start",
            InitState::AwaitingReply(_) => "awaiting reply",
            InitState::Established(_) => "established",
            InitState::Finished => "finished",
        };
        f.debug_struct("Initiator")
            .field("target", &self.target)
            .field("options", &self.options)
            .field("state", &state)
            .finish()
    }
}

impl Initiator {
    /// An initiator for `target`.
    #[inline]
    #[must_use]
    pub const fn new(target: Name, options: InitiatorOptions) -> Self {
        Self {
            target,
            options,
            state: InitState::Start,
        }
    }

    /// One step of the context establishment.
    ///
    /// The first call (no input) builds the AP-REQ token from a service ticket
    /// of `credential`; with mutual authentication, the second verifies the
    /// acceptor's AP-REP.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedStep`] out of order,
    /// [`Error::WrongCredentialUsage`] for an acceptor credential,
    /// [`Error::BadName`] for a target without a host, [`Error::NoCredential`]
    /// without a live ticket for the target, [`Error::NotNegotiated`] for a
    /// DCE-style request, and the token, AP-REQ, AP-REP and policy errors.
    /// A failed step ends the context.
    #[inline]
    pub fn init_sec_context(
        &mut self,
        credential: &Credential,
        input_token: Option<&[u8]>,
    ) -> Result<InitStep, Error> {
        initiator::step(self, credential, input_token)
    }

    /// Whether the context is established.
    #[inline]
    #[must_use]
    pub const fn is_established(&self) -> bool {
        matches!(self.state, InitState::Established(_))
    }

    /// The established context, for the negotiation layered on this one.
    pub(crate) fn established_mut(&mut self) -> Option<&mut EstablishedContext> {
        match &mut self.state {
            InitState::Established(context) => Some(context),
            InitState::Start | InitState::AwaitingReply(_) | InitState::Finished => None,
        }
    }

    /// The established context.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedStep`] before the context is established.
    #[inline]
    pub fn into_established(self) -> Result<EstablishedContext, Error> {
        match self.state {
            InitState::Established(context) => Ok(*context),
            InitState::Start | InitState::AwaitingReply(_) | InitState::Finished => {
                Err(Error::UnexpectedStep("the context is not established"))
            }
        }
    }
}

/// How an [`Acceptor`] accepts contexts.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct AcceptorOptions {
    /// The acceptor's channel bindings.
    bindings: Option<ChannelBindings>,
    /// Whether a context must be channel-bound.
    require_bindings: bool,
    /// `ignore_acceptor_hostname`: a named host-based acceptor takes any host.
    ignore_acceptor_hostname: bool,
}

impl AcceptorOptions {
    /// No channel bindings, the acceptor name matched exactly.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The defaults with the `[libdefaults]` relation `ignore_acceptor_hostname`
    /// of `config`.
    #[inline]
    #[must_use]
    pub fn from_config(config: &Config) -> Self {
        Self::new()
            .with_ignore_acceptor_hostname(config.libdefaults.ignore_acceptor_hostname.is_enabled())
    }

    /// Hold `bindings`: a token with other non-zero bindings is refused, a
    /// token with the same ones yields a channel-bound context.
    #[inline]
    #[must_use]
    pub fn with_channel_bindings(mut self, bindings: ChannelBindings) -> Self {
        self.bindings = Some(bindings);
        self
    }

    /// Refuse every context that is not channel-bound, a token without
    /// bindings (a zero digest) included.
    #[inline]
    #[must_use]
    pub const fn require_channel_bindings(mut self, required: bool) -> Self {
        self.require_bindings = required;
        self
    }

    /// Let a named host-based acceptor accept a ticket for any host of its
    /// service (MIT `krb5_sname_match`, `sname_match.c:51-54`).
    ///
    /// # Security
    ///
    /// The acceptor then answers for every host whose key its keytab holds.
    #[inline]
    #[must_use]
    pub const fn with_ignore_acceptor_hostname(mut self, ignore: bool) -> Self {
        self.ignore_acceptor_hostname = ignore;
        self
    }

    /// Whether the host of a named acceptor is ignored.
    #[inline]
    #[must_use]
    pub const fn ignore_acceptor_hostname(&self) -> bool {
        self.ignore_acceptor_hostname
    }
}

/// The acceptor of Kerberos security contexts (`gss_accept_sec_context`):
/// one keytab-backed validator, so one replay cache, for every context.
#[non_exhaustive]
pub struct Acceptor<'keytab> {
    /// The AP-REQ validator.
    validator: Validator<'keytab>,
    /// The options.
    options: AcceptorOptions,
}

impl fmt::Debug for Acceptor<'_> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Acceptor")
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

impl<'keytab> Acceptor<'keytab> {
    /// An acceptor of `credential`'s keys, named when the credential is.
    ///
    /// # Errors
    ///
    /// Returns [`Error::WrongCredentialUsage`] for a credential without keys,
    /// and the replay-cache errors of attaching its replay cache.
    #[inline]
    pub fn new(credential: &'keytab Credential, options: AcceptorOptions) -> Result<Self, Error> {
        acceptor::new(credential, options)
    }

    /// An acceptor around a configured validator: its keytab, clock, replay
    /// cache, PAC and transit policies.
    #[inline]
    #[must_use]
    pub const fn from_validator(validator: Validator<'keytab>, options: AcceptorOptions) -> Self {
        Self { validator, options }
    }

    /// Accept the initiator's first token.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TokenTooLarge`] above 256 KiB, the token errors for a
    /// token that is not a krb5 AP-REQ, the AP-REQ validation errors (a replay
    /// and a ticket for another acceptor name included),
    /// [`Error::DefectiveChecksum`] for a malformed authenticator checksum,
    /// [`Error::BadBindings`] for mismatched bindings or a CBT-asserting
    /// initiator without them, [`Error::MissingBindings`] when bindings are
    /// required and absent, and [`Error::DelegatedCredential`] for a delegated
    /// credential that does not decrypt.
    #[inline]
    pub fn accept_sec_context(&mut self, input_token: &[u8]) -> Result<Accepted, Error> {
        acceptor::accept(self, input_token)
    }
}

/// A context the [`Acceptor`] established, and the token to answer with.
#[non_exhaustive]
pub struct Accepted {
    /// The established context.
    context: EstablishedContext,
    /// The AP-REP token, under mutual authentication.
    output_token: Option<Vec<u8>>,
}

impl fmt::Debug for Accepted {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Accepted")
            .field("context", &self.context)
            .field("output_token_len", &self.output_token.as_ref().map(Vec::len))
            .finish()
    }
}

impl Accepted {
    /// The established context.
    #[inline]
    #[must_use]
    pub const fn context(&self) -> &EstablishedContext {
        &self.context
    }

    /// The token to send back: the AP-REP under mutual authentication.
    #[inline]
    #[must_use]
    pub fn output_token(&self) -> Option<&[u8]> {
        self.output_token.as_deref()
    }

    /// The established context.
    #[inline]
    #[must_use]
    pub fn into_context(self) -> EstablishedContext {
        self.context
    }

    /// The established context, for the negotiation layered on this one.
    pub(crate) const fn context_mut(&mut self) -> &mut EstablishedContext {
        &mut self.context
    }

    /// Whether the context is established: false only for a DCE-style
    /// acceptor waiting for the initiator's AP-REP.
    #[inline]
    #[must_use]
    pub const fn is_established(&self) -> bool {
        self.context.open
    }

    /// The third leg of a DCE-style context: verify the initiator's AP-REP
    /// and open the context (MIT `kg_accept_dce`, `accept_sec_context.c:283-360`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedStep`] for a context that is not waiting for
    /// it, [`Error::DefectiveToken`] for an AP-REP that carries a subkey or
    /// does not echo the acceptor's sequence number, and the AP-REP decoding,
    /// decryption and policy errors. A failed third leg leaves the context
    /// unestablished.
    #[inline]
    pub fn complete_dce(&mut self, token: &[u8]) -> Result<(), Error> {
        dce::complete(self, token)
    }

    /// The same context answered with `token` instead, for the negotiation
    /// layered on this one.
    pub(crate) fn with_output_token(mut self, token: Option<Vec<u8>>) -> Self {
        self.output_token = token;
        self
    }
}

/// An established Kerberos security context.
///
/// It holds the names, flags, keys and sequence state, and protects and
/// verifies per-message tokens (RFC 4121 section 4.2).
///
/// The context key is the acceptor subkey when the acceptor sent one, else the
/// initiator subkey, else the ticket session key. Keys and the delegated
/// credential are erased when the context is dropped and never shown by `Debug`.
#[non_exhaustive]
pub struct EstablishedContext {
    /// Whether this end started the context.
    initiated: bool,
    /// The initiator.
    source: Name,
    /// The acceptor.
    target: Name,
    /// The negotiated flags.
    flags: ContextFlags,
    /// The ticket session key.
    session_key: EncryptionKey,
    /// The initiator's subkey.
    initiator_subkey: Option<EncryptionKey>,
    /// The acceptor's subkey.
    acceptor_subkey: Option<EncryptionKey>,
    /// The next sequence number to send.
    send_sequence: u64,
    /// The window of received sequence numbers.
    window: seq::Window,
    /// When the ticket, and so the context, expires.
    expires: SystemTime,
    /// The runtime enctype policy.
    crypto_policy: CryptoPolicy,
    /// The credential the initiator delegated.
    delegated: Option<Box<Credential>>,
    /// The ticket's verified PAC, on the acceptor.
    pac: Option<pac::Verified>,
    /// Whether the context is established; a DCE-style acceptor opens on the
    /// initiator's AP-REP.
    open: bool,
}

impl fmt::Debug for EstablishedContext {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EstablishedContext")
            .field("initiated", &self.initiated)
            .field("source", &self.source)
            .field("target", &self.target)
            .field("flags", &self.flags)
            .field("key_etype", &self.session_key.etype())
            .field("send_sequence", &self.send_sequence)
            .field("expires", &self.expires)
            .field("delegated", &self.delegated.is_some())
            .finish_non_exhaustive()
    }
}

impl EstablishedContext {
    /// `gss_inquire_context`: names, lifetime, mechanism, flags and roles.
    #[inline]
    #[must_use]
    pub fn inquire(&self) -> ContextInquiry {
        context::inquire(self)
    }

    /// `gss_get_mic`: a MIC token over `message`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ContextExpired`] after the ticket expired,
    /// [`Error::LegacyTokenFormat`] for a DES3 or RC4 context, and the
    /// checksum errors.
    #[inline]
    pub fn get_mic(&mut self, message: &[u8]) -> Result<Vec<u8>, Error> {
        context::get_mic(self, message)
    }

    /// `gss_verify_mic`: verify `token` over `message` and admit its sequence
    /// number.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::get_mic`], the token errors for a token
    /// from this end or with the wrong key flag, the checksum errors, and the
    /// window errors ([`Error::DuplicateToken`], [`Error::OldToken`],
    /// [`Error::UnsequencedToken`], [`Error::GapToken`]).
    #[inline]
    pub fn verify_mic(&mut self, message: &[u8], token: &[u8]) -> Result<(), Error> {
        context::verify_mic(self, message, token)
    }

    /// `gss_wrap`: a Wrap token of `message`, sealed when `confidential`.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::get_mic`] and the encryption errors.
    #[inline]
    pub fn wrap(&mut self, message: &[u8], confidential: bool) -> Result<Vec<u8>, Error> {
        context::wrap(self, message, confidential)
    }

    /// `gss_unwrap`: verify or decrypt `token` and admit its sequence number.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::verify_mic`] and the decryption errors.
    #[inline]
    pub fn unwrap(&mut self, token: &[u8]) -> Result<Unwrapped, Error> {
        context::unwrap(self, token)
    }

    /// `gss_wrap_iov`: seal or sign `buffers` in place.
    ///
    /// The array needs one HEADER buffer; a TRAILER buffer receives the
    /// trailer, otherwise the trailer is rotated into the header (RFC 4121
    /// RRC); PADDING is emptied, as RFC 4121 tokens have none; DATA buffers
    /// are sealed when `confidential` and `SIGN_ONLY` buffers are only covered
    /// by the integrity tag. Returns whether the token is sealed: an array
    /// without DATA buffers is only signed (MIT `kg_integ_only_iov`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::BadIov`] for a missing header, a duplicated framing
    /// buffer, a STREAM or MIC buffer or more than 64 buffers,
    /// [`Error::NotNegotiated`] for `SIGN_ONLY` data in a sealed Camellia
    /// token, and the errors of [`Self::wrap`].
    #[inline]
    pub fn wrap_iov(&mut self, buffers: &mut [IovBuffer], confidential: bool) -> Result<bool, Error> {
        iov::wrap(self, buffers, confidential)
    }

    /// `gss_wrap_iov_length`: size the HEADER, TRAILER and PADDING buffers as
    /// [`Self::wrap_iov`] fills them, with zero bytes.
    ///
    /// # Errors
    ///
    /// Returns the layout and context errors of [`Self::wrap_iov`].
    #[inline]
    pub fn wrap_iov_length(&self, buffers: &mut [IovBuffer], confidential: bool) -> Result<bool, Error> {
        iov::wrap_length(self, buffers, confidential)
    }

    /// `gss_unwrap_iov`: verify and open `buffers` in place and admit the
    /// token's sequence number; returns whether the token was sealed.
    ///
    /// The array holds the HEADER, DATA, `SIGN_ONLY` and TRAILER buffers as
    /// [`Self::wrap_iov`] produced them, or one STREAM buffer with a whole
    /// token, the `SIGN_ONLY` buffers and exactly one DATA buffer that receives
    /// the message. A refused token leaves the buffers and the window as they
    /// were.
    ///
    /// # Security
    ///
    /// Every buffer is attacker-controlled: lengths, rotation counts and the
    /// sealed header copy are checked, and the tag is verified in constant
    /// time before the sequence window moves.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BadIov`] for a bad layout or framing length,
    /// [`Error::DefectiveToken`] for a malformed header, rotation or header
    /// copy, [`Error::BadSignature`] when the tag does not verify,
    /// [`Error::TokenTooLarge`] above 16 MiB, and the window errors of
    /// [`Self::verify_mic`].
    #[inline]
    pub fn unwrap_iov(&mut self, buffers: &mut [IovBuffer]) -> Result<bool, Error> {
        iov::unwrap(self, buffers)
    }

    /// `gss_get_mic_iov`: a MIC over the DATA and `SIGN_ONLY` buffers in array
    /// order, into the `MIC_TOKEN` buffer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BadIov`] without exactly one `MIC_TOKEN` buffer, and the
    /// errors of [`Self::get_mic`].
    #[inline]
    pub fn get_mic_iov(&mut self, buffers: &mut [IovBuffer]) -> Result<(), Error> {
        iov::get_mic(self, buffers)
    }

    /// `gss_verify_mic_iov`: verify the `MIC_TOKEN` buffer over the DATA and
    /// `SIGN_ONLY` buffers and admit its sequence number.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BadIov`] without exactly one `MIC_TOKEN` buffer or for
    /// one of the wrong length, [`Error::BadSignature`] when it does not
    /// verify, and the errors of [`Self::verify_mic`].
    #[inline]
    pub fn verify_mic_iov(&mut self, buffers: &[IovBuffer]) -> Result<(), Error> {
        iov::verify_mic(self, buffers)
    }

    /// `gss_wrap_aead`: a Wrap token of `message` whose tag also covers
    /// `associated`, which is not sent.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::wrap_iov`].
    #[inline]
    pub fn wrap_aead(
        &mut self,
        associated: &[u8],
        message: &[u8],
        confidential: bool,
    ) -> Result<Vec<u8>, Error> {
        iov::wrap_aead(self, associated, message, confidential)
    }

    /// `gss_unwrap_aead`: open a token of [`Self::wrap_aead`] with the same
    /// associated data.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::unwrap_iov`]; a DCE-style context has no
    /// STREAM unwrapping (MIT `k5unsealiov.c:381-384`).
    #[inline]
    pub fn unwrap_aead(&mut self, token: &[u8], associated: &[u8]) -> Result<Unwrapped, Error> {
        iov::unwrap_aead(self, token, associated)
    }

    /// `gss_pseudo_random`: `length` bytes of RFC 4402 `PRF+` over `input`
    /// and the context key `key` selects.
    ///
    /// # Security
    ///
    /// The output is as secret as the key and is erased when dropped.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedStep`] before the context is established,
    /// the policy error of the key, and [`Error::Crypto`] above the 1 MiB
    /// `PRF+` bound.
    #[inline]
    pub fn pseudo_random(
        &self,
        key: PrfKey,
        input: &[u8],
        length: usize,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        prf::pseudo_random(self, key, input, length)
    }

    /// `gss_export_sec_context` under the transfer contract: consume the
    /// context and seal it under `key`.
    ///
    /// The blob holds the names, flags, keys, sequence window, expiry,
    /// delegated credential and verified PAC; the importer applies the default
    /// enctype policy, so a DES3 or RC4 context needs its policy again.
    ///
    /// # Security
    ///
    /// There is no unprotected export: the keys only leave the process sealed
    /// under `key`, and the sending end cannot use the context afterwards.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotNegotiated`] for a delegated credential with an
    /// in-memory replay cache, and the serialization, random-source and
    /// encryption errors.
    #[inline]
    pub fn export(self, key: &TransferKey) -> Result<TransferBlob, Error> {
        export::export_context(self, key)
    }

    /// `gss_import_sec_context` under the transfer contract.
    ///
    /// # Security
    ///
    /// The transfer id is consumed in `ledger` only after the blob
    /// authenticates; duplicate-use protection holds within that ledger's
    /// scope only (see [`TransferLedger`]).
    ///
    /// # Errors
    ///
    /// Returns [`Error::TokenTooLarge`] above 1 MiB, [`Error::TransferRejected`]
    /// for a tampered blob, another key, version or kind, and
    /// [`Error::TransferReplayed`] for a transfer id `ledger` has consumed.
    #[inline]
    pub fn import(
        blob: &TransferBlob,
        key: &TransferKey,
        ledger: &mut dyn TransferLedger,
    ) -> Result<Self, Error> {
        export::import_context(blob, key, ledger)
    }

    /// The credential the initiator delegated, on the acceptor.
    #[inline]
    #[must_use]
    pub fn delegated_credential(&self) -> Option<&Credential> {
        self.delegated.as_deref()
    }

    /// Take the delegated credential.
    #[inline]
    pub fn take_delegated_credential(&mut self) -> Option<Credential> {
        self.delegated.take().map(|credential| *credential)
    }

    /// The ticket's verified PAC, on the acceptor.
    #[inline]
    #[must_use]
    pub const fn pac(&self) -> Option<&pac::Verified> {
        self.pac.as_ref()
    }

    /// The context key (`GSS_C_INQ_SSPI_SESSION_KEY`); it must not outlive the
    /// context.
    #[inline]
    #[must_use]
    pub fn session_key(&self) -> &EncryptionKey {
        context::key(self)
    }

    /// `gss_context_time`: how long the context lives, zero once expired.
    #[inline]
    #[must_use]
    pub fn context_time(&self) -> Duration {
        self.expires
            .duration_since(SystemTime::now())
            .unwrap_or(Duration::ZERO)
    }
}

/// What `gss_inquire_context` reports about an [`EstablishedContext`].
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ContextInquiry {
    /// The initiator.
    source: Name,
    /// The acceptor.
    target: Name,
    /// When the context expires.
    expires: SystemTime,
    /// The mechanism.
    mechanism: ObjectIdentifier,
    /// The negotiated flags.
    flags: ContextFlags,
    /// Whether this end started the context.
    locally_initiated: bool,
    /// Whether the context is established.
    open: bool,
    /// The context key's enctype.
    key_etype: i32,
    /// The security strength factor of the context key.
    ssf: u32,
}

impl ContextInquiry {
    /// The initiator.
    #[inline]
    #[must_use]
    pub const fn source(&self) -> &Name {
        &self.source
    }

    /// The acceptor.
    #[inline]
    #[must_use]
    pub const fn target(&self) -> &Name {
        &self.target
    }

    /// When the context expires.
    #[inline]
    #[must_use]
    pub const fn expires(&self) -> SystemTime {
        self.expires
    }

    /// The mechanism: krb5.
    #[inline]
    #[must_use]
    pub const fn mechanism(&self) -> &ObjectIdentifier {
        &self.mechanism
    }

    /// The negotiated flags.
    #[inline]
    #[must_use]
    pub const fn flags(&self) -> ContextFlags {
        self.flags
    }

    /// Whether this end started the context.
    #[inline]
    #[must_use]
    pub const fn locally_initiated(&self) -> bool {
        self.locally_initiated
    }

    /// Whether the context is established (`GSS_C_ESTABLISHED` of
    /// `gss_inquire_context`).
    #[inline]
    #[must_use]
    pub const fn open(&self) -> bool {
        self.open
    }

    /// The context key's enctype (`GSS_C_INQ_SSPI_SESSION_KEY`'s type).
    #[inline]
    #[must_use]
    pub const fn key_etype(&self) -> i32 {
        self.key_etype
    }

    /// The SASL security strength factor of the context key
    /// (`GSS_C_SEC_CONTEXT_SASL_SSF`; MIT's enctype strengths: 256 for the
    /// 256-bit AES and Camellia keys, 128 for the 128-bit ones, 112 for DES3,
    /// 64 for RC4-HMAC).
    #[inline]
    #[must_use]
    pub const fn ssf(&self) -> u32 {
        self.ssf
    }
}

/// The message of an unwrapped token, erased when dropped.
#[non_exhaustive]
pub struct Unwrapped {
    /// The message.
    message: Zeroizing<Vec<u8>>,
    /// Whether the token was sealed.
    confidential: bool,
}

impl fmt::Debug for Unwrapped {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Unwrapped")
            .field("message_len", &self.message.len())
            .field("confidential", &self.confidential)
            .finish()
    }
}

impl Unwrapped {
    /// The message.
    #[inline]
    #[must_use]
    pub fn message(&self) -> &[u8] {
        &self.message
    }

    /// Whether the token was sealed.
    #[inline]
    #[must_use]
    pub const fn confidential(&self) -> bool {
        self.confidential
    }
}

/// A caller-supplied 256-bit key that seals and opens [`TransferBlob`]s.
///
/// It is the protocol key of the RFC 8009 `aes256-cts-hmac-sha384-192`
/// profile; the exporting and the importing process must hold the same key.
/// The key is erased when dropped and never shown by `Debug`.
#[non_exhaustive]
pub struct TransferKey {
    /// The key bytes.
    bytes: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for TransferKey {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransferKey").finish_non_exhaustive()
    }
}

impl TransferKey {
    /// The key `bytes`.
    #[inline]
    #[must_use]
    pub fn new(bytes: [u8; 32]) -> Self {
        Self {
            bytes: Zeroizing::new(bytes),
        }
    }

    /// A random key from the system random source.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Random`] when the random source fails.
    #[inline]
    pub fn generate() -> Result<Self, Error> {
        let mut bytes = Zeroizing::new([0; 32]);
        getrandom::fill(bytes.as_mut_slice())?;
        Ok(Self { bytes })
    }

    /// The key bytes.
    pub(crate) fn bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

/// An exported security context or credential: versioned, encrypted and
/// authenticated under a [`TransferKey`] (format: `src/gss/export.rs`).
///
/// It carries a random transfer id and the export time in its authenticated
/// header; it holds ciphertext only, so its bytes may be stored or sent, but
/// whoever holds the key and the blob holds the context.
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub struct TransferBlob {
    /// The header and the ciphertext.
    bytes: Vec<u8>,
}

impl fmt::Debug for TransferBlob {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransferBlob")
            .field("len", &self.bytes.len())
            .finish()
    }
}

impl TransferBlob {
    /// A blob received as `bytes`; it is checked when it is imported.
    #[inline]
    #[must_use]
    pub const fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// The blob's bytes.
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The blob's bytes.
    #[inline]
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// The record of the transfer ids an importer has consumed.
///
/// An import authenticates the blob first and then asks the ledger to consume
/// its transfer id; a ledger that answers `false` makes the import fail with
/// [`Error::TransferReplayed`].
///
/// # Security
///
/// Duplicate-use protection holds only within one ledger's scope: a copy of a
/// blob imported through a separate ledger is accepted. Processes that may
/// import the same blob must share a ledger (a persistent or networked
/// implementation of this trait); replay across separate ledgers is out of
/// scope.
pub trait TransferLedger {
    /// Record `id`, exported at `exported`, as consumed; `Ok(false)` when it
    /// already was.
    ///
    /// # Errors
    ///
    /// Returns an error when the ledger cannot record the id; the import then
    /// fails closed.
    fn consume(&mut self, id: [u8; 16], exported: SystemTime) -> Result<bool, Error>;
}

/// An in-memory [`TransferLedger`] of at most 65,536 transfer ids.
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct MemoryTransferLedger {
    /// The consumed ids.
    consumed: HashSet<[u8; 16]>,
}

impl MemoryTransferLedger {
    /// The most transfer ids one ledger records.
    pub const CAPACITY: usize = 0x1_0000;

    /// An empty ledger.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl TransferLedger for MemoryTransferLedger {
    /// # Errors
    ///
    /// Returns [`Error::TransferLedgerFull`] once [`Self::CAPACITY`] ids are
    /// recorded: the ledger never forgets an id.
    #[inline]
    fn consume(&mut self, id: [u8; 16], _exported: SystemTime) -> Result<bool, Error> {
        if self.consumed.contains(&id) {
            return Ok(false);
        }
        if self.consumed.len() >= Self::CAPACITY {
            return Err(Error::TransferLedgerFull);
        }
        Ok(self.consumed.insert(id))
    }
}

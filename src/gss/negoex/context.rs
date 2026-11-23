/// The key usage of the `VERIFY` message of an acceptor, which MIT's initiator
/// signs with: the specification has the two usages the other way round
/// (`negoex_ctx.c:333-337`, `gssapiP_negoex.h:57-58`).
const KEYUSAGE_ACCEPTOR_CHECKSUM: u32 = 25;
/// The key usage of an initiator's `VERIFY` message.
const KEYUSAGE_INITIATOR_CHECKSUM: u32 = 23;

/// The source of the conversation id and the nonces.
///
/// The default is the system random source; a fixed one makes tokens
/// reproducible for tests and captures and must not be used otherwise.
pub trait RandomSource: Send + Sync {
    /// Fill `bytes` with random bytes.
    ///
    /// # Errors
    ///
    /// Returns the random source's failure.
    fn fill(&self, bytes: &mut [u8]) -> Result<(), getrandom::Error>;
}

/// The system random source.
struct SystemRandom;

impl RandomSource for SystemRandom {
    #[inline]
    fn fill(&self, bytes: &mut [u8]) -> Result<(), getrandom::Error> {
        getrandom::fill(bytes)
    }
}

/// The result of one [`Context::step`].
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub struct Step {
    /// The token for the peer, if any.
    token: Option<Vec<u8>>,
    /// Whether the mechanism is established and the peer's `VERIFY` message verified.
    complete: bool,
}

impl fmt::Debug for Step {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Step")
            .field("token_len", &self.token.as_ref().map(Vec::len))
            .field("complete", &self.complete)
            .finish()
    }
}

impl Step {
    /// The token for the peer, if any.
    #[inline]
    #[must_use]
    pub fn token(&self) -> Option<&[u8]> {
        self.token.as_deref()
    }

    /// The token for the peer, taken out of the step.
    #[inline]
    #[must_use]
    pub fn into_token(self) -> Option<Vec<u8>> {
        self.token
    }

    /// Whether the negotiation is complete (`GSS_S_COMPLETE`).
    #[inline]
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.complete
    }
}

/// The result of an acceptor's mechanism step.
struct AcceptOutcome {
    /// The token for the initiator.
    output: Option<Vec<u8>>,
    /// Whether the step ended without a mechanism failure.
    succeeded: bool,
}

/// A `NegoEx` negotiation (MIT `negoex_init` and `negoex_accept`).
///
/// An initiator's first [`Context::step`] takes no token and returns the
/// `INITIATOR_NEGO`, the meta-data and, when the first mechanism makes one, an
/// optimistic `AP_REQUEST`; each later step takes the acceptor's token. An
/// acceptor takes the initiator's token. Every step but the last returns a token
/// for the peer; the negotiation is complete when [`Step::is_complete`].
///
/// A step that fails leaves the context unusable.
///
/// # Security
///
/// - Only the mechanisms the application names are offered, each registered
///   as a [`GssMechanism`](crate::extensions::GssMechanism); NTLM is refused by name.
/// - A mechanism is established only after the peer's `VERIFY` message
///   verified: an RFC 3961 keyed checksum of the whole transcript under the
///   mechanism's key, of the checksum type the key's encryption type defines.
///   A peer that sends no `VERIFY` message leaves the context incomplete.
/// - Keys live in zeroizing owners; the transcript is erased on drop; `Debug`
///   shows no key and no token.
#[non_exhaustive]
pub struct Context {
    /// Which end this context is.
    role: Role,
    /// What the application asked for.
    request: Request,
    /// The candidate mechanisms; one remains once the exchange selected it.
    entries: Vec<Entry>,
    /// Steps taken so far.
    step: u32,
    /// The sequence number and conversation id.
    conversation: Conversation,
    /// Every message sent and received, which the `VERIFY` checksums cover.
    transcript: Zeroizing<Vec<u8>>,
    /// The random source.
    random: Arc<dyn RandomSource>,
    /// Whether the initiator sends an optimistic `AP_REQUEST`.
    optimistic: bool,
    /// The permission snapshot the mechanism keys are checked against.
    policy: CryptoPolicy,
    /// Whether a step failed.
    failed: bool,
}

impl fmt::Debug for Context {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Context")
            .field("role", &self.role)
            .field("step", &self.step)
            .field("mechanisms", &self.entries.len())
            .field("transcript_len", &self.transcript.len())
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}

/// The mechanisms of `negotiable` as entries.
///
/// # Errors
///
/// Returns [`Negoex::NoAvailableMechs`] for none, [`Negoex::TooManySchemes`]
/// above the bound, [`Negoex::InvalidMechanismOid`], [`Negoex::RejectedMechanism`],
/// [`Negoex::UnregisteredMechanism`] and [`Negoex::DuplicateScheme`].
fn entries_of(
    registry: &Registry,
    negotiable: &[Arc<dyn Mechanism>],
) -> Result<Vec<Entry>, Negoex> {
    if negotiable.is_empty() {
        return Err(Negoex::NoAvailableMechs);
    }
    if negotiable.len() > MAX_SCHEMES {
        return Err(Negoex::TooManySchemes {
            maximum: MAX_SCHEMES,
            actual: negotiable.len(),
        });
    }
    let mut entries: Vec<Entry> = Vec::with_capacity(negotiable.len());
    for mechanism in negotiable {
        let oid = ObjectIdentifier::from_der_content(mechanism.oid())
            .map_err(|_malformed| Negoex::InvalidMechanismOid)?;
        if oid.arcs() == NTLMSSP_ARCS {
            return Err(Negoex::RejectedMechanism(oid));
        }
        if registry.gss_mechanism(mechanism.oid()).is_none() {
            return Err(Negoex::UnregisteredMechanism(oid));
        }
        let entry = Entry::new(Arc::clone(mechanism), oid);
        if entries.iter().any(|earlier| earlier.scheme == entry.scheme) {
            return Err(Negoex::DuplicateScheme(entry.scheme));
        }
        entries.push(entry);
    }
    Ok(entries)
}

/// NTLMSSP, `1.3.6.1.4.1.311.2.2.10`, which no `NegoEx` negotiation here offers.
const NTLMSSP_ARCS: &[u32] = &[1, 3, 6, 1, 4, 1, 311, 2, 2, 10];

impl Context {
    /// A context offering `mechanisms` as an initiator for `request`.
    ///
    /// # Errors
    ///
    /// Returns the errors of the mechanism checks: [`Negoex::NoAvailableMechs`],
    /// [`Negoex::TooManySchemes`], [`Negoex::InvalidMechanismOid`],
    /// [`Negoex::RejectedMechanism`], [`Negoex::UnregisteredMechanism`] and
    /// [`Negoex::DuplicateScheme`].
    #[inline]
    pub fn initiator(
        registry: &Registry,
        mechanisms: &[Arc<dyn Mechanism>],
        request: Request,
    ) -> Result<Self, Negoex> {
        Self::new(Role::Initiator, registry, mechanisms, request)
    }

    /// A context accepting any of `mechanisms` as an acceptor.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Context::initiator`].
    #[inline]
    pub fn acceptor(
        registry: &Registry,
        mechanisms: &[Arc<dyn Mechanism>],
        request: Request,
    ) -> Result<Self, Negoex> {
        Self::new(Role::Acceptor, registry, mechanisms, request)
    }

    /// A context for `role`.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Context::initiator`].
    fn new(
        role: Role,
        registry: &Registry,
        mechanisms: &[Arc<dyn Mechanism>],
        request: Request,
    ) -> Result<Self, Negoex> {
        Ok(Self {
            role,
            request,
            entries: entries_of(registry, mechanisms)?,
            step: 0,
            conversation: Conversation::accepting(),
            transcript: Zeroizing::new(Vec::new()),
            random: Arc::new(SystemRandom),
            optimistic: true,
            policy: CryptoPolicy::default(),
            failed: false,
        })
    }

    /// The same context drawing its conversation id and nonces from `fill`
    /// (for reproducible tokens in tests and captures).
    #[inline]
    #[must_use]
    pub fn with_random_source(mut self, source: Arc<dyn RandomSource>) -> Self {
        self.random = source;
        self
    }

    /// The same context sending no optimistic `AP_REQUEST` in its first token
    /// when `optimistic` is false (MIT `NEGOEX_NO_OPTIMISTIC_TOKEN`, `negoex_ctx.c:255-258`).
    #[inline]
    #[must_use]
    pub const fn with_optimistic_token(mut self, optimistic: bool) -> Self {
        self.optimistic = optimistic;
        self
    }

    /// The same context checking mechanism keys against `policy`.
    #[inline]
    #[must_use]
    pub fn with_crypto_policy(mut self, policy: CryptoPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// The mechanisms still in the negotiation, in order of preference.
    #[inline]
    #[must_use]
    pub fn mechanisms(&self) -> Vec<MechanismMetadata> {
        self.entries.iter().map(Entry::describe).collect()
    }

    /// Whether the negotiation is complete: the first mechanism is established
    /// and the peer's `VERIFY` message verified.
    #[inline]
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.step > 0
            && !self.failed
            && self
                .entries
                .first()
                .is_some_and(|entry| entry.is_complete() && entry.verified_checksum)
    }

    /// The mechanism in use once the negotiation is complete.
    #[inline]
    #[must_use]
    pub fn selected(&self) -> Option<MechanismMetadata> {
        self.entries
            .first()
            .filter(|_entry| self.is_complete())
            .map(Entry::describe)
    }

    /// The context flags of the first mechanism's session: none before it has one.
    #[inline]
    #[must_use]
    pub fn selected_flags(&self) -> ContextFlags {
        self.entries
            .first()
            .and_then(|entry| entry.session.as_ref())
            .map_or_else(ContextFlags::default, |session| session.context_flags())
    }

    /// The selected mechanism's session, once the negotiation is complete.
    ///
    /// # Errors
    ///
    /// Returns [`Negoex::UnexpectedStep`] before the negotiation is complete.
    #[inline]
    pub fn into_session(self) -> Result<Box<dyn Session>, Negoex> {
        if !self.is_complete() {
            return Err(Negoex::UnexpectedStep("the negotiation is not complete"));
        }
        self.entries
            .into_iter()
            .next()
            .and_then(|entry| entry.session)
            .ok_or(Negoex::UnexpectedStep("the selected mechanism has no session"))
    }

    /// One step: the initiator's first takes no token; every other step takes the
    /// peer's token.
    ///
    /// # Errors
    ///
    /// Returns the framing errors of [`Conversation::parse`], [`Negoex::MissingNegoMessage`],
    /// [`Negoex::NoAvailableMechs`], [`Negoex::MissingApRequestMessage`],
    /// [`Negoex::NoVerifyKey`], [`Negoex::InvalidChecksum`], [`Negoex::Provider`]
    /// when every mechanism failed, [`Negoex::UnexpectedStep`] after a failure or
    /// completion, and the key policy and random source errors. The context is
    /// unusable after an error.
    ///
    /// # Cancel safety
    ///
    /// The method is not async.
    #[inline]
    pub fn step(&mut self, peer_token: Option<&[u8]>) -> Result<Step, Negoex> {
        if self.failed {
            return Err(Negoex::UnexpectedStep("an earlier step failed"));
        }
        if self.is_complete() {
            return Err(Negoex::UnexpectedStep("the negotiation is complete"));
        }
        let token = peer_token.filter(|bytes| !bytes.is_empty());
        let result = match self.role {
            Role::Initiator => initiate(self, token),
            Role::Acceptor => accept(self, token),
        };
        self.failed = result.is_err();
        result
    }
}

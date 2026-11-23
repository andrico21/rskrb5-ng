/// What [`IakerbContext::accept_sec_context`] needs the application to do next.
#[non_exhaustive]
pub enum AcceptStep {
    /// Send this token to the initiator and pass its answer to the next step
    /// (`GSS_S_CONTINUE_NEEDED`).
    Continue(Vec<u8>),
    /// The context is established (`GSS_S_COMPLETE`).
    Complete(Box<Accepted>),
}

impl fmt::Debug for AcceptStep {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Continue(token) => write!(f, "Continue({} bytes)", token.len()),
            Self::Complete(accepted) => f.debug_tuple("Complete").field(accepted).finish(),
        }
    }
}

/// An IAKERB security context: the initiator that relays its Kerberos
/// exchanges through the acceptor, or the acceptor that relays them.
///
/// The initiator takes the credential at every step, as [`super::Initiator`]
/// does; the acceptor takes the keytab-backed [`Acceptor`] and the application's
/// [`KdcRelay`]. A failed step ends the initiator; the acceptor refuses the
/// token and stays as it was.
#[non_exhaustive]
pub struct IakerbContext {
    /// The tokens exchanged and their bounds.
    conversation: conversation::Conversation,
    /// This end.
    role: Role,
}

/// Which end a context is.
enum Role {
    /// The initiator.
    Initiator(Box<initiator::State>),
    /// The acceptor.
    Acceptor(acceptor::State),
}

impl fmt::Debug for IakerbContext {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let role = match &self.role {
            Role::Initiator(_) => "initiator",
            Role::Acceptor(_) => "acceptor",
        };
        f.debug_struct("IakerbContext")
            .field("role", &role)
            .field("established", &self.is_established())
            .finish_non_exhaustive()
    }
}

impl IakerbContext {
    /// The IAKERB mechanism, `1.3.6.1.5.2.5`.
    #[inline]
    #[must_use]
    pub fn mechanism() -> ObjectIdentifier {
        ObjectIdentifier::from_static(&[1, 3, 6, 1, 5, 2, 5])
    }

    /// An initiator context for `target`; the AS and TGS requests take their
    /// lifetimes, flags, enctypes and policy from `config`'s `[libdefaults]`.
    ///
    /// # Errors
    ///
    /// Returns the errors of reading the request defaults of `config`
    /// ([`Error::Client`]) and of the random source.
    #[inline]
    pub fn initiator(
        config: &Config,
        target: super::Name,
        options: super::InitiatorOptions,
    ) -> Result<Self, Error> {
        let now = std::time::SystemTime::now();
        let mut nonce = [0_u8; 4];
        getrandom::fill(&mut nonce)?;
        let nonce = u32::from_be_bytes(nonce) & 0x7fff_ffff;
        let exchanges = (
            crate::client::stepwise::InitCredsOptions::from_config(config, now, nonce)?,
            crate::client::stepwise::TicketOptions::new(
                crate::client::options::TgsReq::from_libdefaults(now, nonce, &config.libdefaults)?,
            ),
        );
        Ok(Self {
            conversation: conversation::Conversation::with_defaults(),
            role: Role::Initiator(Box::new(initiator::new(target, options, exchanges))),
        })
    }

    /// An acceptor context that relays under `policy`.
    #[inline]
    #[must_use]
    pub fn acceptor(policy: RelayPolicy) -> Self {
        Self {
            conversation: conversation::Conversation::for_policy(&policy),
            role: Role::Acceptor(acceptor::new(policy)),
        }
    }

    /// One initiator step: the first call (no input) sends the first token,
    /// each later call takes the acceptor's answer. The AS and TGS requests go
    /// out as proxy tokens; when the service ticket is in hand the AP-REQ goes
    /// out, and with mutual authentication the AP-REP completes the context.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedStep`] out of order or on an acceptor
    /// context, the token errors, [`Error::KdcNotFound`] and
    /// [`Error::KdcNoResponse`] when the acceptor reports them, the exchange
    /// errors ([`Error::Client`]), [`Error::UnsupportedPrompt`], and the
    /// bound errors ([`Error::RoundLimit`], [`Error::TranscriptTooLarge`]).
    #[inline]
    pub fn init_sec_context(
        &mut self,
        credential: &Credential,
        input_token: Option<&[u8]>,
    ) -> Result<InitStep, Error> {
        match &mut self.role {
            Role::Initiator(state) => {
                initiator::step(state, &mut self.conversation, credential, input_token)
            }
            Role::Acceptor(_) => Err(Error::UnexpectedStep("this is an acceptor context")),
        }
    }

    /// One acceptor step. A proxy token is answered with a proxy token: the
    /// acceptor's realm for a discovery request, the KDC's reply for a request
    /// it relays through `relay`. The AP-REQ completes the context.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedStep`] out of order or on an initiator
    /// context, the token errors, [`Error::RealmNotPermitted`] and
    /// [`Error::RequestRefused`] for a request the policy refuses,
    /// [`Error::RoundLimit`], [`Error::TokenTooLarge`] and
    /// [`Error::TranscriptTooLarge`] at the bounds, [`Error::RelayFailed`] and
    /// [`Error::BadRelayReply`] for the relay, and for the AP-REQ the
    /// validation errors, [`Error::MissingFinished`], [`Error::BadFinished`]
    /// and [`Error::UnexpectedFinished`].
    ///
    /// # Security
    ///
    /// The relay is called only after the realm and the request passed the
    /// policy. The context accepts at most one AP-REQ.
    #[inline]
    pub fn accept_sec_context(
        &mut self,
        acceptor: &mut Acceptor<'_>,
        relay: &mut dyn KdcRelay,
        input_token: &[u8],
    ) -> Result<AcceptStep, Error> {
        match &mut self.role {
            Role::Acceptor(state) => acceptor::step(
                state,
                &mut self.conversation,
                (acceptor, relay),
                input_token,
            ),
            Role::Initiator(_) => Err(Error::UnexpectedStep("this is an initiator context")),
        }
    }

    /// Whether the context is established.
    #[inline]
    #[must_use]
    pub const fn is_established(&self) -> bool {
        match &self.role {
            Role::Initiator(state) => state.is_established(),
            Role::Acceptor(state) => state.is_established(),
        }
    }

    /// The established context of an initiator; the acceptor's comes with
    /// [`AcceptStep::Complete`]. The context reports the krb5 mechanism, as
    /// every [`EstablishedContext`] does.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedStep`] before the context is established and
    /// on an acceptor context.
    #[inline]
    pub fn into_established(self) -> Result<EstablishedContext, Error> {
        match self.role {
            Role::Initiator(state) => state.into_established(),
            Role::Acceptor(_) => Err(Error::UnexpectedStep("an acceptor context has no initiator part")),
        }
    }
}

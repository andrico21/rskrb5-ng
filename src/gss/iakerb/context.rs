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
#[non_exhaustive]
pub struct IakerbContext {
    /// Whether this end started the context.
    initiator: bool,
}

impl fmt::Debug for IakerbContext {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IakerbContext")
            .field("initiator", &self.initiator)
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

    /// An initiator context for `target`.
    ///
    /// # Errors
    ///
    /// Returns the errors of reading the request defaults of `config`.
    #[inline]
    pub fn initiator(
        config: &Config,
        target: super::Name,
        options: super::InitiatorOptions,
    ) -> Result<Self, Error> {
        let _unread = (config, target, options);
        Ok(Self { initiator: true })
    }

    /// An acceptor context that relays under `policy`.
    #[inline]
    #[must_use]
    pub fn acceptor(policy: RelayPolicy) -> Self {
        let _unread = policy;
        Self { initiator: false }
    }

    /// One initiator step.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedStep`] out of order.
    #[inline]
    pub fn init_sec_context(
        &mut self,
        credential: &Credential,
        input_token: Option<&[u8]>,
    ) -> Result<InitStep, Error> {
        let _unread = (credential, input_token);
        Err(Error::UnexpectedStep("not implemented"))
    }

    /// One acceptor step.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedStep`] out of order.
    #[inline]
    pub fn accept_sec_context(
        &mut self,
        acceptor: &mut Acceptor<'_>,
        relay: &mut dyn KdcRelay,
        input_token: &[u8],
    ) -> Result<AcceptStep, Error> {
        let _unread = (acceptor, relay, input_token);
        Err(Error::UnexpectedStep("not implemented"))
    }

    /// Whether the context is established.
    #[inline]
    #[must_use]
    pub const fn is_established(&self) -> bool {
        false
    }

    /// The established context of an initiator.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedStep`] before the context is established.
    #[inline]
    pub fn into_established(self) -> Result<EstablishedContext, Error> {
        Err(Error::UnexpectedStep("not implemented"))
    }
}

/// A SPNEGO initiator over the GSS Kerberos mechanism (RFC 4178).
///
/// It wraps the [`gss::Initiator`]'s tokens in SPNEGO and verifies the
/// acceptor's `mechListMIC` with the established GSS context, which it then
/// yields.
#[non_exhaustive]
pub struct Initiator {
    /// The Kerberos initiator.
    inner: gss::Initiator,
    /// The DER `MechTypeList` the initiator offered, for the `mechListMIC`.
    offered: Option<Vec<u8>>,
}

impl Initiator {
    /// A SPNEGO initiator offering the Kerberos mechanism of `inner`.
    #[inline]
    #[must_use]
    pub const fn new(inner: gss::Initiator) -> Self {
        Self {
            inner,
            offered: None,
        }
    }

    /// One step: the first call sends a `NegTokenInit` with the optimistic
    /// Kerberos token; the next takes the acceptor's `NegTokenResp`.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`gss::Initiator::init_sec_context`],
    /// [`Error::WrongNegotiationToken`] for a `NegTokenInit` reply,
    /// [`Error::NegotiationRequiresState`] unless the reply completes,
    /// [`Error::UnsupportedMechanism`] for a mechanism that was not offered,
    /// [`Error::MissingApRep`] without the AP-REP a mutual context needs, and
    /// the MIC verification errors.
    #[inline]
    pub fn init_sec_context(
        &mut self,
        credential: &gss::Credential,
        input_token: Option<&[u8]>,
    ) -> Result<gss::InitStep, error::Gss> {
        gss_contexts::initiate(self, credential, input_token)
    }

    /// The established GSS context.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`gss::Initiator::into_established`].
    #[inline]
    pub fn into_established(self) -> Result<gss::EstablishedContext, error::Gss> {
        self.inner.into_established()
    }
}

/// Where a SPNEGO [`Acceptor`] is.
#[non_exhaustive]
pub enum AcceptStep {
    /// Send this `NegTokenResp` (`accept-incomplete`) and pass the initiator's
    /// next token to the next step.
    Continue(Vec<u8>),
    /// The context is established; send its output token.
    Complete(Box<gss::Accepted>),
}

/// A SPNEGO acceptor over the GSS Kerberos mechanism (RFC 4178).
///
/// Its contexts are [`gss::EstablishedContext`]s, and a `NegTokenInit` without
/// an optimistic token is continued with the initiator's next `NegTokenResp`.
#[non_exhaustive]
pub struct Acceptor<'keytab> {
    /// The Kerberos acceptor.
    inner: gss::Acceptor<'keytab>,
    /// The received `MechTypeList`, the selected mechanism and whether a MIC is
    /// required, for a negotiation waiting for the initiator's token.
    waiting: Option<(Vec<u8>, ObjectIdentifier, bool)>,
}

impl<'keytab> Acceptor<'keytab> {
    /// A SPNEGO acceptor over `inner`.
    #[inline]
    #[must_use]
    pub const fn new(inner: gss::Acceptor<'keytab>) -> Self {
        Self {
            inner,
            waiting: None,
        }
    }

    /// Take one initiator token: a `NegTokenInit` (or a raw Kerberos token), or
    /// the `NegTokenResp` that continues a negotiation.
    ///
    /// # Errors
    ///
    /// Returns the SPNEGO token errors, [`Error::MissingMechListMic`] when a
    /// non-first Kerberos selection has no MIC, [`Error::InvalidMechListMic`]
    /// for a bad MIC, [`Error::NegotiationRequiresState`] for a continuation
    /// nothing waits for, and the errors of [`gss::Acceptor::accept_sec_context`].
    #[inline]
    pub fn accept_sec_context(&mut self, input_token: &[u8]) -> Result<AcceptStep, error::Gss> {
        gss_contexts::accept(self, input_token)
    }
}

impl fmt::Debug for Initiator {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Initiator")
            .field("inner", &self.inner)
            .field("offered_len", &self.offered.as_ref().map(Vec::len))
            .finish()
    }
}

impl fmt::Debug for AcceptStep {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Continue(token) => f
                .debug_struct("Continue")
                .field("token_len", &token.len())
                .finish(),
            Self::Complete(accepted) => f.debug_tuple("Complete").field(accepted).finish(),
        }
    }
}

impl fmt::Debug for Acceptor<'_> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Acceptor")
            .field("inner", &self.inner)
            .field("waiting", &self.waiting.is_some())
            .finish()
    }
}

/// Why a [`KdcRelay`] could not deliver a request.
///
/// The first two answer the initiator with the IAKERB error codes of MIT
/// (`iakerb.c:437-445`); [`Self::Other`] ends the context.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RelayFailure {
    /// No KDC of the realm answered (`KRB5_KDC_UNREACH`,
    /// `KRB_AP_ERR_IAKERB_KDC_NO_RESPONSE`).
    KdcUnreachable,
    /// The application knows no KDC for the realm (`KRB5_REALM_UNKNOWN`,
    /// `KRB_AP_ERR_IAKERB_KDC_NOT_FOUND`).
    RealmUnknown,
    /// Any other failure; the text is for the application's log.
    Other(String),
}

/// The application's channel to the KDCs: the acceptor hands it a request and
/// the realm it is for, and returns what it answers.
///
/// The library never opens a socket to a KDC here. The implementation decides
/// which servers a realm maps to, the transport and the retries (MIT retries a
/// `KRB_ERR_RESPONSE_TOO_BIG` over TCP, `iakerb.c:416-435`); it is called only
/// for requests the [`RelayPolicy`] already admitted.
///
/// # Security
///
/// The reply is not authenticated by the acceptor: the initiator binds every
/// reply to its own request, as it does over a direct transport.
pub trait KdcRelay {
    /// Send `request`, a DER AS-REQ or TGS-REQ for `realm`, to a KDC of `realm`
    /// and return its DER reply (an AS-REP, a TGS-REP or a KRB-ERROR).
    ///
    /// # Errors
    ///
    /// Returns [`RelayFailure`] when the realm has no KDC or none answers.
    fn relay(&mut self, realm: &str, request: &[u8]) -> Result<Vec<u8>, RelayFailure>;
}

/// What an IAKERB acceptor may relay: the realms, the rounds and the bytes.
///
/// A policy names its realms explicitly; there is no way to relay for "any
/// realm" (the acceptor is never an open proxy).
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct RelayPolicy {
    /// The acceptor's own realm, which realm discovery answers.
    local_realm: String,
    /// The realms a request may name.
    realms: Vec<String>,
    /// The most tokens the acceptor produces.
    max_rounds: usize,
    /// The longest token or relayed message.
    max_message_bytes: usize,
    /// The longest transcript.
    max_transcript_bytes: usize,
}

impl RelayPolicy {
    /// The default bound on rounds: 16 AS rounds and 10 referral hops (MIT
    /// `IAKERB_MAX_HOPS`, `iakerb.c:55`).
    pub const DEFAULT_MAX_ROUNDS: usize = 26;
    /// The default bound on one token or relayed message, in bytes.
    pub const DEFAULT_MAX_MESSAGE_BYTES: usize = 0x4_0000;
    /// The default bound on the transcript, in bytes.
    pub const DEFAULT_MAX_TRANSCRIPT_BYTES: usize = 0x10_0000;
    /// The most realms a policy may name.
    pub const MAX_REALMS: usize = 16;

    /// A policy that relays for `local_realm` only, which realm discovery
    /// answers.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPolicy`] for an empty realm or one above 255 bytes.
    #[inline]
    pub fn new(local_realm: &str) -> Result<Self, Error> {
        let _unread = local_realm;
        Err(Error::InvalidPolicy("not implemented"))
    }

    /// Also relay for `realm`, for example a realm a referral may reach.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPolicy`] for an empty realm, one above 255
    /// bytes, or more than [`Self::MAX_REALMS`] realms.
    #[inline]
    pub fn with_realm(self, realm: &str) -> Result<Self, Error> {
        let _unread = realm;
        Err(Error::InvalidPolicy("not implemented"))
    }

    /// Allow at most `rounds` tokens from the acceptor.
    #[inline]
    #[must_use]
    pub const fn with_max_rounds(mut self, rounds: usize) -> Self {
        self.max_rounds = rounds;
        self
    }

    /// Allow tokens and relayed messages of at most `bytes`.
    #[inline]
    #[must_use]
    pub const fn with_max_message_bytes(mut self, bytes: usize) -> Self {
        self.max_message_bytes = bytes;
        self
    }

    /// Allow a transcript of at most `bytes`.
    #[inline]
    #[must_use]
    pub const fn with_max_transcript_bytes(mut self, bytes: usize) -> Self {
        self.max_transcript_bytes = bytes;
        self
    }

    /// Whether a request for `realm` may be relayed.
    #[inline]
    #[must_use]
    pub fn permits(&self, realm: &str) -> bool {
        self.realms.iter().any(|allowed| allowed == realm)
    }
}

/// The type of a `NegoEx` message (MS-NEGOEX 2.2.6.2; MIT `gssapiP_negoex.h:79-88`).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum MessageType {
    /// `MESSAGE_TYPE_INITIATOR_NEGO`.
    InitiatorNego,
    /// `MESSAGE_TYPE_ACCEPTOR_NEGO`.
    AcceptorNego,
    /// `MESSAGE_TYPE_INITIATOR_META_DATA`.
    InitiatorMetaData,
    /// `MESSAGE_TYPE_ACCEPTOR_META_DATA`.
    AcceptorMetaData,
    /// `MESSAGE_TYPE_CHALLENGE`.
    Challenge,
    /// `MESSAGE_TYPE_AP_REQUEST`.
    ApRequest,
    /// `MESSAGE_TYPE_VERIFY`.
    Verify,
    /// `MESSAGE_TYPE_ALERT`.
    Alert,
}

impl MessageType {
    /// The wire value.
    #[inline]
    #[must_use]
    pub const fn code(self) -> u32 {
        match self {
            Self::InitiatorNego => 0,
            Self::AcceptorNego => 1,
            Self::InitiatorMetaData => 2,
            Self::AcceptorMetaData => 3,
            Self::Challenge => 4,
            Self::ApRequest => 5,
            Self::Verify => 6,
            Self::Alert => 7,
        }
    }

    /// The type of a wire value.
    #[inline]
    #[must_use]
    pub const fn from_code(code: u32) -> Option<Self> {
        match code {
            0 => Some(Self::InitiatorNego),
            1 => Some(Self::AcceptorNego),
            2 => Some(Self::InitiatorMetaData),
            3 => Some(Self::AcceptorMetaData),
            4 => Some(Self::Challenge),
            5 => Some(Self::ApRequest),
            6 => Some(Self::Verify),
            7 => Some(Self::Alert),
            _ => None,
        }
    }

    /// MIT's trace name (`negoex_util.c:101-120`).
    #[inline]
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::InitiatorNego => "INITIATOR_NEGO",
            Self::AcceptorNego => "ACCEPTOR_NEGO",
            Self::InitiatorMetaData => "INITIATOR_META_DATA",
            Self::AcceptorMetaData => "ACCEPTOR_META_DATA",
            Self::Challenge => "CHALLENGE",
            Self::ApRequest => "AP_REQUEST",
            Self::Verify => "VERIFY",
            Self::Alert => "ALERT",
        }
    }
}

/// `INITIATOR_NEGO` or `ACCEPTOR_NEGO`: a random value and the schemes offered.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct NegoMessage {
    /// The message type.
    message_type: MessageType,
    /// The 32 random bytes.
    random: [u8; 32],
    /// The schemes in order of preference.
    schemes: Vec<AuthScheme>,
}

impl NegoMessage {
    /// A negotiate message.
    ///
    /// # Errors
    ///
    /// Returns [`Negoex::WrongMessageShape`] for a type other than
    /// `InitiatorNego` and `AcceptorNego`, and [`Negoex::TooManySchemes`] above the bound.
    #[inline]
    pub fn new(
        message_type: MessageType,
        random: [u8; 32],
        schemes: Vec<AuthScheme>,
    ) -> Result<Self, Negoex> {
        if !matches!(
            message_type,
            MessageType::InitiatorNego | MessageType::AcceptorNego
        ) {
            return Err(Negoex::WrongMessageShape(message_type));
        }
        if schemes.len() > MAX_SCHEMES {
            return Err(Negoex::TooManySchemes {
                maximum: MAX_SCHEMES,
                actual: schemes.len(),
            });
        }
        Ok(Self {
            message_type,
            random,
            schemes,
        })
    }

    /// The message type.
    #[inline]
    #[must_use]
    pub const fn message_type(&self) -> MessageType {
        self.message_type
    }

    /// The 32 random bytes.
    #[inline]
    #[must_use]
    pub const fn random(&self) -> &[u8; 32] {
        &self.random
    }

    /// The schemes in order of preference.
    #[inline]
    #[must_use]
    pub fn schemes(&self) -> &[AuthScheme] {
        &self.schemes
    }
}

/// `INITIATOR_META_DATA`, `ACCEPTOR_META_DATA`, `CHALLENGE` or `AP_REQUEST`: a
/// scheme and the bytes of that exchange step.
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub struct ExchangeMessage {
    /// The message type.
    message_type: MessageType,
    /// The scheme the bytes belong to.
    scheme: AuthScheme,
    /// The metadata or mechanism token.
    token: Vec<u8>,
}

impl fmt::Debug for ExchangeMessage {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExchangeMessage")
            .field("message_type", &self.message_type)
            .field("scheme", &self.scheme)
            .field("token_len", &self.token.len())
            .finish()
    }
}

impl ExchangeMessage {
    /// An exchange message.
    ///
    /// # Errors
    ///
    /// Returns [`Negoex::WrongMessageShape`] for a type that is not an exchange type.
    #[inline]
    pub fn new(
        message_type: MessageType,
        scheme: AuthScheme,
        token: Vec<u8>,
    ) -> Result<Self, Negoex> {
        if !matches!(
            message_type,
            MessageType::InitiatorMetaData
                | MessageType::AcceptorMetaData
                | MessageType::Challenge
                | MessageType::ApRequest
        ) {
            return Err(Negoex::WrongMessageShape(message_type));
        }
        Ok(Self {
            message_type,
            scheme,
            token,
        })
    }

    /// The message type.
    #[inline]
    #[must_use]
    pub const fn message_type(&self) -> MessageType {
        self.message_type
    }

    /// The scheme.
    #[inline]
    #[must_use]
    pub const fn scheme(&self) -> AuthScheme {
        self.scheme
    }

    /// The metadata or mechanism token.
    #[inline]
    #[must_use]
    pub fn token(&self) -> &[u8] {
        &self.token
    }
}

/// `VERIFY`: an RFC 3961 checksum over the transcript (MS-NEGOEX 2.2.6.5).
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub struct VerifyMessage {
    /// The scheme whose key made the checksum.
    scheme: AuthScheme,
    /// The RFC 3961 checksum type.
    checksum_type: i32,
    /// The checksum bytes.
    checksum: Vec<u8>,
    /// Where the message starts in the token it was parsed from; 0 for a built one.
    offset_in_token: usize,
}

impl fmt::Debug for VerifyMessage {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifyMessage")
            .field("scheme", &self.scheme)
            .field("checksum_type", &self.checksum_type)
            .field("offset_in_token", &self.offset_in_token)
            .finish_non_exhaustive()
    }
}

impl VerifyMessage {
    /// A verify message to send.
    #[inline]
    #[must_use]
    pub const fn new(scheme: AuthScheme, checksum_type: i32, checksum: Vec<u8>) -> Self {
        Self {
            scheme,
            checksum_type,
            checksum,
            offset_in_token: 0,
        }
    }

    /// The scheme.
    #[inline]
    #[must_use]
    pub const fn scheme(&self) -> AuthScheme {
        self.scheme
    }

    /// The RFC 3961 checksum type.
    #[inline]
    #[must_use]
    pub const fn checksum_type(&self) -> i32 {
        self.checksum_type
    }

    /// The checksum bytes.
    #[inline]
    #[must_use]
    pub fn checksum(&self) -> &[u8] {
        &self.checksum
    }

    /// Where the message starts in the token it was parsed from: the checksum
    /// covers the transcript and the token bytes before this offset.
    #[inline]
    #[must_use]
    pub const fn offset_in_token(&self) -> usize {
        self.offset_in_token
    }
}

/// `ALERT`: only the `ALERT_VERIFY_NO_KEY` pulse is told apart (MIT `negoex_util.c:327-340`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct AlertMessage {
    /// The scheme the alert is about.
    scheme: AuthScheme,
    /// Whether the alerts include a `VERIFY_NO_KEY` pulse.
    verify_no_key: bool,
}

impl AlertMessage {
    /// An alert holding one `ALERT_TYPE_PULSE` of reason `ALERT_VERIFY_NO_KEY`.
    #[inline]
    #[must_use]
    pub const fn verify_no_key(scheme: AuthScheme) -> Self {
        Self {
            scheme,
            verify_no_key: true,
        }
    }

    /// The scheme.
    #[inline]
    #[must_use]
    pub const fn scheme(&self) -> AuthScheme {
        self.scheme
    }

    /// Whether the alert asks the receiver to send its `VERIFY` message again.
    #[inline]
    #[must_use]
    pub const fn is_verify_no_key(&self) -> bool {
        self.verify_no_key
    }
}

/// One `NegoEx` message.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Message {
    /// `INITIATOR_NEGO` or `ACCEPTOR_NEGO`.
    Nego(NegoMessage),
    /// A metadata, `CHALLENGE` or `AP_REQUEST` message.
    Exchange(ExchangeMessage),
    /// `VERIFY`.
    Verify(VerifyMessage),
    /// `ALERT`.
    Alert(AlertMessage),
}

impl Message {
    /// The message type.
    #[inline]
    #[must_use]
    pub const fn message_type(&self) -> MessageType {
        match self {
            Self::Nego(message) => message.message_type,
            Self::Exchange(message) => message.message_type,
            Self::Verify(_) => MessageType::Verify,
            Self::Alert(_) => MessageType::Alert,
        }
    }
}

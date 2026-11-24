/// `NegoEx` (MS-NEGOEX) negotiation error ([`crate::gss::negoex`]).
///
/// The first thirteen variants are MIT krb5 1.22.2's `ERR_NEGOEX_*` codes
/// (`negoex_util.c`, `negoex_ctx.c`, `spnego_mech.c:1759-1786`); the others are
/// the bounds and policy refusals of this implementation.
#[cfg(feature = "spnego")]
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Negoex {
    /// A message does not start with the `NEGOEXTS` signature.
    #[error("invalid NegoEx message signature")]
    InvalidMessageSignature,
    /// A message type outside `INITIATOR_NEGO` to `ALERT`.
    #[error("invalid NegoEx message type {0}")]
    InvalidMessageType(u32),
    /// A length, offset or count leaves its message, or a header is shorter than its type needs.
    #[error("invalid NegoEx message size")]
    InvalidMessageSize,
    /// A message of the conversation carries another conversation id.
    #[error("invalid NegoEx conversation ID")]
    InvalidConversationId,
    /// The peer's `NEGO_MESSAGE` is missing.
    #[error("missing NegoEx negotiate message")]
    MissingNegoMessage,
    /// A continuing token carries no `AP_REQUEST`.
    #[error("missing NegoEx authentication protocol request message")]
    MissingApRequestMessage,
    /// No authentication scheme is left in common.
    #[error("no mutually supported NegoEx authentication schemes")]
    NoAvailableMechs,
    /// The selected mechanism has no key to verify or sign with.
    #[error("no NegoEx verify key")]
    NoVerifyKey,
    /// A `VERIFY` checksum scheme other than RFC 3961 (1).
    #[error("unknown NegoEx checksum scheme {0}")]
    UnknownChecksumScheme(u32),
    /// A `VERIFY` checksum does not verify, or its type is not a keyed checksum of the key.
    #[error("invalid NegoEx checksum")]
    InvalidChecksum,
    /// A critical extension this implementation does not know.
    #[error("unsupported critical NegoEx extension")]
    UnsupportedCriticalExtension,
    /// A protocol version other than 0.
    #[error("unsupported NegoEx version {0}")]
    UnsupportedVersion(u64),
    /// A message whose sequence number is not the next one.
    #[error("NegoEx message out of sequence: expected {expected}, got {actual}")]
    MessageOutOfSequence {
        /// The sequence number that was due.
        expected: u32,
        /// The sequence number the message carries.
        actual: u32,
    },
    /// A token above its byte bound.
    #[error("NegoEx token is {actual} bytes, above the {maximum}-byte limit")]
    TokenTooLarge {
        /// The bound.
        maximum: usize,
        /// The length offered.
        actual: usize,
    },
    /// A token with more messages than the bound.
    #[error("NegoEx token holds more than {maximum} messages")]
    TooManyMessages {
        /// The bound.
        maximum: usize,
    },
    /// A `NEGO_MESSAGE` with more authentication schemes than the bound.
    #[error("NegoEx message lists {actual} authentication schemes, above the limit of {maximum}")]
    TooManySchemes {
        /// The bound.
        maximum: usize,
        /// The count offered.
        actual: usize,
    },
    /// A message vector (extensions, alerts) above its bound.
    #[error("NegoEx {field} vector holds {actual} entries, above the limit of {maximum}")]
    TooManyEntries {
        /// The vector.
        field: &'static str,
        /// The bound.
        maximum: usize,
        /// The count offered.
        actual: usize,
    },
    /// A step the context does not expect now.
    #[error("the NegoEx context does not expect this step: {0}")]
    UnexpectedStep(&'static str),
    /// A message type the constructor does not build.
    #[error("NegoEx message type {0:?} does not fit this message shape")]
    WrongMessageShape(MessageType),
    /// The selected mechanism offers integrity, which needs a `mechListMIC`
    /// exchange that `NegoEx` under SPNEGO does not implement.
    #[error("a mechListMIC exchange for a NegoEx mechanism with integrity is not supported")]
    MechListMicUnsupported,
    /// A mechanism whose object identifier does not decode.
    #[error("a mechanism object identifier is malformed")]
    InvalidMechanismOid,
    /// A mechanism whose object identifier is not registered as a GSS mechanism.
    #[error("mechanism {0:?} is not a registered GSS mechanism")]
    UnregisteredMechanism(ObjectIdentifier),
    /// A mechanism the security policy rejects by name (NTLM).
    #[error("mechanism {0:?} is rejected by the security policy")]
    RejectedMechanism(ObjectIdentifier),
    /// Two mechanisms of one negotiation share an authentication scheme.
    #[error("authentication scheme {0} is offered twice")]
    DuplicateScheme(AuthScheme),
    /// A mechanism failed.
    #[error("mechanism failure: {0}")]
    Provider(#[source] ProviderFailure),
    /// The mechanism's key is refused by the permanent policy or has the wrong shape.
    #[error("policy error: {0}")]
    Policy(#[from] Policy),
    /// A checksum could not be computed.
    #[error("crypto error: {0}")]
    Crypto(#[from] Crypto),
    /// The system random source failed.
    #[error("random source error: {0}")]
    Random(#[from] getrandom::Error),
}

#[cfg(feature = "spnego")]
impl Negoex {
    /// The RFC 2744 major status of this error (MIT `negoex_ctx.c`, `negoex_util.c`).
    #[inline]
    #[must_use]
    pub const fn major_status(&self) -> u32 {
        let routine = match self {
            Self::InvalidMessageSignature
            | Self::InvalidMessageType(_)
            | Self::InvalidMessageSize
            | Self::InvalidConversationId
            | Self::MissingNegoMessage
            | Self::MissingApRequestMessage
            | Self::MessageOutOfSequence {
                expected: _,
                actual: _,
            }
            | Self::TokenTooLarge {
                maximum: _,
                actual: _,
            }
            | Self::TooManyMessages { maximum: _ }
            | Self::TooManySchemes {
                maximum: _,
                actual: _,
            }
            | Self::TooManyEntries {
                field: _,
                maximum: _,
                actual: _,
            } => 9,
            Self::UnsupportedVersion(_)
            | Self::UnsupportedCriticalExtension
            | Self::UnknownChecksumScheme(_)
            | Self::NoVerifyKey => 16,
            Self::InvalidChecksum => 6,
            Self::UnexpectedStep(_) | Self::MechListMicUnsupported => 8,
            Self::NoAvailableMechs
            | Self::InvalidMechanismOid
            | Self::UnregisteredMechanism(_)
            | Self::RejectedMechanism(_)
            | Self::DuplicateScheme(_) => 1,
            Self::WrongMessageShape(_)
            | Self::Provider(_)
            | Self::Policy(_)
            | Self::Crypto(_)
            | Self::Random(_) => 13,
        };
        routine << 16
    }
}

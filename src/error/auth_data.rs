/// Authorization-data helper error ([`crate::authdata`]).
#[cfg(feature = "messages")]
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuthData {
    /// ASN.1 DER decode failed.
    #[error("failed to decode {target}: {message}")]
    Decode {
        /// Decoded type name.
        target: &'static str,
        /// Decoder error text.
        message: String,
    },
    /// ASN.1 DER encode failed.
    #[error("failed to encode {target}: {message}")]
    Encode {
        /// Encoded type name.
        target: &'static str,
        /// Encoder error text.
        message: String,
    },
    /// The KDC-issued checksum does not verify (RFC 4120 section 5.2.6.2).
    #[error("the AD-KDC-ISSUED checksum does not verify")]
    ChecksumMismatch,
    /// The checksum type is not implemented or not keyed.
    #[error("unsupported AD-KDC-ISSUED checksum type {0}")]
    UnsupportedChecksumType(i32),
    /// The checksum type does not belong to the key.
    #[error("checksum type {checksum_type} does not match key type {key_etype}")]
    KeyChecksumTypeMismatch {
        /// The key's encryption type.
        key_etype: i32,
        /// The checksum type of the element.
        checksum_type: i32,
    },
    /// The key's encryption type is not implemented.
    #[error("unsupported encryption type {0}")]
    UnsupportedEtype(i32),
    /// The condition count is not between one and the number of elements.
    #[error("AD-AND-OR condition count {count} is impossible for {elements} elements")]
    InvalidConditionCount {
        /// The count in the element.
        count: i32,
        /// The number of embedded elements.
        elements: usize,
    },
    /// A cryptographic operation failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] Crypto),
    /// The encryption type is not permitted.
    #[error("policy error: {0}")]
    Policy(#[from] Policy),
    /// The AD-CAMMAC has no service verifier (RFC 7751 section 4).
    #[error("the AD-CAMMAC has no service verifier")]
    CammacVerifierAbsent,
    /// The AD-CAMMAC service verifier does not verify under the ticket's key.
    #[error("the AD-CAMMAC service verifier does not verify")]
    CammacVerifierMismatch,
}

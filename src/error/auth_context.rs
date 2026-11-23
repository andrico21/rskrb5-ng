/// Authenticated-message error ([`crate::messages::AuthContext`]): MIT's
/// `krb5_mk_priv`/`rd_priv`/`mk_safe`/`rd_safe`/`mk_ncred`/`rd_cred` refusals.
#[cfg(feature = "messages")]
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuthContext {
    /// The context holds neither a session key nor a subkey (MIT `KRB5_..._NOKEY`).
    #[error("the authentication context has no key")]
    NoKey,
    /// KRB-PRIV and KRB-SAFE name the sender: the local address is required
    /// (MIT `KRB5_LOCAL_ADDR_REQUIRED`).
    #[error("the local address is required")]
    LocalAddressRequired,
    /// The message time is outside the allowed clock skew (MIT `KRB5KRB_AP_ERR_SKEW`).
    #[error("message time is outside the clock skew of {max_clock_skew:?}")]
    ClockSkew {
        /// The accepted skew.
        max_clock_skew: Duration,
    },
    /// The message was already seen (MIT `KRB5KRB_AP_ERR_REPEAT`).
    #[error("message replay detected")]
    Replay,
    /// The message sequence number is not the expected one (MIT `KRB5KRB_AP_ERR_BADORDER`).
    #[error("sequence number {received} is out of order, expected {expected}")]
    BadSequence {
        /// The number the context expected.
        expected: u32,
        /// The number the message carried.
        received: u32,
    },
    /// Time checking is on and the message carries no timestamp.
    #[error("the message carries no timestamp")]
    MissingTimestamp,
    /// Sequence checking is on and the message carries no sequence number.
    #[error("the message carries no sequence number")]
    MissingSequence,
    /// A message address does not match the context (MIT `KRB5KRB_AP_ERR_BADADDR`).
    #[error("the {which} address does not match")]
    BadAddress {
        /// Which address: `sender` or `recipient`.
        which: &'static str,
    },
    /// A KRB-CRED would travel unencrypted without a caller-proven protected
    /// channel: the NULL transport is refused.
    #[error("an unencrypted KRB-CRED needs a protected channel")]
    UnauthenticatedTransport,
    /// The replay memory holds only live evidence and refuses another entry.
    #[error("replay memory capacity {capacity} exhausted")]
    ReplayMemoryFull {
        /// The bound on live entries.
        capacity: usize,
    },
    /// A time is outside the range Kerberos can carry.
    #[error("a time is outside the representable range")]
    TimeOutOfRange,
    /// The runtime crypto policy does not permit a key of the context.
    #[error("crypto policy: {0}")]
    Policy(#[from] Policy),
    /// KRB-PRIV processing failed.
    #[error("KRB-PRIV: {0}")]
    Priv(#[from] KrbPriv),
    /// KRB-SAFE processing failed.
    #[error("KRB-SAFE: {0}")]
    Safe(#[from] KrbSafe),
    /// KRB-CRED processing failed.
    #[error("KRB-CRED: {0}")]
    Cred(#[from] KrbCred),
}

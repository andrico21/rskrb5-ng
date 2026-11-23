//! The constructors, builders and message operations of the authenticated message API.

use core::time::Duration;
use std::time::SystemTime;

use rasn_kerberos::HostAddress;
use zeroize::Zeroizing;

use super::{
    AuthContext, CredentialTransport, MessagePolicy, ProtectedChannel, Received, seen::Seen,
};
use crate::{
    ccache::Credential, crypto::CryptoPolicy, error::AuthMessage as Error, keytab::EncryptionKey,
};

impl MessagePolicy {
    /// MIT's defaults: time checked within 300 s, no sequence numbers, the
    /// default (AES only) crypto policy and a replay memory of 65,536 messages.
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        Self {
            check_time: true,
            clock_skew: Duration::from_mins(5),
            check_sequence: false,
            replay_capacity: 0x0001_0000,
            crypto: CryptoPolicy::default(),
        }
    }

    /// Turn timestamps and replay detection on or off (MIT `DO_TIME`).
    ///
    /// # Security
    ///
    /// Off, a captured message can be presented again.
    #[must_use]
    #[inline]
    pub const fn checking_time(mut self, enabled: bool) -> Self {
        self.check_time = enabled;
        self
    }

    /// Turn sequence numbers on or off (MIT `DO_SEQUENCE`).
    #[must_use]
    #[inline]
    pub const fn checking_sequence(mut self, enabled: bool) -> Self {
        self.check_sequence = enabled;
        self
    }

    /// The accepted difference between a message time and the clock.
    #[must_use]
    #[inline]
    pub const fn with_clock_skew(mut self, clock_skew: Duration) -> Self {
        self.clock_skew = clock_skew;
        self
    }

    /// The bound on the replay memory.
    #[must_use]
    #[inline]
    pub const fn with_replay_capacity(mut self, capacity: usize) -> Self {
        self.replay_capacity = capacity;
        self
    }

    /// The runtime permission of the encryption types the context may use.
    #[must_use]
    #[inline]
    pub fn with_crypto_policy(mut self, crypto: CryptoPolicy) -> Self {
        self.crypto = crypto;
        self
    }
}

impl Default for MessagePolicy {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl ProtectedChannel {
    /// Vouch that the channel carrying a KRB-CRED is authenticated and
    /// confidential; `description` names why, for diagnostics.
    ///
    /// # Security
    ///
    /// This is the caller's assertion. A KRB-CRED holds session keys; sending
    /// one over a channel that is not protected discloses them.
    #[must_use]
    #[inline]
    pub const fn vouch(description: &'static str) -> Self {
        Self { description }
    }

    /// What makes the channel protected.
    #[must_use]
    #[inline]
    pub const fn description(&self) -> &'static str {
        self.description
    }
}

impl<T> Received<T> {
    /// A message content with its replay data.
    pub(super) const fn new(
        content: T,
        timestamp: Option<SystemTime>,
        sequence: Option<u32>,
    ) -> Self {
        Self {
            content,
            timestamp,
            sequence,
        }
    }

    /// The user data, or the forwarded credentials.
    #[must_use]
    #[inline]
    pub const fn content(&self) -> &T {
        &self.content
    }

    /// Take the user data, or the forwarded credentials.
    #[must_use]
    #[inline]
    pub fn into_content(self) -> T {
        self.content
    }

    /// The sender's timestamp, when the message carries one.
    #[must_use]
    #[inline]
    pub const fn timestamp(&self) -> Option<SystemTime> {
        self.timestamp
    }

    /// The sender's sequence number, when the message carries one.
    #[must_use]
    #[inline]
    pub const fn sequence(&self) -> Option<u32> {
        self.sequence
    }
}

impl AuthContext {
    /// A context for the session key of an exchange.
    #[must_use]
    #[inline]
    pub fn new(session_key: EncryptionKey, policy: MessagePolicy) -> Self {
        Self::with_key(Some(session_key), policy)
    }

    /// A context without a key. It can only carry an unencrypted KRB-CRED over
    /// a [`ProtectedChannel`] (RFC 6448); every other operation is
    /// [`Error::NoKey`].
    #[must_use]
    #[inline]
    pub fn without_key(policy: MessagePolicy) -> Self {
        Self::with_key(None, policy)
    }

    /// The shared constructor.
    fn with_key(session_key: Option<EncryptionKey>, policy: MessagePolicy) -> Self {
        let capacity = policy.replay_capacity;
        Self {
            session_key,
            send_subkey: None,
            recv_subkey: None,
            local_address: None,
            remote_address: None,
            local_sequence: 0,
            remote_sequence: 0,
            sane_sequence: false,
            heimdal_sequence: false,
            policy,
            now: None,
            seen: Seen::new(capacity),
        }
    }

    /// The sub-keys of the two directions: this end sends under `send` and
    /// reads under `receive`; an absent one falls back to the session key.
    #[must_use]
    #[inline]
    pub fn with_subkeys(
        mut self,
        send: Option<EncryptionKey>,
        receive: Option<EncryptionKey>,
    ) -> Self {
        self.send_subkey = send;
        self.recv_subkey = receive;
        self
    }

    /// This end's address, required to make a KRB-PRIV or KRB-SAFE.
    #[must_use]
    #[inline]
    pub fn with_local_address(mut self, address: HostAddress) -> Self {
        self.local_address = Some(address);
        self
    }

    /// The peer's address: messages must come from it and name it as recipient.
    #[must_use]
    #[inline]
    pub fn with_remote_address(mut self, address: HostAddress) -> Self {
        self.remote_address = Some(address);
        self
    }

    /// The initial sequence numbers: the next this end sends and the next it expects.
    #[must_use]
    #[inline]
    pub const fn with_sequence(mut self, local: u32, remote: u32) -> Self {
        self.local_sequence = local;
        self.remote_sequence = remote;
        self
    }

    /// Fix the clock, for deterministic tests.
    #[must_use]
    #[inline]
    pub const fn with_now(mut self, now: SystemTime) -> Self {
        self.now = Some(now);
        self
    }

    /// The clock of this context.
    pub(super) fn now(&self) -> SystemTime {
        self.now.unwrap_or_else(SystemTime::now)
    }

    /// The number of the next message this end sends.
    #[must_use]
    #[inline]
    pub const fn local_sequence(&self) -> u32 {
        self.local_sequence
    }

    /// The number of the next message this end expects.
    #[must_use]
    #[inline]
    pub const fn remote_sequence(&self) -> u32 {
        self.remote_sequence
    }

    /// Make a KRB-PRIV (MIT `krb5_mk_priv`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::LocalAddressRequired`], [`Error::NoKey`], the crypto
    /// policy error and the codec errors.
    #[inline]
    pub fn mk_priv(&mut self, data: &[u8]) -> Result<Vec<u8>, Error> {
        super::private_safe::make_priv(self, data)
    }

    /// Read a KRB-PRIV (MIT `krb5_rd_priv`): decrypt it and check its addresses,
    /// time, replay status and sequence number.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoKey`], the codec errors, [`Error::BadAddress`],
    /// [`Error::ClockSkew`], [`Error::Replay`], [`Error::MissingTimestamp`],
    /// [`Error::MissingSequence`] and [`Error::BadSequence`].
    #[inline]
    pub fn rd_priv(&mut self, wire: &[u8]) -> Result<Received<Zeroizing<Vec<u8>>>, Error> {
        super::private_safe::read_priv(self, wire)
    }

    /// Make a KRB-SAFE (MIT `krb5_mk_safe`).
    ///
    /// # Errors
    ///
    /// As [`Self::mk_priv`], with the checksum errors of the codec.
    #[inline]
    pub fn mk_safe(&mut self, data: &[u8]) -> Result<Vec<u8>, Error> {
        super::private_safe::make_safe(self, data)
    }

    /// Read a KRB-SAFE (MIT `krb5_rd_safe`): verify its keyed checksum and check
    /// its addresses, time, replay status and sequence number.
    ///
    /// # Errors
    ///
    /// As [`Self::rd_priv`], with the checksum errors of the codec.
    #[inline]
    pub fn rd_safe(&mut self, wire: &[u8]) -> Result<Received<Zeroizing<Vec<u8>>>, Error> {
        super::private_safe::read_safe(self, wire)
    }

    /// Forward credentials in a KRB-CRED (MIT `krb5_mk_ncred`).
    ///
    /// # Security
    ///
    /// The KRB-CRED holds session keys. [`CredentialTransport::Encrypted`]
    /// protects them under a key of the context; [`CredentialTransport::Protected`]
    /// leaves them in the clear and relies on the channel the caller vouched for.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoKey`] for the encrypted transport without a key, and
    /// the codec and policy errors.
    #[inline]
    pub fn mk_cred(
        &mut self,
        credentials: &[Credential],
        transport: CredentialTransport<'_>,
    ) -> Result<Vec<u8>, Error> {
        super::forwarding::make_cred(self, credentials, transport)
    }

    /// Read forwarded credentials (MIT `krb5_rd_cred`), importing only those the
    /// crypto policy permits.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnauthenticatedTransport`] for an unencrypted KRB-CRED
    /// without a [`ProtectedChannel`], [`Error::NoKey`], the codec and policy
    /// errors, and the time, replay and sequence refusals.
    #[inline]
    pub fn rd_cred(
        &mut self,
        wire: &[u8],
        transport: CredentialTransport<'_>,
    ) -> Result<Received<Vec<Credential>>, Error> {
        super::forwarding::read_cred(self, wire, transport)
    }
}

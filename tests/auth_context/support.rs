//! Two ends of one conversation.

use core::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use rskrb5_ng::{
    keytab::EncryptionKey,
    krb_priv::ipv4_host_address,
    messages::{AuthContext, MessagePolicy},
};

use crate::context::{Context as _, TestError};

/// The shared session key (AES256-CTS-HMAC-SHA1-96).
pub(super) fn session_key() -> EncryptionKey {
    EncryptionKey::new(18, vec![0x11; 32])
}

/// A sub-key the initiator sends under.
pub(super) fn initiator_subkey() -> EncryptionKey {
    EncryptionKey::new(18, vec![0x22; 32])
}

/// A sub-key the acceptor sends under.
pub(super) fn acceptor_subkey() -> EncryptionKey {
    EncryptionKey::new(18, vec![0x33; 32])
}

/// A fixed time, so the tests never read the clock.
pub(super) fn at(seconds: u64) -> Result<SystemTime, TestError> {
    UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .context("time is representable")
}

/// The initiator's address.
pub(super) const INITIATOR: [u8; 4] = [10, 0, 0, 1];
/// The acceptor's address.
pub(super) const ACCEPTOR: [u8; 4] = [10, 0, 0, 2];

/// The initiator's end at `seconds`, talking to the acceptor.
pub(super) fn initiator(policy: MessagePolicy, seconds: u64) -> Result<AuthContext, TestError> {
    Ok(AuthContext::new(session_key(), policy)
        .with_local_address(ipv4_host_address(INITIATOR))
        .with_remote_address(ipv4_host_address(ACCEPTOR))
        .with_now(at(seconds)?))
}

/// The acceptor's end at `seconds`, talking to the initiator.
pub(super) fn acceptor(policy: MessagePolicy, seconds: u64) -> Result<AuthContext, TestError> {
    Ok(AuthContext::new(session_key(), policy)
        .with_local_address(ipv4_host_address(ACCEPTOR))
        .with_remote_address(ipv4_host_address(INITIATOR))
        .with_now(at(seconds)?))
}

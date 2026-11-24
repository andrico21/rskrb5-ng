//! A KRB-CRED that MIT krb5 1.22.2 produced (`tests/fixtures/mit-krb-cred/`), read offline.

use std::time::UNIX_EPOCH;

use rskrb5_ng::{
    error::AuthMessage as Error,
    keytab::EncryptionKey,
    krb_cred::{decode, decrypt_krb_cred_enc_part},
    messages::{AuthContext, CredentialTransport, MessagePolicy, ProtectedChannel},
};

use super::support::at;
use crate::context::{Context as _, TestError};

/// The KRB-CRED of MIT's `krb5_fwd_tgt_creds` (hex).
const KRB_CRED: &str = include_str!("../fixtures/mit-krb-cred/krb-cred.hex");

/// The throwaway key it is encrypted under (hex).
const KEY: &str = include_str!("../fixtures/mit-krb-cred/key.hex");

/// The AES256-CTS-HMAC-SHA1-96 key of the fixture.
fn key() -> Result<EncryptionKey, TestError> {
    Ok(EncryptionKey::new(18, hex::decode(KEY.trim())?))
}

/// The wire bytes of the fixture.
fn wire() -> Result<Vec<u8>, TestError> {
    Ok(hex::decode(KRB_CRED.trim())?)
}

/// Pins that MIT's forwarded TGT is read through the encrypted transport at the clock of its own timestamp.
#[test]
fn mit_forwarded_tgt_is_read_through_the_encrypted_transport() -> Result<(), TestError> {
    let sent = decrypt_krb_cred_enc_part(&decode(&wire()?)?, &key()?)?
        .timestamp
        .context("MIT always sets the timestamp")?;
    let seconds = u64::try_from(sent.0.timestamp())?;
    let mut reader = AuthContext::new(key()?, MessagePolicy::new()).with_now(at(seconds)?);

    let received = reader.rd_cred(&wire()?, CredentialTransport::Encrypted)?;

    let credentials = received.content();
    let forwarded = credentials.first().context("one forwarded credential")?;
    assert_eq!(credentials.len(), 1);
    assert_eq!(
        forwarded.client().principal_string(),
        "peeruser@TEST.RSKRB5"
    );
    assert_eq!(
        forwarded.server().principal_string(),
        "krbtgt/TEST.RSKRB5@TEST.RSKRB5"
    );
    assert_eq!(
        forwarded.ticket_flags().first().map(|byte| byte & 0x60),
        Some(0x60)
    );
    let whole_seconds = received
        .timestamp()
        .context("the timestamp is reported")?
        .duration_since(UNIX_EPOCH)?
        .as_secs();
    assert_eq!(whole_seconds, seconds);
    Ok(())
}

/// Pins that the same message is refused as stale a day later, as a replay when read twice, and with the wrong key.
#[test]
fn mit_forwarded_tgt_is_checked_for_time_replay_and_key() -> Result<(), TestError> {
    let sent = decrypt_krb_cred_enc_part(&decode(&wire()?)?, &key()?)?
        .timestamp
        .context("MIT always sets the timestamp")?;
    let seconds = u64::try_from(sent.0.timestamp())?;

    let mut stale = AuthContext::new(key()?, MessagePolicy::new())
        .with_now(at(seconds.saturating_add(86_400))?);
    let late = stale.rd_cred(&wire()?, CredentialTransport::Encrypted);
    assert!(
        matches!(late, Err(Error::ClockSkew { max_clock_skew: _ })),
        "{late:?}"
    );

    let mut twice = AuthContext::new(key()?, MessagePolicy::new()).with_now(at(seconds)?);
    let first = twice.rd_cred(&wire()?, CredentialTransport::Encrypted)?;
    assert_eq!(first.content().len(), 1);
    let again = twice.rd_cred(&wire()?, CredentialTransport::Encrypted);
    assert!(matches!(again, Err(Error::Replay)), "{again:?}");

    let other = EncryptionKey::new(18, vec![0x77; 32]);
    let mut wrong = AuthContext::new(other, MessagePolicy::new()).with_now(at(seconds)?);
    let refused = wrong.rd_cred(&wire()?, CredentialTransport::Encrypted);
    assert!(matches!(refused, Err(Error::Cred(_))), "{refused:?}");

    let channel = ProtectedChannel::vouch("an unrelated channel");
    let mut plain = AuthContext::without_key(MessagePolicy::new()).with_now(at(seconds)?);
    let unprotected = plain.rd_cred(&wire()?, CredentialTransport::Protected(&channel));
    assert!(matches!(unprotected, Err(Error::NoKey)), "{unprotected:?}");
    Ok(())
}

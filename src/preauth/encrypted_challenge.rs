//! The encrypted-challenge FAST factor (RFC 6113 section 5.4.6, MIT
//! `preauth_ec.c`): the client proves its long-term key inside FAST and the
//! KDC proves it back.
//!
//! The challenge keys are `KRB-FX-CF2(armor key, long-term key,
//! "clientchallengearmor" | "kdcchallengearmor", "challengelongterm")`. The
//! client encrypts a `PA-ENC-TS-ENC` in its key (usage 54); the KDC answers
//! with its time in the KDC key (usage 55).
//!
//! # Security
//!
//! The stepwise exchange uses this factor only inside an armored exchange,
//! and requires the KDC's `PA-ENCRYPTED-CHALLENGE` to decrypt and the reply
//! key to be strengthened before it releases the credential (RFC 6113 section
//! 5.4.6: "The KDC MUST strengthen the reply key", "The client MUST check that
//! the timestamp decrypts properly"). MIT 1.22.2 checks the KDC's challenge
//! only when one is present (`preauth_ec.c:64-95`); this is stricter. Both
//! keys are distinct owning [`EncryptionKey`]s erased when dropped.

use core::{fmt, time::Duration};
use std::time::{SystemTime, UNIX_EPOCH};

use rasn::types::Integer;
use rasn_kerberos::{EncryptedData, KerberosTime, PaData, PaEncTsEnc};

use super::fast::{
    PA_ENCRYPTED_CHALLENGE,
    keys::{cf2, decode, encode, open, seal},
};
use crate::{error::Fast as Error, keytab::EncryptionKey};

/// `KEY_USAGE_ENC_CHALLENGE_CLIENT`.
pub const KEY_USAGE_ENC_CHALLENGE_CLIENT: u32 = 54;
/// `KEY_USAGE_ENC_CHALLENGE_KDC`.
pub const KEY_USAGE_ENC_CHALLENGE_KDC: u32 = 55;

/// The two challenge keys of one armor key and one long-term key. Its
/// `Debug` output names no key.
pub struct EncryptedChallenge {
    /// The client challenge key.
    client_key: EncryptionKey,
    /// The KDC challenge key.
    kdc_key: EncryptionKey,
}

impl EncryptedChallenge {
    /// Derive the challenge keys of `armor_key` and the client's `long_term_key`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedEtype`] or the PRF failure.
    #[inline]
    pub fn new(armor_key: &EncryptionKey, long_term_key: &EncryptionKey) -> Result<Self, Error> {
        Ok(Self {
            client_key: cf2(
                (armor_key, b"clientchallengearmor"),
                (long_term_key, b"challengelongterm"),
            )?,
            kdc_key: cf2(
                (armor_key, b"kdcchallengearmor"),
                (long_term_key, b"challengelongterm"),
            )?,
        })
    }

    /// The client's `PA-ENCRYPTED-CHALLENGE` for the KDC time `at` (whole
    /// seconds) and `usec` microseconds.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Codec`] for a time before the epoch or a fractional
    /// second, and the encryption errors.
    #[inline]
    pub fn padata(&self, (at, usec): (SystemTime, u32)) -> Result<PaData, Error> {
        let fractional = Error::Malformed {
            structure: "PA-ENC-TS-ENC",
            reason: "the time is not a whole second after the epoch",
        };
        let since = at
            .duration_since(UNIX_EPOCH)
            .map_err(|_before| Error::Malformed {
                structure: "PA-ENC-TS-ENC",
                reason: "the time is before the epoch",
            })?;
        if since.subsec_nanos() != 0 || usec >= 1_000_000 {
            return Err(fractional);
        }
        let whole = UNIX_EPOCH
            .checked_add(Duration::from_secs(since.as_secs()))
            .ok_or(fractional)?;
        let timestamp = PaEncTsEnc {
            patimestamp: KerberosTime(chrono::DateTime::<chrono::Utc>::from(whole).into()),
            pausec: Some(Integer::from(usec)),
        };
        let plain = encode("PA-ENC-TS-ENC", &timestamp)?;
        let sealed = seal(&self.client_key, KEY_USAGE_ENC_CHALLENGE_CLIENT, &plain)?;
        Ok(PaData {
            r#type: PA_ENCRYPTED_CHALLENGE,
            value: encode("EncryptedChallenge", &sealed)?.to_vec().into(),
        })
    }

    /// Verify the KDC's `PA-ENCRYPTED-CHALLENGE` in the reply `padata`: it must
    /// be present once, decrypt in the KDC challenge key and hold a
    /// `PA-ENC-TS-ENC`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ChallengeReply`] when it is missing, repeated or does
    /// not decrypt, and [`Error::Codec`] when it does not decode.
    #[inline]
    pub fn verify_reply(&self, padata: &[PaData]) -> Result<(), Error> {
        let mut entries = padata
            .iter()
            .filter(|entry| entry.r#type == PA_ENCRYPTED_CHALLENGE);
        let (Some(entry), None) = (entries.next(), entries.next()) else {
            return Err(Error::ChallengeReply {
                what: "exactly one PA-ENCRYPTED-CHALLENGE",
            });
        };
        let encrypted: EncryptedData = decode("EncryptedChallenge", &entry.value)?;
        let plain = open(&self.kdc_key, KEY_USAGE_ENC_CHALLENGE_KDC, &encrypted).map_err(
            |_undecryptable| Error::ChallengeReply {
                what: "a PA-ENCRYPTED-CHALLENGE that decrypts in the KDC challenge key",
            },
        )?;
        decode::<PaEncTsEnc>("PA-ENC-TS-ENC", &plain).map(drop)
    }
}

impl fmt::Debug for EncryptedChallenge {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedChallenge")
            .field("etype", &self.client_key.etype())
            .finish_non_exhaustive()
    }
}

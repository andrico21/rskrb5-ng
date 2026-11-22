//! The PAC API: explicit verification policy, verified state, the builder and its signatures,
//! PAC attributes and `PA-PAC-REQUEST` (plan 2 todo 22, WP-14).
//!
//! The vectors come from the independent generator `tests/fixtures/pac/generate.py` (RFC 3961 and
//! 3962 checksums, the MS-PAC layout and MIT's signing order); the live counterparts are the
//! `interop_pac` and `interop_pac_samba` suites.
#![cfg(feature = "messages")]

/// The gokrb5 `AD_WIN2K` PAC and the service keytab that verifies it.
#[path = "support/pac_ad_win2k.rs"]
mod pac_ad_win2k;

/// The PAC and ticket captured from MIT krb5 1.22.2.
#[path = "support/pac_mit_capture.rs"]
mod pac_mit_capture;

/// The independently generated PAC vectors and keys.
#[path = "support/pac_vectors.rs"]
mod pac_vectors;

/// The PAC API tests.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod pac_api {
    mod acceptor;
    mod builder;
    mod identity;
    mod mit_fixture;
    mod pac_ticket;
    mod parsing;
    mod regressions;
    mod request;
    mod verification;

    use core::{error::Error, time::Duration};
    use std::time::{SystemTime, UNIX_EPOCH};

    use rskrb5_ng::{keytab::EncryptionKey, pac::ClientBinding};

    use super::pac_vectors;

    /// Decode one generated vector.
    fn vector(hex_text: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        Ok(hex::decode(hex_text)?)
    }

    /// The aes256 service key of the vectors.
    fn server_key() -> Result<EncryptionKey, Box<dyn Error>> {
        Ok(EncryptionKey::new(
            18,
            vector(pac_vectors::SERVER_KEY_AES256)?,
        ))
    }

    /// The aes256 KDC key of the vectors.
    fn kdc_key() -> Result<EncryptionKey, Box<dyn Error>> {
        Ok(EncryptionKey::new(18, vector(pac_vectors::KDC_KEY_AES256)?))
    }

    /// The client the vectors describe, at `auth_time` seconds after the Unix epoch.
    fn client_at(name: &str, auth_time: u64) -> Result<ClientBinding, Box<dyn Error>> {
        let time: SystemTime = UNIX_EPOCH
            .checked_add(Duration::from_secs(auth_time))
            .ok_or("time")?;
        Ok(ClientBinding::new(name, time))
    }

    /// `pacuser` at the authentication time of the vectors.
    fn client() -> Result<ClientBinding, Box<dyn Error>> {
        client_at("pacuser", pac_ticket::AUTH_TIME)
    }
}

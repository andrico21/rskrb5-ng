//! Fuzz the authenticated message readers and the checked DER utilities.
//!
//! The first input byte selects the entry point. Modes 0 to 3 give the rest to
//! a fresh `AuthContext` (fixed key, fixed clock, sequence checking on) as a
//! KRB-PRIV, a KRB-SAFE, an encrypted KRB-CRED and a KRB-CRED over a vouched
//! channel; mode 4 reads it through the public DER length, element and
//! application-tag utilities, and mode 5 through the AD-KDC-ISSUED and
//! AD-AND-OR decoders. A message the context accepts must be one it could
//! also have made (a second read of it is refused). None may panic.

#![no_main]

use core::time::Duration;
use std::time::UNIX_EPOCH;

use libfuzzer_sys::fuzz_target;
use rskrb5_ng::{
    asn1::{Limits, application_tag, decode_length, read_element, validate},
    authdata::{decode_and_or, decode_kdc_issued},
    keytab::EncryptionKey,
    messages::{AuthContext, CredentialTransport, MessagePolicy, ProtectedChannel},
};

/// A fresh context at a fixed time under a fixed key.
fn context() -> AuthContext {
    AuthContext::new(
        EncryptionKey::new(18, vec![0x42; 32]),
        MessagePolicy::new().checking_sequence(true),
    )
    .with_now(
        UNIX_EPOCH
            .checked_add(Duration::from_hours(500_000))
            .unwrap_or(UNIX_EPOCH),
    )
}

/// Read `input` as a KRB-PRIV or KRB-SAFE and require a second read to fail.
///
/// # Panics
///
/// Panics when an accepted message is accepted twice.
fn private_or_safe(input: &[u8], private: bool) {
    let mut reader = context();
    let first = if private {
        reader.rd_priv(input).is_ok()
    } else {
        reader.rd_safe(input).is_ok()
    };
    if first {
        let second = if private {
            reader.rd_priv(input).is_ok()
        } else {
            reader.rd_safe(input).is_ok()
        };
        assert!(!second, "an accepted message was accepted twice");
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((selector, input)) = data.split_first() else {
        return;
    };
    match selector.rem_euclid(6) {
        0 => private_or_safe(input, true),
        1 => private_or_safe(input, false),
        2 => drop(context().rd_cred(input, CredentialTransport::Encrypted)),
        3 => {
            let channel = ProtectedChannel::vouch("fuzz");
            drop(
                AuthContext::without_key(MessagePolicy::new())
                    .rd_cred(input, CredentialTransport::Protected(&channel)),
            );
        }
        4 => {
            let limits = Limits::new().with_max_length(0x0010_0000);
            drop(decode_length(input, &limits));
            drop(read_element(input, &limits));
            drop(application_tag(input, &limits));
            drop(validate(input, &limits));
        }
        _ => {
            drop(decode_kdc_issued(input));
            drop(decode_and_or(input));
        }
    }
});

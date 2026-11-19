//! Fuzz the Camellia-CTS-CMAC decrypt, checksum-verify and string-to-key paths of
//! RFC 6803 on arbitrary input.
//!
//! The low two bits of the first byte select the entry point and the third bit
//! picks camellia128 or camellia256; the second byte is the key usage and the rest
//! is the input under a fixed protocol key: a raw message to decrypt (and a sealed
//! copy of it, which must round-trip and fail once its MAC changes), a checksum
//! split from its data (verified, then recomputed), raw CTS ciphertext, or the
//! `s2kparams` text of string-to-key. None may panic, and a round trip that
//! changes a value is a failure.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rskrb5_ng::{
    crypto::{camellia::CtsCmacEtype, s2kparams_to_iterations},
    error::Crypto,
};

/// The confounder of the sealed mode, one block as RFC 6803 section 3 sizes it.
const CONFOUNDER: [u8; 16] = [0x24; 16];
/// One protocol key long enough for both enctypes; each uses its own prefix.
const KEY: [u8; 32] = [0x42; 32];
/// The largest work factor string-to-key runs here; larger counts are refused or too slow to fuzz.
const MAX_FUZZED_ITERATIONS: u32 = 64;

/// Decrypt `input` as received, then seal it and check the round trip and the MAC.
///
/// # Panics
/// Panics when sealing fails, when the sealed message does not decrypt to `input`, or
/// when a changed MAC is accepted.
fn messages(etype: CtsCmacEtype, key: &[u8], input: &[u8], usage: u32) {
    let _verdict = etype.decrypt_message(key, input, usage);
    let result = etype.encrypt_message_with_confounder(key, input, usage, &CONFOUNDER);
    assert!(result.is_ok(), "sealing a message failed");
    let Ok(mut sealed) = result else {
        return;
    };
    assert_eq!(
        etype.decrypt_message(key, &sealed, usage),
        Ok(input.to_vec()),
        "a sealed message must decrypt to its plaintext"
    );
    if let Some(last) = sealed.last_mut() {
        *last ^= 1;
    }
    assert_eq!(
        etype.decrypt_message(key, &sealed, usage),
        Err(Crypto::IntegrityCheckFailed),
        "a changed MAC must be refused"
    );
}

/// Verify a checksum split from its data, then verify the one the key computes.
///
/// # Panics
/// Panics when the computed checksum is refused or a changed one is accepted.
fn checksums(etype: CtsCmacEtype, key: &[u8], input: &[u8], usage: u32) {
    let Some((&cut, rest)) = input.split_first() else {
        return;
    };
    let (received, data) = rest
        .split_at_checked(usize::from(cut))
        .unwrap_or((rest, &[]));
    let _verdict = etype.verify_checksum(key, data, received, usage);
    let result = etype.checksum(key, data, usage);
    assert!(result.is_ok(), "computing a checksum failed");
    let Ok(mut computed) = result else {
        return;
    };
    assert!(
        etype.verify_checksum(key, data, &computed, usage),
        "the computed checksum must verify"
    );
    if let Some(first) = computed.first_mut() {
        *first ^= 1;
    }
    assert!(
        !etype.verify_checksum(key, data, &computed, usage),
        "a changed checksum must be refused"
    );
}

/// Decrypt raw CTS ciphertext; an accepted ciphertext must encrypt back to itself.
///
/// # Panics
/// Panics when the round trip changes the ciphertext.
fn cts(etype: CtsCmacEtype, key: &[u8], input: &[u8]) {
    if let Ok(plaintext) = etype.decrypt_data(key, input) {
        assert_eq!(
            etype.encrypt_data(key, &plaintext).map(|(_, again)| again),
            Ok(input.to_vec()),
            "CTS decryption must invert CTS encryption"
        );
    }
}

/// Derive a key from the `s2kparams` text, running only counts small enough to fuzz.
fn string_to_key(etype: CtsCmacEtype, input: &[u8]) {
    let text = String::from_utf8_lossy(input);
    if s2kparams_to_iterations(&text).is_ok_and(|iterations| iterations > MAX_FUZZED_ITERATIONS) {
        return;
    }
    drop(etype.string_to_key(b"fuzz secret", b"fuzz salt", &text));
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let Some((&usage, input)) = rest.split_first() else {
        return;
    };
    let Some(etype) = CtsCmacEtype::from_etype_id(if selector & 0x04 == 0 { 25 } else { 26 })
    else {
        return;
    };
    let Some(key) = KEY.get(..etype.key_len()) else {
        return;
    };
    match selector & 0x03 {
        0 => messages(etype, key, input, u32::from(usage)),
        1 => checksums(etype, key, input, u32::from(usage)),
        2 => cts(etype, key, input),
        _ => string_to_key(etype, input),
    }
});

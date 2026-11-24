//! Fuzz the import of context and credential transfer blobs.
//!
//! Bit 0 of the first byte picks a context or a credential import. Without
//! bit 1 the rest is a blob as received; with it the rest is a payload that
//! is sealed as the documented version-1 format does it (header `"GSSX" |
//! version | kind | transfer id | export time`, then the RFC 8009
//! `aes256-cts-hmac-sha384-192` encryption of header and payload under a fixed
//! transfer key, key usage `0x47535831`), so the payload decoder behind the
//! authentication runs. Every import goes through one ledger per run, and a
//! second import of the same blob must fail. None may panic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rskrb5_ng::{
    crypto::AesSha2Etype,
    gss::{Credential, EstablishedContext, MemoryTransferLedger, TransferBlob, TransferKey},
};

/// The fixed transfer key.
const KEY: [u8; 32] = [0x42; 32];

/// The key usage of the transfer format.
const USAGE: u32 = 0x4753_5831;

/// `payload` sealed as a version-1 blob of `kind`.
fn sealed(kind: u8, payload: &[u8]) -> Option<Vec<u8>> {
    let mut header = b"GSSX".to_vec();
    header.extend_from_slice(&[1, kind]);
    header.extend_from_slice(&[7; 16]);
    header.extend_from_slice(&1_700_000_000_u64.to_be_bytes());
    let plaintext = [header.as_slice(), payload].concat();
    let ciphertext = AesSha2Etype::Aes256
        .encrypt_message_with_confounder(&KEY, &plaintext, USAGE, &[0; 16])
        .ok()?;
    Some([header, ciphertext].concat())
}

fuzz_target!(|data: &[u8]| {
    let Some((selector, input)) = data.split_first() else {
        return;
    };
    let kind = if selector & 0x01 == 0 { 1 } else { 2 };
    let bytes = if selector & 0x02 == 0 {
        input.to_vec()
    } else {
        let Some(blob) = sealed(kind, input) else {
            return;
        };
        blob
    };
    let blob = TransferBlob::from_bytes(bytes);
    let key = TransferKey::new(KEY);
    let mut ledger = MemoryTransferLedger::new();
    let accepted = if kind == 1 {
        EstablishedContext::import(&blob, &key, &mut ledger).map(|context| drop(context.inquire()))
    } else {
        Credential::import(&blob, &key, &mut ledger).map(|credential| drop(credential.inquire()))
    };
    if accepted.is_ok() {
        let again = if kind == 1 {
            EstablishedContext::import(&blob, &key, &mut ledger).is_ok()
        } else {
            Credential::import(&blob, &key, &mut ledger).is_ok()
        };
        assert!(!again, "a consumed transfer id was imported twice");
    }
});

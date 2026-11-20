//! Fuzz the PA-SPAKE codec and the SPAKE client half on an arbitrary KDC value.
//!
//! Every input is decoded twice with `Message::decode`, which must agree. Then
//! a fresh `Client` that permits all four groups answers the input as the first
//! PA-SPAKE value of an exchange: an empty or out-of-policy value gets a
//! support message, a challenge in a permitted group a response, which decodes
//! the KDC element of edwards25519, P-256, P-384 or P-521 and derives the keys.
//! It answers the same input once more, as the value after that one. None may
//! panic, and a second challenge is never answered.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rskrb5_ng::{
    error::Spake,
    keytab::EncryptionKey,
    preauth::spake::{Client, Group, Message, Policy, Step},
};

fuzz_target!(|data: &[u8]| {
    let first = Message::decode(data);
    let second = Message::decode(data);
    assert_eq!(first.is_ok(), second.is_ok(), "decode is deterministic");
    if let (Ok(left), Ok(right)) = (&first, &second) {
        assert_eq!(left, right, "decode is deterministic");
    }
    let key = EncryptionKey::new(18, vec![0x42; 32]);
    let mut client = Client::new(Policy::new(Group::ALL));
    let answered = client.process(data, b"kdc-req-body", || Ok::<_, Spake>(key.clone()));
    let responded = matches!(
        answered,
        Ok(Step::Response {
            padata: _,
            reply_key: _
        })
    );
    let again = client.process(data, b"kdc-req-body", || Ok::<_, Spake>(key.clone()));
    if responded {
        assert!(again.is_err(), "a second challenge is never answered");
    }
});

//! Fuzz the `PA-OTP-CHALLENGE` decoder and the OTP request builder behind it.
//!
//! Every input is decoded twice with `Challenge::decode`, which must agree, once
//! more under a tight policy, and an accepted challenge then answers every token
//! (and one index beyond the list) with a plain value and with a value and a PIN
//! under an AES256 armor key. None may panic, and every built request is an
//! OTP padata of the request type.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rskrb5_ng::{
    keytab::EncryptionKey,
    preauth::otp::{Challenge, PA_OTP_REQUEST, Policy, Response},
};

fuzz_target!(|data: &[u8]| {
    let policy = Policy::default();
    let first = Challenge::decode(data, &policy);
    let second = Challenge::decode(data, &policy);
    assert_eq!(first.is_ok(), second.is_ok(), "decode is deterministic");
    if let (Ok(left), Ok(right)) = (&first, &second) {
        assert_eq!(left, right, "decode is deterministic");
    }
    let tight = Policy::default()
        .with_max_tokens(2)
        .with_max_field_bytes(8)
        .with_max_challenge_bytes(64);
    drop(Challenge::decode(data, &tight));
    let Ok(challenge) = first else {
        return;
    };
    let key = EncryptionKey::new(18, vec![0x42; 32]);
    for index in 0..=challenge.tokens().len() {
        let plain = Response::new(index, b"123456".to_vec());
        let pinned = Response::new(index, b"000000".to_vec()).with_pin("4242".to_owned());
        for response in [plain, pinned] {
            if let Ok(padata) = challenge.request(&response, &key, &policy) {
                assert_eq!(padata.r#type, PA_OTP_REQUEST, "an OTP request");
            }
        }
    }
});

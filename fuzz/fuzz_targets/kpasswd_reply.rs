//! Fuzz the kadmin frame parsers on arbitrary input: `Reply`,
//! `ChangePasswordResult` (numeric result code and raw result text) and `Request`.
//! None may panic; every input must return `Ok`/`Err`.
//! An accepted reply is also processed the way the password-change client
//! reads it: the KRB-ERROR or KRB-PRIV result is decrypted and the AP-REP is
//! verified against a fixed request built from synthetic keys.

#![no_main]

use core::time::Duration;
use std::time::SystemTime;

use libfuzzer_sys::fuzz_target;
use rskrb5_ng::{
    Principal,
    client::{
        AsRepSession, Password,
        kpasswd::{self, BuiltKpasswdRequest, RequestOptions},
    },
    kadmin::{ChangePasswdData, ChangePasswordResult, Reply, Request},
    keytab::EncryptionKey,
    krb_priv,
};

/// The AES256 key of the gokrb5 test vectors: session and reply key.
const KEY: [u8; 32] = [
    0x9c, 0xad, 0x00, 0xbb, 0xc7, 0x2d, 0x70, 0x32, 0x58, 0xe9, 0x11, 0xdc, 0x18, 0xe6, 0xd5, 0x48,
    0x7c, 0xf7, 0x37, 0xbf, 0x67, 0xfd, 0x11, 0x1f, 0x0c, 0x24, 0x63, 0xad, 0x60, 0x33, 0xbf, 0x51,
];

/// A DER Ticket from the gokrb5 test vectors, carried by the kadmin session.
const TICKET: &[u8] = include_bytes!("../fixtures/ticket.der");

/// AES256-CTS-HMAC-SHA1-96.
const AES256: i32 = 18;

/// Fixed request time, so every run builds the same request.
const NOW: Duration = Duration::from_secs(1_893_553_447);

/// A fixed password-change request under [`KEY`].
fn request() -> Option<BuiltKpasswdRequest> {
    let now = SystemTime::UNIX_EPOCH.checked_add(NOW)?;
    let end = now.checked_add(Duration::from_secs(36_000))?;
    let key = EncryptionKey::new(AES256, KEY.to_vec());
    let session = AsRepSession::new(
        Principal::user("TEST.GOKRB5", "testuser1"),
        Principal::new("TEST.GOKRB5", 2, ["kadmin", "changepw"]),
        key.clone(),
        TICKET.to_vec().into(),
        [0x40, 0xe1, 0x00, 0x00],
        now,
        end,
    );
    let options = RequestOptions::new(now, 0, 1, krb_priv::ipv4_host_address([127, 0, 0, 1]));
    kpasswd::build_kpasswd_request_with_confounders(
        &session,
        &ChangePasswdData::new(Password::copy_from_str("new password")),
        key,
        &options,
        &[0; 16],
        &[0; 16],
    )
    .ok()
}

fuzz_target!(|data: &[u8]| {
    // Only returning matters: a rejected input is the `Err` arm, and an
    // accepted one is dropped unused.
    if let Ok(reply) = Reply::parse(data) {
        drop(reply.decrypt_result(&EncryptionKey::new(AES256, KEY.to_vec())));
        if let Some(built) = request() {
            drop(kpasswd::verify_kpasswd_ap_rep(&reply, &built));
        }
    }
    if let Ok(result) = ChangePasswordResult::parse(data) {
        drop(result);
    }
    if let Ok(request) = Request::parse(data) {
        drop(request);
    }
});

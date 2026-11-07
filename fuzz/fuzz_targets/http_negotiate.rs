//! Fuzz the HTTP Negotiate header handling on both sides of the exchange.
//!
//! An even first input byte makes the rest the `Authorization` header of a
//! request the service accepts with a validator holding a synthetic test
//! keytab. An odd one splits the rest at newlines into `WWW-Authenticate`
//! header values of a response the client reads: challenge selection, the
//! response classification and the AP-REP verification of an initiator
//! context built from synthetic keys. None may panic.

#![no_main]

use core::time::Duration;
use std::time::SystemTime;

use libfuzzer_sys::fuzz_target;
use rskrb5_ng::{
    Principal,
    client::AsRepSession,
    http,
    keytab::{EncryptionKey, Keytab},
    service::Validator,
    spnego::{self, InitiatorContext, InitiatorContextOptions},
};

/// The synthetic `HTTP/host.test.gokrb5` keytab of the service tests.
const HTTP_KEYTAB: &[u8] = include_bytes!("../fixtures/http.keytab");

/// A DER Ticket from the gokrb5 test vectors, carried by the client session.
const TICKET: &[u8] = include_bytes!("../fixtures/ticket.der");

/// The AES256 key of the gokrb5 AP-REP vectors, used as the session key.
const SESSION_KEY: [u8; 32] = [
    0x9c, 0xad, 0x00, 0xbb, 0xc7, 0x2d, 0x70, 0x32, 0x58, 0xe9, 0x11, 0xdc, 0x18, 0xe6, 0xd5, 0x48,
    0x7c, 0xf7, 0x37, 0xbf, 0x67, 0xfd, 0x11, 0x1f, 0x0c, 0x24, 0x63, 0xad, 0x60, 0x33, 0xbf, 0x51,
];

/// AES256-CTS-HMAC-SHA1-96.
const AES256: i32 = 18;

/// Fixed time: the service tests' validation time and the context's clock.
const NOW: Duration = Duration::from_secs(1_893_553_447);

/// A default value of an inferred type: the request type is only reachable
/// through the crate's signatures, not by name.
fn fresh<T>() -> T
where
    T: Default,
{
    T::default()
}

/// Accept `header` as the `Authorization` header of a request.
fn server(header: &str) {
    let Ok(keytab) = Keytab::parse(HTTP_KEYTAB) else {
        return;
    };
    let Some(now) = SystemTime::UNIX_EPOCH.checked_add(NOW) else {
        return;
    };
    let mut validator = Validator::new(&keytab)
        .with_now(now)
        .without_shared_replay_cache();
    let mut request = fresh();
    if http::set_authorization_header::<()>(&mut request, header).is_ok() {
        drop(http::accept_request(&mut validator, &mut request));
    }
}

/// An initiator context for a fixed service session.
fn initiator() -> Option<InitiatorContext> {
    let now = SystemTime::UNIX_EPOCH.checked_add(NOW)?;
    let end = now.checked_add(Duration::from_secs(36_000))?;
    let session = AsRepSession::new(
        Principal::user("TEST.GOKRB5", "testuser1"),
        Principal::new("TEST.GOKRB5", 2, ["HTTP", "host.test.gokrb5"]),
        EncryptionKey::new(AES256, SESSION_KEY.to_vec()),
        TICKET.to_vec().into(),
        [0x40, 0xe1, 0x00, 0x00],
        now,
        end,
    );
    let options = InitiatorContextOptions::new().with_sequence_number(Some(1));
    spnego::init_sec_context_with_confounder(&session, options, now, 0, &[0; 16]).ok()
}

/// Read the newline-separated `values` as `WWW-Authenticate` headers.
fn client(values: &[u8]) {
    let Some(context) = initiator() else {
        return;
    };
    let mut response = http::challenge_response::<()>();
    let headers = response.headers_mut();
    headers.clear();
    for line in values.split(|byte| *byte == b'\n') {
        if let Ok(value) = line.try_into() {
            let _: bool = headers.append("www-authenticate", value);
        }
    }
    drop(http::www_authenticate_negotiate_header(&response));
    drop(http::classify_negotiate_response(&context, &response));
    drop(http::verify_ap_rep_response(&context, &response));
}

fuzz_target!(|data: &[u8]| {
    let Some((selector, input)) = data.split_first() else {
        return;
    };
    if selector & 0x01 == 0 {
        server(&String::from_utf8_lossy(input));
    } else {
        client(input);
    }
});

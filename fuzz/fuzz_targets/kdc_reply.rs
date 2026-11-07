//! Fuzz the KDC reply decoders and the client reply processing.
//!
//! The first input byte selects the entry point and the rest is its input:
//! the AS-REP, TGS-REP, `EncKDCRepPart`, KRB-ERROR and METHOD-DATA decoders,
//! the client's KRB-ERROR processing (with preauthentication hint selection
//! and `s2kparams` parsing), AS-REP/TGS-REP processing against fixed
//! requests built from a synthetic test key, and structured replies whose
//! fuzzed `EncKDCRepPart` is encrypted under that key so the checks behind
//! decryption are reached. None may panic.

#![no_main]

use core::time::Duration;
use std::time::SystemTime;

use libfuzzer_sys::fuzz_target;
use rskrb5_ng::{
    Principal,
    client::{
        self, AsRepSession,
        options::{AsReq, TgsReq},
    },
    crypto, kdc_rep,
    keytab::EncryptionKey,
    krb_error,
};

/// The AES256 reply key of the gokrb5 test vectors.
const REPLY_KEY: [u8; 32] = [
    0x9c, 0xad, 0x00, 0xbb, 0xc7, 0x2d, 0x70, 0x32, 0x58, 0xe9, 0x11, 0xdc, 0x18, 0xe6, 0xd5, 0x48,
    0x7c, 0xf7, 0x37, 0xbf, 0x67, 0xfd, 0x11, 0x1f, 0x0c, 0x24, 0x63, 0xad, 0x60, 0x33, 0xbf, 0x51,
];

/// The AES256 TGT session key of the client test vectors.
const SESSION_KEY: [u8; 32] = [
    0x88, 0x45, 0xcb, 0xac, 0xcb, 0xf1, 0x1c, 0xb9, 0xf4, 0x67, 0xfd, 0x57, 0x7b, 0xa5, 0x1c, 0x70,
    0xd7, 0x3d, 0xe6, 0x55, 0x49, 0x80, 0xa0, 0x53, 0x95, 0xbf, 0x31, 0x9e, 0x18, 0xbd, 0xda, 0x07,
];

/// A DER Ticket from the gokrb5 test vectors, carried as the TGT.
const TICKET: &[u8] = include_bytes!("../fixtures/ticket.der");

/// The gokrb5 AS-REP vector, the template of the structured AS mode.
const AS_REP: &[u8] = include_bytes!("../fixtures/as_rep.der");

/// The gokrb5 TGS-REP vector, the template of the structured TGS mode.
const TGS_REP: &[u8] = include_bytes!("../fixtures/tgs_rep.der");

/// A fixed confounder, so every run encrypts the same bytes.
const CONFOUNDER: [u8; 16] = [0x44; 16];

/// The nonce of the gokrb5 `EncKDCRepPart` vector.
const TEMPLATE_NONCE: u32 = 42;

/// AES256-CTS-HMAC-SHA1-96.
const AES256: i32 = 18;

/// Fixed request time, so every run builds the same requests.
const NOW: Duration = Duration::from_secs(1_893_553_447);

/// The enctypes a client offers when it selects a preauthentication hint.
const REQUESTED_ETYPES: [i32; 3] = [18, 17, 23];

/// The fixed client principal of the requests.
fn client_principal() -> Principal {
    Principal::user("TEST.GOKRB5", "testuser1")
}

/// Process `input` as an AS-REP answering a fixed AS-REQ.
fn process_as_rep(input: &[u8]) {
    let Some(now) = SystemTime::UNIX_EPOCH.checked_add(NOW) else {
        return;
    };
    let Ok(request) = client::build_tgt_as_req(client_principal(), AsReq::new(now, 1)) else {
        return;
    };
    let key = EncryptionKey::new(AES256, REPLY_KEY.to_vec());
    drop(client::process_as_rep(&request, input, &key));
}

/// Process `input` as a TGS-REP answering a fixed TGS-REQ, with and without
/// referrals permitted.
fn process_tgs_rep(input: &[u8]) {
    let Some(now) = SystemTime::UNIX_EPOCH.checked_add(NOW) else {
        return;
    };
    let Some(end) = now.checked_add(Duration::from_secs(36_000)) else {
        return;
    };
    let session_key = EncryptionKey::new(AES256, SESSION_KEY.to_vec());
    let tgt = AsRepSession::new(
        client_principal(),
        Principal::tgt_service("TEST.GOKRB5"),
        session_key.clone(),
        TICKET.to_vec().into(),
        [0x40, 0xe1, 0x00, 0x00],
        now,
        end,
    );
    let service = Principal::new("TEST.GOKRB5", 2, ["HTTP", "host.test.gokrb5"]);
    let Ok(request) =
        client::build_tgs_req_with_confounder(&tgt, service, TgsReq::new(now, 1), now, 0, &[0; 16])
    else {
        return;
    };
    drop(client::process_tgs_rep(&request, input, &session_key));
    drop(client::process_tgs_rep_with_referral(
        &request,
        input,
        &session_key,
    ));
}

/// The client and service principal of the gokrb5 reply vectors.
fn template_principal() -> Principal {
    Principal::new("ATHENA.MIT.EDU", 1, ["hftsai", "extra"])
}

/// Encrypt a fuzzed `EncASRepPart` into the AS-REP template and process it
/// against an AS-REQ for the template's client, service and nonce.
fn structured_as_rep(input: &[u8]) -> Option<()> {
    let enc_part = kdc_rep::decode_enc_kdc_rep_part(input).ok()?;
    let mut reply = kdc_rep::decode_as_rep(AS_REP).ok()?;
    let key = EncryptionKey::new(AES256, REPLY_KEY.to_vec());
    reply.0.enc_part =
        kdc_rep::encrypt_as_rep_enc_part_with_confounder(&enc_part, &key, None, &CONFOUNDER)
            .ok()?;
    let now = SystemTime::UNIX_EPOCH.checked_add(NOW)?;
    let request = client::build_as_req(
        template_principal(),
        template_principal(),
        AsReq::new(now, TEMPLATE_NONCE),
    )
    .ok()?;
    drop(client::process_as_rep(
        &request,
        &kdc_rep::encode_as_rep(&reply).ok()?,
        &key,
    ));
    Some(())
}

/// Encrypt a fuzzed `EncTGSRepPart` into the TGS-REP template and process it
/// against a TGS-REQ for the template's client, service and nonce.
fn structured_tgs_rep(input: &[u8]) -> Option<()> {
    let enc_part = kdc_rep::decode_enc_kdc_rep_part(input).ok()?;
    let mut reply = kdc_rep::decode_tgs_rep(TGS_REP).ok()?;
    let session_key = EncryptionKey::new(AES256, SESSION_KEY.to_vec());
    reply.0.enc_part = kdc_rep::encrypt_tgs_rep_enc_part_with_confounder(
        &enc_part,
        &session_key,
        None,
        &CONFOUNDER,
    )
    .ok()?;
    let now = SystemTime::UNIX_EPOCH.checked_add(NOW)?;
    let end = now.checked_add(Duration::from_secs(36_000))?;
    let tgt = AsRepSession::new(
        template_principal(),
        Principal::tgt_service("ATHENA.MIT.EDU"),
        session_key.clone(),
        TICKET.to_vec().into(),
        [0x40, 0xe1, 0x00, 0x00],
        now,
        end,
    );
    let request = client::build_tgs_req_with_confounder(
        &tgt,
        template_principal(),
        TgsReq::new(now, TEMPLATE_NONCE),
        now,
        0,
        &CONFOUNDER,
    )
    .ok()?;
    let bytes = kdc_rep::encode_tgs_rep(&reply).ok()?;
    drop(client::process_tgs_rep(&request, &bytes, &session_key));
    drop(client::process_tgs_rep_with_referral(
        &request,
        &bytes,
        &session_key,
    ));
    Some(())
}

/// Process `input` as a KRB-ERROR the way the AS exchange reads a
/// preauthentication-required reply.
fn process_kdc_error(input: &[u8]) {
    let Ok(error) = client::process_kdc_error(input) else {
        return;
    };
    if let Ok(info) = client::select_preauth_key_info(&error, &REQUESTED_ETYPES)
        && let Some(s2kparams) = info.s2kparams
    {
        let hex: String = s2kparams
            .iter()
            .flat_map(|byte| [byte >> 4_u8, byte & 0x0f])
            .filter_map(|nibble| char::from_digit(u32::from(nibble), 16))
            .collect();
        let _: u32 = crypto::s2kparams_to_iterations(&hex).unwrap_or_default();
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((selector, input)) = data.split_first() else {
        return;
    };
    match selector & 0x0f {
        0 => drop(kdc_rep::decode_as_rep(input)),
        1 => drop(kdc_rep::decode_tgs_rep(input)),
        2 => drop(kdc_rep::decode_enc_kdc_rep_part(input)),
        3 => {
            drop(krb_error::decode(input));
            drop(krb_error::decode_krb_error_info(input));
            drop(krb_error::decode_method_data(input));
        }
        4 => process_kdc_error(input),
        5 => process_as_rep(input),
        6 => process_tgs_rep(input),
        8 => structured_as_rep(input).unwrap_or_default(),
        9 => structured_tgs_rep(input).unwrap_or_default(),
        _ => {
            if let Ok(error) = krb_error::decode(input) {
                drop(krb_error::preauth_method_data(&error, 25));
            }
        }
    }
});

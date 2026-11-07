//! Fuzz the RFC 4121 per-message tokens and the initiator's AP-REP checks.
//!
//! The low three bits of the first input byte select the entry point, the
//! next three pick a synthetic session key (AES128, RC4-HMAC, DES3, AES256,
//! AES128-SHA256 or AES256-SHA384) and the top one the expected sender; the
//! rest is the input: the Krb5
//! mechanism token, MIC decode and verify, Wrap decode with verify or unwrap,
//! a sealed Wrap whose fuzzed plaintext is encrypted under the key so the
//! checks behind decryption are reached, AP-REP verification by an initiator
//! context (raw and inside a Negotiate header), and a structured AP-REP whose
//! fuzzed `EncAPRepPart` is encrypted under the context's session key. None
//! may panic.

#![no_main]

mod session_ticket;

use core::time::Duration;
use std::time::SystemTime;

use libfuzzer_sys::fuzz_target;
use rskrb5_ng::{
    Config, Principal, ap_rep,
    client::AsRepSession,
    crypto::{CryptoPolicy, KerberosEtype},
    keytab::EncryptionKey,
    spnego::{
        self, GSSAPI_ACCEPTOR_SEAL_USAGE, GSSAPI_ACCEPTOR_SIGN_USAGE, GSSAPI_INITIATOR_SEAL_USAGE,
        GSSAPI_INITIATOR_SIGN_USAGE, InitiatorContext, InitiatorContextOptions, Krb5MechToken,
        MicToken, WrapToken,
    },
};

/// The AES128 session key of the gokrb5 GSS-API vectors.
const AES128_KEY: [u8; 16] = [
    0x14, 0xf9, 0xbd, 0xe6, 0xb5, 0x0e, 0xc5, 0x08, 0x20, 0x1a, 0x97, 0xf7, 0x4c, 0x4e, 0x5b, 0xd3,
];

/// The RC4-HMAC session key of the gokrb5 GSS-API vectors.
const RC4_KEY: [u8; 16] = [
    0xac, 0x8e, 0x65, 0x7f, 0x83, 0xdf, 0x82, 0xbe, 0xea, 0x5d, 0x43, 0xbd, 0xaf, 0x78, 0x00, 0xcc,
];

/// The DES3 session key of the gokrb5 GSS-API vectors.
const DES3_KEY: [u8; 24] = [
    0x85, 0x0b, 0xb5, 0x13, 0x58, 0x54, 0x8c, 0xd0, 0x5e, 0x86, 0x76, 0x8c, 0x31, 0x3e, 0x3b, 0xfe,
    0xf7, 0x51, 0x19, 0x37, 0xdc, 0xf7, 0x2c, 0x3e,
];

/// The AES256 key of the gokrb5 AP-REP vectors.
const AES256_KEY: [u8; 32] = [
    0x9c, 0xad, 0x00, 0xbb, 0xc7, 0x2d, 0x70, 0x32, 0x58, 0xe9, 0x11, 0xdc, 0x18, 0xe6, 0xd5, 0x48,
    0x7c, 0xf7, 0x37, 0xbf, 0x67, 0xfd, 0x11, 0x1f, 0x0c, 0x24, 0x63, 0xad, 0x60, 0x33, 0xbf, 0x51,
];

/// A synthetic AES128-CTS-HMAC-SHA256-128 session key.
const AES128_SHA2_KEY: [u8; 16] = [0x37; 16];

/// A synthetic AES256-CTS-HMAC-SHA384-192 session key.
const AES256_SHA2_KEY: [u8; 32] = [0x38; 32];

/// Fixed context time, so every run builds the same AP-REQ.
const NOW: Duration = Duration::from_secs(1_893_553_447);

/// A confounder long enough for every supported enctype.
const CONFOUNDER: [u8; 16] = [0x22; 16];

/// The RFC 4121 Wrap token header length.
const WRAP_HEADER_LEN: usize = 16;

/// The session key `choice` selects.
fn session_key(choice: u8) -> EncryptionKey {
    match choice & 0x07 {
        0 => EncryptionKey::new(17, AES128_KEY.to_vec()),
        1 => EncryptionKey::new(23, RC4_KEY.to_vec()),
        2 => EncryptionKey::new(16, DES3_KEY.to_vec()),
        4 => EncryptionKey::new(19, AES128_SHA2_KEY.to_vec()),
        5 => EncryptionKey::new(20, AES256_SHA2_KEY.to_vec()),
        _ => EncryptionKey::new(18, AES256_KEY.to_vec()),
    }
}

/// The sign and seal key usages for tokens from the expected sender.
const fn usages(from_acceptor: bool) -> (u32, u32) {
    if from_acceptor {
        (GSSAPI_ACCEPTOR_SIGN_USAGE, GSSAPI_ACCEPTOR_SEAL_USAGE)
    } else {
        (GSSAPI_INITIATOR_SIGN_USAGE, GSSAPI_INITIATOR_SEAL_USAGE)
    }
}

/// Split `input` into a part whose length is the first two bytes (big
/// endian) and the rest; `None` when the input is too short.
fn split_prefixed(input: &[u8]) -> Option<(&[u8], &[u8])> {
    let (length, rest) = input.split_first_chunk::<2>()?;
    rest.split_at_checked(usize::from(u16::from_be_bytes(*length)))
}

/// Decode a MIC token, attach the payload that follows it and verify it.
fn mic(input: &[u8], key: &EncryptionKey, from_acceptor: bool) {
    let Some((token, payload)) = split_prefixed(input) else {
        return;
    };
    if let Ok(mic) = MicToken::decode(token, from_acceptor) {
        let (sign, _) = usages(from_acceptor);
        drop(mic.with_payload(payload.to_vec()).verify(key, sign));
    }
}

/// Decode a Wrap token, then verify or unwrap it.
fn wrap(input: &[u8], key: &EncryptionKey, from_acceptor: bool) {
    let Ok(mut wrap) = WrapToken::decode(input, from_acceptor) else {
        return;
    };
    let (sign, seal) = usages(from_acceptor);
    if wrap.is_sealed() {
        drop(wrap.decrypt_and_set_payload(key, seal));
    } else {
        drop(wrap.verify(key, sign));
    }
    drop(wrap.encode());
}

/// Encrypt the plaintext after a 16-byte Wrap header under `key`, rotate the
/// ciphertext by the header's RRC and unwrap the resulting sealed token.
fn sealed(input: &[u8], key: &EncryptionKey, from_acceptor: bool) -> Option<()> {
    let (header, plaintext) = input.split_at_checked(WRAP_HEADER_LEN)?;
    let [.., rrc_0, rrc_1, _, _, _, _, _, _, _, _] = *header else {
        return None;
    };
    let etype = KerberosEtype::from_etype_id(key.etype)?;
    let (_, seal) = usages(from_acceptor);
    let confounder = CONFOUNDER.get(..etype.confounder_len())?;
    let cipher = etype
        .encrypt_message_with_confounder(&key.value, plaintext, seal, confounder)
        .ok()?;
    let rotation = usize::from(u16::from_be_bytes([rrc_0, rrc_1])).checked_rem(cipher.len())?;
    let (front, back) = cipher.split_at_checked(cipher.len().checked_sub(rotation)?)?;
    let token = [header, back, front].concat();
    wrap(&token, key, from_acceptor);
    Some(())
}

/// An initiator context for a fixed service session under `key`.
fn initiator(key: &EncryptionKey) -> Option<InitiatorContext> {
    let now = SystemTime::UNIX_EPOCH.checked_add(NOW)?;
    let end = now.checked_add(Duration::from_secs(36_000))?;
    let service = Principal::new("TEST.GOKRB5", 2, ["HTTP", "host.test.gokrb5"]);
    let ticket = session_ticket::encoded(&service, key)?;
    let session = AsRepSession::new(
        Principal::user("TEST.GOKRB5", "testuser1"),
        service,
        key.clone(),
        ticket.into(),
        [0x40, 0xe1, 0x00, 0x00],
        now,
        end,
    );
    let config = Config::parse(
        "[libdefaults]\nallow_rc4 = true\nallow_des3 = true\npermitted_enctypes = DEFAULT rc4 des3",
    )
    .ok()?;
    let options = InitiatorContextOptions::new()
        .with_sequence_number(Some(1))
        .with_crypto_policy(CryptoPolicy::from_libdefaults(&config.libdefaults).ok()?);
    let confounder = CONFOUNDER.get(..KerberosEtype::from_etype_id(key.etype)?.confounder_len())?;
    spnego::init_sec_context_with_confounder(&session, options, now, 0, confounder).ok()
}

/// Verify `input` as an AP-REP, raw and as a Negotiate response header.
fn ap_rep_reply(input: &[u8], key: &EncryptionKey) {
    if let Some(context) = initiator(key) {
        drop(context.verify_ap_rep(input));
        drop(context.verify_ap_rep_response_header(&String::from_utf8_lossy(input)));
    }
}

/// Encrypt a fuzzed `EncAPRepPart` under the context's session key and verify
/// the resulting AP-REP.
fn structured_ap_rep(input: &[u8], key: &EncryptionKey) -> Option<()> {
    let context = initiator(key)?;
    let enc_part = ap_rep::decode_enc_ap_rep_part(input).ok()?;
    let confounder = CONFOUNDER.get(..KerberosEtype::from_etype_id(key.etype)?.confounder_len())?;
    let reply =
        ap_rep::build_ap_rep_with_confounder(&enc_part, &context.session_key, None, confounder)
            .ok()?;
    drop(context.verify_ap_rep(&ap_rep::encode(&reply).ok()?));
    Some(())
}

fuzz_target!(|data: &[u8]| {
    for choice in 0..6 {
        assert!(
            initiator(&session_key(choice)).is_some(),
            "every fixed GSS context must be reachable"
        );
    }
    let Some((selector, input)) = data.split_first() else {
        return;
    };
    let key = session_key(selector >> 3_u8);
    let from_acceptor = selector & 0x40 != 0;
    match selector & 0x07 {
        0 => {
            if let Ok(token) = Krb5MechToken::decode(input) {
                drop(token.encode());
            }
        }
        1 => mic(input, &key, from_acceptor),
        2 => wrap(input, &key, from_acceptor),
        3 => sealed(input, &key, from_acceptor).unwrap_or_default(),
        4 => ap_rep_reply(input, &key),
        _ => structured_ap_rep(input, &key).unwrap_or_default(),
    }
});

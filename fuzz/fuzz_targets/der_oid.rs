//! Fuzz the crate's own DER and OBJECT IDENTIFIER decoders.
//!
//! The first input byte selects the entry point and the rest is its input:
//! OID content octets inside a SPNEGO `NegTokenResp` (decoded, re-encoded and
//! decoded again, which must give the same value), raw DER through the
//! SPNEGO reader, arcs through `ObjectIdentifier::from_arcs` and the encoder
//! round trip, and a decrypted Authenticator whose fuzzed plaintext reaches
//! the zero-padding trimmer and the complete-message DER decoder. None may
//! panic, and a round trip that changes a value is a failure.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rskrb5_ng::{
    ap_req,
    crypto::KerberosEtype,
    keytab::EncryptionKey,
    spnego::{NegTokenInit, NegTokenResp, NegotiationToken, Token, oid::ObjectIdentifier},
};

/// An AP-REQ whose authenticator ciphertext the trimming mode replaces.
const TEMPLATE_AP_REQ: &[u8] = include_bytes!("../fixtures/valid_ap_req.der");

/// A fixed AES256 key for the trimming mode.
const KEY: [u8; 32] = [0x3c; 32];

/// AES256-CTS-HMAC-SHA1-96.
const AES256: i32 = 18;

/// The AP-REQ authenticator key usage.
const AP_REQ_AUTHENTICATOR_USAGE: u32 = 11;

/// A fixed confounder, so every run encrypts the same bytes.
const CONFOUNDER: [u8; 16] = [0x33; 16];

/// Encode one DER element with a definite length.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match u8::try_from(content.len()) {
        Ok(short) if short < 0x80 => out.push(short),
        _ => {
            let length = content.len().to_be_bytes();
            let significant: Vec<u8> = length.into_iter().skip_while(|byte| *byte == 0).collect();
            out.push(0x80 | u8::try_from(significant.len()).unwrap_or(0));
            out.extend_from_slice(&significant);
        }
    }
    out.extend_from_slice(content);
    out
}

/// Decode `bytes` as a `NegTokenResp`, re-encode it and require the second
/// decode to agree.
///
/// # Panics
///
/// Panics when the round trip changes the decoded value.
fn resp_round_trip(bytes: &[u8]) {
    let Ok(token) = NegTokenResp::decode(bytes) else {
        return;
    };
    let Ok(encoded) = token.encode() else {
        return;
    };
    let again = NegTokenResp::decode(&encoded).ok();
    assert_eq!(
        again.as_ref(),
        Some(&token),
        "NegTokenResp round trip changed the value"
    );
}

/// Decode `content` as the OID of a `NegTokenResp` `supportedMech`.
fn oid_content(content: &[u8]) {
    let mech = tlv(0xa1, &tlv(0x06, content));
    resp_round_trip(&tlv(0xa1, &tlv(0x30, &mech)));
}

/// Build an OID from big-endian `u32` arcs and round-trip it.
///
/// # Panics
///
/// Panics when the round trip changes the OID.
fn arcs(input: &[u8]) {
    let (chunks, _) = input.as_chunks::<4>();
    let values = chunks
        .iter()
        .map(|chunk| u32::from_be_bytes(*chunk))
        .collect();
    if let Ok(oid) = ObjectIdentifier::from_arcs(values) {
        let mut token = NegTokenResp::accept_completed();
        token.set_supported_mech(Some(oid));
        if let Ok(encoded) = token.encode() {
            let again = NegTokenResp::decode(&encoded).ok();
            assert_eq!(
                again.as_ref(),
                Some(&token),
                "OID round trip changed the value"
            );
        }
    }
}

/// Encrypt `plaintext` as the AP-REQ authenticator and decrypt it again.
fn padded_authenticator(plaintext: &[u8]) -> Option<()> {
    let mut message = ap_req::decode(TEMPLATE_AP_REQ).ok()?;
    let etype = KerberosEtype::from_etype_id(AES256)?;
    let cipher = etype
        .encrypt_message_with_confounder(&KEY, plaintext, AP_REQ_AUTHENTICATOR_USAGE, &CONFOUNDER)
        .ok()?;
    message.authenticator.etype = AES256;
    message.authenticator.cipher = cipher.into();
    let key = EncryptionKey::new(AES256, KEY.to_vec());
    drop(ap_req::decrypt_ap_req_authenticator(
        &message,
        &key,
        AP_REQ_AUTHENTICATOR_USAGE,
    ));
    Some(())
}

fuzz_target!(|data: &[u8]| {
    let Some((selector, input)) = data.split_first() else {
        return;
    };
    match selector & 0x07 {
        0 => oid_content(input),
        1 => {
            if let Ok(token) = Token::decode(input) {
                drop(token.encode());
            }
        }
        2 => {
            if let Ok(token) = NegotiationToken::decode(input) {
                drop(token.encode());
            }
        }
        3 => {
            if let Ok(token) = NegTokenInit::decode(input) {
                drop(token.encode());
            }
        }
        4 => resp_round_trip(input),
        5 => arcs(input),
        _ => padded_authenticator(input).unwrap_or_default(),
    }
});

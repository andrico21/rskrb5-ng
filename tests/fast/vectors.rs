//! Derivation vectors with provenance.
//!
//! The MIT encoding vectors of the FAST messages are unit tests of the
//! crate-private message module. Derivations: an independent RFC 3961/3962 and RFC 6113 section 5.1
//! implementation in Python (pyca/cryptography AES and hashlib only), which
//! first reproduces MIT `t_cf2.expected` rows 1-2 for enctypes 17 and 18, then
//! derives the FAST keys of fixed inputs: subkey `01..`, ticket session key
//! `02..`, strengthen key `03..`, long-term key `04..` (script sha256
//! 6544dae70e81d2619ec0a67fdbba77342acb54faeba777dd1b5f2401f80606fc, output
//! sha256 9c5091997d37dc5109a8e1f927b46c5a44df9b9ebcb443029f9fdf6e382e1b4d,
//! archived with the task 7 evidence).

use core::{str::from_utf8, time::Duration};
use std::time::UNIX_EPOCH;

use rasn::der;
use rasn_kerberos::{EncryptedData, PaData, PaEncTsEnc};
use rskrb5_ng::{
    crypto::{KerberosEtype, prf},
    keytab::EncryptionKey,
    preauth::{
        encrypted_challenge::{
            EncryptedChallenge, KEY_USAGE_ENC_CHALLENGE_CLIENT, KEY_USAGE_ENC_CHALLENGE_KDC,
        },
        fast::PA_ENCRYPTED_CHALLENGE,
    },
};

use super::kdc::{TestError, seal};

/// One FAST derivation row of the independent implementation.
struct Derivation {
    /// The enctype.
    etype: i32,
    /// `KRB-FX-CF2(subkey, session, "subkeyarmor", "ticketarmor")`.
    armor: &'static str,
    /// `KRB-FX-CF2(strengthen, long-term, "strengthenkey", "replykey")`.
    reply: &'static str,
    /// The client challenge key.
    client_challenge: &'static str,
    /// The KDC challenge key.
    kdc_challenge: &'static str,
}

/// The rows of `fast_cf2.out`.
const DERIVATIONS: [Derivation; 2] = [
    Derivation {
        etype: 17,
        armor: "f0ddd81565ba1fc15b2fadef97814b4a",
        reply: "b754c1f035e36318875a282abbe617ef",
        client_challenge: "844de52639eb7703b913b16dabb13337",
        kdc_challenge: "545ba3352ec306de87c394e5c8452c18",
    },
    Derivation {
        etype: 18,
        armor: "e1612084cd22373bdd68f5b5f9c36942b02f9fc92f4a12eb3a97d8b25fd81e40",
        reply: "084523ee077a1cdac8f2609ab376326caaab872ce60483aff244e404a1f67545",
        client_challenge: "814aa46073d5d6f8639de215dde5f645ae1f2585ba253d49ecb69acddc547785",
        kdc_challenge: "a92d669146972dbd94a21e6735975b5f8755a98c994bceee8242a590c6843694",
    },
];

/// Bytes from spaced or plain hex.
fn hex(text: &str) -> Result<Vec<u8>, TestError> {
    let digits: Vec<u8> = text.bytes().filter(u8::is_ascii_hexdigit).collect();
    digits
        .chunks(2)
        .map(|pair| Ok(u8::from_str_radix(from_utf8(pair)?, 16)?))
        .collect()
}

/// The RFC 6113 FAST derivations equal the independent implementation.
#[test]
fn fast_key_derivations_match_the_independent_vectors() -> Result<(), TestError> {
    for row in DERIVATIONS {
        let etype = KerberosEtype::from_etype_id(row.etype).ok_or("etype")?;
        let size = etype.key_len();
        let fill = |byte: u8| vec![byte; size];
        let cf2 = |first: &[u8], first_pepper: &[u8], second: &[u8], second_pepper: &[u8]| {
            prf::krb_fx_cf2(
                &prf::CfInput::new(prf::Key::new(etype, first), first_pepper),
                &prf::CfInput::new(prf::Key::new(etype, second), second_pepper),
            )
        };
        let armor = cf2(&fill(1), b"subkeyarmor", &fill(2), b"ticketarmor")?;
        assert_eq!(armor.to_vec(), hex(row.armor)?, "{}: armor key", row.etype);
        let reply = cf2(&fill(3), b"strengthenkey", &fill(4), b"replykey")?;
        assert_eq!(
            reply.to_vec(),
            hex(row.reply)?,
            "{}: strengthened reply key",
            row.etype
        );
        challenge_keys(&row, &armor, &fill(4))?;
    }
    Ok(())
}

/// The encrypted challenge seals in the vector client key and accepts the
/// vector KDC key's reply, and nothing else.
fn challenge_keys(row: &Derivation, armor: &[u8], long_term: &[u8]) -> Result<(), TestError> {
    let challenge = EncryptedChallenge::new(
        &EncryptionKey::new(row.etype, armor.to_vec()),
        &EncryptionKey::new(row.etype, long_term.to_vec()),
    )?;
    let at = UNIX_EPOCH
        .checked_add(Duration::from_mins(31_559_224))
        .ok_or("time")?;
    let padata = challenge.padata((at, 123))?;
    assert_eq!(padata.r#type, PA_ENCRYPTED_CHALLENGE, "{}: type", row.etype);
    let encrypted: EncryptedData = der::decode(&padata.value)?;
    let etype = KerberosEtype::from_etype_id(row.etype).ok_or("etype")?;
    let plain = etype.decrypt_message(
        &hex(row.client_challenge)?,
        &encrypted.cipher,
        KEY_USAGE_ENC_CHALLENGE_CLIENT,
    )?;
    let timestamp: PaEncTsEnc = der::decode(&plain)?;
    assert_eq!(
        timestamp.pausec,
        Some(123_i32.into()),
        "{}: usec",
        row.etype
    );
    let reply = |key: &[u8], usage: u32| -> Result<Vec<PaData>, TestError> {
        let sealed = seal(&EncryptionKey::new(row.etype, key.to_vec()), usage, &plain)?;
        Ok(vec![PaData {
            r#type: PA_ENCRYPTED_CHALLENGE,
            value: der::encode(&sealed)?.into(),
        }])
    };
    challenge.verify_reply(&reply(
        &hex(row.kdc_challenge)?,
        KEY_USAGE_ENC_CHALLENGE_KDC,
    )?)?;
    assert!(
        challenge
            .verify_reply(&reply(
                &hex(row.client_challenge)?,
                KEY_USAGE_ENC_CHALLENGE_KDC
            )?)
            .is_err(),
        "{}: the client key does not answer for the KDC",
        row.etype
    );
    assert!(
        challenge.verify_reply(&[]).is_err(),
        "{}: a missing reply",
        row.etype
    );
    Ok(())
}

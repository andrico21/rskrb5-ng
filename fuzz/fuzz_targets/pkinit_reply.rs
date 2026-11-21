//! Fuzz the KDC's reply to a PA-PK-AS-REQ (RFC 4556 PKINIT, RFC 6112).
//!
//! A certificate exchange runs through the stepwise engine: the first request,
//! a fixed `PREAUTH_REQUIRED` that offers PA-PK-AS-REQ, then the fuzzed reply.
//! The first input byte selects how the rest reaches the client: mode 0 feeds
//! the bytes as the whole reply (the AS-REP and KRB-ERROR decoders and the
//! PA-PK-AS-REP lookup); mode 1 places them as the PA-PK-AS-REP value of an
//! AS-REP, so the `PA-PK-AS-REP`, `DHRepInfo`, CMS `ContentInfo` and
//! `SignedData`, X.509 certificate, CRL and path, `KDCDHKeyInfo` and
//! key-agreement decoders run. No input may complete the exchange: the KDC's
//! key is unknown to the fuzzer.

#![no_main]

use std::time::SystemTime;

use libfuzzer_sys::fuzz_target;
use rskrb5_ng::{
    Principal,
    client::{
        options::AsReq,
        stepwise::{ExchangeStep, InitCreds, InitCredsOptions, StepInput},
    },
    preauth::pkinit::{CertificatePolicy, DhGroup, Exchange, Identity, KdcTrust},
};

/// The realm.
const REALM: &str = "TEST.RSKRB5";
/// The client's certificate.
const CLIENT_PEM: &[u8] = include_bytes!("../../tests/pkinit/fixtures/client.pem");
/// The client's key.
const CLIENT_KEY: &[u8] = include_bytes!("../../tests/pkinit/fixtures/client.key");
/// The anchor.
const CA_PEM: &[u8] = include_bytes!("../../tests/pkinit/fixtures/ca-ec.pem");

/// A DER element of `tag` around `content`.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let length = content.len();
    if length < 0x80 {
        out.push(u8::try_from(length).unwrap_or(0));
    } else {
        let digits: Vec<u8> = length
            .to_be_bytes()
            .into_iter()
            .skip_while(|digit| *digit == 0)
            .collect();
        out.push(0x80 | u8::try_from(digits.len()).unwrap_or(0));
        out.extend(digits);
    }
    out.extend_from_slice(content);
    out
}

/// A SEQUENCE of `parts`.
fn sequence(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

/// The context tag `number` around `inner`.
fn tagged(number: u8, inner: &[u8]) -> Vec<u8> {
    tlv(0xa0 | number, inner)
}

/// A small non-negative INTEGER.
fn integer(value: u8) -> Vec<u8> {
    if value < 0x80 {
        tlv(0x02, &[value])
    } else {
        tlv(0x02, &[0, value])
    }
}

/// A `KerberosString`.
fn text(value: &str) -> Vec<u8> {
    tlv(0x1b, value.as_bytes())
}

/// A `PrincipalName`.
fn name(kind: u8, parts: &[&str]) -> Vec<u8> {
    let strings: Vec<Vec<u8>> = parts.iter().map(|part| text(part)).collect();
    sequence(&[tagged(0, &integer(kind)), tagged(1, &sequence(&strings))])
}

/// An AES256 `EncryptedData` that never decrypts.
fn encrypted() -> Vec<u8> {
    sequence(&[tagged(0, &integer(18)), tagged(2, &tlv(0x04, &[0x5a; 48]))])
}

/// The `PREAUTH_REQUIRED` KRB-ERROR offering PA-PK-AS-REQ.
fn preauth_required() -> Vec<u8> {
    let offer = sequence(&[tagged(1, &integer(16)), tagged(2, &tlv(0x04, &[]))]);
    tlv(
        0x7e,
        &sequence(&[
            tagged(0, &integer(5)),
            tagged(1, &integer(30)),
            tagged(4, &tlv(0x18, b"20300101000000Z")),
            tagged(5, &integer(0)),
            tagged(6, &integer(25)),
            tagged(9, &text(REALM)),
            tagged(10, &name(2, &["krbtgt", REALM])),
            tagged(12, &tlv(0x04, &sequence(&[offer]))),
        ]),
    )
}

/// An AS-REP whose padata is the PA-PK-AS-REP `value`.
fn as_rep(value: &[u8]) -> Vec<u8> {
    let padata = sequence(&[sequence(&[
        tagged(1, &integer(17)),
        tagged(2, &tlv(0x04, value)),
    ])]);
    let ticket = tlv(
        0x61,
        &sequence(&[
            tagged(0, &integer(5)),
            tagged(1, &text(REALM)),
            tagged(2, &name(2, &["krbtgt", REALM])),
            tagged(3, &encrypted()),
        ]),
    );
    tlv(
        0x6b,
        &sequence(&[
            tagged(0, &integer(5)),
            tagged(1, &integer(11)),
            tagged(2, &padata),
            tagged(3, &text(REALM)),
            tagged(4, &name(1, &["pkinituser"])),
            tagged(5, &ticket),
            tagged(6, &encrypted()),
        ]),
    )
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let (Ok(identity), Ok(trust)) = (
        Identity::from_pem(CLIENT_PEM, CLIENT_KEY),
        KdcTrust::from_pem(CA_PEM),
    ) else {
        return;
    };
    let exchange = Exchange::new(
        identity,
        trust,
        CertificatePolicy::default().with_group(DhGroup::P256),
    );
    let options =
        InitCredsOptions::new(AsReq::new(SystemTime::now(), 0x0102_0304).with_etypes(vec![18_i32]));
    let mut engine =
        InitCreds::with_pkinit(Principal::user(REALM, "pkinituser"), exchange, options);
    let Ok(ExchangeStep::Outbound(_)) = engine.step(StepInput::Start) else {
        return;
    };
    let Ok(ExchangeStep::Outbound(_)) = engine.step(StepInput::Reply(&preauth_required())) else {
        return;
    };
    let reply = if mode & 1 == 0 {
        rest.to_vec()
    } else {
        as_rep(rest)
    };
    let outcome = engine.step(StepInput::Reply(&reply));
    assert!(
        !matches!(outcome, Ok(ExchangeStep::Complete(_))),
        "a fuzzed PKINIT reply completed the exchange"
    );
});

//! Fuzz the `pkinit_cert_match` rules and the certificate text they match.
//!
//! The input is the text of a rule, a newline, then the DER bytes of a
//! candidate certificate. `CertificateRules::parse` reads configuration text
//! (a bounded `[&&|||]` list of `<SUBJECT>`, `<ISSUER>`, `<SAN>`, `<EKU>` and
//! `<KU>` components whose patterns run on the linear-time `regex` engine); an
//! accepted rule selects among the fuzzed certificate and the OpenSSL fixtures
//! of `tests/pkinit/fixtures/match`, which reads the fuzzed certificate's
//! subject, issuer, SAN and key usage text as OpenSSL would print it. A fixed
//! rule list also runs over the fuzzed certificate alone. None may panic and a
//! selected index is always a candidate.

#![no_main]

use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use rskrb5_ng::preauth::pkinit::{KdcTrust, matching::CertificateRules};

/// The fixture certificates (PEM).
const FIXTURES: [&[u8]; 6] = [
    include_bytes!("../../tests/pkinit/fixtures/match/user.pem"),
    include_bytes!("../../tests/pkinit/fixtures/match/alice.pem"),
    include_bytes!("../../tests/pkinit/fixtures/match/carol.pem"),
    include_bytes!("../../tests/pkinit/fixtures/match/erin.pem"),
    include_bytes!("../../tests/pkinit/fixtures/match/gina.pem"),
    include_bytes!("../../tests/pkinit/fixtures/match/henry.pem"),
];

/// The rules every certificate is matched against.
const FIXED_RULES: [&str; 6] = [
    "<SUBJECT>CN=.*",
    "<ISSUER>^O=MIT,",
    "<SAN>[[:alpha:]]+@.*",
    "||<EKU>pkinit,clientAuth<KU>digitalSignature,keyEncipherment",
    "&&<SUBJECT>^(O|C)=[^,]*,.*$<SAN>.*",
    "<SUBJECT>(a*)*b",
];

/// The fixtures as DER.
static CERTIFICATES: LazyLock<Vec<Vec<u8>>> = LazyLock::new(|| {
    FIXTURES
        .iter()
        .filter_map(|pem| KdcTrust::from_pem(pem).ok())
        .filter_map(|trust| trust.anchors().first().cloned())
        .collect()
});

/// The compiled fixed rules.
static RULES: LazyLock<Vec<CertificateRules>> = LazyLock::new(|| {
    FIXED_RULES
        .iter()
        .filter_map(|rule| CertificateRules::parse(&[*rule]).ok())
        .collect()
});

fuzz_target!(|data: &[u8]| {
    let mut parts = data.splitn(2, |byte| *byte == b'\n');
    let text = String::from_utf8_lossy(parts.next().unwrap_or_default());
    let der = parts.next().unwrap_or_default();
    for rules in RULES.iter() {
        if let Ok(index) = rules.select(&[der]) {
            assert_eq!(index, 0, "one candidate");
        }
    }
    let Ok(rules) = CertificateRules::parse(&[text.as_ref()]) else {
        return;
    };
    let mut candidates: Vec<&[u8]> = CERTIFICATES.iter().map(Vec::as_slice).collect();
    candidates.push(der);
    if let Ok(index) = rules.select(&candidates) {
        assert!(index < candidates.len(), "a selected index is a candidate");
    }
});

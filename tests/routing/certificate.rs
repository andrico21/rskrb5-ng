//! The certificate identity of certificate `S4U2Self` (MS-SFU 2.2.2 `S4UUserID`).
//!
//! Always compiled, dependency-free, bounded, and checked through the
//! inspection seam a certificate parser (the `pkinit` leaf) can implement.

use core::sync::atomic::{AtomicUsize, Ordering};

use rskrb5_ng::{
    error::Routing,
    extensions::ProviderError,
    routing::{CertificateIdentity, CertificateInspector},
};

use crate::TestError;

/// An inspector that counts its calls and refuses certificates starting with 0x00.
#[derive(Debug, Default)]
struct Counting(AtomicUsize);

impl CertificateInspector for Counting {
    fn inspect(&self, certificate: &[u8]) -> Result<(), ProviderError> {
        let _previous = self.0.fetch_add(1, Ordering::SeqCst);
        if certificate.first() == Some(&0) {
            return Err("not a certificate".into());
        }
        Ok(())
    }
}

/// The identity keeps the DER bytes, the user's realm and the optional name.
#[test]
fn identity_keeps_its_parts() -> Result<(), TestError> {
    // When an identity is built from a certificate and a requested name.
    let identity = CertificateIdentity::new(vec![0x30, 0x03, 0x02, 0x01, 0x01], "USER.TEST")?
        .with_name(["alice"]);
    // Then each part is readable and the Debug form shows no certificate bytes.
    assert_eq!(identity.certificate(), [0x30, 0x03, 0x02, 0x01, 0x01]);
    assert_eq!(identity.realm(), "USER.TEST");
    assert_eq!(identity.name(), ["alice"]);
    let shown = format!("{identity:?}");
    assert!(shown.contains("5 bytes"), "{shown}");
    Ok(())
}

/// An empty or oversized certificate and an empty realm are refused.
#[test]
fn identity_bounds_are_enforced() {
    // When identities past each bound are built.
    let empty = CertificateIdentity::new(Vec::new(), "USER.TEST");
    let oversized = CertificateIdentity::new(
        vec![0x30; CertificateIdentity::MAX_CERTIFICATE_BYTES + 1],
        "USER.TEST",
    );
    let realmless = CertificateIdentity::new(vec![0x30], "");
    // Then each is refused by name.
    assert!(
        matches!(empty, Err(Routing::CertificateSize { max }) if max == CertificateIdentity::MAX_CERTIFICATE_BYTES),
        "{empty:?}"
    );
    assert!(
        matches!(oversized, Err(Routing::CertificateSize { max: _ })),
        "{oversized:?}"
    );
    assert!(
        matches!(realmless, Err(Routing::EmptyRealm)),
        "{realmless:?}"
    );
}

/// The inspection seam sees the certificate once and its refusal is carried.
#[test]
fn inspector_decides_and_its_refusal_is_carried() -> Result<(), TestError> {
    // Given an inspector.
    let inspector = Counting::default();
    // When a good and a bad certificate are inspected.
    let good = CertificateIdentity::new(vec![0x30, 0x00], "USER.TEST")?.inspected(&inspector);
    let bad = CertificateIdentity::new(vec![0x00], "USER.TEST")?.inspected(&inspector);
    // Then the good one passes, the bad one carries the inspector's refusal.
    assert!(good.is_ok(), "{good:?}");
    assert!(
        matches!(&bad, Err(Routing::CertificateRejected(source)) if source.to_string() == "not a certificate"),
        "{bad:?}"
    );
    assert_eq!(inspector.0.load(Ordering::SeqCst), 2);
    Ok(())
}

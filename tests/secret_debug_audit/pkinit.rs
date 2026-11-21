//! Credential owners of PKINIT (WP-06).

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
pub(super) mod tests {
    extern crate alloc;

    use alloc::sync::Arc;
    use core::error::Error;

    use rskrb5_ng::{
        client::KdcTransport,
        error::Client,
        extensions::ProviderError,
        preauth::pkinit::{
            AnonymousArmorSource, CertificatePolicy, Exchange, Identity, KdcTrust,
            SignatureAlgorithm, Signer,
        },
    };

    use crate::tests::{pattern, redacted};

    /// A transport that holds a credential-like value.
    struct Holding(Vec<u8>);

    impl KdcTransport for Holding {
        fn send(&mut self, _realm: &str, _request: &[u8]) -> Result<Vec<u8>, Client> {
            Ok(self.0.clone())
        }
    }

    /// A signer that holds a key-like value.
    struct HoldingSigner(Vec<u8>);

    impl Signer for HoldingSigner {
        fn algorithm(&self) -> SignatureAlgorithm {
            SignatureAlgorithm::EcdsaP256Sha256
        }

        fn sign(&self, _message: &[u8]) -> Result<Vec<u8>, ProviderError> {
            Ok(self.0.clone())
        }
    }

    pub(crate) fn run_audit() -> Result<(), Box<dyn Error>> {
        anonymous_armor_source_redacts_its_transport()?;
        exchange_redacts_its_identity()
    }

    /// A PKINIT exchange names neither its signer's key nor its certificates.
    #[test]
    fn exchange_redacts_its_identity() -> Result<(), Box<dyn Error>> {
        let key = pattern(161);
        let certificate = pattern(177);
        let identity = Identity::new(
            vec![certificate.clone()],
            Arc::new(HoldingSigner(key.clone())),
        )?;
        redacted(
            &Exchange::new(
                identity,
                KdcTrust::new(vec![pattern(193)]),
                CertificatePolicy::default(),
            ),
            &[&key, &certificate],
        );
        Ok(())
    }

    /// The anonymous-armor source names neither its transport's contents nor
    /// its anchors.
    #[test]
    fn anonymous_armor_source_redacts_its_transport() -> Result<(), Box<dyn Error>> {
        let secret = pattern(225);
        let anchor = pattern(241);
        redacted(
            &AnonymousArmorSource::new(
                Holding(secret.clone()),
                KdcTrust::new(vec![anchor.clone()]),
                CertificatePolicy::default(),
            ),
            &[&secret, &anchor],
        );
        Ok(())
    }
}

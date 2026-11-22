//! Credential owners of the PAC API (WP-14): the builder, the signing request and the verification
//! request hold PAC buffers and borrowed keys and show none of them.

#[cfg(test)]
pub(super) mod tests {
    use rskrb5_ng::{
        keytab::EncryptionKey,
        pac::{Builder, ClientBinding, Signing, Verification, VerificationPolicy},
    };

    use crate::tests::{pattern, redacted};

    pub(crate) fn run_audit() -> Result<(), rskrb5_ng::error::Pac> {
        let mut builder = Builder::new();
        builder.add_buffer(100, &pattern(81))?;
        redacted(&builder, &[&pattern(81)]);
        let (server, kdc) = (
            EncryptionKey::new(18, pattern(91)),
            EncryptionKey::new(18, pattern(111)),
        );
        let covered = pattern(131);
        let client = ClientBinding::new("alice", std::time::UNIX_EPOCH);
        redacted(
            &Signing::new(&server, &kdc)
                .with_client(client.clone())
                .with_ticket_signature_input(&covered),
            &[&pattern(91), &pattern(111)],
        );
        redacted(
            &Verification::new(VerificationPolicy::kdc())
                .with_server_key(&server)
                .with_kdc_key(&kdc)
                .with_client(client)
                .with_ticket_signature_input(&covered),
            &[&pattern(91), &pattern(111)],
        );
        Ok(())
    }
}

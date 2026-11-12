use super::*;

/// Long-term credential attachment regressions.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use super::*;

    fn alice_keytab() -> Keytab {
        let mut keys = Keytab::new();
        keys.entries_mut().push(KeytabEntry::new(
            KeytabPrincipal::new("TEST.GOKRB5", 10, ["alice"]),
            1_893_553_440,
            1,
            EncryptionKey::new(18, vec![0x42; 32]),
            1,
        ));
        keys
    }

    fn credential_source(client: &Tokio) -> Result<(String, Vec<i32>), TestError> {
        let diagnostics = runtime()?.block_on(client.diagnostics());
        Ok((diagnostics.credential_source, diagnostics.keytab_enctypes))
    }

    /// An attached password replaces the client's retained keytab.
    #[test]
    fn password_attachment_replaces_keytab_credential() -> Result<(), TestError> {
        let client = Tokio::with_keytab(
            config_with_kdc_server("127.0.0.1:88")?,
            KdcProtocol::Tcp,
            Principal::user("TEST.GOKRB5", "alice"),
            alice_keytab(),
        );
        assert_eq!(credential_source(&client)?, ("keytab".to_owned(), vec![18]));
        let replaced = client.with_password_credential(TESTUSER_PASSWORD);
        assert_eq!(
            credential_source(&replaced)?,
            ("password".to_owned(), Vec::new())
        );
        Ok(())
    }

    /// An attached keytab replaces the client's retained password.
    #[test]
    fn keytab_attachment_replaces_password_credential() -> Result<(), TestError> {
        let client = Tokio::with_password(
            config_with_kdc_server("127.0.0.1:88")?,
            KdcProtocol::Tcp,
            Principal::user("TEST.GOKRB5", "alice"),
            TESTUSER_PASSWORD,
        );
        assert_eq!(
            credential_source(&client)?,
            ("password".to_owned(), Vec::new())
        );
        let replaced = client.with_keytab_credential(alice_keytab());
        assert_eq!(
            credential_source(&replaced)?,
            ("keytab".to_owned(), vec![18])
        );
        Ok(())
    }
}

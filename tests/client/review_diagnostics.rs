use super::*;

/// Structured client diagnostics regressions.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use super::*;

    /// Same-realm keys for another client are unavailable; advisory name type is ignored.
    #[test]
    fn diagnostics_require_client_keys() -> Result<(), TestError> {
        let cases: [(&str, Vec<i32>); 2] = [("bob", Vec::new()), ("alice", vec![17, 18, 19, 20])];
        for (name, expected) in cases {
            let mut keys = Keytab::new();
            let enctypes: [(i32, usize); 4] = [(17, 16), (18, 32), (19, 16), (20, 32)];
            for (etype, length) in enctypes {
                keys.entries_mut().push(KeytabEntry::new(
                    KeytabPrincipal::new("TEST.GOKRB5", 10, [name]),
                    1_893_553_440,
                    1,
                    EncryptionKey::new(etype, vec![0x42; length]),
                    1,
                ));
            }
            let client = Tokio::with_keytab(
                config_with_kdc_server("127.0.0.1:88")?,
                KdcProtocol::Tcp,
                Principal::user("TEST.GOKRB5", "alice"),
                keys,
            );
            let diagnostics = runtime()?.block_on(client.diagnostics());
            assert_eq!(diagnostics.keytab_enctypes, expected);
            assert_eq!(diagnostics.errors.len(), if name == "bob" { 4 } else { 0 });
            assert_eq!(diagnostics.is_ok(), name == "alice");
        }
        Ok(())
    }

    /// Pins that client diagnostics report the keytab and the KDC state.
    #[cfg(all(feature = "tokio", feature = "serde"))]
    #[test]
    fn tokio_client_diagnostics_reports_keytab_and_kdc_state() -> Result<(), TestError> {
        let client = Tokio::with_keytab(
            config_with_kdc()?,
            KdcProtocol::Auto,
            Principal::user("TEST.GOKRB5", "testuser1"),
            keytab_with_reply_key(1)?,
        );

        let diagnostics = runtime()?.block_on(client.diagnostics());

        assert_eq!(diagnostics.client, "testuser1");
        assert_eq!(diagnostics.realm, "TEST.GOKRB5");
        assert_eq!(diagnostics.protocol, "Auto");
        assert_eq!(diagnostics.credential_source, "keytab");
        assert!(!diagnostics.has_tgt);
        assert_eq!(diagnostics.tgt_session_count, 0);
        assert_eq!(diagnostics.service_ticket_cache_count, 0);
        assert_eq!(diagnostics.default_tkt_enctypes, [18_i32, 17_i32]);
        assert_eq!(diagnostics.preferred_preauth_types, [18_i32, 17_i32]);
        assert_eq!(diagnostics.keytab_enctypes, [18_i32]);
        assert_eq!(diagnostics.udp_kdcs, ["kdc.test.gokrb5:88"]);
        assert_eq!(diagnostics.tcp_kdcs, ["kdc.test.gokrb5:88"]);
        assert_eq!(
            diagnostics.errors,
            [
                "default_tkt_enctypes specifies 17 but this enctype is not available in the client's keytab",
            ]
        );
        assert!(!diagnostics.is_ok());

        let json = runtime()?
            .block_on(client.diagnostics_json())
            .context("diagnostics JSON renders")?;
        assert!(json.contains(r#""CredentialSource": "keytab""#));
        assert!(json.contains(r#""UDPKDCs": ["#));
        assert!(json.contains(r#""TCPKDCs": ["#));
        Ok(())
    }

    /// Default PA-DATA preferences do not require similarly numbered keytab enctypes.
    #[test]
    fn default_preauth_preferences_do_not_fail_keytab_diagnostics() -> Result<(), TestError> {
        // Given: default crypto and preauth preferences, all default AES keys, explicit KDCs.
        let config = config_with_kdc_server("127.0.0.1:88")?;
        let mut keytab = Keytab::new();
        let keys: [(i32, usize); 4] = [(20, 32), (19, 16), (18, 32), (17, 16)];
        for (etype, length) in keys {
            keytab.entries_mut().push(KeytabEntry::new(
                KeytabPrincipal::new("TEST.GOKRB5", 1, ["testuser1"]),
                1_893_553_440,
                1,
                EncryptionKey::new(etype, vec![0x42; length]),
                1,
            ));
        }
        let client = Tokio::with_keytab(
            config,
            KdcProtocol::Auto,
            Principal::user("TEST.GOKRB5", "testuser1"),
            keytab,
        );

        // When: diagnostics compare configured encryption types with available keys.
        let diagnostics = runtime()?.block_on(client.diagnostics());

        // Then: padata stays informational and the fully provisioned keytab is healthy.
        assert_eq!(diagnostics.preferred_preauth_types, [17_i32, 16_i32]);
        assert_eq!(
            diagnostics.keytab_enctypes,
            [17_i32, 18_i32, 19_i32, 20_i32]
        );
        assert_eq!(diagnostics.errors, Vec::<String>::new());
        assert!(diagnostics.is_ok());
        Ok(())
    }
}

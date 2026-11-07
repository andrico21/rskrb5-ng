use super::*;

/// Field-by-field redaction audits and observable secret-free formatting.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::str;
    use std::{fs::read_to_string, path::Path};

    use rskrb5_ng::client::{TokioClientCredentials, build_tgs_req_for_realm_with_subkey};
    use zeroize::Zeroizing;

    use super::*;

    /// Pin explicit field audits; Rust rejects a new field until each pattern is updated.
    #[test]
    fn secret_debug_enumerates_every_field() -> Result<(), TestError> {
        // Given each manually redacted struct, including todo6's file-key owners.
        for (file, owner, fields) in [
            (
                "src/client.rs",
                "TgsFastRequestParts",
                "request,ap_req_der,authenticator_subkey",
            ),
            (
                "src/client.rs",
                "Tokio",
                "config,import_policy_error,protocol,transport,client,credentials,tgt,tgt_sessions,service_tickets,assume_preauthentication,fast_negotiation",
            ),
            (
                "src/client/negotiate.rs",
                "BlockingClient",
                "runtime:_,client",
            ),
            ("src/ccache.rs", "EncryptionKey", "etype,value"),
            ("src/keytab.rs", "EncryptionKey", "etype,value"),
        ] {
            let source = read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(file))?;
            let compact: String = source
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect();
            // When selecting that owner's actual Debug implementation, not another method.
            let implementation = compact
                .split_once(&format!("implfmt::Debugfor{owner}{{"))
                .context("Debug implementation")?
                .1;
            let body = implementation
                .split_once(".debug_struct(")
                .context("Debug builder")?
                .0;
            // Then every field is explicit, with no rest pattern swallowing new secrets.
            let pattern = format!("letSelf{{{fields}}}=self;");
            let trailing = format!("letSelf{{{fields},}}=self;");
            assert!(
                body.contains(&pattern) || body.contains(&trailing),
                "missing exhaustive audit: {file} {owner}"
            );
        }
        Ok(())
    }

    /// Passwords, cached tickets and implicit-FAST keys remain absent from actual Debug output.
    #[test]
    fn audited_debug_redacts_secret_fields() -> Result<(), TestError> {
        // Given independent secret markers in credentials, cached tickets and FAST material.
        let principal = Principal::user("TEST.GOKRB5", "testuser1");
        let mut client = Tokio::with_password(
            Config::new(),
            KdcProtocol::Tcp,
            principal,
            b"password-audit-canary".to_vec(),
        );
        let mut session = sample_tgt_session()?;
        let mut fast = build_tgs_req_for_realm_with_subkey(
            &session,
            "TEST.GOKRB5",
            Principal::user("TEST.GOKRB5", "service"),
            TgsReq::new(timestamp(1_893_553_452)?, 42),
        )?;
        fast.ap_req_der = b"fast-token-audit-canary".to_vec();
        fast.authenticator_subkey.value = b"fast-key-audit-canary".to_vec();
        session.ticket = marked_ticket(b"ticket-audit-canary")?;
        client.cache_tgt_session(session)?;
        let credentials =
            TokioClientCredentials::Password(Zeroizing::new(b"password-audit-canary".to_vec()));
        // When formatting the audited client and credential variant.
        let rendered = format!("{client:?} {credentials:?} {fast:?}");
        assert!(
            format!("{credentials:?}").starts_with("Password("),
            "redacted credentials retain their diagnostic kind"
        );
        // Then neither text nor byte-array renderings disclose the secret values.
        for marker in [
            b"password-audit-canary".as_slice(),
            b"ticket-audit-canary".as_slice(),
            b"fast-token-audit-canary".as_slice(),
            b"fast-key-audit-canary".as_slice(),
        ] {
            assert!(!rendered.contains(&format!("{marker:?}")));
            assert!(!rendered.contains(str::from_utf8(marker)?));
        }
        #[cfg(feature = "spnego")]
        {
            let blocking =
                BlockingNegotiateClient::new(NegotiateClient::from_tokio_client(client))?;
            let wrapped = format!("{blocking:?}");
            assert!(!wrapped.contains("password-audit-canary"));
            assert!(!wrapped.contains("ticket-audit-canary"));
            assert!(!wrapped.contains(&format!("{:?}", b"password-audit-canary")));
        }
        Ok(())
    }
}

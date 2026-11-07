use super::*;

/// Cross-realm TGT destination diagnostics.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use rasn::der;
    use serde_json::{Value, json};

    use super::*;

    /// A krbtgt/B@A session reports B even alongside the local krbtgt/A@A session.
    #[test]
    fn cross_realm_tgt_json_reports_destination() -> Result<(), TestError> {
        // Given: consistent encoded ticket and session metadata with distinct issuer/destination.
        let local = sample_tgt_session()?;
        let mut referral = local.clone();
        referral.service = Principal::new("TEST.GOKRB5", 2, ["krbtgt", "OTHER.REALM"]);
        let mut encoded: rasn_kerberos::Ticket = der::decode(&referral.ticket)?;
        encoded.sname = rasn_principal(&referral.service)?;
        encoded.realm = realm(&referral.service.realm)?;
        referral.ticket = der::encode(&encoded)?.into();
        let mut client = Tokio::from_tgt_session(Config::new(), KdcProtocol::Tcp, local);
        client.cache_tgt_session(referral)?;

        // When: the public diagnostics API serializes both cached sessions.
        let actual: Value = serde_json::from_str(&client.sessions_json()?)?;

        // Then: each destination appears once with unchanged non-secret metadata.
        assert_eq!(
            actual,
            json!([
                {
                    "Realm": "OTHER.REALM",
                    "AuthTime": "2030-01-02T03:04:05Z",
                    "EndTime": "2030-01-03T03:04:05Z",
                    "RenewTill": "2030-01-08T03:04:05Z",
                    "SessionKeyExpiration": "2030-01-03T03:04:05Z"
                },
                {
                    "Realm": "TEST.GOKRB5",
                    "AuthTime": "2030-01-02T03:04:05Z",
                    "EndTime": "2030-01-03T03:04:05Z",
                    "RenewTill": "2030-01-08T03:04:05Z",
                    "SessionKeyExpiration": "2030-01-03T03:04:05Z"
                }
            ])
        );
        Ok(())
    }
}

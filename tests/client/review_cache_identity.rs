use super::*;

/// Structured cache identity regressions.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use super::*;

    /// Mislabeled ticket services fail before cache mutation or AP construction.
    #[test]
    fn cache_rejects_mislabeled_ticket_service() -> Result<(), TestError> {
        let tgt = sample_tgt_session()?;
        let mut client =
            Tokio::from_tgt_session(config_without_kdcs()?, KdcProtocol::Tcp, tgt.clone());
        let before = client.to_ccache()?;
        for service in [
            sample_service_principal(),
            Principal::tgt_service("OTHER.REALM"),
        ] {
            let mut mislabeled = tgt.clone();
            mislabeled.service = service;
            assert!(matches!(
                client.cache_service_ticket(mislabeled.clone()),
                Err(Error::ServicePrincipalMismatch {
                    expected: _,
                    actual: _
                })
            ));
            assert!(matches!(
                client.cache_tgt_session(mislabeled.clone()),
                Err(Error::ServicePrincipalMismatch {
                    expected: _,
                    actual: _
                })
            ));
            assert!(matches!(
                build_ap_req_with_confounder(
                    &mislabeled,
                    ApReq::new(),
                    timestamp(1_893_553_452)?,
                    0,
                    &[0; 16]
                ),
                Err(Error::ServicePrincipalMismatch {
                    expected: _,
                    actual: _
                })
            ));
            assert_eq!(client.to_ccache()?, before);
        }
        let mut advisory = tgt;
        advisory.service.name_type = 10_i32;
        client.cache_tgt_session(advisory)?;
        Ok(())
    }

    /// Embedded separators do not alias a different component sequence.
    #[test]
    fn service_cache_preserves_component_boundaries() -> Result<(), TestError> {
        let tgt = current_tgt_session(1, 60)?;
        let mut ticket = tgt.clone();
        ticket.service = Principal::new("TEST.GOKRB5", 2, ["HTTP", "a\0b"]);
        align_ticket_service(&mut ticket)?;
        let mut client = Tokio::from_tgt_session(config_without_kdcs()?, KdcProtocol::Tcp, tgt);
        client.cache_service_ticket(ticket)?;
        assert!(
            client
                .cached_service_ticket(Principal::new("TEST.GOKRB5", 2, ["HTTP", "a", "b"]))
                .is_none()
        );
        Ok(())
    }

    /// Foreign users, realms and reordered components cannot enter the service cache.
    #[test]
    fn service_cache_rejects_foreign_client_identity() -> Result<(), TestError> {
        // Given: an empty cache bound to a two-component client, with no network route.
        for foreign in [
            Principal::new("TEST.GOKRB5", 1, ["other", "instance"]),
            Principal::new("OTHER.REALM", 1, ["user", "instance"]),
            Principal::new("TEST.GOKRB5", 1, ["instance", "user"]),
        ] {
            let mut tgt = current_tgt_session(1, 60)?;
            tgt.client = Principal::new("TEST.GOKRB5", 1, ["user", "instance"]);
            let mut ticket = tgt.clone();
            ticket.client = foreign;
            ticket.service = sample_service_principal();
            align_ticket_service(&mut ticket)?;
            let service = ticket.service.clone();
            let mut client = Tokio::from_tgt_session(config_without_kdcs()?, KdcProtocol::Tcp, tgt);
            client.destroy();
            let before = client.to_ccache()?;

            // When: a session for a different client is offered for insertion.
            let result = client.cache_service_ticket(ticket);

            // Then: no cached credential or outbound authentication token is available.
            assert!(matches!(result, Err(Error::CacheClientMismatch)));
            assert!(client.cached_service_ticket(service.clone()).is_none());
            assert_eq!(client.to_ccache()?, before);
            #[cfg(feature = "spnego")]
            assert!(matches!(
                runtime()?.block_on(client.spnego_header(service)),
                Err(Error::NoClientCredentials)
            ));
        }
        Ok(())
    }

    /// Foreign identities cannot enter either the primary or referral TGT cache.
    #[test]
    fn tgt_cache_rejects_foreign_client_identity() -> Result<(), TestError> {
        for foreign in [
            Principal::new("TEST.GOKRB5", 1, ["other", "instance"]),
            Principal::new("OTHER.REALM", 1, ["user", "instance"]),
            Principal::new("TEST.GOKRB5", 1, ["instance", "user"]),
        ] {
            for destination in ["TEST.GOKRB5", "OTHER.REALM"] {
                // Given: an empty identity-bound client and a foreign-client TGT.
                let mut tgt = current_tgt_session(1, 60)?;
                tgt.client = Principal::new("TEST.GOKRB5", 1, ["user", "instance"]);
                let mut client =
                    Tokio::from_tgt_session(config_without_kdcs()?, KdcProtocol::Tcp, tgt.clone());
                client.destroy();
                let before = client.to_ccache()?;
                tgt.client = foreign.clone();
                tgt.service = Principal::new("TEST.GOKRB5", 2, ["krbtgt", destination]);
                align_ticket_service(&mut tgt)?;

                // When: the foreign TGT is offered for insertion.
                let result = client.cache_tgt_session(tgt);

                // Then: insertion fails without changing either cache.
                assert!(matches!(result, Err(Error::CacheClientMismatch)));
                assert_eq!(client.to_ccache()?, before);
                assert!(matches!(
                    runtime()?.block_on(client.affirm_login()),
                    Err(Error::NoClientCredentials)
                ));
            }
        }
        Ok(())
    }

    /// Advisory name types do not prevent same-identity cache reuse.
    #[test]
    fn cache_insertion_accepts_advisory_name_type_changes() -> Result<(), TestError> {
        for name_type in [0_i32, 10_i32] {
            // Given: matching realm/components with different advisory name types.
            let mut tgt = current_tgt_session(1, 60)?;
            let mut client =
                Tokio::from_tgt_session(config_without_kdcs()?, KdcProtocol::Tcp, tgt.clone());
            client.destroy();
            tgt.client.name_type = name_type;
            let mut ticket = tgt.clone();
            ticket.service = sample_service_principal();
            align_ticket_service(&mut ticket)?;

            // When: both session kinds are inserted.
            client.cache_tgt_session(tgt.clone())?;
            client.cache_service_ticket(ticket.clone())?;

            // Then: login and service acquisition reuse those sessions without a KDC.
            assert_eq!(
                runtime()?.block_on(client.affirm_login())?.client,
                tgt.client
            );
            assert_eq!(
                runtime()?
                    .block_on(client.get_service_ticket(ticket.service))?
                    .client,
                ticket.client
            );
        }
        Ok(())
    }
}

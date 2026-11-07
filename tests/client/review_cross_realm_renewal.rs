use super::*;

/// Renewal preserves the cross-realm server and returns to its issuing realm.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicUsize, Ordering};

    use rasn::der;
    use rskrb5_ng::{
        client::{AsRepSession, build_tgt_renewal_req},
        ticket,
    };
    use tokio::{task::JoinSet, time::timeout};

    use super::*;

    /// A valid renewable krbtgt/B@A, with matching encoded ticket identity.
    fn referral() -> Result<AsRepSession, TestError> {
        let mut session = current_tgt_session(10, 50)?;
        session.service = Principal::new("TEST.GOKRB5", 2, ["krbtgt", "RESDOM.GOKRB5"]);
        session.ticket =
            ticket::encode(&delegated_ticket(&session.client, &session.service)?)?.into();
        Ok(session)
    }

    /// Both random and explicit builders preserve issuer routing, wire server and original ticket.
    #[test]
    fn cross_realm_renewal_builders_preserve_server() -> Result<(), TestError> {
        // Given a genuine cross-realm server distinct from its destination realm.
        let session = referral()?;
        let options = TgsReq::new(timestamp(1_893_553_450)?, 42);
        // When each renewal builder encodes a request.
        for request in [
            build_tgt_renewal_req(&session, options.clone())?,
            build_tgt_renewal_req_with_confounder(
                &session,
                options,
                timestamp(1_893_553_451)?,
                123_456,
                &[0; 16],
            )?,
        ] {
            let decoded: rasn_kerberos::TgsReq = der::decode(&request.der)?;
            // Then the server is exactly krbtgt/B@A, never krbtgt/B@B.
            assert_eq!(request.kdc_realm, "TEST.GOKRB5");
            assert_eq!(request.service, session.service);
            assert_eq!(
                principal_from_parts(
                    &decoded.0.req_body.realm,
                    decoded.0.req_body.sname.as_ref().context("server")?
                )?,
                session.service
            );
            let padata = decoded.0.padata.as_ref().context("padata")?;
            let ap: rasn_kerberos::ApReq = der::decode(
                padata
                    .iter()
                    .find(|pa| pa.r#type == PA_TGS_REQ)
                    .context("AP-REQ")?
                    .value
                    .as_ref(),
            )?;
            assert_eq!(ticket::encode(&ap.ticket)?, *session.ticket);
        }
        Ok(())
    }

    /// Separate issuer and destination endpoints prove renewal does not route like ordinary use.
    #[test]
    fn cross_realm_renewal_contacts_issuer_only() -> Result<(), TestError> {
        runtime()?.block_on(async {
            // Given separate configured KDCs and a cached renewable krbtgt/B@A.
            let issuer = TcpListener::bind("127.0.0.1:0").await?;
            let destination = TcpListener::bind("127.0.0.1:0").await?;
            let config = Config::parse(&format!("[libdefaults]\n dns_lookup_kdc = false\n[realms]\n TEST.GOKRB5 = {{\n kdc = {}\n }}\n RESDOM.GOKRB5 = {{\n kdc = {}\n }}\n", issuer.local_addr()?, destination.local_addr()?))?;
            let session = referral()?;
            let expected = session.service.clone();
            let key = session.session_key.clone();
            let primary = current_tgt_session(10, 50)?;
            let principal = primary.client.clone();
            let mut client = Tokio::from_tgt_session(config, KdcProtocol::Tcp, primary.clone());
            client.cache_tgt_session(session)?;
            let wrong_calls = Arc::new(AtomicUsize::new(0));
            let wrong_peer_calls = Arc::clone(&wrong_calls);
            let mut peers = JoinSet::new();
            drop(peers.spawn(async move {
                let (_request, mut socket) = read_tcp_kdc_request(&destination).await?;
                let _: usize = wrong_peer_calls.fetch_add(1, Ordering::SeqCst);
                write_tcp_kdc_response(&mut socket, b"wrong realm").await?;
                Ok::<(), TestError>(())
            }));
            let reply_server = expected.clone();
            drop(peers.spawn(async move {
                let (bytes, mut socket) = read_tcp_kdc_request(&issuer).await?;
                let decoded: rasn_kerberos::TgsReq = der::decode(&bytes)?;
                assert_eq!(principal_from_parts(&decoded.0.req_body.realm, decoded.0.req_body.sname.as_ref().context("server")?)?, reply_server);
                let mut built = built_tgs_request_from_der(decoded, &bytes)?;
                built.client = principal;
                let response = synthetic_tgs_rep_with_service(&built, built.nonce, &key, &reply_server)?;
                write_tcp_kdc_response(&mut socket, &response).await?;
                Ok::<(), TestError>(())
            }));
            // When renewing the destination's cached TGT.
            let renewed = timeout(Duration::from_secs(5), client.renew_tgt_session_for_realm("RESDOM.GOKRB5")).await??;
            // Then issuer reply validates unchanged server identity and destination cache indexing.
            assert_eq!(renewed.service, expected);
            assert_eq!(client.tgt_session_for_realm("RESDOM.GOKRB5"), Some(&renewed));
            assert_eq!(client.tgt_session(), Some(&primary));
            assert_eq!(wrong_calls.load(Ordering::SeqCst), 0);
            peers.join_next().await.context("issuer task")???;
            Ok(())
        })
    }
}

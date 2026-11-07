use super::*;

/// Delegated ticket identity binding regressions.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use rasn::der;

    use super::*;

    /// S4U replaces caller PA-FOR-USER without dropping unrelated padata.
    #[test]
    fn s4u_replaces_only_impersonation_padata() -> Result<(), TestError> {
        let tgt = sample_tgt_session()?;
        let options = TgsReq::new(timestamp(1_893_553_450)?, 42).with_padata(vec![
            rasn_kerberos::PaData {
                r#type: 129,
                value: vec![0].into(),
            },
            rasn_kerberos::PaData {
                r#type: 777,
                value: vec![17].into(),
            },
        ]);
        let request = build_s4u2self_req_with_confounder(
            &tgt,
            Principal::user("TEST.GOKRB5", "alice"),
            options,
            timestamp(1_893_553_451)?,
            0,
            &decode_hex(TGS_REQ_CONFOUNDER)?,
        )?;
        let data = request.message.0.padata.as_ref().context("padata")?;
        assert_eq!(
            data.iter().filter(|entry| entry.r#type == 129_i32).count(),
            1
        );
        assert!(
            data.iter()
                .any(|entry| entry.r#type == 777_i32 && entry.value.as_ref() == [17])
        );
        Ok(())
    }

    /// A keyless S4U reply cannot establish its ticket's delegated client.
    #[test]
    fn s4u_reply_fails_closed_without_service_key() -> Result<(), TestError> {
        let mut tgt = sample_tgt_session()?;
        tgt.client = sample_service_principal();
        let request = build_s4u2self_req_with_confounder(
            &tgt,
            Principal::user("TEST.GOKRB5", "alice"),
            TgsReq::new(timestamp(1_893_553_450)?, 42).with_etypes(vec![18_i32]),
            timestamp(1_893_553_451)?,
            0,
            &decode_hex(TGS_REQ_CONFOUNDER)?,
        )?;
        let reply = synthetic_tgs_rep(&request, request.nonce, &tgt.session_key)?;
        assert!(matches!(
            process_tgs_rep(&request, &reply, &tgt.session_key),
            Err(Error::DelegationKeyRequired)
        ));
        Ok(())
    }

    /// Rewritten cleartext cannot disguise a different encrypted ticket client.
    #[test]
    fn s4u_self_rejects_ticket_client_mismatch() -> Result<(), TestError> {
        let mut tgt = sample_tgt_session()?;
        tgt.client = sample_service_principal();
        let request = build_s4u2self_req_with_confounder(
            &tgt,
            Principal::user("TEST.GOKRB5", "alice"),
            TgsReq::new(timestamp(1_893_553_450)?, 42)
                .with_etypes(vec![18_i32])
                .with_delegation_keytab(delegation_keytab()?),
            timestamp(1_893_553_451)?,
            0,
            &decode_hex(TGS_REQ_CONFOUNDER)?,
        )?;
        let mut reply: rasn_kerberos::TgsRep = der::decode(&synthetic_tgs_rep(
            &request,
            request.nonce,
            &tgt.session_key,
        )?)?;
        reply.0.ticket =
            delegated_ticket(&Principal::user("TEST.GOKRB5", "bob"), &request.service)?;
        assert!(matches!(
            process_tgs_rep(&request, &der::encode(&reply)?, &tgt.session_key),
            Err(Error::DelegationPrincipalMismatch)
        ));
        Ok(())
    }

    /// Proxy acceptance checks the frontend-decrypted evidence identity.
    #[test]
    fn s4u_proxy_rejects_relabelled_evidence() -> Result<(), TestError> {
        let user_tgt = sample_tgt_session()?;
        let mut evidence = sample_service_ticket_session(&user_tgt)?;
        evidence.client = Principal::user("TEST.GOKRB5", "other-user");
        let mut tgt = sample_tgt_session()?;
        tgt.client = sample_service_principal();
        let request = build_s4u2proxy_req_with_confounder(
            &tgt,
            &evidence,
            Principal::new("TEST.GOKRB5", 2, ["HTTP", "backend"]),
            TgsReq::new(timestamp(1_893_553_450)?, 42)
                .with_etypes(vec![18_i32])
                .with_delegation_keytab(delegation_keytab()?),
            timestamp(1_893_553_451)?,
            0,
            &decode_hex(TGS_REQ_CONFOUNDER)?,
        )?;
        let reply = synthetic_tgs_rep(&request, request.nonce, &tgt.session_key)?;
        assert!(matches!(
            process_tgs_rep(&request, &reply, &tgt.session_key),
            Err(Error::DelegationPrincipalMismatch)
        ));
        Ok(())
    }
}

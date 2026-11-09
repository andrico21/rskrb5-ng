use super::*;

#[cfg(feature = "tokio")]
#[path = "review_cancellation.rs"]
mod review_cancellation;

#[cfg(all(feature = "tokio", feature = "spnego"))]
#[path = "review_blocking.rs"]
mod review_blocking;

/// Cross-realm authenticator regression tests.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use rasn::der;
    use rskrb5_ng::ap_req::decrypt_ap_req_authenticator;

    use super::*;

    /// The client realm survives a referral through a different ticket issuer.
    #[test]
    fn tgs_authenticator_uses_client_realm_when_issuer_differs() -> Result<(), TestError> {
        let mut tgt = sample_tgt_session()?;
        let mut identity = tgt.client().clone();
        identity.realm = "CLIENT.EXAMPLE".to_owned();
        tgt.set_client(identity);
        let request = build_tgs_req_for_realm_with_confounder(
            &tgt,
            "DEST.EXAMPLE",
            Principal::new("DEST.EXAMPLE", 2, ["HTTP", "host"]),
            TgsReq::new(timestamp(1_893_553_450)?, 42).with_etypes(vec![18_i32]),
            timestamp(1_893_553_451)?,
            0,
            &decode_hex(TGS_REQ_CONFOUNDER)?,
        )?;
        let padata = request.message().0.padata.as_ref().context("padata")?;
        let ap: rasn_kerberos::ApReq =
            der::decode(padata.first().context("AP request")?.value.as_ref())?;
        let auth =
            decrypt_ap_req_authenticator(&ap, tgt.session_key(), TGS_REQ_AUTHENTICATOR_USAGE)?;
        assert_eq!(
            &principal_from_parts(&auth.crealm, &auth.cname)?,
            tgt.client()
        );
        Ok(())
    }
}

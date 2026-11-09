use super::*;

/// Negotiated TGS reply integrity regression tests.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use rasn::der;
    use rskrb5_ng::kdc_rep::decrypt_tgs_rep_enc_part;

    use super::*;

    /// A negotiated TGS request rejects a missing encrypted request checksum.
    #[test]
    fn tgs_reply_rejects_missing_negotiated_checksum() -> Result<(), TestError> {
        let tgt = sample_tgt_session()?;
        let request = build_tgs_req_with_confounder(
            &tgt,
            sample_service_principal(),
            TgsReq::new(timestamp(1_893_553_450)?, 42)
                .with_etypes(vec![18_i32])
                .with_padata(vec![rasn_kerberos::PaData {
                    r#type: PA_REQ_ENC_PA_REP,
                    value: Vec::new().into(),
                }]),
            timestamp(1_893_553_451)?,
            0,
            &decode_hex(TGS_REQ_CONFOUNDER)?,
        )?;
        let response = synthetic_tgs_rep(&request, request.nonce(), tgt.session_key())?;
        assert!(matches!(
            process_tgs_rep(&request, &response, tgt.session_key()),
            Err(Error::InvalidFastNegotiationResponse)
        ));
        Ok(())
    }

    /// A negotiated TGS response verifies its checksum over the entire request.
    #[test]
    fn tgs_reply_accepts_valid_negotiated_checksum() -> Result<(), TestError> {
        let tgt = sample_tgt_session()?;
        let request = build_tgs_req_with_confounder(
            &tgt,
            sample_service_principal(),
            TgsReq::new(timestamp(1_893_553_450)?, 42)
                .with_etypes(vec![18_i32])
                .with_padata(vec![rasn_kerberos::PaData {
                    r#type: PA_REQ_ENC_PA_REP,
                    value: Vec::new().into(),
                }]),
            timestamp(1_893_553_451)?,
            0,
            &decode_hex(TGS_REQ_CONFOUNDER)?,
        )?;
        let mut response: rasn_kerberos::TgsRep = der::decode(&synthetic_tgs_rep(
            &request,
            request.nonce(),
            tgt.session_key(),
        )?)?;
        let mut part = decrypt_tgs_rep_enc_part(&response, tgt.session_key())?;
        let etype = KerberosEtype::from_etype_id(tgt.session_key().etype()).context("etype")?;
        part.encrypted_pa_data = Some(vec![rasn_kerberos::PaData {
            r#type: PA_REQ_ENC_PA_REP,
            value: PaReqEncPaRep::new(
                etype.checksum_type_id(),
                etype
                    .checksum(
                        tgt.session_key().value(),
                        request.der(),
                        AS_REQ_CHECKSUM_USAGE,
                    )?
                    .into(),
            )
            .encode_der()?
            .into(),
        }]);
        response.0.enc_part.cipher = encrypt_message(
            tgt.session_key(),
            &der::encode(&rasn_kerberos::EncTgsRepPart(part))?,
            TGS_REP_ENCPART_SESSION_KEY_USAGE,
            TGS_REP_CONFOUNDER,
        )?
        .into();
        let session = process_tgs_rep(&request, &der::encode(&response)?, tgt.session_key())?;
        assert_eq!(session.service(), request.service());
        Ok(())
    }
}

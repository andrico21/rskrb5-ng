use super::*;

/// TGS exchange tests: TGS-REQ building, referrals, S4U, renewal, permitted
/// enctypes and the implicit-armor subkey.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use rasn::{der, types::Integer};
    use rskrb5_ng::{
        ap_req::decrypt_ap_req_authenticator,
        config::LibDefaults,
        error::{Crypto, Policy},
        messages::{PaForUser, PaPacOptions},
    };

    use super::*;

    /// Pins a TGS-REQ with its PA-TGS-REQ AP-REQ and the authenticator body checksum.
    #[test]
    fn builds_tgs_req_with_pa_tgs_req_and_checksum() -> Result<(), TestError> {
        let tgt = sample_tgt_session()?;
        let service = sample_service_principal();
        let options = TgsReq::new(timestamp(1_893_553_450)?, 0x5566_7788)
            .with_ticket_lifetime(Duration::from_hours(2))
            .with_etypes(vec![18_i32]);

        let request = build_tgs_req_with_confounder(
            &tgt,
            service.clone(),
            options,
            timestamp(1_893_553_451)?,
            654_321,
            &decode_hex(TGS_REQ_CONFOUNDER)?,
        )
        .context("TGS-REQ builds")?;
        let decoded: rasn_kerberos::TgsReq =
            der::decode(request.der()).context("TGS-REQ decodes")?;

        assert_eq!(request.message(), &decoded);
        assert_eq!(decoded.0.pvno, Integer::from(5_i32));
        assert_eq!(decoded.0.msg_type, Integer::from(12_i32));

        let body = &decoded.0.req_body;
        assert_eq!(
            principal_from_parts(&body.realm, body.cname.as_ref().context("cname")?)?,
            tgt.client().clone()
        );
        assert_eq!(
            principal_from_parts(&body.realm, body.sname.as_ref().context("sname")?)?,
            service
        );
        assert_eq!(
            system_time_from_kerberos_time(&body.till)?,
            timestamp(1_893_560_650)?
        );
        assert!(body.rtime.is_none());
        assert_eq!(body.nonce, 0x5566_7788);
        assert_eq!(body.etype, vec![18_i32]);

        let padata = decoded.0.padata.as_ref().context("TGS-REQ has padata")?;
        assert_eq!(padata.len(), 1);
        let [pa_tgs_req] = padata.as_slice() else {
            return Err("TGS-REQ carries one padata".into());
        };
        assert_eq!(pa_tgs_req.r#type, PA_TGS_REQ);
        let ap_req: rasn_kerberos::ApReq =
            der::decode(pa_tgs_req.value.as_ref()).context("PA-TGS-REQ AP-REQ decodes")?;
        assert_eq!(ap_req.pvno, Integer::from(5_i32));
        assert_eq!(ap_req.msg_type, Integer::from(14_i32));
        assert_eq!(ap_req.ap_options.0.as_raw_slice(), &[0, 0, 0, 0]);
        let tgt_ticket: rasn_kerberos::Ticket =
            der::decode(tgt.ticket()).context("TGT ticket decodes")?;
        assert_eq!(ap_req.ticket, tgt_ticket);
        assert_eq!(ap_req.authenticator.etype, 18_i32);
        assert_eq!(ap_req.authenticator.kvno, Some(2));

        let authenticator_bytes = AesSha1Etype::Aes256
            .decrypt_message(
                tgt.session_key().value(),
                ap_req.authenticator.cipher.as_ref(),
                TGS_REQ_AUTHENTICATOR_USAGE,
            )
            .context("TGS authenticator decrypts")?;
        let authenticator: rasn_kerberos::Authenticator =
            der::decode(&authenticator_bytes).context("Authenticator decodes")?;
        assert_eq!(
            principal_from_parts(&authenticator.crealm, &authenticator.cname)?,
            tgt.client().clone()
        );
        assert_eq!(
            authenticator
                .cusec
                .to_string()
                .parse::<u32>()
                .context("cusec")?,
            654_321
        );
        assert_eq!(
            system_time_from_kerberos_time(&authenticator.ctime)?,
            timestamp(1_893_553_451)?
        );
        let checksum = authenticator.cksum.context("authenticator has checksum")?;
        assert_eq!(checksum.r#type, AesSha1Etype::Aes256.checksum_type_id());
        let body_der = der::encode(body).context("TGS-REQ-BODY encodes")?;
        assert!(AesSha1Etype::Aes256.verify_checksum(
            tgt.session_key().value(),
            &body_der,
            checksum.checksum.as_ref(),
            TGS_REQ_AUTHENTICATOR_CHECKSUM_USAGE,
        ));
        Ok(())
    }

    /// Pins that TGS-REQ options from libdefaults carry `canonicalize` and the configured KDC options.
    #[test]
    fn tgs_req_options_from_libdefaults_sets_canonicalize_flag() -> Result<(), TestError> {
        let defaults = LibDefaults::default()
            .with_canonicalize(true.into())
            .with_kdc_default_options(0x0000_0010);
        let tgt = sample_tgt_session()?;
        let service = sample_service_principal();
        let options = TgsReq::from_libdefaults(timestamp(1_893_553_450)?, 0x5566_7788, &defaults);

        let request = build_tgs_req_with_confounder(
            &tgt,
            service,
            options,
            timestamp(1_893_553_451)?,
            654_321,
            &decode_hex(TGS_REQ_CONFOUNDER)?,
        )
        .context("TGS-REQ builds")?;
        let decoded: rasn_kerberos::TgsReq =
            der::decode(request.der()).context("TGS-REQ decodes")?;
        let body = &decoded.0.req_body;

        assert_eq!(
            body.kdc_options.0.as_raw_slice(),
            (KDC_OPTION_CANONICALIZE | 0x0000_0010)
                .to_be_bytes()
                .as_slice()
        );
        Ok(())
    }

    /// Pins that a TGS-REQ can be addressed to an explicit KDC realm.
    #[test]
    fn builds_tgs_req_for_explicit_kdc_realm() -> Result<(), TestError> {
        let tgt = sample_tgt_session()?;
        let service = Principal::new("RESDOM.GOKRB5", 2, ["HTTP", "host.resdom.gokrb5"]);
        let request = build_tgs_req_for_realm_with_confounder(
            &tgt,
            "TEST.GOKRB5",
            service.clone(),
            TgsReq::new(timestamp(1_893_553_450)?, 0x4455_6677).with_etypes(vec![18_i32]),
            timestamp(1_893_553_451)?,
            654_321,
            &decode_hex(TGS_REQ_CONFOUNDER)?,
        )
        .context("TGS-REQ builds")?;
        let decoded: rasn_kerberos::TgsReq =
            der::decode(request.der()).context("TGS-REQ decodes")?;

        assert_eq!(request.kdc_realm(), "TEST.GOKRB5");
        assert_eq!(request.service(), &service);
        assert_eq!(
            kerberos_string_to_string(&decoded.0.req_body.realm)?,
            "TEST.GOKRB5"
        );
        assert_eq!(
            principal_from_parts(
                &realm("RESDOM.GOKRB5")?,
                decoded.0.req_body.sname.as_ref().context("sname")?
            )?,
            service
        );
        Ok(())
    }

    /// Pins an `S4U2Self` TGS-REQ with PA-TGS-REQ and PA-FOR-USER.
    #[test]
    fn builds_s4u2self_tgs_req_with_pa_for_user() -> Result<(), TestError> {
        let mut service_tgt = sample_tgt_session()?;
        service_tgt.set_client(sample_service_principal());
        let user = Principal::user("TEST.GOKRB5", "delegated-user");

        let request = build_s4u2self_req_with_confounder(
            &service_tgt,
            user.clone(),
            TgsReq::new(timestamp(1_893_553_450)?, 0x5566_7788).with_etypes(vec![18_i32]),
            timestamp(1_893_553_451)?,
            654_321,
            &decode_hex(TGS_REQ_CONFOUNDER)?,
        )
        .context("S4U2Self TGS-REQ builds")?;
        let decoded: rasn_kerberos::TgsReq =
            der::decode(request.der()).context("TGS-REQ decodes")?;

        assert_eq!(request.client(), &user);
        assert_eq!(request.service(), service_tgt.client());
        assert_eq!(request.kdc_realm(), "TEST.GOKRB5");
        assert_eq!(
            principal_from_parts(
                &decoded.0.req_body.realm,
                decoded.0.req_body.cname.as_ref().context("cname")?
            )?,
            service_tgt.client().clone()
        );
        assert_eq!(
            principal_from_parts(
                &decoded.0.req_body.realm,
                decoded.0.req_body.sname.as_ref().context("sname")?
            )?,
            service_tgt.client().clone()
        );

        let padata = decoded.0.padata.as_ref().context("S4U TGS-REQ padata")?;
        assert_eq!(padata.len(), 2);
        let [pa_tgs_req, pa_for_user_data] = padata.as_slice() else {
            return Err("S4U TGS-REQ carries two padata".into());
        };
        assert_eq!(pa_tgs_req.r#type, PA_TGS_REQ);
        assert_eq!(pa_for_user_data.r#type, PA_FOR_USER);
        let pa_for_user = PaForUser::decode_der(pa_for_user_data.value.as_ref())
            .context("PA-FOR-USER decodes")?;
        assert_eq!(
            principal_from_parts(pa_for_user.user_realm(), pa_for_user.user_name())?,
            user
        );
        assert_eq!(pa_for_user.auth_package().as_bytes(), b"Kerberos");
        assert_eq!(pa_for_user.cksum().r#type, -138_i32);
        let s4u_bytes = s4u_byte_array(&user, "Kerberos");
        let expected_checksum = kerb_checksum_hmac_md5(
            service_tgt.session_key().value(),
            &s4u_bytes,
            PA_FOR_USER_CHECKSUM_USAGE,
        );
        assert_eq!(pa_for_user.cksum().checksum.as_ref(), expected_checksum);
        Ok(())
    }

    /// Pins an `S4U2Proxy` TGS-REQ with CNAME-IN-ADDL-TKT and the evidence ticket.
    #[test]
    fn builds_s4u2proxy_tgs_req_with_evidence_ticket() -> Result<(), TestError> {
        let user_tgt = sample_tgt_session()?;
        let evidence_ticket = sample_service_ticket_session(&user_tgt)?;
        let mut service_tgt = sample_tgt_session()?;
        service_tgt.set_client(sample_service_principal());
        let target_service = Principal::new("TEST.GOKRB5", 2, ["HTTP", "backend.test.gokrb5"]);

        let request = build_s4u2proxy_req_with_confounder(
            &service_tgt,
            &evidence_ticket,
            target_service.clone(),
            TgsReq::new(timestamp(1_893_553_450)?, 0x9988_7766).with_etypes(vec![18_i32]),
            timestamp(1_893_553_451)?,
            654_321,
            &decode_hex(TGS_REQ_CONFOUNDER)?,
        )
        .context("S4U2Proxy TGS-REQ builds")?;
        let decoded: rasn_kerberos::TgsReq =
            der::decode(request.der()).context("TGS-REQ decodes")?;
        let body = &decoded.0.req_body;

        assert_eq!(request.client(), evidence_ticket.client());
        assert_eq!(request.service(), &target_service);
        assert_eq!(
            body.kdc_options.0.as_raw_slice(),
            KDC_OPTION_CNAME_IN_ADDL_TKT.to_be_bytes().as_slice()
        );
        assert_eq!(
            principal_from_parts(&body.realm, body.cname.as_ref().context("cname")?)?,
            service_tgt.client().clone()
        );
        assert_eq!(
            principal_from_parts(&body.realm, body.sname.as_ref().context("sname")?)?,
            target_service
        );
        let additional_tickets = body
            .additional_tickets
            .as_ref()
            .context("S4U2Proxy additional ticket")?;
        assert_eq!(additional_tickets.len(), 1);
        let [evidence] = additional_tickets.as_slice() else {
            return Err("S4U2Proxy TGS-REQ carries one additional ticket".into());
        };
        assert_eq!(
            principal_from_parts(&evidence.realm, &evidence.sname)?,
            service_tgt.client().clone()
        );
        let padata = decoded.0.padata.as_ref().context("S4U2Proxy padata")?;
        assert_eq!(padata.len(), 1);
        let [pa_tgs_req] = padata.as_slice() else {
            return Err("S4U2Proxy TGS-REQ carries one padata".into());
        };
        assert_eq!(pa_tgs_req.r#type, PA_TGS_REQ);
        Ok(())
    }

    /// Pins that an `S4U2Proxy` TGS-REQ carries the requested PA-PAC-OPTIONS.
    #[test]
    fn builds_s4u2proxy_tgs_req_with_pac_options() -> Result<(), TestError> {
        let user_tgt = sample_tgt_session()?;
        let evidence_ticket = sample_service_ticket_session(&user_tgt)?;
        let mut service_tgt = sample_tgt_session()?;
        service_tgt.set_client(sample_service_principal());
        let target_service = Principal::new("TEST.GOKRB5", 2, ["HTTP", "backend.test.gokrb5"]);
        let pac_options = pa_pac_options_padata(PAC_OPTION_RESOURCE_BASED_CONSTRAINED_DELEGATION)
            .context("PA-PAC-OPTIONS padata builds")?;

        let request = build_s4u2proxy_req_with_confounder(
            &service_tgt,
            &evidence_ticket,
            target_service,
            TgsReq::new(timestamp(1_893_553_450)?, 0x8877_6655)
                .with_etypes(vec![18_i32])
                .with_kdc_option_bits(KDC_OPTION_CNAME_IN_ADDL_TKT)
                .with_padata(vec![pac_options]),
            timestamp(1_893_553_451)?,
            654_321,
            &decode_hex(TGS_REQ_CONFOUNDER)?,
        )
        .context("S4U2Proxy TGS-REQ builds")?;
        let decoded: rasn_kerberos::TgsReq =
            der::decode(request.der()).context("TGS-REQ decodes")?;
        assert_eq!(
            decoded.0.req_body.kdc_options.0.as_raw_slice(),
            KDC_OPTION_CNAME_IN_ADDL_TKT.to_be_bytes().as_slice(),
            "a caller-set CNAME-IN-ADDL-TKT bit stays set"
        );
        let padata = decoded.0.padata.as_ref().context("S4U2Proxy padata")?;

        assert_eq!(padata.len(), 2);
        let [pa_tgs_req, pa_pac_options] = padata.as_slice() else {
            return Err("S4U2Proxy TGS-REQ carries two padata".into());
        };
        assert_eq!(pa_tgs_req.r#type, PA_TGS_REQ);
        assert_eq!(pa_pac_options.r#type, PA_PAC_OPTIONS);
        let decoded_pac_options = PaPacOptions::decode_der(pa_pac_options.value.as_ref())
            .context("PA-PAC-OPTIONS decodes")?;
        assert_eq!(
            decoded_pac_options.bits(),
            PAC_OPTION_RESOURCE_BASED_CONSTRAINED_DELEGATION
        );
        Ok(())
    }

    /// Pins a service AP-REQ whose authenticator carries the subkey and sequence number.
    #[test]
    fn builds_service_ap_req_with_subkey_and_sequence_number() -> Result<(), TestError> {
        let tgt = sample_tgt_session()?;
        let request = sample_tgs_request(&tgt)?;
        let response = synthetic_tgs_rep(&request, request.nonce(), tgt.session_key())?;
        let service_ticket =
            process_tgs_rep(&request, &response, tgt.session_key()).context("TGS-REP validates")?;
        let subkey = EncryptionKey::new(18, vec![0x44; 32]);
        let options = ApReq::new()
            .with_ap_option_bits(0x2000_0000)
            .with_subkey(Some(subkey.clone()))
            .with_sequence_number(Some(42));

        let built = build_ap_req_with_confounder(
            &service_ticket,
            options,
            timestamp(1_893_553_452)?,
            456_789,
            &decode_hex(TGS_REQ_CONFOUNDER)?,
        )
        .context("AP-REQ builds")?;
        let decoded: rasn_kerberos::ApReq = der::decode(built.der()).context("AP-REQ decodes")?;

        assert_eq!(built.message(), &decoded);
        assert_eq!(built.client(), service_ticket.client());
        assert_eq!(built.service(), service_ticket.service());
        assert_eq!(built.sequence_number(), Some(42));
        assert_eq!(built.subkey(), Some(&subkey));
        assert_eq!(decoded.pvno, Integer::from(5_i32));
        assert_eq!(decoded.msg_type, Integer::from(14_i32));
        assert_eq!(
            decoded.ap_options.0.as_raw_slice(),
            0x2000_0000_u32.to_be_bytes().as_slice()
        );
        assert_eq!(
            decoded.authenticator.etype,
            service_ticket.session_key().etype()
        );

        let authenticator_bytes = AesSha1Etype::Aes256
            .decrypt_message(
                service_ticket.session_key().value(),
                decoded.authenticator.cipher.as_ref(),
                AP_REQ_AUTHENTICATOR_USAGE,
            )
            .context("AP-REQ authenticator decrypts")?;
        let authenticator: rasn_kerberos::Authenticator =
            der::decode(&authenticator_bytes).context("Authenticator decodes")?;

        assert_eq!(
            principal_from_parts(&authenticator.crealm, &authenticator.cname)?,
            service_ticket.client().clone()
        );
        assert!(authenticator.cksum.is_none());
        assert_eq!(authenticator.seq_number, Some(42));
        let decoded_subkey = authenticator.subkey.context("authenticator subkey")?;
        assert_eq!(decoded_subkey.r#type, subkey.etype());
        assert_eq!(decoded_subkey.value.as_ref(), subkey.value().as_slice());
        assert_eq!(
            authenticator
                .cusec
                .to_string()
                .parse::<u32>()
                .context("cusec")?,
            456_789
        );
        assert_eq!(
            system_time_from_kerberos_time(&authenticator.ctime)?,
            timestamp(1_893_553_452)?
        );
        Ok(())
    }

    /// Pins that a TGT renewal request sets the RENEW and RENEWABLE KDC options.
    #[test]
    fn builds_tgt_renewal_req_sets_renew_options() -> Result<(), TestError> {
        let tgt = sample_tgt_session()?;
        let request = build_tgt_renewal_req_with_confounder(
            &tgt,
            TgsReq::new(timestamp(1_893_553_450)?, 0x7788_99aa)
                .with_kdc_option_bits(0x0000_0010)
                .with_renew_lifetime(Some(Duration::from_hours(10)))
                .with_etypes(vec![18_i32]),
            timestamp(1_893_553_451)?,
            654_321,
            &decode_hex(TGS_REQ_CONFOUNDER)?,
        )
        .context("TGT renewal TGS-REQ builds")?;
        let decoded: rasn_kerberos::TgsReq =
            der::decode(request.der()).context("TGS-REQ decodes")?;
        let expected_options = 0x0000_0010 | KDC_OPTION_RENEWABLE | KDC_OPTION_RENEW;

        assert_eq!(request.kdc_realm(), "TEST.GOKRB5");
        assert_eq!(request.service(), &Principal::tgt_service("TEST.GOKRB5"));
        let body = &decoded.0.req_body;
        assert_eq!(
            body.kdc_options.0.as_raw_slice(),
            expected_options.to_be_bytes().as_slice()
        );
        assert_eq!(
            principal_from_parts(&body.realm, body.sname.as_ref().context("sname")?)?,
            Principal::tgt_service("TEST.GOKRB5")
        );
        assert_eq!(
            system_time_from_kerberos_time(body.rtime.as_ref().context("renew time")?)?,
            timestamp(1_893_589_450)?
        );
        Ok(())
    }

    /// Pins that a ticket renewal request names the service and sets the renew options.
    #[test]
    fn builds_ticket_renewal_req_sets_service_and_renew_options() -> Result<(), TestError> {
        let tgt = sample_tgt_session()?;
        let service_ticket = sample_service_ticket_session(&tgt)?;
        let request = build_ticket_renewal_req_with_confounder(
            &service_ticket,
            TgsReq::new(timestamp(1_893_553_450)?, 0x8877_6655)
                .with_kdc_option_bits(0x0000_0010)
                .with_renew_lifetime(Some(Duration::from_hours(10)))
                .with_etypes(vec![18_i32]),
            timestamp(1_893_553_451)?,
            654_321,
            &decode_hex(TGS_REQ_CONFOUNDER)?,
        )
        .context("service-ticket renewal TGS-REQ builds")?;
        let decoded: rasn_kerberos::TgsReq =
            der::decode(request.der()).context("TGS-REQ decodes")?;
        let expected_options = 0x0000_0010 | KDC_OPTION_RENEWABLE | KDC_OPTION_RENEW;

        assert_eq!(request.kdc_realm(), "TEST.GOKRB5");
        assert_eq!(request.service(), &sample_service_principal());
        let body = &decoded.0.req_body;
        assert_eq!(
            body.kdc_options.0.as_raw_slice(),
            expected_options.to_be_bytes().as_slice()
        );
        assert_eq!(
            principal_from_parts(&body.realm, body.sname.as_ref().context("sname")?)?,
            sample_service_principal()
        );
        assert_eq!(
            system_time_from_kerberos_time(body.rtime.as_ref().context("renew time")?)?,
            timestamp(1_893_589_450)?
        );
        Ok(())
    }

    /// Pins that a valid TGS-REP yields the service ticket and exports it as a ccache credential.
    #[test]
    fn processes_tgs_rep_and_exports_ccache_credential() -> Result<(), TestError> {
        let tgt = sample_tgt_session()?;
        let request = sample_tgs_request(&tgt)?;
        let response = synthetic_tgs_rep(&request, request.nonce(), tgt.session_key())?;

        let session =
            process_tgs_rep(&request, &response, tgt.session_key()).context("TGS-REP validates")?;

        assert_eq!(
            session.client(),
            &Principal::user("TEST.GOKRB5", "testuser1")
        );
        assert_eq!(session.service(), &sample_service_principal());
        assert_eq!(session.session_key().etype(), 18_i32);
        assert_eq!(
            hex_encode(session.session_key().value())?,
            SERVICE_SESSION_KEY
        );
        assert_eq!(session.ticket_flags(), *TICKET_FLAGS);
        assert_eq!(session.auth_time(), timestamp(1_893_553_445)?);
        assert_eq!(session.start_time(), timestamp(1_893_553_446)?);
        assert_eq!(session.end_time(), timestamp(1_893_560_646)?);
        assert_eq!(session.renew_till(), Some(timestamp(1_894_071_846)?));

        let credential = session
            .to_ccache_credential()
            .context("ccache credential converts")?;
        assert_eq!(credential.client().components, vec!["testuser1"]);
        assert_eq!(
            credential.server().components,
            vec!["HTTP", "host.test.gokrb5"]
        );
        assert_eq!(
            credential.key().value().as_slice(),
            decode_hex(SERVICE_SESSION_KEY)?
        );
        assert_eq!(credential.times().auth_time, 1_893_553_445);
        assert_eq!(credential.times().start_time, 1_893_553_446);
        assert_eq!(credential.times().end_time, 1_893_560_646);
        assert!(!credential.ticket().is_empty(), "the ticket is not empty");
        Ok(())
    }

    /// Pins that a KRB-ERROR in place of a TGS-REP surfaces as a KDC error.
    #[test]
    fn process_tgs_rep_surfaces_kdc_error_response() -> Result<(), TestError> {
        let tgt = sample_tgt_session()?;
        let request = sample_tgs_request(&tgt)?;
        let error = process_tgs_rep(
            &request,
            &synthetic_preauth_required_error()?,
            tgt.session_key(),
        )
        .err()
        .context("KRB-ERROR response is surfaced")?;

        assert!(matches!(
            error,
            Error::Kdc(kdc_error) if kdc_error.error_code() == KDC_ERR_PREAUTH_REQUIRED
        ));
        Ok(())
    }

    /// Pins that referral processing accepts an intermediate TGT that strict processing rejects.
    #[test]
    fn process_tgs_rep_with_referral_accepts_intermediate_tgt() -> Result<(), TestError> {
        let tgt = sample_tgt_session()?;
        let request = sample_tgs_request(&tgt)?;
        let referral = Principal::new("TEST.GOKRB5", 2, ["krbtgt", "RESDOM.GOKRB5"]);
        let response = synthetic_tgs_rep_with_service(
            &request,
            request.nonce(),
            tgt.session_key(),
            &referral,
        )?;

        let strict = process_tgs_rep(&request, &response, tgt.session_key())
            .err()
            .context("strict TGS-REP validation rejects referrals")?;
        assert!(matches!(
            strict,
            Error::ServicePrincipalMismatch {
                expected: _,
                actual: _
            }
        ));

        let session = process_tgs_rep_with_referral(&request, &response, tgt.session_key())
            .context("referral TGS-REP validates")?;
        assert_eq!(
            session.client(),
            &Principal::user("TEST.GOKRB5", "testuser1")
        );
        assert_eq!(session.service(), &referral);
        assert_eq!(session.session_key().etype(), 18_i32);
        assert!(!session.ticket().is_empty(), "the ticket is not empty");
        Ok(())
    }

    /// Pins that the TGS exchange sends the request through the `KdcTransport` to the KDC realm.
    #[test]
    fn exchange_tgs_req_uses_transport_boundary() -> Result<(), TestError> {
        let tgt = sample_tgt_session()?;
        let request = sample_tgs_request(&tgt)?;
        let response = synthetic_tgs_rep(&request, request.nonce(), tgt.session_key())?;
        let mut transport = MockTransport {
            expected_realm: "TEST.GOKRB5".to_owned(),
            expected_request: request.der().to_vec(),
            response,
            called: false,
        };

        let session = exchange_tgs_req(&mut transport, &request, tgt.session_key())
            .context("transport exchange works")?;

        assert!(transport.called);
        assert_eq!(session.service(), &sample_service_principal());
        Ok(())
    }

    /// Pins that `S4U2Self` goes through the `KdcTransport` and returns the impersonated session.
    #[test]
    fn s4u2self_uses_transport_boundary() -> Result<(), TestError> {
        let mut service_tgt = sample_tgt_session()?;
        service_tgt.set_client(sample_service_principal());
        let user = Principal::user("TEST.GOKRB5", "delegated-user");
        let mut transport = S4uTransport {
            session_key: service_tgt.session_key().clone(),
            expected_service: service_tgt.client().clone(),
            expected_user: user.clone(),
            calls: 0,
        };

        let session = s4u2self(
            &mut transport,
            &service_tgt,
            user.clone(),
            TgsReq::new(timestamp(1_893_553_450)?, 0x6677_8899)
                .with_etypes(vec![18_i32])
                .with_delegation_keytab(delegation_keytab()?),
        )
        .context("S4U2Self exchange succeeds")?;

        assert_eq!(transport.calls, 1);
        assert_eq!(session.client(), &user);
        assert_eq!(session.service(), service_tgt.client());
        Ok(())
    }

    /// Pins that `S4U2Proxy` goes through the `KdcTransport` and returns the delegated session.
    #[test]
    fn s4u2proxy_uses_transport_boundary() -> Result<(), TestError> {
        let user_tgt = sample_tgt_session()?;
        let evidence_ticket = sample_service_ticket_session(&user_tgt)?;
        let mut service_tgt = sample_tgt_session()?;
        service_tgt.set_client(sample_service_principal());
        let target_service = Principal::new("TEST.GOKRB5", 2, ["HTTP", "backend.test.gokrb5"]);
        let mut transport = S4u2ProxyTransport {
            session_key: service_tgt.session_key().clone(),
            expected_frontend_service: service_tgt.client().clone(),
            expected_target_service: target_service.clone(),
            expected_client: evidence_ticket.client().clone(),
            calls: 0,
        };

        let session = s4u2proxy(
            &mut transport,
            &service_tgt,
            &evidence_ticket,
            target_service.clone(),
            TgsReq::new(timestamp(1_893_553_450)?, 0x6655_4433)
                .with_etypes(vec![18_i32])
                .with_delegation_keytab(delegation_keytab()?),
        )
        .context("S4U2Proxy exchange succeeds")?;

        assert_eq!(transport.calls, 1);
        assert_eq!(session.client(), evidence_ticket.client());
        assert_eq!(session.service(), &target_service);
        Ok(())
    }

    /// Pins that the Tokio transport performs `S4U2Self` against a TCP KDC.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_transport_s4u2self_uses_tcp_kdc() -> Result<(), TestError> {
        runtime()?.block_on(async {
            let mut service_tgt = current_tgt_session(5, 180)?;
            service_tgt.set_client(sample_service_principal());
            let user = Principal::user("TEST.GOKRB5", "delegated-user");
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .context("bind local KDC listener")?;
            let addr = listener.local_addr().context("local listener address")?;

            let task = tokio::spawn(serve_s4u2self_tcp_request(
                listener,
                service_tgt.session_key().clone(),
                service_tgt.client().clone(),
                user.clone(),
            ));

            let session = TokioKdcTransport::new()
                .s4u2self(
                    KdcProtocol::Tcp,
                    addr,
                    &service_tgt,
                    user.clone(),
                    TgsReq::new(timestamp(1_893_553_450)?, 0x6677_8899)
                        .with_etypes(vec![18_i32])
                        .with_delegation_keytab(delegation_keytab()?),
                )
                .await
                .context("Tokio transport S4U2Self succeeds")?;
            task.await.context("KDC task succeeds")??;

            assert_eq!(session.client(), &user);
            assert_eq!(session.service(), service_tgt.client());
            Ok::<(), TestError>(())
        })?;
        Ok(())
    }

    /// Pins that the Tokio client performs `S4U2Self` with its current TGT, bypassing the service cache.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_s4u2self_uses_current_service_tgt_without_service_cache()
    -> Result<(), TestError> {
        runtime()?.block_on(async {
            let mut service_tgt = current_tgt_session(5, 180)?;
            service_tgt.set_client(sample_service_principal());
            let user = Principal::user("TEST.GOKRB5", "delegated-user");
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .context("bind local KDC listener")?;
            let addr = listener.local_addr().context("local listener address")?;
            let mut client = Tokio::from_tgt_session(
                config_with_kdc_server(&addr.to_string())?,
                KdcProtocol::Tcp,
                service_tgt.clone(),
            );

            let task = tokio::spawn(serve_s4u2self_tcp_request(
                listener,
                service_tgt.session_key().clone(),
                service_tgt.client().clone(),
                user.clone(),
            ));

            let session = client
                .s4u2self_with_options(
                    user.clone(),
                    TgsReq::new(timestamp(1_893_553_450)?, 0x7766_5544)
                        .with_etypes(vec![18_i32])
                        .with_delegation_keytab(delegation_keytab()?),
                )
                .await
                .context("Tokio client S4U2Self succeeds")?;
            task.await.context("KDC task succeeds")??;

            assert_eq!(session.client(), &user);
            assert_eq!(session.service(), service_tgt.client());
            assert_eq!(client.cached_service_ticket_count(), 0);
            Ok::<(), TestError>(())
        })?;
        Ok(())
    }

    /// Pins that the Tokio transport performs `S4U2Proxy` against a TCP KDC.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_transport_s4u2proxy_uses_tcp_kdc() -> Result<(), TestError> {
        runtime()?.block_on(async {
            let user_tgt = sample_tgt_session()?;
            let evidence_ticket = sample_service_ticket_session(&user_tgt)?;
            let mut service_tgt = current_tgt_session(5, 180)?;
            service_tgt.set_client(sample_service_principal());
            let target_service = Principal::new("TEST.GOKRB5", 2, ["HTTP", "backend.test.gokrb5"]);
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .context("bind local KDC listener")?;
            let addr = listener.local_addr().context("local listener address")?;

            let task = tokio::spawn(serve_s4u2proxy_tcp_request(
                listener,
                service_tgt.session_key().clone(),
                service_tgt.client().clone(),
                target_service.clone(),
                evidence_ticket.client().clone(),
            ));

            let session = TokioKdcTransport::new()
                .s4u2proxy(
                    KdcProtocol::Tcp,
                    addr,
                    &service_tgt,
                    &evidence_ticket,
                    target_service.clone(),
                    TgsReq::new(timestamp(1_893_553_450)?, 0x2233_4455)
                        .with_etypes(vec![18_i32])
                        .with_delegation_keytab(delegation_keytab()?),
                )
                .await
                .context("Tokio transport S4U2Proxy succeeds")?;
            task.await.context("KDC task succeeds")??;

            assert_eq!(session.client(), evidence_ticket.client());
            assert_eq!(session.service(), &target_service);
            Ok::<(), TestError>(())
        })?;
        Ok(())
    }

    /// Pins that the Tokio client performs `S4U2Proxy` with its current TGT, bypassing the service cache.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_s4u2proxy_uses_current_service_tgt_without_service_cache()
    -> Result<(), TestError> {
        runtime()?.block_on(async {
            let user_tgt = sample_tgt_session()?;
            let evidence_ticket = sample_service_ticket_session(&user_tgt)?;
            let mut service_tgt = current_tgt_session(5, 180)?;
            service_tgt.set_client(sample_service_principal());
            let target_service = Principal::new("TEST.GOKRB5", 2, ["HTTP", "backend.test.gokrb5"]);
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .context("bind local KDC listener")?;
            let addr = listener.local_addr().context("local listener address")?;
            let mut client = Tokio::from_tgt_session(
                config_with_kdc_server(&addr.to_string())?,
                KdcProtocol::Tcp,
                service_tgt.clone(),
            );

            let task = tokio::spawn(serve_s4u2proxy_tcp_request(
                listener,
                service_tgt.session_key().clone(),
                service_tgt.client().clone(),
                target_service.clone(),
                evidence_ticket.client().clone(),
            ));

            let session = client
                .s4u2proxy_with_options(
                    &evidence_ticket,
                    target_service.clone(),
                    TgsReq::new(timestamp(1_893_553_450)?, 0x3344_5566)
                        .with_etypes(vec![18_i32])
                        .with_delegation_keytab(delegation_keytab()?),
                )
                .await
                .context("Tokio client S4U2Proxy succeeds")?;
            task.await.context("KDC task succeeds")??;

            assert_eq!(session.client(), evidence_ticket.client());
            assert_eq!(session.service(), &target_service);
            assert_eq!(client.cached_service_ticket_count(), 0);
            Ok::<(), TestError>(())
        })?;
        Ok(())
    }

    /// Pins that TGT renewal goes through the `KdcTransport`.
    #[test]
    fn renew_tgt_uses_transport_boundary() -> Result<(), TestError> {
        let tgt = sample_tgt_session()?;
        let mut transport = RenewalTransport {
            session_key: tgt.session_key().clone(),
            expected_service: Principal::tgt_service("TEST.GOKRB5"),
            calls: 0,
        };

        let session = renew_tgt(
            &mut transport,
            &tgt,
            TgsReq::new(timestamp(1_893_553_450)?, 0x6677_8899).with_etypes(vec![18_i32]),
        )
        .context("TGT renewal succeeds")?;

        assert_eq!(transport.calls, 1);
        assert_eq!(
            session.client(),
            &Principal::user("TEST.GOKRB5", "testuser1")
        );
        assert_eq!(session.service(), &Principal::tgt_service("TEST.GOKRB5"));
        assert!(!session.ticket().is_empty(), "the ticket is not empty");
        Ok(())
    }

    /// Pins that service-ticket renewal goes through the `KdcTransport`.
    #[test]
    fn renew_ticket_uses_transport_boundary() -> Result<(), TestError> {
        let tgt = sample_tgt_session()?;
        let service_ticket = sample_service_ticket_session(&tgt)?;
        let mut transport = RenewalTransport {
            session_key: service_ticket.session_key().clone(),
            expected_service: sample_service_principal(),
            calls: 0,
        };

        let session = renew_ticket(
            &mut transport,
            &service_ticket,
            TgsReq::new(timestamp(1_893_553_450)?, 0x7766_5544).with_etypes(vec![18_i32]),
        )
        .context("service-ticket renewal succeeds")?;

        assert_eq!(transport.calls, 1);
        assert_eq!(
            session.client(),
            &Principal::user("TEST.GOKRB5", "testuser1")
        );
        assert_eq!(session.service(), &sample_service_principal());
        assert!(!session.ticket().is_empty(), "the ticket is not empty");
        Ok(())
    }

    /// Pins that a TGS-REP session key outside the requested etypes is rejected.
    #[test]
    fn process_tgs_rep_rejects_session_key_outside_requested_enctypes() -> Result<(), TestError> {
        let tgt = sample_tgt_session()?;
        let request = build_tgs_req_with_confounder(
            &tgt,
            sample_service_principal(),
            TgsReq::new(timestamp(1_893_553_450)?, 0x5566_7788).with_etypes(vec![17_i32]),
            timestamp(1_893_553_451)?,
            654_321,
            &decode_hex(TGS_REQ_CONFOUNDER)?,
        )?;
        let response = synthetic_tgs_rep(&request, request.nonce(), tgt.session_key())?;

        let Err(error) = process_tgs_rep(&request, &response, tgt.session_key()) else {
            return Err("a session key outside the requested list must be rejected".into());
        };
        assert!(matches!(error, Error::EnctypeNotRequested(18_i32)));
        Ok(())
    }

    /// Pins that the configured AS exchange rejects a session key outside `permitted_enctypes`.
    #[cfg(feature = "tokio")]
    #[test]
    fn exchange_as_req_with_config_rejects_session_key_outside_permitted_enctypes()
    -> Result<(), TestError> {
        runtime()?.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            let config = Config::parse(&format!(
                "
[libdefaults]
 dns_lookup_kdc = false
 permitted_enctypes = des3-cbc-sha1-kd
 allow_des3 = true

[realms]
 TEST.GOKRB5 = {{
  kdc = {addr}
 }}
"
            ))?;
            let request = build_tgt_as_req(
                Principal::user("TEST.GOKRB5", "testuser1"),
                AsReq::new(timestamp(1_893_553_447)?, 0x1122_3344).with_etypes(vec![18_i32]),
            )?;
            let reply_key = reply_key()?;
            let response = synthetic_as_rep_with_reply_key(
                &request,
                request.nonce(),
                request.service(),
                &reply_key,
            )?;
            let task = tokio::spawn(async move {
                let (_request, mut socket) = read_tcp_kdc_request(&listener).await?;
                write_tcp_kdc_response(&mut socket, &response).await?;
                Ok::<(), TestError>(())
            });

            let Err(error) = TokioKdcTransport::new()
                .exchange_as_req_with_config(&config, KdcProtocol::Tcp, &request, &reply_key)
                .await
            else {
                return Err("a session key outside the permit list must be rejected".into());
            };
            task.abort();
            assert!(
                task.await
                    .err()
                    .context("peer was never contacted")?
                    .is_cancelled()
            );
            assert!(matches!(
                error,
                Error::Crypto(Crypto::Policy(Policy::EnctypeNotPermitted {
                    etype: 18_i32,
                    usage: _
                }))
            ));
            Ok::<(), TestError>(())
        })
    }

    /// Pins that the configured TGS exchange rejects a session key outside `permitted_enctypes`.
    #[cfg(feature = "tokio")]
    #[test]
    fn exchange_tgs_req_with_config_rejects_session_key_outside_permitted_enctypes()
    -> Result<(), TestError> {
        runtime()?.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            let config = Config::parse(&format!(
                "
[libdefaults]
 dns_lookup_kdc = false
 permitted_enctypes = des3-cbc-sha1-kd
 allow_des3 = true

[realms]
 TEST.GOKRB5 = {{
  kdc = {addr}
 }}
"
            ))?;
            let tgt = sample_tgt_session()?;
            let request = build_tgs_req_with_confounder(
                &tgt,
                sample_service_principal(),
                TgsReq::new(timestamp(1_893_553_450)?, 0x5566_7788).with_etypes(vec![18_i32]),
                timestamp(1_893_553_451)?,
                654_321,
                &decode_hex(TGS_REQ_CONFOUNDER)?,
            )?;
            let response = synthetic_tgs_rep(&request, request.nonce(), tgt.session_key())?;
            let task = tokio::spawn(async move {
                let (_request, mut socket) = read_tcp_kdc_request(&listener).await?;
                write_tcp_kdc_response(&mut socket, &response).await?;
                Ok::<(), TestError>(())
            });

            let Err(error) = TokioKdcTransport::new()
                .exchange_tgs_req_with_config(
                    &config,
                    KdcProtocol::Tcp,
                    &request,
                    tgt.session_key(),
                )
                .await
            else {
                return Err("a session key outside the permit list must be rejected".into());
            };
            task.abort();
            assert!(
                task.await
                    .err()
                    .context("peer was never contacted")?
                    .is_cancelled()
            );
            assert!(matches!(
                error,
                Error::Crypto(Crypto::Policy(Policy::EnctypeNotPermitted {
                    etype: 18_i32,
                    usage: _
                }))
            ));
            Ok::<(), TestError>(())
        })
    }

    /// Pins rejection of a mixed disabled TGS-REQ enctype list without narrowing.
    #[test]
    fn tgs_req_rejects_mixed_disabled_enctype_list() -> Result<(), TestError> {
        let defaults = LibDefaults::default()
            .with_default_tgs_enctypes(vec![
                "aes256-cts".into(),
                "aes128-cts".into(),
                "rc4-hmac".into(),
            ])
            .with_permitted_enctypes(vec!["aes256-cts".into()])
            .with_permitted_enctypes_explicit(true.into());
        let options = TgsReq::from_libdefaults(timestamp(1_893_553_450)?, 0x5566_7788, &defaults);
        let request = build_tgs_req_with_confounder(
            &sample_tgt_session()?,
            sample_service_principal(),
            options,
            timestamp(1_893_553_451)?,
            654_321,
            &decode_hex(TGS_REQ_CONFOUNDER)?,
        )
        .err()
        .context("disabled mixed list is rejected")?;
        assert!(matches!(request, Error::EmptyEtypes));
        Ok(())
    }

    /// Pins that a TGS-REQ for implicit FAST armor carries the caller's subkey.
    ///
    /// RFC 6113 section 5.4.2: a TGS request that will be FAST-armored with the TGT
    /// in `PA-TGS-REQ` must carry a subkey in its authenticator, because the
    /// implicit TGS armor key is
    /// `KRB-FX-CF2(subkey, TGT session key, "subkeyarmor", "ticketarmor")`.
    ///
    /// This is the red test for the subkey seam: the unarmored builder leaves
    /// `Authenticator.subkey` as `None`, so a caller's FAST layer has no subkey
    /// to derive the armor key from. It asserts by decrypting the authenticator, not
    /// by inspecting a flag.
    #[test]
    fn tgs_req_authenticator_carries_subkey_for_implicit_armor() -> Result<(), TestError> {
        let tgt = sample_tgt_session()?;
        let service = sample_service_principal();
        let options = TgsReq::new(timestamp(1_893_553_450)?, 0x5566_7788)
            .with_ticket_lifetime(Duration::from_hours(2))
            .with_etypes(vec![18_i32]);

        let subkey = EncryptionKey::new(18, vec![0x42; 32]);
        let parts = build_tgs_req_for_realm_with_confounder_and_subkey(
            &tgt,
            "TEST.GOKRB5",
            service,
            rskrb5_ng::client::TgsRequestParts::new(
                options,
                &decode_hex(TGS_REQ_CONFOUNDER)?,
                &subkey,
            )
            .with_timestamp(timestamp(1_893_553_451)?, 654_321),
        )?;
        let decoded: rasn_kerberos::TgsReq = der::decode(parts.request().der())?;
        let padata = decoded.0.padata.as_ref().ok_or("TGS-REQ has padata")?;
        let pa_tgs_req = padata.first().ok_or("TGS-REQ has a PA-TGS-REQ")?;
        let ap_req: rasn_kerberos::ApReq = der::decode(pa_tgs_req.value.as_ref())?;

        let authenticator =
            decrypt_ap_req_authenticator(&ap_req, tgt.session_key(), TGS_REQ_AUTHENTICATOR_USAGE)?;
        let carried = authenticator
            .subkey
            .as_ref()
            .ok_or("implicit TGS armor needs the authenticator subkey (RFC 6113 section 5.4.2)")?;
        assert_eq!(
            carried.r#type,
            subkey.etype(),
            "the authenticator carries the supplied subkey's enctype"
        );
        assert_eq!(
            carried.value.as_ref(),
            subkey.value().as_slice(),
            "the authenticator carries exactly the subkey the caller supplied"
        );
        assert_eq!(
            parts.authenticator_subkey().value(),
            subkey.value(),
            "and the seam hands the same subkey back for the armor key"
        );
        Ok(())
    }

    /// Pins that the seam exposes the AP-REQ DER the outer `PA-TGS-REQ` carries.
    ///
    /// Those are the bytes RFC 6113 section 5.4.2 keys the FAST `req-checksum` over,
    /// so a caller must be able to name them without re-encoding the request.
    #[test]
    fn tgs_req_exposes_pa_tgs_req_ap_req_bytes() -> Result<(), TestError> {
        let tgt = sample_tgt_session()?;
        let service = sample_service_principal();
        let options = TgsReq::new(timestamp(1_893_553_450)?, 0x5566_7788)
            .with_ticket_lifetime(Duration::from_hours(2))
            .with_etypes(vec![18_i32]);
        let subkey = EncryptionKey::new(18, vec![0x24; 32]);

        let parts = build_tgs_req_for_realm_with_confounder_and_subkey(
            &tgt,
            "TEST.GOKRB5",
            service,
            rskrb5_ng::client::TgsRequestParts::new(
                options,
                &decode_hex(TGS_REQ_CONFOUNDER)?,
                &subkey,
            )
            .with_timestamp(timestamp(1_893_553_451)?, 654_321),
        )?;
        let decoded: rasn_kerberos::TgsReq = der::decode(parts.request().der())?;
        let padata = decoded.0.padata.as_ref().ok_or("TGS-REQ has padata")?;
        let pa_tgs_req = padata.first().ok_or("TGS-REQ has a PA-TGS-REQ")?;
        assert_eq!(pa_tgs_req.r#type, PA_TGS_REQ);
        assert_eq!(
            pa_tgs_req.value.as_ref(),
            parts.ap_req_der().as_slice(),
            "the exposed bytes are the AP-REQ the outer PA-TGS-REQ carries"
        );
        let ap_req: rasn_kerberos::ApReq = der::decode(parts.ap_req_der())?;
        assert_eq!(ap_req.msg_type, Integer::from(14_i32));
        Ok(())
    }

    /// The unarmored builders keep the shape every existing caller has: no subkey.
    #[test]
    fn legacy_tgs_builder_stays_unarmored_for_existing_callers() -> Result<(), TestError> {
        let tgt = sample_tgt_session()?;
        let service = sample_service_principal();
        let options = TgsReq::new(timestamp(1_893_553_450)?, 0x5566_7788)
            .with_ticket_lifetime(Duration::from_hours(2))
            .with_etypes(vec![18_i32]);

        let request = build_tgs_req_with_confounder(
            &tgt,
            service,
            options,
            timestamp(1_893_553_451)?,
            654_321,
            &decode_hex(TGS_REQ_CONFOUNDER)?,
        )?;
        let decoded: rasn_kerberos::TgsReq = der::decode(request.der())?;
        let padata = decoded.0.padata.as_ref().ok_or("TGS-REQ has padata")?;
        let pa_tgs_req = padata.first().ok_or("TGS-REQ has a PA-TGS-REQ")?;
        let ap_req: rasn_kerberos::ApReq = der::decode(pa_tgs_req.value.as_ref())?;

        let authenticator =
            decrypt_ap_req_authenticator(&ap_req, tgt.session_key(), TGS_REQ_AUTHENTICATOR_USAGE)?;
        assert!(
            authenticator.subkey.is_none(),
            "a caller that did not ask for implicit armor gets no subkey"
        );
        Ok(())
    }

    /// Pins that the deterministic builder refuses a subkey unlike the session key.
    ///
    /// It only accepts a subkey shaped like the random-subkey builder's, in the TGT
    /// session key's enctype and length; anything else is refused.
    #[test]
    fn tgs_subkey_must_match_the_session_key_enctype_and_length() -> Result<(), TestError> {
        let tgt = sample_tgt_session()?;
        let request_time = timestamp(1_893_553_450)?;
        let authenticator_time = timestamp(1_893_553_451)?;
        let confounder = decode_hex(TGS_REQ_CONFOUNDER)?;
        let build = |subkey: &EncryptionKey| {
            build_tgs_req_for_realm_with_confounder_and_subkey(
                &tgt,
                "TEST.GOKRB5",
                sample_service_principal(),
                rskrb5_ng::client::TgsRequestParts::new(
                    TgsReq::new(request_time, 0x5566_7788).with_etypes(vec![18_i32]),
                    &confounder,
                    subkey,
                )
                .with_timestamp(authenticator_time, 654_321),
            )
        };
        let other_etype = EncryptionKey::new(17, vec![0x42; 16]);
        let Err(error) = build(&other_etype) else {
            return Err("a subkey in another enctype must be refused".into());
        };
        assert!(matches!(
            error,
            Error::ApReqKeyEtypeMismatch {
                key_etype: 17_i32,
                encrypted_data_etype: _,
            }
        ));
        let short = EncryptionKey::new(tgt.session_key().etype(), vec![0x42; 16]);
        assert!(matches!(build(&short), Err(Error::Crypto(_))));
        Ok(())
    }

    /// Pins that the configured AS exchange rejects every session key when an
    /// explicit allowlist holds no enctype ID.
    #[cfg(feature = "tokio")]
    #[test]
    fn exchange_as_req_with_config_rejects_every_session_key_with_an_empty_explicit_allowlist()
    -> Result<(), TestError> {
        runtime()?.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            let mut config = Config::parse(&format!(
                "
[libdefaults]
 dns_lookup_kdc = false
 permitted_enctypes = aes256-cts-hmac-sha1-96

[realms]
 TEST.GOKRB5 = {{
  kdc = {addr}
 }}
"
            ))?;
            config.libdefaults.permitted_enctypes.clear();
            let request = build_tgt_as_req(
                Principal::user("TEST.GOKRB5", "testuser1"),
                AsReq::new(timestamp(1_893_553_447)?, 0x1122_3344).with_etypes(vec![18_i32]),
            )?;
            let reply_key = reply_key()?;
            let response = synthetic_as_rep_with_reply_key(
                &request,
                request.nonce(),
                request.service(),
                &reply_key,
            )?;
            let task = tokio::spawn(async move {
                let (_request, mut socket) = read_tcp_kdc_request(&listener).await?;
                write_tcp_kdc_response(&mut socket, &response).await?;
                Ok::<(), TestError>(())
            });

            let Err(error) = TokioKdcTransport::new()
                .exchange_as_req_with_config(&config, KdcProtocol::Tcp, &request, &reply_key)
                .await
            else {
                return Err("an empty explicit allowlist must permit no session key".into());
            };
            task.abort();
            assert!(
                task.await
                    .err()
                    .context("peer was never contacted")?
                    .is_cancelled()
            );
            assert!(matches!(
                error,
                Error::Crypto(Crypto::Policy(Policy::InvalidConfiguration))
            ));
            Ok::<(), TestError>(())
        })
    }

    /// Pins that the configured TGS exchange rejects every session key when an
    /// explicit allowlist holds no enctype ID.
    #[cfg(feature = "tokio")]
    #[test]
    fn exchange_tgs_req_with_config_rejects_every_session_key_with_an_empty_explicit_allowlist()
    -> Result<(), TestError> {
        runtime()?.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            let mut config = Config::parse(&format!(
                "
[libdefaults]
 dns_lookup_kdc = false
 permitted_enctypes = aes256-cts-hmac-sha1-96

[realms]
 TEST.GOKRB5 = {{
  kdc = {addr}
 }}
"
            ))?;
            config.libdefaults.permitted_enctypes.clear();
            let tgt = sample_tgt_session()?;
            let request = build_tgs_req_with_confounder(
                &tgt,
                sample_service_principal(),
                TgsReq::new(timestamp(1_893_553_450)?, 0x5566_7788).with_etypes(vec![18_i32]),
                timestamp(1_893_553_451)?,
                654_321,
                &decode_hex(TGS_REQ_CONFOUNDER)?,
            )?;
            let response = synthetic_tgs_rep(&request, request.nonce(), tgt.session_key())?;
            let task = tokio::spawn(async move {
                let (_request, mut socket) = read_tcp_kdc_request(&listener).await?;
                write_tcp_kdc_response(&mut socket, &response).await?;
                Ok::<(), TestError>(())
            });

            let Err(error) = TokioKdcTransport::new()
                .exchange_tgs_req_with_config(
                    &config,
                    KdcProtocol::Tcp,
                    &request,
                    tgt.session_key(),
                )
                .await
            else {
                return Err("an empty explicit allowlist must permit no session key".into());
            };
            task.abort();
            assert!(
                task.await
                    .err()
                    .context("peer was never contacted")?
                    .is_cancelled()
            );
            assert!(matches!(
                error,
                Error::Crypto(Crypto::Policy(Policy::InvalidConfiguration))
            ));
            Ok::<(), TestError>(())
        })
    }

    /// Pins that programmatic `LibDefaults` with the explicit flag and no permitted
    /// enctype ID fail both request builders closed.
    #[test]
    fn programmatic_explicit_empty_permitted_ids_fail_closed() -> Result<(), TestError> {
        let defaults = LibDefaults::default()
            .with_default_tkt_enctypes(vec!["aes256-cts".into(), "aes128-cts".into()])
            .with_default_tgs_enctypes(vec!["aes256-cts".into(), "aes128-cts".into()])
            .with_permitted_enctypes(Vec::new())
            .with_permitted_enctypes_explicit(true.into());

        let as_options = AsReq::from_libdefaults(timestamp(1_893_553_447)?, 0x1122_3344, &defaults);
        assert!(
            as_options.etypes().is_empty(),
            "no AS-REQ etype is permitted: {:?}",
            as_options.etypes()
        );
        let Err(as_error) =
            build_tgt_as_req(Principal::user("TEST.GOKRB5", "testuser1"), as_options)
        else {
            return Err("an empty explicit allowlist must fail the AS-REQ closed".into());
        };
        assert!(matches!(
            as_error,
            Error::Crypto(Crypto::Policy(Policy::InvalidConfiguration))
        ));

        let tgs_options =
            TgsReq::from_libdefaults(timestamp(1_893_553_450)?, 0x5566_7788, &defaults);
        assert!(
            tgs_options.etypes().is_empty(),
            "no TGS-REQ etype is permitted: {:?}",
            tgs_options.etypes()
        );
        let Err(tgs_error) = build_tgs_req_with_confounder(
            &sample_tgt_session()?,
            sample_service_principal(),
            tgs_options,
            timestamp(1_893_553_451)?,
            654_321,
            &decode_hex(TGS_REQ_CONFOUNDER)?,
        ) else {
            return Err("an empty explicit allowlist must fail the TGS-REQ closed".into());
        };
        assert!(matches!(
            tgs_error,
            Error::Crypto(Crypto::Policy(Policy::InvalidConfiguration))
        ));
        Ok(())
    }
}

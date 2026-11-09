use super::*;

/// Authenticated KDC replies must respect request time and flag constraints.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use rasn::der;
    use rskrb5_ng::kdc_rep::{decrypt_as_rep_enc_part, decrypt_tgs_rep_enc_part};

    use super::*;

    /// Alter one authenticated field while retaining valid encryption and request binding.
    #[derive(Clone, Copy)]
    enum Violation {
        EndBeyondTill,
        StartAfterEnd,
        AuthAfterStart,
        RenewBeforeEnd,
        RenewBeyondRequest,
        UnrequestedForwardable,
        UnrequestedProxiable,
        UnrequestedPostdated,
        UnrequestedRenewable,
    }

    /// Apply a single violation to an otherwise request-conforming reply.
    fn violate(part: &mut rasn_kerberos::EncKdcRepPart, case: Violation) -> Result<(), TestError> {
        match case {
            Violation::EndBeyondTill => part.end_time = kerberos_time(1_893_639_845)?,
            Violation::StartAfterEnd => part.start_time = Some(kerberos_time(1_893_553_600)?),
            Violation::AuthAfterStart => part.auth_time = kerberos_time(1_893_553_600)?,
            Violation::RenewBeforeEnd => {
                part.flags = flags(KDC_OPTION_RENEWABLE);
                part.renew_till = Some(kerberos_time(1_893_553_445)?);
            }
            Violation::RenewBeyondRequest => {
                part.flags = flags(KDC_OPTION_RENEWABLE);
                part.renew_till = Some(kerberos_time(1_894_071_845)?);
            }
            Violation::UnrequestedForwardable => part.flags = flags(0x4000_0000),
            Violation::UnrequestedProxiable => part.flags = flags(0x1000_0000),
            Violation::UnrequestedPostdated => part.flags = flags(0x0200_0000),
            Violation::UnrequestedRenewable => {
                part.flags = flags(KDC_OPTION_RENEWABLE);
                part.renew_till = Some(kerberos_time(1_893_553_500)?);
            }
        }
        Ok(())
    }

    /// Construct a wire ticket flag value.
    fn flags(bits: u32) -> rasn_kerberos::TicketFlags {
        rasn_kerberos::TicketFlags(rasn_kerberos::KerberosFlags::from_slice(
            &bits.to_be_bytes(),
        ))
    }

    /// A valid short-lived reply independent of the legacy broad fixture defaults.
    fn conform(part: &mut rasn_kerberos::EncKdcRepPart) -> Result<(), TestError> {
        part.flags = flags(0);
        part.auth_time = kerberos_time(1_893_553_445)?;
        part.start_time = Some(kerberos_time(1_893_553_445)?);
        part.end_time = kerberos_time(1_893_553_447)?;
        part.renew_till = None;
        Ok(())
    }

    /// Re-encrypt AS replies with one changed field or a valid shorter lifetime.
    fn as_reply(request: &BuiltAsReq, case: Option<Violation>) -> Result<Vec<u8>, TestError> {
        let key = reply_key()?;
        let mut reply: rasn_kerberos::AsRep =
            der::decode(&synthetic_as_rep(request, request.nonce())?)?;
        let mut part = decrypt_as_rep_enc_part(&reply, &key)?;
        conform(&mut part)?;
        if let Some(violation) = case {
            violate(&mut part, violation)?;
        }
        reply.0.enc_part.cipher = encrypt_message(
            &key,
            &der::encode(&rasn_kerberos::EncAsRepPart(part))?,
            AS_REP_ENCPART_USAGE,
            AS_REP_CONFOUNDER,
        )?
        .into();
        Ok(der::encode(&reply)?)
    }

    /// Re-encrypt TGS replies with one changed field or a valid shorter lifetime.
    fn tgs_reply(request: &BuiltTgsReq, case: Option<Violation>) -> Result<Vec<u8>, TestError> {
        let key = EncryptionKey::new(18, decode_hex(SESSION_KEY)?);
        let mut reply: rasn_kerberos::TgsRep =
            der::decode(&synthetic_tgs_rep(request, request.nonce(), &key)?)?;
        let mut part = decrypt_tgs_rep_enc_part(&reply, &key)?;
        conform(&mut part)?;
        if let Some(violation) = case {
            violate(&mut part, violation)?;
        }
        reply.0.enc_part.cipher = encrypt_message(
            &key,
            &der::encode(&rasn_kerberos::EncTgsRepPart(part))?,
            TGS_REP_ENCPART_SESSION_KEY_USAGE,
            TGS_REP_CONFOUNDER,
        )?
        .into();
        Ok(der::encode(&reply)?)
    }

    /// Each time or flag violation is rejected by both authenticated reply processors.
    #[test]
    fn authenticated_replies_reject_request_constraint_violations() -> Result<(), TestError> {
        let as_request = build_tgt_as_req(
            Principal::user("TEST.GOKRB5", "testuser1"),
            AsReq::new(timestamp(1_893_553_447)?, 42).with_ticket_lifetime(Duration::from_secs(1)),
        )?;
        let tgt = sample_tgt_session()?;
        let tgs_request = build_tgs_req_with_confounder(
            &tgt,
            sample_service_principal(),
            TgsReq::new(timestamp(1_893_553_447)?, 42).with_ticket_lifetime(Duration::from_secs(1)),
            timestamp(1_893_553_447)?,
            0,
            &decode_hex(TGS_REQ_CONFOUNDER)?,
        )?;
        let mut accepted = Vec::new();
        for case in [
            Violation::EndBeyondTill,
            Violation::StartAfterEnd,
            Violation::AuthAfterStart,
            Violation::RenewBeforeEnd,
            Violation::RenewBeyondRequest,
            Violation::UnrequestedForwardable,
            Violation::UnrequestedProxiable,
            Violation::UnrequestedPostdated,
            Violation::UnrequestedRenewable,
        ] {
            // Given/When: an authentic reply changes one requested constraint.
            let as_result = process_as_rep(
                &as_request,
                &as_reply(&as_request, Some(case))?,
                &reply_key()?,
            );
            let tgs_result = process_tgs_rep(
                &tgs_request,
                &tgs_reply(&tgs_request, Some(case))?,
                tgt.session_key(),
            );
            // Then: neither exchange imports the malformed credential.
            accepted.push((as_result.is_ok(), tgs_result.is_ok()));
        }
        assert_eq!(accepted, vec![(false, false); 9]);
        Ok(())
    }

    /// Shorter valid tickets remain accepted; request bounds are not equality requirements.
    #[test]
    fn authenticated_replies_accept_shorter_lifetimes() -> Result<(), TestError> {
        let request = sample_request()?;
        let session = process_as_rep(&request, &as_reply(&request, None)?, &reply_key()?)?;
        assert_eq!(session.end_time(), timestamp(1_893_553_447)?);
        let tgt = sample_tgt_session()?;
        let tgs_request = sample_tgs_request(&tgt)?;
        let tgs_session = process_tgs_rep(
            &tgs_request,
            &tgs_reply(&tgs_request, None)?,
            tgt.session_key(),
        )?;
        assert_eq!(tgs_session.end_time(), timestamp(1_893_553_447)?);
        Ok(())
    }

    /// Explicit renewable bounds reject excess even when the renewable flag is requested.
    #[test]
    fn renewable_horizon_is_bounded_by_rtime() -> Result<(), TestError> {
        let request = build_tgt_as_req(
            Principal::user("TEST.GOKRB5", "testuser1"),
            AsReq::new(timestamp(1_893_553_447)?, 42)
                .with_renew_lifetime(Some(Duration::from_secs(60))),
        )?;
        assert!(matches!(
            process_as_rep(
                &request,
                &as_reply(&request, Some(Violation::RenewBeyondRequest))?,
                &reply_key()?
            ),
            Err(Error::ReplyTimeConstraint)
        ));
        Ok(())
    }

    /// Unrequested renewal metadata does not activate either optional request bound.
    #[test]
    fn unrequested_renewal_metadata_ignores_optional_bounds() -> Result<(), TestError> {
        let mut request = build_tgt_as_req(
            Principal::user("TEST.GOKRB5", "testuser1"),
            AsReq::new(timestamp(1_893_553_447)?, 42),
        )?;
        let mut message = request.message().clone();
        message.0.req_body.till = kerberos_time(1_893_553_499)?;
        message.0.req_body.rtime = Some(kerberos_time(1_893_553_499)?);
        request.set_message(message);
        let key = reply_key()?;
        let mut reply: rasn_kerberos::AsRep = der::decode(&as_reply(&request, None)?)?;
        let mut part = decrypt_as_rep_enc_part(&reply, &key)?;
        part.renew_till = Some(kerberos_time(1_893_553_500)?);
        reply.0.enc_part.cipher = encrypt_message(
            &key,
            &der::encode(&rasn_kerberos::EncAsRepPart(part))?,
            AS_REP_ENCPART_USAGE,
            AS_REP_CONFOUNDER,
        )?
        .into();
        let session = process_as_rep(&request, &der::encode(&reply)?, &key)?;
        assert_eq!(session.renew_till(), Some(timestamp(1_893_553_500)?));
        Ok(())
    }

    /// Only postdated requests bind the granted start to the requested from time.
    #[test]
    fn requested_from_binds_only_postdated_replies() -> Result<(), TestError> {
        for (options, from, accepted) in [
            (0_u32, 1_893_553_446_u64, true),
            (0x0200_0000, 1_893_553_445, true),
            (0x0200_0000, 1_893_553_446, false),
        ] {
            let mut request = build_tgt_as_req(
                Principal::user("TEST.GOKRB5", "testuser1"),
                AsReq::new(timestamp(1_893_553_447)?, 42).with_kdc_option_bits(options),
            )?;
            let mut message = request.message().clone();
            message.0.req_body.from = Some(kerberos_time(from)?);
            request.set_message(message);
            if options != 0 {
                request.set_reply_clock((timestamp(0)?, request.reply_clock().1));
            }
            let result = process_as_rep(&request, &as_reply(&request, None)?, &reply_key()?);
            assert_eq!(result.is_ok(), accepted);
        }
        Ok(())
    }

    /// Configured clock skew accepts its boundary and rejects one second beyond it.
    #[test]
    fn reply_start_obeys_configured_skew_boundary() -> Result<(), TestError> {
        let config = Config::parse("[libdefaults]\n clockskew = 2s\n")?;
        let mut request = build_tgt_as_req(
            Principal::user("TEST.GOKRB5", "testuser1"),
            AsReq::from_libdefaults(timestamp(1_893_553_447)?, 42, &config.libdefaults),
        )?;
        let bytes = as_reply(&request, None)?;
        let accepted = process_as_rep(&request, &bytes, &reply_key()?)?;
        assert_eq!(accepted.start_time(), timestamp(1_893_553_445)?);
        request.set_reply_clock((timestamp(1_893_553_448)?, request.reply_clock().1));
        assert!(matches!(
            process_as_rep(&request, &bytes, &reply_key()?),
            Err(Error::ReplyTimeConstraint)
        ));
        Ok(())
    }

    /// Renewable-OK permits renewable replies only within the originally requested lifetime.
    #[test]
    fn renewable_ok_accepts_bounded_renewal() -> Result<(), TestError> {
        let mut request = build_tgt_as_req(
            Principal::user("TEST.GOKRB5", "testuser1"),
            AsReq::new(timestamp(1_893_553_447)?, 42).with_kdc_option_bits(0x0000_0010),
        )?;
        let bytes = as_reply(&request, Some(Violation::UnrequestedRenewable))?;
        let accepted = process_as_rep(&request, &bytes, &reply_key()?)?;
        assert_eq!(accepted.renew_till(), Some(timestamp(1_893_553_500)?));
        let mut message = request.message().clone();
        message.0.req_body.till = kerberos_time(1_893_553_499)?;
        request.set_message(message);
        assert!(matches!(
            process_as_rep(&request, &bytes, &reply_key()?),
            Err(Error::ReplyTimeConstraint)
        ));
        Ok(())
    }

    /// Renewal may preserve a capability not repeated in the renewal options.
    #[test]
    fn renewal_accepts_inherited_forwardable_flag() -> Result<(), TestError> {
        let tgt = sample_tgt_session()?;
        let request = build_tgt_renewal_req_with_confounder(
            &tgt,
            TgsReq::new(timestamp(1_893_553_447)?, 42),
            timestamp(1_893_553_447)?,
            0,
            &decode_hex(TGS_REQ_CONFOUNDER)?,
        )?;
        let accepted = process_tgs_rep(
            &request,
            &tgs_reply(&request, Some(Violation::UnrequestedForwardable))?,
            tgt.session_key(),
        )?;
        assert_eq!(u32::from_be_bytes(accepted.ticket_flags()), 0x4000_0000);
        Ok(())
    }
}

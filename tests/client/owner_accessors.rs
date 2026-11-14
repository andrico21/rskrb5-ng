use super::*;

/// Accessors and setters of the private client owners return what was stored.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use rskrb5_ng::{client::build_tgs_req_for_realm_with_subkey, crypto::CryptoPolicy};

    use super::*;

    /// Session validity and key-expiration setters are read back unchanged.
    #[test]
    fn session_times_are_replaced() -> Result<(), TestError> {
        let mut session = sample_tgt_session()?;
        let start = timestamp(1_893_553_000)?;
        let end = timestamp(1_893_560_000)?;
        let expiry = timestamp(1_893_570_000)?;
        session.set_start_time(start);
        session.set_end_time(end);
        session.set_key_expiration(Some(expiry));
        assert_eq!(session.start_time(), start);
        assert_eq!(session.end_time(), end);
        assert_eq!(session.key_expiration(), Some(expiry));
        Ok(())
    }

    /// Built requests keep the replacement message, keys and delegation keytab.
    #[test]
    fn built_request_replacements_are_kept() -> Result<(), TestError> {
        let session = sample_tgt_session()?;
        let confounder = decode_hex(TGS_REQ_CONFOUNDER)?;
        let mut ap = build_ap_req_with_confounder(
            &session,
            ApReq::new(),
            timestamp(1_893_553_452)?,
            123,
            &confounder,
        )?;
        let other = build_ap_req_with_confounder(
            &session,
            ApReq::new(),
            timestamp(1_893_553_453)?,
            456,
            &confounder,
        )?;
        assert_ne!(ap.message(), other.message());
        ap.set_message(other.message().clone());
        assert_eq!(ap.message(), other.message());
        let key = EncryptionKey::new(17, vec![0x5a; 16]);
        ap.set_session_key(key.clone());
        assert_eq!(ap.session_key(), &key);

        let mut keytab = Keytab::new();
        keytab.entries_mut().push(KeytabEntry::new(
            KeytabPrincipal::new("TEST.GOKRB5", 1, ["service"]),
            1,
            1,
            EncryptionKey::new(17, vec![0x3c; 16]),
            1,
        ));
        let service = Principal::user("TEST.GOKRB5", "service");
        let mut tgs = build_tgs_req_with_confounder(
            &session,
            service.clone(),
            TgsReq::new(timestamp(1_893_553_452)?, 42).with_delegation_keytab(keytab.clone()),
            timestamp(1_893_553_452)?,
            123,
            &confounder,
        )?;
        assert_eq!(tgs.delegation_keytab(), Some(&keytab));
        let replacement = build_tgs_req_with_confounder(
            &session,
            service.clone(),
            TgsReq::new(timestamp(1_893_553_452)?, 43),
            timestamp(1_893_553_452)?,
            123,
            &confounder,
        )?;
        assert_ne!(tgs.message(), replacement.message());
        tgs.set_message(replacement.message().clone());
        assert_eq!(tgs.message(), replacement.message());

        let mut fast = build_tgs_req_for_realm_with_subkey(
            &session,
            "TEST.GOKRB5",
            service,
            TgsReq::new(timestamp(1_893_553_452)?, 44),
        )?;
        fast.set_authenticator_subkey(key.clone());
        assert_eq!(fast.authenticator_subkey(), &key);
        Ok(())
    }

    /// KRB-ERROR preauthentication setters are read back unchanged.
    #[test]
    fn kdc_error_preauth_replacements_are_kept() -> Result<(), TestError> {
        let padata = rasn_kerberos::PaData {
            r#type: PA_ETYPE_INFO2,
            value: vec![0x30, 0x00].into(),
        };
        let hint = PreauthKeyInfo::new(17).with_salt(Some("TEST.GOKRB5alice".to_owned()));
        let mut error = KdcError::new(
            timestamp(1_893_553_452)?,
            0,
            KDC_ERR_PREAUTH_REQUIRED,
            Principal::tgt_service("TEST.GOKRB5"),
        );
        error.set_method_data(vec![padata.clone()]);
        error.set_preauth_key_info(vec![hint.clone()]);
        assert_eq!(error.method_data(), [padata]);
        assert_eq!(error.preauth_key_info(), [hint]);
        Ok(())
    }

    /// Attaching a delegation keytab replaces the one already retained.
    #[test]
    fn delegation_keytab_attachment_replaces_the_previous_keytab() -> Result<(), TestError> {
        let replacement = delegation_keytab()?;
        let options = TgsReq::new(timestamp(1_893_553_452)?, 42)
            .with_delegation_keytab(Keytab::new())
            .with_delegation_keytab(replacement.clone());
        assert_eq!(options.delegation_keytab(), Some(&replacement));
        Ok(())
    }
    /// The private fields of the explicit TGS request inputs are read and taken back unchanged.
    #[test]
    fn tgs_request_parts_return_configured_components() -> Result<(), TestError> {
        let options = TgsReq::new(timestamp(1_893_553_452)?, 42);
        let subkey = EncryptionKey::new(18, vec![0x22; 32]);
        let confounder = [0x11_u8; 16];
        let at = timestamp(1_893_553_500)?;
        let parts = rskrb5_ng::client::TgsRequestParts::new(options.clone(), &confounder, &subkey)
            .with_timestamp(at, 7);
        assert_eq!(parts.options().nonce(), options.nonce());
        assert_eq!(parts.timestamp(), at);
        assert_eq!(parts.cusec(), 7);
        assert_eq!(parts.confounder(), confounder);
        assert_eq!(parts.subkey(), &subkey);
        let (taken, taken_at, cusec, taken_confounder, taken_subkey) = parts.into_parts();
        assert_eq!(taken.nonce(), options.nonce());
        assert_eq!(taken_at, at);
        assert_eq!(cusec, 7);
        assert_eq!(taken_confounder, confounder);
        assert_eq!(taken_subkey, &subkey);
        Ok(())
    }
    /// AS, TGS and AP-REQ options return every configured component.
    #[test]
    fn request_options_return_configured_components() -> Result<(), TestError> {
        let mut as_req = AsReq::new(UNIX_EPOCH, 1);
        let now = timestamp(1_893_553_452)?;
        as_req.set_now(now);
        as_req.set_nonce(0x1234_5678);
        assert_eq!(as_req.now(), now);
        assert_eq!(as_req.nonce(), 0x1234_5678);
        let padata = rasn_kerberos::PaData {
            r#type: PA_PAC_OPTIONS,
            value: vec![0x30, 0x00].into(),
        };
        let keytab = Keytab::new();
        let tgs_req = TgsReq::new(now, 42)
            .with_padata(vec![padata.clone()])
            .with_delegation_keytab(keytab.clone());
        assert_eq!(tgs_req.padata(), [padata]);
        assert_eq!(tgs_req.delegation_keytab(), Some(&keytab));

        let policy = CryptoPolicy::default();
        let checksum = rasn_kerberos::Checksum {
            r#type: 16,
            checksum: vec![0x11; 12].into(),
        };
        let subkey = EncryptionKey::new(18, vec![0x22; 32]);
        let mut options = ApReq::new()
            .with_ap_option_bits(0x2000_0000)
            .with_checksum(Some(checksum.clone()))
            .with_subkey(Some(subkey.clone()))
            .with_sequence_number(Some(7));
        options.set_crypto_policy(Some(policy.clone()));
        assert_eq!(options.crypto_policy(), Some(&policy));
        assert_eq!(options.ap_option_bits(), 0x2000_0000);
        assert_eq!(options.checksum(), Some(&checksum));
        assert_eq!(options.subkey(), Some(&subkey));
        assert_eq!(options.sequence_number(), Some(7));
        Ok(())
    }
}

use super::*;

/// Negotiated AS and TGS reply integrity regression tests.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use rasn::der;
    use rskrb5_ng::{
        client::{AsRepSession, TgsRepSession},
        config::LibDefaults,
        crypto::CryptoPolicy,
        error::{Crypto, Policy, RejectedFeature},
        kdc_rep::decrypt_tgs_rep_enc_part,
    };

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

    /// Every implemented reply-key family with the checksum types of the other families that
    /// the same key bytes can compute.
    fn families() -> Result<Vec<(KerberosEtype, Vec<KerberosEtype>)>, TestError> {
        let etypes = [16_i32, 17_i32, 18_i32, 19_i32, 20_i32, 23_i32]
            .into_iter()
            .map(|id| KerberosEtype::from_etype_id(id).context("implemented etype"))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(etypes
            .iter()
            .map(|&key_etype| {
                let foreign = etypes
                    .iter()
                    .copied()
                    .filter(|other| {
                        other.checksum_type_id() != key_etype.checksum_type_id()
                            && other.key_len() == key_etype.key_len()
                    })
                    .collect();
                (key_etype, foreign)
            })
            .collect())
    }

    /// A policy that permits every implemented family.
    fn every_family_policy() -> Result<CryptoPolicy, TestError> {
        let mut defaults = LibDefaults::new();
        defaults.allow_rc4 = true.into();
        defaults.allow_des3 = true.into();
        defaults.permitted_enctypes = ["DEFAULT", "rc4", "des3"].map(str::to_owned).to_vec();
        Ok(CryptoPolicy::from_libdefaults(&defaults)?)
    }

    /// The reply key bytes of one family, and the bytes of a different key of that family (DES3 ignores the parity bit).
    fn family_key(etype: KerberosEtype, fill: u8) -> EncryptionKey {
        EncryptionKey::new(etype.etype_id(), vec![fill; etype.key_len()])
    }

    /// The checksum a KDC puts in the PA-REQ-ENC-PA-REP of its reply: the type it names and the
    /// profile that computes it (none: a fixed filler, for an unkeyed or weak type).
    #[derive(Clone, Copy)]
    struct Sent {
        /// The checksum type on the wire.
        checksum_type: i32,
        /// The profile that computes the checksum under the reply key.
        profile: Option<KerberosEtype>,
    }

    impl Sent {
        /// The checksum of `profile`, with its own type.
        fn profile(profile: KerberosEtype) -> Self {
            Self {
                checksum_type: profile.checksum_type_id(),
                profile: Some(profile),
            }
        }

        /// A filler under the unkeyed or weak type `checksum_type`.
        const fn weak(checksum_type: i32) -> Self {
            Self {
                checksum_type,
                profile: None,
            }
        }
    }

    /// A PA-REQ-ENC-PA-REP carrying `sent` over `request` under `key`.
    fn checksum_padata(
        request: &[u8],
        sent: Sent,
        key: &EncryptionKey,
    ) -> Result<rasn_kerberos::PaData, TestError> {
        let checksum = match sent.profile {
            Some(profile) => profile.checksum(key.value(), request, AS_REQ_CHECKSUM_USAGE)?,
            None => vec![0x5a; 16],
        };
        let value = PaReqEncPaRep::new(sent.checksum_type, checksum.into());
        Ok(rasn_kerberos::PaData {
            r#type: PA_REQ_ENC_PA_REP,
            value: value.encode_der()?.into(),
        })
    }

    /// The AS-REQ of `family` with the negotiation marker, and its reply with `padata`.
    fn as_attempt(
        family: KerberosEtype,
        sent: Sent,
        signing_fill: u8,
    ) -> Result<Result<AsRepSession, Error>, TestError> {
        let key = family_key(family, 0x42);
        let mut options = AsReq::new(timestamp(1_893_553_447)?, 0x1122_3344)
            .with_etypes(vec![family.etype_id(), 18_i32])
            .with_padata(vec![rasn_kerberos::PaData {
                r#type: PA_REQ_ENC_PA_REP,
                value: Vec::new().into(),
            }]);
        options.set_crypto_policy(Ok(every_family_policy()?));
        let request = build_tgt_as_req(Principal::user("TEST.GOKRB5", "testuser1"), options)?;
        let padata = checksum_padata(request.der(), sent, &family_key(family, signing_fill))?;
        let response = synthetic_as_rep_with_reply_key_and_encrypted_padata(
            &request,
            request.nonce(),
            request.service(),
            &key,
            Some(vec![padata]),
        )?;
        Ok(process_as_rep(&request, &response, &key))
    }

    /// The TGS-REQ with the negotiation marker, and its reply under a `family` key.
    fn tgs_attempt(
        family: KerberosEtype,
        sent: Sent,
        signing_fill: u8,
    ) -> Result<Result<TgsRepSession, Error>, TestError> {
        let key = family_key(family, 0x42);
        let mut options = TgsReq::new(timestamp(1_893_553_450)?, 42)
            .with_etypes(vec![18_i32])
            .with_padata(vec![rasn_kerberos::PaData {
                r#type: PA_REQ_ENC_PA_REP,
                value: Vec::new().into(),
            }]);
        options.set_crypto_policy(Ok(every_family_policy()?));
        let request = build_tgs_req_with_confounder(
            &sample_tgt_session()?,
            sample_service_principal(),
            options,
            timestamp(1_893_553_451)?,
            0,
            &decode_hex(TGS_REQ_CONFOUNDER)?,
        )?;
        let mut response: rasn_kerberos::TgsRep =
            der::decode(&synthetic_tgs_rep(&request, request.nonce(), &key)?)?;
        let mut part = decrypt_tgs_rep_enc_part(&response, &key)?;
        part.encrypted_pa_data = Some(vec![checksum_padata(
            request.der(),
            sent,
            &family_key(family, signing_fill),
        )?]);
        response.0.enc_part.cipher = encrypt_message(
            &key,
            &der::encode(&rasn_kerberos::EncTgsRepPart(part))?,
            TGS_REP_ENCPART_SESSION_KEY_USAGE,
            TGS_REP_CONFOUNDER,
        )?
        .into();
        Ok(process_tgs_rep(&request, &der::encode(&response)?, &key))
    }

    /// What a reply attempt for `family` and each checksum a KDC can send must do, as the list of
    /// departures from it.
    fn departures(
        family: KerberosEtype,
        foreign: &[KerberosEtype],
        attempt: &dyn Fn(KerberosEtype, Sent, u8) -> Result<Result<(), Error>, TestError>,
    ) -> Result<Vec<String>, TestError> {
        let mut found = Vec::new();
        let id = family.etype_id();
        if let Err(error) = attempt(family, Sent::profile(family), 0x42)? {
            found.push(format!("own checksum under etype {id} refused: {error}"));
        }
        if !matches!(
            attempt(family, Sent::profile(family), 0x24)?,
            Err(Error::FastNegotiationChecksumMismatch)
        ) {
            found.push(format!(
                "wrong-key own checksum under etype {id} not a mismatch"
            ));
        }
        for profile in foreign {
            let checksum = profile.checksum_type_id();
            if !matches!(
                attempt(family, Sent::profile(*profile), 0x42)?,
                Err(Error::UnsupportedChecksumType(refused)) if refused == checksum
            ) {
                found.push(format!(
                    "checksum {checksum} under an etype {id} key not refused"
                ));
            }
        }
        for weak in (1_i32..=10_i32).chain([14_i32]) {
            if !matches!(
                attempt(family, Sent::weak(weak), 0x42)?,
                Err(Error::Crypto(Crypto::Policy(Policy::RejectedFeature {
                    feature: RejectedFeature::UnauthenticatedChecksum { id: refused },
                    reason: _,
                }))) if refused == weak
            ) {
                found.push(format!(
                    "weak checksum {weak} under an etype {id} key not refused"
                ));
            }
        }
        Ok(found)
    }

    /// An AS reply accepts only the reply key's own checksum type, for every key family.
    #[test]
    fn as_reply_checksum_type_is_the_reply_keys_own() -> Result<(), TestError> {
        let mut found = Vec::new();
        for (family, foreign) in families()? {
            found.extend(departures(family, &foreign, &|key, sent, fill| {
                Ok(as_attempt(key, sent, fill)?.map(drop))
            })?);
        }
        assert!(found.is_empty(), "{found:#?}");
        Ok(())
    }

    /// A TGS reply accepts only the reply key's own checksum type, for every key family.
    #[test]
    fn tgs_reply_checksum_type_is_the_reply_keys_own() -> Result<(), TestError> {
        let mut found = Vec::new();
        for (family, foreign) in families()? {
            found.extend(departures(family, &foreign, &|key, sent, fill| {
                Ok(tgs_attempt(key, sent, fill)?.map(drop))
            })?);
        }
        assert!(found.is_empty(), "{found:#?}");
        Ok(())
    }
}

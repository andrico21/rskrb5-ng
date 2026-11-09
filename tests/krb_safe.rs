//! KRB-SAFE tests: gokrb5 fixture decoding, checksum building and verification.
#![cfg(feature = "messages")]

/// KRB-SAFE tests.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error;

    use pretty_assertions::assert_eq;
    use rasn::{der, types::Integer};
    use rskrb5_ng::{
        crypto::AesSha1Etype,
        error::{Crypto, KrbSafe as Error, Policy, RejectedFeature},
        keytab::EncryptionKey,
        krb_safe::{
            KRB_SAFE_CHECKSUM_USAGE, KRB_SAFE_MSG_TYPE, build as build_krb_safe,
            checksum as krb_safe_checksum, decode as decode_krb_safe, encode as encode_krb_safe,
            verify_krb_safe_checksum,
        },
    };

    /// Error type of the `Result`-returning tests.
    type TestError = Box<dyn error::Error>;

    /// AES256 reply key of the gokrb5 fixtures.
    const REPLY_KEY: &str = "9cad00bbc72d703258e911dc18e6d5487cf737bf67fd111f0c2463ad6033bf51";
    /// Timestamp of the gokrb5 fixtures, in seconds since the Unix epoch.
    const TEST_TIME_SECONDS: i64 = 771_228_197;
    /// gokrb5 KRB-SAFE fixture with every optional field set.
    const KRB_SAFE: &str = concat!(
        "746E306CA003020105A103020114A24F304DA00A04086B72623564617461A111",
        "180F31393934303631303036303331375AA205020301E240A303020111A40F",
        "300DA003020102A106040412D00023A50F300DA003020102A106040412D",
        "00023A30F300DA003020101A106040431323334",
    );
    /// gokrb5 KRB-SAFE fixture without optional fields.
    const KRB_SAFE_OPTIONALS_NULL: &str = concat!(
        "743E303CA003020105A103020114A21F301DA00A04086B72623564617461",
        "A40F300DA003020102A106040412D00023A30F300DA003020101A106",
        "040431323334",
    );

    /// Pins that the gokrb5 KRB-SAFE fixture decodes to the expected fields.
    #[test]
    fn decodes_gokrb5_krb_safe_fixture() -> Result<(), TestError> {
        let krb_safe = decode_krb_safe(&hex::decode(KRB_SAFE)?)?;

        assert_eq!(krb_safe.pvno, Integer::from(5_i32));
        assert_eq!(krb_safe.msg_type, Integer::from(KRB_SAFE_MSG_TYPE));
        assert_eq!(krb_safe.body.user_data.as_ref(), b"krb5data");
        assert_eq!(
            krb_safe
                .body
                .timestamp
                .as_ref()
                .ok_or("timestamp")?
                .0
                .timestamp(),
            TEST_TIME_SECONDS
        );
        assert_eq!(krb_safe.body.usec, Some(Integer::from(123_456_i32)));
        assert_eq!(krb_safe.body.seq_number, Some(17));
        assert_eq!(krb_safe.body.s_address.addr_type, 2_i32);
        assert_eq!(
            krb_safe.body.s_address.address.as_ref(),
            hex::decode("12d00023")?
        );
        assert_eq!(
            krb_safe
                .body
                .r_address
                .as_ref()
                .ok_or("recipient address")?
                .address
                .as_ref(),
            hex::decode("12d00023")?
        );
        assert_eq!(krb_safe.cksum.r#type, 1_i32);
        assert_eq!(krb_safe.cksum.checksum.as_ref(), b"1234");
        Ok(())
    }

    /// Pins that the gokrb5 KRB-SAFE fixture without optional fields decodes.
    #[test]
    fn decodes_gokrb5_krb_safe_optionals_null_fixture() -> Result<(), TestError> {
        let krb_safe = decode_krb_safe(&hex::decode(KRB_SAFE_OPTIONALS_NULL)?)?;

        assert_eq!(krb_safe.pvno, Integer::from(5_i32));
        assert_eq!(krb_safe.msg_type, Integer::from(KRB_SAFE_MSG_TYPE));
        assert_eq!(krb_safe.body.user_data.as_ref(), b"krb5data");
        assert!(krb_safe.body.timestamp.is_none(), "timestamp is absent");
        assert!(krb_safe.body.usec.is_none(), "usec is absent");
        assert!(
            krb_safe.body.seq_number.is_none(),
            "sequence number is absent"
        );
        assert_eq!(krb_safe.body.s_address.addr_type, 2_i32);
        assert_eq!(
            krb_safe.body.s_address.address.as_ref(),
            hex::decode("12d00023")?
        );
        assert!(
            krb_safe.body.r_address.is_none(),
            "recipient address is absent"
        );
        assert_eq!(krb_safe.cksum.r#type, 1_i32);
        assert_eq!(krb_safe.cksum.checksum.as_ref(), b"1234");
        Ok(())
    }

    /// Pins that a built KRB-SAFE carries the computed checksum and verifies.
    #[test]
    fn builds_and_verifies_krb_safe_checksum() -> Result<(), TestError> {
        let fixture = decode_krb_safe(&hex::decode(KRB_SAFE)?)?;
        let key = reply_key()?;

        let checksum = krb_safe_checksum(&fixture.body, &key)?;
        let krb_safe = build_krb_safe(fixture.body, &key)?;

        assert_eq!(checksum.r#type, 16_i32);
        assert_eq!(krb_safe.cksum, checksum);
        verify_krb_safe_checksum(&krb_safe, &key)?;
        Ok(())
    }

    /// Checks generation against independently encoded RFC 4120 section 5.6.1 input.
    #[test]
    fn checksum_matches_whole_message_oracle() -> Result<(), TestError> {
        // Given a peer message with the normative zero-type, empty checksum.
        let mut peer = decode_krb_safe(&hex::decode(KRB_SAFE)?)?;
        peer.cksum = rasn_kerberos::Checksum {
            r#type: 0,
            checksum: Vec::new().into(),
        };
        let key = reply_key()?;
        let input = der::encode(&peer)?;
        let expected = AesSha1Etype::Aes256.checksum(key.value(), &input, 15)?;

        // When the public generator computes a checksum for that body.
        let actual = krb_safe_checksum(&peer.body, &key)?;

        // Then it matches the independently constructed whole-message MAC.
        assert_eq!(actual.checksum.as_ref(), expected);
        Ok(())
    }

    /// Checks that a normative peer MAC is accepted without using the local builder.
    #[test]
    fn verifies_independent_whole_message_checksum() -> Result<(), TestError> {
        // Given an independently signed whole KRB-SAFE message.
        let mut peer = decode_krb_safe(&hex::decode(KRB_SAFE)?)?;
        peer.cksum = rasn_kerberos::Checksum {
            r#type: 0,
            checksum: Vec::new().into(),
        };
        let key = reply_key()?;
        let input = der::encode(&peer)?;
        peer.cksum = rasn_kerberos::Checksum {
            r#type: 16,
            checksum: AesSha1Etype::Aes256
                .checksum(key.value(), &input, 15)?
                .into(),
        };

        // When the peer checksum is verified, then it is accepted.
        verify_krb_safe_checksum(&peer, &key)?;
        Ok(())
    }

    /// Pins that a built KRB-SAFE encodes, decodes back unchanged and still verifies.
    #[test]
    fn encodes_krb_safe_roundtrip() -> Result<(), TestError> {
        let fixture = decode_krb_safe(&hex::decode(KRB_SAFE)?)?;
        let key = reply_key()?;
        let krb_safe = build_krb_safe(fixture.body, &key)?;

        let bytes = encode_krb_safe(&krb_safe)?;
        let decoded = decode_krb_safe(&bytes)?;

        assert_eq!(decoded, krb_safe);
        verify_krb_safe_checksum(&decoded, &key)?;
        Ok(())
    }

    /// Pins that the fixture's unkeyed checksum type is rejected.
    #[test]
    fn rejects_unsupported_krb_safe_checksum_type() -> Result<(), TestError> {
        let krb_safe = decode_krb_safe(&hex::decode(KRB_SAFE)?)?;
        let key = reply_key()?;

        let error = verify_krb_safe_checksum(&krb_safe, &key)
            .err()
            .ok_or("unsupported fixture checksum type is rejected")?;

        assert!(
            matches!(
                error,
                Error::Crypto(Crypto::Policy(Policy::RejectedFeature {
                    feature: RejectedFeature::UnauthenticatedChecksum { id: 1_i32 },
                    reason: _,
                }))
            ),
            "{error:?}"
        );
        Ok(())
    }

    /// Pins that a tampered KRB-SAFE body fails checksum verification.
    #[test]
    fn rejects_krb_safe_checksum_mismatch() -> Result<(), TestError> {
        let fixture = decode_krb_safe(&hex::decode(KRB_SAFE)?)?;
        let key = reply_key()?;
        let mut krb_safe = build_krb_safe(fixture.body, &key)?;
        krb_safe.body.user_data = b"tampered".to_vec().into();

        let error = verify_krb_safe_checksum(&krb_safe, &key)
            .err()
            .ok_or("tampered KRB-SAFE body is rejected")?;

        assert!(matches!(error, Error::ChecksumMismatch), "{error:?}");
        Ok(())
    }

    /// Pins that a key whose etype does not match the checksum type is rejected.
    #[test]
    fn rejects_krb_safe_key_checksum_type_mismatch() -> Result<(), TestError> {
        let fixture = decode_krb_safe(&hex::decode(KRB_SAFE)?)?;
        let key = reply_key()?;
        let krb_safe = build_krb_safe(fixture.body, &key)?;
        let wrong_etype_key = EncryptionKey::new(17, vec![0; 16]);

        let error = verify_krb_safe_checksum(&krb_safe, &wrong_etype_key)
            .err()
            .ok_or("wrong key etype is rejected")?;

        assert!(
            matches!(
                error,
                Error::KeyChecksumTypeMismatch {
                    key_etype: 17_i32,
                    checksum_type: 16_i32,
                }
            ),
            "{error:?}"
        );
        Ok(())
    }

    /// Pins the KRB-SAFE checksum key usage number.
    #[test]
    fn exposes_krb_safe_checksum_usage_constant() {
        assert_eq!(KRB_SAFE_CHECKSUM_USAGE, 15);
    }

    /// Returns the AES256 reply key of the gokrb5 fixtures.
    fn reply_key() -> Result<EncryptionKey, TestError> {
        Ok(EncryptionKey::new(18, hex::decode(REPLY_KEY)?))
    }
}

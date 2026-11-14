//! Behavioral coverage for surviving crypto mutations.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error::Error;

    use rskrb5_ng::{
        config::LibDefaults,
        crypto::{
            AesSha2Etype, CryptoPolicy, Des3CbcSha1KdEtype, Rc4HmacEtype, Use, checked,
            kerb_checksum_hmac_md5, nfold, s2k::Family, selection,
        },
        error::Crypto,
    };

    /// Fallible test result.
    type TestError = Box<dyn Error>;

    /// MIT direct random-to-key preserves the seed and RFC 6229's independent keystream.
    #[test]
    fn rc4_random_to_key_preserves_seed() -> Result<(), TestError> {
        let seed = hex::decode("0102030405060708090a0b0c0d0e0f10")?;
        let key = Rc4HmacEtype::random_to_key(&seed)?;
        assert_eq!(hex::encode(&key), "0102030405060708090a0b0c0d0e0f10");
        assert_eq!(
            Rc4HmacEtype::decrypt_data(&key, &hex::decode("9ac7cc9a609d1ef7b2932899cde41b97")?)?,
            [0; 16]
        );
        assert_eq!(
            Rc4HmacEtype::random_to_key(&hex::decode("000102030405060708090a0b0c0d0e0f")?)?,
            hex::decode("000102030405060708090a0b0c0d0e0f")?
        );
        for length in [0_usize, 3, 15, 17] {
            assert!(
                matches!(Rc4HmacEtype::random_to_key(&vec![0; length]), Err(Crypto::InvalidKeyLength { expected: 16, actual }) if actual == length)
            );
        }
        Ok(())
    }

    /// RFC 2202 case 1 HMAC-MD5 with the required 16-byte protocol key.
    #[test]
    fn rc4_derive_key_matches_hmac_vector() -> Result<(), TestError> {
        assert_eq!(
            hex::encode(Rc4HmacEtype::derive_key(&[0x0b; 16], b"Hi There")?),
            "9294727a3638bb1c13f48ef8158bfc9d"
        );
        Ok(())
    }

    /// RFC6229 section 2 gives the first 128-bit-key keystream block.
    #[test]
    fn rc4_raw_decryption_recovers_message() -> Result<(), TestError> {
        let key = hex::decode("0102030405060708090a0b0c0d0e0f10")?;
        let ciphertext = hex::decode("9ac7cc9a609d1ef7b2932899cde41b97")?;
        assert_eq!(Rc4HmacEtype::decrypt_data(&key, &ciphertext)?, [0; 16]);
        Ok(())
    }

    /// RFC 3961 section 6.3.1 weak-key adjustment flips the last octet.
    #[test]
    fn des3_random_to_key_fixes_weak_keys() -> Result<(), TestError> {
        for (seed, block) in [(0_u8, "01010101010101f1"), (0xff, "fefefefefefefe0e")] {
            assert_eq!(
                hex::encode(Des3CbcSha1KdEtype::random_to_key(&[seed; 21])?),
                block.repeat(3)
            );
        }
        Ok(())
    }

    /// DES3 validates before n-fold, which otherwise can derive from a wrong key size.
    #[test]
    fn des3_derivation_rejects_short_protocol_key() {
        assert_eq!(
            Des3CbcSha1KdEtype::derive_random(&[0x42; 23], b""),
            Err(Crypto::InvalidKeyLength {
                expected: 24,
                actual: 23
            })
        );
    }

    /// SHA2 KDF requires the selected protocol size even though HMAC accepts any size.
    #[test]
    fn sha2_derivation_rejects_short_protocol_key() {
        assert_eq!(
            AesSha2Etype::Aes256.derive_key(&[0x42; 16], b"kerberos"),
            Err(Crypto::InvalidKeyLength {
                expected: 32,
                actual: 16
            })
        );
    }

    /// AES256 raw encryption cannot silently dispatch a valid AES128 key.
    #[test]
    fn sha2_encryption_rejects_wrong_family_key() {
        assert_eq!(
            AesSha2Etype::Aes256.encrypt_data(&[0x42; 16], &[0x24; 16]),
            Err(Crypto::InvalidKeyLength {
                expected: 32,
                actual: 16
            })
        );
    }

    /// The RFC3961 fold domain excludes fractions of a byte.
    #[test]
    fn nfold_rejects_non_byte_output() {
        assert_eq!(
            nfold(b"kerberos", 7),
            Err(Crypto::InvalidNfoldOutputBits(7))
        );
    }

    /// Checked dispatch retains the RFC3962 Appendix B known answer.
    #[test]
    fn checked_s2k_matches_rfc3962() -> Result<(), TestError> {
        let defaults = LibDefaults::new().with_min_s2k_iterations(Family::AesSha1, 1)?;
        let etype = checked::Etype::new(&CryptoPolicy::from_libdefaults(&defaults)?, 17)?;
        assert_eq!(
            hex::encode(etype.string_to_key(b"password", b"ATHENA.MIT.EDUraeburn", "00000001")?),
            "42263c6e89f4fc28b8df68ee09799f15"
        );
        Ok(())
    }

    /// RFC3961 Appendix A derives a 21-byte random string from the DES3 base key.
    #[test]
    fn des3_derivation_matches_rfc3961() -> Result<(), TestError> {
        let key = hex::decode("dce06b1f64c857a11c3db57c51899b2cc1791008ce973b92")?;
        assert_eq!(
            hex::encode(Des3CbcSha1KdEtype::derive_random(
                &key,
                &[0, 0, 0, 1, 0x55]
            )?),
            "935079d14490a75c3093c4a6e8c3b049c71e6ee705"
        );
        Ok(())
    }

    /// Checked integrity verification rejects a changed message.
    #[test]
    fn checked_checksum_rejects_tampering() -> Result<(), TestError> {
        let etype = checked::Etype::new(&CryptoPolicy::default(), 17)?;
        let key = [0x42; 16];
        let tag = etype.checksum(&key, b"original", 2)?;
        assert_eq!(
            etype.verify_checksum(&key, b"changed", &tag, 2),
            Err(Crypto::IntegrityCheckFailed)
        );
        Ok(())
    }

    /// Explicit checksum names preserve the IANA numeric identity, including negatives.
    #[test]
    fn checksum_names_resolve_protocol_ids() -> Result<(), TestError> {
        for (name, id) in [
            ("rsa-md4-des", 3_i32),
            ("des-mac", 4_i32),
            ("des-mac-k", 5_i32),
            ("rsa-md4-des-k", 6_i32),
            ("hmac-sha1-des3-kd", 12_i32),
            ("hmac-md5-earcfour", -138_i32),
            ("hmac-sha1-96-aes128", 15_i32),
            ("hmac-sha1-96-aes256", 16_i32),
            ("hmac-sha256-128-aes128", 19_i32),
            ("hmac-sha384-192-aes256", 20_i32),
            ("cmac-camellia128", 17_i32),
            ("cmac-camellia256", 18_i32),
            ("md5-hmac-rc4", -137_i32),
        ] {
            let actual = selection::checksum_name(name).ok_or("checksum name not recognized")?;
            assert_eq!(actual, id, "{name}");
        }
        Ok(())
    }

    /// Checksum profile 20 selects AES256-SHA384 rather than an unavailable profile.
    #[test]
    fn checksum_selection_supports_sha384() -> Result<(), TestError> {
        let selected = selection::checksum(20)?.ok_or("SHA384 checksum unavailable")?;
        assert_eq!(selected.etype_id(), 20_i32);
        Ok(())
    }

    /// `TryFrom` must retain the configured exclusion instead of returning default permission.
    #[test]
    fn policy_conversion_retains_configured_permission() -> Result<(), TestError> {
        let mut defaults = LibDefaults::new();
        defaults.permitted_enctypes = vec!["aes128-cts-hmac-sha1-96".to_owned()];
        let policy = CryptoPolicy::try_from(&defaults)?;
        assert!(
            policy.check_use(20, Use::ReplyKey).is_err(),
            "excluded SHA384 accepted"
        );
        Ok(())
    }

    /// Policy usage is included in diagnostics, not silently formatted away.
    #[test]
    fn policy_usage_display_identifies_boundary() {
        assert_eq!(Use::ReplyKey.to_string(), "reply key");
    }

    /// DES3 raw CBC produces a full encrypted block and its next IV.
    #[test]
    fn des3_raw_encryption_produces_ciphertext() -> Result<(), TestError> {
        let (iv, ciphertext) = Des3CbcSha1KdEtype::encrypt_data(&[0x42; 24], b"12345678")?;
        assert_eq!(ciphertext.len(), 8);
        assert_eq!(iv, ciphertext);
        assert_ne!(ciphertext, b"12345678");
        Ok(())
    }

    /// RFC4757 maps AS-REP and TGS-REP usage numbers to message type eight.
    #[test]
    fn rc4_checksum_maps_reply_usages() -> Result<(), TestError> {
        let key = [0x42; 16];
        let expected = Rc4HmacEtype::checksum(&key, b"reply", 8)?;
        for usage in [3, 9] {
            assert_eq!(Rc4HmacEtype::checksum(&key, b"reply", usage)?, expected);
        }
        Ok(())
    }

    /// A valid arbitrary-key HMAC is not a valid RC4 protocol checksum with a short key.
    #[test]
    fn rc4_verification_rejects_correct_tag_with_short_key() -> Result<(), TestError> {
        let key = [0x42; 15];
        let tag = kerb_checksum_hmac_md5(&key, b"message", 2);
        let expected_tag: [u8; 16] = tag.as_slice().try_into()?;
        assert!(
            !Rc4HmacEtype::verify_checksum(&key, b"message", &expected_tag, 2),
            "short protocol key authorized"
        );
        Ok(())
    }
}

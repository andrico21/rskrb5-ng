//! Camellia-CTS-CMAC (RFC 6803) behind the additive `camellia` leaf feature.
//!
//! Vectors: every RFC 6803 section 10 vector (string-to-key, key derivation, sample
//! encryptions and checksums) and fixtures from MIT's libk5crypto 1.22.1 and MIT's
//! own `src/tests/gssapi/t_prf.c` (`tests/crypto_camellia/vectors.rs` names each source).
//! The feature never grants runtime permission: the policy tests below pin that.
#![cfg(feature = "camellia")]

/// The Camellia tests.
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
    use rskrb5_ng::{
        config::{Config, EnctypeExpr, ParseMode, Toggle},
        crypto::{
            CryptoPolicy, KerberosEtype, Use,
            camellia::{self, CamelliaCtsCmacEtype},
            checked,
            prf::{self, CfInput, Key},
            s2k::Family,
            selection,
        },
        error::{Crypto as Error, Policy},
    };

    include!("crypto_camellia/vectors.rs");

    /// Error type of the `Result`-returning tests.
    type TestError = Box<dyn error::Error>;

    /// Both enctypes with their key sizes in bits.
    const ETYPES: [(CamelliaCtsCmacEtype, u32); 2] = [
        (CamelliaCtsCmacEtype::Camellia128, 128),
        (CamelliaCtsCmacEtype::Camellia256, 256),
    ];

    /// The RFC 3961 usage constant: the usage in four big-endian octets and `suffix`.
    fn usage_constant(usage: u32, suffix: u8) -> Vec<u8> {
        [&usage.to_be_bytes()[..], &[suffix]].concat()
    }

    /// The enctype of a key size in bits.
    fn etype_of(bits: u32) -> Result<CamelliaCtsCmacEtype, TestError> {
        ETYPES
            .iter()
            .find_map(|(etype, size)| (*size == bits).then_some(*etype))
            .ok_or_else(|| format!("no Camellia enctype of {bits} bits").into())
    }

    /// The dispatching enctype of an ID.
    fn dispatch(id: i32) -> Result<KerberosEtype, TestError> {
        KerberosEtype::from_etype_id(id).ok_or_else(|| format!("etype {id} unavailable").into())
    }

    /// The `s2kparams` of an iteration count.
    fn params(iterations: u32) -> String {
        format!("{iterations:08x}")
    }

    /// The wire metadata of both enctypes and their dispatch through `KerberosEtype`.
    #[test]
    fn reports_metadata_and_dispatch() -> Result<(), TestError> {
        /// Etype ID, checksum type ID, name, key size and enctype.
        const CASES: [(i32, i32, &str, usize, CamelliaCtsCmacEtype); 2] = [
            (
                25,
                17,
                "camellia128-cts-cmac",
                16,
                CamelliaCtsCmacEtype::Camellia128,
            ),
            (
                26,
                18,
                "camellia256-cts-cmac",
                32,
                CamelliaCtsCmacEtype::Camellia256,
            ),
        ];
        if !camellia::AVAILABLE {
            return Err("the camellia leaf is not compiled in".into());
        }
        for (id, checksum, name, key_len, etype) in CASES {
            assert_eq!(CamelliaCtsCmacEtype::from_etype_id(id), Some(etype));
            assert_eq!(
                CamelliaCtsCmacEtype::from_checksum_type_id(checksum),
                Some(etype)
            );
            assert_eq!(etype.etype_id(), id);
            assert_eq!(etype.checksum_type_id(), checksum);
            assert_eq!(etype.ename(), name);
            assert_eq!(etype.key_len(), key_len);
            let general = KerberosEtype::Camellia(etype);
            assert_eq!(KerberosEtype::from_etype_id(id), Some(general));
            assert_eq!(
                KerberosEtype::from_checksum_type_id(checksum),
                Some(general)
            );
            assert_eq!(selection::enctype(id)?, Some(general));
            assert_eq!(selection::checksum(checksum)?, Some(general));
            assert_eq!(KerberosEtype::try_from(id)?, general);
            assert_eq!(general.etype_id(), id);
            assert_eq!(general.checksum_type_id(), checksum);
            assert_eq!(general.key_len(), key_len);
            assert_eq!(general.confounder_len(), 16);
            assert_eq!(general.hmac_len(), 16);
            assert_eq!(general.default_s2kparams(), "00008000");
        }
        assert_eq!(CamelliaCtsCmacEtype::from_etype_id(24), None);
        assert_eq!(CamelliaCtsCmacEtype::from_checksum_type_id(19), None);
        Ok(())
    }

    /// RFC 6803 section 10 string-to-key vectors for both key sizes.
    #[test]
    fn rfc6803_string_to_key() -> Result<(), TestError> {
        for S2kVector {
            iterations,
            password,
            salt,
            key128,
            key256,
        } in S2K
        {
            let (secret, salt_bytes) = (hex::decode(password)?, hex::decode(salt)?);
            for (bits, expected) in [(128_u32, key128), (256, key256)] {
                let key =
                    etype_of(bits)?.string_to_key(&secret, &salt_bytes, &params(*iterations))?;
                assert_eq!(
                    hex::encode(key),
                    *expected,
                    "{bits}-bit key, {iterations} iterations"
                );
            }
        }
        Ok(())
    }

    /// RFC 6803 section 10 key derivation: `Kc`, `Ke` and `Ki` of usage 2.
    #[test]
    fn rfc6803_key_derivation() -> Result<(), TestError> {
        for KdfVector {
            bits,
            key,
            kc,
            ke,
            ki,
        } in KDF
        {
            let (etype, base) = (etype_of(*bits)?, hex::decode(key)?);
            for (suffix, expected) in [(0x99_u8, kc), (0xaa, ke), (0x55, ki)] {
                let derived = etype.derive_key(&base, &usage_constant(2, suffix))?;
                assert_eq!(
                    hex::encode(derived),
                    *expected,
                    "{bits}-bit, suffix {suffix:#x}"
                );
            }
        }
        Ok(())
    }

    /// RFC 6803 section 10 sample encryptions, both directions, with the explicit confounder.
    #[test]
    fn rfc6803_encryptions() -> Result<(), TestError> {
        for EncVector {
            bits,
            key,
            usage,
            plain,
            confounder,
            cipher,
        } in ENC
        {
            let (etype, base) = (etype_of(*bits)?, hex::decode(key)?);
            let sealed = etype.encrypt_message_with_confounder(
                &base,
                plain.as_bytes(),
                *usage,
                &hex::decode(confounder)?,
            )?;
            assert_eq!(
                hex::encode(&sealed),
                *cipher,
                "{bits}-bit, plaintext {plain:?}"
            );
            assert_eq!(
                etype.decrypt_message(&base, &sealed, *usage)?,
                plain.as_bytes()
            );
            let general = dispatch(etype.etype_id())?;
            assert_eq!(
                general.decrypt_message(&base, &sealed, *usage)?,
                plain.as_bytes()
            );
        }
        Ok(())
    }

    /// RFC 6803 section 10 sample checksums, through the checksum-type dispatch.
    #[test]
    fn rfc6803_checksums() -> Result<(), TestError> {
        for CksumVector {
            bits,
            key,
            usage,
            plain,
            tag,
        } in CKSUM
        {
            let (etype, base) = (etype_of(*bits)?, hex::decode(key)?);
            let expected = hex::decode(tag)?;
            assert_eq!(etype.checksum(&base, plain.as_bytes(), *usage)?, expected);
            assert!(etype.verify_checksum(&base, plain.as_bytes(), &expected, *usage));
            let by_type = selection::checksum(etype.checksum_type_id())?.ok_or("checksum type")?;
            assert!(by_type.verify_checksum(&base, plain.as_bytes(), &expected, *usage));
        }
        Ok(())
    }

    /// Default-parameter string-to-key against libk5crypto.
    #[test]
    fn string_to_key_matches_libk5crypto() -> Result<(), TestError> {
        for HostS2kVector {
            etype,
            password,
            salt,
            key,
        } in HOST_S2K
        {
            let kind = dispatch(*etype)?;
            let derived = kind.string_to_key(
                &hex::decode(password)?,
                &hex::decode(salt)?,
                kind.default_s2kparams(),
            )?;
            assert_eq!(hex::encode(derived), *key, "etype {etype}");
        }
        Ok(())
    }

    /// Checksums of types 17 and 18 against `krb5_c_make_checksum`.
    #[test]
    fn checksums_match_libk5crypto() -> Result<(), TestError> {
        for HostCksumVector {
            etype,
            key,
            usage,
            msg,
            tag,
        } in HOST_CKSUM
        {
            let (kind, base, data) = (dispatch(*etype)?, hex::decode(key)?, hex::decode(msg)?);
            assert_eq!(
                hex::encode(kind.checksum(&base, &data, *usage)?),
                *tag,
                "etype {etype}"
            );
        }
        Ok(())
    }

    /// Messages sealed by `krb5_c_encrypt` open here, and re-sealing with their confounder is identical.
    #[test]
    fn libk5crypto_ciphertexts_open_and_reseal() -> Result<(), TestError> {
        for HostEncVector {
            etype,
            key,
            usage,
            plain,
            cipher,
        } in HOST_ENC
        {
            let (kind, base) = (etype_of_id(*etype)?, hex::decode(key)?);
            let sealed = hex::decode(cipher)?;
            assert_eq!(
                hex::encode(kind.decrypt_message(&base, &sealed, *usage)?),
                *plain,
                "etype {etype}"
            );
            // The confounder is the first block of the decrypted encryption-key output.
            let ke = kind.derive_key(&base, &usage_constant(*usage, 0xaa))?;
            let opened = kind.decrypt_data(&ke, sealed.get(..sealed.len() - 16).ok_or("short")?)?;
            let resealed = kind.encrypt_message_with_confounder(
                &base,
                &hex::decode(plain)?,
                *usage,
                opened.get(..16).ok_or("confounder")?,
            )?;
            assert_eq!(resealed, sealed, "etype {etype} re-sealed");
        }
        Ok(())
    }

    /// The Camellia enctype of an ID.
    fn etype_of_id(id: i32) -> Result<CamelliaCtsCmacEtype, TestError> {
        CamelliaCtsCmacEtype::from_etype_id(id).ok_or_else(|| format!("etype {id}").into())
    }

    /// CTS round trips for every length from one byte to five blocks, with a block-aligned tail.
    #[test]
    fn cts_round_trips_every_length() -> Result<(), TestError> {
        for (etype, _) in ETYPES {
            let key = vec![0x5a; etype.key_len()];
            for len in 1..=80_usize {
                let plain: Vec<u8> = (0..=u8::MAX).cycle().take(len).collect();
                let (_, sealed) = etype.encrypt_data(&key, &plain)?;
                assert_eq!(sealed.len(), plain.len().max(16), "length {len}");
                let opened = etype.decrypt_data(&key, &sealed)?;
                assert_eq!(opened.get(..len), Some(plain.as_slice()), "length {len}");
            }
        }
        Ok(())
    }

    /// Every rejection path of the message and checksum functions is typed.
    #[test]
    fn malformed_input_is_rejected() -> Result<(), TestError> {
        for (etype, _) in ETYPES {
            let key = vec![9; etype.key_len()];
            let sealed = etype.encrypt_message_with_confounder(&key, b"payload", 3, &[1; 16])?;
            // A flipped bit in the ciphertext or in the MAC fails integrity, not parsing.
            for position in [0_usize, 5, sealed.len().saturating_sub(1)] {
                let mut forged = sealed.clone();
                if let Some(byte) = forged.get_mut(position) {
                    *byte ^= 1;
                }
                assert_eq!(
                    etype.decrypt_message(&key, &forged, 3).err(),
                    Some(Error::IntegrityCheckFailed)
                );
            }
            // The wrong usage derives other keys.
            assert_eq!(
                etype.decrypt_message(&key, &sealed, 4).err(),
                Some(Error::IntegrityCheckFailed)
            );
            // Fewer bytes than a confounder and a MAC.
            for len in [0_usize, 16, 31] {
                assert_eq!(
                    etype
                        .decrypt_message(&key, sealed.get(..len).ok_or("prefix")?, 3)
                        .err(),
                    Some(Error::CiphertextTooShort {
                        minimum: 32,
                        actual: len
                    })
                );
            }
            assert_eq!(
                etype.decrypt_data(&key, &[0; 15]).err(),
                Some(Error::CiphertextTooShort {
                    minimum: 16,
                    actual: 15
                })
            );
            assert_eq!(
                etype.encrypt_data(&key, b"").err(),
                Some(Error::EmptyPlaintext)
            );
            assert_eq!(
                etype
                    .encrypt_message_with_confounder(&key, b"x", 3, &[1; 15])
                    .err(),
                Some(Error::InvalidConfounderLength {
                    expected: 16,
                    actual: 15
                })
            );
            let short = Error::InvalidKeyLength {
                expected: etype.key_len(),
                actual: 15,
            };
            assert_eq!(
                etype.decrypt_message(&[0; 15], &sealed, 3).err(),
                Some(short)
            );
            assert_eq!(etype.checksum(&[0; 15], b"x", 3).err(), Some(short));
            assert_eq!(etype.derive_key(&[0; 15], b"kerberos").err(), Some(short));
            assert_eq!(etype.derive_key(&key, b"").err(), Some(Error::EmptyUsage));
            // A checksum is exactly 16 bytes, compared completely.
            let tag = etype.checksum(&key, b"data", 3)?;
            assert!(etype.verify_checksum(&key, b"data", &tag, 3));
            assert!(!etype.verify_checksum(&key, b"data", tag.get(..15).ok_or("prefix")?, 3));
            assert!(!etype.verify_checksum(&key, b"data", &[tag.as_slice(), &[0]].concat(), 3));
            assert!(!etype.verify_checksum(&key, b"datb", &tag, 3));
            assert!(!etype.verify_checksum(&key, b"data", &tag, 4));
            assert!(!etype.verify_checksum(&[0; 15], b"data", &tag, 3));
        }
        Ok(())
    }

    /// Peer-supplied string-to-key work is bounded before any PBKDF2 runs.
    #[test]
    fn string_to_key_parameters_are_bounded() {
        let etype = CamelliaCtsCmacEtype::Camellia256;
        assert_eq!(
            etype.string_to_key(b"p", b"s", "00000000").err(),
            Some(Error::UnsupportedIterationCountZero)
        );
        assert_eq!(
            etype.string_to_key(b"p", b"s", "01000001").err(),
            Some(Error::IterationCountTooHigh {
                maximum: 0x0100_0000_u32,
                actual: 0x0100_0001_u32
            })
        );
        assert_eq!(
            etype.string_to_key(b"p", b"s", "0001").err(),
            Some(Error::InvalidS2kParamsLength(4))
        );
    }

    /// The RFC 6803 PRF as MIT's `gss_pseudo_random` vectors check it, both key roles.
    #[test]
    fn gss_prf_plus_matches_mit_gss_vectors() -> Result<(), TestError> {
        /// The 61-byte input of `src/tests/gssapi/t_prf.c`.
        const INPUT: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz123456789";
        for GssVector {
            etype,
            key1,
            out1,
            key2,
            out2,
        } in GSS
        {
            let kind = dispatch(*etype)?;
            let (first, second) = (hex::decode(key1)?, hex::decode(key2)?);
            let empty = prf::gss_prf_plus(&Key::new(kind, &first), b"", 44)?;
            assert_eq!(hex::encode(&*empty), *out1, "etype {etype}, empty input");
            let full = prf::gss_prf_plus(&Key::new(kind, &second), INPUT, 44)?;
            assert_eq!(hex::encode(&*full), *out2, "etype {etype}, 61-byte input");
        }
        Ok(())
    }

    /// `krb5_c_prfplus` (RFC 6113 counters) against libk5crypto.
    #[test]
    fn fast_prf_plus_matches_libk5crypto() -> Result<(), TestError> {
        for PlusVector {
            etype,
            key,
            input,
            len,
            expected,
        } in PLUS
        {
            let base = hex::decode(key)?;
            let out = prf::fast_prf_plus(
                &Key::new(dispatch(*etype)?, &base),
                &hex::decode(input)?,
                *len,
            )?;
            assert_eq!(hex::encode(&*out), *expected, "etype {etype}, {len} bytes");
        }
        Ok(())
    }

    /// `krb5_c_fx_cf2_simple` against libk5crypto.
    #[test]
    fn krb_fx_cf2_matches_libk5crypto() -> Result<(), TestError> {
        for CfVector {
            etype,
            key1,
            key2,
            pepper1,
            pepper2,
            expected,
        } in CF2_HOST
        {
            let (kind, first, second) = (dispatch(*etype)?, hex::decode(key1)?, hex::decode(key2)?);
            let out = prf::krb_fx_cf2(
                &CfInput::new(Key::new(kind, &first), pepper1.as_bytes()),
                &CfInput::new(Key::new(kind, &second), pepper2.as_bytes()),
            )?;
            assert_eq!(hex::encode(&*out), *expected, "etype {etype}");
        }
        Ok(())
    }

    /// The leaf alone grants nothing: the default policy refuses both enctypes everywhere.
    #[test]
    fn the_leaf_does_not_grant_permission() -> Result<(), TestError> {
        let policy = CryptoPolicy::default();
        for id in [25_i32, 26_i32] {
            for usage in [
                Use::RequestList,
                Use::ReplyKey,
                Use::SessionKey,
                Use::TicketKey,
                Use::AcceptorTicket,
                Use::ImportedCredential,
            ] {
                assert_eq!(
                    policy.check_use(id, usage),
                    Err(Policy::EnctypeNotPermitted { etype: id, usage })
                );
            }
            assert_eq!(
                checked::Etype::new(&policy, id).err(),
                Some(Policy::EnctypeNotPermitted {
                    etype: id,
                    usage: Use::CheckedLowLevel
                })
            );
        }
        let aes_only = Config::parse("[libdefaults]\npermitted_enctypes = aes256-cts")?;
        let narrow = CryptoPolicy::from_libdefaults(&aes_only.libdefaults)?;
        assert!(narrow.check_use(26, Use::AcceptorTicket).is_err());
        Ok(())
    }

    /// Naming Camellia in `permitted_enctypes` is the only way to permit it.
    #[test]
    fn naming_camellia_permits_exactly_that() -> Result<(), TestError> {
        let config =
            Config::parse("[libdefaults]\npermitted_enctypes = aes256-cts camellia256-cts-cmac")?;
        let policy = CryptoPolicy::from_libdefaults(&config.libdefaults)?;
        assert_eq!(policy.check_use(26, Use::AcceptorTicket), Ok(()));
        assert!(
            policy.check_use(25, Use::AcceptorTicket).is_err(),
            "camellia128 stays refused"
        );
        let etype = checked::Etype::new(&policy, 26)?;
        let key = [7_u8; 32];
        let sealed = etype.encrypt_message_with_confounder(&key, b"checked", 11, &[2; 16])?;
        assert_eq!(etype.decrypt_message(&key, &sealed, 11)?, b"checked");
        Ok(())
    }

    /// `DEFAULT` never expands to Camellia while the admitted implementation is not constant-time.
    #[test]
    fn default_excludes_camellia() -> Result<(), TestError> {
        if camellia::CONSTANT_TIME {
            return Err(
                "the admission record now says constant-time: revisit the DEFAULT list".into(),
            );
        }
        let default = EnctypeExpr::parse("DEFAULT")?.resolve(
            Toggle::Disabled,
            Toggle::Disabled,
            ParseMode::Strict,
        )?;
        let ids: Vec<i32> = default
            .enctypes()
            .iter()
            .copied()
            .map(KerberosEtype::etype_id)
            .collect();
        assert_eq!(ids, vec![20_i32, 19_i32, 18_i32, 17_i32]);
        // And the crate's built-in policy is the same list.
        let policy = CryptoPolicy::default();
        assert!(
            [25_i32, 26_i32]
                .iter()
                .all(|id| policy.check_use(*id, Use::RequestList).is_err())
        );
        Ok(())
    }

    /// Camellia names resolve only when named, in MIT's order, and removal works per size.
    #[test]
    fn camellia_names_resolve_when_named() -> Result<(), TestError> {
        /// An expression and the IDs it resolves to.
        const CASES: [(&str, &[i32]); 6] = [
            ("camellia", &[26, 25]),
            ("camellia128-cts", &[25]),
            ("CAMELLIA256-CTS-CMAC", &[26]),
            ("camellia camellia128-cts-cmac", &[26, 25]),
            ("camellia -camellia128-cts", &[26]),
            ("DEFAULT camellia256-cts", &[20, 19, 18, 17, 26]),
        ];
        for (text, expected) in CASES {
            let resolved = EnctypeExpr::parse(text)?.resolve(
                Toggle::Disabled,
                Toggle::Disabled,
                ParseMode::Strict,
            )?;
            let ids: Vec<i32> = resolved
                .enctypes()
                .iter()
                .copied()
                .map(KerberosEtype::etype_id)
                .collect();
            assert_eq!(ids, expected, "{text}");
            assert!(resolved.diagnostics().is_empty(), "{text}");
        }
        Ok(())
    }

    /// The password-derivation floor of the policy covers Camellia like the AES families.
    #[test]
    fn the_policy_floors_camellia_iterations() -> Result<(), TestError> {
        let config = Config::parse("[libdefaults]\npermitted_enctypes = camellia")?;
        let policy = CryptoPolicy::from_libdefaults(&config.libdefaults)?;
        assert_eq!(policy.min_s2k_iterations(25), Some(0x8000_u32));
        assert_eq!(policy.min_s2k_iterations(26), Some(0x8000_u32));
        assert_eq!(policy.check_s2k_params(25, "00008000"), Ok(()));
        assert_eq!(
            policy.check_s2k_params(26, "00000001").err(),
            Some(Error::Policy(Policy::S2kIterationsTooLow {
                etype: 26_i32,
                minimum: 0x8000_u32,
                actual: 1_u32
            }))
        );
        let checked_etype = checked::Etype::new(&policy, 25)?;
        assert_eq!(
            checked_etype.string_to_key(b"p", b"s", "00000010").err(),
            Some(Error::Policy(Policy::S2kIterationsTooLow {
                etype: 25_i32,
                minimum: 0x8000_u32,
                actual: 16_u32
            }))
        );
        let lowered = config
            .libdefaults
            .with_min_s2k_iterations(Family::Camellia, 1)?;
        assert_eq!(
            CryptoPolicy::from_libdefaults(&lowered)?.min_s2k_iterations(25),
            Some(1_u32)
        );
        Ok(())
    }
}

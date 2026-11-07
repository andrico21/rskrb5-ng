//! GSS-API MIC and wrap token tests against the gokrb5 vectors.
#![cfg(feature = "spnego")]

#[path = "support/context.rs"]
mod context;

/// GSS-API MIC and wrap token tests.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use hex::FromHexError;
    use pretty_assertions::assert_eq;
    use rskrb5_ng::{
        error::Spnego as Error,
        keytab::EncryptionKey,
        spnego::{
            GSS_TOKEN_FLAG_SEALED, GSS_TOKEN_FLAG_SENT_BY_ACCEPTOR, GSSAPI_ACCEPTOR_SEAL_USAGE,
            GSSAPI_ACCEPTOR_SIGN_USAGE, GSSAPI_INITIATOR_SEAL_USAGE, GSSAPI_INITIATOR_SIGN_USAGE,
            MicToken, WrapToken,
        },
    };

    use super::context::{Context as _, TestError};

    /// Secret-free diagnostics still identify MIC and Wrap token kinds.
    #[test]
    fn token_debug_keeps_diagnostic_kind() {
        assert!(format!("{:?}", MicToken::default()).starts_with("MicToken"));
        assert!(format!("{:?}", WrapToken::default()).starts_with("WrapToken"));
    }

    /// MIC and Wrap decoders reject each other's token identifiers.
    #[test]
    fn token_ids_are_type_specific() -> Result<(), TestError> {
        assert!(matches!(
            MicToken::decode(&decode_hex(WRAP_FROM_INITIATOR)?, false),
            Err(Error::InvalidGssTokenId {
                expected: _,
                actual: _
            })
        ));
        assert!(matches!(
            WrapToken::decode(&decode_hex(MIC_FROM_INITIATOR)?, false),
            Err(Error::InvalidGssTokenId {
                expected: _,
                actual: _
            })
        ));
        Ok(())
    }

    /// Explicit nonzero extra counts survive checksum installation.
    #[test]
    fn wrap_checksum_preserves_explicit_extra_count() -> Result<(), TestError> {
        let mut token = WrapToken::default().with_ec(7).with_payload(vec![42]);
        token.set_checksum(&session_key()?, GSSAPI_INITIATOR_SIGN_USAGE)?;
        assert_eq!(token.ec, 7);
        Ok(())
    }

    /// Random sealed construction produces an authenticated decryptable payload.
    #[test]
    fn random_sealed_wrap_roundtrips_payload() -> Result<(), TestError> {
        let key = session_key()?;
        let token = WrapToken::new_initiator_sealed(b"payload".to_vec(), &key)?;
        assert_eq!(
            token.decrypt_payload(&key, GSSAPI_INITIATOR_SEAL_USAGE)?,
            b"payload"
        );
        Ok(())
    }

    const MIC_PAYLOAD: &str = "deadbeef";
    const MIC_FROM_ACCEPTOR: &str = "040401ffffffffff00000000575e85d6c34d12ba3e5b1b1310cd9cb3";
    const MIC_FROM_INITIATOR: &str = "040400ffffffffff00000000000000009649ca09d2f1bc51ff6e5ca3";

    const WRAP_FROM_ACCEPTOR: &str =
        "050401ff000c000000000000575e85d601010000853b728d5268525a1386c19f";
    const WRAP_FROM_INITIATOR: &str =
        "050400ff000c000000000000000000000101000079a033510b6f127212242b97";
    const WRAP_PAYLOAD: &str = "01010000";
    const WRAP_SEALED_CONFOUNDER: &str = "000102030405060708090a0b0c0d0e0f";
    const WRAP_SEALED_FROM_INITIATOR: &str = "050402ff000000000000000000000000debcb2b270f4152cfe1cde9c62f90d12a59afda0127a094f4b18e8d8b8fc253c63239cc38ef96b6ce3e92c754f8a97b3";
    const WRAP_SEALED_RRC_FROM_INITIATOR: &str = "050402ff00000009000000000000000741b1ec99c834f8c7d3debcb2b270f4152cfe1cde9c62f90d12bde6bc91659577018ad4118b1e18e27263239cc39150a9";

    const SESSION_KEY: &str = "14f9bde6b50ec508201a97f74c4e5bd3";
    const RC4_SESSION_KEY: &str = "ac8e657f83df82beea5d43bdaf7800cc";
    const RC4_MIC_FROM_ACCEPTOR: &str =
        "040401ffffffffff00000000575e85d666d5c8d8c6568a15db2d0c324ec32414";
    const RC4_MIC_FROM_INITIATOR: &str =
        "040400ffffffffff000000000000000074a9a679e1682edfc21ba70654fd1ccc";
    const RC4_WRAP_FROM_ACCEPTOR: &str =
        "050401ff0010000000000000575e85d601010000fd1aa518115cffc141a7edbd4b844482";
    const RC4_WRAP_FROM_INITIATOR: &str =
        "050400ff001000000000000000000000010100009a6def57aa756af352904deb83ca78ff";
    const DES3_SESSION_KEY: &str = "850bb51358548cd05e86768c313e3bfef7511937dcf72c3e";
    const DES3_MIC_FROM_ACCEPTOR: &str =
        "040401ffffffffff00000000575e85d6c139350ffc99da64e9a2591db9a21d609aa2748f";
    const DES3_MIC_FROM_INITIATOR: &str =
        "040400ffffffffff0000000000000000e6c29e7e63d5fdc851285c34c1d1453b6abea103";
    const DES3_WRAP_FROM_ACCEPTOR: &str =
        "050401ff0014000000000000575e85d6010100004fb03cbebce9ef771327d9f394804c27884a8e66";
    const DES3_WRAP_FROM_INITIATOR: &str =
        "050400ff001400000000000000000000010100004cdcec3881979bb4af72359f96cdea61b05cc1f7";

    /// Pins that the gokrb5 acceptor and initiator MIC tokens decode and re-encode byte for byte.
    #[test]
    fn mic_token_decodes_and_roundtrips_gokrb5_vectors() -> Result<(), TestError> {
        let acceptor_bytes = decode_hex(MIC_FROM_ACCEPTOR)?;
        let token = MicToken::decode(&acceptor_bytes, true).context("acceptor MIC decodes")?;
        assert_eq!(
            token,
            MicToken::default()
                .with_flags(GSS_TOKEN_FLAG_SENT_BY_ACCEPTOR)
                .with_snd_seq_num(u64::from_be_bytes(
                    acceptor_bytes
                        .get(8..16)
                        .context("token carries a sequence number")?
                        .try_into()?
                ))
                .with_checksum(Some(
                    acceptor_bytes
                        .get(16..)
                        .context("MIC carries a checksum")?
                        .to_vec()
                ))
        );
        assert_eq!(
            hex_encode(&token.encode().context("acceptor MIC encodes")?),
            MIC_FROM_ACCEPTOR
        );

        let initiator_bytes = decode_hex(MIC_FROM_INITIATOR)?;
        let initiator_token =
            MicToken::decode(&initiator_bytes, false).context("initiator MIC decodes")?;
        assert_eq!(
            initiator_token,
            MicToken::default()
                .with_flags(0)
                .with_snd_seq_num(0)
                .with_checksum(Some(
                    initiator_bytes
                        .get(16..)
                        .context("MIC carries a checksum")?
                        .to_vec()
                ))
        );
        assert_eq!(
            hex_encode(&initiator_token.encode().context("initiator MIC encodes")?),
            MIC_FROM_INITIATOR
        );
        Ok(())
    }

    /// Pins that a MIC token from the wrong sender, or without a checksum, is rejected.
    #[test]
    fn mic_token_rejects_wrong_sender_and_missing_checksum() -> Result<(), TestError> {
        assert!(matches!(
            MicToken::decode(&decode_hex(MIC_FROM_ACCEPTOR)?, false),
            Err(Error::UnexpectedGssTokenSender {
                expected_from_acceptor: false,
                actual_from_acceptor: true,
            })
        ));
        assert!(matches!(
            MicToken::decode(&decode_hex(MIC_FROM_INITIATOR)?, true),
            Err(Error::UnexpectedGssTokenSender {
                expected_from_acceptor: true,
                actual_from_acceptor: false,
            })
        ));
        assert!(matches!(
            MicToken::new(0, 0).encode(),
            Err(Error::MissingGssChecksum)
        ));
        Ok(())
    }

    /// Pins that an AES MIC verifies only with its key and usage, and that the initiator MIC matches gokrb5.
    #[test]
    fn mic_token_verifies_and_builds_initiator_token() -> Result<(), TestError> {
        let key = session_key()?;
        let acceptor = MicToken::decode(&decode_hex(MIC_FROM_ACCEPTOR)?, true)
            .context("acceptor MIC decodes")?
            .with_payload(decode_hex(MIC_PAYLOAD)?);
        acceptor
            .verify(&key, GSSAPI_ACCEPTOR_SIGN_USAGE)
            .context("acceptor MIC verifies")?;
        assert!(matches!(
            acceptor.verify(&key, GSSAPI_INITIATOR_SIGN_USAGE),
            Err(Error::GssChecksumMismatch)
        ));

        let wrong_key = EncryptionKey::new(17, decode_hex("14f9bde6b50ec508201a97f74c4effff")?);
        assert!(matches!(
            acceptor.verify(&wrong_key, GSSAPI_ACCEPTOR_SIGN_USAGE),
            Err(Error::GssChecksumMismatch)
        ));

        let mut initiator = MicToken::new_initiator(decode_hex(MIC_PAYLOAD)?, &key)
            .context("initiator MIC builds")?;
        initiator.payload = None;
        assert_eq!(
            initiator,
            MicToken::default()
                .with_flags(0)
                .with_snd_seq_num(0)
                .with_checksum(Some(decode_hex(
                    MIC_FROM_INITIATOR
                        .get(32..)
                        .context("MIC carries a checksum")?
                )?))
        );
        assert_eq!(
            hex_encode(&initiator.encode().context("initiator MIC encodes")?),
            MIC_FROM_INITIATOR
        );
        Ok(())
    }

    /// Pins that RC4-HMAC MIC tokens verify and build as gokrb5 does.
    #[test]
    fn mic_token_matches_gokrb5_rc4_hmac_vectors() -> Result<(), TestError> {
        let key = rc4_session_key()?;
        let acceptor_bytes = decode_hex(RC4_MIC_FROM_ACCEPTOR)?;
        let acceptor = MicToken::decode(&acceptor_bytes, true)
            .context("RC4 acceptor MIC decodes")?
            .with_payload(decode_hex(MIC_PAYLOAD)?);
        acceptor
            .verify(&key, GSSAPI_ACCEPTOR_SIGN_USAGE)
            .context("RC4 acceptor MIC verifies")?;

        let initiator = MicToken::new_initiator(decode_hex(MIC_PAYLOAD)?, &key)
            .context("RC4 initiator MIC builds")?;
        assert_eq!(
            hex_encode(&initiator.encode().context("RC4 initiator MIC encodes")?),
            RC4_MIC_FROM_INITIATOR
        );

        let decoded = MicToken::decode(&decode_hex(RC4_MIC_FROM_INITIATOR)?, false)
            .context("RC4 MIC decodes")?
            .with_payload(decode_hex(MIC_PAYLOAD)?);
        decoded
            .verify(&key, GSSAPI_INITIATOR_SIGN_USAGE)
            .context("RC4 initiator MIC verifies")?;
        assert_eq!(
            hex_encode(&decoded.encode().context("RC4 MIC roundtrips")?),
            RC4_MIC_FROM_INITIATOR
        );
        Ok(())
    }

    /// Pins that DES3 MIC tokens verify and build as gokrb5 does.
    #[test]
    fn mic_token_matches_gokrb5_des3_vectors() -> Result<(), TestError> {
        let key = des3_session_key()?;
        let acceptor_bytes = decode_hex(DES3_MIC_FROM_ACCEPTOR)?;
        let acceptor = MicToken::decode(&acceptor_bytes, true)
            .context("DES3 acceptor MIC decodes")?
            .with_payload(decode_hex(MIC_PAYLOAD)?);
        acceptor
            .verify(&key, GSSAPI_ACCEPTOR_SIGN_USAGE)
            .context("DES3 acceptor MIC verifies")?;

        let initiator = MicToken::new_initiator(decode_hex(MIC_PAYLOAD)?, &key)
            .context("DES3 initiator MIC builds")?;
        assert_eq!(
            hex_encode(&initiator.encode().context("DES3 initiator MIC encodes")?),
            DES3_MIC_FROM_INITIATOR
        );

        let decoded = MicToken::decode(&decode_hex(DES3_MIC_FROM_INITIATOR)?, false)
            .context("DES3 MIC decodes")?
            .with_payload(decode_hex(MIC_PAYLOAD)?);
        decoded
            .verify(&key, GSSAPI_INITIATOR_SIGN_USAGE)
            .context("DES3 initiator MIC verifies")?;
        assert_eq!(
            hex_encode(&decoded.encode().context("DES3 MIC roundtrips")?),
            DES3_MIC_FROM_INITIATOR
        );
        Ok(())
    }

    /// Pins that the gokrb5 acceptor and initiator wrap tokens decode and re-encode byte for byte.
    #[test]
    fn wrap_token_decodes_and_roundtrips_gokrb5_vectors() -> Result<(), TestError> {
        let acceptor_bytes = decode_hex(WRAP_FROM_ACCEPTOR)?;
        let token = WrapToken::decode(&acceptor_bytes, true).context("acceptor wrap decodes")?;
        assert_eq!(
            token,
            WrapToken::default()
                .with_flags(GSS_TOKEN_FLAG_SENT_BY_ACCEPTOR)
                .with_ec(12)
                .with_rrc(0)
                .with_snd_seq_num(u64::from_be_bytes(
                    acceptor_bytes
                        .get(8..16)
                        .context("token carries a sequence number")?
                        .try_into()?
                ))
                .with_payload(decode_hex(WRAP_PAYLOAD)?)
                .with_checksum(Some(
                    acceptor_bytes
                        .get(20..)
                        .context("wrap carries a checksum")?
                        .to_vec()
                ))
                .with_encrypted_body(None)
        );
        assert_eq!(
            hex_encode(&token.encode().context("acceptor wrap encodes")?),
            WRAP_FROM_ACCEPTOR
        );

        let initiator_bytes = decode_hex(WRAP_FROM_INITIATOR)?;
        let initiator_token =
            WrapToken::decode(&initiator_bytes, false).context("initiator wrap decodes")?;
        assert_eq!(
            initiator_token,
            WrapToken::default()
                .with_flags(0)
                .with_ec(12)
                .with_rrc(0)
                .with_snd_seq_num(0)
                .with_payload(decode_hex(WRAP_PAYLOAD)?)
                .with_checksum(Some(
                    initiator_bytes
                        .get(20..)
                        .context("wrap carries a checksum")?
                        .to_vec()
                ))
                .with_encrypted_body(None)
        );
        assert_eq!(
            hex_encode(&initiator_token.encode().context("initiator wrap encodes")?),
            WRAP_FROM_INITIATOR
        );
        Ok(())
    }

    /// Pins that RC4-HMAC wrap tokens verify and build as gokrb5 does.
    #[test]
    fn wrap_token_matches_gokrb5_rc4_hmac_vectors() -> Result<(), TestError> {
        let key = rc4_session_key()?;
        let acceptor = WrapToken::decode(&decode_hex(RC4_WRAP_FROM_ACCEPTOR)?, true)
            .context("RC4 wrap decodes")?;
        assert_eq!(acceptor.ec, 16);
        assert_eq!(
            acceptor.payload.as_ref().map(|value| value.as_slice()),
            Some(decode_hex(WRAP_PAYLOAD)?.as_slice())
        );
        acceptor
            .verify(&key, GSSAPI_ACCEPTOR_SEAL_USAGE)
            .context("RC4 acceptor wrap verifies")?;

        let initiator =
            WrapToken::new_initiator(decode_hex(WRAP_PAYLOAD)?, &key).context("RC4 wrap builds")?;
        assert_eq!(initiator.ec, 16);
        assert_eq!(
            hex_encode(&initiator.encode().context("RC4 wrap encodes")?),
            RC4_WRAP_FROM_INITIATOR
        );

        let decoded = WrapToken::decode(&decode_hex(RC4_WRAP_FROM_INITIATOR)?, false)
            .context("RC4 wrap decodes")?;
        assert_eq!(
            hex_encode(&decoded.encode().context("RC4 wrap roundtrips")?),
            RC4_WRAP_FROM_INITIATOR
        );
        Ok(())
    }

    /// Pins that DES3 wrap tokens verify and build as gokrb5 does.
    #[test]
    fn wrap_token_matches_gokrb5_des3_vectors() -> Result<(), TestError> {
        let key = des3_session_key()?;
        let acceptor = WrapToken::decode(&decode_hex(DES3_WRAP_FROM_ACCEPTOR)?, true)
            .context("DES3 wrap decodes")?;
        assert_eq!(acceptor.ec, 20);
        assert_eq!(
            acceptor.payload.as_ref().map(|value| value.as_slice()),
            Some(decode_hex(WRAP_PAYLOAD)?.as_slice())
        );
        acceptor
            .verify(&key, GSSAPI_ACCEPTOR_SEAL_USAGE)
            .context("DES3 acceptor wrap verifies")?;

        let initiator = WrapToken::new_initiator(decode_hex(WRAP_PAYLOAD)?, &key)
            .context("DES3 wrap builds")?;
        assert_eq!(initiator.ec, 20);
        assert_eq!(
            hex_encode(&initiator.encode().context("DES3 wrap encodes")?),
            DES3_WRAP_FROM_INITIATOR
        );

        let decoded = WrapToken::decode(&decode_hex(DES3_WRAP_FROM_INITIATOR)?, false)
            .context("DES3 wrap decodes")?;
        assert_eq!(
            hex_encode(&decoded.encode().context("DES3 wrap roundtrips")?),
            DES3_WRAP_FROM_INITIATOR
        );
        Ok(())
    }

    /// Pins that wrap tokens from the wrong sender, or without a payload or checksum, are rejected.

    #[test]
    fn wrap_token_rejects_invalid_inputs() -> Result<(), TestError> {
        assert!(matches!(
            WrapToken::decode(&decode_hex(WRAP_FROM_ACCEPTOR)?, false),
            Err(Error::UnexpectedGssTokenSender {
                expected_from_acceptor: false,
                actual_from_acceptor: true,
            })
        ));
        assert!(matches!(
            WrapToken::decode(&decode_hex(WRAP_FROM_INITIATOR)?, true),
            Err(Error::UnexpectedGssTokenSender {
                expected_from_acceptor: true,
                actual_from_acceptor: false,
            })
        ));
        assert!(matches!(
            WrapToken::new(0, 0).encode(),
            Err(Error::MissingGssPayload)
        ));
        assert!(matches!(
            WrapToken::new(0, 0)
                .with_payload(decode_hex(WRAP_PAYLOAD)?)
                .encode(),
            Err(Error::MissingGssChecksum)
        ));
        Ok(())
    }

    /// Pins that an AES wrap token verifies only with its key and usage, and that the initiator token matches gokrb5.
    #[test]
    fn wrap_token_verifies_and_builds_initiator_token() -> Result<(), TestError> {
        let key = session_key()?;
        let acceptor = WrapToken::decode(&decode_hex(WRAP_FROM_ACCEPTOR)?, true)
            .context("acceptor wrap decodes")?;
        acceptor
            .verify(&key, GSSAPI_ACCEPTOR_SEAL_USAGE)
            .context("acceptor wrap verifies")?;
        assert!(matches!(
            acceptor.verify(&key, GSSAPI_INITIATOR_SEAL_USAGE),
            Err(Error::GssChecksumMismatch)
        ));

        let wrong_key = EncryptionKey::new(17, decode_hex("14f9bde6b50ec508201a97f74c4effff")?);
        assert!(matches!(
            acceptor.verify(&wrong_key, GSSAPI_ACCEPTOR_SEAL_USAGE),
            Err(Error::GssChecksumMismatch)
        ));

        let initiator = WrapToken::new_initiator(decode_hex(WRAP_PAYLOAD)?, &key)
            .context("initiator wrap builds")?;
        assert_eq!(
            initiator,
            WrapToken::default()
                .with_flags(0)
                .with_ec(12)
                .with_rrc(0)
                .with_snd_seq_num(0)
                .with_payload(decode_hex(WRAP_PAYLOAD)?)
                .with_checksum(Some(decode_hex(
                    WRAP_FROM_INITIATOR
                        .get(40..)
                        .context("wrap carries a checksum")?
                )?))
                .with_encrypted_body(None)
        );
        assert_eq!(
            hex_encode(&initiator.encode().context("initiator wrap encodes")?),
            WRAP_FROM_INITIATOR
        );
        Ok(())
    }

    /// Pins that a sealed wrap token encrypts to the expected bytes, decrypts, verifies and round-trips.
    #[test]
    fn sealed_wrap_token_encrypts_decrypts_and_roundtrips() -> Result<(), TestError> {
        let key = session_key()?;
        let token = WrapToken::new_initiator_sealed_with_confounder(
            decode_hex(WRAP_PAYLOAD)?,
            &key,
            &decode_hex(WRAP_SEALED_CONFOUNDER)?,
        )
        .context("sealed initiator wrap builds")?;

        assert_eq!(token.flags, GSS_TOKEN_FLAG_SEALED);
        assert_eq!(token.ec, 0);
        assert_eq!(token.rrc, 0);
        assert_eq!(token.snd_seq_num, 0);
        assert_eq!(
            token.payload.as_ref().map(|value| value.as_slice()),
            Some(decode_hex(WRAP_PAYLOAD)?.as_slice())
        );
        assert!(token.checksum.is_none());
        assert!(token.encrypted_body.is_some());

        let encoded = token.encode().context("sealed wrap encodes")?;
        assert_eq!(hex_encode(&encoded), WRAP_SEALED_FROM_INITIATOR);
        let mut decoded = WrapToken::decode(&encoded, false).context("sealed wrap decodes")?;
        assert!(decoded.is_sealed());
        assert!(decoded.payload.is_none());
        assert_eq!(
            decoded
                .decrypt_payload(&key, GSSAPI_INITIATOR_SEAL_USAGE)
                .context("sealed wrap decrypts")?,
            decode_hex(WRAP_PAYLOAD)?
        );
        decoded
            .verify(&key, GSSAPI_INITIATOR_SEAL_USAGE)
            .context("sealed wrap verifies")?;

        assert_eq!(
            decoded
                .decrypt_and_set_payload(&key, GSSAPI_INITIATOR_SEAL_USAGE)
                .context("sealed wrap decrypts into token")?,
            decode_hex(WRAP_PAYLOAD)?.as_slice()
        );
        assert_eq!(
            decoded.payload.as_ref().map(|value| value.as_slice()),
            Some(decode_hex(WRAP_PAYLOAD)?.as_slice())
        );
        Ok(())
    }

    /// Pins that a sealed wrap token with a right rotation count encodes, decodes and decrypts.
    #[test]
    fn sealed_wrap_token_supports_rrc_rotation() -> Result<(), TestError> {
        let key = session_key()?;
        let mut token =
            WrapToken::new(GSS_TOKEN_FLAG_SEALED, 7).with_payload(decode_hex(WRAP_PAYLOAD)?);
        token.rrc = 9;
        token
            .encrypt_payload_with_confounder(
                &key,
                GSSAPI_INITIATOR_SEAL_USAGE,
                &decode_hex(WRAP_SEALED_CONFOUNDER)?,
            )
            .context("sealed wrap encrypts")?;

        let encoded = token.encode().context("rotated sealed wrap encodes")?;
        assert_eq!(hex_encode(&encoded), WRAP_SEALED_RRC_FROM_INITIATOR);
        assert_eq!(
            u16::from_be_bytes(
                encoded
                    .get(6..8)
                    .context("wrap carries an RRC")?
                    .try_into()?
            ),
            9
        );

        let decoded = WrapToken::decode(&encoded, false).context("rotated sealed wrap decodes")?;
        assert_eq!(decoded.rrc, 9);
        assert_eq!(
            decoded
                .decrypt_payload(&key, GSSAPI_INITIATOR_SEAL_USAGE)
                .context("rotated sealed wrap decrypts")?,
            decode_hex(WRAP_PAYLOAD)?
        );
        Ok(())
    }

    /// Pins that a sealed wrap token fails to decrypt under the wrong usage, a changed header or a flipped ciphertext bit.
    #[test]
    fn sealed_wrap_token_rejects_tampering_and_wrong_usage() -> Result<(), TestError> {
        let key = session_key()?;
        let token = WrapToken::new_initiator_sealed_with_confounder(
            decode_hex(WRAP_PAYLOAD)?,
            &key,
            &decode_hex(WRAP_SEALED_CONFOUNDER)?,
        )
        .context("sealed initiator wrap builds")?;
        let mut decoded = WrapToken::decode(&token.encode().context("sealed wrap encodes")?, false)
            .context("decodes")?;

        assert!(matches!(
            decoded.decrypt_payload(&key, GSSAPI_ACCEPTOR_SEAL_USAGE),
            Err(Error::Crypto(_))
        ));

        decoded.snd_seq_num = 1;
        assert!(matches!(
            decoded.decrypt_payload(&key, GSSAPI_INITIATOR_SEAL_USAGE),
            Err(Error::InvalidGssEncryptedHeader)
        ));

        let mut encoded = token.encode().context("sealed wrap encodes")?;
        let last = encoded.last_mut().context("sealed wrap is not empty")?;
        *last ^= 0x01;
        let tampered =
            WrapToken::decode(&encoded, false).context("tampered sealed wrap still parses")?;
        assert!(matches!(
            tampered.decrypt_payload(&key, GSSAPI_INITIATOR_SEAL_USAGE),
            Err(Error::Crypto(_))
        ));
        Ok(())
    }

    /// Pins RFC 4121 body rotation against independently rotated wire bytes.
    #[test]
    fn unsealed_wrap_applies_rrc_on_decode_and_encode() -> Result<(), TestError> {
        let key = session_key()?;
        let baseline = decode_hex(WRAP_FROM_INITIATOR)?;
        for rrc in [0_u16, 3, 19] {
            let mut wire = baseline.clone();
            wire.get_mut(6..8)
                .context("RRC field")?
                .copy_from_slice(&rrc.to_be_bytes());
            let body = wire.get_mut(16..).context("wrap body")?;
            let shift = usize::from(rrc)
                .checked_rem(body.len())
                .context("nonempty body")?;
            body.rotate_right(shift);
            let decoded = WrapToken::decode(&wire, false)?;
            decoded.verify(&key, GSSAPI_INITIATOR_SEAL_USAGE)?;
            assert_eq!(
                decoded.payload.as_ref().map(|value| value.as_slice()),
                Some(decode_hex(WRAP_PAYLOAD)?.as_slice())
            );
            assert_eq!(
                WrapToken::new_initiator(decode_hex(WRAP_PAYLOAD)?, &key)?
                    .with_rrc(rrc)
                    .encode()?,
                wire
            );
        }
        Ok(())
    }

    /// Pins exact DES3 payload recovery for every block residue, including trailing zeroes.
    #[test]
    fn sealed_des3_wrap_roundtrips_all_payload_residues() -> Result<(), TestError> {
        let key = des3_session_key()?;
        for len in 0_usize..=17 {
            // Given a payload whose trailing zeroes must not be stripped.
            let payload = vec![0; len];
            // When the convenience constructor seals and serializes it.
            let token =
                WrapToken::new_initiator_sealed_with_confounder(payload.clone(), &key, &[0x42; 8])?;
            let decoded = WrapToken::decode(&token.encode()?, false)?;
            // Then the embedded header and exact payload survive decryption.
            assert_eq!(
                decoded.decrypt_payload(&key, GSSAPI_INITIATOR_SEAL_USAGE)?,
                payload
            );
            assert_eq!(usize::from(decoded.ec), len.wrapping_neg() & 7);
        }
        Ok(())
    }

    /// Pins manual filler preservation and completion before the encrypted header, with rotation.
    #[test]
    fn sealed_des3_wrap_completes_manual_filler() -> Result<(), TestError> {
        let key = des3_session_key()?;
        for (requested, expected) in [(7, 7), (15, 15), (1, 7), (8, 15)] {
            // Given an explicit filler request and a nonzero sequence/rotation.
            let mut token = WrapToken::new(GSS_TOKEN_FLAG_SEALED, 42)
                .with_payload(vec![0])
                .with_ec(requested)
                .with_rrc(9);
            // When sealing through the shared mutable entry point.
            token.encrypt_payload_with_confounder(&key, GSSAPI_INITIATOR_SEAL_USAGE, &[0x42; 8])?;
            let decoded = WrapToken::decode(&token.encode()?, false)?;
            // Then filler is sufficient and no application byte is lost.
            assert_eq!(
                decoded.decrypt_payload(&key, GSSAPI_INITIATOR_SEAL_USAGE)?,
                vec![0]
            );
            assert_eq!(decoded.ec, expected);
        }
        Ok(())
    }

    /// Pins rejection when DES3 alignment would overflow the wire EC field.
    #[test]
    fn sealed_des3_wrap_rejects_filler_overflow() -> Result<(), TestError> {
        let key = des3_session_key()?;
        let mut token = WrapToken::new(GSS_TOKEN_FLAG_SEALED, 0)
            .with_payload(vec![0; 2])
            .with_ec(u16::MAX);
        assert!(matches!(
            token.encrypt_payload_with_confounder(&key, GSSAPI_INITIATOR_SEAL_USAGE, &[0x42; 8]),
            Err(Error::InvalidGssFiller)
        ));
        assert!(token.encrypted_body.is_none());
        Ok(())
    }

    fn session_key() -> Result<EncryptionKey, TestError> {
        Ok(EncryptionKey::new(17, decode_hex(SESSION_KEY)?))
    }

    fn rc4_session_key() -> Result<EncryptionKey, TestError> {
        Ok(EncryptionKey::new(23, decode_hex(RC4_SESSION_KEY)?))
    }

    fn des3_session_key() -> Result<EncryptionKey, TestError> {
        Ok(EncryptionKey::new(16, decode_hex(DES3_SESSION_KEY)?))
    }

    /// Decodes a hex fixture.
    fn decode_hex(input: &str) -> Result<Vec<u8>, FromHexError> {
        hex::decode(input)
    }

    /// Encodes bytes as lowercase hex.
    fn hex_encode(bytes: &[u8]) -> String {
        hex::encode(bytes)
    }
}

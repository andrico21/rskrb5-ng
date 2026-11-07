//! KRB-CRED decoding, decryption and ccache conversion tests.
#![cfg(feature = "messages")]

/// KRB-CRED decoding, decryption and ccache conversion tests.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::{error, fmt::Display};

    use pretty_assertions::assert_eq;
    use rasn::{der, types::Integer};
    use rasn_kerberos::{EncKrbCredPart, EncryptedData, KrbCred};
    use rskrb5_ng::{
        ccache,
        crypto::KerberosEtype,
        error::KrbCred as Error,
        keytab::EncryptionKey,
        krb_cred::{
            KRB_CRED_ENCPART_USAGE, KRB_CRED_MSG_TYPE, ccache_credentials_to_krb_cred_parts,
            decode as decode_krb_cred, decode_decrypt_krb_cred_to_ccache_credentials,
            decode_enc_krb_cred_part, decrypt_krb_cred_enc_part,
            decrypt_krb_cred_to_ccache_credentials, decrypted_krb_cred_to_ccache_credentials,
            encode_encrypt_ccache_credentials_to_krb_cred_with_confounder,
            encode_encrypted_ccache_credentials as encode_encrypt_ccache_credentials_to_krb_cred,
            encrypt_ccache_credentials_to_krb_cred_with_confounder,
        },
    };

    /// Error type of the `Result`-returning tests.
    type TestError = Box<dyn error::Error>;

    /// Attaches a description to a failure, as `expect` would, but as an error
    /// that `?` propagates.
    trait Context<T> {
        /// Returns the value, or an error that names `what`.
        fn context(self, what: &str) -> Result<T, TestError>;
    }

    impl<T, E: Display> Context<T> for Result<T, E> {
        fn context(self, what: &str) -> Result<T, TestError> {
            self.map_err(|cause| format!("{what}: {cause}").into())
        }
    }

    impl<T> Context<T> for Option<T> {
        fn context(self, what: &str) -> Result<T, TestError> {
            self.ok_or_else(|| what.into())
        }
    }

    /// The AES-256 reply key the encrypted part is sealed under.
    const REPLY_KEY: &str = "9cad00bbc72d703258e911dc18e6d5487cf737bf67fd111f0c2463ad6033bf51";
    /// The fixed confounder of the deterministic encryptions.
    const CONFOUNDER: &str = "101112131415161718191a1b1c1d1e1f";
    /// The gokrb5 fixture time, 1994-06-10 06:03:17 UTC, in Unix seconds.
    const TEST_TIME_SECONDS: u32 = 771_228_197;
    /// The gokrb5 KRB-CRED fixture with two tickets.
    const KRB_CRED: &str = concat!(
        "7681F63081F3A003020105A103020116A281BF3081BC615C305AA003020105A110",
        "1B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866",
        "747361691B056578747261A3253023A003020100A103020105A21704156B726241",
        "534E2E312074657374206D657373616765615C305AA003020105A1101B0E415448",
        "454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B",
        "056578747261A3253023A003020100A103020105A21704156B726241534E2E3120",
        "74657374206D657373616765A3253023A003020100A103020105A21704156B7262",
        "41534E2E312074657374206D657373616765",
    );
    /// The gokrb5 `EncKrbCredPart` fixture with two ticket infos.
    const ENC_KRB_CRED_PART: &str = concat!(
        "7D8202233082021FA08201DA308201D63081E8A0133011A003020101A10A040831",
        "32333435363738A1101B0E415448454E412E4D49542E454455A21A3018A0030201",
        "01A111300F1B066866747361691B056578747261A307030500FEDCBA98A411180F",
        "31393934303631303036303331375AA511180F3139393430363130303630333137",
        "5AA611180F31393934303631303036303331375AA711180F313939343036313030",
        "36303331375AA8101B0E415448454E412E4D49542E454455A91A3018A003020101",
        "A111300F1B066866747361691B056578747261AA20301E300DA003020102A10604",
        "0412D00023300DA003020102A106040412D000233081E8A0133011A003020101A1",
        "0A04083132333435363738A1101B0E415448454E412E4D49542E454455A21A3018",
        "A003020101A111300F1B066866747361691B056578747261A307030500FEDCBA98",
        "A411180F31393934303631303036303331375AA511180F31393934303631303036",
        "303331375AA611180F31393934303631303036303331375AA711180F3139393430",
        "3631303036303331375AA8101B0E415448454E412E4D49542E454455A91A3018A0",
        "03020101A111300F1B066866747361691B056578747261AA20301E300DA0030201",
        "02A106040412D00023300DA003020102A106040412D00023A10302012AA211180F",
        "31393934303631303036303331375AA305020301E240A40F300DA003020102A106",
        "040412D00023A50F300DA003020102A106040412D00023",
    );

    /// Pins the version, message type, tickets and encrypted part of the gokrb5 KRB-CRED fixture.
    #[test]
    fn decodes_gokrb5_krb_cred_fixture() -> Result<(), TestError> {
        let krb_cred = decode_krb_cred(&hex::decode(KRB_CRED)?).context("KRB-CRED decodes")?;

        assert_eq!(krb_cred.pvno, Integer::from(5_i32));
        assert_eq!(krb_cred.msg_type, Integer::from(KRB_CRED_MSG_TYPE));
        assert_eq!(krb_cred.tickets.len(), 2);
        let ticket = krb_cred.tickets.first().context("a first ticket")?;
        assert_eq!(ticket.tkt_vno, Integer::from(5_i32));
        assert_eq!(ticket.enc_part.etype, 0_i32);
        assert_eq!(ticket.enc_part.kvno, Some(5));
        assert_eq!(krb_cred.enc_part.etype, 0_i32);
        assert_eq!(krb_cred.enc_part.kvno, Some(5));
        assert_eq!(krb_cred.enc_part.cipher.as_ref(), b"krbASN.1 test message");
        Ok(())
    }

    /// Pins the ticket infos, nonce, usec and addresses of the gokrb5 `EncKrbCredPart` fixture.
    #[test]
    fn decodes_gokrb5_enc_krb_cred_part_fixture() -> Result<(), TestError> {
        let enc_part = decode_enc_krb_cred_part(&hex::decode(ENC_KRB_CRED_PART)?)
            .context("EncKrbCredPart decodes")?;

        assert_eq!(enc_part.ticket_info.len(), 2);
        let info = enc_part
            .ticket_info
            .first()
            .context("a first ticket info")?;
        assert_eq!(info.key.r#type, 1_i32);
        assert_eq!(info.key.value.as_ref(), b"12345678");
        assert_eq!(enc_part.nonce, Some(42));
        assert_eq!(enc_part.usec, Some(Integer::from(123_456_i32)));
        assert_eq!(
            enc_part
                .sender_address
                .as_ref()
                .context("sender")?
                .addr_type,
            2_i32
        );
        assert_eq!(
            enc_part
                .recipient_address
                .as_ref()
                .context("recipient")?
                .addr_type,
            2_i32
        );
        Ok(())
    }

    /// Pins that the encrypted part decrypts back to the encrypted `EncKrbCredPart`.
    #[test]
    fn decrypts_krb_cred_encrypted_part() -> Result<(), TestError> {
        let enc_part = decode_enc_krb_cred_part(&hex::decode(ENC_KRB_CRED_PART)?)
            .context("EncKrbCredPart decodes")?;
        let krb_cred = encrypted_krb_cred(&enc_part)?;
        let key = reply_key()?;

        let decrypted = decrypt_krb_cred_enc_part(&krb_cred, &key)
            .context("KRB-CRED encrypted part decrypts")?;

        assert_eq!(decrypted, enc_part);
        Ok(())
    }

    /// Pins the ccache credentials converted from the decoded gokrb5 fixtures.
    #[test]
    fn converts_decrypted_krb_cred_to_ccache_credentials() -> Result<(), TestError> {
        let krb_cred = decode_krb_cred(&hex::decode(KRB_CRED)?).context("KRB-CRED decodes")?;
        let enc_part = decode_enc_krb_cred_part(&hex::decode(ENC_KRB_CRED_PART)?)
            .context("EncKrbCredPart decodes")?;

        let credentials = decrypted_krb_cred_to_ccache_credentials(&krb_cred, &enc_part)
            .context("KRB-CRED converts to ccache credentials")?;

        assert_eq!(credentials.len(), 2);
        let credential = credentials.first().context("a first credential")?;
        assert_eq!(credential.client.realm, "ATHENA.MIT.EDU");
        assert_eq!(credential.client.components, ["hftsai", "extra"]);
        assert_eq!(credential.server.realm, "ATHENA.MIT.EDU");
        assert_eq!(credential.server.components, ["hftsai", "extra"]);
        assert_eq!(credential.key.etype, 1_i32);
        assert_eq!(credential.key.value, b"12345678");
        assert_eq!(credential.times.auth_time, TEST_TIME_SECONDS);
        assert_eq!(credential.times.start_time, TEST_TIME_SECONDS);
        assert_eq!(credential.times.end_time, TEST_TIME_SECONDS);
        assert_eq!(credential.times.renew_till, TEST_TIME_SECONDS);
        assert_eq!(credential.ticket_flags, [0xfe, 0xdc, 0xba, 0x98]);
        assert_eq!(credential.addresses.len(), 2);
        let address = credential.addresses.first().context("a first address")?;
        assert_eq!(address.addr_type, 2_i32);
        assert_eq!(address.address, hex::decode("12d00023")?);
        assert_eq!(
            credential.ticket.as_slice(),
            der::encode(krb_cred.tickets.first().context("a first ticket")?)
                .context("ticket encodes")?
        );
        assert!(credential.auth_data.is_empty(), "no auth-data is converted");
        assert!(
            credential.second_ticket.is_empty(),
            "no second ticket is converted"
        );
        Ok(())
    }

    /// Pins that an encrypted KRB-CRED decrypts into ccache credentials carrying the tickets.
    #[test]
    fn decrypts_krb_cred_to_ccache_credentials() -> Result<(), TestError> {
        let enc_part = decode_enc_krb_cred_part(&hex::decode(ENC_KRB_CRED_PART)?)
            .context("EncKrbCredPart decodes")?;
        let krb_cred = encrypted_krb_cred(&enc_part)?;
        let key = reply_key()?;

        let credentials = decrypt_krb_cred_to_ccache_credentials(&krb_cred, &key)
            .context("KRB-CRED decrypts and converts")?;

        assert_eq!(credentials.len(), 2);
        let [first, second] = credentials.as_slice() else {
            return Err("two credentials".into());
        };
        let [first_ticket, second_ticket] = krb_cred.tickets.as_slice() else {
            return Err("two tickets".into());
        };
        assert_eq!(first.client.components, ["hftsai", "extra"]);
        assert_eq!(
            first.ticket.as_slice(),
            der::encode(first_ticket).context("ticket encodes")?
        );
        assert_eq!(
            second.ticket.as_slice(),
            der::encode(second_ticket).context("ticket encodes")?
        );
        Ok(())
    }

    /// Pins that DER KRB-CRED bytes decode, decrypt and convert into ccache credentials.
    #[test]
    fn decodes_decrypts_krb_cred_to_ccache_credentials() -> Result<(), TestError> {
        let enc_part = decode_enc_krb_cred_part(&hex::decode(ENC_KRB_CRED_PART)?)
            .context("EncKrbCredPart decodes")?;
        let krb_cred = encrypted_krb_cred(&enc_part)?;
        let bytes = der::encode(&krb_cred).context("KRB-CRED encodes")?;
        let key = reply_key()?;

        let credentials = decode_decrypt_krb_cred_to_ccache_credentials(&bytes, &key)
            .context("KRB-CRED bytes decode, decrypt, and convert")?;

        assert_eq!(credentials.len(), 2);
        assert_eq!(
            credentials
                .first()
                .context("a first credential")?
                .server
                .realm,
            "ATHENA.MIT.EDU"
        );
        assert_eq!(
            credentials
                .get(1)
                .context("a second credential")?
                .times
                .end_time,
            TEST_TIME_SECONDS
        );
        Ok(())
    }

    /// Pins the tickets and ticket infos built from ccache credentials.
    #[test]
    fn builds_krb_cred_parts_from_ccache_credentials() -> Result<(), TestError> {
        let credentials = fixture_ccache_credentials()?;

        let (tickets, enc_part) =
            ccache_credentials_to_krb_cred_parts(&credentials).context("KRB-CRED parts build")?;

        assert_eq!(tickets.len(), 2);
        assert_eq!(
            tickets.first().context("a first built ticket")?,
            decode_krb_cred(&hex::decode(KRB_CRED)?)
                .context("KRB-CRED decodes")?
                .tickets
                .first()
                .context("a first fixture ticket")?
        );
        assert_eq!(enc_part.ticket_info.len(), 2);
        let info = enc_part
            .ticket_info
            .first()
            .context("a first ticket info")?;
        assert_eq!(info.key.r#type, 1_i32);
        assert_eq!(info.key.value.as_ref(), b"12345678");
        assert_eq!(
            info.prealm.as_ref().context("client realm")?.as_bytes(),
            b"ATHENA.MIT.EDU"
        );
        Ok(())
    }

    /// Pins that ccache credentials survive an export to KRB-CRED and an import back.
    #[test]
    fn encrypts_ccache_credentials_to_krb_cred_roundtrip() -> Result<(), TestError> {
        let credentials = fixture_ccache_credentials()?;
        let key = reply_key()?;

        let krb_cred = encrypt_ccache_credentials_to_krb_cred_with_confounder(
            &credentials,
            &key,
            &hex::decode(CONFOUNDER)?,
        )
        .context("KRB-CRED exports")?;
        let round_tripped = decrypt_krb_cred_to_ccache_credentials(&krb_cred, &key)
            .context("exported KRB-CRED imports")?;

        assert_eq!(round_tripped, credentials);
        Ok(())
    }

    /// Pins that zero start and renew times round-trip as zero, without a start-time fallback.
    #[test]
    fn exports_zero_ccache_times_without_start_time_fallback() -> Result<(), TestError> {
        let mut credentials = fixture_ccache_credentials()?;
        let first = credentials.first_mut().context("a first credential")?;
        first.times.start_time = 0;
        first.times.renew_till = 0;
        let key = reply_key()?;

        let krb_cred = encrypt_ccache_credentials_to_krb_cred_with_confounder(
            &credentials,
            &key,
            &hex::decode(CONFOUNDER)?,
        )
        .context("KRB-CRED exports")?;
        let round_tripped = decrypt_krb_cred_to_ccache_credentials(&krb_cred, &key)
            .context("exported KRB-CRED imports")?;

        assert_eq!(
            round_tripped
                .first()
                .context("a first imported credential")?
                .times,
            credentials
                .first()
                .context("a first exported credential")?
                .times
        );
        Ok(())
    }

    /// Pins that ccache credentials survive an export to DER KRB-CRED bytes and an import back.
    #[test]
    fn encodes_ccache_credentials_to_krb_cred_bytes() -> Result<(), TestError> {
        let credentials = fixture_ccache_credentials()?;
        let key = reply_key()?;

        let bytes = encode_encrypt_ccache_credentials_to_krb_cred_with_confounder(
            &credentials,
            &key,
            &hex::decode(CONFOUNDER)?,
        )
        .context("DER KRB-CRED exports")?;
        let round_tripped = decode_decrypt_krb_cred_to_ccache_credentials(&bytes, &key)
            .context("DER KRB-CRED imports")?;

        assert_eq!(round_tripped, credentials);
        Ok(())
    }

    /// Pins that an export with a random confounder imports back unchanged.
    #[test]
    fn encodes_ccache_credentials_to_krb_cred_with_random_confounder() -> Result<(), TestError> {
        let credentials = fixture_ccache_credentials()?;
        let key = reply_key()?;

        let bytes = encode_encrypt_ccache_credentials_to_krb_cred(&credentials, &key)
            .context("random-confounder DER KRB-CRED exports")?;
        let round_tripped = decode_decrypt_krb_cred_to_ccache_credentials(&bytes, &key)
            .context("random-confounder DER KRB-CRED imports")?;

        assert_eq!(round_tripped, credentials);
        Ok(())
    }

    /// Pins that credentials with auth-data or a second ticket cannot be exported.
    #[test]
    fn rejects_ccache_credentials_with_unrepresentable_fields() -> Result<(), TestError> {
        let mut with_auth_data = fixture_ccache_credentials()?;
        with_auth_data
            .first_mut()
            .context("a first credential")?
            .auth_data = vec![ccache::AuthorizationDataEntry::new(1, vec![2, 3].into())];

        let auth_data_error = ccache_credentials_to_krb_cred_parts(&with_auth_data)
            .err()
            .context("ccache auth-data is rejected")?;

        assert!(matches!(
            auth_data_error,
            Error::UnsupportedCredentialAuthData
        ));

        let mut with_second_ticket = fixture_ccache_credentials()?;
        with_second_ticket
            .first_mut()
            .context("a first credential")?
            .second_ticket = vec![0x61, 0x03, 0x02, 0x01, 0x05].into();

        let second_ticket_error = ccache_credentials_to_krb_cred_parts(&with_second_ticket)
            .err()
            .context("ccache second ticket is rejected")?;

        assert!(matches!(
            second_ticket_error,
            Error::UnsupportedSecondTicket
        ));
        Ok(())
    }

    /// Pins that a ticket-info count that differs from the ticket count is rejected.
    #[test]
    fn rejects_krb_cred_ticket_info_count_mismatch() -> Result<(), TestError> {
        let krb_cred = decode_krb_cred(&hex::decode(KRB_CRED)?).context("KRB-CRED decodes")?;
        let mut enc_part = decode_enc_krb_cred_part(&hex::decode(ENC_KRB_CRED_PART)?)
            .context("EncKrbCredPart decodes")?;
        drop(enc_part.ticket_info.pop());

        let error = decrypted_krb_cred_to_ccache_credentials(&krb_cred, &enc_part)
            .err()
            .context("ticket-info count mismatch is rejected")?;

        assert!(matches!(
            error,
            Error::TicketInfoCountMismatch {
                ticket_count: 2,
                info_count: 1,
            }
        ));
        Ok(())
    }

    /// Converts the decoded gokrb5 fixtures into ccache credentials.
    fn fixture_ccache_credentials() -> Result<Vec<ccache::Credential>, TestError> {
        let krb_cred = decode_krb_cred(&hex::decode(KRB_CRED)?).context("KRB-CRED decodes")?;
        let enc_part = decode_enc_krb_cred_part(&hex::decode(ENC_KRB_CRED_PART)?)
            .context("EncKrbCredPart decodes")?;
        decrypted_krb_cred_to_ccache_credentials(&krb_cred, &enc_part)
            .context("KRB-CRED converts to ccache credentials")
    }

    /// Pins that a key whose etype differs from the encrypted part's is rejected.
    #[test]
    fn rejects_krb_cred_key_etype_mismatch() -> Result<(), TestError> {
        let enc_part = decode_enc_krb_cred_part(&hex::decode(ENC_KRB_CRED_PART)?)
            .context("EncKrbCredPart decodes")?;
        let krb_cred = encrypted_krb_cred(&enc_part)?;
        let key = EncryptionKey::new(17, vec![0; 16]);

        let error = decrypt_krb_cred_enc_part(&krb_cred, &key)
            .err()
            .context("wrong key etype is rejected")?;

        assert!(matches!(
            error,
            Error::KeyEtypeMismatch {
                key_etype: 17_i32,
                encrypted_data_etype: 18_i32,
            }
        ));
        Ok(())
    }

    /// Builds the fixture KRB-CRED with `enc_part` encrypted under the reply key.
    fn encrypted_krb_cred(enc_part: &EncKrbCredPart) -> Result<KrbCred, TestError> {
        let key = reply_key()?;
        let etype = KerberosEtype::from_etype_id(key.etype).context("supported etype")?;
        let plaintext = der::encode(enc_part).context("EncKrbCredPart encodes")?;
        let cipher = etype
            .encrypt_message_with_confounder(
                &key.value,
                &plaintext,
                KRB_CRED_ENCPART_USAGE,
                &hex::decode(CONFOUNDER)?,
            )
            .context("KRB-CRED encrypted part encrypts")?;
        let fixture = decode_krb_cred(&hex::decode(KRB_CRED)?).context("KRB-CRED decodes")?;
        Ok(KrbCred {
            pvno: Integer::from(5_i32),
            msg_type: Integer::from(KRB_CRED_MSG_TYPE),
            tickets: fixture.tickets,
            enc_part: EncryptedData {
                etype: key.etype,
                kvno: Some(7),
                cipher: cipher.into(),
            },
        })
    }

    /// The AES-256 reply key.
    fn reply_key() -> Result<EncryptionKey, TestError> {
        Ok(EncryptionKey::new(18, hex::decode(REPLY_KEY)?))
    }
}

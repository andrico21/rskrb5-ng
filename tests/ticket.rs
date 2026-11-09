//! Ticket tests: gokrb5 fixture decoding, encrypted-part building and decryption.
#![cfg(feature = "messages")]

/// Ticket tests.
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
    use rasn::types::{GeneralString, Integer};
    use rasn_kerberos::{PrincipalName, TicketFlags};
    use rskrb5_ng::{
        crypto::KerberosEtype,
        error::Ticket as Error,
        keytab::EncryptionKey,
        ticket::{
            KDC_REP_TICKET_USAGE, KRB5_TKT_VNO, build as build_ticket,
            build_ticket_with_confounder, decode as decode_ticket, decode_enc_ticket_part,
            decrypt_ticket_enc_part, encode as encode_ticket, encode_build_ticket_with_confounder,
        },
    };

    /// Error type of the `Result`-returning tests.
    type TestError = Box<dyn error::Error>;

    /// gokrb5 Ticket fixture.
    const MARSHALLED_TICKET: &str = concat!(
        "615C305AA003020105A1101B0E415448454E412E4D49542E454455A21A",
        "3018A003020101A111300F1B066866747361691B056578747261A32530",
        "23A003020100A103020105A21704156B726241534E2E31207465737420",
        "6D657373616765",
    );
    /// gokrb5 `EncTicketPart` fixture with every optional field set.
    const MARSHALLED_ENC_TICKET_PART: &str = concat!(
        "6382011430820110A007030500FEDCBA98A1133011A003020101A10A",
        "04083132333435363738A2101B0E415448454E412E4D49542E454455A3",
        "1A3018A003020101A111300F1B066866747361691B056578747261A42E",
        "302CA003020101A12504234544552C4D49542E2C415448454E412E2C",
        "57415348494E47544F4E2E4544552C43532EA511180F313939343036",
        "31303036303331375AA611180F31393934303631303036303331375AA7",
        "11180F31393934303631303036303331375AA811180F31393934303631",
        "303036303331375AA920301E300DA003020102A106040412D00023300D",
        "A003020102A106040412D00023AA243022300FA003020101A1080406",
        "666F6F626172300FA003020101A1080406666F6F626172",
    );
    /// gokrb5 `EncTicketPart` fixture without optional fields.
    const MARSHALLED_ENC_TICKET_PART_OPTIONALS_NULL: &str = concat!(
        "6381A53081A2A007030500FEDCBA98A1133011A003020101A10A04",
        "083132333435363738A2101B0E415448454E412E4D49542E454455A31A",
        "3018A003020101A111300F1B066866747361691B056578747261A42E",
        "302CA003020101A12504234544552C4D49542E2C415448454E412E2C",
        "57415348494E47544F4E2E4544552C43532EA511180F313939343036",
        "31303036303331375AA711180F31393934303631303036303331375A",
    );
    /// Timestamp of the gokrb5 fixtures, in seconds since the Unix epoch.
    const TEST_TIME_SECONDS: i64 = 771_228_197;
    /// AES256 key used to encrypt the ticket parts.
    const REPLY_KEY: &str = "9cad00bbc72d703258e911dc18e6d5487cf737bf67fd111f0c2463ad6033bf51";

    /// Pins that the gokrb5 Ticket fixture decodes to the expected fields and re-encodes byte for byte.
    #[test]
    fn decodes_gokrb5_ticket_fixture() -> Result<(), TestError> {
        let bytes = hex::decode(MARSHALLED_TICKET)?;

        let ticket = decode_ticket(&bytes)?;

        assert_eq!(ticket.tkt_vno, Integer::from(KRB5_TKT_VNO));
        assert_eq!(ticket.realm.as_bytes(), b"ATHENA.MIT.EDU");
        assert_eq!(ticket.sname.r#type, 1_i32);
        assert_eq!(
            principal_components(&ticket.sname),
            vec![b"hftsai".as_slice(), b"extra".as_slice()],
        );
        assert_eq!(ticket.enc_part.etype, 0_i32);
        assert_eq!(ticket.enc_part.kvno, Some(5));
        assert_eq!(ticket.enc_part.cipher.as_ref(), b"krbASN.1 test message");
        assert_eq!(encode_ticket(&ticket)?, bytes);
        Ok(())
    }

    /// Pins that the gokrb5 `EncTicketPart` fixture decodes to the expected fields.
    #[test]
    fn decodes_gokrb5_enc_ticket_part_fixture() -> Result<(), TestError> {
        let enc_ticket = decode_enc_ticket_part(&hex::decode(MARSHALLED_ENC_TICKET_PART)?)?;

        assert_eq!(ticket_flags_to_bits(&enc_ticket.flags), 0xfedc_ba98);
        assert_eq!(enc_ticket.key.r#type, 1_i32);
        assert_eq!(enc_ticket.key.value.as_ref(), b"12345678");
        assert_eq!(enc_ticket.crealm.as_bytes(), b"ATHENA.MIT.EDU");
        assert_eq!(enc_ticket.cname.r#type, 1_i32);
        assert_eq!(
            principal_components(&enc_ticket.cname),
            vec![b"hftsai".as_slice(), b"extra".as_slice()],
        );
        assert_eq!(enc_ticket.transited.r#type, 1_i32);
        assert_eq!(
            enc_ticket.transited.contents.as_ref(),
            b"EDU,MIT.,ATHENA.,WASHINGTON.EDU,CS.",
        );
        assert_eq!(enc_ticket.auth_time.0.timestamp(), TEST_TIME_SECONDS);
        assert_eq!(
            enc_ticket
                .start_time
                .as_ref()
                .ok_or("start time")?
                .0
                .timestamp(),
            TEST_TIME_SECONDS,
        );
        assert_eq!(enc_ticket.end_time.0.timestamp(), TEST_TIME_SECONDS);
        assert_eq!(
            enc_ticket
                .renew_till
                .as_ref()
                .ok_or("renew till")?
                .0
                .timestamp(),
            TEST_TIME_SECONDS,
        );
        let addresses = enc_ticket.caddr.as_ref().ok_or("addresses")?;
        assert_eq!(addresses.len(), 2);
        let expected_address = hex::decode("12d00023")?;
        for address in addresses {
            assert_eq!(address.addr_type, 2_i32);
            assert_eq!(address.address.as_ref(), expected_address);
        }
        let auth_data = enc_ticket
            .authorization_data
            .as_ref()
            .ok_or("authorization data")?;
        assert_eq!(auth_data.len(), 2);
        for element in auth_data {
            assert_eq!(element.r#type, 1_i32);
            assert_eq!(element.data.as_ref(), b"foobar");
        }
        Ok(())
    }

    /// Pins that the gokrb5 `EncTicketPart` fixture without optional fields decodes.
    #[test]
    fn decodes_gokrb5_enc_ticket_part_optionals_null_fixture() -> Result<(), TestError> {
        let enc_ticket =
            decode_enc_ticket_part(&hex::decode(MARSHALLED_ENC_TICKET_PART_OPTIONALS_NULL)?)?;

        assert_eq!(ticket_flags_to_bits(&enc_ticket.flags), 0xfedc_ba98);
        assert_eq!(enc_ticket.key.r#type, 1_i32);
        assert_eq!(enc_ticket.key.value.as_ref(), b"12345678");
        assert_eq!(enc_ticket.crealm.as_bytes(), b"ATHENA.MIT.EDU");
        assert_eq!(enc_ticket.cname.r#type, 1_i32);
        assert_eq!(enc_ticket.auth_time.0.timestamp(), TEST_TIME_SECONDS);
        assert!(enc_ticket.start_time.is_none(), "start time is absent");
        assert_eq!(enc_ticket.end_time.0.timestamp(), TEST_TIME_SECONDS);
        assert!(enc_ticket.renew_till.is_none(), "renew till is absent");
        assert!(enc_ticket.caddr.is_none(), "addresses are absent");
        assert!(
            enc_ticket.authorization_data.is_none(),
            "authorization data is absent"
        );
        Ok(())
    }

    /// Pins that a ticket built with an explicit confounder decrypts back to its encrypted part.
    #[test]
    fn builds_and_decrypts_ticket_with_explicit_confounder() -> Result<(), TestError> {
        let fixture = decode_ticket(&hex::decode(MARSHALLED_TICKET)?)?;
        let enc_ticket = decode_enc_ticket_part(&hex::decode(MARSHALLED_ENC_TICKET_PART)?)?;
        let key = reply_key()?;
        let etype = KerberosEtype::from_etype_id(key.etype()).ok_or("AES256 etype")?;
        let confounder = vec![0x66; etype.confounder_len()];

        let ticket = build_ticket_with_confounder(
            fixture.realm.clone(),
            fixture.sname,
            &enc_ticket,
            &key,
            Some(3),
            &confounder,
        )?;

        assert_eq!(ticket.tkt_vno, Integer::from(KRB5_TKT_VNO));
        assert_eq!(ticket.enc_part.etype, key.etype());
        assert_eq!(ticket.enc_part.kvno, Some(3));
        let decrypted = decrypt_ticket_enc_part(&ticket, &key)?;
        assert_eq!(decrypted, enc_ticket);
        Ok(())
    }

    /// Pins that an encoded ticket built with an explicit confounder decodes and decrypts.
    #[test]
    fn encodes_built_ticket_with_explicit_confounder() -> Result<(), TestError> {
        let fixture = decode_ticket(&hex::decode(MARSHALLED_TICKET)?)?;
        let enc_ticket =
            decode_enc_ticket_part(&hex::decode(MARSHALLED_ENC_TICKET_PART_OPTIONALS_NULL)?)?;
        let key = reply_key()?;
        let etype = KerberosEtype::from_etype_id(key.etype()).ok_or("AES256 etype")?;
        let confounder = vec![0x77; etype.confounder_len()];

        let encoded = encode_build_ticket_with_confounder(
            fixture.realm,
            fixture.sname,
            &enc_ticket,
            &key,
            None,
            &confounder,
        )?;
        let decoded = decode_ticket(&encoded)?;

        assert_eq!(decoded.enc_part.etype, key.etype());
        assert!(decoded.enc_part.kvno.is_none(), "kvno is absent");
        let decrypted = decrypt_ticket_enc_part(&decoded, &key)?;
        assert_eq!(decrypted, enc_ticket);
        Ok(())
    }

    /// Pins that a ticket built with a random confounder decrypts back to its encrypted part.
    #[test]
    fn builds_and_decrypts_ticket_with_random_confounder() -> Result<(), TestError> {
        let fixture = decode_ticket(&hex::decode(MARSHALLED_TICKET)?)?;
        let enc_ticket = decode_enc_ticket_part(&hex::decode(MARSHALLED_ENC_TICKET_PART)?)?;
        let key = reply_key()?;

        let ticket = build_ticket(fixture.realm, fixture.sname, &enc_ticket, &key, None)?;

        let decrypted = decrypt_ticket_enc_part(&ticket, &key)?;
        assert_eq!(decrypted, enc_ticket);
        Ok(())
    }

    /// Pins that decrypting a ticket with a key of another etype is rejected.
    #[test]
    fn rejects_ticket_key_etype_mismatch() -> Result<(), TestError> {
        let fixture = decode_ticket(&hex::decode(MARSHALLED_TICKET)?)?;
        let enc_ticket = decode_enc_ticket_part(&hex::decode(MARSHALLED_ENC_TICKET_PART)?)?;
        let key = reply_key()?;
        let etype = KerberosEtype::from_etype_id(key.etype()).ok_or("AES256 etype")?;
        let confounder = vec![0x66; etype.confounder_len()];
        let ticket = build_ticket_with_confounder(
            fixture.realm,
            fixture.sname,
            &enc_ticket,
            &key,
            None,
            &confounder,
        )?;
        let wrong_key = EncryptionKey::new(17, vec![0; 16]);

        let error = decrypt_ticket_enc_part(&ticket, &wrong_key)
            .err()
            .ok_or("wrong etype key is rejected")?;

        assert!(
            matches!(
                error,
                Error::KeyEtypeMismatch {
                    key_etype: 17_i32,
                    encrypted_data_etype: 18_i32,
                }
            ),
            "{error:?}"
        );
        Ok(())
    }

    /// Pins the ticket encrypted-part key usage number.
    #[test]
    fn exposes_ticket_key_usage_constant() {
        assert_eq!(KDC_REP_TICKET_USAGE, 2);
    }

    /// Returns the AES256 key used to encrypt the ticket parts.
    fn reply_key() -> Result<EncryptionKey, TestError> {
        Ok(EncryptionKey::new(18, hex::decode(REPLY_KEY)?))
    }

    /// Returns the name components of a principal name as byte slices.
    fn principal_components(name: &PrincipalName) -> Vec<&[u8]> {
        name.string.iter().map(GeneralString::as_bytes).collect()
    }

    /// Returns the first 32 ticket flag bits as a big-endian integer; missing bytes read as zero.
    fn ticket_flags_to_bits(flags: &TicketFlags) -> u32 {
        let raw = flags.0.as_raw_slice();
        u32::from_be_bytes([
            raw.first().copied().unwrap_or_default(),
            raw.get(1).copied().unwrap_or_default(),
            raw.get(2).copied().unwrap_or_default(),
            raw.get(3).copied().unwrap_or_default(),
        ])
    }
}

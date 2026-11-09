//! KRB-PRIV tests: gokrb5 fixture round-trips and encrypted-part building and decryption.
#![cfg(feature = "messages")]

/// KRB-PRIV tests.
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
    use rasn::types::Integer;
    use rasn_kerberos::HostAddress;
    use rskrb5_ng::{
        crypto::KerberosEtype,
        keytab::EncryptionKey,
        krb_priv::{
            EncKrbPrivPartOptions, KRB_PRIV_MSG_TYPE, KRB_PRIV_PVNO, build as build_krb_priv,
            build_krb_priv_with_confounder, decode as decode_krb_priv, decode_enc_krb_priv_part,
            decrypt_krb_priv_enc_part, encode as encode_krb_priv, encode_enc_krb_priv_part,
            ipv4_host_address, ipv6_host_address,
        },
    };

    /// Error type of the `Result`-returning tests.
    type TestError = Box<dyn error::Error>;

    /// gokrb5 KRB-PRIV fixture.
    const MARSHALLED_KRB_PRIV: &str = concat!(
        "75333031A003020105A103020115A3253023A003020100A103020105A217",
        "04156B726241534E2E312074657374206D657373616765",
    );
    /// gokrb5 `EncKrbPrivPart` fixture with every optional field set.
    const MARSHALLED_ENC_KRB_PRIV_PART: &str = concat!(
        "7C4F304DA00A04086B72623564617461A111180F31393934303631303036",
        "303331375AA205020301E240A303020111A40F300DA003020102A10604",
        "0412D00023A50F300DA003020102A106040412D00023",
    );
    /// gokrb5 `EncKrbPrivPart` fixture without optional fields.
    const MARSHALLED_ENC_KRB_PRIV_PART_OPTIONALS_NULL: &str = concat!(
        "7C1F301DA00A04086B72623564617461A40F300DA003020102A10604",
        "0412D00023",
    );
    /// Timestamp of the gokrb5 fixtures, in seconds since the Unix epoch.
    const TEST_TIME_SECONDS: i64 = 771_228_197;

    /// Pins that the gokrb5 KRB-PRIV fixture decodes to the expected fields and re-encodes byte for byte.
    #[test]
    fn decodes_and_roundtrips_gokrb5_krb_priv_fixture() -> Result<(), TestError> {
        let bytes = hex::decode(MARSHALLED_KRB_PRIV)?;

        let krb_priv = decode_krb_priv(&bytes)?;

        assert_eq!(krb_priv.pvno, Integer::from(KRB_PRIV_PVNO));
        assert_eq!(krb_priv.msg_type, Integer::from(KRB_PRIV_MSG_TYPE));
        assert_eq!(krb_priv.enc_part.etype, 0_i32);
        assert_eq!(krb_priv.enc_part.kvno, Some(5));
        assert_eq!(krb_priv.enc_part.cipher.as_ref(), b"krbASN.1 test message");
        assert_eq!(encode_krb_priv(&krb_priv)?, bytes);
        Ok(())
    }

    /// Pins that the gokrb5 `EncKrbPrivPart` fixture decodes to the expected fields and re-encodes byte for byte.
    #[test]
    fn decodes_and_roundtrips_gokrb5_enc_krb_priv_part_fixture() -> Result<(), TestError> {
        let bytes = hex::decode(MARSHALLED_ENC_KRB_PRIV_PART)?;

        let enc_part = decode_enc_krb_priv_part(&bytes)?;

        assert_eq!(enc_part.user_data.as_ref(), b"krb5data");
        assert_eq!(
            enc_part
                .timestamp
                .as_ref()
                .ok_or("timestamp")?
                .0
                .timestamp(),
            TEST_TIME_SECONDS
        );
        assert_eq!(enc_part.usec, Some(Integer::from(123_456_i32)));
        assert_eq!(enc_part.seq_number, Some(17));
        assert_eq!(enc_part.sender_address.addr_type, HostAddress::IPV4);
        assert_eq!(
            enc_part.sender_address.address.as_ref(),
            hex::decode("12d00023")?
        );
        assert_eq!(
            enc_part
                .recipient_address
                .as_ref()
                .ok_or("recipient address")?
                .address
                .as_ref(),
            hex::decode("12d00023")?
        );
        assert_eq!(encode_enc_krb_priv_part(&enc_part)?, bytes);
        Ok(())
    }

    /// Pins that the gokrb5 `EncKrbPrivPart` fixture without optional fields decodes and re-encodes byte for byte.
    #[test]
    fn decodes_and_roundtrips_gokrb5_enc_krb_priv_part_optionals_null_fixture()
    -> Result<(), TestError> {
        let bytes = hex::decode(MARSHALLED_ENC_KRB_PRIV_PART_OPTIONALS_NULL)?;

        let enc_part = decode_enc_krb_priv_part(&bytes)?;

        assert_eq!(enc_part.user_data.as_ref(), b"krb5data");
        assert!(enc_part.timestamp.is_none(), "timestamp is absent");
        assert!(enc_part.usec.is_none(), "usec is absent");
        assert!(enc_part.seq_number.is_none(), "sequence number is absent");
        assert_eq!(enc_part.sender_address.addr_type, HostAddress::IPV4);
        assert_eq!(
            enc_part.sender_address.address.as_ref(),
            hex::decode("12d00023")?
        );
        assert!(
            enc_part.recipient_address.is_none(),
            "recipient address is absent"
        );
        assert_eq!(encode_enc_krb_priv_part(&enc_part)?, bytes);
        Ok(())
    }

    /// Pins that a KRB-PRIV built with an explicit confounder decrypts back to its user data and addresses.
    #[test]
    fn builds_and_decrypts_krb_priv_with_explicit_confounder() -> Result<(), TestError> {
        let key = EncryptionKey::new(18, vec![0x11; 32]);
        let sender_address = ipv4_host_address([127, 0, 0, 1]);
        let recipient_address = ipv6_host_address([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let options = EncKrbPrivPartOptions::new(sender_address.clone())
            .with_sequence_number(7)
            .with_recipient_address(recipient_address.clone());
        let etype = KerberosEtype::from_etype_id(key.etype()).ok_or("AES256 etype")?;
        let confounder = vec![0x22; etype.confounder_len()];

        let krb_priv =
            build_krb_priv_with_confounder(b"krb5data", options, &key, Some(3), &confounder)?;

        assert_eq!(krb_priv.pvno, Integer::from(KRB_PRIV_PVNO));
        assert_eq!(krb_priv.msg_type, Integer::from(KRB_PRIV_MSG_TYPE));
        assert_eq!(krb_priv.enc_part.etype, key.etype());
        assert_eq!(krb_priv.enc_part.kvno, Some(3));

        let enc_part = decrypt_krb_priv_enc_part(&krb_priv, &key)?;

        assert_eq!(enc_part.user_data.as_ref(), b"krb5data");
        assert_eq!(enc_part.sender_address, sender_address);
        assert_eq!(enc_part.recipient_address, Some(recipient_address));
        assert_eq!(enc_part.seq_number, Some(7));
        Ok(())
    }

    /// Pins that a KRB-PRIV built with a random confounder decrypts back to its user data.
    #[test]
    fn builds_and_decrypts_krb_priv_with_random_confounder() -> Result<(), TestError> {
        let key = EncryptionKey::new(18, vec![0x11; 32]);
        let options = EncKrbPrivPartOptions::new(ipv4_host_address([127, 0, 0, 1]));

        let krb_priv = build_krb_priv(b"krb5data", options, &key, None)?;
        let enc_part = decrypt_krb_priv_enc_part(&krb_priv, &key)?;

        assert_eq!(enc_part.user_data.as_ref(), b"krb5data");
        Ok(())
    }
}

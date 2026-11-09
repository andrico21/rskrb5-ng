//! Enctype-aware AP-REP and KRB-CRED DER padding boundaries.
#![cfg(feature = "messages")]

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error::Error;

    use rasn::der;
    use rskrb5_ng::{ap_rep, crypto::KerberosEtype, keytab::EncryptionKey, krb_cred};

    /// Every supported enctype handles all eight plaintext-length residues.
    #[test]
    fn encrypted_parts_roundtrip_all_padding_residues() -> Result<(), Box<dyn Error>> {
        // Given AP-REP and KRB-CRED parts with variable-length key values.
        let utc = chrono::DateTime::from_timestamp(1, 0).ok_or("time")?;
        let offset = chrono::FixedOffset::east_opt(0).ok_or("offset")?;
        for id in [16_i32, 17_i32, 18_i32, 19_i32, 20_i32, 23_i32] {
            let etype = KerberosEtype::from_etype_id(id).ok_or("etype")?;
            let key = EncryptionKey::new(id, vec![0x42; etype.key_len()]);
            let confounder = vec![0x24; etype.confounder_len()];
            let mut residues = [false; 8];
            let mut cred_residues = [false; 8];
            for length in 1..=8 {
                let part = rasn_kerberos::EncApRepPart {
                    ctime: rasn_kerberos::KerberosTime(utc.with_timezone(&offset)),
                    cusec: 0_i32.into(),
                    subkey: Some(rasn_kerberos::EncryptionKey {
                        r#type: 17,
                        value: vec![0x33; length].into(),
                    }),
                    seq_number: None,
                };
                let bytes = der::encode(&part)?;
                *residues
                    .get_mut(bytes.len().rem_euclid(8))
                    .ok_or("residue")? = true;
                let cred_part = rasn_kerberos::EncKrbCredPart {
                    ticket_info: vec![rasn_kerberos::KrbCredInfo {
                        key: part.subkey.clone().ok_or("subkey")?,
                        prealm: None,
                        pname: None,
                        flags: None,
                        auth_time: None,
                        start_time: None,
                        end_time: None,
                        renew_till: None,
                        srealm: None,
                        sname: None,
                        caddr: None,
                    }],
                    nonce: None,
                    timestamp: None,
                    usec: None,
                    sender_address: None,
                    recipient_address: None,
                };
                let cred_der = der::encode(&cred_part)?;
                *cred_residues
                    .get_mut(cred_der.len().rem_euclid(8))
                    .ok_or("credential residue")? = true;
                // When encrypted parts are built and passed through real decrypt decoders.
                let reply = ap_rep::build_ap_rep_with_confounder(&part, &key, None, &confounder)?;
                assert_eq!(ap_rep::decrypt_ap_rep_enc_part(&reply, &key)?, part);
                let cred = rasn_kerberos::KrbCred {
                    pvno: 5_i32.into(),
                    msg_type: 22_i32.into(),
                    tickets: Vec::new(),
                    enc_part: rasn_kerberos::EncryptedData {
                        etype: id,
                        kvno: None,
                        cipher: etype
                            .encrypt_message_with_confounder(
                                key.value(),
                                &der::encode(&cred_part)?,
                                14,
                                &confounder,
                            )?
                            .into(),
                    },
                };
                // Then both decoded values preserve their exact fields.
                assert_eq!(krb_cred::decrypt_krb_cred_enc_part(&cred, &key)?, cred_part);
            }
            assert_eq!(residues, [true; 8]);
            assert_eq!(cred_residues, [true; 8]);
        }
        Ok(())
    }

    /// Authenticated excessive or nonzero suffixes are never accepted as padding.
    #[test]
    fn encrypted_parts_reject_invalid_padding() -> Result<(), Box<dyn Error>> {
        // Given a minimal valid AP-REP part with authenticated suffixes.
        let bytes = hex::decode("7B1C301AA011180F31393934303631303036303331375AA105020301E240")?;
        for id in [16_i32, 17_i32, 18_i32, 19_i32, 20_i32, 23_i32] {
            let etype = KerberosEtype::from_etype_id(id).ok_or("etype")?;
            let key = EncryptionKey::new(id, vec![0x42; etype.key_len()]);
            for suffix in [vec![1], vec![0; 8]] {
                let mut plaintext = bytes.clone();
                plaintext.extend(suffix);
                let reply = rasn_kerberos::ApRep {
                    pvno: 5_i32.into(),
                    msg_type: 15_i32.into(),
                    enc_part: rasn_kerberos::EncryptedData {
                        etype: id,
                        kvno: None,
                        cipher: etype
                            .encrypt_message_with_confounder(
                                key.value(),
                                &plaintext,
                                12,
                                &vec![0x24; etype.confounder_len()],
                            )?
                            .into(),
                    },
                };
                // When an authenticated but invalid suffix reaches the decoder.
                let result = ap_rep::decrypt_ap_rep_enc_part(&reply, &key);
                // Then complete DER decoding rejects it.
                assert!(result.is_err(), "invalid padding accepted for {id}");
            }
        }
        Ok(())
    }
}

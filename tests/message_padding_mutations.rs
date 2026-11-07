//! Authenticated padding and credential-import boundary tests.
#![cfg(feature = "messages")]

/// Padding and import tests using real encryption and RFC 4120 values.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error::Error;

    use rasn::{der, types::Integer};
    use rasn_kerberos::{
        EncKrbCredPart, EncryptedData, KerberosString, KrbCred, KrbCredInfo, PrincipalName,
    };
    use rskrb5_ng::{
        ap_rep,
        crypto::{CryptoPolicy, KerberosEtype},
        error::{ApRep as ApRepError, KrbCred as CredError},
        keytab::EncryptionKey,
        krb_cred,
    };

    /// A valid RFC 4120 section 5.3 ticket with an opaque AES ciphertext.
    fn ticket_value() -> Result<rasn_kerberos::Ticket, Box<dyn Error>> {
        Ok(rasn_kerberos::Ticket {
            tkt_vno: Integer::from(5_i32),
            realm: KerberosString::from_bytes(b"TICKET.EXAMPLE")?,
            sname: PrincipalName {
                r#type: 2_i32,
                string: vec![KerberosString::from_bytes(b"ticket-service")?],
            },
            enc_part: EncryptedData {
                etype: 18_i32,
                kvno: None,
                cipher: vec![1_u8].into(),
            },
        })
    }

    /// Credential info whose server differs from the outer ticket fallback.
    fn credential_part() -> Result<EncKrbCredPart, Box<dyn Error>> {
        Ok(EncKrbCredPart {
            ticket_info: vec![KrbCredInfo {
                key: rasn_kerberos::EncryptionKey {
                    r#type: 18_i32,
                    value: vec![0x22_u8; 32].into(),
                },
                prealm: Some(KerberosString::from_bytes(b"CLIENT.EXAMPLE")?),
                pname: Some(PrincipalName {
                    r#type: 1_i32,
                    string: vec![KerberosString::from_bytes(b"alice")?],
                }),
                flags: None,
                auth_time: None,
                start_time: None,
                end_time: None,
                renew_till: None,
                srealm: Some(KerberosString::from_bytes(b"INFO.EXAMPLE")?),
                sname: Some(PrincipalName {
                    r#type: 2_i32,
                    string: vec![KerberosString::from_bytes(b"info-service")?],
                }),
                caddr: None,
            }],
            nonce: None,
            timestamp: None,
            usec: None,
            sender_address: None,
            recipient_address: None,
        })
    }

    /// KRB-CRED wrapping the supplied authenticated plaintext.
    fn encrypted_credential(
        plaintext: &[u8],
        key: &EncryptionKey,
    ) -> Result<KrbCred, Box<dyn Error>> {
        let etype = KerberosEtype::from_etype_id(key.etype).ok_or("enctype")?;
        let cipher = etype.encrypt_message_with_confounder(
            &key.value,
            plaintext,
            14,
            &vec![0_u8; etype.confounder_len()],
        )?;
        Ok(KrbCred {
            pvno: Integer::from(5_i32),
            msg_type: Integer::from(22_i32),
            tickets: vec![ticket_value()?],
            enc_part: EncryptedData {
                etype: key.etype,
                kvno: None,
                cipher: cipher.into(),
            },
        })
    }

    /// The optional server principal overrides the ticket, but absence uses the ticket.
    #[test]
    fn credential_server_uses_info_or_ticket_fallback() -> Result<(), Box<dyn Error>> {
        for present in [true, false] {
            let mut part = credential_part()?;
            if !present {
                let info = part.ticket_info.first_mut().ok_or("info")?;
                info.srealm = None;
                info.sname = None;
            }
            let key = EncryptionKey::new(18, vec![0x11; 32]);
            let credential = encrypted_credential(&der::encode(&part)?, &key)?;
            let imported = krb_cred::decrypted_krb_cred_to_ccache_credentials(&credential, &part)?;
            let server = &imported.first().ok_or("credential")?.server;
            let (realm, name) = if present {
                ("INFO.EXAMPLE", "info-service")
            } else {
                ("TICKET.EXAMPLE", "ticket-service")
            };
            assert_eq!(server.realm, realm);
            assert_eq!(server.components, [name]);
        }
        Ok(())
    }

    /// Policy-checked decode/decrypt returns the authenticated credential rather than an empty success.
    #[test]
    fn checked_import_delivers_authenticated_credential() -> Result<(), Box<dyn Error>> {
        let part = credential_part()?;
        let key = EncryptionKey::new(18, vec![0x11; 32]);
        let credential = encrypted_credential(&der::encode(&part)?, &key)?;
        let imported = krb_cred::import::decode_decrypt(
            &CryptoPolicy::default(),
            &der::encode(&credential)?,
            &key,
        )?;
        let [only] = imported.as_slice() else {
            return Err("one imported credential".into());
        };
        assert_eq!(only.client.components, ["alice"]);
        assert_eq!(only.key.value, vec![0x22_u8; 32]);
        Ok(())
    }

    /// AES authenticated trailing zero octets are not DES3 block padding.
    #[test]
    fn aes_credential_rejects_authenticated_zero_suffix() -> Result<(), Box<dyn Error>> {
        let mut plaintext = der::encode(&credential_part()?)?;
        plaintext.push(0);
        let key = EncryptionKey::new(18, vec![0x11; 32]);
        let credential = encrypted_credential(&plaintext, &key)?;
        assert!(matches!(
            krb_cred::decrypt_krb_cred_enc_part(&credential, &key),
            Err(CredError::Decode {
                target: _,
                message: _
            })
        ));
        Ok(())
    }

    /// A complete extra DES3 block is not permitted padding on an AP reply.
    #[test]
    fn des3_ap_reply_rejects_complete_padding_block() -> Result<(), Box<dyn Error>> {
        let mut part = ap_rep::decode_enc_ap_rep_part(&hex::decode(
            "7B1C301AA011180F31393934303631303036303331375AA105020301E240",
        )?)?;
        part.cusec = Integer::from(0x8000_0000_i64);
        let mut plaintext = der::encode(&part)?;
        assert_eq!(plaintext.len(), 32);
        plaintext.extend_from_slice(&[0_u8; 8]);
        let key = EncryptionKey::new(
            16,
            hex::decode("dce06b1f64c857a11c3db57c51899b2cc1791008ce973b92")?,
        );
        let etype = KerberosEtype::from_etype_id(16).ok_or("DES3")?;
        let cipher =
            etype.encrypt_message_with_confounder(&key.value, &plaintext, 12, &[0_u8; 8])?;
        let reply = rasn_kerberos::ApRep {
            pvno: Integer::from(5_i32),
            msg_type: Integer::from(15_i32),
            enc_part: EncryptedData {
                etype: 16_i32,
                kvno: None,
                cipher: cipher.into(),
            },
        };
        assert!(matches!(
            ap_rep::decrypt_ap_rep_enc_part(&reply, &key),
            Err(ApRepError::Decode {
                target: _,
                message: _
            })
        ));
        Ok(())
    }

    /// KRB-CRED also rejects exactly one surplus authenticated DES3 block.
    #[test]
    fn des3_credential_rejects_complete_padding_block() -> Result<(), Box<dyn Error>> {
        let mut part = credential_part()?;
        part.ticket_info.first_mut().ok_or("info")?.key.value = vec![0x22_u8; 35].into();
        let mut plaintext = der::encode(&part)?;
        assert_eq!(plaintext.len(), plaintext.len().next_multiple_of(8));
        plaintext.extend_from_slice(&[0_u8; 8]);
        let key = EncryptionKey::new(
            16,
            hex::decode("dce06b1f64c857a11c3db57c51899b2cc1791008ce973b92")?,
        );
        let credential = encrypted_credential(&plaintext, &key)?;
        assert!(matches!(
            krb_cred::decrypt_krb_cred_enc_part(&credential, &key),
            Err(CredError::Decode {
                target: _,
                message: _
            })
        ));
        Ok(())
    }
}

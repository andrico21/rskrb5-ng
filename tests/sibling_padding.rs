//! Authenticated padding admission at the four sibling message boundaries.
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
    use rasn_kerberos::{
        Authenticator, EncAsRepPart, EncKdcRepPart, EncKrbPrivPart, EncTicketPart, EncryptedData,
        KerberosFlags, KerberosString, KerberosTime, PrincipalName, TicketFlags,
    };
    use rskrb5_ng::{
        ap_req, crypto::KerberosEtype, kdc_rep, keytab::EncryptionKey, krb_priv, ticket,
    };

    /// Encrypt independently, preserving the deliberately malformed authenticated suffix.
    fn seal<T>(
        part: &T,
        key: &EncryptionKey,
        usage: u32,
        suffix: &[u8],
    ) -> Result<EncryptedData, Box<dyn Error>>
    where
        T: rasn::Encode,
    {
        let etype = KerberosEtype::from_etype_id(key.etype).ok_or("etype")?;
        let mut bytes = der::encode(part)?;
        bytes.extend_from_slice(suffix);
        Ok(EncryptedData {
            etype: key.etype,
            kvno: None,
            cipher: etype
                .encrypt_message_with_confounder(
                    &key.value,
                    &bytes,
                    usage,
                    &vec![0x24; etype.confounder_len()],
                )?
                .into(),
        })
    }

    /// Exact values and short DES3 padding pass; AES/RC4 suffixes and surplus DES3 blocks fail.
    #[test]
    fn sibling_decryptors_enforce_enctype_padding() -> Result<(), Box<dyn Error>> {
        for id in [16_i32, 17_i32, 18_i32, 19_i32, 20_i32, 23_i32] {
            for length in 1..=8 {
                check_parts(id, length)?;
            }
        }
        Ok(())
    }

    /// Exercise each complete-message decoder with independently encrypted parts.
    fn check_parts(id: i32, length: usize) -> Result<(), Box<dyn Error>> {
        let realm = KerberosString::from_bytes(b"EXAMPLE.TEST")?;
        let name = PrincipalName {
            r#type: 1,
            string: vec![KerberosString::from_bytes(b"alice")?],
        };
        let time = KerberosTime(
            chrono::DateTime::from_timestamp(1, 0)
                .ok_or("time")?
                .fixed_offset(),
        );
        let etype = KerberosEtype::from_etype_id(id).ok_or("etype")?;
        let key = EncryptionKey::new(id, vec![0x42; etype.key_len()]);
        let inner_key = rasn_kerberos::EncryptionKey {
            r#type: 17,
            value: vec![0x33; length].into(),
        };
        let auth = Authenticator {
            authenticator_vno: 5_i32.into(),
            crealm: realm.clone(),
            cname: name.clone(),
            cksum: None,
            cusec: 0_i32.into(),
            ctime: time.clone(),
            subkey: Some(inner_key.clone()),
            seq_number: None,
            authorization_data: None,
        };
        let ticket_part = EncTicketPart {
            flags: TicketFlags(KerberosFlags::from_slice(&[0; 4])),
            key: inner_key.clone(),
            crealm: realm.clone(),
            cname: name.clone(),
            transited: rasn_kerberos::TransitedEncoding {
                r#type: 0_i32,
                contents: Vec::new().into(),
            },
            auth_time: time.clone(),
            start_time: None,
            end_time: time.clone(),
            renew_till: None,
            caddr: None,
            authorization_data: None,
        };
        let reply_part = EncAsRepPart(EncKdcRepPart {
            key: inner_key,
            last_req: Vec::new(),
            nonce: 42,
            key_expiration: None,
            flags: TicketFlags(KerberosFlags::from_slice(&[0; 4])),
            auth_time: time.clone(),
            start_time: None,
            end_time: time,
            renew_till: None,
            srealm: realm.clone(),
            sname: name.clone(),
            caddr: None,
            encrypted_pa_data: None,
        });
        let private_part = private_part(length);
        for suffix in [Vec::new(), vec![0; if id == 16 { 8 } else { 1 }]] {
            let valid = suffix.is_empty();
            let ticket = rasn_kerberos::Ticket {
                tkt_vno: 5_i32.into(),
                realm: realm.clone(),
                sname: name.clone(),
                enc_part: seal(&ticket_part, &key, 2, &suffix)?,
            };
            let ap = rasn_kerberos::ApReq {
                pvno: 5_i32.into(),
                msg_type: 14_i32.into(),
                ap_options: ap_req::ap_options_from_bits(0),
                ticket: ticket.clone(),
                authenticator: seal(&auth, &key, 11, &suffix)?,
            };
            let reply = rasn_kerberos::AsRep(rasn_kerberos::KdcRep {
                pvno: 5_i32.into(),
                msg_type: 11_i32.into(),
                padata: None,
                crealm: realm.clone(),
                cname: name.clone(),
                ticket: ticket.clone(),
                enc_part: seal(&reply_part, &key, 3, &suffix)?,
            });
            let private = rasn_kerberos::KrbPriv {
                pvno: 5_i32.into(),
                msg_type: 21_i32.into(),
                enc_part: seal(&private_part, &key, 13, &suffix)?,
            };
            let results = [
                ticket::decrypt_ticket_enc_part(&ticket, &key).is_ok(),
                ap_req::decrypt_ap_req_authenticator(&ap, &key, 11).is_ok(),
                kdc_rep::decrypt_as_rep_enc_part(&reply, &key).is_ok(),
                krb_priv::decrypt_krb_priv_enc_part(&private, &key).is_ok(),
            ];
            assert_eq!(results, [valid; 4], "enctype {id}, length {length}");
        }
        Ok(())
    }

    /// Variable-length private payload for all DES3 padding residues.
    fn private_part(length: usize) -> EncKrbPrivPart {
        EncKrbPrivPart {
            user_data: vec![0x33; length].into(),
            timestamp: None,
            usec: None,
            seq_number: None,
            sender_address: rasn_kerberos::HostAddress {
                addr_type: 2,
                address: vec![127, 0, 0, 1].into(),
            },
            recipient_address: None,
        }
    }
}

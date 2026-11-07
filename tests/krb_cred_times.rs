//! Semantic KRB-CRED credential timestamp boundaries.
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
    use rskrb5_ng::{ccache, krb_cred};

    /// Each imported credential time rejects a fractional Kerberos timestamp.
    #[test]
    fn import_rejects_fractional_credential_times() -> Result<(), Box<dyn Error>> {
        // Given a valid credential with all four time fields.
        let principal = ccache::Principal::new("EXAMPLE.COM", 1, vec!["user".into()]);
        let ticket = rasn_kerberos::Ticket {
            tkt_vno: 5_i32.into(),
            realm: rasn_kerberos::Realm::from_bytes(b"EXAMPLE.COM")?,
            sname: rasn_kerberos::PrincipalName {
                r#type: 1,
                string: vec![rasn_kerberos::KerberosString::from_bytes(b"user")?],
            },
            enc_part: rasn_kerberos::EncryptedData {
                etype: 17,
                kvno: None,
                cipher: vec![0x42].into(),
            },
        };
        let credential = ccache::Credential::new(
            principal.clone(),
            principal,
            ccache::EncryptionKey::new(17, vec![0x42; 16]),
            ccache::CredentialTimes::default(),
            [0; 4],
            der::encode(&ticket)?.into(),
        );
        let (tickets, part) = krb_cred::ccache_credentials_to_krb_cred_parts(&[credential])?;
        let message = rasn_kerberos::KrbCred {
            pvno: 5_i32.into(),
            msg_type: 22_i32.into(),
            tickets,
            enc_part: rasn_kerberos::EncryptedData {
                etype: 17,
                kvno: None,
                cipher: Vec::new().into(),
            },
        };
        for field in 0_usize..4 {
            let mut mutated = part.clone();
            let info = mutated.ticket_info.first_mut().ok_or("ticket info")?;
            let time = match field {
                0 => &mut info.auth_time,
                1 => &mut info.start_time,
                2 => &mut info.end_time,
                _ => &mut info.renew_till,
            };
            time.as_mut().ok_or("time")?.0 += chrono::Duration::nanoseconds(1);
            // When the semantic import crosses the ccache timestamp boundary.
            let result = krb_cred::decrypted_krb_cred_to_ccache_credentials(&message, &mutated);
            // Then a fractional value is rejected rather than truncated.
            assert!(
                result.is_err(),
                "fractional credential field {field} accepted"
            );
        }
        Ok(())
    }
}

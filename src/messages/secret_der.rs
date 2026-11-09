//! Owning boundary for secret-bearing message DER staging.

use core::ops::Deref;

use zeroize::{Zeroize as _, Zeroizing};

/// Secret DER allocation erased before release on every ordinary exit path.
pub(crate) struct SecretDer {
    /// Secret bytes, including any spare allocation capacity.
    bytes: Zeroizing<Vec<u8>>,
    /// Purpose used to distinguish owners in test observations.
    purpose: &'static str,
}

impl SecretDer {
    /// Adopt an encoded or authenticated-decrypted allocation without copying.
    pub(crate) fn new(bytes: Vec<u8>, purpose: &'static str) -> Self {
        Self {
            bytes: Zeroizing::new(bytes),
            purpose,
        }
    }
}

impl Deref for SecretDer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

// Drop audit: erasure is synchronous and allocation-free in production.
impl Drop for SecretDer {
    fn drop(&mut self) {
        let Self { bytes, purpose } = self;
        let _: &mut &'static str = purpose;
        bytes.as_mut_slice().zeroize();
        #[cfg(test)]
        {
            assert!(bytes.iter().all(|byte| *byte == 0), "DER erasure failed");
            tests::ERASED.with_borrow_mut(|events| events.push((*purpose, bytes.len())));
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    /// KDC reply encoder ownership regressions.
    mod kdc;
    use core::{cell::RefCell, error::Error};

    use rasn::der;

    use crate::{
        ap_rep, ap_req, crypto::KerberosEtype, kdc_rep, keytab::EncryptionKey, krb_cred, ticket,
    };

    std::thread_local! {
        /// Owner-labelled erasure events isolated from parallel test threads.
        pub(super) static ERASED: RefCell<Vec<(&'static str, usize)>> = const { RefCell::new(Vec::new()) };
    }

    /// AP-REP encoding scratch is erased on encryption success and failure.
    #[test]
    fn ap_rep_encode_owner_erased_on_each_exit() -> Result<(), Box<dyn Error>> {
        // Given a marker subkey and either a valid or invalid confounder.
        let part: rasn_kerberos::EncApRepPart = der::decode(&hex::decode(
            "7B363034A011180F31393934303631303036303331375AA105020301E240A2133011A003020101A10A04083132333435363738A303020111",
        )?)?;
        let key = EncryptionKey::new(17, vec![0x42; 16]);
        let length = der::encode(&part)?.len();
        for confounder in [vec![0x24; 16], Vec::new()] {
            ERASED.with_borrow_mut(Vec::clear);
            // When the real builder consumes its internal encoded staging.
            let result = ap_rep::build_ap_rep_with_confounder(&part, &key, None, &confounder);
            // Then exactly the encoder owner was erased regardless of the result.
            assert_eq!(result.is_ok(), confounder.len() == 16);
            ERASED.with_borrow(|events| assert_eq!(events.as_slice(), [("ap-rep encode", length)]));
            if let Ok(message) = result {
                ERASED.with_borrow_mut(Vec::clear);
                assert_eq!(ap_rep::decrypt_ap_rep_enc_part(&message, &key)?, part);
                ERASED.with_borrow(|events| {
                    assert_eq!(events.as_slice(), [("ap-rep decrypt", length)]);
                });
            }
        }
        Ok(())
    }

    /// KRB-CRED encoding and successful decryption each erase their own staging.
    #[test]
    fn credential_owners_erased_on_each_exit() -> Result<(), Box<dyn Error>> {
        // Given an empty credential envelope and valid or invalid encryption input.
        let key = EncryptionKey::new(17, vec![0x42; 16]);
        for confounder in [vec![0x24; 16], Vec::new()] {
            ERASED.with_borrow_mut(Vec::clear);
            // When the real export API encodes and attempts encryption.
            let result = krb_cred::encrypt_ccache_credentials_to_krb_cred_with_confounder(
                &[],
                &key,
                &confounder,
            );
            // Then the exact encode owner is observed even on encryption failure.
            assert_eq!(result.is_ok(), confounder.len() == 16);
            ERASED.with_borrow(|events| assert_eq!(events.as_slice(), [("krb-cred encode", 8)]));
            if let Ok(message) = result {
                ERASED.with_borrow_mut(Vec::clear);
                let part = krb_cred::decrypt_krb_cred_enc_part(&message, &key)?;
                assert!(part.ticket_info.is_empty(), "empty envelope");
                ERASED
                    .with_borrow(|events| assert_eq!(events.as_slice(), [("krb-cred decrypt", 8)]));
            }
        }
        Ok(())
    }

    /// Ticket encoding and decoding retain separate erasure observations.
    #[test]
    fn ticket_owners_erased_on_each_exit() -> Result<(), Box<dyn Error>> {
        // Given a marker-bearing ticket part and explicit confounder choices.
        let part: rasn_kerberos::EncTicketPart = der::decode(&hex::decode(concat!(
            "6381A53081A2A007030500FEDCBA98A1133011A003020101A10A04083132333435363738",
            "A2101B0E415448454E412E4D49542E454455A31A3018A003020101A111300F1B066866",
            "747361691B056578747261A42E302CA003020101A12504234544552C4D49542E2C4154",
            "48454E412E2C57415348494E47544F4E2E4544552C43532EA511180F313939343036",
            "31303036303331375AA711180F31393934303631303036303331375A"
        ))?)?;
        let key = EncryptionKey::new(17, vec![0x42; 16]);
        let length = der::encode(&part)?.len();
        for confounder in [vec![0x24; 16], Vec::new()] {
            ERASED.with_borrow_mut(Vec::clear);
            // When the real ticket builder seals its encoded part.
            let result = ticket::build_ticket_with_confounder(
                part.crealm.clone(),
                part.cname.clone(),
                &part,
                &key,
                None,
                &confounder,
            );
            // Then both successful and failing encryption erase the encode owner.
            assert_eq!(result.is_ok(), confounder.len() == 16);
            ERASED.with_borrow(|events| assert_eq!(events.as_slice(), [("ticket encode", length)]));
            if let Ok(message) = result {
                ERASED.with_borrow_mut(Vec::clear);
                assert_eq!(ticket::decrypt_ticket_enc_part(&message, &key)?, part);
                ERASED.with_borrow(|events| {
                    assert_eq!(events.as_slice(), [("ticket decrypt", length)]);
                });
            }
        }
        Ok(())
    }

    /// Authenticator staging is erased on both encryption outcomes.
    #[test]
    fn authenticator_encode_erased_on_each_exit() -> Result<(), Box<dyn Error>> {
        // Given a marker-bearing authenticator fixture.
        let part: rasn_kerberos::Authenticator = der::decode(&hex::decode(concat!(
            "6281A130819EA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003",
            "020101A111300F1B066866747361691B056578747261A30F300DA003020101A1060404",
            "31323334A405020301E240A511180F31393934303631303036303331375AA6133011",
            "A003020101A10A04083132333435363738A703020111A8243022300FA003020101A108",
            "0406666F6F626172300FA003020101A1080406666F6F626172"
        ))?)?;
        let ticket = rasn_kerberos::Ticket {
            tkt_vno: 5_i32.into(),
            realm: part.crealm.clone(),
            sname: part.cname.clone(),
            enc_part: rasn_kerberos::EncryptedData {
                etype: 17,
                kvno: None,
                cipher: Vec::new().into(),
            },
        };
        let key = EncryptionKey::new(17, vec![0x42; 16]);
        let length = der::encode(&part)?.len();
        for confounder in [vec![0x24; 16], Vec::new()] {
            ERASED.with_borrow_mut(Vec::clear);
            // When the real authenticator builder attempts encryption.
            let result = ap_req::build_ap_req_with_confounder(
                ticket.clone(),
                ap_req::ap_options_from_bits(0),
                &part,
                &key,
                11,
                None,
                &confounder,
            );
            // Then exactly the encoder owner is erased on either outcome.
            assert_eq!(result.is_ok(), confounder.len() == 16);
            ERASED.with_borrow(|events| assert_eq!(events.as_slice(), [("ap-req encode", length)]));
            if let Ok(message) = result {
                ERASED.with_borrow_mut(Vec::clear);
                assert_eq!(
                    ap_req::decrypt_ap_req_authenticator(&message, &key, 11)?,
                    part
                );
                ERASED.with_borrow(|events| {
                    assert_eq!(events.as_slice(), [("ap-req decrypt", length)]);
                });
            }
        }
        Ok(())
    }

    /// Authenticated malformed DER still erases each family's decrypted allocation.
    #[test]
    fn malformed_der_erases_every_decrypt_owner() -> Result<(), Box<dyn Error>> {
        drop(super::SecretDer::new(vec![0x42], "observer control"));
        // Given malformed DER authenticated with a real AES key and each key usage.
        let key = EncryptionKey::new(17, vec![0x42; 16]);
        let etype = KerberosEtype::from_etype_id(17).ok_or("etype")?;
        for (purpose, usage) in [
            ("ap-rep decrypt", 12),
            ("ap-req decrypt", 11),
            ("kdc-rep decrypt", 3),
            ("krb-cred decrypt", 14),
            ("ticket decrypt", 2),
        ] {
            let encrypted = rasn_kerberos::EncryptedData {
                etype: 17,
                kvno: None,
                cipher: etype
                    .encrypt_message_with_confounder(
                        key.value(),
                        &[0xff, 0x55],
                        usage,
                        &[0x24; 16],
                    )?
                    .into(),
            };
            let ticket = rasn_kerberos::Ticket {
                tkt_vno: 5_i32.into(),
                realm: rasn_kerberos::Realm::from_bytes(b"EXAMPLE.COM")?,
                sname: rasn_kerberos::PrincipalName {
                    r#type: 1,
                    string: vec![rasn_kerberos::KerberosString::from_bytes(b"user")?],
                },
                enc_part: encrypted.clone(),
            };
            ERASED.with_borrow_mut(Vec::clear);
            // When the real decoder fails after successful authentication.
            let rejected = match usage {
                12 => ap_rep::decrypt_ap_rep_enc_part(
                    &rasn_kerberos::ApRep {
                        pvno: 5_i32.into(),
                        msg_type: 15_i32.into(),
                        enc_part: encrypted,
                    },
                    &key,
                )
                .is_err(),
                11 => ap_req::decrypt_ap_req_authenticator(
                    &rasn_kerberos::ApReq {
                        pvno: 5_i32.into(),
                        msg_type: 14_i32.into(),
                        ticket,
                        ap_options: ap_req::ap_options_from_bits(0),
                        authenticator: encrypted,
                    },
                    &key,
                    11,
                )
                .is_err(),
                3 => kdc_rep::decrypt_as_rep_enc_part(
                    &rasn_kerberos::AsRep(rasn_kerberos::KdcRep {
                        pvno: 5_i32.into(),
                        msg_type: 11_i32.into(),
                        padata: None,
                        crealm: ticket.realm.clone(),
                        cname: ticket.sname.clone(),
                        ticket,
                        enc_part: encrypted,
                    }),
                    &key,
                )
                .is_err(),
                14 => krb_cred::decrypt_krb_cred_enc_part(
                    &rasn_kerberos::KrbCred {
                        pvno: 5_i32.into(),
                        msg_type: 22_i32.into(),
                        tickets: vec![ticket],
                        enc_part: encrypted,
                    },
                    &key,
                )
                .is_err(),
                _ => ticket::decrypt_ticket_enc_part(&ticket, &key).is_err(),
            };
            // Then exactly this message-layer owner is observed erased.
            assert!(rejected, "malformed DER accepted");
            ERASED.with_borrow(|events| assert_eq!(events.as_slice(), [(purpose, 2)]));
        }
        Ok(())
    }
}

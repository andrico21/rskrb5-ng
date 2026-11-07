//! RFC 4120 message header and encoded-builder boundary contracts.
#![cfg(feature = "messages")]

/// Message boundary tests over RFC 4120 section 5 ASN.1 values.
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
    use rasn_kerberos::{AsRep, AsReq, EncryptedData, KdcRep, KdcReq, TgsRep, TgsReq};
    use rskrb5_ng::{
        ap_rep, ap_req,
        error::{
            ApRep as ApRepError, ApReq as ApReqError, KdcRep as KdcRepError, KdcReq as KdcReqError,
            KrbCred as CredError, KrbPriv as PrivError, KrbSafe as SafeError,
        },
        kdc_rep, kdc_req,
        keytab::EncryptionKey,
        krb_cred, krb_priv, krb_safe, ticket,
    };

    /// RFC 4120 section 5.3 Ticket with the existing gokrb5 interoperability values.
    fn ticket_value() -> Result<rasn_kerberos::Ticket, Box<dyn Error>> {
        Ok(ticket::decode(&hex::decode(concat!(
            "615C305AA003020105A1101B0E415448454E412E4D49542E454455A21A",
            "3018A003020101A111300F1B066866747361691B056578747261A32530",
            "23A003020100A103020105A21704156B726241534E2E31207465737420",
            "6D657373616765"
        ))?)?)
    }

    /// RFC 4120 section 5.2.9 opaque encrypted data, without a key version.
    fn encrypted_data() -> EncryptedData {
        EncryptedData {
            etype: 18_i32,
            kvno: None,
            cipher: vec![1_u8].into(),
        }
    }

    /// RFC 4120 section 5.4.1 minimal request body with an additional ticket.
    fn request_body() -> Result<rasn_kerberos::KdcReqBody, Box<dyn Error>> {
        let mut body = kdc_req::decode_kdc_req_body(&hex::decode(concat!(
            "3059A007030500FEDCBA90A2101B0E415448454E412E4D49542E454455",
            "A31A3018A003020101A111300F1B066866747361691B056578747261",
            "A511180F31393934303631303036303331375AA70302012AA8083006020100020101"
        ))?)?;
        body.additional_tickets = Some(vec![ticket_value()?]);
        Ok(body)
    }

    /// Direct AP validators reject each independently invalid RFC header field.
    #[test]
    fn ap_validators_reject_wrong_headers() -> Result<(), Box<dyn Error>> {
        for (pvno, msg_type) in [(4_i32, 15_i32), (5_i32, 14_i32)] {
            let reply = rasn_kerberos::ApRep {
                pvno: Integer::from(pvno),
                msg_type: Integer::from(msg_type),
                enc_part: encrypted_data(),
            };
            assert!(matches!(
                ap_rep::validate(&reply),
                Err(ApRepError::InvalidMessage {
                    field: _,
                    expected: _,
                    actual: _
                })
            ));
        }
        for (pvno, msg_type) in [(4_i32, 14_i32), (5_i32, 15_i32)] {
            let request = rasn_kerberos::ApReq {
                pvno: Integer::from(pvno),
                msg_type: Integer::from(msg_type),
                ap_options: ap_req::ap_options_from_bits(0),
                ticket: ticket_value()?,
                authenticator: encrypted_data(),
            };
            assert!(matches!(
                ap_req::validate(&request),
                Err(ApReqError::InvalidMessage {
                    field: _,
                    expected: _,
                    actual: _
                })
            ));
        }
        Ok(())
    }

    /// AS and TGS reply validators enforce protocol headers independently of DER decoding.
    #[test]
    fn kdc_reply_validators_reject_wrong_headers() -> Result<(), Box<dyn Error>> {
        for expected in [11_i32, 13_i32] {
            for (pvno, msg_type) in [(4_i32, expected), (5_i32, 0_i32)] {
                let reply = KdcRep {
                    pvno: Integer::from(pvno),
                    msg_type: Integer::from(msg_type),
                    padata: None,
                    crealm: rasn_kerberos::KerberosString::from_bytes(b"EXAMPLE.COM")?,
                    cname: ticket_value()?.sname,
                    ticket: ticket_value()?,
                    enc_part: encrypted_data(),
                };
                let result = match expected {
                    11_i32 => kdc_rep::validate_as_rep(&AsRep(reply)),
                    _ => kdc_rep::validate_tgs_rep(&TgsRep(reply)),
                };
                assert!(matches!(
                    result,
                    Err(KdcRepError::InvalidMessage {
                        field: _,
                        expected: _,
                        actual: _
                    })
                ));
            }
        }
        Ok(())
    }

    /// AS and TGS request validators enforce headers and nested ticket versions.
    #[test]
    fn kdc_request_validators_reject_wrong_headers_and_tickets() -> Result<(), Box<dyn Error>> {
        for expected in [10_i32, 12_i32] {
            for (pvno, msg_type) in [(4_i32, expected), (5_i32, 0_i32)] {
                let request = KdcReq {
                    pvno: Integer::from(pvno),
                    msg_type: Integer::from(msg_type),
                    padata: None,
                    req_body: request_body()?,
                };
                let result = match expected {
                    10_i32 => kdc_req::validate_as_req(&AsReq(request)),
                    _ => kdc_req::validate_tgs_req(&TgsReq(request)),
                };
                assert!(matches!(
                    result,
                    Err(KdcReqError::InvalidMessage {
                        field: _,
                        expected: _,
                        actual: _
                    })
                ));
            }
        }
        let mut body = request_body()?;
        body.additional_tickets
            .as_mut()
            .ok_or("tickets")?
            .first_mut()
            .ok_or("ticket")?
            .tkt_vno = Integer::from(4_i32);
        assert!(matches!(
            kdc_req::validate_kdc_req_body(&body),
            Err(KdcReqError::InvalidMessage {
                field: _,
                expected: _,
                actual: _
            })
        ));
        Ok(())
    }

    /// KRB-CRED, KRB-PRIV and KRB-SAFE reject invalid protocol integers on the wire.
    #[test]
    fn protected_message_decoders_reject_wrong_headers() -> Result<(), Box<dyn Error>> {
        for (pvno, msg_type) in [(4_i32, 22_i32), (5_i32, 0_i32)] {
            let credential = rasn_kerberos::KrbCred {
                pvno: Integer::from(pvno),
                msg_type: Integer::from(msg_type),
                tickets: vec![ticket_value()?],
                enc_part: encrypted_data(),
            };
            assert!(matches!(
                krb_cred::decode(&der::encode(&credential)?),
                Err(CredError::InvalidMessage {
                    field: _,
                    expected: _,
                    actual: _
                })
            ));
        }
        for pvno in [4_i32, 5_i32] {
            let private = rasn_kerberos::KrbPriv {
                pvno: Integer::from(pvno),
                msg_type: Integer::from(0_i32),
                enc_part: encrypted_data(),
            };
            assert!(matches!(
                krb_priv::validate(&private),
                Err(PrivError::InvalidMessage {
                    field: _,
                    expected: _,
                    actual: _
                })
            ));
        }
        let mut safe = hex::decode(
            "743E303CA003020104A103020114A21F301DA00A04086B72623564617461A40F300DA003020102A106040412D00023A30F300DA003020101A106040431323334",
        )?;
        assert!(matches!(
            krb_safe::decode(&safe),
            Err(SafeError::InvalidMessage {
                field: _,
                expected: _,
                actual: _
            })
        ));
        *safe.get_mut(8).ok_or("version byte")? = 5;
        *safe.get_mut(13).ok_or("message byte")? = 0;
        assert!(matches!(
            krb_safe::decode(&safe),
            Err(SafeError::InvalidMessage {
                field: _,
                expected: _,
                actual: _
            })
        ));
        Ok(())
    }

    /// Random-confounder encoded AP replies retain the RFC encrypted-part value.
    #[test]
    fn encoded_ap_reply_decrypts_to_known_answer() -> Result<(), Box<dyn Error>> {
        let wire = hex::decode("7B1C301AA011180F31393934303631303036303331375AA105020301E240")?;
        let part = ap_rep::decode_enc_ap_rep_part(&wire)?;
        let key = EncryptionKey::new(18, vec![0x11; 32]);
        let encoded = ap_rep::build_encoded(&part, &key, Some(7))?;
        let reply = ap_rep::decode(&encoded)?;
        assert_eq!(reply.enc_part.kvno, Some(7));
        assert_eq!(
            der::encode(&ap_rep::decrypt_ap_rep_enc_part(&reply, &key)?)?,
            wire
        );
        Ok(())
    }

    /// Random-confounder encoded AP requests retain the RFC authenticator value.
    #[test]
    fn encoded_ap_request_decrypts_to_known_answer() -> Result<(), Box<dyn Error>> {
        let wire = hex::decode(concat!(
            "623E303CA003020105A10D1B0B4558414D504C452E434F4DA20E300C",
            "A003020101A10530031B0161A403020100A511180F31393934303631303036303331375A"
        ))?;
        let authenticator = ap_req::decode_authenticator(&wire)?;
        let key = EncryptionKey::new(18, vec![0x11; 32]);
        let encoded = ap_req::build_encoded(
            ticket_value()?,
            ap_req::ap_options_from_bits(0),
            &authenticator,
            &key,
            11,
            None,
        )?;
        let request = ap_req::decode(&encoded)?;
        assert_eq!(
            der::encode(&ap_req::decrypt_ap_req_authenticator(&request, &key, 11)?)?,
            wire
        );
        Ok(())
    }

    /// Random-confounder encoded tickets retain a known RFC encrypted ticket part.
    #[test]
    fn encoded_ticket_decrypts_to_known_answer() -> Result<(), Box<dyn Error>> {
        let wire = hex::decode(concat!(
            "6381A53081A2A007030500FEDCBA98A1133011A003020101A10A04",
            "083132333435363738A2101B0E415448454E412E4D49542E454455A31A",
            "3018A003020101A111300F1B066866747361691B056578747261A42E",
            "302CA003020101A12504234544552C4D49542E2C415448454E412E2C",
            "57415348494E47544F4E2E4544552C43532EA511180F313939343036",
            "31303036303331375AA711180F31393934303631303036303331375A"
        ))?;
        let part = ticket::decode_enc_ticket_part(&wire)?;
        let fixture = ticket_value()?;
        let key = EncryptionKey::new(18, vec![0x11; 32]);
        let encoded = ticket::build_encoded(fixture.realm, fixture.sname, &part, &key, None)?;
        assert_eq!(
            der::encode(&ticket::decrypt_ticket_enc_part(
                &ticket::decode(&encoded)?,
                &key
            )?)?,
            wire
        );
        Ok(())
    }
}

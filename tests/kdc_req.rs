//! KDC-REQ tests: gokrb5 AS-REQ, TGS-REQ and KDC-REQ-BODY fixtures and request building.
#![cfg(feature = "messages")]

/// KDC-REQ tests.
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
    use rasn::{
        der,
        types::{GeneralString, Integer},
    };
    use rasn_kerberos::{
        EncryptedData, HostAddress, KdcOptions, KdcReq, KdcReqBody, PaData, PrincipalName, Ticket,
    };
    use rskrb5_ng::{
        error::{Crypto, KdcReq as RequestError, Policy, RejectedFeature},
        kdc_req::{
            KRB_AS_REQ_MSG_TYPE, KRB_TGS_REQ_MSG_TYPE, build_as_req, build_tgs_req, decode_as_req,
            decode_kdc_req_body, decode_tgs_req, encode_as_req, encode_build_as_req,
            encode_build_tgs_req, encode_kdc_req_body, encode_tgs_req,
        },
    };

    /// Error type of the `Result`-returning tests.
    type TestError = Box<dyn error::Error>;

    /// gokrb5 KDC-REQ-BODY fixture with every optional field set.
    const KDC_REQ_BODY: &str = "308201A6A007030500FEDCBA90A11A3018A003020101A111300F1B066866747361691B056578747261A2101B0E415448454E412E4D49542E454455A31A3018A003020101A111300F1B066866747361691B056578747261A411180F31393934303631303036303331375AA511180F31393934303631303036303331375AA611180F31393934303631303036303331375AA70302012AA8083006020100020101A920301E300DA003020102A106040412D00023300DA003020102A106040412D00023AA253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765AB81BF3081BC615C305AA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A3253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765615C305AA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A3253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765";
    /// gokrb5 KDC-REQ-BODY fixture with only the additional tickets set.
    const KDC_REQ_BODY_OPTIONALS_NULL_EXCEPT_SECOND_TICKET: &str = "3081FFA007030500FEDCBA98A2101B0E415448454E412E4D49542E454455A511180F31393934303631303036303331375AA70302012AA8083006020100020101AB81BF3081BC615C305AA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A3253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765615C305AA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A3253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765";
    /// gokrb5 KDC-REQ-BODY fixture with only the server name set.
    const KDC_REQ_BODY_OPTIONALS_NULL_EXCEPT_SERVER: &str = "3059A007030500FEDCBA90A2101B0E415448454E412E4D49542E454455A31A3018A003020101A111300F1B066866747361691B056578747261A511180F31393934303631303036303331375AA70302012AA8083006020100020101";
    /// gokrb5 AS-REQ fixture with every optional field set.
    const AS_REQ: &str = "6A8201E4308201E0A103020105A20302010AA32630243010A10302010DA209040770612D646174613010A10302010DA209040770612D64617461A48201AA308201A6A007030500FEDCBA90A11A3018A003020101A111300F1B066866747361691B056578747261A2101B0E415448454E412E4D49542E454455A31A3018A003020101A111300F1B066866747361691B056578747261A411180F31393934303631303036303331375AA511180F31393934303631303036303331375AA611180F31393934303631303036303331375AA70302012AA8083006020100020101A920301E300DA003020102A106040412D00023300DA003020102A106040412D00023AA253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765AB81BF3081BC615C305AA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A3253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765615C305AA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A3253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765";
    /// gokrb5 AS-REQ fixture with only the additional tickets set.
    const AS_REQ_OPTIONALS_NULL_EXCEPT_SECOND_TICKET: &str = "6A82011430820110A103020105A20302010AA48201023081FFA007030500FEDCBA98A2101B0E415448454E412E4D49542E454455A511180F31393934303631303036303331375AA70302012AA8083006020100020101AB81BF3081BC615C305AA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A3253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765615C305AA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A3253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765";
    /// gokrb5 AS-REQ fixture with only the server name set.
    const AS_REQ_OPTIONALS_NULL_EXCEPT_SERVER: &str = "6A693067A103020105A20302010AA45B3059A007030500FEDCBA90A2101B0E415448454E412E4D49542E454455A31A3018A003020101A111300F1B066866747361691B056578747261A511180F31393934303631303036303331375AA70302012AA8083006020100020101";
    /// gokrb5 TGS-REQ fixture with every optional field set.
    const TGS_REQ: &str = "6C8201E4308201E0A103020105A20302010CA32630243010A10302010DA209040770612D646174613010A10302010DA209040770612D64617461A48201AA308201A6A007030500FEDCBA90A11A3018A003020101A111300F1B066866747361691B056578747261A2101B0E415448454E412E4D49542E454455A31A3018A003020101A111300F1B066866747361691B056578747261A411180F31393934303631303036303331375AA511180F31393934303631303036303331375AA611180F31393934303631303036303331375AA70302012AA8083006020100020101A920301E300DA003020102A106040412D00023300DA003020102A106040412D00023AA253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765AB81BF3081BC615C305AA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A3253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765615C305AA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A3253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765";
    /// gokrb5 TGS-REQ fixture with only the additional tickets set.
    const TGS_REQ_OPTIONALS_NULL_EXCEPT_SECOND_TICKET: &str = "6C82011430820110A103020105A20302010CA48201023081FFA007030500FEDCBA98A2101B0E415448454E412E4D49542E454455A511180F31393934303631303036303331375AA70302012AA8083006020100020101AB81BF3081BC615C305AA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A3253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765615C305AA003020105A1101B0E415448454E412E4D49542E454455A21A3018A003020101A111300F1B066866747361691B056578747261A3253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765";
    /// gokrb5 TGS-REQ fixture with only the server name set.
    const TGS_REQ_OPTIONALS_NULL_EXCEPT_SERVER: &str = "6C693067A103020105A20302010CA45B3059A007030500FEDCBA90A2101B0E415448454E412E4D49542E454455A31A3018A003020101A111300F1B066866747361691B056578747261A511180F31393934303631303036303331375AA70302012AA8083006020100020101";
    /// Timestamp of the gokrb5 fixtures, in seconds since the Unix epoch.
    const TEST_TIME_SECONDS: i64 = 771_228_197;

    /// Which optional KDC-REQ-BODY fields a fixture carries.
    #[derive(Clone, Copy)]
    enum BodyShape {
        /// Every optional field is present.
        Full,
        /// Only the additional tickets are present.
        SecondTicketOnly,
        /// Only the server name is present.
        ServerOnly,
    }

    /// Historical body fixtures decode intact but cannot select DES on output.
    #[test]
    fn decodes_gokrb5_kdc_req_body_fixtures() -> Result<(), TestError> {
        for (fixture, shape) in [
            (KDC_REQ_BODY, BodyShape::Full),
            (
                KDC_REQ_BODY_OPTIONALS_NULL_EXCEPT_SECOND_TICKET,
                BodyShape::SecondTicketOnly,
            ),
            (
                KDC_REQ_BODY_OPTIONALS_NULL_EXCEPT_SERVER,
                BodyShape::ServerOnly,
            ),
        ] {
            let bytes = hex::decode(fixture)?;

            let body = decode_kdc_req_body(&bytes)?;

            assert_kdc_req_body(&body, shape)?;
            assert_eq!(der::encode(&body)?, bytes);
            assert_des_rejected(&encode_kdc_req_body(&body));
        }
        Ok(())
    }

    /// Historical AS fixtures decode intact but cannot select DES on output.
    #[test]
    fn decodes_gokrb5_as_req_fixtures() -> Result<(), TestError> {
        for (fixture, shape) in [
            (AS_REQ, BodyShape::Full),
            (
                AS_REQ_OPTIONALS_NULL_EXCEPT_SECOND_TICKET,
                BodyShape::SecondTicketOnly,
            ),
            (AS_REQ_OPTIONALS_NULL_EXCEPT_SERVER, BodyShape::ServerOnly),
        ] {
            let bytes = hex::decode(fixture)?;

            let as_req = decode_as_req(&bytes)?;

            assert_kdc_req_fields(&as_req.0, KRB_AS_REQ_MSG_TYPE, shape)?;
            assert_eq!(der::encode(&as_req)?, bytes);
            assert_des_rejected(&encode_as_req(&as_req));
        }
        Ok(())
    }

    /// Historical TGS fixtures decode intact but cannot select DES on output.
    #[test]
    fn decodes_gokrb5_tgs_req_fixtures() -> Result<(), TestError> {
        for (fixture, shape) in [
            (TGS_REQ, BodyShape::Full),
            (
                TGS_REQ_OPTIONALS_NULL_EXCEPT_SECOND_TICKET,
                BodyShape::SecondTicketOnly,
            ),
            (TGS_REQ_OPTIONALS_NULL_EXCEPT_SERVER, BodyShape::ServerOnly),
        ] {
            let bytes = hex::decode(fixture)?;

            let tgs_req = decode_tgs_req(&bytes)?;

            assert_kdc_req_fields(&tgs_req.0, KRB_TGS_REQ_MSG_TYPE, shape)?;
            assert_eq!(der::encode(&tgs_req)?, bytes);
            assert_des_rejected(&encode_tgs_req(&tgs_req));
        }
        Ok(())
    }

    /// AS construction preserves historical fields while outgoing encoding rejects DES.
    #[test]
    fn builds_as_req_from_body_and_padata() -> Result<(), TestError> {
        let body = decode_kdc_req_body(&hex::decode(KDC_REQ_BODY)?)?;
        let fixture = decode_as_req(&hex::decode(AS_REQ)?)?;
        let padata = fixture.0.padata.clone();

        let built = build_as_req(body.clone(), padata.clone());

        assert_eq!(built.0.pvno, Integer::from(5_i32));
        assert_eq!(built.0.msg_type, Integer::from(KRB_AS_REQ_MSG_TYPE));
        assert_eq!(built.0.padata, padata);
        assert_eq!(built.0.req_body, body);
        assert_eq!(der::encode(&built)?, hex::decode(AS_REQ)?);
        assert_des_rejected(&encode_as_req(&built));
        assert_des_rejected(&encode_build_as_req(body, fixture.0.padata));
        Ok(())
    }

    /// TGS construction preserves historical fields while outgoing encoding rejects DES.
    #[test]
    fn builds_tgs_req_from_body_and_padata() -> Result<(), TestError> {
        let body = decode_kdc_req_body(&hex::decode(KDC_REQ_BODY)?)?;
        let fixture = decode_tgs_req(&hex::decode(TGS_REQ)?)?;
        let padata = fixture.0.padata.clone();

        let built = build_tgs_req(body.clone(), padata.clone());

        assert_eq!(built.0.pvno, Integer::from(5_i32));
        assert_eq!(built.0.msg_type, Integer::from(KRB_TGS_REQ_MSG_TYPE));
        assert_eq!(built.0.padata, padata);
        assert_eq!(built.0.req_body, body);
        assert_eq!(der::encode(&built)?, hex::decode(TGS_REQ)?);
        assert_des_rejected(&encode_tgs_req(&built));
        assert_des_rejected(&encode_build_tgs_req(body, fixture.0.padata));
        Ok(())
    }

    /// Require the historical fixture's exact permanent DES refusal.
    fn assert_des_rejected(result: &Result<Vec<u8>, RequestError>) {
        assert!(matches!(
            result,
            Err(RequestError::Crypto(Crypto::Policy(
                Policy::RejectedFeature {
                    feature: RejectedFeature::SingleDes,
                    reason: _,
                }
            )))
        ));
    }

    /// Asserts the KDC-REQ header, pre-authentication data and body of a fixture shape.
    fn assert_kdc_req_fields(
        req: &KdcReq,
        expected_msg_type: i32,
        expected_shape: BodyShape,
    ) -> Result<(), TestError> {
        assert_eq!(req.pvno, Integer::from(5_i32));
        assert_eq!(req.msg_type, Integer::from(expected_msg_type));
        match expected_shape {
            BodyShape::Full => assert_padata(req.padata.as_ref().ok_or("padata")?),
            BodyShape::SecondTicketOnly | BodyShape::ServerOnly => {
                assert!(req.padata.is_none(), "padata is absent");
            }
        }
        assert_kdc_req_body(&req.req_body, expected_shape)
    }

    /// Asserts the KDC-REQ-BODY fields of a fixture shape.
    fn assert_kdc_req_body(body: &KdcReqBody, expected_shape: BodyShape) -> Result<(), TestError> {
        let expected_options = match expected_shape {
            BodyShape::SecondTicketOnly => 0xfedc_ba98,
            BodyShape::Full | BodyShape::ServerOnly => 0xfedc_ba90,
        };
        assert_eq!(kdc_options_to_bits(&body.kdc_options), expected_options);
        assert_eq!(body.realm.as_bytes(), b"ATHENA.MIT.EDU");
        assert_eq!(body.till.0.timestamp(), TEST_TIME_SECONDS);
        assert_eq!(body.nonce, 42);
        assert_eq!(body.etype, vec![0_i32, 1_i32]);

        match expected_shape {
            BodyShape::Full => {
                assert_principal(body.cname.as_ref().ok_or("cname")?);
                assert_principal(body.sname.as_ref().ok_or("sname")?);
                assert_eq!(
                    body.from.as_ref().ok_or("from")?.0.timestamp(),
                    TEST_TIME_SECONDS,
                );
                assert_eq!(
                    body.rtime.as_ref().ok_or("rtime")?.0.timestamp(),
                    TEST_TIME_SECONDS,
                );
                assert_addresses(body.addresses.as_ref().ok_or("addresses")?)?;
                assert_encrypted_data(body.enc_authorization_data.as_ref().ok_or("auth data")?);
                assert_tickets(body.additional_tickets.as_ref().ok_or("tickets")?, 2);
            }
            BodyShape::SecondTicketOnly => {
                assert!(body.cname.is_none(), "cname is absent");
                assert!(body.sname.is_none(), "sname is absent");
                assert!(body.from.is_none(), "from is absent");
                assert!(body.rtime.is_none(), "rtime is absent");
                assert!(body.addresses.is_none(), "addresses are absent");
                assert!(
                    body.enc_authorization_data.is_none(),
                    "authorization data is absent"
                );
                assert_tickets(body.additional_tickets.as_ref().ok_or("tickets")?, 2);
            }
            BodyShape::ServerOnly => {
                assert!(body.cname.is_none(), "cname is absent");
                assert_principal(body.sname.as_ref().ok_or("sname")?);
                assert!(body.from.is_none(), "from is absent");
                assert!(body.rtime.is_none(), "rtime is absent");
                assert!(body.addresses.is_none(), "addresses are absent");
                assert!(
                    body.enc_authorization_data.is_none(),
                    "authorization data is absent"
                );
                assert!(
                    body.additional_tickets.is_none(),
                    "additional tickets are absent"
                );
            }
        }
        Ok(())
    }

    /// Asserts the two gokrb5 fixture pre-authentication data entries.
    fn assert_padata(padata: &[PaData]) {
        assert_eq!(padata.len(), 2);
        for entry in padata {
            assert_eq!(entry.r#type, 13_i32);
            assert_eq!(entry.value.as_ref(), b"pa-data");
        }
    }

    /// Asserts the gokrb5 fixture principal name `hftsai/extra`.
    fn assert_principal(name: &PrincipalName) {
        assert_eq!(name.r#type, 1_i32);
        assert_eq!(
            principal_components(name),
            vec![b"hftsai".as_slice(), b"extra".as_slice()],
        );
    }

    /// Asserts the two gokrb5 fixture host addresses.
    fn assert_addresses(addresses: &[HostAddress]) -> Result<(), TestError> {
        assert_eq!(addresses.len(), 2);
        let expected_address = hex::decode("12d00023")?;
        for address in addresses {
            assert_eq!(address.addr_type, 2_i32);
            assert_eq!(address.address.as_ref(), expected_address);
        }
        Ok(())
    }

    /// Asserts the gokrb5 fixture encrypted data.
    fn assert_encrypted_data(encrypted_data: &EncryptedData) {
        assert_eq!(encrypted_data.etype, 0_i32);
        assert_eq!(encrypted_data.kvno, Some(5));
        assert_eq!(encrypted_data.cipher.as_ref(), b"krbASN.1 test message");
    }

    /// Asserts `expected_count` gokrb5 fixture tickets.
    fn assert_tickets(tickets: &[Ticket], expected_count: usize) {
        assert_eq!(tickets.len(), expected_count);
        for ticket in tickets {
            assert_eq!(ticket.tkt_vno, Integer::from(5_i32));
            assert_eq!(ticket.realm.as_bytes(), b"ATHENA.MIT.EDU");
            assert_principal(&ticket.sname);
            assert_encrypted_data(&ticket.enc_part);
        }
    }

    /// Returns the name components of a principal name as byte slices.
    fn principal_components(name: &PrincipalName) -> Vec<&[u8]> {
        name.string.iter().map(GeneralString::as_bytes).collect()
    }

    /// Returns the first 32 KDC option bits as a big-endian integer; missing bytes read as zero.
    fn kdc_options_to_bits(flags: &KdcOptions) -> u32 {
        let raw = flags.0.as_raw_slice();
        u32::from_be_bytes([
            raw.first().copied().unwrap_or_default(),
            raw.get(1).copied().unwrap_or_default(),
            raw.get(2).copied().unwrap_or_default(),
            raw.get(3).copied().unwrap_or_default(),
        ])
    }
}

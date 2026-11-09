//! SPNEGO, Kerberos mech token and HTTP Negotiate header tests against the gokrb5 vectors.
#![cfg(feature = "spnego")]

#[path = "support/context.rs"]
mod context;

/// SPNEGO and Kerberos mech token tests.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::time::Duration;
    use std::time::{SystemTime, UNIX_EPOCH};

    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use chrono::DateTime;
    use hex::FromHexError;
    use pretty_assertions::{assert_eq, assert_ne};
    use rasn::der;
    use rskrb5_ng::{
        ap_req::{self, decode as decode_ap_req},
        client::{
            AsRepSession, build_ap_req_with_confounder, options::ApReq, principal::Principal,
        },
        crypto::AesSha1Etype,
        error::{Service, Spnego},
        keytab::{EncryptionKey, Keytab},
        service::{ApRepOptions, Validator},
        spnego::{
            self, CONTEXT_FLAG_CONF, CONTEXT_FLAG_INTEG, InitiatorContextOptions, Krb5MechToken,
            Krb5TokenId, NegState, NegTokenInit, NegTokenResp, NegotiationToken, Token,
            oid::ObjectIdentifier,
        },
    };

    use super::context::{Context as _, TestError};

    /// Repeated context masks do not cancel flags in the GSS authenticator checksum.
    #[test]
    fn checksum_flags_are_idempotent() {
        assert_eq!(
            spnego::authenticator_checksum(&[CONTEXT_FLAG_INTEG, CONTEXT_FLAG_INTEG]),
            spnego::authenticator_checksum(&[CONTEXT_FLAG_INTEG])
        );
    }

    /// Response-token extraction reports unsupported mechanisms rather than state errors.
    #[test]
    fn response_ap_req_checks_selected_mechanism() -> Result<(), TestError> {
        let mut response = NegTokenResp::accept_completed();
        response.set_supported_mech(Some(ObjectIdentifier::from_arcs(vec![
            1, 3, 6, 1, 5, 5, 2,
        ])?));
        assert!(matches!(
            Token::Resp(response).krb5_ap_req(),
            Err(Spnego::UnsupportedMechanism(_))
        ));
        Ok(())
    }

    /// Secret-free initiator diagnostics retain their context kind.
    #[test]
    fn initiator_debug_keeps_diagnostic_kind() -> Result<(), TestError> {
        let session = service_ticket_session_from_valid_ap_req()?;
        let context = spnego::init_sec_context_with_confounder(
            &session,
            InitiatorContextOptions::new().with_sequence_number(Some(42)),
            timestamp(1_893_553_447)?,
            123_456,
            &decode_hex(AP_REP_CONFOUNDER)?,
        )?;
        assert!(format!("{context:?}").starts_with("InitiatorContext"));
        let credential = format!("{:?}", context.krb5_token().message());
        assert!(!format!("{:?}", context.krb5_token()).contains(&credential));
        assert!(format!("{:?}", context.krb5_token()).starts_with("Krb5MechToken {"));
        assert!(format!("{:?}", context.krb5_token()).contains(&format!(
            "message_len: {}",
            context.krb5_token().message().len()
        )));
        let Token::Init(init) = context.spnego_token() else {
            return Err(TestError::from("expected initial token"));
        };
        let wire = format!("{:?}", init.mech_token().context("mechanism token")?);
        assert!(format!("{init:?}").starts_with("NegTokenInit {"));
        assert!(format!("{init:?}").contains("mech_token_len: Some("));
        let response =
            NegTokenResp::accept_completed().with_response_token(context.ap_req_der_ref().to_vec());
        assert!(format!("{response:?}").starts_with("NegTokenResp {"));
        assert!(format!("{response:?}").contains(&format!(
            "response_token_len: Some({})",
            context.ap_req_der_ref().len()
        )));
        for diagnostic in [
            format!("{init:?}"),
            format!("{:?}", context.spnego_token()),
            format!("{:?}", NegotiationToken::Init(init.clone())),
            format!("{response:?}"),
        ] {
            assert!(!diagnostic.contains(&credential));
            assert!(!diagnostic.contains(&wire));
        }
        Ok(())
    }

    /// Either mismatched timestamp component invalidates an authenticated AP-REP.
    #[test]
    fn initiator_rejects_each_timestamp_mismatch() -> Result<(), TestError> {
        use rskrb5_ng::ap_rep;
        let session = service_ticket_session_from_valid_ap_req()?;
        let context = spnego::init_sec_context_with_confounder(
            &session,
            InitiatorContextOptions::new().with_sequence_number(Some(42)),
            timestamp(1_893_553_447)?,
            123_456,
            &decode_hex(AP_REP_CONFOUNDER)?,
        )?;
        for (seconds, micros) in [
            (1_893_553_448_u64, 123_456_i32),
            (1_893_553_447_u64, 123_457_i32),
        ] {
            let part = rasn_kerberos::EncApRepPart {
                ctime: rasn_kerberos::KerberosTime(
                    DateTime::from_timestamp(i64::try_from(seconds)?, 0)
                        .context("time")?
                        .fixed_offset(),
                ),
                cusec: micros.into(),
                subkey: None,
                seq_number: Some(42),
            };
            let reply = ap_rep::build_ap_rep_with_confounder(
                &part,
                session.session_key(),
                None,
                &decode_hex(AP_REP_CONFOUNDER)?,
            )?;
            assert!(matches!(
                context.verify_ap_rep(&ap_rep::encode(&reply)?),
                Err(Spnego::ApRepTimestampMismatch {
                    expected: _,
                    actual: _
                })
            ));
        }
        Ok(())
    }

    /// A valid MIC checksum cannot excuse a completion token's wrong sequence number.
    #[test]
    fn completion_mic_rejects_wrong_sequence() -> Result<(), TestError> {
        use rskrb5_ng::spnego::{
            GSS_TOKEN_FLAG_SENT_BY_ACCEPTOR, GSSAPI_ACCEPTOR_SIGN_USAGE, MicToken,
        };
        let session = service_ticket_session_from_valid_ap_req()?;
        let context = spnego::init_sec_context_with_confounder(
            &session,
            InitiatorContextOptions::new().with_sequence_number(Some(42)),
            timestamp(1_893_553_447)?,
            123_456,
            &decode_hex(AP_REP_CONFOUNDER)?,
        )?;
        let keytab = Keytab::parse(&decode_hex(HTTP_KEYTAB)?)?;
        let mut validator = Validator::new(&keytab).with_now(timestamp(1_893_553_447)?);
        let accepted = spnego::accept_sec_context_header(&mut validator, context.header_ref())?;
        let header = accepted.ap_rep_response_header_with_confounder(
            &decode_hex(AP_REP_CONFOUNDER)?,
            &ApRepOptions::default(),
        )?;
        let Token::Resp(mut response) = spnego::parse_negotiate_header(&header)? else {
            return Err("response".into());
        };
        let mut mic =
            MicToken::new(GSS_TOKEN_FLAG_SENT_BY_ACCEPTOR, 1).with_payload(decode_hex(KRB5_ONLY)?);
        mic.set_checksum(session.session_key(), GSSAPI_ACCEPTOR_SIGN_USAGE)?;
        response.set_mech_list_mic(Some(mic.encode()?.into()));
        assert!(matches!(
            context
                .verify_ap_rep_response_header(&spnego::negotiate_header(&Token::Resp(response))?),
            Err(Spnego::InvalidMechListMic)
        ));
        Ok(())
    }

    /// Kerberos token accessors expose only their matching message kind and original bytes.
    #[test]
    fn mech_token_accessors_preserve_kind_and_bytes() -> Result<(), TestError> {
        for id in [Krb5TokenId::ApReq, Krb5TokenId::ApRep] {
            let token = Krb5MechToken::decode(&Krb5MechToken::new(id, vec![42, 17]).encode()?)?;
            assert_eq!(
                token.ap_req_bytes(),
                (id == Krb5TokenId::ApReq).then_some([42, 17].as_slice())
            );
            assert_eq!(
                token.ap_rep_bytes(),
                (id == Krb5TokenId::ApRep).then_some([42, 17].as_slice())
            );
        }
        Ok(())
    }

    /// Header parsing rejects either a wrong scheme or an empty encoded token.
    #[test]
    fn header_scheme_and_empty_token_are_independent() -> Result<(), TestError> {
        let token = Token::Resp(NegTokenResp::accept_completed());
        let header = spnego::negotiate_header(&token)?;
        let wrong = header.replacen("Negotiate", "Basic", 1);
        for input in [wrong.as_str(), "Negotiate "] {
            assert!(matches!(
                spnego::parse_negotiate_header(input),
                Err(Spnego::InvalidNegotiateHeader)
            ));
        }
        Ok(())
    }

    const KRB5_TOKEN: &str = concat!(
        "6082026306092a864886f71201020201006e8202523082024ea003020105a10302010ea207030",
        "50000000000a382015d6182015930820155a003020105a10d1b0b544553542e474f4b524235",
        "a2233021a003020101a11a30181b04485454501b10686f73742e746573742e676f6b726235",
        "a382011830820114a003020112a103020103a28201060482010230621d868c97f30bf401e0",
        "3bbffcd724bd9d067dce2afc31f71a356449b070cdafcc1ff372d0eb1e7a708b50c015",
        "2f3996c45b1ea312a803907fb97192d39f20cdcaea29876190f51de6e2b4a4df0460",
        "122ed97f363434e1e120b0e76c172b4424a536987152ac0b73013ab88af4b13a3fcdc",
        "63f739039dd46d839709cf5b51bb0ce6cb3af05fab3844caac280929955495235e9d",
        "0424f8a1fb9b4bd4f6bba971f40b97e9da60b9dabfcf0b1feebfca02c9a19b327",
        "a0004aa8e19192726cf347561fa8ac74afad5d6a264e50cf495b93aac86c77b2bc2",
        "d184234f6c2767dbea431485a25687b9044a20b601e968efaefffa1fc5283ff32aa6a",
        "53cb6c5cdd2eddcb26a481d73081d4a003020112a103020103a281c70481c4a1b29e",
        "420324f7edf9efae39df7bcaaf196a3160cf07e72f52a4ef8a965721b2f3343719c",
        "50699046e4fcc18ca26c2bfc7e4a9eddfc9d9cfc57ff2f6bdbbd1fc40ac442195",
        "bc669b9a0dbba12563b3e4cac9f4022fc01b8aa2d1ab84815bb078399ff7f4d5",
        "f9815eef896a0c7e3c049e6fd9932b97096cdb5861425b9d81753d0743212ded1",
        "a0fb55a00bf71a46be5ce5e1c8a5cc327b914347d9efcb6cb31ca363b1850d95c",
        "7b6c4c3cc6301615ad907318a0c5379d343610fab17eca9c7dc0a5a60658",
    );
    const AUTH_CHECKSUM: &str = "100000000000000000000000000000000000000030000000";

    const NEG_TOKEN_INIT: &str = concat!(
        "a08202aa308202a6a027302506092a864886f71201020206052b0501050206092a864882",
        "f71201020206062b0601050205a2820279048202756082027106092a864886f712010202",
        "01006e8202603082025ca003020105a10302010ea20703050000000000a38201706182",
        "016c30820168a003020105a10d1b0b544553542e474f4b524235a2233021a003020103",
        "a11a30181b04485454501b10686f73742e746573742e676f6b726235a382012b308201",
        "27a003020112a103020102a282011904820115d4bd890abc456f44e2e7a2e8111bd676",
        "7abf03266dfcda97c629af2ece450a5ae1f145e4a4d1bc2c848e66a6c6b31d974",
        "0b26b03cdbd2570bfcf126e90adf5f5ebce9e283ff5086da47b129b14fc0aabd",
        "4d1df9c1f3c72b80cc614dfc28783450b2c7b7749651f432b47aaa2ff158c0066",
        "b757f3fb00dd7b4f63d68276c76373ecdd3f19c66ebc43a81e577f3c263b87835",
        "6f57e8d6c4eccd587b81538e70392cf7e73fc12a6f7c537a894a7bb5566c83ac",
        "4d69757aa320a51d8d690017aebf952add1889adfc3307b0e6cd8c9b57cf8589",
        "fbe52800acb6461c25473d49faa1bdceb8bce3f61db23f9cd6a09d5adceb411e",
        "1c4546b30b33331e570fd6bc50aa403557e75f488e759750ea038aab6454667d9",
        "b64f41a481d23081cfa003020112a281c70481c4d67ba2ae4cf5d917caab1d863",
        "605249320e90482563662ed92408a543b6ad5edeb8f9375e9060a205491df082f",
        "d2a5fec93dfb76f41012bb60cae20f07adbb77a1aa56f0521f36e1ea10dc9f",
        "b762902b254dd7664d0bcc6f751f2003e41990af1b4330d10477bfad638b9f0b",
        "704ac80cc47731f8ec8d801762bad8884b8de90adb1dbe7fc7b0ffafd38fb5e",
        "b8b6547cee30d89873281ce63ad70042a13478b1a7c2bdde0f223ace62dbb84",
        "e2d06f1070f4265f66e0544449335e2fcc4d0aee5bf81c5999",
    );
    const NEG_TOKEN_RESP: &str = "a1143012a0030a0100a10b06092a864886f712010202";
    const SPNEGO_INIT_PREFIX: &str = "608202b606062b0601050502";
    const SPNEGO_RESP: &str = NEG_TOKEN_RESP;

    const HTTP_KEYTAB: &str = concat!(
        "0502000000440002000b544553542e474f4b5242350004485454500010686f73742e746573742e676f6b",
        "72623500000001590dc4dc010011001057a7754c70c4d85c155c718c2f1292b0000000540002000b",
        "544553542e474f4b5242350004485454500010686f73742e746573742e676f6b72623500000001590d",
        "c4dc01001200209cad00bbc72d703258e911dc18e6d5487cf737bf67fd111f0c2463ad6033bf51",
        "000000440002000b544553542e474f4b5242350004485454500010686f73742e746573742e676f6b",
        "72623500000001590dc4dc020011001057a7754c70c4d85c155c718c2f1292b0000000540002000b",
        "544553542e474f4b5242350004485454500010686f73742e746573742e676f6b72623500000001590d",
        "c4dc02001200209cad00bbc72d703258e911dc18e6d5487cf737bf67fd111f0c2463ad6033bf51",
    );

    const VALID_AP_REQ: &str = concat!(
        "6e8201f8308201f4a003020105a10302010ea20703050000000000a382012f6182012b30820127a0",
        "03020105a10d1b0b544553542e474f4b524235a2233021a003020101a11a30181b04485454501b",
        "10686f73742e746573742e676f6b726235a381eb3081e8a003020112a103020101a281db0481d8",
        "5e7242bdf5331825046b4692f2f850f62dedee984e72a490ac48fc3375f5bc1a50c07ff766338",
        "cbb1486cd8f9974b0865f3fd3ecb4e72b6dc556bb73a1cea8f4579983e625676b43854ff9910",
        "a0b60996f148ee1b6a49a1896d41afde6e82d2d8ed9f7304ac0ded7a74f88694dc69ab532",
        "ff51f5e7ba7fce87f4ba19885fc915e6d83f11f2152bd64f3fd63cb8b160148fed6fa9b01",
        "d86acd337d20c3b99622b166b6b283cd3704f36147972015c3a750ce9c855ae58ec598929ed",
        "953b4008dbad1ca6f0a715eb07ee19f5124ff7354ded3928fccd6cc7e8a481ab3081a8a0",
        "03020112a103020101a2819b04819882e028aad111ace518b36bd7305f9ff06545036b2214916",
        "00d07509d4e1bbcacb5a6bde72ec8812c2ef087cb64dcd905d7eba708d7a7c1a782e7bc",
        "cc3d46bfc503e5075bd6ca1d2f27b218ebb907483b6b0b8bac5137fa15fb59b1df434371",
        "e041c817d652e3068912e55203ec6ea5ce374a20e5b9b5ed9dfb6bdb06137b90b2db2a",
        "db192d415375581bdf9a2bfe73d19c13ba1d983bf513",
    );
    const AP_REP_CONFOUNDER: &str = "000102030405060708090a0b0c0d0e0f";
    const VALID_SESSION_KEY: &str =
        "8845cbaccbf11cb9f467fd577ba51c70d73de6554980a05395bf319e18bdda07";
    const AP_REP_RESPONSE_HEADER: &str = concat!(
        "Negotiate oXwweqADCgEAoQsGCSqGSIb3EgECAqJmBGRgYgYJKoZIhvcSAQICAgBvUzBRoAMCA",
        "QWhAwIBD6JFMEOgAwIBEqI8BDppQ8cwkzFMwZgOlePIcX3CimzQtTGRdViU5aDq1oZTFG",
        "9V/4+A4ZnQpz6O7l/4QbGdSdvItSIeIMNL",
    );

    /// Pins the arcs of the KRB5, legacy Microsoft KRB5 and SPNEGO OIDs.

    #[test]
    fn reports_gssapi_oids() {
        assert_eq!(
            ObjectIdentifier::krb5().arcs(),
            &[1, 2, 840, 113_554, 1, 2, 2]
        );
        assert_eq!(
            ObjectIdentifier::ms_legacy_krb5().arcs(),
            &[1, 2, 840, 48_018, 1, 2, 2]
        );
        assert_eq!(ObjectIdentifier::spnego().arcs(), &[1, 3, 6, 1, 5, 5, 2]);
    }

    /// Pins that the GSS authenticator checksum matches the gokrb5 bytes.
    #[test]
    fn authenticator_checksum_matches_gokrb5() {
        assert_eq!(
            hex_encode(&spnego::authenticator_checksum(&[
                CONTEXT_FLAG_INTEG,
                CONTEXT_FLAG_CONF
            ])),
            AUTH_CHECKSUM
        );
    }

    /// Pins that the gokrb5 KRB5 mech token decodes to an AP-REQ and re-encodes byte for byte.
    #[test]
    fn decodes_and_roundtrips_gokrb5_krb5_mech_token() -> Result<(), TestError> {
        let bytes = decode_hex(KRB5_TOKEN)?;
        let token = Krb5MechToken::decode(&bytes).context("KRB5 token decodes")?;

        assert_eq!(token.oid(), &ObjectIdentifier::krb5());
        assert_eq!(token.token_id(), Krb5TokenId::ApReq);
        let ap_req = decode_ap_req(token.message()).context("AP-REQ decodes")?;
        assert_eq!(ap_req.msg_type, 14_i32.into());
        assert_eq!(ap_req.authenticator.etype, 18_i32);
        assert_eq!(
            hex_encode(&token.encode().context("KRB5 token encodes")?),
            KRB5_TOKEN
        );
        Ok(())
    }

    /// Pins that the gokrb5 `NegTokenInit` decodes and re-encodes byte for byte.
    #[test]
    fn decodes_and_roundtrips_gokrb5_neg_token_init() -> Result<(), TestError> {
        let bytes = decode_hex(NEG_TOKEN_INIT)?;
        let token = NegTokenInit::decode(&bytes).context("NegTokenInit decodes")?;

        assert_eq!(token.mech_types().len(), 4);
        assert_eq!(
            token.mech_types().first().context("first mech type")?,
            &ObjectIdentifier::krb5()
        );
        assert_eq!(
            token.mech_types().get(2).context("third mech type")?,
            &ObjectIdentifier::ms_legacy_krb5()
        );
        assert!(token.mech_token().is_some_and(|value| !value.is_empty()));
        assert_eq!(
            hex_encode(&token.encode().context("NegTokenInit encodes")?),
            NEG_TOKEN_INIT
        );
        Ok(())
    }

    /// Pins that the gokrb5 `NegTokenResp` decodes and re-encodes byte for byte.
    #[test]
    fn decodes_and_roundtrips_gokrb5_neg_token_resp() -> Result<(), TestError> {
        let bytes = decode_hex(NEG_TOKEN_RESP)?;
        let token = NegTokenResp::decode(&bytes).context("NegTokenResp decodes")?;

        assert_eq!(token.neg_state(), Some(NegState::AcceptCompleted));
        assert_eq!(token.supported_mech(), Some(&ObjectIdentifier::krb5()));
        assert_eq!(
            hex_encode(&token.encode().context("NegTokenResp encodes")?),
            NEG_TOKEN_RESP
        );
        Ok(())
    }

    /// Pins that complete SPNEGO init and response tokens decode and re-encode byte for byte.
    #[test]
    fn decodes_and_roundtrips_full_spnego_tokens() -> Result<(), TestError> {
        let spnego_init = format!("{SPNEGO_INIT_PREFIX}{NEG_TOKEN_INIT}");
        let init = Token::decode(&decode_hex(&spnego_init)?).context("SPNEGO init decodes")?;
        let Token::Init(init_token) = &init else {
            return Err("expected NegTokenInit".into());
        };
        assert_eq!(init_token.mech_types().len(), 4);
        assert_ne!(
            init_token.krb5_ap_req().context("AP-REQ exists")?,
            [0_u8; 0]
        );
        assert_eq!(
            hex_encode(&init.encode().context("SPNEGO init encodes")?),
            spnego_init
        );

        let resp = Token::decode(&decode_hex(SPNEGO_RESP)?).context("SPNEGO resp decodes")?;
        let Token::Resp(resp_token) = &resp else {
            return Err("expected NegTokenResp".into());
        };
        assert_eq!(resp_token.neg_state(), Some(NegState::AcceptCompleted));
        assert_eq!(
            hex_encode(&resp.encode().context("SPNEGO resp encodes")?),
            SPNEGO_RESP
        );
        Ok(())
    }

    /// Pins that the HTTP Negotiate header helpers produce and parse the gokrb5 headers.
    #[test]
    fn http_negotiate_helpers_match_gokrb5_headers() -> Result<(), TestError> {
        let header = format!(
            "Negotiate {}",
            base64_encode(&decode_hex(&format!(
                "{SPNEGO_INIT_PREFIX}{NEG_TOKEN_INIT}"
            ))?)
        );
        let token = spnego::parse_negotiate_header(&header).context("header parses")?;
        assert!(matches!(token, Token::Init(_)));

        assert_eq!(spnego::challenge_header(), "Negotiate");
        assert_eq!(
            spnego::accept_completed_header().context("accept header encodes")?,
            "Negotiate oRQwEqADCgEAoQsGCSqGSIb3EgECAg=="
        );
        assert_eq!(
            spnego::accept_incomplete_krb5_header().context("incomplete header encodes")?,
            "Negotiate oRQwEqADCgEBoQsGCSqGSIb3EgECAg=="
        );
        assert_eq!(
            spnego::reject_header().context("reject header encodes")?,
            "Negotiate oQcwBaADCgEC"
        );
        Ok(())
    }

    /// Pins that a Negotiate header carrying a raw KRB5 AP-REQ token parses.
    #[test]
    fn http_negotiate_header_accepts_raw_krb5_ap_req_token() -> Result<(), TestError> {
        let raw = decode_hex(KRB5_TOKEN)?;
        let header = format!("Negotiate {}", base64_encode(&raw));
        let parsed = spnego::parse_negotiate_header(&header).context("raw KRB5 header parses")?;
        let krb5 = Krb5MechToken::decode(&raw).context("raw KRB5 token decodes")?;

        assert!(matches!(parsed, Token::Init(_)));
        assert_eq!(
            parsed.krb5_ap_req().context("AP-REQ unwraps")?,
            krb5.message()
        );
        Ok(())
    }

    /// Pins that the acceptor validates an SPNEGO header and answers with an AP-REP the initiator verifies.
    #[test]
    fn validates_service_ap_req_from_spnego_header_and_builds_ap_rep_response()
    -> Result<(), TestError> {
        let ap_req_token = Krb5MechToken::ap_req(gss_ap_req_fixture()?)
            .encode()
            .context("KRB5 AP-REQ token encodes")?;
        let spnego_token = Token::Init(NegTokenInit::krb5(ap_req_token));
        let header = spnego::negotiate_header(&spnego_token).context("Negotiate header encodes")?;

        let keytab = Keytab::parse(&decode_hex(HTTP_KEYTAB)?).context("HTTP keytab parses")?;
        let mut validator = Validator::new(&keytab).with_now(timestamp(1_893_553_447)?);
        let accepted = spnego::accept_sec_context_header(&mut validator, &header)
            .context("SPNEGO AP-REQ validates")?;
        assert_eq!(accepted.ap_req.client().name(), "testuser1");

        let ap_rep_header = accepted
            .ap_rep_response_header_with_confounder(
                &decode_hex(AP_REP_CONFOUNDER)?,
                &ApRepOptions::default(),
            )
            .context("AP-REP response header encodes")?;
        assert_eq!(ap_rep_header, AP_REP_RESPONSE_HEADER);
        let response =
            spnego::parse_negotiate_header(&ap_rep_header).context("AP-REP header parses")?;
        let Token::Resp(resp) = response else {
            return Err("expected NegTokenResp".into());
        };
        let response_token = resp.response_token().context("response token exists")?;
        let krb5 = Krb5MechToken::decode(response_token).context("KRB5 AP-REP token decodes")?;
        assert_eq!(krb5.token_id(), Krb5TokenId::ApRep);
        drop(
            accepted
                .ap_req
                .verify_ap_rep(krb5.message())
                .context("AP-REP verifies")?,
        );

        Ok(())
    }

    /// Pins that the initiator builds an SPNEGO header whose AP-REQ carries the expected authenticator.
    #[test]
    fn builds_client_spnego_header_from_service_ticket() -> Result<(), TestError> {
        let service_ticket = service_ticket_session_from_valid_ap_req()?;
        let context = spnego::init_sec_context_with_confounder(
            &service_ticket,
            InitiatorContextOptions::new().with_sequence_number(Some(42)),
            timestamp(1_893_553_447)?,
            123_456,
            &decode_hex(AP_REP_CONFOUNDER)?,
        )
        .context("client SPNEGO context builds")?;

        assert_eq!(
            context.client(),
            &Principal::user("TEST.GOKRB5", "testuser1")
        );
        assert_eq!(
            context.service().clone(),
            Principal::new("TEST.GOKRB5", 1, ["HTTP", "host.test.gokrb5"])
        );
        assert_eq!(context.sequence_number(), Some(42));

        let parsed =
            spnego::parse_negotiate_header(context.header_ref()).context("header parses")?;
        assert_eq!(&parsed, context.spnego_token());
        assert_eq!(
            parsed.krb5_ap_req().context("AP-REQ in SPNEGO")?,
            *context.ap_req_der_ref()
        );

        let ap_req: rasn_kerberos::ApReq =
            der::decode(context.ap_req_der_ref()).context("AP-REQ decodes")?;
        assert_eq!(ap_req.msg_type, 14_i32.into());
        assert_eq!(ap_req.ap_options.0.as_raw_slice(), &[0, 0, 0, 0]);
        assert_eq!(ap_req.authenticator.etype, 18_i32);

        let authenticator_bytes = AesSha1Etype::Aes256
            .decrypt_message(
                service_ticket.session_key().value(),
                ap_req.authenticator.cipher.as_ref(),
                11,
            )
            .context("authenticator decrypts")?;
        let authenticator: rasn_kerberos::Authenticator =
            der::decode(&authenticator_bytes).context("Authenticator decodes")?;
        let checksum = authenticator.cksum.context("GSS checksum exists")?;
        assert_eq!(checksum.r#type, 0x8003_i32);
        assert_eq!(hex_encode(checksum.checksum.as_ref()), AUTH_CHECKSUM);
        assert_eq!(authenticator.seq_number, Some(42));

        let keytab = Keytab::parse(&decode_hex(HTTP_KEYTAB)?).context("HTTP keytab parses")?;
        let mut validator = Validator::new(&keytab).with_now(timestamp(1_893_553_447)?);
        let accepted = spnego::accept_sec_context_header(&mut validator, context.header_ref())
            .context("client SPNEGO header validates")?;
        assert_eq!(accepted.ap_req.client().name(), "testuser1");
        assert_eq!(accepted.ap_req.service().name(), "HTTP/host.test.gokrb5");
        assert_eq!(accepted.ap_req.sequence_number(), Some(42));
        Ok(())
    }

    /// Pins that the initiator verifies the acceptor's SPNEGO AP-REP response header.
    #[test]
    fn verifies_spnego_ap_rep_response_header_as_client() -> Result<(), TestError> {
        let service_ticket = service_ticket_session_from_valid_ap_req()?;
        let context = spnego::init_sec_context_with_confounder(
            &service_ticket,
            InitiatorContextOptions::new().with_sequence_number(Some(42)),
            timestamp(1_893_553_447)?,
            123_456,
            &decode_hex(AP_REP_CONFOUNDER)?,
        )
        .context("client SPNEGO context builds")?;
        let keytab = Keytab::parse(&decode_hex(HTTP_KEYTAB)?).context("HTTP keytab parses")?;
        let mut validator = Validator::new(&keytab).with_now(timestamp(1_893_553_447)?);
        let accepted = spnego::accept_sec_context_header(&mut validator, context.header_ref())
            .context("client SPNEGO header validates")?;
        let response_header = accepted
            .ap_rep_response_header_with_confounder(
                &decode_hex(AP_REP_CONFOUNDER)?,
                &ApRepOptions::default(),
            )
            .context("AP-REP response header builds")?;

        let verified = context
            .verify_ap_rep_response_header(&response_header)
            .context("client verifies AP-REP response header")?;

        assert_eq!(verified.ctime(), context.authenticator_ctime());
        assert_eq!(verified.cusec(), context.authenticator_cusec());
        assert_eq!(verified.authenticator_time(), context.authenticator_time());
        Ok(())
    }

    /// Pins that the negotiation token enum round-trips both token kinds.
    #[test]
    fn negotiation_token_enum_roundtrips() -> Result<(), TestError> {
        let init = NegotiationToken::decode(&decode_hex(NEG_TOKEN_INIT)?)
            .context("init choice decodes")?;
        assert!(matches!(init, NegotiationToken::Init(_)));
        assert_eq!(
            hex_encode(&init.encode().context("init choice encodes")?),
            NEG_TOKEN_INIT
        );

        let resp = NegotiationToken::decode(&decode_hex(NEG_TOKEN_RESP)?)
            .context("resp choice decodes")?;
        assert!(matches!(resp, NegotiationToken::Resp(_)));
        assert_eq!(
            hex_encode(&resp.encode().context("resp choice encodes")?),
            NEG_TOKEN_RESP
        );
        Ok(())
    }

    fn service_ticket_session_from_valid_ap_req() -> Result<AsRepSession, TestError> {
        let ap_req: rasn_kerberos::ApReq =
            der::decode(&decode_hex(VALID_AP_REQ)?).context("AP-REQ fixture decodes")?;
        Ok(AsRepSession::new(
            Principal::user("TEST.GOKRB5", "testuser1"),
            Principal::new("TEST.GOKRB5", 1, ["HTTP", "host.test.gokrb5"]),
            EncryptionKey::new(18, decode_hex(VALID_SESSION_KEY)?),
            der::encode(&ap_req.ticket)
                .context("ticket encodes")?
                .into(),
            [0; 4],
            timestamp(1_893_553_445)?,
            timestamp(1_893_639_845)?,
        )
        .with_start_time(timestamp(1_893_553_445)?)
        .with_renew_till(None)
        .with_key_expiration(None))
    }

    // Independent RFC 4178 MechTypeList DER, without the explicit [0] tag.
    const MS_THEN_KRB5: &str = "301606092a864882f71201020206092a864886f712010202";
    const KRB5_ONLY: &str = "300b06092a864886f712010202";

    /// A valid MIC permits selecting Kerberos after an NTLM preference.
    #[test]
    fn mech_list_mic_accepts_kerberos_after_ntlm() -> Result<(), TestError> {
        let mut init = acceptor_init(ObjectIdentifier::krb5())?;
        init.mech_types_mut().insert(
            0,
            ObjectIdentifier::from_arcs(vec![1, 3, 6, 1, 4, 1, 311, 2, 2, 10])?,
        );
        init.set_mech_list_mic(Some(independent_mic(
            "3017060a2b06010401823702020a06092a864886f712010202",
            &decode_hex(VALID_SESSION_KEY)?,
            false,
        )?));
        let accepted = accept_token(&Token::Init(init))??;
        assert_eq!(accepted.selected_mechanism, ObjectIdentifier::krb5());
        Ok(())
    }

    fn test_tlv(tag: u8, value: &[u8]) -> Result<Vec<u8>, TestError> {
        let mut bytes = vec![tag, 0x82];
        bytes.extend_from_slice(&u16::try_from(value.len())?.to_be_bytes());
        bytes.extend_from_slice(value);
        Ok(bytes)
    }

    /// Nonminimal transcript lengths are rejected before MIC authentication.
    #[test]
    fn mech_list_mic_does_not_normalize_received_encoding() -> Result<(), TestError> {
        // Given a nonminimal long-form list length, signed in its canonical form instead.
        let init = mic_init()?;
        let list = decode_hex(MS_THEN_KRB5)?;
        let raw_list = test_tlv(0x30, list.get(2..).context("list contents")?)?;
        let mut fields = test_tlv(0xa0, &raw_list)?;
        fields.extend_from_slice(&test_tlv(
            0xa2,
            &test_tlv(4, init.mech_token().context("token")?)?,
        )?);
        fields.extend_from_slice(&test_tlv(
            0xa3,
            &test_tlv(4, init.mech_list_mic().context("MIC")?)?,
        )?);
        let wire = test_tlv(0xa0, &test_tlv(0x30, &fields)?)?;
        let header = format!("Negotiate {}", base64_encode(&wire));
        let keytab = Keytab::parse(&decode_hex(HTTP_KEYTAB)?)?;
        let mut validator = Validator::new(&keytab).with_now(timestamp(1_893_553_447)?);
        // When verified, then re-encoding cannot hide a wire transcript change.
        assert!(matches!(
            spnego::accept_sec_context_header(&mut validator, &header),
            Err(Spnego::NonminimalLength)
        ));
        Ok(())
    }

    /// Construct RFC 4121 wire bytes without using the SPNEGO MIC implementation.
    fn independent_mic(
        list: &str,
        key: &[u8],
        acceptor: bool,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, TestError> {
        independent_mic_flags(list, key, u8::from(acceptor))
    }

    fn independent_mic_flags(
        list: &str,
        key: &[u8],
        flags: u8,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, TestError> {
        let mut header = vec![4, 4, flags, 255, 255, 255, 255, 255];
        header.extend_from_slice(&42_u64.to_be_bytes());
        let mut signed = decode_hex(list)?;
        signed.extend_from_slice(&header);
        let checksum =
            AesSha1Etype::Aes256.checksum(key, &signed, if flags & 1 != 0 { 23 } else { 25 })?;
        header.extend_from_slice(&checksum);
        Ok(header.into())
    }

    fn mic_init() -> Result<NegTokenInit, TestError> {
        let mut init = acceptor_init(ObjectIdentifier::krb5())?;
        init.mech_types_mut()
            .insert(0, ObjectIdentifier::ms_legacy_krb5());
        init.set_mech_list_mic(Some(independent_mic(
            MS_THEN_KRB5,
            &decode_hex(VALID_SESSION_KEY)?,
            false,
        )?));
        Ok(init)
    }

    /// A supplied MIC on an alias-first offer authenticates both directions.
    #[test]
    fn mech_list_mic_accepts_nonfirst_and_authenticates_response() -> Result<(), TestError> {
        // Given an independently signed MS-first / standard optimistic token.
        let init = mic_init()?;
        // When the one-shot acceptor verifies the complete exchange.
        let accepted = accept_token(&Token::Init(init))??;
        // Then its response selects the offered alias and signs the same list.
        assert_eq!(
            accepted.selected_mechanism,
            ObjectIdentifier::ms_legacy_krb5()
        );
        let header = accepted.ap_rep_response_header_with_confounder(
            &decode_hex(AP_REP_CONFOUNDER)?,
            &ApRepOptions::default().with_sequence_number(Some(42)),
        )?;
        let Token::Resp(response) = spnego::parse_negotiate_header(&header)? else {
            return Err("expected response".into());
        };
        assert_eq!(response.neg_state(), Some(NegState::AcceptCompleted));
        assert_eq!(
            response.supported_mech(),
            Some(&ObjectIdentifier::ms_legacy_krb5())
        );
        assert_eq!(
            response.mech_list_mic(),
            Some(independent_mic(MS_THEN_KRB5, &decode_hex(VALID_SESSION_KEY)?, true)?.as_slice())
        );
        let krb5 = Krb5MechToken::decode(response.response_token().context("AP-REP")?)?;
        assert_eq!(krb5.oid(), &ObjectIdentifier::krb5());
        drop(accepted.ap_req.verify_ap_rep(krb5.message())?);
        Ok(())
    }

    /// An optional first-choice MIC must also verify and receive a MIC response.
    #[test]
    fn mech_list_mic_accepts_first_choice() -> Result<(), TestError> {
        // Given a first-choice token with an independent MIC.
        let mut init = acceptor_init(ObjectIdentifier::krb5())?;
        init.set_mech_list_mic(Some(independent_mic(
            KRB5_ONLY,
            &decode_hex(VALID_SESSION_KEY)?,
            false,
        )?));
        // When accepted.
        let accepted = accept_token(&Token::Init(init))??;
        // Then the list is mutually authenticated even though MIC was optional.
        let header = accepted.ap_rep_response_header_with_confounder(
            &decode_hex(AP_REP_CONFOUNDER)?,
            &ApRepOptions::default().with_sequence_number(Some(42)),
        )?;
        let Token::Resp(response) = spnego::parse_negotiate_header(&header)? else {
            return Err("expected response".into());
        };
        assert_eq!(
            response.mech_list_mic(),
            Some(independent_mic(KRB5_ONLY, &decode_hex(VALID_SESSION_KEY)?, true)?.as_slice())
        );
        Ok(())
    }

    /// List reordering and checksum corruption must fail, without consuming replay state.
    #[test]
    fn mech_list_mic_rejects_tampering_before_replay_commit() -> Result<(), TestError> {
        // Given a valid AP-REQ with two different invalid MICs.
        let valid = mic_init()?;
        let mut tampered = valid.clone();
        let mut mic = tampered.mech_list_mic().context("MIC")?.to_vec();
        *mic.last_mut().context("tag")? ^= 1;
        tampered.set_mech_list_mic(Some(mic.into()));
        let mut other_list = valid.clone();
        other_list.set_mech_list_mic(Some(independent_mic(
            KRB5_ONLY,
            &decode_hex(VALID_SESSION_KEY)?,
            false,
        )?));
        let keytab = Keytab::parse(&decode_hex(HTTP_KEYTAB)?)?;
        let mut validator = Validator::new(&keytab).with_now(timestamp(1_893_553_447)?);
        // When either invalid MIC is presented.
        for init in [tampered, other_list] {
            let header = spnego::negotiate_header(&Token::Init(init))?;
            assert!(matches!(
                spnego::accept_sec_context_header(&mut validator, &header),
                Err(Spnego::InvalidMechListMic)
            ));
            assert!(
                validator.replay_cache_mut().is_empty(),
                "invalid MIC must not consume replay state"
            );
        }
        // Then a correctly signed retransmission can still establish the context.
        let header = spnego::negotiate_header(&Token::Init(valid))?;
        let accepted = spnego::accept_sec_context_header(&mut validator, &header)?;
        assert_eq!(accepted.ap_req.client().name(), "testuser1");
        Ok(())
    }

    /// Context subkeys take precedence over the ticket key in each direction.
    #[test]
    fn mech_list_mic_uses_context_subkeys() -> Result<(), TestError> {
        // Given an AP-REQ whose subkey differs from the ticket key.
        let initiator_key = EncryptionKey::new(18, vec![0x35; 32]);
        let acceptor_key = EncryptionKey::new(18, vec![0x76; 32]);
        let built = build_ap_req_with_confounder(
            &service_ticket_session_from_valid_ap_req()?,
            ApReq::new()
                .with_checksum(Some(gss_checksum(&[])))
                .with_sequence_number(Some(42))
                .with_subkey(Some(initiator_key.clone())),
            timestamp(1_893_553_447)?,
            123_456,
            &decode_hex(AP_REP_CONFOUNDER)?,
        )?;
        let mut init = mic_init()?;
        init.set_mech_token(Some(
            Krb5MechToken::ap_req(built.der().to_vec()).encode()?.into(),
        ));
        assert!(matches!(
            accept_token(&Token::Init(init.clone()))?,
            Err(Spnego::InvalidMechListMic)
        ));
        init.set_mech_list_mic(Some(independent_mic(
            MS_THEN_KRB5,
            initiator_key.value(),
            false,
        )?));
        // When the authenticator subkey authenticates the list.
        let accepted = accept_token(&Token::Init(init))??;
        // Then response MICs use the initiator subkey unless AP-REP supplies an acceptor subkey.
        for subkey in [None, Some(acceptor_key)] {
            let flags = if subkey.is_some() { 5 } else { 1 };
            let key = subkey.as_ref().unwrap_or(&initiator_key);
            let expected = independent_mic_flags(MS_THEN_KRB5, key.value(), flags)?;
            let header = accepted.ap_rep_response_header_with_confounder(
                &decode_hex(AP_REP_CONFOUNDER)?,
                &ApRepOptions::default().with_subkey(subkey),
            )?;
            let Token::Resp(response) = spnego::parse_negotiate_header(&header)? else {
                return Err("expected response".into());
            };
            assert_eq!(response.mech_list_mic(), Some(expected.as_slice()));
        }
        Ok(())
    }

    /// Independently decrypt a response header's AP-REP and return it with the response MIC.
    fn response_ap_rep_part(
        header: &str,
    ) -> Result<(rasn_kerberos::EncApRepPart, Option<Vec<u8>>), TestError> {
        let Token::Resp(response) = spnego::parse_negotiate_header(header)? else {
            return Err("expected response".into());
        };
        let krb5 = Krb5MechToken::decode(response.response_token().context("AP-REP")?)?;
        let ap_rep: rasn_kerberos::ApRep = der::decode(krb5.message()).context("AP-REP decodes")?;
        let part = AesSha1Etype::Aes256.decrypt_message(
            &decode_hex(VALID_SESSION_KEY)?,
            ap_rep.enc_part.cipher.as_ref(),
            12,
        )?;
        Ok((
            der::decode(&part).context("EncAPRepPart decodes")?,
            response.mech_list_mic().map(<[u8]>::to_vec),
        ))
    }

    /// The AP-REP must carry the sequence number its reciprocal MIC consumed.
    #[test]
    fn mech_list_mic_response_sequence_is_in_ap_rep() -> Result<(), TestError> {
        // Given an authenticated non-first selection (authenticator sequence 42).
        let accepted = accept_token(&Token::Init(mic_init()?))??;
        for (options, expected) in [
            (ApRepOptions::default(), 42_u32),
            (ApRepOptions::default().with_sequence_number(Some(7)), 7_u32),
        ] {
            // When the acceptor answers with a reciprocal MIC.
            let header = accepted.ap_rep_response_header_with_confounder(
                &decode_hex(AP_REP_CONFOUNDER)?,
                &options,
            )?;
            // Then the AP-REP seq-number equals the MIC's SND_SEQ, as MIT initiators expect.
            let (part, response_mic) = response_ap_rep_part(&header)?;
            let mic = response_mic.context("response MIC")?;
            let snd_seq: [u8; 8] = mic.get(8..16).context("SND_SEQ")?.try_into()?;
            assert_eq!(u64::from_be_bytes(snd_seq), u64::from(expected));
            assert_eq!(part.seq_number, Some(expected));
        }
        // And a reply without a MIC keeps its AP-REP sequence number optional.
        let plain = accept_token(&Token::Init(acceptor_init(ObjectIdentifier::krb5())?))??;
        let header = plain.ap_rep_response_header_with_confounder(
            &decode_hex(AP_REP_CONFOUNDER)?,
            &ApRepOptions::default(),
        )?;
        let (part, mic) = response_ap_rep_part(&header)?;
        assert_eq!((part.seq_number, mic), (None, None));
        Ok(())
    }

    /// A correct checksum does not excuse a context-inconsistent token header.
    #[test]
    fn mech_list_mic_rejects_wrong_direction_flags_and_sequence() -> Result<(), TestError> {
        // Given correctly checksummed but context-inconsistent MIC headers.
        for flags in [1, 2, 4] {
            let mut init = mic_init()?;
            init.set_mech_list_mic(Some(independent_mic_flags(
                MS_THEN_KRB5,
                &decode_hex(VALID_SESSION_KEY)?,
                flags,
            )?));
            // When checked against the initiator context, then reject.
            assert!(matches!(
                accept_token(&Token::Init(init))?,
                Err(Spnego::InvalidMechListMic)
            ));
        }
        let mut init = mic_init()?;
        let mut mic = independent_mic(MS_THEN_KRB5, &decode_hex(VALID_SESSION_KEY)?, false)?;
        *mic.get_mut(15).context("sequence")? = 43;
        let mut signed = decode_hex(MS_THEN_KRB5)?;
        signed.extend_from_slice(mic.get(..16).context("MIC header")?);
        mic.truncate(16);
        mic.extend_from_slice(&AesSha1Etype::Aes256.checksum(
            &decode_hex(VALID_SESSION_KEY)?,
            &signed,
            25,
        )?);
        init.set_mech_list_mic(Some(mic));
        assert!(matches!(
            accept_token(&Token::Init(init))?,
            Err(Spnego::InvalidMechListMic)
        ));
        Ok(())
    }

    /// Bare init tokens retain the same authenticated transcript as GSS-wrapped init tokens.
    #[test]
    fn mech_list_mic_supports_bare_init_and_preserves_received_list() -> Result<(), TestError> {
        // Given a bare init instead of the GSS SPNEGO wrapper.
        let init = mic_init()?;
        let header = format!("Negotiate {}", base64_encode(&init.encode()?));
        let keytab = Keytab::parse(&decode_hex(HTTP_KEYTAB)?)?;
        let mut validator = Validator::new(&keytab).with_now(timestamp(1_893_553_447)?);
        // When accepted, then retain the actual list TLV rather than its [0] wrapper.
        let accepted = spnego::accept_sec_context_header(&mut validator, &header)?;
        assert_eq!(accepted.mech_types_der, Some(decode_hex(MS_THEN_KRB5)?));
        Ok(())
    }

    /// Selecting Kerberos after a non-Kerberos preference requires a MIC.
    #[test]
    fn acceptor_rejects_nonfirst_kerberos() -> Result<(), TestError> {
        let mut init = acceptor_init(ObjectIdentifier::krb5())?;
        init.mech_types_mut().insert(
            0,
            ObjectIdentifier::from_arcs(vec![1, 3, 6, 1, 4, 1, 311, 2, 2, 10])?,
        );
        assert!(matches!(
            accept_token(&Token::Init(init))?,
            Err(Spnego::MissingMechListMic)
        ));
        Ok(())
    }

    /// Check captured negotiation bytes and a test-key version of the same offer.
    fn accept_windows_capture(capture: &str) -> Result<(), TestError> {
        let request_header = format!("Negotiate {}", capture.trim());
        let Token::Init(mut init) = spnego::parse_negotiate_header(&request_header)? else {
            return Err("expected captured init".into());
        };
        let inner = Krb5MechToken::decode(init.mech_token().context("token")?)?;
        assert_eq!(
            init.mech_types().first(),
            Some(&ObjectIdentifier::ms_legacy_krb5())
        );
        assert_eq!(inner.oid(), &ObjectIdentifier::krb5());
        assert_eq!(init.mech_list_mic(), None);
        // When selected, then the captured AP-REQ is extracted unchanged.
        assert_eq!(init.krb5_ap_req()?, inner.message());
        // Capture keys are unavailable. Keep its offer/OID/MIC shape, but
        // substitute our test AP-REQ for full validation and reply verification.
        init.set_mech_token(
            acceptor_init(inner.oid().clone())?
                .mech_token()
                .map(|value| value.to_vec().into()),
        );
        let accepted = accept_token(&Token::Init(init))??;
        let header = accepted.ap_rep_response_header_with_confounder(
            &decode_hex(AP_REP_CONFOUNDER)?,
            &ApRepOptions::default(),
        )?;
        let Token::Resp(response) = spnego::parse_negotiate_header(&header)? else {
            return Err("expected response".into());
        };
        assert_eq!(
            response.supported_mech(),
            Some(&ObjectIdentifier::ms_legacy_krb5())
        );
        assert_eq!(response.mech_list_mic(), None);
        let reply = Krb5MechToken::decode(response.response_token().context("AP-REP")?)?;
        assert_eq!(reply.oid(), &ObjectIdentifier::krb5());
        drop(accepted.ap_req.verify_ap_rep(reply.message())?);
        Ok(())
    }

    /// Windows Server 2019 SMB offers MS-KRB5 first with a standard inner token.
    #[test]
    fn acceptor_accepts_windows_sspi_smb_capture() -> Result<(), TestError> {
        accept_windows_capture(include_str!("fixtures/win2019_sspi_init.b64"))
    }

    /// Windows LDAP offers MS-KRB5 first with a standard inner token.
    #[test]
    fn acceptor_accepts_windows_sspi_ldap_capture() -> Result<(), TestError> {
        accept_windows_capture(include_str!("fixtures/ldap_sspi_init.b64"))
    }

    /// Even an optional MIC must not be silently ignored.
    #[test]
    fn acceptor_rejects_unverified_mech_list_mic() -> Result<(), TestError> {
        for mic in [Vec::new(), vec![0xde, 0xad]] {
            let mut init = acceptor_init(ObjectIdentifier::krb5())?;
            init.set_mech_list_mic(Some(mic.into()));
            assert!(matches!(
                accept_token(&Token::Init(init))?,
                Err(Spnego::InvalidMechListMic)
            ));
        }
        Ok(())
    }

    /// A continuation cannot prove the original offer to a stateless acceptor.
    #[test]
    fn acceptor_rejects_stateless_continuation() -> Result<(), TestError> {
        let init = acceptor_init(ObjectIdentifier::krb5())?;
        let mut token = NegTokenResp::accept_completed()
            .with_response_token(init.mech_token().context("mechanism token")?.to_vec());
        for state in [
            None,
            Some(NegState::AcceptCompleted),
            Some(NegState::AcceptIncomplete),
            Some(NegState::RequestMic),
            Some(NegState::Reject),
        ] {
            token.set_neg_state(state);
            assert!(matches!(
                accept_token(&Token::Resp(token.clone()))?,
                Err(Spnego::NegotiationRequiresState)
            ));
        }
        Ok(())
    }

    /// Both supported OIDs must survive selection and the acceptor's reply.
    #[test]
    fn acceptor_preserves_selected_kerberos_oid() -> Result<(), TestError> {
        for oid in [ObjectIdentifier::krb5(), ObjectIdentifier::ms_legacy_krb5()] {
            let mut init = acceptor_init(oid.clone())?;
            init.mech_types_mut().push(ObjectIdentifier::spnego());
            let accepted = accept_token(&Token::Init(init))?.context("accepted Kerberos")?;
            let header = accepted
                .ap_rep_response_header_with_confounder(
                    &decode_hex(AP_REP_CONFOUNDER)?,
                    &ApRepOptions::default(),
                )
                .context("AP-REP response")?;
            let Token::Resp(response) =
                spnego::parse_negotiate_header(&header).context("response parses")?
            else {
                return Err("expected response".into());
            };
            assert_eq!(response.supported_mech(), Some(&oid));
            let krb5 = Krb5MechToken::decode(response.response_token().context("AP-REP token")?)
                .context("AP-REP mechanism")?;
            assert_eq!(krb5.oid(), &oid);
        }
        Ok(())
    }

    /// Unsupported offers and selections must return the mechanism error, not authenticate.
    #[test]
    fn acceptor_rejects_unsupported_mechanisms() -> Result<(), TestError> {
        let mut init = acceptor_init(ObjectIdentifier::krb5())?;
        let unsupported = ObjectIdentifier::from_arcs(vec![1, 3, 6, 1, 4, 1, 311, 2, 2, 10])?;
        init.set_mech_types(vec![unsupported.clone()]);
        let mut resp = NegTokenResp::accept_completed()
            .with_response_token(init.mech_token().context("mechanism token")?.to_vec());
        resp.set_supported_mech(Some(unsupported.clone()));
        for token in [Token::Init(init), Token::Resp(resp)] {
            assert!(
                matches!(accept_token(&token)?, Err(Spnego::UnsupportedMechanism(oid)) if oid == unsupported)
            );
        }
        Ok(())
    }

    /// A sole Kerberos alias offer still accepts a standard Kerberos optimistic token.
    #[test]
    fn acceptor_accepts_optimistic_kerberos_alias() -> Result<(), TestError> {
        let mut init = acceptor_init(ObjectIdentifier::krb5())?;
        init.set_mech_types(vec![ObjectIdentifier::ms_legacy_krb5()]);
        let accepted = accept_token(&Token::Init(init))??;
        assert_eq!(
            accepted.selected_mechanism,
            ObjectIdentifier::ms_legacy_krb5()
        );
        Ok(())
    }

    /// Raw MS Kerberos headers keep their OID when adapted to the SPNEGO shape.
    #[test]
    fn acceptor_accepts_raw_ms_kerberos() -> Result<(), TestError> {
        let init = acceptor_init(ObjectIdentifier::ms_legacy_krb5())?;
        let header = format!(
            "Negotiate {}",
            base64_encode(init.mech_token().context("mechanism token")?)
        );
        let keytab = Keytab::parse(&decode_hex(HTTP_KEYTAB)?).context("keytab parses")?;
        let mut validator = Validator::new(&keytab).with_now(timestamp(1_893_553_447)?);
        let accepted = spnego::accept_sec_context_header(&mut validator, &header)?;
        assert_eq!(
            accepted.selected_mechanism,
            ObjectIdentifier::ms_legacy_krb5()
        );
        Ok(())
    }

    /// Rejected negotiation metadata must not consume a valid AP-REQ in the replay cache.
    #[test]
    fn acceptor_rejection_preserves_replay_cache() -> Result<(), TestError> {
        let mut init = acceptor_init(ObjectIdentifier::krb5())?;
        init.set_mech_list_mic(Some(vec![0xde, 0xad].into()));
        let bad = spnego::negotiate_header(&Token::Init(init.clone()))?;
        init.set_mech_list_mic(None);
        let good = spnego::negotiate_header(&Token::Init(init))?;
        let keytab = Keytab::parse(&decode_hex(HTTP_KEYTAB)?).context("keytab parses")?;
        let mut validator = Validator::new(&keytab).with_now(timestamp(1_893_553_447)?);
        assert!(matches!(
            spnego::accept_sec_context_header(&mut validator, &bad),
            Err(Spnego::InvalidMechListMic)
        ));
        let accepted = spnego::accept_sec_context_header(&mut validator, &good)?;
        assert_eq!(accepted.ap_req.client().name(), "testuser1");
        Ok(())
    }

    fn acceptor_init(oid: ObjectIdentifier) -> Result<NegTokenInit, TestError> {
        let mut krb5 = Krb5MechToken::ap_req(gss_ap_req_fixture()?);
        krb5.set_oid(oid.clone());
        let mut init = NegTokenInit::krb5(krb5.encode().context("AP-REQ token")?);
        init.set_mech_types(vec![oid]);
        Ok(init)
    }

    fn accept_token(token: &Token) -> Result<Result<spnego::AcceptedContext, Spnego>, TestError> {
        let header = spnego::negotiate_header(token).context("header encodes")?;
        let keytab = Keytab::parse(&decode_hex(HTTP_KEYTAB)?).context("keytab parses")?;
        let mut validator = Validator::new(&keytab).with_now(timestamp(1_893_553_447)?);
        Ok(spnego::accept_sec_context_header(&mut validator, &header))
    }

    /// Missing GSS fields must not turn ordinary Kerberos into a GSS context.
    #[test]
    fn gss_authenticator_requires_checksum() -> Result<(), TestError> {
        let token = authenticator_token(None, Some(42))?;
        assert!(matches!(
            accept_token(&token)?,
            Err(Spnego::MissingAuthenticatorChecksum)
        ));
        Ok(())
    }

    /// A sequence is mandatory even without the GSS sequencing flag.
    #[test]
    fn gss_authenticator_requires_sequence() -> Result<(), TestError> {
        let token = authenticator_token(Some(gss_checksum(&[])), None)?;
        assert!(matches!(
            accept_token(&token)?,
            Err(Spnego::MissingAuthenticatorSequence)
        ));
        Ok(())
    }

    /// A generic checksum cannot stand in for the GSS checksum type.
    #[test]
    fn gss_authenticator_rejects_wrong_checksum_type() -> Result<(), TestError> {
        let mut checksum = gss_checksum(&[]);
        checksum.r#type = 16_i32;
        let token = authenticator_token(Some(checksum), Some(42))?;
        assert!(matches!(
            accept_token(&token)?,
            Err(Spnego::InvalidAuthenticatorChecksum)
        ));
        Ok(())
    }

    /// Every truncation of the mandatory checksum header is rejected.
    #[test]
    fn gss_authenticator_rejects_short_checksum() -> Result<(), TestError> {
        let valid = spnego::authenticator_checksum(&[]);
        for length in 0..24 {
            let bytes = valid.get(..length).context("checksum prefix")?;
            let checksum = rasn_kerberos::Checksum {
                r#type: 0x8003,
                checksum: bytes.to_vec().into(),
            };
            let token = authenticator_token(Some(checksum), Some(42))?;
            assert!(
                matches!(
                    accept_token(&token)?,
                    Err(Spnego::InvalidAuthenticatorChecksum)
                ),
                "length {length}"
            );
        }
        Ok(())
    }

    /// Bnd is exactly sixteen bytes, with its length encoded little-endian.
    #[test]
    fn gss_authenticator_rejects_invalid_binding_length() -> Result<(), TestError> {
        for length in [0_u32, 15, 17, 0x1000_0000, u32::MAX] {
            let mut bytes = length.to_le_bytes().to_vec();
            bytes.extend_from_slice(&[0; 20]);
            let checksum = rasn_kerberos::Checksum {
                r#type: 0x8003,
                checksum: bytes.into(),
            };
            let token = authenticator_token(Some(checksum), Some(42))?;
            assert!(
                matches!(
                    accept_token(&token)?,
                    Err(Spnego::InvalidAuthenticatorChecksum)
                ),
                "Bnd length {length}"
            );
        }
        Ok(())
    }

    /// Delegation framing must contain option 1 and the declared credential bytes.
    #[test]
    fn gss_authenticator_rejects_malformed_delegation() -> Result<(), TestError> {
        for suffix in [
            vec![],
            vec![1, 0, 0],
            vec![0, 0, 0, 0],
            vec![1, 0, 1, 0],
            vec![1, 0, 0, 0],
            vec![1, 0, 1, 0, 0xff],
        ] {
            let mut bytes = spnego::authenticator_checksum(&[]);
            *bytes.get_mut(20).context("flags byte")? = 1;
            bytes.extend_from_slice(&suffix);
            let checksum = rasn_kerberos::Checksum {
                r#type: 0x8003,
                checksum: bytes.into(),
            };
            let token = authenticator_token(Some(checksum), Some(42))?;
            assert!(
                matches!(
                    accept_token(&token)?,
                    Err(Spnego::InvalidAuthenticatorChecksum)
                ),
                "suffix {suffix:?}"
            );
        }
        Ok(())
    }

    /// A no-bindings acceptor ignores Bnd, unknown flags and trailing extensions.
    #[test]
    fn gss_authenticator_accepts_extensions_and_zero_sequence() -> Result<(), TestError> {
        let mut bytes = 16_u32.to_le_bytes().to_vec();
        bytes.extend_from_slice(&[0xa5; 16]);
        bytes.extend_from_slice(&0x8000_0000_u32.to_le_bytes());
        bytes.extend_from_slice(&[0xde, 0xad]);
        let checksum = rasn_kerberos::Checksum {
            r#type: 0x8003,
            checksum: bytes.into(),
        };
        let token = authenticator_token(Some(checksum), Some(0))?;
        let accepted = accept_token(&token)?.context("GSS context")?;
        assert_eq!(accepted.ap_req.sequence_number(), Some(0));
        Ok(())
    }

    /// GSS rejection must precede replay insertion and leave generic Kerberos usable.
    #[test]
    fn gss_authenticator_rejection_preserves_generic_validation() -> Result<(), TestError> {
        let token = authenticator_token(None, None)?;
        let header = spnego::negotiate_header(&token)?;
        let bytes = token.krb5_ap_req()?;
        let keytab = Keytab::parse(&decode_hex(HTTP_KEYTAB)?)?;
        let mut validator = Validator::new(&keytab).with_now(timestamp(1_893_553_447)?);
        assert!(matches!(
            spnego::accept_sec_context_header(&mut validator, &header),
            Err(Spnego::MissingAuthenticatorChecksum)
        ));
        assert!(
            validator.replay_cache_mut().is_empty(),
            "GSS rejection must not record a replay"
        );
        let accepted = validator.validate_ap_req(&bytes)?;
        assert_eq!(accepted.client().name(), "testuser1");
        assert_eq!(accepted.sequence_number(), None);
        Ok(())
    }

    /// Deterministic construction must not emit a nonconforming GSS authenticator.
    #[test]
    fn gss_authenticator_deterministic_builder_requires_sequence() -> Result<(), TestError> {
        let session = service_ticket_session_from_valid_ap_req()?;
        let result = spnego::init_sec_context_with_confounder(
            &session,
            InitiatorContextOptions::new(),
            timestamp(1_893_553_447)?,
            123_456,
            &decode_hex(AP_REP_CONFOUNDER)?,
        );
        assert!(matches!(result, Err(Spnego::MissingAuthenticatorSequence)));
        Ok(())
    }

    /// Delegation without a credential must fail for both split and combined flag masks.
    #[test]
    fn initiator_rejects_delegation_without_credentials() -> Result<(), TestError> {
        let session = service_ticket_session_from_valid_ap_req()?;
        for flags in [
            vec![spnego::CONTEXT_FLAG_DELEG],
            vec![spnego::CONTEXT_FLAG_DELEG, CONTEXT_FLAG_INTEG],
            vec![spnego::CONTEXT_FLAG_DELEG | CONTEXT_FLAG_INTEG],
        ] {
            let options = InitiatorContextOptions::new()
                .with_sequence_number(Some(42))
                .with_context_flags(flags);
            let result = spnego::init_sec_context_with_confounder(
                &session,
                options,
                timestamp(1_893_553_447)?,
                123_456,
                &decode_hex(AP_REP_CONFOUNDER)?,
            );
            assert!(
                matches!(result, Err(Spnego::DelegationRequiresCredential)),
                "delegation must not emit an AP-REQ without KRB-CRED"
            );
        }
        Ok(())
    }

    /// The random builder and authorization-header wrapper must also reject delegation.
    #[test]
    fn initiator_wrappers_reject_delegation() -> Result<(), TestError> {
        let session = service_ticket_session_from_valid_ap_req()?;
        let options = InitiatorContextOptions::new()
            .with_context_flags(vec![spnego::CONTEXT_FLAG_DELEG | CONTEXT_FLAG_INTEG]);
        assert!(matches!(
            spnego::init_sec_context(&session, options.clone()),
            Err(Spnego::DelegationRequiresCredential)
        ));
        assert!(matches!(
            spnego::authorization_header(&session, options),
            Err(Spnego::DelegationRequiresCredential)
        ));
        Ok(())
    }

    /// Nondelegating split and combined masks remain acceptable on the wire.
    #[test]
    fn initiator_preserves_nondelegating_flag_masks() -> Result<(), TestError> {
        let session = service_ticket_session_from_valid_ap_req()?;
        for flags in [
            vec![],
            vec![CONTEXT_FLAG_INTEG, CONTEXT_FLAG_CONF],
            vec![CONTEXT_FLAG_INTEG | CONTEXT_FLAG_CONF],
        ] {
            let expected = spnego::authenticator_checksum(&flags);
            let context = spnego::init_sec_context_with_confounder(
                &session,
                InitiatorContextOptions::new()
                    .with_sequence_number(Some(42))
                    .with_context_flags(flags),
                timestamp(1_893_553_447)?,
                123_456,
                &decode_hex(AP_REP_CONFOUNDER)?,
            )?;
            let authenticator = ap_req::decrypt_ap_req_authenticator(
                context.ap_req_ref(),
                session.session_key(),
                11,
            )?;
            assert_eq!(
                authenticator
                    .cksum
                    .context("GSS checksum")?
                    .checksum
                    .as_ref(),
                expected.as_slice()
            );
            let accepted =
                accept_token(context.spnego_token())?.context("nondelegating context")?;
            assert_eq!(accepted.ap_req.sequence_number(), Some(42));
        }
        Ok(())
    }

    /// The raw prefix never invents delegation fields and merges split flags as a bit mask.
    #[test]
    fn authenticator_checksum_delegation_prefix_is_mask_independent() -> Result<(), TestError> {
        let split =
            spnego::authenticator_checksum(&[spnego::CONTEXT_FLAG_DELEG, CONTEXT_FLAG_INTEG]);
        let combined =
            spnego::authenticator_checksum(&[spnego::CONTEXT_FLAG_DELEG | CONTEXT_FLAG_INTEG]);
        let mut expected = vec![0x10];
        expected.extend_from_slice(&[0; 19]);
        expected.extend_from_slice(&[0x21, 0, 0, 0]);
        (split.len() == 24).ok_or("delegation prefix must contain exactly 24 bytes")?;
        assert_eq!(split, expected);
        assert_eq!(combined, expected);
        Ok(())
    }

    /// Raw Kerberos headers must pass the same GSS checks as SPNEGO headers.
    #[test]
    fn gss_authenticator_checks_raw_kerberos_headers() -> Result<(), TestError> {
        let Token::Init(init) = authenticator_token(None, Some(42))? else {
            return Err("expected init".into());
        };
        let header = format!(
            "Negotiate {}",
            base64_encode(init.mech_token().context("token")?)
        );
        let keytab = Keytab::parse(&decode_hex(HTTP_KEYTAB)?)?;
        let mut validator = Validator::new(&keytab).with_now(timestamp(1_893_553_447)?);
        assert!(matches!(
            spnego::accept_sec_context_header(&mut validator, &header),
            Err(Spnego::MissingAuthenticatorChecksum)
        ));
        Ok(())
    }

    /// GSS checks do not replace the authenticator's cryptographic integrity check.
    #[test]
    fn gss_authenticator_rejects_corrupted_ciphertext() -> Result<(), TestError> {
        let token = authenticator_token(Some(gss_checksum(&[])), Some(42))?;
        let mut ap_req = decode_ap_req(&token.krb5_ap_req()?)?;
        let mut cipher = ap_req.authenticator.cipher.to_vec();
        *cipher.first_mut().context("ciphertext")? ^= 1;
        ap_req.authenticator.cipher = cipher.into();
        let corrupted = Token::Init(NegTokenInit::krb5(
            Krb5MechToken::ap_req(ap_req::encode(&ap_req)?).encode()?,
        ));
        assert!(matches!(
            accept_token(&corrupted)?,
            Err(Spnego::Service(Service::Crypto(_)))
        ));
        Ok(())
    }

    /// Delegation framing permits extension bytes beyond the declared KRB-CRED.
    #[test]
    fn gss_authenticator_accepts_delegation_envelope_and_extensions() -> Result<(), TestError> {
        let session = service_ticket_session_from_valid_ap_req()?;
        let credential = rasn_kerberos::KrbCred {
            pvno: 5_i32.into(),
            msg_type: 22_i32.into(),
            tickets: vec![der::decode(session.ticket())?],
            enc_part: rasn_kerberos::EncryptedData {
                etype: 18,
                kvno: None,
                cipher: vec![0; 32].into(),
            },
        };
        let encoded_credential = der::encode(&credential)?;
        let mut bytes = spnego::authenticator_checksum(&[]);
        *bytes.get_mut(20).context("flags byte")? = 1;
        bytes.extend_from_slice(&1_u16.to_le_bytes());
        bytes.extend_from_slice(&u16::try_from(encoded_credential.len())?.to_le_bytes());
        bytes.extend_from_slice(&encoded_credential);
        bytes.extend_from_slice(&[0xde, 0xad]);
        let token = authenticator_token(
            Some(rasn_kerberos::Checksum {
                r#type: 0x8003,
                checksum: bytes.into(),
            }),
            Some(u32::MAX),
        )?;
        let accepted = accept_token(&token)?.context("framed delegation")?;
        assert_eq!(accepted.ap_req.sequence_number(), Some(u32::MAX));
        Ok(())
    }

    fn gss_checksum(flags: &[u32]) -> rasn_kerberos::Checksum {
        rasn_kerberos::Checksum {
            r#type: 0x8003,
            checksum: spnego::authenticator_checksum(flags).into(),
        }
    }

    fn gss_ap_req_fixture() -> Result<Vec<u8>, TestError> {
        let original = decode_ap_req(&decode_hex(VALID_AP_REQ)?)?;
        let key = EncryptionKey::new(18, decode_hex(VALID_SESSION_KEY)?);
        let mut authenticator = ap_req::decrypt_ap_req_authenticator(&original, &key, 11)?;
        authenticator.cksum = Some(gss_checksum(&[]));
        authenticator.seq_number = Some(42);
        authenticator.subkey = None;
        let message = ap_req::build_ap_req_with_confounder(
            original.ticket,
            original.ap_options,
            &authenticator,
            &key,
            11,
            original.authenticator.kvno,
            &decode_hex(AP_REP_CONFOUNDER)?,
        )?;
        Ok(ap_req::encode(&message)?)
    }

    fn authenticator_token(
        checksum: Option<rasn_kerberos::Checksum>,
        sequence: Option<u32>,
    ) -> Result<Token, TestError> {
        let built = build_ap_req_with_confounder(
            &service_ticket_session_from_valid_ap_req()?,
            ApReq::new()
                .with_checksum(checksum)
                .with_sequence_number(sequence),
            timestamp(1_893_553_447)?,
            123_456,
            &decode_hex(AP_REP_CONFOUNDER)?,
        )?;
        Ok(Token::Init(NegTokenInit::krb5(
            Krb5MechToken::ap_req(built.der().to_vec()).encode()?,
        )))
    }

    /// Returns the instant `seconds` after the Unix epoch.
    fn timestamp(seconds: u64) -> Result<SystemTime, TestError> {
        UNIX_EPOCH
            .checked_add(Duration::from_secs(seconds))
            .context("timestamp is representable")
    }

    /// Encodes bytes as standard padded base64.
    fn base64_encode(bytes: &[u8]) -> String {
        STANDARD.encode(bytes)
    }

    /// Decodes a hex fixture.
    fn decode_hex(input: &str) -> Result<Vec<u8>, FromHexError> {
        hex::decode(input)
    }

    /// Encodes bytes as lowercase hex.
    fn hex_encode(bytes: &[u8]) -> String {
        hex::encode(bytes)
    }
}

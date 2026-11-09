//! Credential-bearing request options and password frames.
// allow: SIZE_OK - this fixture module covers the message-feature credential graph with independent byte patterns.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
pub(super) mod tests {
    use core::error::Error;
    #[cfg(feature = "tower")]
    use std::time::SystemTime;
    use std::time::UNIX_EPOCH;

    use rasn::der;
    #[cfg(feature = "http")]
    use rskrb5_ng::http::ClientNegotiateResponse;
    #[cfg(feature = "tower")]
    use rskrb5_ng::http::set_authorization_header;
    #[cfg(feature = "tower")]
    use rskrb5_ng::keytab::Keytab;
    #[cfg(feature = "spnego")]
    use rskrb5_ng::spnego::{self, Krb5MechToken, NegTokenInit, Token};
    use rskrb5_ng::{
        ap_rep,
        client::{
            Password, ReferralTgsResult, TgsRequestParts,
            build_tgs_req_for_realm_with_confounder_and_subkey, build_tgt_as_req,
            kpasswd::verify_kpasswd_ap_rep,
            options::{ApReq, AsReq, TgsReq},
            principal::Principal,
        },
        error::{Any as AnyError, Client as ClientError},
        kadmin::{
            ChangePasswdData, PasswordEncryption, Reply, Request,
            build_change_password_request_with_confounder,
        },
        keytab::EncryptionKey,
        krb_error, krb_priv,
        krb_priv::{EncKrbPrivPartOptions, ipv4_host_address},
        messages::KrbErrorInfo,
        pac::NtlmSupplementalCredential,
    };

    use crate::tests::{pattern, redacted, render};
    #[cfg(feature = "tower")]
    use crate::tokens::tests::CredentialService;

    pub(crate) fn run_audit() -> Result<(), Box<dyn Error>> {
        ntlm_hash_fields_own_erasure()?;
        options_redact_each_credential_field()?;
        password_frames_redact_each_credential_field()?;
        password_owners_redact_live_bytes()?;
        pac_encrypted_credentials_are_redacted()?;
        pac_supplemental_credentials_are_redacted()?;
        pac_validation_records_redact_credentials()?;
        kdc_diagnostics_redact_credential_payloads()?;
        sessions_and_validators_redact_credentials()?;
        message_wrappers_redact_credentials()?;
        #[cfg(feature = "tokio")]
        tokio_clients_redact_passwords()?;
        authenticated_service_owners_redact_credentials()
    }

    /// Tokio clients and their credential enum redact a retained password.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_clients_redact_passwords() -> Result<(), Box<dyn Error>> {
        use rskrb5_ng::{
            Config,
            client::{Tokio, TokioClientCredentials, transport::KdcProtocol},
        };
        let secret = pattern(65);
        redacted(
            &TokioClientCredentials::Password(secret.clone().into()),
            &[&secret],
        );
        let client = Tokio::with_password(
            Config::new(),
            KdcProtocol::Tcp,
            Principal::user("EXAMPLE.COM", "alice"),
            secret.clone(),
        );
        redacted(&client, &[&secret]);
        assert!(
            !render(&client)?.is_empty(),
            "client diagnostics remain useful"
        );
        Ok(())
    }

    /// Hash access is borrowed and diagnostics redact both independently owned hashes.
    #[test]
    fn ntlm_hash_fields_own_erasure() -> Result<(), Box<dyn Error>> {
        let mut wire = vec![0; 4];
        wire.extend_from_slice(&3_u32.to_le_bytes());
        wire.extend_from_slice(&pattern(65));
        wire.extend_from_slice(&pattern(81));
        let credential = NtlmSupplementalCredential::parse(&wire)?;
        redacted(&credential, &[&pattern(65), &pattern(81)]);
        assert_eq!(
            credential.lm_password().map(<[u8; 16]>::as_slice),
            Some(pattern(65).as_slice())
        );
        assert_eq!(
            credential.nt_password().map(<[u8; 16]>::as_slice),
            Some(pattern(81).as_slice())
        );
        Ok(())
    }

    /// Each option credential field is independently populated, including nested ASN.1 bytes.
    #[test]
    fn options_redact_each_credential_field() -> Result<(), Box<dyn Error>> {
        let preauth = pattern(65);
        let ticket = pattern(81);
        let checksum = pattern(97);
        let subkey = pattern(113);
        let data = vec![rasn_kerberos::PaData {
            r#type: 1,
            value: preauth.clone().into(),
        }];
        let frame = Request::parse(&hex::decode(
            include_str!("../fixtures/kpasswd-request.hex").trim(),
        )?)?;
        let (mut ap_req, _) = frame.into_parts();
        ap_req.ticket.enc_part.cipher = ticket.clone().into();
        redacted(
            &AsReq::new(UNIX_EPOCH, 42).with_padata(data.clone()),
            &[&preauth],
        );
        let built_as = build_tgt_as_req(
            Principal::user("EXAMPLE.COM", "alice"),
            AsReq::new(UNIX_EPOCH, 42).with_padata(data.clone()),
        )?;
        redacted(&built_as, &[&preauth]);
        redacted(
            &TgsReq::new(UNIX_EPOCH, 43)
                .with_padata(data)
                .with_additional_tickets(vec![ap_req.ticket]),
            &[&preauth, &ticket],
        );
        redacted(
            &ApReq::new()
                .with_checksum(Some(rasn_kerberos::Checksum {
                    r#type: 0x8003,
                    checksum: checksum.clone().into(),
                }))
                .with_subkey(Some(EncryptionKey::new(17, subkey.clone()))),
            &[&checksum, &subkey],
        );
        redacted(
            &TgsRequestParts::new(
                TgsReq::new(UNIX_EPOCH, 42),
                &preauth,
                &EncryptionKey::new(17, subkey.clone()),
            ),
            &[&preauth, &subkey],
        );
        Ok(())
    }

    /// Password request frames cannot disclose either protected component.
    #[test]
    fn password_frames_redact_each_credential_field() -> Result<(), Box<dyn Error>> {
        let fixture = Request::parse(&hex::decode(
            include_str!("../fixtures/kpasswd-request.hex").trim(),
        )?)?;
        let ticket = pattern(65);
        let authenticator = pattern(81);
        let private = pattern(97);
        let (mut authentication, mut krb_priv) = fixture.into_parts();
        authentication.ticket.enc_part.cipher = ticket.clone().into();
        authentication.authenticator.cipher = authenticator.clone().into();
        krb_priv.enc_part.cipher = private.clone().into();
        let frame = Request::new(authentication, krb_priv);
        redacted(&frame, &[&ticket, &authenticator, &private]);
        let password = ChangePasswdData::new(Password::from_vec(pattern(33)));
        let reply_key = pattern(49);
        let built = build_change_password_request_with_confounder(
            frame.ap_req().clone(),
            &password,
            EncryptionKey::new(17, reply_key.clone()),
            EncKrbPrivPartOptions::new(ipv4_host_address([127, 0, 0, 1])),
            &pattern(17),
        )?;
        redacted(&built, &[&ticket, &authenticator, &reply_key]);
        let encryption = PasswordEncryption::new(
            EncryptionKey::new(17, reply_key.clone()),
            &ticket,
            &authenticator,
        );
        redacted(&encryption, &[&reply_key, &ticket, &authenticator]);
        let mut reply_wire = vec![0; 6];
        let ap_rep = rasn_kerberos::ApRep {
            pvno: 5_i32.into(),
            msg_type: 15_i32.into(),
            enc_part: rasn_kerberos::EncryptedData {
                etype: 17,
                kvno: None,
                cipher: authenticator.clone().into(),
            },
        };
        let ap_bytes = der::encode(&ap_rep)?;
        let private_bytes = der::encode(frame.krb_priv())?;
        let len = u16::try_from(
            6_usize
                .saturating_add(ap_bytes.len())
                .saturating_add(private_bytes.len()),
        )?;
        reply_wire
            .get_mut(..2)
            .ok_or("length")?
            .copy_from_slice(&len.to_be_bytes());
        reply_wire
            .get_mut(2..4)
            .ok_or("version")?
            .copy_from_slice(&1_u16.to_be_bytes());
        reply_wire
            .get_mut(4..6)
            .ok_or("AP length")?
            .copy_from_slice(&u16::try_from(ap_bytes.len())?.to_be_bytes());
        reply_wire.extend_from_slice(&ap_bytes);
        reply_wire.extend_from_slice(&private_bytes);
        redacted(&Reply::parse(&reply_wire)?, &[&authenticator, &private]);
        Ok(())
    }

    /// Password owners redact a live nonempty password rather than an empty fixture.
    #[test]
    fn password_owners_redact_live_bytes() -> Result<(), Box<dyn Error>> {
        let secret = pattern(65);
        let password = Password::from_vec(secret.clone());
        redacted(&password, &[&secret]);
        assert!(
            !render(&password)?.is_empty(),
            "password diagnostics remain useful"
        );
        let payload = ChangePasswdData::new(password);
        redacted(payload.new_passwd(), &[&secret]);
        redacted(&payload, &[&secret]);
        Ok(())
    }

    /// Opaque encrypted PAC credentials are diagnostic secrets as well as plaintext hashes.
    #[test]
    fn pac_encrypted_credentials_are_redacted() -> Result<(), Box<dyn Error>> {
        use rskrb5_ng::pac::CredentialsInfo;
        let secret = pattern(65);
        let mut wire = vec![0; 4];
        wire.extend_from_slice(&17_u32.to_le_bytes());
        wire.extend_from_slice(&secret);
        redacted(&CredentialsInfo::parse(&wire)?, &[&secret]);
        Ok(())
    }

    /// Supplemental package bytes are redacted directly and through credential data.
    #[test]
    fn pac_supplemental_credentials_are_redacted() -> Result<(), Box<dyn Error>> {
        use rskrb5_ng::pac::CredentialData;
        let mut wire = vec![1, 0x10, 8, 0, 0xcc, 0xcc, 0xcc, 0xcc];
        wire.extend_from_slice(&32_u32.to_le_bytes());
        wire.extend_from_slice(&0_u32.to_le_bytes());
        wire.extend_from_slice(&0x0002_0000_u32.to_le_bytes());
        wire.extend_from_slice(&1_u32.to_le_bytes());
        wire.extend_from_slice(&1_u32.to_le_bytes());
        wire.extend_from_slice(&[0; 20]);
        let mut data = CredentialData::parse(&wire)?;
        let secret = pattern(65);
        data.credentials_mut()
            .first_mut()
            .ok_or("package")?
            .set_credentials(secret.clone().into())?;
        redacted(data.credentials().first().ok_or("package")?, &[&secret]);
        redacted(&data, &[&secret]);
        Ok(())
    }

    /// PAC containers and validation records redact the embedded session key.
    #[test]
    fn pac_validation_records_redact_credentials() -> Result<(), Box<dyn Error>> {
        use rskrb5_ng::pac::{KerbValidationInfo, Pac};
        let secret = pattern(65);
        let mut wire = vec![0; 240];
        wire.get_mut(..8)
            .ok_or("header")?
            .copy_from_slice(&[1, 0x10, 8, 0, 0xcc, 0xcc, 0xcc, 0xcc]);
        wire.get_mut(8..12)
            .ok_or("extent")?
            .copy_from_slice(&224_u32.to_le_bytes());
        wire.get_mut(16..20)
            .ok_or("pointer")?
            .copy_from_slice(&1_u32.to_le_bytes());
        wire.get_mut(140..156)
            .ok_or("key")?
            .copy_from_slice(&secret);
        let info = KerbValidationInfo::parse(&wire)?;
        redacted(&info, &[&secret]);
        redacted(info.user_session_key(), &[&secret]);
        let mut container = vec![0; 24];
        container
            .get_mut(..4)
            .ok_or("count")?
            .copy_from_slice(&1_u32.to_le_bytes());
        container
            .get_mut(8..12)
            .ok_or("kind")?
            .copy_from_slice(&1_u32.to_le_bytes());
        container
            .get_mut(12..16)
            .ok_or("size")?
            .copy_from_slice(&240_u32.to_le_bytes());
        container
            .get_mut(16..24)
            .ok_or("offset")?
            .copy_from_slice(&24_u64.to_le_bytes());
        container.extend_from_slice(&wire);
        redacted(&Pac::parse_and_process(&container)?, &[&secret]);
        Ok(())
    }

    /// KDC diagnostics cannot disclose opaque payloads or nested padata.
    #[test]
    fn kdc_diagnostics_redact_credential_payloads() -> Result<(), Box<dyn Error>> {
        use rskrb5_ng::client::KdcError;
        let payload = pattern(65);
        let preauth = pattern(81);
        let error = KdcError::new(UNIX_EPOCH, 0, 25, Principal::user("EXAMPLE.COM", "kdc"))
            .with_e_data(Some(payload.clone().into()))
            .with_method_data(vec![rasn_kerberos::PaData {
                r#type: 1,
                value: preauth.clone().into(),
            }]);
        redacted(&error, &[&payload, &preauth]);
        redacted(
            &ClientError::Kdc(Box::new(error.clone())),
            &[&payload, &preauth],
        );
        redacted(
            &AnyError::Client(ClientError::Kdc(Box::new(error.clone()))),
            &[&payload, &preauth],
        );
        let fixture = krb_error::decode(&hex::decode(concat!(
            "7E60305EA003020105A10302011EA305020301E240A411180F3139393430363130303630",
            "3331375AA505020301E240A60302013CA9101B0E415448454E412E4D49542E454455AA1A",
            "3018A003020101A111300F1B066866747361691B056578747261",
        ))?)?;
        let mut wire = fixture;
        wire.e_data = Some(payload.clone().into());
        redacted(&KrbErrorInfo::from_rasn(&wire)?, &[&payload]);
        assert!(render(&error)?.contains("25"), "retain numeric error code");
        Ok(())
    }

    /// Session results, clients and validators retain real keys without diagnostic disclosure.
    #[test]
    fn sessions_and_validators_redact_credentials() -> Result<(), Box<dyn Error>> {
        use rskrb5_ng::{
            client::{
                AsRepSession,
                kpasswd::{RequestOptions, build_kpasswd_request_with_confounders},
            },
            keytab::{self, Keytab},
            service::Validator,
            ticket,
        };
        let frame = Request::parse(&hex::decode(
            include_str!("../fixtures/kpasswd-request.hex").trim(),
        )?)?;
        let key = pattern(65);
        let ticket_bytes = ticket::encode(&frame.ap_req().ticket)?;
        let session = AsRepSession::new(
            Principal::user("TEST.GOKRB5", "testuser1"),
            Principal::new("TEST.GOKRB5", 2, ["kadmin", "changepw"]),
            EncryptionKey::new(17, key.clone()),
            ticket_bytes.clone().into(),
            [0; 4],
            UNIX_EPOCH,
            UNIX_EPOCH,
        );
        redacted(&session, &[&key, &ticket_bytes]);
        redacted(
            &ReferralTgsResult::new(session.clone(), vec![session.clone()]),
            &[&key, &ticket_bytes],
        );
        let fast = build_tgs_req_for_realm_with_confounder_and_subkey(
            &session,
            "TEST.GOKRB5",
            Principal::new("TEST.GOKRB5", 2, ["HTTP", "backend"]),
            TgsRequestParts::new(
                TgsReq::new(UNIX_EPOCH, 42),
                &pattern(33),
                &EncryptionKey::new(17, pattern(81)),
            ),
        )?;
        redacted(&fast, &[&key, &ticket_bytes, &pattern(81)]);
        redacted(fast.request(), &[&key, &ticket_bytes, &pattern(81)]);
        let mut tab = Keytab::new();
        tab.entries_mut().push(keytab::Entry::new(
            keytab::Principal::new("TEST.GOKRB5", 1, ["alice"]),
            1,
            1,
            EncryptionKey::new(17, key.clone()),
            1,
        ));
        redacted(&Validator::new(&tab), &[&key]);
        let reply_key = pattern(81);
        let options = RequestOptions::new(UNIX_EPOCH, 0, 1, ipv4_host_address([127, 0, 0, 1]));
        let built = build_kpasswd_request_with_confounders(
            &session,
            &ChangePasswdData::new(Password::from_vec(pattern(97))),
            EncryptionKey::new(17, reply_key.clone()),
            &options,
            &pattern(17),
            &pattern(33),
        )?;
        redacted(&built, &[&key, &ticket_bytes, &reply_key]);
        redacted(built.ap_req(), &[&key, &ticket_bytes, &reply_key]);
        let acceptor = pattern(113);
        let part = rasn_kerberos::EncApRepPart {
            ctime: rasn_kerberos::KerberosTime(
                chrono::DateTime::from_timestamp(0, 0)
                    .ok_or("epoch")?
                    .into(),
            ),
            cusec: 0_i32.into(),
            subkey: Some(rasn_kerberos::EncryptionKey {
                r#type: 17,
                value: acceptor.clone().into(),
            }),
            seq_number: Some(1),
        };
        let ap_rep = ap_rep::build_ap_rep_with_confounder(
            &part,
            built.ap_req().session_key(),
            None,
            &[0; 16],
        )?;
        let ap_bytes = ap_rep::encode(&ap_rep)?;
        let private = krb_priv::encode(built.request().krb_priv())?;
        let mut wire = u16::try_from(
            6_usize
                .saturating_add(ap_bytes.len())
                .saturating_add(private.len()),
        )?
        .to_be_bytes()
        .to_vec();
        wire.extend_from_slice(&1_u16.to_be_bytes());
        wire.extend_from_slice(&u16::try_from(ap_bytes.len())?.to_be_bytes());
        wire.extend_from_slice(&ap_bytes);
        wire.extend_from_slice(&private);
        let reply = Reply::parse(&wire)?;
        redacted(
            &verify_kpasswd_ap_rep(&reply, &built)?.ok_or("verified reply")?,
            &[&acceptor],
        );
        Ok(())
    }

    /// Message wrappers must not print opaque ciphertext or authentication checksums.
    #[test]
    fn message_wrappers_redact_credentials() -> Result<(), Box<dyn Error>> {
        use rskrb5_ng::messages::{EncryptedData, PaForUser, PaReqEncPaRep};
        let cipher = pattern(65);
        let checksum = pattern(81);
        redacted(&EncryptedData::new(17, cipher.clone().into()), &[&cipher]);
        redacted(
            &PaReqEncPaRep::new(15, checksum.clone().into()),
            &[&checksum],
        );
        let principal = rasn_kerberos::PrincipalName {
            r#type: 1,
            string: vec![rasn_kerberos::KerberosString::try_from("alice")?],
        };
        let for_user = PaForUser::new(
            principal,
            rasn_kerberos::KerberosString::try_from("EXAMPLE.COM")?,
            rasn_kerberos::Checksum {
                r#type: -138,
                checksum: checksum.clone().into(),
            },
            rasn_kerberos::KerberosString::try_from("Kerberos")?,
        );
        redacted(&for_user, &[&checksum]);
        assert!(
            render(&EncryptedData::new(17, cipher.into()))?.contains("17"),
            "retain encryption type"
        );
        Ok(())
    }

    /// Validated service and reply owners redact populated keys at real protocol boundaries.
    #[test]
    fn authenticated_service_owners_redact_credentials() -> Result<(), Box<dyn Error>> {
        use core::time::Duration;

        use rskrb5_ng::{
            ap_req,
            keytab::{self, Keytab},
            service::{ApRepOptions, Validator},
            ticket,
        };
        let mut request = ap_req::decode(include_bytes!("../fixtures/valid_ap_req.der"))?;
        let service_key = EncryptionKey::new(
            18,
            hex::decode("9cad00bbc72d703258e911dc18e6d5487cf737bf67fd111f0c2463ad6033bf51")?,
        );
        let mut part = ticket::decrypt_ticket_enc_part(&request.ticket, &service_key)?;
        let original_key = EncryptionKey::new(part.key.r#type, part.key.value.as_ref().to_vec());
        let mut auth = ap_req::decrypt_ap_req_authenticator(&request, &original_key, 11)?;
        let session = pattern(65);
        let initiator = pattern(81);
        let acceptor = pattern(97);
        part.key = rasn_kerberos::EncryptionKey {
            r#type: 17,
            value: session.clone().into(),
        };
        auth.subkey = Some(rasn_kerberos::EncryptionKey {
            r#type: 17,
            value: initiator.clone().into(),
        });
        request.ticket = ticket::build_ticket_with_confounder(
            request.ticket.realm.clone(),
            request.ticket.sname.clone(),
            &part,
            &service_key,
            request.ticket.enc_part.kvno,
            &[0; 16],
        )?;
        request = ap_req::build_ap_req_with_confounder(
            request.ticket,
            request.ap_options,
            &auth,
            &EncryptionKey::new(17, session.clone()),
            11,
            None,
            &[0; 16],
        )?;
        let mut tab = Keytab::new();
        tab.entries_mut().push(keytab::Entry::new(
            keytab::Principal::new("TEST.GOKRB5", 1, ["HTTP", "host.test.gokrb5"]),
            1,
            1,
            service_key,
            1,
        ));
        let now = UNIX_EPOCH + Duration::from_secs(u64::try_from(auth.ctime.0.timestamp())?);
        let mut validator = Validator::new(&tab).with_now(now);
        let validated = validator.validate_ap_req(&ap_req::encode(&request)?)?;
        redacted(&validated, &[&session, &initiator]);
        let options =
            ApRepOptions::default().with_subkey(Some(EncryptionKey::new(17, acceptor.clone())));
        redacted(&options, &[&acceptor]);
        let reply = validated.build_ap_rep_with_confounder(&[0; 16], &options)?;
        let verified = validated.verify_ap_rep(&reply)?;
        redacted(&verified, &[&acceptor]);
        #[cfg(feature = "spnego")]
        {
            auth.cksum = Some(gss_checksum()?);
            auth.seq_number = Some(42);
            let plain = ap_req::build_ap_req_with_confounder(
                request.ticket.clone(),
                request.ap_options,
                &auth,
                &EncryptionKey::new(17, session.clone()),
                11,
                None,
                &[0; 16],
            )?;
            let token = Token::Init(NegTokenInit::krb5(
                Krb5MechToken::ap_req(ap_req::encode(&plain)?).encode()?,
            ));
            let mut independent = Validator::new(&tab).with_now(now);
            let accepted = spnego::accept_sec_context_header(
                &mut independent,
                &spnego::negotiate_header(&token)?,
            )?;
            redacted(&accepted, &[&session, &initiator]);
            #[cfg(feature = "tower")]
            {
                audit_http_future(&tab, now, &token, &[&session, &initiator])?;
            }
            #[cfg(feature = "http")]
            {
                let classified = ClientNegotiateResponse::Accepted {
                    ap_rep: Some(verified),
                };
                redacted(&classified, &[&acceptor]);
            }
        }
        Ok(())
    }

    #[cfg(feature = "tower")]
    fn audit_http_future(
        tab: &Keytab,
        now: SystemTime,
        token: &Token,
        secrets: &[&[u8]],
    ) -> Result<(), Box<dyn Error>> {
        use tower_layer::Layer as _;
        use tower_service::Service as _;
        let mut service = rskrb5_ng::http::NegotiateLayer::new(tab)
            .with_now(now)
            .layer(CredentialService::new(pattern(113)));
        let mut request = http_types::Request::new(());
        set_authorization_header(&mut request, &spnego::negotiate_header(token)?)?;
        redacted(&service.call(request), secrets);
        Ok(())
    }

    #[cfg(feature = "spnego")]
    fn gss_checksum() -> Result<rasn_kerberos::Checksum, Box<dyn Error>> {
        let mut bytes = vec![0; 24];
        bytes
            .get_mut(..4)
            .ok_or("checksum header")?
            .copy_from_slice(&16_u32.to_le_bytes());
        Ok(rasn_kerberos::Checksum {
            r#type: 0x8003,
            checksum: bytes.into(),
        })
    }
}

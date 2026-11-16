#[cfg(feature = "tokio")]
use rskrb5_ng::error::Kadmin as KadminError;

use super::*;

/// Password-change tests: kpasswd requests and replies, cached `kadmin/changepw`
/// tickets, explicit targets and credential rotation.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    #[cfg(all(feature = "tokio", feature = "spnego"))]
    use std::{net::TcpListener as StdTcpListener, thread};

    use rasn::der;
    #[cfg(feature = "tokio")]
    use rasn::types::Integer;
    #[cfg(feature = "tokio")]
    use rskrb5_ng::{
        ap_req::decrypt_ap_req_authenticator,
        client::{AsRepSession, TgsRepSession},
        kadmin::decrypt_krb_priv_enc_part,
    };
    #[cfg(feature = "tokio")]
    use tokio::sync::oneshot;

    use super::*;

    /// Binds a local KDC and a local kpasswd server, and returns them with a
    /// TCP-only configuration that points `TEST.GOKRB5` at both.
    #[cfg(feature = "tokio")]
    async fn local_kdc_and_kpasswd() -> Result<(TcpListener, TcpListener, Config), TestError> {
        let kdc_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .context("bind local kdc listener")?;
        let kdc_addr = kdc_listener
            .local_addr()
            .context("local kdc listener address")?;
        let kpasswd_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .context("bind local kpasswd listener")?;
        let kpasswd_addr = kpasswd_listener
            .local_addr()
            .context("local kpasswd listener address")?;

        let config = Config::parse(&format!(
            "
[libdefaults]
dns_lookup_kdc = false
udp_preference_limit = 1

[realms]
TEST.GOKRB5 = {{
 kdc = {kdc_addr}
 kpasswd_server = {kpasswd_addr}
}}
"
        ))
        .context("config parses")?;
        Ok((kdc_listener, kpasswd_listener, config))
    }

    /// Decrypts the `ChangePasswdData` of a parsed kpasswd request whose AP-REQ
    /// is under `service_session_key`, with the reply subkey of its authenticator.
    #[cfg(feature = "tokio")]
    fn decrypt_change_data(
        parsed: &KpasswdRequest,
        service_session_key: &EncryptionKey,
    ) -> Result<(rasn_kerberos::Authenticator, ChangePasswdData), TestError> {
        let authenticator = decrypt_ap_req_authenticator(
            parsed.ap_req(),
            service_session_key,
            AP_REQ_AUTHENTICATOR_USAGE,
        )
        .context("AP-REQ authenticator decrypts")?;
        let subkey = authenticator
            .subkey
            .as_ref()
            .context("AP-REQ reply key included")?;
        let reply_key = EncryptionKey::new(subkey.r#type, subkey.value.as_ref().to_vec());
        let enc_part = decrypt_krb_priv_enc_part(parsed.krb_priv(), &reply_key)
            .context("KRB-PRIV payload decrypts")?;
        let change_data = ChangePasswdData::decode_der(enc_part.user_data.as_ref())
            .context("ChangePasswdData decodes")?;
        Ok((authenticator, change_data))
    }

    /// Serves two password logins of `client` for `kadmin/changepw` on
    /// `listener`, encrypting the n-th AS-REP under the n-th of `reply_keys`.
    #[cfg(feature = "tokio")]
    async fn serve_changepw_logins(
        listener: TcpListener,
        client: Principal,
        reply_keys: [EncryptionKey; 2],
    ) -> Result<(), TestError> {
        let expected_service = change_password_principal();
        for reply_key in &reply_keys {
            let (request, mut socket) = read_tcp_kdc_request(&listener).await?;
            let decoded: rasn_kerberos::AsReq = der::decode(&request).context("AS-REQ decodes")?;
            let built = built_request_from_der(decoded, &request)?;
            assert_eq!(built.client(), &client);
            assert_eq!(built.service(), &expected_service);
            let response =
                synthetic_as_rep_with_reply_key(&built, built.nonce(), built.service(), reply_key)?;
            write_tcp_kdc_response(&mut socket, &response).await?;
        }
        Ok(())
    }

    /// A `kadmin/changepw` ticket obtained with `tgt`, valid from a minute ago
    /// for an hour and renewable for two.
    #[cfg(feature = "tokio")]
    fn current_changepw_ticket(tgt: &AsRepSession) -> Result<TgsRepSession, TestError> {
        let request = build_tgs_req_with_confounder(
            tgt,
            change_password_principal(),
            TgsReq::new(timestamp(1_893_553_450)?, 0x2233_4455).with_etypes(vec![18_i32]),
            timestamp(1_893_553_451)?,
            654_321,
            &decode_hex(TGS_REQ_CONFOUNDER)?,
        )
        .context("changepw TGS-REQ builds")?;
        let response = synthetic_tgs_rep(&request, request.nonce(), tgt.session_key())?;
        let mut changepw_ticket =
            process_tgs_rep(&request, &response, tgt.session_key()).context("TGS-REP validates")?;
        let now = SystemTime::now();
        changepw_ticket.set_start_time(
            now.checked_sub(Duration::from_mins(1))
                .context("start time")?,
        );
        changepw_ticket.set_end_time(
            now.checked_add(Duration::from_hours(1))
                .context("end time")?,
        );
        changepw_ticket.set_renew_till(Some(
            now.checked_add(Duration::from_hours(2))
                .context("renew time")?,
        ));
        Ok(changepw_ticket)
    }

    /// Pins a kpasswd request whose KRB-PRIV payload is encrypted under the AP-REQ subkey.
    #[test]
    fn builds_kpasswd_request_with_subkey_encrypted_payload() -> Result<(), TestError> {
        let tgt = sample_tgt_session()?;
        let request = sample_tgs_request(&tgt)?;
        let response = synthetic_tgs_rep(&request, request.nonce(), tgt.session_key())?;
        let service_ticket =
            process_tgs_rep(&request, &response, tgt.session_key()).context("TGS-REP validates")?;
        let reply_key = EncryptionKey::new(18, vec![0x55; 32]);
        let change_data = ChangePasswdData::for_target(
            Password::copy_from_str("newpassword"),
            1,
            ["testuser1"],
            "TEST.GOKRB5",
        )
        .context("ChangePasswdData builds")?;

        let built = build_kpasswd_request_with_confounders(
            &service_ticket,
            &change_data,
            reply_key.clone(),
            &RequestOptions::new(
                timestamp(1_893_553_452)?,
                456_789,
                42,
                ipv4_host_address([127, 0, 0, 1]),
            ),
            &decode_hex(TGS_REQ_CONFOUNDER)?,
            &decode_hex(PREAUTH_CONFOUNDER)?,
        )
        .context("kpasswd request builds")?;

        assert_eq!(built.reply_key(), &reply_key);
        assert_eq!(
            *built.der(),
            built.request().encode().context("request encodes")?
        );
        let parsed = KpasswdRequest::parse(built.der()).context("request parses")?;
        assert_eq!(parsed.ap_req(), built.request().ap_req());
        assert_eq!(parsed.krb_priv(), built.request().krb_priv());

        let authenticator_bytes = AesSha1Etype::Aes256
            .decrypt_message(
                service_ticket.session_key().value(),
                parsed.ap_req().authenticator.cipher.as_ref(),
                AP_REQ_AUTHENTICATOR_USAGE,
            )
            .context("AP-REQ authenticator decrypts")?;
        let authenticator: rasn_kerberos::Authenticator =
            der::decode(&authenticator_bytes).context("Authenticator decodes")?;
        let subkey = authenticator.subkey.context("authenticator subkey")?;
        assert_eq!(subkey.r#type, reply_key.etype());
        assert_eq!(subkey.value.as_ref(), reply_key.value().as_slice());
        assert_eq!(authenticator.seq_number, Some(42));

        let krb_priv_bytes = AesSha1Etype::Aes256
            .decrypt_message(
                reply_key.value(),
                parsed.krb_priv().enc_part.cipher.as_ref(),
                KRB_PRIV_ENCPART_USAGE,
            )
            .context("KRB-PRIV decrypts")?;
        let enc_part: rasn_kerberos::EncKrbPrivPart =
            der::decode(&krb_priv_bytes).context("EncKrbPrivPart decodes")?;
        let decoded_change_data =
            ChangePasswdData::decode_der(enc_part.user_data.as_ref()).context("payload decodes")?;

        assert_eq!(decoded_change_data, change_data);
        assert_eq!(enc_part.seq_number, Some(42));
        assert_eq!(
            enc_part
                .usec
                .context("KRB-PRIV usec")?
                .to_string()
                .parse::<u32>()
                .context("usec parses")?,
            456_789
        );
        assert_eq!(
            system_time_from_kerberos_time(
                enc_part.timestamp.as_ref().context("KRB-PRIV timestamp")?
            )?,
            timestamp(1_893_553_452)?
        );
        Ok(())
    }

    /// Pins that a kpasswd request built without a reply key generates one in the ticket enctype.
    #[test]
    fn builds_kpasswd_request_with_generated_reply_key() -> Result<(), TestError> {
        let tgt = sample_tgt_session()?;
        let request = sample_tgs_request(&tgt)?;
        let response = synthetic_tgs_rep(&request, request.nonce(), tgt.session_key())?;
        let service_ticket =
            process_tgs_rep(&request, &response, tgt.session_key()).context("TGS-REP validates")?;
        let change_data = ChangePasswdData::new(Password::copy_from_str("newpassword"));

        let built = build_kpasswd_request(
            &service_ticket,
            &change_data,
            &RequestOptions::new(
                timestamp(1_893_553_452)?,
                456_789,
                42,
                ipv4_host_address([127, 0, 0, 1]),
            ),
        )
        .context("kpasswd request builds")?;
        let parsed = KpasswdRequest::parse(built.der()).context("request parses")?;

        assert_eq!(
            built.reply_key().etype(),
            service_ticket.session_key().etype()
        );
        assert_eq!(built.reply_key().value().len(), 32);

        let krb_priv_bytes = AesSha1Etype::Aes256
            .decrypt_message(
                built.reply_key().value(),
                parsed.krb_priv().enc_part.cipher.as_ref(),
                KRB_PRIV_ENCPART_USAGE,
            )
            .context("KRB-PRIV decrypts")?;
        let enc_part: rasn_kerberos::EncKrbPrivPart =
            der::decode(&krb_priv_bytes).context("EncKrbPrivPart decodes")?;
        let decoded_change_data =
            ChangePasswdData::decode_der(enc_part.user_data.as_ref()).context("payload decodes")?;

        assert_eq!(decoded_change_data, change_data);
        assert_eq!(enc_part.seq_number, Some(42));
        Ok(())
    }

    /// Pins that a kpasswd AP-REP echoing the request timestamp verifies.
    #[test]
    fn verifies_kpasswd_reply_ap_rep_timestamp() -> Result<(), TestError> {
        let built = sample_built_kpasswd_request()?;
        let ap_rep = kpasswd_ap_rep(&built, 456_789)?;
        let reply = KpasswdReply::parse(&kpasswd_reply_with_ap_rep(&built, &ap_rep)?)
            .context("kpasswd reply parses")?;

        let mut verified = verify_kpasswd_ap_rep(&reply, &built)
            .context("AP-REP verifies")?
            .context("successful reply has AP-REP")?;

        assert_eq!(verified.ctime(), timestamp(1_893_553_452)?);
        assert_eq!(verified.cusec(), 456_789);
        assert_eq!(verified.sequence_number(), Some(99));
        assert_eq!(verified.subkey(), None);
        let subkey = EncryptionKey::new(18, vec![0x6d; 32]);
        verified.set_subkey(Some(subkey.clone()));
        assert_eq!(verified.subkey(), Some(&subkey));
        Ok(())
    }

    /// Pins that a kpasswd AP-REP with another timestamp is rejected.
    #[test]
    fn rejects_kpasswd_reply_ap_rep_timestamp_mismatch() -> Result<(), TestError> {
        let built = sample_built_kpasswd_request()?;
        let ap_rep = kpasswd_ap_rep(&built, 456_790)?;
        let reply = KpasswdReply::parse(&kpasswd_reply_with_ap_rep(&built, &ap_rep)?)
            .context("kpasswd reply parses")?;

        assert!(matches!(
            verify_kpasswd_ap_rep(&reply, &built)
                .err()
                .context("timestamp mismatch is rejected")?,
            Error::KpasswdApRepTimestampMismatch {
                expected: _,
                actual: _
            }
        ));
        Ok(())
    }

    /// Pins a password change through a cached `kadmin/changepw` ticket against an authenticated reply.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_changes_password_with_cached_changepw_ticket() -> Result<(), TestError> {
        runtime()?.block_on(async {
            let tgt = sample_tgt_session()?;
            let changepw_ticket = current_changepw_ticket(&tgt)?;
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .context("bind local kpasswd listener")?;
            let addr = listener.local_addr().context("local listener address")?;
            let mut client = Tokio::from_tgt_session(
                config_with_kpasswd_server(&addr.to_string())?,
                KdcProtocol::Tcp,
                tgt,
            );
            client.cache_service_ticket(changepw_ticket)?;
            let task = tokio::spawn(async move {
                let (request, mut socket) = read_tcp_kdc_request(&listener).await?;
                let parsed = KpasswdRequest::parse(&request).context("kpasswd request parses")?;
                assert_eq!(parsed.ap_req().msg_type, Integer::from(14_i32));
                assert_eq!(parsed.krb_priv().msg_type, Integer::from(21_i32));

                let session_key = EncryptionKey::new(18, decode_hex(SERVICE_SESSION_KEY)?);
                let response = kpasswd_authenticated_success_reply(&request, &session_key, 0x77)?;
                write_tcp_kdc_response(&mut socket, &response).await?;
                Ok::<(), TestError>(())
            });

            let result = client
                .change_password_with_options(
                    Password::copy_from_str("newpassword"),
                    RequestOptions::new(
                        timestamp(1_893_553_452)?,
                        456_789,
                        42,
                        ipv4_host_address([127, 0, 0, 1]),
                    ),
                )
                .await
                .context("change password succeeds")?;

            task.await.context("kpasswd listener task completes")??;
            assert_eq!(result.code, KPASSWD_SUCCESS);
            assert_eq!(result.text, "password changed");
            Ok(())
        })
    }

    /// Pins that the Tokio client decrypts the kpasswd result under the AP-REP subkey.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_changes_password_uses_kpasswd_ap_rep_subkey_for_result() -> Result<(), TestError>
    {
        runtime()?.block_on(async {
            let tgt = sample_tgt_session()?;
            let changepw_ticket = current_changepw_ticket(&tgt)?;
            let changepw_session_key = changepw_ticket.session_key().clone();
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .context("bind local kpasswd listener")?;
            let addr = listener.local_addr().context("local listener address")?;
            let mut client = Tokio::from_tgt_session(
                config_with_kpasswd_server(&addr.to_string())?,
                KdcProtocol::Tcp,
                tgt,
            );
            client.cache_service_ticket(changepw_ticket)?;
            let task = tokio::spawn(async move {
                let (request, mut socket) = read_tcp_kdc_request(&listener).await?;
                let parsed = KpasswdRequest::parse(&request).context("kpasswd request parses")?;
                let authenticator = decrypt_ap_req_authenticator(
                    parsed.ap_req(),
                    &changepw_session_key,
                    AP_REQ_AUTHENTICATOR_USAGE,
                )
                .context("AP-REQ authenticator decrypts")?;
                let response_key = EncryptionKey::new(18, vec![0x66; 32]);
                let response = kpasswd_success_reply_with_ap_rep_subkey(
                    &authenticator,
                    &changepw_session_key,
                    &response_key,
                    KPASSWD_SUCCESS,
                    "password changed",
                )?;
                write_tcp_kdc_response(&mut socket, &response).await?;
                Ok::<(), TestError>(())
            });

            let result = client
                .change_password_with_options(
                    Password::copy_from_str("newpassword"),
                    RequestOptions::new(
                        timestamp(1_893_553_452)?,
                        456_789,
                        42,
                        ipv4_host_address([127, 0, 0, 1]),
                    ),
                )
                .await
                .context("change password succeeds")?;

            task.await.context("kpasswd listener task completes")??;
            assert_eq!(result.code, KPASSWD_SUCCESS);
            assert_eq!(result.text, "password changed");
            Ok::<(), TestError>(())
        })?;
        Ok(())
    }

    /// Rejects authenticated replies whose protected control fields are invalid.
    #[cfg(feature = "tokio")]
    #[test]
    fn kpasswd_rejects_invalid_protected_controls() -> Result<(), TestError> {
        runtime()?.block_on(async {
            for mode in 0_u8..6 {
                // Given a real authenticated reply with one invalid protected control.
                let tgt = sample_tgt_session()?;
                let ticket = current_changepw_ticket(&tgt)?;
                let key = ticket.session_key().clone();
                let listener = TcpListener::bind("127.0.0.1:0").await?;
                let addr = listener.local_addr()?;
                let mut client = Tokio::from_tgt_session(
                    config_with_kpasswd_server(&addr.to_string())?,
                    KdcProtocol::Tcp,
                    tgt,
                );
                client.cache_service_ticket(ticket)?;
                let task = tokio::spawn(async move {
                    let (request, mut socket) = read_tcp_kdc_request(&listener).await?;
                    let parsed = KpasswdRequest::parse(&request)?;
                    let (authenticator, _data) = decrypt_change_data(&parsed, &key)?;
                    let response = kpasswd_success_reply_with_ap_rep_subkey(
                        &authenticator,
                        &key,
                        &key,
                        KPASSWD_SUCCESS,
                        "changed",
                    )?;
                    let mut reply = KpasswdReply::parse(&response)?;
                    let mut part = decrypt_krb_priv_enc_part(
                        reply.krb_priv().as_ref().context("priv")?,
                        &key,
                    )?;
                    part.seq_number = Some(99);
                    match mode {
                        0 => part.seq_number = None,
                        1 => part.seq_number = Some(999),
                        2 => part.sender_address = ipv4_host_address([127, 0, 0, 9]),
                        3 => part.recipient_address = Some(ipv4_host_address([127, 0, 0, 9])),
                        4 => {
                            part.timestamp = Some(kerberos_time(1_893_550_000)?);
                            part.usec = Some(Integer::from(0_i32));
                        }
                        _ => part.usec = Some(Integer::from(1_000_000_i32)),
                    }
                    let plaintext = der::encode(&part)?;
                    let cipher = AesSha1Etype::Aes256.encrypt_message_with_confounder(
                        key.value(),
                        &plaintext,
                        KRB_PRIV_ENCPART_USAGE,
                        &decode_hex(PREAUTH_CONFOUNDER)?,
                    )?;
                    let mut modified = reply.krb_priv().cloned();
                    if let Some(ref mut krb_priv) = modified {
                        krb_priv.enc_part.cipher = cipher.into();
                    }
                    reply.set_krb_priv(modified);
                    write_tcp_kdc_response(&mut socket, &reply.encode()?).await?;
                    Ok::<(), TestError>(())
                });
                // When the high-level mutation consumes the response.
                let result = client
                    .change_password_with_options(
                        Password::copy_from_str("newpassword"),
                        RequestOptions::new(
                            timestamp(1_893_553_452)?,
                            456_789,
                            42,
                            ipv4_host_address([127, 0, 0, 1]),
                        )
                        .with_recipient_address(ipv4_host_address([127, 0, 0, 1])),
                    )
                    .await;
                task.await??;
                // Then no invalid authenticated result is accepted.
                assert!(result.is_err(), "invalid control mode {mode} was accepted");
            }
            Ok(())
        })
    }

    /// Connection refusal cannot have delivered a password mutation.
    #[cfg(feature = "tokio")]
    #[test]
    fn kpasswd_classification_preserves_pre_send_failure() -> Result<(), TestError> {
        runtime()?.block_on(async {
            // Given a cached ticket and a local port with no listening server.
            let tgt = sample_tgt_session()?;
            let ticket = current_changepw_ticket(&tgt)?;
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            drop(listener);
            let mut client = Tokio::from_tgt_session(
                config_with_kpasswd_server(&addr.to_string())?,
                KdcProtocol::Tcp,
                tgt,
            );
            client.cache_service_ticket(ticket)?;
            // When connection establishment fails before sending anything.
            let error = client
                .change_password_with_options(
                    Password::copy_from_str("dummy-password"),
                    RequestOptions::new(
                        timestamp(1_893_553_452)?,
                        456_789,
                        42,
                        ipv4_host_address([127, 0, 0, 1]),
                    ),
                )
                .await
                .err()
                .context("connection refused")?;
            // Then the definite endpoint failure remains safely retryable.
            assert!(matches!(
                error,
                Error::KdcEndpointFailures {
                    realm: _,
                    protocol: _,
                    failures: _
                }
            ));
            Ok(())
        })
    }

    /// A timeout after complete delivery has exactly one unknown-outcome wrapper.
    #[cfg(feature = "tokio")]
    #[test]
    fn kpasswd_classification_wraps_post_send_timeout_once() -> Result<(), TestError> {
        runtime()?.block_on(async {
            // Given a peer that consumes the request but never answers it.
            let tgt = sample_tgt_session()?;
            let ticket = current_changepw_ticket(&tgt)?;
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            let mut client = Tokio::from_tgt_session(
                config_with_kpasswd_server(&addr.to_string())?,
                KdcProtocol::Tcp,
                tgt,
            )
            .with_transport(TokioKdcTransport::new().with_timeout(Duration::from_secs(1)));
client.cache_service_ticket(ticket)?;
            let (release, wait) = oneshot::channel();
            let task = tokio::spawn(async move {
                let (_request, socket) = read_tcp_kdc_request(&listener).await?;
                wait.await?;
                drop(socket);
                Ok::<(), TestError>(())
            });
            // When the reply deadline expires after delivery.
            let error = client
                .change_password_with_options(
                    Password::copy_from_str("dummy-password"),
                    RequestOptions::new(
                        timestamp(1_893_553_452)?,
                        456_789,
                        42,
                        ipv4_host_address([127, 0, 0, 1]),
                    ),
                )
                .await
                .err()
                .context("reply timeout")?;
            release.send(()).map_err(|()| "release peer")?;
            task.await??;
            // Then the original transport timeout is the immediate cause.
            assert!(matches!(
                error,
                Error::KpasswdOutcomeUnknown(source) if matches!(*source, Error::TransportTimeout(_))
            ));
            Ok(())
        })
    }

    /// Marks a lost reply as unknown rather than implying mutation rollback.
    #[cfg(feature = "tokio")]
    #[test]
    fn kpasswd_lost_reply_has_unknown_outcome() -> Result<(), TestError> {
        runtime()?.block_on(async {
            // Given a peer that consumes the complete mutation before disconnecting.
            let tgt = sample_tgt_session()?;
            let ticket = current_changepw_ticket(&tgt)?;
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            let mut client = Tokio::from_tgt_session(
                config_with_kpasswd_server(&addr.to_string())?,
                KdcProtocol::Tcp,
                tgt,
            );
            client.cache_service_ticket(ticket)?;
            let task = tokio::spawn(async move {
                let (_request, socket) = read_tcp_kdc_request(&listener).await?;
                drop(socket);
                Ok::<(), TestError>(())
            });
            // When the response is lost, then callers receive an explicit unknown class.
            let error = client
                .change_password_with_options(
                    Password::copy_from_str("dummy-password"),
                    RequestOptions::new(
                        timestamp(1_893_553_452)?,
                        456_789,
                        42,
                        ipv4_host_address([127, 0, 0, 1]),
                    ),
                )
                .await
                .err()
                .context("reply lost")?;
            task.await??;
            assert!(matches!(error, Error::KpasswdOutcomeUnknown(_)));
            Ok(())
        })
    }

    #[cfg(feature = "tokio")]
    #[test]
    /// Preserves mutation uncertainty when the delivered request receives invalid framing.
    fn kpasswd_classification_marks_malformed_reply_unknown() -> Result<(), TestError> {
        runtime()?.block_on(async {
            // Given a server that consumes the mutation and returns a malformed reply.
            let tgt = sample_tgt_session()?;
            let ticket = current_changepw_ticket(&tgt)?;
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            let mut client = Tokio::from_tgt_session(
                config_with_kpasswd_server(&addr.to_string())?,
                KdcProtocol::Tcp,
                tgt,
            );
            client.cache_service_ticket(ticket)?;
            let task = tokio::spawn(async move {
                let (_request, mut socket) = read_tcp_kdc_request(&listener).await?;
                write_tcp_kdc_response(&mut socket, b"invalid").await?;
                Ok::<(), TestError>(())
            });
            // When response parsing fails after delivery.
            let error = client
                .change_password_with_options(
                    Password::copy_from_str("dummy-password"),
                    RequestOptions::new(
                        timestamp(1_893_553_452)?,
                        456_789,
                        42,
                        ipv4_host_address([127, 0, 0, 1]),
                    ),
                )
                .await
                .err()
                .context("malformed reply")?;
            task.await??;
            // Then parsing failure cannot imply that the password was unchanged.
            assert!(matches!(
                error,
                Error::KpasswdOutcomeUnknown(source) if matches!(*source, Error::Kadmin(_))
            ));
            Ok(())
        })
    }

    /// Pins that the Tokio client sends the explicit target principal and new password to kpasswd.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_changes_explicit_target_password() -> Result<(), TestError> {
        runtime()?.block_on(async {
            let tgt = sample_tgt_session()?;
            let changepw_ticket = current_changepw_ticket(&tgt)?;
            let changepw_session_key = changepw_ticket.session_key().clone();
            let target = Principal::new("TEST.GOKRB5", 1, ["other-user"]);
            let target_for_server = target.clone();
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .context("bind local kpasswd listener")?;
            let addr = listener.local_addr().context("local listener address")?;
            let mut client = Tokio::from_tgt_session(
                config_with_kpasswd_server(&addr.to_string())?,
                KdcProtocol::Tcp,
                tgt,
            );
            client.cache_service_ticket(changepw_ticket)?;
            let task = tokio::spawn(async move {
                let (request, mut socket) = read_tcp_kdc_request(&listener).await?;
                let parsed = KpasswdRequest::parse(&request).context("kpasswd request parses")?;
                let (authenticator, change_data) =
                    decrypt_change_data(&parsed, &changepw_session_key)?;
                assert_eq!(
                    principal_from_parts(
                        change_data.targ_realm().context("target realm set")?,
                        change_data
                            .targ_name()
                            .context("target principal name set")?,
                    )?,
                    target_for_server
                );
                assert_eq!(change_data.new_passwd().to_vec(), b"newpassword".to_vec());
                let response = kpasswd_success_reply_with_ap_rep_subkey(
                    &authenticator,
                    &changepw_session_key,
                    &changepw_session_key,
                    KPASSWD_SUCCESS,
                    "password changed",
                )?;
                write_tcp_kdc_response(&mut socket, &response).await?;
                Ok::<(), TestError>(())
            });

            let result = client
                .change_password_for_with_options(
                    target.clone(),
                    Password::copy_from_str("newpassword"),
                    RequestOptions::new(
                        timestamp(1_893_553_452)?,
                        456_789,
                        42,
                        ipv4_host_address([127, 0, 0, 1]),
                    ),
                )
                .await
                .context("change target password succeeds")?;

            task.await.context("kpasswd listener task completes")??;
            assert_eq!(result.code, KPASSWD_SUCCESS);
            assert_eq!(result.text, "password changed");
            Ok::<(), TestError>(())
        })?;
        Ok(())
    }

    #[cfg(all(feature = "tokio", feature = "spnego"))]
    /// Pins a `NegotiateClient` password change through a cached `kadmin/changepw` ticket.
    #[test]
    fn negotiate_client_changes_password_with_cached_changepw_ticket() -> Result<(), TestError> {
        runtime()?.block_on(async {
            let tgt = sample_tgt_session()?;
            let changepw_ticket = current_changepw_ticket(&tgt)?;

            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .context("bind local kpasswd listener")?;
            let listener_addr = listener.local_addr().context("local listener address")?;
            let mut tokio_client = Tokio::from_tgt_session(
                config_with_kpasswd_server(&listener_addr.to_string())?,
                KdcProtocol::Tcp,
                tgt,
            );
            tokio_client.cache_service_ticket(changepw_ticket)?;
            let mut client = NegotiateClient::from_tokio_client(tokio_client);

            let task = tokio::spawn(async move {
                let (request, mut socket) = read_tcp_kdc_request(&listener).await?;
                drop(KpasswdRequest::parse(&request).context("kpasswd request parses")?);

                let session_key = EncryptionKey::new(18, decode_hex(SERVICE_SESSION_KEY)?);
                let response = kpasswd_authenticated_success_reply(&request, &session_key, 0x77)?;
                write_tcp_kdc_response(&mut socket, &response).await?;
                Ok::<(), TestError>(())
            });

            let result = client
                .change_password_with_options(
                    Password::copy_from_str("newpassword"),
                    RequestOptions::new(
                        timestamp(1_893_553_452)?,
                        456_789,
                        42,
                        ipv4_host_address([127, 0, 0, 1]),
                    ),
                )
                .await
                .context("change password succeeds")?;

            task.await.context("kpasswd listener task completes")??;
            assert_eq!(result.code, KPASSWD_SUCCESS);
            assert_eq!(result.text, "password changed");
            Ok(())
        })
    }

    #[cfg(all(feature = "tokio", feature = "spnego"))]
    /// Pins a `NegotiateClient` password change for an explicit target principal.
    #[test]
    fn negotiate_client_changes_explicit_target_password() -> Result<(), TestError> {
        runtime()?.block_on(async {
            let tgt = sample_tgt_session()?;
            let changepw_ticket = current_changepw_ticket(&tgt)?;

            let changepw_session_key = changepw_ticket.session_key().clone();
            let target = Principal::new("TEST.GOKRB5", 1, ["other-user"]);
            let target_for_server = target.clone();

            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .context("bind local kpasswd listener")?;
            let addr = listener.local_addr().context("local listener address")?;
            let mut tokio_client = Tokio::from_tgt_session(
                config_with_kpasswd_server(&addr.to_string())?,
                KdcProtocol::Tcp,
                tgt,
            );
            tokio_client.cache_service_ticket(changepw_ticket)?;
            let mut client = NegotiateClient::from_tokio_client(tokio_client);

            let task = tokio::spawn(async move {
                let (request, mut socket) = read_tcp_kdc_request(&listener).await?;
                let parsed = KpasswdRequest::parse(&request).context("kpasswd request parses")?;
                let (authenticator, change_data) =
                    decrypt_change_data(&parsed, &changepw_session_key)?;
                assert_eq!(
                    principal_from_parts(
                        change_data.targ_realm().context("target realm set")?,
                        change_data.targ_name().context("target principal set")?,
                    )?,
                    target_for_server
                );
                assert_eq!(change_data.new_passwd().to_vec(), b"newpassword".to_vec());
                let response_key = EncryptionKey::new(18, vec![0x77; 32]);
                let response = kpasswd_success_reply_with_ap_rep_subkey(
                    &authenticator,
                    &changepw_session_key,
                    &response_key,
                    KPASSWD_SUCCESS,
                    "password changed",
                )?;
                write_tcp_kdc_response(&mut socket, &response).await?;
                Ok::<(), TestError>(())
            });

            let result = client
                .change_password_for_with_options(
                    target,
                    Password::copy_from_str("newpassword"),
                    RequestOptions::new(
                        timestamp(1_893_553_452)?,
                        456_789,
                        42,
                        ipv4_host_address([127, 0, 0, 1]),
                    ),
                )
                .await
                .context("change target password succeeds")?;

            task.await.context("kpasswd listener task completes")??;
            assert_eq!(result.code, KPASSWD_SUCCESS);
            assert_eq!(result.text, "password changed");
            Ok(())
        })
    }

    #[cfg(all(feature = "tokio", feature = "spnego"))]
    /// Pins a `BlockingNegotiateClient` password change through a cached `kadmin/changepw` ticket.
    #[test]
    fn blocking_negotiate_client_changes_password_with_cached_changepw_ticket()
    -> Result<(), TestError> {
        let tgt = sample_tgt_session()?;
        let changepw_ticket = current_changepw_ticket(&tgt)?;

        let listener = StdTcpListener::bind("127.0.0.1:0")
            .map_err(|cause| format!("bind local kpasswd listener: {cause}"))?;
        let listener_addr = listener
            .local_addr()
            .map_err(|cause| format!("local listener address: {cause}"))?;
        let mut tokio_client = Tokio::from_tgt_session(
            config_with_kpasswd_server(&listener_addr.to_string())?,
            KdcProtocol::Tcp,
            tgt,
        );
        tokio_client.cache_service_ticket(changepw_ticket)?;
        let mut client =
            BlockingNegotiateClient::new(NegotiateClient::from_tokio_client(tokio_client))
                .map_err(|cause| {
                    format!("blocking negotiate client wraps tokio client: {cause}")
                })?;

        let server = thread::spawn(move || -> Result<(), TestError> {
            use std::io::{Read as _, Write as _};

            let (mut socket, _) = listener.accept().context("accept client")?;
            let mut header = [0; 4];
            socket
                .read_exact(&mut header)
                .context("read request length")?;
            let request_len = usize::try_from(u32::from_be_bytes(header))?;
            let mut request = vec![0; request_len];
            socket.read_exact(&mut request).context("read request")?;
            let session_key = EncryptionKey::new(18, decode_hex(SERVICE_SESSION_KEY)?);
            let response = kpasswd_authenticated_success_reply(&request, &session_key, 0x77)?;
            socket
                .write_all(&u32::try_from(response.len())?.to_be_bytes())
                .context("write response length")?;
            socket.write_all(&response).context("write response")?;
            Ok(())
        });

        let result = client
            .change_password_with_options(
                Password::copy_from_str("newpassword"),
                RequestOptions::new(
                    timestamp(1_893_553_452)?,
                    456_789,
                    42,
                    ipv4_host_address([127, 0, 0, 1]),
                ),
            )
            .map_err(|cause| format!("change password succeeds: {cause}"))?;

        server
            .join()
            .map_err(|cause| format!("kpasswd listener task completes: {cause:?}"))??;
        assert_eq!(result.code, KPASSWD_SUCCESS);
        assert_eq!(result.text, "password changed");
        Ok(())
    }

    /// Pins that changing an explicit target's password keeps the client's own password credential.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_changes_explicit_target_does_not_rotate_password_credentials()
    -> Result<(), TestError> {
        runtime()?.block_on(async {
            let old_password = b"old-passwordvalue";
            let new_password = b"new-passwordvalue";
            let self_client = Principal::user("TEST.GOKRB5", "testuser1");
            let explicit_target = Principal::new("TEST.GOKRB5", 1, ["other-user"]);
            let old_reply_key =
                derive_password_reply_key(&self_client, old_password, &password_key_info())
                    .context("old reply key derives")?;
            let service_key = EncryptionKey::new(18, decode_hex(SESSION_KEY)?);

            let (kdc_listener, kpasswd_listener, config) = local_kdc_and_kpasswd().await?;
            let mut client = Tokio::with_password(
                config,
                KdcProtocol::Tcp,
                self_client.clone(),
                old_password.to_vec(),
            );

            let kdc_task = tokio::spawn(serve_changepw_logins(
                kdc_listener,
                self_client.clone(),
                [old_reply_key.clone(), old_reply_key],
            ));

            let kpasswd_task_target = explicit_target.clone();
            let kpasswd_task = tokio::spawn(async move {
                let expected_target = kpasswd_task_target;
                let service_session_key = service_key;
                for call in 0_i32..2_i32 {
                    let (request, mut socket) = read_tcp_kdc_request(&kpasswd_listener).await?;
                    let parsed =
                        KpasswdRequest::parse(&request).context("kpasswd request parses")?;
                    let (_, change_data) = decrypt_change_data(&parsed, &service_session_key)?;
                    let target = principal_from_parts(
                        change_data.targ_realm().context("target realm set")?,
                        change_data.targ_name().context("target principal set")?,
                    )?;
                    if call == 0_i32 {
                        assert_eq!(target, expected_target);
                        assert_eq!(change_data.new_passwd(), &new_password.to_vec());
                    } else {
                        assert_eq!(target, self_client.clone());
                        assert_eq!(change_data.new_passwd(), &old_password.to_vec());
                    }
                    let session_key = EncryptionKey::new(18, decode_hex(SESSION_KEY)?);
                    let response =
                        kpasswd_authenticated_success_reply(&request, &session_key, 0x77)?;
                    write_tcp_kdc_response(&mut socket, &response).await?;
                }
                Ok::<(), TestError>(())
            });

            let options = RequestOptions::new(
                timestamp(1_893_553_452)?,
                456_789,
                42,
                ipv4_host_address([127, 0, 0, 1]),
            );
            let change_target = client
                .change_password_for_with_options(
                    explicit_target,
                    Password::from_vec(new_password.to_vec()),
                    options,
                )
                .await
                .context("change target password succeeds")?;
            let change_self = client
                .change_password_with_options(
                    Password::from_vec(old_password.to_vec()),
                    RequestOptions::new(
                        timestamp(1_893_553_453)?,
                        456_790,
                        43,
                        ipv4_host_address([127, 0, 0, 1]),
                    ),
                )
                .await
                .context("change own password with old credential succeeds")?;

            kdc_task.await.context("kdc task completes")??;
            kpasswd_task.await.context("kpasswd task completes")??;
            assert_eq!(change_target.code, KPASSWD_SUCCESS);
            assert_eq!(change_target.text, "password changed");
            assert_eq!(change_self.code, KPASSWD_SUCCESS);
            assert_eq!(change_self.text, "password changed");
            Ok(())
        })
    }

    /// Pins that changing the client's own password rotates its stored password credential.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_changes_password_updates_password_credentials() -> Result<(), TestError> {
        runtime()?.block_on(async {
            let old_password = b"old-passwordvalue";
            let new_password = b"new-passwordvalue";
            let self_client = Principal::user("TEST.GOKRB5", "testuser1");
            let old_reply_key =
                derive_password_reply_key(&self_client, old_password, &password_key_info())
                    .context("old reply key derives")?;
            let new_reply_key =
                derive_password_reply_key(&self_client, new_password, &password_key_info())
                    .context("new reply key derives")?;

            let (kdc_listener, kpasswd_listener, config) = local_kdc_and_kpasswd().await?;
            let mut client = Tokio::with_password(
                config,
                KdcProtocol::Tcp,
                self_client.clone(),
                old_password.to_vec(),
            );

            let kdc_task = tokio::spawn(serve_changepw_logins(
                kdc_listener,
                self_client.clone(),
                [old_reply_key.clone(), new_reply_key],
            ));

            let kpasswd_task = tokio::spawn(async move {
                for _ in 0_i32..2_i32 {
                    let (request, mut socket) = read_tcp_kdc_request(&kpasswd_listener).await?;
                    let session_key = EncryptionKey::new(18, decode_hex(SESSION_KEY)?);
                    let response =
                        kpasswd_authenticated_success_reply(&request, &session_key, 0x77)?;
                    write_tcp_kdc_response(&mut socket, &response).await?;
                }
                Ok::<(), TestError>(())
            });

            let change_self_with_new = client
                .change_password_with_options(
                    Password::from_vec(new_password.to_vec()),
                    RequestOptions::new(
                        timestamp(1_893_553_452)?,
                        456_789,
                        42,
                        ipv4_host_address([127, 0, 0, 1]),
                    ),
                )
                .await
                .context("change own password succeeds")?;
            let change_self_with_updated = client
                .change_password_with_options(
                    Password::from_vec(new_password.to_vec()),
                    RequestOptions::new(
                        timestamp(1_893_553_453)?,
                        456_790,
                        43,
                        ipv4_host_address([127, 0, 0, 1]),
                    ),
                )
                .await
                .context("change own password with rotated credential succeeds")?;

            kdc_task.await.context("kdc task completes")??;
            kpasswd_task.await.context("kpasswd task completes")??;
            assert_eq!(change_self_with_new.code, KPASSWD_SUCCESS);
            assert_eq!(change_self_with_new.text, "password changed");
            assert_eq!(change_self_with_updated.code, KPASSWD_SUCCESS);
            assert_eq!(change_self_with_updated.text, "password changed");
            Ok(())
        })
    }

    /// Pins that an unsigned kpasswd success result is rejected and keeps the old credential.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_rejects_unsigned_kpasswd_success() -> Result<(), TestError> {
        runtime()?.block_on(async {
            let old_password = b"old-passwordvalue";
            let new_password = b"new-passwordvalue";
            let self_client = Principal::user("TEST.GOKRB5", "testuser1");
            let old_reply_key =
                derive_password_reply_key(&self_client, old_password, &password_key_info())?;

            let kdc_listener = TcpListener::bind("127.0.0.1:0").await?;
            let kdc_addr = kdc_listener.local_addr()?;
            let kpasswd_listener = TcpListener::bind("127.0.0.1:0").await?;
            let kpasswd_addr = kpasswd_listener.local_addr()?;

            let config = Config::parse(&format!(
                "
[libdefaults]
dns_lookup_kdc = false
udp_preference_limit = 1

[realms]
TEST.GOKRB5 = {{
 kdc = {kdc_addr}
 kpasswd_server = {kpasswd_addr}
}}
"
            ))?;
            let mut client = Tokio::with_password(
                config,
                KdcProtocol::Tcp,
                self_client.clone(),
                old_password.to_vec(),
            );

            let kdc_task_client = self_client.clone();
            let kdc_task = tokio::spawn(async move {
                let expected_service = change_password_principal();
                for _ in 0_u8..2 {
                    let (request, mut socket) = read_tcp_kdc_request(&kdc_listener).await?;
                    let decoded: rasn_kerberos::AsReq = der::decode(&request)?;
                    let built = built_request_from_der(decoded, &request)?;
                    assert_eq!(built.client(), &kdc_task_client);
                    assert_eq!(built.service(), &expected_service);
                    // The failed change must not rotate the stored credential, so
                    // both AS exchanges have to decrypt under the old reply key.
                    let response = synthetic_as_rep_with_reply_key(
                        &built,
                        built.nonce(),
                        built.service(),
                        &old_reply_key,
                    )?;
                    write_tcp_kdc_response(&mut socket, &response).await?;
                }
                Ok::<(), TestError>(())
            });

            let kpasswd_task = tokio::spawn(async move {
                for _ in 0_u8..2 {
                    let (_request, mut socket) = read_tcp_kdc_request(&kpasswd_listener).await?;
                    let response = kpasswd_reply_frame(
                        0,
                        &kpasswd_result_krb_error(KPASSWD_SUCCESS, "password changed")?,
                    )?;
                    write_tcp_kdc_response(&mut socket, &response).await?;
                }
                Ok::<(), TestError>(())
            });

            for attempt in 0_u64..2 {
                let Err(error) = client
                    .change_password_with_options(
                        Password::from_vec(new_password.to_vec()),
                        RequestOptions::new(
                            timestamp(1_893_553_452 + attempt)?,
                            456_789,
                            42,
                            ipv4_host_address([127, 0, 0, 1]),
                        ),
                    )
                    .await
                else {
                    return Err("an unsigned success result must be rejected".into());
                };
                assert!(matches!(
                    error,
                    Error::KpasswdOutcomeUnknown(source)
                        if matches!(*source, Error::Kadmin(KadminError::UnauthenticatedSuccess))
                ));
            }

            kdc_task.await??;
            kpasswd_task.await??;
            Ok::<(), TestError>(())
        })
    }
}

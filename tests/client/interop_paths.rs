use super::*;

/// The Tokio client and transport paths that only the live MIT and Samba
/// suites reached before plan 2 todo 29: the `S4U` convenience wrappers with
/// a keytab client, the forwardable re-login before `S4U2Self`, an explicit
/// TGT renewal, and the password login's reply-without-preauthentication and
/// UDP follow-up paths.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::net::SocketAddr;

    use rasn::der;
    use rskrb5_ng::messages::PaForUser;
    use tokio::{net::UdpSocket, time::timeout};

    use super::*;

    /// `KDCOptions` forwardable.
    const FORWARDABLE: u32 = 0x4000_0000;
    /// `KDCOptions` proxiable.
    const PROXIABLE: u32 = 0x1000_0000;
    /// Flags of a TGT that is not forwardable.
    const NOT_FORWARDABLE: [u8; 4] = [0x00, 0x81, 0x00, 0x10];

    /// A profile whose `TEST.GOKRB5` KDC is `server` and whose requests ask
    /// for forwardable and proxiable tickets.
    fn forwardable_profile(server: &str) -> Result<Config, TestError> {
        Config::parse(&format!(
            "
[libdefaults]
 dns_lookup_kdc = false
 forwardable = true
 proxiable = true

[realms]
 TEST.GOKRB5 = {{
  kdc = {server}
 }}
"
        ))
        .context("config parses")
    }

    /// The `KDCOptions` bits of a request body.
    fn option_bits(body: &rasn_kerberos::KdcReqBody) -> Result<u32, TestError> {
        Ok(u32::from_be_bytes(
            body.kdc_options
                .0
                .as_raw_slice()
                .get(..4)
                .context("four option bytes")?
                .try_into()?,
        ))
    }

    /// The keys of `HTTP/host.test.gokrb5`: the AS reply key (kvno 3) and the
    /// key its delegated tickets are sealed in (kvno 4).
    fn service_keytab() -> Result<Keytab, TestError> {
        let service = sample_service_principal();
        let mut keytab = delegation_keytab()?;
        keytab.entries_mut().push(KeytabEntry::new(
            KeytabPrincipal::new(service.realm, service.name_type, service.components),
            1_893_553_440,
            3,
            reply_key()?,
            3,
        ));
        Ok(keytab)
    }

    /// A keytab client of `HTTP/host.test.gokrb5` for the KDC `addr`, holding
    /// a current service TGT with `flags`.
    fn keytab_client(addr: &str, flags: [u8; 4]) -> Result<Tokio, TestError> {
        let mut client = Tokio::with_keytab(
            forwardable_profile(addr)?,
            KdcProtocol::Tcp,
            sample_service_principal(),
            service_keytab()?,
        );
        let mut tgt = current_tgt_session(5, 180)?;
        tgt.set_client(sample_service_principal());
        tgt.set_ticket_flags(flags);
        client.cache_tgt_session(tgt)?;
        Ok(client)
    }

    /// Serves one keytab AS-REQ for the service's TGT, which must ask for a
    /// forwardable and proxiable ticket, with an AS-REP in the keytab's key.
    async fn serve_forwardable_login(listener: &TcpListener) -> Result<(), TestError> {
        let (request, mut socket) = read_tcp_kdc_request(listener).await?;
        let decoded: rasn_kerberos::AsReq = der::decode(&request).context("AS-REQ decodes")?;
        let options = option_bits(&decoded.0.req_body)?;
        assert_eq!(options & FORWARDABLE, FORWARDABLE, "{options:#010x}");
        assert_eq!(options & PROXIABLE, PROXIABLE, "{options:#010x}");
        let built = built_request_from_der(decoded, &request)?;
        assert_eq!(built.client(), &sample_service_principal());
        assert_eq!(built.service(), &Principal::tgt_service("TEST.GOKRB5"));
        let response =
            synthetic_as_rep_with_reply_key(&built, built.nonce(), built.service(), &reply_key()?)?;
        write_tcp_kdc_response(&mut socket, &response).await
    }

    /// Serves one `S4U2Self` TGS-REQ for `user` under the TGT session key
    /// `tgt_key`; the request must ask for forwardable and proxiable evidence.
    async fn serve_forwardable_s4u2self(
        listener: &TcpListener,
        tgt_key: &EncryptionKey,
        user: Principal,
    ) -> Result<(), TestError> {
        let (request, mut socket) = read_tcp_kdc_request(listener).await?;
        let decoded: rasn_kerberos::TgsReq = der::decode(&request).context("TGS-REQ decodes")?;
        let options = option_bits(&decoded.0.req_body)?;
        assert_eq!(options & FORWARDABLE, FORWARDABLE, "{options:#010x}");
        assert_eq!(options & PROXIABLE, PROXIABLE, "{options:#010x}");
        let for_user = decoded
            .0
            .padata
            .as_deref()
            .unwrap_or_default()
            .iter()
            .find(|entry| entry.r#type == PA_FOR_USER)
            .context("PA-FOR-USER")?;
        let pa_for_user = PaForUser::decode_der(for_user.value.as_ref())?;
        assert_eq!(
            principal_from_parts(pa_for_user.user_realm(), pa_for_user.user_name())?,
            user
        );
        let mut built = built_tgs_request_from_der(decoded, &request)?;
        built.set_client(user);
        let response = synthetic_tgs_rep(&built, built.nonce(), tgt_key)?;
        write_tcp_kdc_response(&mut socket, &response).await
    }

    /// FU-IOP-P11 through the convenience wrapper: a keytab client whose TGT is
    /// not forwardable first logs in again for a forwardable TGT, then asks for
    /// forwardable evidence; the evidence decrypts with the client's own keytab.
    #[test]
    fn s4u2self_relogs_in_for_a_forwardable_tgt_and_asks_for_forwardable_evidence()
    -> Result<(), TestError> {
        runtime()?.block_on(async {
            // Given a keytab client whose cached TGT is not forwardable.
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .context("bind local KDC listener")?;
            let addr = listener.local_addr().context("local listener address")?;
            let mut client = keytab_client(&addr.to_string(), NOT_FORWARDABLE)?;
            let user = Principal::user("TEST.GOKRB5", "delegated-user");
            let user_for_kdc = user.clone();
            let kdc = tokio::spawn(async move {
                serve_forwardable_login(&listener).await?;
                let new_tgt_key = EncryptionKey::new(18, decode_hex(SESSION_KEY)?);
                serve_forwardable_s4u2self(&listener, &new_tgt_key, user_for_kdc).await
            });

            // When the service impersonates the user.
            let evidence = client
                .s4u2self(user.clone())
                .await
                .context("S4U2Self succeeds")?;
            kdc.await.context("KDC task completes")??;

            // Then the evidence names the user for the service, and the
            // forwardable TGT of the new login is cached.
            assert_eq!(evidence.client(), &user);
            assert_eq!(evidence.service(), &sample_service_principal());
            let cached = client.tgt_session().context("cached TGT")?;
            assert_eq!(
                u32::from_be_bytes(cached.ticket_flags()) & FORWARDABLE,
                FORWARDABLE
            );
            Ok::<(), TestError>(())
        })
    }

    /// A keytab client with a forwardable TGT asks for forwardable evidence
    /// without a new login, and `S4U2Self` with options that name no
    /// delegation keytab uses the client's keytab.
    #[test]
    fn s4u2self_with_a_forwardable_tgt_uses_it_and_the_client_keytab() -> Result<(), TestError> {
        runtime()?.block_on(async {
            // Given a keytab client whose cached TGT is forwardable.
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .context("bind local KDC listener")?;
            let addr = listener.local_addr().context("local listener address")?;
            let mut client = keytab_client(&addr.to_string(), *TICKET_FLAGS)?;
            let tgt_key = client.tgt_session().context("cached TGT")?.session_key().clone();
            let user = Principal::user("TEST.GOKRB5", "delegated-user");
            let user_for_kdc = user.clone();
            let key_for_kdc = tgt_key.clone();
            let kdc = tokio::spawn(async move {
                serve_forwardable_s4u2self(&listener, &key_for_kdc, user_for_kdc.clone()).await?;
                serve_forwardable_s4u2self(&listener, &key_for_kdc, user_for_kdc).await
            });

            // When the service impersonates the user through both entry points.
            let wrapped = client.s4u2self(user.clone()).await;
            let explicit = client
                .s4u2self_with_options(
                    user.clone(),
                    TgsReq::new(SystemTime::now(), 0x0bad_cafe)
                        .with_etypes(vec![18_i32])
                        .with_kdc_option_bits(FORWARDABLE | PROXIABLE),
                )
                .await;
            kdc.await.context("KDC task completes")??;

            // Then both return the user's evidence for the service.
            for evidence in [wrapped?, explicit?] {
                assert_eq!(evidence.client(), &user);
                assert_eq!(evidence.service(), &sample_service_principal());
            }
            Ok::<(), TestError>(())
        })
    }

    /// The `S4U2Proxy` wrapper asks with the profile's options and the client's
    /// keytab, and returns the target's ticket in the user's name.
    #[test]
    fn s4u2proxy_wrapper_uses_the_profile_options_and_the_client_keytab() -> Result<(), TestError> {
        runtime()?.block_on(async {
            // Given a keytab client with a forwardable service TGT and a user's evidence.
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .context("bind local KDC listener")?;
            let addr = listener.local_addr().context("local listener address")?;
            let mut client = keytab_client(&addr.to_string(), *TICKET_FLAGS)?;
            let tgt_key = client.tgt_session().context("cached TGT")?.session_key().clone();
            let evidence = sample_service_ticket_session(&sample_tgt_session()?)?;
            let user = evidence.client().clone();
            let target = Principal::new("TEST.GOKRB5", 2, ["HTTP", "backend.test.gokrb5"]);
            let target_for_kdc = target.clone();
            let user_for_kdc = user.clone();
            let kdc = tokio::spawn(async move {
                let (request, mut socket) = read_tcp_kdc_request(&listener).await?;
                let decoded: rasn_kerberos::TgsReq =
                    der::decode(&request).context("TGS-REQ decodes")?;
                let body = &decoded.0.req_body;
                let options = option_bits(body)?;
                let cname_in_addl_tkt =
                    u32::from_be_bytes(KDC_OPTION_CNAME_IN_ADDL_TKT.to_be_bytes());
                assert_eq!(
                    options & cname_in_addl_tkt,
                    cname_in_addl_tkt,
                    "{options:#010x}"
                );
                assert_eq!(options & PROXIABLE, PROXIABLE, "{options:#010x}");
                assert_eq!(
                    principal_from_parts(&body.realm, body.sname.as_ref().context("sname")?)?,
                    target_for_kdc
                );
                assert_eq!(body.additional_tickets.as_ref().map(Vec::len), Some(1));
                let mut built = built_tgs_request_from_der(decoded, &request)?;
                built.set_client(user_for_kdc);
                let response = synthetic_tgs_rep(&built, built.nonce(), &tgt_key)?;
                write_tcp_kdc_response(&mut socket, &response).await
            });

            // When the service asks for the target in the user's name.
            let delegated = client
                .s4u2proxy(&evidence, target.clone())
                .await
                .context("S4U2Proxy succeeds")?;
            kdc.await.context("KDC task completes")??;

            // Then the ticket is the user's ticket to the target.
            assert_eq!(delegated.client(), &user);
            assert_eq!(delegated.service(), &target);
            Ok::<(), TestError>(())
        })
    }

    /// The transport renews a TGT at an explicit KDC: a RENEW request for the
    /// TGT's own service that carries the TGT.
    #[test]
    fn transport_renews_a_tgt_at_an_explicit_kdc() -> Result<(), TestError> {
        runtime()?.block_on(async {
            // Given a renewable TGT and a KDC.
            let tgt = current_tgt_session(5, 180)?;
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .context("bind local KDC listener")?;
            let addr = listener.local_addr().context("local listener address")?;
            let tgt_key = tgt.session_key().clone();
            let ticket = tgt.ticket().to_vec();
            let kdc = tokio::spawn(async move {
                let (request, mut socket) = read_tcp_kdc_request(&listener).await?;
                let decoded: rasn_kerberos::TgsReq =
                    der::decode(&request).context("TGS-REQ decodes")?;
                let options = option_bits(&decoded.0.req_body)?;
                let renew = KDC_OPTION_RENEW;
                assert_eq!(options & renew, renew, "{options:#010x}");
                let header = decoded
                    .0
                    .padata
                    .as_deref()
                    .unwrap_or_default()
                    .iter()
                    .find(|entry| entry.r#type == PA_TGS_REQ)
                    .context("PA-TGS-REQ")?;
                let ap_req: rasn_kerberos::ApReq = der::decode(header.value.as_ref())?;
                assert_eq!(
                    der::encode(&ap_req.ticket)?,
                    ticket,
                    "the renewed TGT is sent"
                );
                let built = built_tgs_request_from_der(decoded, &request)?;
                assert_eq!(built.service(), &Principal::tgt_service("TEST.GOKRB5"));
                let response = synthetic_tgs_rep(&built, built.nonce(), &tgt_key)?;
                write_tcp_kdc_response(&mut socket, &response).await
            });

            // When the transport renews it.
            let renewed = TokioKdcTransport::new()
                .renew_tgt(
                    KdcProtocol::Tcp,
                    addr,
                    &tgt,
                    TgsReq::new(timestamp(1_893_553_450)?, 0x0102_0304).with_etypes(vec![18_i32]),
                )
                .await
                .context("TGT renewal succeeds")?;
            kdc.await.context("KDC task completes")??;

            // Then the renewed TGT is the client's TGT.
            assert_eq!(renewed.client(), tgt.client());
            assert_eq!(renewed.service(), &Principal::tgt_service("TEST.GOKRB5"));
            Ok::<(), TestError>(())
        })
    }

    /// A UDP KDC socket on loopback.
    async fn udp_kdc() -> Result<(UdpSocket, SocketAddr), TestError> {
        let socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .context("bind UDP KDC")?;
        let addr = socket.local_addr().context("UDP KDC address")?;
        Ok((socket, addr))
    }

    /// Receives one AS-REQ datagram on `socket` within 10 s.
    async fn receive_as_req(
        socket: &UdpSocket,
    ) -> Result<(rasn_kerberos::AsReq, Vec<u8>, SocketAddr), TestError> {
        let mut buffer = vec![0_u8; 65_536];
        let (length, peer) = timeout(Duration::from_secs(10), socket.recv_from(&mut buffer))
            .await
            .context("AS-REQ within 10 s")?
            .context("receive AS-REQ")?;
        buffer.truncate(length);
        let decoded = der::decode(&buffer).context("AS-REQ decodes")?;
        Ok((decoded, buffer, peer))
    }

    /// The AS-REP for `request` sealed in the `testuser1` password key.
    fn password_as_rep(decoded: rasn_kerberos::AsReq, bytes: &[u8]) -> Result<Vec<u8>, TestError> {
        let built = built_request_from_der(decoded, bytes)?;
        let key =
            derive_password_reply_key(built.client(), TESTUSER_PASSWORD, &password_key_info())
                .context("password key derives")?;
        synthetic_as_rep_with_reply_key(&built, built.nonce(), built.service(), &key)
    }

    /// A KDC that issues the ticket to the unauthenticated request ends the
    /// password login after one exchange (MIT `get_in_tkt.c`: an AS-REP to the
    /// first request is the result).
    #[test]
    fn password_login_accepts_a_reply_to_the_unauthenticated_request() -> Result<(), TestError> {
        runtime()?.block_on(async {
            // Given a UDP KDC that answers the first AS-REQ with an AS-REP.
            let (socket, addr) = udp_kdc().await?;
            let kdc = tokio::spawn(async move {
                let (decoded, bytes, peer) = receive_as_req(&socket).await?;
                assert!(
                    decoded
                        .0
                        .padata
                        .as_deref()
                        .unwrap_or_default()
                        .iter()
                        .all(|entry| entry.r#type != PA_ENC_TIMESTAMP),
                    "the first request is not preauthenticated"
                );
                let reply = password_as_rep(decoded, &bytes)?;
                let _: usize = socket.send_to(&reply, peer).await?;
                Ok::<(), TestError>(())
            });

            // When testuser1 logs in for kadmin/changepw.
            let session = TokioKdcTransport::new()
                .login_as_service_with_password(
                    KdcProtocol::Udp,
                    addr,
                    Principal::user("TEST.GOKRB5", "testuser1"),
                    change_password_principal(),
                    TESTUSER_PASSWORD,
                    AsReq::new(SystemTime::now(), 0x4455_6677).with_etypes(vec![18_i32]),
                )
                .await
                .context("password login succeeds")?;
            kdc.await.context("KDC task completes")??;

            // Then the session is testuser1's ticket for kadmin/changepw.
            assert_eq!(
                session.client(),
                &Principal::user("TEST.GOKRB5", "testuser1")
            );
            assert_eq!(session.service(), &change_password_principal());
            Ok::<(), TestError>(())
        })
    }

    /// Over UDP no connection is pinned, so the preauthenticated retry after
    /// `PREAUTH_REQUIRED` is a new datagram to the KDC.
    #[test]
    fn udp_password_login_sends_the_preauth_retry_as_a_new_datagram() -> Result<(), TestError> {
        runtime()?.block_on(async {
            // Given a UDP KDC that requires preauthentication.
            let (socket, addr) = udp_kdc().await?;
            let kdc = tokio::spawn(async move {
                let (_, _, first_peer) = receive_as_req(&socket).await?;
                let _: usize = socket
                    .send_to(&synthetic_preauth_required_error()?, first_peer)
                    .await?;
                let (decoded, bytes, peer) = receive_as_req(&socket).await?;
                assert_pa_enc_timestamp(&decoded, None)?;
                let reply = password_as_rep(decoded, &bytes)?;
                let _: usize = socket.send_to(&reply, peer).await?;
                Ok::<(), TestError>(())
            });

            // When testuser1 logs in for kadmin/changepw over UDP.
            let session = TokioKdcTransport::new()
                .login_as_service_with_password(
                    KdcProtocol::Udp,
                    addr,
                    Principal::user("TEST.GOKRB5", "testuser1"),
                    change_password_principal(),
                    TESTUSER_PASSWORD,
                    AsReq::new(SystemTime::now(), 0x5566_7788).with_etypes(vec![18_i32]),
                )
                .await
                .context("preauthenticated password login succeeds")?;
            kdc.await.context("KDC task completes")??;

            // Then the preauthenticated retry produced the session.
            assert_eq!(
                session.client(),
                &Principal::user("TEST.GOKRB5", "testuser1")
            );
            assert_eq!(session.service(), &change_password_principal());
            Ok::<(), TestError>(())
        })
    }
}

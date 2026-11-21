use super::*;

/// The exchange engine and the Tokio client emit redacted trace events (WP-18).
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use rasn::der;
    use rskrb5_ng::{
        client::{
            AsRepSession,
            stepwise::{
                Answer, ExchangeStep, InitCreds, InitCredsOptions, Prompt, Responder, StepInput,
                TicketCreds, TicketOptions, drive,
            },
        },
        error::Trace as TraceError,
        extensions::ProviderError,
        trace::{Event, Guard, Options, Sink, capture::Memory},
    };

    use super::*;

    /// Answers every prompt with the real test password.
    struct Answering;

    impl Responder for Answering {
        fn respond(&mut self, _prompt: &Prompt) -> Result<Answer, ProviderError> {
            Ok(Answer::Password(Password::from_vec(
                TESTUSER_PASSWORD.to_vec(),
            )))
        }
    }

    /// A sink that fails every write.
    struct Failing;

    impl Sink for Failing {
        fn write(&self, _event: &Event<'_>, _text: &str) -> Result<(), TraceError> {
            Err(TraceError::Refused)
        }
    }

    /// A guard over a capture sink that allows identities.
    fn captured() -> (Guard, Memory) {
        let sink = Memory::new();
        (
            Guard::new(sink.clone(), Options::new().with_identities(true)),
            sink,
        )
    }

    /// The AS template of these tests.
    fn as_options() -> Result<AsReq, TestError> {
        Ok(AsReq::new(timestamp(1_893_553_447)?, 0x1122_3344).with_etypes(vec![18_i32]))
    }

    /// The first word of every captured line: the event names, in order.
    fn names(sink: &Memory) -> Vec<String> {
        sink.lines()
            .iter()
            .map(|line| line.split(' ').next().unwrap_or_default().to_owned())
            .collect()
    }

    /// One password login through the blocking driver with `trace`.
    fn login(trace: Option<Guard>) -> Result<AsRepSession, TestError> {
        let client = Principal::user("TEST.GOKRB5", "testuser1");
        let reply_key =
            derive_password_reply_key(&client, TESTUSER_PASSWORD, &password_key_info())?;
        let mut kdc = PreauthTransport::new(reply_key, None);
        let mut exchange =
            InitCreds::with_password(client, None, InitCredsOptions::new(as_options()?));
        if let Some(guard) = trace {
            exchange = exchange.with_trace(guard);
        }
        Ok(drive(&mut kdc, &mut exchange, &mut Answering)?)
    }

    /// The AS exchange traces each step and never a secret.
    #[test]
    fn initial_exchange_traces_each_step_without_secrets() -> Result<(), TestError> {
        let (guard, sink) = captured();
        let session = login(Some(guard))?;
        assert_eq!(
            names(&sink),
            [
                "exchange-started",
                "request-sent",
                "reply-received",
                "prompted",
                "request-sent",
                "reply-received",
                "completed",
            ]
        );
        let text = sink.lines().join("\n");
        assert!(text.contains("client=testuser1@TEST.GOKRB5"), "{text}");
        assert!(text.contains("realm=TEST.GOKRB5"), "{text}");
        assert!(text.contains("enctype=18"), "{text}");
        for secret in [
            String::from_utf8(TESTUSER_PASSWORD.to_vec())?,
            hex_encode(session.session_key().value())?,
            hex_encode(session.ticket())?,
            hex_encode(reply_key()?.value())?,
        ] {
            assert!(!text.contains(&secret), "{secret} reached the sink");
        }
        Ok(())
    }

    /// A KDC refusal is traced with its KRB-ERROR number only.
    #[test]
    fn kdc_refusal_is_traced_with_its_code() -> Result<(), TestError> {
        let (guard, sink) = captured();
        let client = Principal::user("TEST.GOKRB5", "testuser1");
        let mut exchange =
            InitCreds::with_password(client, None, InitCredsOptions::new(as_options()?))
                .with_trace(guard);
        drop(exchange.step(StepInput::Start)?);
        let refusal = synthetic_preauth_required_error()?;
        drop(exchange.step(StepInput::Reply(&refusal))?);
        drop(
            exchange.step(StepInput::Answer(Answer::Password(Password::from_vec(
                TESTUSER_PASSWORD.to_vec(),
            ))))?,
        );
        let failed = exchange.step(StepInput::Reply(&refusal));
        assert!(matches!(failed, Err(Error::Kdc(_))), "{failed:?}");
        let lines = sink.lines();
        let last = lines.last().ok_or("no event")?;
        assert!(last.starts_with("failed "), "{last}");
        assert!(last.contains("kdc_error=25"), "{last}");
        Ok(())
    }

    /// A failing sink changes nothing about the credential.
    #[test]
    fn failing_sink_leaves_the_credential_unchanged() -> Result<(), TestError> {
        let failing = Guard::new(Failing, Options::new());
        let traced = login(Some(failing.clone()))?;
        let plain = login(None)?;
        assert_eq!(traced.client(), plain.client());
        assert_eq!(traced.service(), plain.service());
        assert_eq!(traced.ticket().as_slice(), plain.ticket().as_slice());
        assert_eq!(
            traced.session_key().value().as_slice(),
            plain.session_key().value().as_slice()
        );
        assert!(failing.stats().failed >= 7, "{:?}", failing.stats());
        assert_eq!(failing.stats().emitted, 0);
        Ok(())
    }

    /// The TGS exchange traces its start, request, reply and completion.
    #[test]
    fn ticket_exchange_is_traced() -> Result<(), TestError> {
        let (guard, sink) = captured();
        let tgt = sample_tgt_session()?;
        let service = Principal::new("TEST.GOKRB5", 2, ["HTTP", "host.test.gokrb5"]);
        let options = TicketOptions::new(
            TgsReq::new(timestamp(1_893_553_450)?, 0x7766_5544).with_etypes(vec![18_i32]),
        );
        let mut exchange = TicketCreds::new(tgt.clone(), service, options)?.with_trace(guard);
        let ExchangeStep::Outbound(first) = exchange.step(StepInput::Start)? else {
            return Err("expected a request".into());
        };
        let decoded: rasn_kerberos::TgsReq = der::decode(first.message())?;
        let built = built_tgs_request_from_der(decoded, first.message())?;
        let reply = synthetic_tgs_rep(&built, built.nonce(), tgt.session_key())?;
        let done = exchange.step(StepInput::Reply(&reply))?;
        assert!(matches!(done, ExchangeStep::Complete(_)), "{done:?}");
        assert_eq!(
            names(&sink),
            [
                "exchange-started",
                "request-sent",
                "reply-received",
                "completed"
            ]
        );
        assert!(sink.lines().join("\n").contains("kind=ticket"));
        Ok(())
    }

    /// The Tokio client traces a login and its failure.
    #[tokio::test]
    async fn tokio_client_traces_login() -> Result<(), TestError> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let size = stream.read_u32().await?;
            let mut bytes = vec![0; usize::try_from(size)?];
            let _read = stream.read_exact(&mut bytes).await?;
            let built = built_request_from_der(der::decode(&bytes)?, &bytes)?;
            let reply = synthetic_as_rep_with_reply_key(
                &built,
                built.nonce(),
                built.service(),
                &reply_key()?,
            )?;
            stream.write_u32(u32::try_from(reply.len())?).await?;
            stream.write_all(&reply).await?;
            Ok::<(), TestError>(())
        });
        let (guard, sink) = captured();
        let mut client = Tokio::from_tgt_session(
            config_with_kdc_server(&address.to_string())?,
            KdcProtocol::Tcp,
            sample_tgt_session()?,
        )
        .with_keytab_credential(keytab_with_reply_key(3)?)
        .with_trace(guard);
        let _session = client.login().await?;
        task.await??;
        assert_eq!(
            names(&sink),
            [
                "exchange-started",
                "transport",
                "transport",
                "transport",
                "completed"
            ]
        );
        let (second_guard, second_sink) = captured();
        let mut expired = sample_tgt_session()?;
        expired.set_end_time(timestamp(1_000)?);
        let mut without = Tokio::from_tgt_session(
            config_with_kdc_server("127.0.0.1:9")?,
            KdcProtocol::Tcp,
            expired,
        )
        .with_trace(second_guard);
        let failure = without.login().await.err();
        assert!(
            matches!(failure, Some(Error::NoClientCredentials)),
            "{failure:?}"
        );
        assert_eq!(names(&second_sink), ["exchange-started", "failed"]);
        Ok(())
    }

    /// The transport traces where a login's request went (FU-TRC-P01).
    ///
    /// The realm's endpoints, the send and the answer are traced with sizes only, and
    /// the endpoint and realm are withheld unless the guard allows identities.
    #[tokio::test]
    async fn tokio_client_traces_transport_steps_without_secrets() -> Result<(), TestError> {
        for identities in [true, false] {
            // Given a KDC on a loopback stream and a guard over a capture sink.
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let address = listener.local_addr()?;
            let task = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await?;
                let size = stream.read_u32().await?;
                let mut bytes = vec![0; usize::try_from(size)?];
                let _read = stream.read_exact(&mut bytes).await?;
                let built = built_request_from_der(der::decode(&bytes)?, &bytes)?;
                let reply = synthetic_as_rep_with_reply_key(
                    &built,
                    built.nonce(),
                    built.service(),
                    &reply_key()?,
                )?;
                stream.write_u32(u32::try_from(reply.len())?).await?;
                stream.write_all(&reply).await?;
                Ok::<(u32, usize), TestError>((size, reply.len()))
            });
            let sink = Memory::new();
            let guard = Guard::new(sink.clone(), Options::new().with_identities(identities));
            let mut client = Tokio::from_tgt_session(
                config_with_kdc_server(&address.to_string())?,
                KdcProtocol::Tcp,
                sample_tgt_session()?,
            )
            .with_keytab_credential(keytab_with_reply_key(3)?)
            .with_trace(guard);
            // When the client logs in.
            let session = client.login().await?.clone();
            let (sent, answered) = task.await??;
            // Then the transport steps sit between the exchange's start and its end.
            let (endpoint, realm) = if identities {
                (address.to_string(), "TEST.GOKRB5".to_owned())
            } else {
                ("-".to_owned(), "-".to_owned())
            };
            assert_eq!(
                sink.lines(),
                [
                    sink.lines().first().cloned().unwrap_or_default(),
                    format!("transport step=located wire=tcp target={realm} size=1"),
                    format!("transport step=sending wire=tcp target={endpoint} size={sent}"),
                    format!("transport step=answered wire=tcp target={endpoint} size={answered}"),
                    sink.lines().last().cloned().unwrap_or_default(),
                ]
            );
            assert_eq!(
                names(&sink),
                [
                    "exchange-started",
                    "transport",
                    "transport",
                    "transport",
                    "completed"
                ]
            );
            let text = sink.lines().join("\n");
            for secret in [
                hex_encode(session.session_key().value())?,
                hex_encode(session.ticket())?,
                hex_encode(reply_key()?.value())?,
            ] {
                assert!(!text.contains(&secret), "{secret} reached the sink");
            }
        }
        Ok(())
    }
}

//! Token diagnostics with separately populated credential fields.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
pub(super) mod tests {
    use core::error::Error;
    #[cfg(any(feature = "tower", all(feature = "http", feature = "tokio")))]
    use core::{convert::Infallible, future::ready};
    #[cfg(feature = "tower")]
    use core::{
        future::Ready,
        task::{Context, Poll},
    };

    #[cfg(feature = "http")]
    use rskrb5_ng::error::Http as HttpError;
    #[cfg(feature = "tower")]
    use rskrb5_ng::http::TowerError;
    use rskrb5_ng::{
        error::{Client as ClientError, Spnego as SpnegoError},
        spnego::{
            Krb5MechToken, MicToken, NegTokenInit, NegTokenResp, NegotiationToken, Token, WrapToken,
        },
    };

    use crate::tests::{pattern, redacted};

    #[cfg(feature = "tower")]
    #[derive(Debug)]
    pub(crate) struct CredentialService(Vec<u8>);

    #[cfg(feature = "tower")]
    impl CredentialService {
        pub(crate) const fn new(bytes: Vec<u8>) -> Self {
            Self(bytes)
        }
    }

    #[cfg(feature = "tower")]
    impl tower_service::Service<http_types::Request<()>> for CredentialService {
        type Response = http_types::Response<Vec<u8>>;
        type Error = Infallible;
        type Future = Ready<Result<Self::Response, Self::Error>>;
        fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
        fn call(&mut self, _: http_types::Request<()>) -> Self::Future {
            ready(Ok(http_types::Response::new(self.0.clone())))
        }
    }

    pub(crate) fn run_audit() -> Result<(), Box<dyn Error>> {
        negotiation_tokens_redact_credentials()?;
        error_wrappers_redact_credential_payloads();
        #[cfg(feature = "tokio")]
        client_wrappers_redact_passwords()?;
        #[cfg(all(feature = "http", feature = "tokio"))]
        {
            http_errors_redact_credential_payloads()?;
            http_response_redacts_credential_payloads()?;
        }
        initiator_context_redacts_credentials()
    }

    /// Direct and nested negotiation tokens redact both token and MIC bytes.
    #[test]
    fn negotiation_tokens_redact_credentials() -> Result<(), Box<dyn Error>> {
        let payload = pattern(65);
        let mic = pattern(81);
        let mechanism = Krb5MechToken::ap_req(payload.clone());
        redacted(&mechanism, &[&payload]);
        let mut initial = NegTokenInit::krb5(payload.clone());
        initial.set_mech_list_mic(Some(mic.clone().into()));
        redacted(&initial, &[&payload, &mic]);
        let encoded = initial.encode()?;
        redacted(&NegotiationToken::decode(&encoded)?, &[&payload, &mic]);
        redacted(&Token::decode(&encoded)?, &[&payload, &mic]);
        let mut response = NegTokenResp::accept_completed().with_response_token(payload.clone());
        response.set_mech_list_mic(Some(mic.clone().into()));
        redacted(&response, &[&payload, &mic]);
        let mic_token = MicToken::new(0, 1)
            .with_payload(payload.clone())
            .with_checksum(Some(mic.clone()));
        redacted(&mic_token, &[&payload, &mic]);
        let encrypted = pattern(97);
        let wrapped = WrapToken::new(0, 2)
            .with_payload(payload.clone())
            .with_checksum(Some(mic.clone()))
            .with_encrypted_body(Some(encrypted.clone()));
        redacted(&wrapped, &[&payload, &mic, &encrypted]);
        Ok(())
    }

    /// Client error whose nested KDC e-data holds a credential payload.
    fn kdc_client_error(secret: &[u8]) -> ClientError {
        use std::time::UNIX_EPOCH;

        use rskrb5_ng::client::{KdcError, principal::Principal};
        ClientError::Kdc(Box::new(
            KdcError::new(UNIX_EPOCH, 0, 25, Principal::tgt_service("EXAMPLE.COM"))
                .with_e_data(Some(secret.to_vec().into())),
        ))
    }

    /// SPNEGO, HTTP and Tower error wrappers redact nested credential payloads.
    #[test]
    fn error_wrappers_redact_credential_payloads() {
        let secret = pattern(65);
        redacted(
            &SpnegoError::Client(Box::new(kdc_client_error(&secret))),
            &[&secret],
        );
        #[cfg(feature = "http")]
        redacted(
            &HttpError::Spnego(SpnegoError::Client(Box::new(kdc_client_error(&secret)))),
            &[&secret],
        );
        #[cfg(feature = "tower")]
        redacted(&TowerError::<Vec<u8>>::Inner(secret.clone()), &[&secret]);
    }

    /// Negotiate client wrappers redact their retained password.
    #[cfg(feature = "tokio")]
    #[test]
    fn client_wrappers_redact_passwords() -> Result<(), Box<dyn Error>> {
        use rskrb5_ng::{
            Config,
            client::{
                Tokio,
                negotiate::{BlockingClient, Client},
                principal::Principal,
                transport::KdcProtocol,
            },
        };
        let secret = pattern(65);
        let client = Tokio::with_password(
            Config::new(),
            KdcProtocol::Tcp,
            Principal::user("EXAMPLE.COM", "alice"),
            secret.clone(),
        );
        redacted(&Client::from_tokio_client(client), &[&secret]);
        let blocking = BlockingClient::with_password(
            Config::new(),
            Principal::user("EXAMPLE.COM", "alice"),
            secret.clone(),
        )?;
        redacted(&blocking, &[&secret]);
        Ok(())
    }

    /// HTTP errors redact caller-controlled body and sender credential bytes.
    #[cfg(all(feature = "http", feature = "tokio"))]
    #[test]
    fn http_errors_redact_credential_payloads() -> Result<(), Box<dyn Error>> {
        use rskrb5_ng::http::{ClientNegotiateResponse, NegotiateHttpError};
        let secret = pattern(65);
        let error = NegotiateHttpError::<Vec<u8>, Vec<u8>>::MutualAuthenticationNotProven {
            negotiation: Some(ClientNegotiateResponse::InvalidToken {
                message: String::from_utf8(secret.clone())?,
            }),
            response: Box::new(http_types::Response::new(secret.clone())),
        };
        redacted(&error, &[&secret]);
        redacted(&HttpError::Client(kdc_client_error(&secret)), &[&secret]);
        redacted(
            &NegotiateHttpError::<Vec<u8>, Vec<u8>>::Sender(secret.clone()),
            &[&secret],
        );
        Ok(())
    }

    /// The public HTTP send result redacts its real response body.
    #[cfg(all(feature = "http", feature = "tokio"))]
    #[test]
    fn http_response_redacts_credential_payloads() -> Result<(), Box<dyn Error>> {
        use rskrb5_ng::{
            Config,
            client::{Tokio, negotiate::Client, principal::Principal, transport::KdcProtocol},
            http::send_with_negotiate,
        };
        use tokio::runtime::Builder;
        let secret = pattern(65);
        let mut client = Client::from_tokio_client(Tokio::with_password(
            Config::new(),
            KdcProtocol::Tcp,
            Principal::user("EXAMPLE.COM", "alice"),
            pattern(81),
        ));
        let runtime = Builder::new_current_thread().enable_all().build()?;
        let result = runtime.block_on(send_with_negotiate(
            &mut client,
            Principal::new("EXAMPLE.COM", 2, ["HTTP", "host"]),
            || http_types::Request::new(()),
            |_| {
                ready(Ok::<_, Infallible>(http_types::Response::new(
                    secret.clone(),
                )))
            },
        ))?;
        redacted(&result, &[&secret]);
        Ok(())
    }

    /// Initiator contexts redact retained wire credentials, headers and both keys.
    #[test]
    fn initiator_context_redacts_credentials() -> Result<(), Box<dyn Error>> {
        use std::time::UNIX_EPOCH;

        use rskrb5_ng::{
            client::{AsRepSession, principal::Principal},
            kadmin::Request,
            keytab::EncryptionKey,
            spnego::{InitiatorContextOptions, init_sec_context_with_confounder},
            ticket,
        };
        let frame = Request::parse(&hex::decode(
            include_str!("../fixtures/kpasswd-request.hex").trim(),
        )?)?;
        let key = pattern(65);
        let subkey = pattern(81);
        let ticket_bytes = ticket::encode(&frame.ap_req().ticket)?;
        let session = AsRepSession::new(
            Principal::user("TEST.GOKRB5", "alice"),
            Principal::new("TEST.GOKRB5", 2, ["kadmin", "changepw"]),
            EncryptionKey::new(17, key.clone()),
            ticket_bytes.clone().into(),
            [0; 4],
            UNIX_EPOCH,
            UNIX_EPOCH,
        );
        let options = InitiatorContextOptions::new()
            .with_sequence_number(Some(42))
            .with_subkey(Some(EncryptionKey::new(17, subkey.clone())));
        redacted(&options, &[&subkey]);
        let context =
            init_sec_context_with_confounder(&session, options, UNIX_EPOCH, 0, &pattern(97))?;
        redacted(
            &context,
            &[
                &key,
                &subkey,
                &ticket_bytes,
                context.header_ref().as_bytes(),
            ],
        );
        Ok(())
    }
}

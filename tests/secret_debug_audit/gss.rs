//! GSS-API credentials, contexts and SPNEGO-over-GSS objects with populated secrets.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
pub(super) mod tests {
    use core::{error::Error, time::Duration};
    use std::time::{SystemTime, UNIX_EPOCH};

    use chrono::DateTime;
    use rskrb5_ng::{
        client::{KdcError, TgsRepSession, principal::Principal},
        error::{Client as ClientError, Gss, Spnego as SpnegoError},
        gss::{
            self, AcceptorOptions, CredStore, Credential, InitStep, InitiatorOptions, Name,
            NameType, negoex,
        },
        keytab::{self, EncryptionKey, Keytab},
        spnego::{self, AcceptStep},
        ticket,
    };
    use zeroize::Zeroizing;

    use crate::tests::{pattern, redacted};

    /// A Kerberos string.
    fn text(value: &str) -> Result<rasn_kerberos::KerberosString, Box<dyn Error>> {
        rasn_kerberos::KerberosString::from_bytes(value.as_bytes())
            .map_err(|cause| format!("Kerberos string: {cause:?}").into())
    }

    /// A whole-second Kerberos time.
    fn time(at: SystemTime) -> Result<rasn_kerberos::KerberosTime, Box<dyn Error>> {
        let seconds = i64::try_from(at.duration_since(UNIX_EPOCH)?.as_secs())?;
        let utc = DateTime::from_timestamp(seconds, 0).ok_or("time")?;
        Ok(rasn_kerberos::KerberosTime(utc.fixed_offset()))
    }

    /// A live service ticket of `alice` for `HTTP/www.example.com`, sealed in
    /// `service_key`, with `session` as its session key.
    fn ticket_for(
        service_key: &EncryptionKey,
        session: &EncryptionKey,
    ) -> Result<TgsRepSession, Box<dyn Error>> {
        let now = SystemTime::now();
        let start = UNIX_EPOCH
            .checked_add(Duration::from_secs(
                now.duration_since(UNIX_EPOCH)?.as_secs().saturating_sub(60),
            ))
            .ok_or("start")?;
        let end = start.checked_add(Duration::from_hours(1)).ok_or("end")?;
        let part = rasn_kerberos::EncTicketPart {
            flags: rasn_kerberos::TicketFlags(rasn_kerberos::KerberosFlags::repeat(false, 32)),
            key: rasn_kerberos::EncryptionKey {
                r#type: session.etype(),
                value: session.value().to_vec().into(),
            },
            crealm: text("EXAMPLE.COM")?,
            cname: rasn_kerberos::PrincipalName {
                r#type: 1,
                string: vec![text("alice")?],
            },
            transited: rasn_kerberos::TransitedEncoding {
                r#type: 1,
                contents: Vec::new().into(),
            },
            auth_time: time(start)?,
            start_time: None,
            end_time: time(end)?,
            renew_till: None,
            caddr: None,
            authorization_data: None,
        };
        let der = ticket::encode_build_ticket_with_confounder(
            text("EXAMPLE.COM")?,
            rasn_kerberos::PrincipalName {
                r#type: 3,
                string: vec![text("HTTP")?, text("www.example.com")?],
            },
            &part,
            service_key,
            Some(1),
            &[0x11; 16],
        )?;
        Ok(TgsRepSession::new(
            Principal::user("EXAMPLE.COM", "alice"),
            Principal::new("EXAMPLE.COM", 3, ["HTTP", "www.example.com"]),
            session.clone(),
            Zeroizing::new(der),
            [0; 4],
            start,
            end,
        ))
    }

    pub(crate) fn run_audit() -> Result<(), Box<dyn Error>> {
        gss_objects_redact_credentials()?;
        negoex_objects_redact_keys()
    }

    /// A `NegoEx` mechanism whose keys are known bytes, available at once.
    struct KeyedMechanism(Vec<u8>);

    impl negoex::Mechanism for KeyedMechanism {
        fn oid(&self) -> &[u8] {
            &[0x69, 0x85, 0xa2, 0xc0, 0xac, 0x66]
        }

        fn auth_scheme(&self) -> negoex::AuthScheme {
            negoex::AuthScheme::from_bytes([7; 16])
        }

        fn session(&self, _role: negoex::Role) -> Box<dyn negoex::Session> {
            Box::new(KeyedSession(self.0.clone()))
        }
    }

    /// The session of [`KeyedMechanism`]: one hop, the same key both ways.
    struct KeyedSession(Vec<u8>);

    impl negoex::Session for KeyedSession {
        fn query_meta_data(&mut self, _: &negoex::Request) -> Result<Vec<u8>, negoex::ProviderFailure> {
            Ok(Vec::new())
        }

        fn exchange_meta_data(
            &mut self,
            _: &negoex::Request,
            _: &[u8],
        ) -> Result<(), negoex::ProviderFailure> {
            Ok(())
        }

        fn init_sec_context(
            &mut self,
            _: &negoex::Request,
            _: Option<&[u8]>,
        ) -> Result<negoex::MechanismStep, negoex::ProviderFailure> {
            Ok(negoex::MechanismStep::complete(Some(vec![1])))
        }

        fn accept_sec_context(
            &mut self,
            _: &negoex::Request,
            _: &[u8],
        ) -> Result<negoex::MechanismStep, negoex::ProviderFailure> {
            Ok(negoex::MechanismStep::complete(None))
        }

        fn keys(&self) -> negoex::VerifyKeys {
            negoex::VerifyKeys::none()
                .with_checksum_key(EncryptionKey::new(18, self.0.clone()))
                .with_verify_key(EncryptionKey::new(18, self.0.clone()))
        }
    }

    /// `NegoEx` contexts and their SPNEGO drivers never show a mechanism key.
    #[test]
    fn negoex_objects_redact_keys() -> Result<(), Box<dyn Error>> {
        let key = [pattern(33), pattern(49)].concat();
        let mut registry = rskrb5_ng::extensions::Registry::new();
        registry.register(rskrb5_ng::extensions::Extension::GssMechanism(
            std::sync::Arc::new(Registered),
        ))?;
        let mechanisms: Vec<std::sync::Arc<dyn negoex::Mechanism>> =
            vec![std::sync::Arc::new(KeyedMechanism(key.clone()))];
        let mut initiator = negoex::Context::initiator(&registry, &mechanisms, negoex::Request::new())?;
        let step = initiator.step(None)?;
        redacted(&step, &[step.token().ok_or("a first token")?]);
        let first = step.into_token().ok_or("a first token")?;
        redacted(&initiator, &[&key]);
        let failing = pattern(177);
        redacted(
            &negoex::ProviderFailure::new("mechanism failed").with_output_token(failing.clone()),
            &[&failing],
        );
        redacted(
            &negoex::VerifyKeys::none().with_checksum_key(EncryptionKey::new(18, key.clone())),
            &[&key],
        );
        let scheme = negoex::AuthScheme::from_bytes([7; 16]);
        let token = pattern(145);
        let exchange =
            negoex::ExchangeMessage::new(negoex::MessageType::ApRequest, scheme, token.clone())?;
        redacted(&exchange, &[&token]);
        redacted(&negoex::Message::Exchange(exchange), &[&token]);
        let checksum = pattern(161);
        redacted(
            &negoex::VerifyMessage::new(scheme, 16, checksum.clone()),
            &[&checksum],
        );
        let mut acceptor = negoex::Context::acceptor(&registry, &mechanisms, negoex::Request::new())?;
        drop(acceptor.step(Some(&first))?);
        redacted(&acceptor, &[&key]);
        let mut spnego_initiator = spnego::negoex::Initiator::new(negoex::Context::initiator(
            &registry,
            &mechanisms,
            negoex::Request::new(),
        )?);
        let InitStep::Continue(offer) = spnego_initiator.init_sec_context(None)? else {
            return Err("the acceptor's answer is awaited".into());
        };
        redacted(&spnego_initiator, &[&key]);
        let mut spnego_acceptor = spnego::negoex::Acceptor::new(negoex::Context::acceptor(
            &registry,
            &mechanisms,
            negoex::Request::new(),
        )?);
        redacted(&spnego_acceptor, &[&key]);
        let step = spnego_acceptor.accept_sec_context(&offer)?;
        redacted(&step, &[&key]);
        if let spnego::negoex::AcceptStep::Complete(accepted) = step {
            redacted(&*accepted, &[&key]);
        }
        Ok(())
    }

    /// The registry entry of the keyed mechanism.
    struct Registered;

    impl rskrb5_ng::extensions::GssMechanism for Registered {
        fn id(&self) -> &str {
            "keyed"
        }

        fn oid(&self) -> &[u8] {
            &[0x69, 0x85, 0xa2, 0xc0, 0xac, 0x66]
        }
    }

    /// Credentials, stores, contexts, unwrapped messages, the SPNEGO objects and
    /// the error never show their keys, tickets, passwords or messages.
    #[test]
    fn gss_objects_redact_credentials() -> Result<(), Box<dyn Error>> {
        let service_bytes = [pattern(33), pattern(49)].concat();
        let session_bytes = [pattern(65), pattern(81)].concat();
        let service_key = EncryptionKey::new(18, service_bytes.clone());
        let session = EncryptionKey::new(18, session_bytes.clone());
        let ticket = ticket_for(&service_key, &session)?;
        let ticket_bytes = ticket.ticket().to_vec();
        let mut keys = Keytab::new();
        keys.entries_mut().push(keytab::Entry::new(
            keytab::Principal::new("EXAMPLE.COM", 3, ["HTTP", "www.example.com"]),
            0,
            1,
            service_key,
            1,
        ));
        let password = pattern(97);
        let store = CredStore::new().with("password", &String::from_utf8_lossy(&password))?;
        redacted(&store, &[&password]);
        let initiator_credential = Credential::from_service_ticket(&ticket);
        redacted(&initiator_credential, &[&session_bytes, &ticket_bytes]);
        let acceptor_credential = Credential::from_keytab(keys);
        redacted(&acceptor_credential, &[&service_bytes]);
        let target = Name::import(b"HTTP@www.example.com", NameType::HostbasedService)?;
        let mut initiator = gss::Initiator::new(target.clone(), InitiatorOptions::new());
        let InitStep::Continue(first) = initiator.init_sec_context(&initiator_credential, None)?
        else {
            return Err("mutual authentication waits".into());
        };
        redacted(&initiator, &[&session_bytes, &ticket_bytes]);
        let mut acceptor = gss::Acceptor::new(&acceptor_credential, AcceptorOptions::new())?;
        redacted(&acceptor, &[&service_bytes]);
        let accepted = acceptor.accept_sec_context(&first)?;
        redacted(&accepted, &[&session_bytes, &service_bytes]);
        let reply = accepted.output_token().ok_or("an AP-REP")?.to_vec();
        let mut context = accepted.into_context();
        redacted(&context, &[&session_bytes, &service_bytes]);
        drop(initiator.init_sec_context(&initiator_credential, Some(&reply))?);
        let mut established = initiator.into_established()?;
        let message = pattern(113);
        let opened = context.unwrap(&established.wrap(&message, true)?)?;
        redacted(&opened, &[&message]);
        let mut spnego_initiator =
            spnego::Initiator::new(gss::Initiator::new(target, InitiatorOptions::new()));
        let InitStep::Continue(offer) =
            spnego_initiator.init_sec_context(&initiator_credential, None)?
        else {
            return Err("mutual authentication waits".into());
        };
        redacted(&spnego_initiator, &[&session_bytes, &ticket_bytes]);
        let mut spnego_acceptor = spnego::Acceptor::new(gss::Acceptor::new(
            &acceptor_credential,
            AcceptorOptions::new(),
        )?);
        redacted(&spnego_acceptor, &[&service_bytes]);
        let step: AcceptStep = spnego_acceptor.accept_sec_context(&offer)?;
        redacted(&step, &[&session_bytes, &service_bytes]);
        let secret = pattern(129);
        let error = Gss::Spnego(SpnegoError::Client(Box::new(ClientError::Kdc(Box::new(
            KdcError::new(UNIX_EPOCH, 0, 25, Principal::tgt_service("EXAMPLE.COM"))
                .with_e_data(Some(secret.clone().into())),
        )))));
        redacted(&error, &[&secret]);
        Ok(())
    }
}

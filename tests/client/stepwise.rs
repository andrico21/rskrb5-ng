use super::*;

/// The stepwise exchange engine against deterministic fake KDCs (WP-04).
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use alloc::sync::Arc;
    use core::net::{IpAddr, Ipv4Addr};

    use rasn::der;
    use rskrb5_ng::{
        client::{
            AsRepSession,
            stepwise::{
                Answer, Exchange, ExchangeStep, InitCreds, InitCredsOptions, Prompt, Responder,
                StepInput, TicketCreds, TicketOptions, drive,
            },
        },
        crypto::CryptoPolicy,
        extensions::{
            ClientPreauth, Extension, PreauthInput, PreauthState, ProviderError, Registry,
        },
        ticket::encode as encode_ticket,
    };

    use super::*;

    /// A responder that answers every password prompt and counts the prompts.
    struct CountingResponder {
        /// Prompts seen, in order.
        prompts: Vec<Prompt>,
    }

    impl Responder for CountingResponder {
        fn respond(&mut self, prompt: &Prompt) -> Result<Answer, ProviderError> {
            self.prompts.push(prompt.clone());
            Ok(Answer::Password(Password::from_vec(
                TESTUSER_PASSWORD.to_vec(),
            )))
        }
    }

    /// The AS template of the fake-KDC tests.
    fn as_options() -> Result<AsReq, TestError> {
        Ok(AsReq::new(timestamp(1_893_553_447)?, 0x1122_3344).with_etypes(vec![18_i32]))
    }

    /// The outbound request of `step`, or a test failure.
    fn outbound(step: ExchangeStep) -> Result<(String, Vec<u8>, bool), TestError> {
        if let ExchangeStep::Outbound(outbound) = step {
            return Ok((
                outbound.realm().to_owned(),
                outbound.message().to_vec(),
                outbound.follow_up(),
            ));
        }
        Err(format!("expected an outbound request, got {step:?}").into())
    }

    /// Multi-round password exchange: probe, prompt, preauthenticated request, AS-REP.
    #[test]
    fn password_exchange_prompts_once_and_completes() -> Result<(), TestError> {
        let client = Principal::user("TEST.GOKRB5", "testuser1");
        let reply_key =
            derive_password_reply_key(&client, TESTUSER_PASSWORD, &password_key_info())?;
        let mut kdc = PreauthTransport::new(reply_key, None);
        let mut exchange =
            InitCreds::with_password(client.clone(), None, InitCredsOptions::new(as_options()?));

        let (realm, first, follow_up) = outbound(exchange.step(StepInput::Start)?)?;
        assert_eq!((realm.as_str(), follow_up), ("TEST.GOKRB5", false));
        let challenge = kdc.send(&realm, &first)?;
        let prompt = exchange.step(StepInput::Reply(&challenge))?;
        let ExchangeStep::Prompt(Prompt::Password { client: asked }) = prompt else {
            return Err(format!("expected a password prompt, got {prompt:?}").into());
        };
        assert_eq!(asked, client);
        let answer = Answer::Password(Password::from_vec(TESTUSER_PASSWORD.to_vec()));
        assert_eq!(format!("{answer:?}"), "Answer::Password([REDACTED])");
        let (second_realm, second, continued) =
            outbound(exchange.step(StepInput::Answer(answer))?)?;
        assert!(
            continued,
            "the preauthenticated request continues the exchange"
        );
        let reply = kdc.send(&second_realm, &second)?;
        let ExchangeStep::Complete(session) = exchange.step(StepInput::Reply(&reply))? else {
            return Err("expected the finished credential".into());
        };

        assert_eq!(kdc.calls, 2);
        assert_eq!(session.client(), &client);
        assert_eq!(session.service(), &Principal::tgt_service("TEST.GOKRB5"));
        assert!(matches!(
            exchange.step(StepInput::Start),
            Err(Error::UnexpectedStepInput { expected: _ })
        ));
        Ok(())
    }

    /// The blocking driver answers prompts through the responder.
    #[test]
    fn drive_answers_prompts_through_the_responder() -> Result<(), TestError> {
        let client = Principal::user("TEST.GOKRB5", "testuser1");
        let reply_key =
            derive_password_reply_key(&client, TESTUSER_PASSWORD, &password_key_info())?;
        let mut kdc = PreauthTransport::new(reply_key, None);
        let mut responder = CountingResponder {
            prompts: Vec::new(),
        };
        let mut exchange =
            InitCreds::with_password(client.clone(), None, InitCredsOptions::new(as_options()?));

        let session = drive(&mut kdc, &mut exchange, &mut responder)?;

        assert_eq!(session.client(), &client);
        assert_eq!(responder.prompts, [Prompt::Password { client }]);
        Ok(())
    }

    /// QA failure scenario: an AS-REP that answers another nonce is rejected.
    #[test]
    fn replayed_as_rep_with_another_nonce_is_rejected() -> Result<(), TestError> {
        let client = Principal::user("TEST.GOKRB5", "testuser1");
        let keytab = keytab_with_reply_key(3)?;
        let mut exchange =
            InitCreds::with_keytab(client, keytab, InitCredsOptions::new(as_options()?));
        let (_, request, _) = outbound(exchange.step(StepInput::Start)?)?;
        let decoded: rasn_kerberos::AsReq = der::decode(&request)?;
        let built = built_request_from_der(decoded, &request)?;
        let replayed = synthetic_as_rep(&built, built.nonce().wrapping_add(1))?;

        let result = exchange.step(StepInput::Reply(&replayed));

        assert!(
            matches!(result, Err(Error::NonceMismatch { expected, actual }) if actual == expected.wrapping_add(1)),
            "{result:?}"
        );
        Ok(())
    }

    /// An input the exchange does not expect is refused and the state is kept.
    #[test]
    fn unexpected_input_keeps_the_exchange() -> Result<(), TestError> {
        let client = Principal::user("TEST.GOKRB5", "testuser1");
        let mut exchange = InitCreds::with_keytab(
            client,
            keytab_with_reply_key(3)?,
            InitCredsOptions::new(as_options()?),
        );
        assert!(matches!(
            exchange.step(StepInput::Reply(b"early")),
            Err(Error::UnexpectedStepInput { expected: "start" })
        ));
        assert!(matches!(
            exchange.step(StepInput::Start)?,
            ExchangeStep::Outbound(_)
        ));
        Ok(())
    }

    /// Request addresses come from the options; none by default.
    #[test]
    fn addresses_follow_the_options() -> Result<(), TestError> {
        let client = Principal::user("TEST.GOKRB5", "testuser1");
        for (addresses, expected) in [
            (Vec::new(), None),
            (
                vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
                Some(vec![(2_i32, vec![127_u8, 0, 0, 1])]),
            ),
        ] {
            let options = InitCredsOptions::new(as_options()?).with_addresses(addresses);
            let mut exchange =
                InitCreds::with_keytab(client.clone(), keytab_with_reply_key(3)?, options);
            let (_, request, _) = outbound(exchange.step(StepInput::Start)?)?;
            let decoded: rasn_kerberos::AsReq = der::decode(&request)?;
            let actual = decoded.0.req_body.addresses.map(|list| {
                list.iter()
                    .map(|address| (address.addr_type, address.address.to_vec()))
                    .collect::<Vec<_>>()
            });
            assert_eq!(actual, expected);
        }
        Ok(())
    }

    /// `noaddresses = false` binds requests to `extra_addresses` and fails without them.
    #[test]
    fn extra_addresses() -> Result<(), TestError> {
        let bound =
            Config::parse("[libdefaults]\n noaddresses = false\n extra_addresses = 192.0.2.7\n")?;
        let options = InitCredsOptions::from_config(&bound, timestamp(1_893_553_447)?, 7)?;
        assert_eq!(
            options.request().addresses(),
            [IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7))]
        );
        let unbound = Config::parse("[libdefaults]\n noaddresses = false\n")?;
        assert!(matches!(
            InitCredsOptions::from_config(&unbound, timestamp(1_893_553_447)?, 7),
            Err(Error::NoRequestAddresses)
        ));
        let default = InitCredsOptions::from_config(&Config::new(), timestamp(1_893_553_447)?, 7)?;
        assert_eq!(
            default.request().addresses(),
            [IpAddr::V4(Ipv4Addr::UNSPECIFIED); 0]
        );
        Ok(())
    }

    /// The forwardable and proxiable options set and clear their request bits.
    #[test]
    fn flag_options_set_request_bits() -> Result<(), TestError> {
        let options = InitCredsOptions::new(as_options()?)
            .with_forwardable(true)
            .with_proxiable(true);
        assert_eq!(
            options.request().kdc_option_bits() & 0x5000_0000,
            0x5000_0000
        );
        let cleared = options.with_forwardable(false).with_proxiable(false);
        assert_eq!(cleared.request().kdc_option_bits() & 0x5000_0000, 0);
        Ok(())
    }

    /// Under `kdc_timesync` a reply from a skewed KDC is accepted and its offset kept;
    /// without it the reply start time must be within the clock skew.
    #[test]
    fn kdc_timesync() -> Result<(), TestError> {
        let now = timestamp(1_893_553_447)?;
        assert!(InitCredsOptions::from_config(&Config::new(), now, 1)?.kdc_timesync());
        let off = Config::parse("[libdefaults]\n kdc_timesync = 0\n")?;
        assert!(!InitCredsOptions::from_config(&off, now, 1)?.kdc_timesync());
        let client = Principal::user("TEST.GOKRB5", "testuser1");
        for timesync in [false, true] {
            let options = InitCredsOptions::new(as_options()?).with_kdc_timesync(timesync);
            let mut exchange =
                InitCreds::with_keytab(client.clone(), keytab_with_reply_key(3)?, options);
            let (_, request, _) = outbound(exchange.step(StepInput::Start)?)?;
            let decoded: rasn_kerberos::AsReq = der::decode(&request)?;
            let mut built = built_request_from_der(decoded, &request)?;
            let kdc_clock = timestamp(1_893_553_447 + 3_600)?;
            built.set_reply_clock((kdc_clock, built.reply_clock().1));
            let reply = synthetic_as_rep(&built, built.nonce())?;

            let result = exchange.step(StepInput::Reply(&reply));

            if timesync {
                assert!(matches!(result?, ExchangeStep::Complete(_)));
                let offset = exchange.kdc_time_offset().ok_or("offset")?;
                assert!((3_300..=3_900).contains(&offset), "offset {offset}");
            } else {
                assert!(
                    matches!(result, Err(Error::ReplyTimeConstraint)),
                    "{result:?}"
                );
                assert_eq!(exchange.kdc_time_offset(), None);
            }
        }
        Ok(())
    }

    /// A referral chain is followed within its bound and stops beyond it.
    #[test]
    fn referrals_are_followed_within_their_bound() -> Result<(), TestError> {
        let service = Principal::new("OTHER.GOKRB5", 2, ["HTTP", "host.other.gokrb5"]);
        let referral_key = EncryptionKey::new(18, decode_hex(SERVICE_SESSION_KEY)?);
        for max in [0_usize, 1] {
            let tgt = sample_tgt_session()?;
            let options = TicketOptions::new(
                TgsReq::new(timestamp(1_893_553_450)?, 0x7766_5544).with_etypes(vec![18_i32]),
            )
            .with_max_referrals(max);
            let mut exchange = TicketCreds::new(tgt.clone(), service.clone(), options)
                .map_err(|error| error.to_string())?;
            let (realm, first, _) = outbound(
                exchange
                    .step(StepInput::Start)
                    .map_err(|error| error.to_string())?,
            )?;
            assert_eq!(realm, "TEST.GOKRB5");
            let decoded: rasn_kerberos::TgsReq = der::decode(&first)?;
            let built = built_tgs_request_from_der(decoded, &first)?;
            assert_eq!(
                built.service(),
                &Principal::new("TEST.GOKRB5", 2, ["krbtgt", "OTHER.GOKRB5"])
            );
            let referral = synthetic_tgs_rep(&built, built.nonce(), tgt.session_key())?;
            let next = exchange.step(StepInput::Reply(&referral));
            if max == 0 {
                assert!(
                    matches!(next, Err(Error::MaxReferralDepth { max: 0 })),
                    "{next:?}"
                );
                continue;
            }
            let (referred_realm, second, _) = outbound(next.map_err(|error| error.to_string())?)?;
            assert_eq!(referred_realm, "OTHER.GOKRB5");
            let referred: rasn_kerberos::TgsReq = der::decode(&second)?;
            let mut referred_built = built_tgs_request_from_der(referred, &second)?;
            referred_built.set_client(tgt.client().clone());
            let reply = synthetic_tgs_rep(&referred_built, referred_built.nonce(), &referral_key)?;
            let ExchangeStep::Complete(ticket) = exchange
                .step(StepInput::Reply(&reply))
                .map_err(|error| error.to_string())?
            else {
                return Err("expected the service ticket".into());
            };
            assert_eq!(ticket.service(), &service);
            assert_eq!(exchange.referral_tgts().len(), 1);
        }
        Ok(())
    }

    /// A user-to-user request names the second ticket and sets ENC-TKT-IN-SKEY.
    #[test]
    fn user_to_user_request_carries_the_second_ticket() -> Result<(), TestError> {
        let tgt = sample_tgt_session()?;
        let server_tgt = sample_tgt_session()?;
        let service = Principal::user("TEST.GOKRB5", "u2u-server");
        let options = TicketOptions::new(
            TgsReq::new(timestamp(1_893_553_450)?, 0x7766_5544).with_etypes(vec![18_i32]),
        )
        .with_user_to_user(server_tgt.ticket())?;
        let mut exchange = TicketCreds::new(tgt, service, options)?;

        let (_, request, _) = outbound(exchange.step(StepInput::Start)?)?;

        let decoded: rasn_kerberos::TgsReq = der::decode(&request)?;
        let body = &decoded.0.req_body;
        let bits = u32::from_be_bytes(body.kdc_options.0.as_raw_slice().try_into()?);
        assert_eq!(bits & 0x0000_0008, 0x0000_0008, "ENC-TKT-IN-SKEY");
        let tickets = body
            .additional_tickets
            .as_ref()
            .ok_or("additional tickets")?;
        assert_eq!(tickets.len(), 1);
        assert_eq!(
            encode_ticket(tickets.first().ok_or("ticket")?)?,
            server_tgt.ticket().as_slice()
        );
        assert!(matches!(
            TicketOptions::new(TgsReq::new(UNIX_EPOCH, 1)).with_user_to_user(b"not a ticket"),
            Err(Error::Decode {
                target: _,
                message: _
            })
        ));
        Ok(())
    }

    /// A registered mechanism for PA type 1000 that answers with a marker.
    struct Marker;

    impl PreauthState for Marker {
        fn process(
            &mut self,
            input: &PreauthInput<'_>,
        ) -> Result<Vec<rasn_kerberos::PaData>, ProviderError> {
            Ok(vec![rasn_kerberos::PaData {
                r#type: input.pa_type,
                value: b"marker".to_vec().into(),
            }])
        }
    }

    impl ClientPreauth for Marker {
        fn id(&self) -> &'static str {
            "marker"
        }

        fn pa_types(&self) -> &[i32] {
            &[1000]
        }

        fn start(&self) -> Box<dyn PreauthState> {
            Box::new(Self)
        }
    }

    /// A `PREAUTH_REQUIRED` error offering encrypted timestamp, ETYPE-INFO2 and PA type 1000.
    fn challenge_offering_the_marker() -> Result<Vec<u8>, TestError> {
        let mut error: rasn_kerberos::KrbError = der::decode(&synthetic_preauth_required_error()?)?;
        let mut offers: rasn_kerberos::MethodData =
            der::decode(error.e_data.as_ref().ok_or("METHOD-DATA")?)?;
        offers.insert(
            0,
            rasn_kerberos::PaData {
                r#type: 2,
                value: Vec::new().into(),
            },
        );
        offers.push(rasn_kerberos::PaData {
            r#type: 1000,
            value: Vec::new().into(),
        });
        error.e_data = Some(der::encode(&offers)?.into());
        Ok(der::encode(&error)?)
    }

    /// `preferred_preauth_types` decides between a registered mechanism and
    /// encrypted timestamp: the preferred mechanism answers, else the built-in one.
    #[test]
    fn preferred_preauth_types() -> Result<(), TestError> {
        let profile = Config::parse("[libdefaults]\n preferred_preauth_types = 1000, 2\n")?;
        let configured = InitCredsOptions::from_config(&profile, timestamp(1_893_553_447)?, 1)?;
        assert_eq!(configured.preferred_preauth_types(), [1000_i32, 2_i32]);
        let client = Principal::user("TEST.GOKRB5", "testuser1");
        let config = Config::new();
        let policy = CryptoPolicy::from_libdefaults(&config.libdefaults)?;
        let mut registry = Registry::new();
        registry.register(Extension::ClientPreauth(Arc::new(Marker)))?;
        for (preferred, expected) in [(vec![1000_i32], 1000_i32), (Vec::new(), 2_i32)] {
            let options =
                InitCredsOptions::new(as_options()?).with_preferred_preauth_types(preferred);
            let password = Password::from_vec(TESTUSER_PASSWORD.to_vec());
            let mut exchange = InitCreds::with_password(client.clone(), Some(password), options)
                .with_preauth(registry.preauth_session(&config, &policy));
            drop(outbound(exchange.step(StepInput::Start)?)?);

            let (_, request, _) =
                outbound(exchange.step(StepInput::Reply(&challenge_offering_the_marker()?))?)?;

            let decoded: rasn_kerberos::AsReq = der::decode(&request)?;
            let types: Vec<i32> = decoded
                .0
                .padata
                .iter()
                .flatten()
                .map(|entry| entry.r#type)
                .filter(|pa_type| [2_i32, 1000_i32].contains(pa_type))
                .collect();
            assert_eq!(types, [expected]);
        }
        Ok(())
    }

    /// An exchange that completes at once and reports a key expiration.
    struct Expiring(Option<AsRepSession>);

    impl Exchange for Expiring {
        fn advance(&mut self, _input: StepInput<'_>) -> Result<ExchangeStep, Error> {
            let session = self.0.take().ok_or(Error::NoTgtSession)?;
            Ok(ExchangeStep::Complete(Box::new(session)))
        }

        fn key_expiration(&self) -> Option<SystemTime> {
            timestamp(1_893_600_000).ok()
        }
    }

    /// A responder that records password-expiry notices.
    struct ExpiryResponder(Vec<SystemTime>);

    impl Responder for ExpiryResponder {
        fn respond(&mut self, prompt: &Prompt) -> Result<Answer, ProviderError> {
            Err(format!("unexpected {prompt:?}").into())
        }

        fn password_expiry(&mut self, expires: SystemTime) {
            self.0.push(expires);
        }
    }

    /// The driver hands a finished exchange's key expiration to the responder
    /// (MIT `krb5_get_init_creds_opt_set_expire_callback`).
    #[test]
    fn drive_reports_the_password_expiry() -> Result<(), TestError> {
        let mut responder = ExpiryResponder(Vec::new());
        let mut exchange = Expiring(Some(sample_tgt_session()?));
        let mut kdc = PreauthTransport::new(EncryptionKey::new(18, vec![0_u8; 32]), None);

        drop(drive(&mut kdc, &mut exchange, &mut responder)?);

        assert_eq!(responder.0, [timestamp(1_893_600_000)?]);
        assert_eq!(kdc.calls, 0, "a finished exchange sends nothing");
        Ok(())
    }
}

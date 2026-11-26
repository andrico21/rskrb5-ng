//! The stepwise engine against MIT krb5 1.22.2: AS with prompt and preauth, AS with
//! a keytab, profile flags and renewal, plain and user-to-user TGS, referrals.

extern crate alloc;

use alloc::sync::Arc;
use core::{error::Error, time::Duration};
use std::{
    io,
    time::{SystemTime, UNIX_EPOCH},
};

use rasn::{der, types::GeneralString};
use rskrb5_ng::{
    client::{
        AsRepSession, Password,
        options::TgsReq,
        principal::Principal,
        stepwise::{
            Answer, ExchangeStep, InitCreds, InitCredsOptions, NoResponder, Prompt, Responder,
            StepInput, TicketCreds, TicketOptions, drive_tokio,
        },
        transport::{KdcProtocol, Tokio as KdcTransport},
    },
    config::Config,
    error::Client as ClientError,
    extensions::{
        Extension, LocateRequest, LocateService, ProviderError, Registry, ServerAddress,
        ServerLocator,
    },
    keytab::{self, Keytab},
    ticket,
};
use tokio::runtime::{Builder, Runtime};

use crate::harness::{
    self, Fixture, assert_negotiated_enctype, assert_negotiated_padata, assert_ticket_flag,
};

/// Enctype ID of `aes256-cts-hmac-sha384-192`, the strongest key of both realms.
const AES256_SHA2: i32 = 20;

/// PA type of the encrypted timestamp (RFC 4120 section 5.2.7.2).
const PA_ENC_TIMESTAMP: i32 = 2;

/// The TEST.RSKRB5 KDC (fixture `mit-kdc`).
const MIT_KDC: Fixture = Fixture::new("mit-kdc", "INTEROP_MIT_KDC");

/// The OTHER.RSKRB5 KDC (fixture `mit-other`).
const MIT_OTHER_KDC: Fixture = Fixture::new("mit-other", "INTEROP_MIT_OTHER_KDC");

/// The current-thread Tokio runtime the scenarios run on.
fn runtime() -> io::Result<Runtime> {
    Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
}

/// A KDC transport with a ten-second timeout.
fn transport() -> KdcTransport {
    KdcTransport::new().with_timeout(Duration::from_secs(10))
}

/// A nonce unique to `sequence` and the current time.
fn nonce(sequence: u32) -> Result<u32, Box<dyn Error>> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH)?;
    Ok(u32::try_from(elapsed.as_nanos() & 0x00ff_ffff)? | sequence.wrapping_shl(24))
}

/// Both realms with `libdefaults` added to `[libdefaults]`.
fn config(libdefaults: &str) -> Result<Config, Box<dyn Error>> {
    let realm = harness::var("INTEROP_MIT_REALM")?;
    let other = harness::var("INTEROP_MIT_OTHER_REALM")?;
    Ok(Config::parse(&format!(
        "[libdefaults]\n default_realm = {realm}\n dns_lookup_kdc = false\n{libdefaults}\
         [realms]\n {realm} = {{\n  kdc = {}\n }}\n {other} = {{\n  kdc = {}\n }}\n",
        harness::var("INTEROP_MIT_KDC")?,
        harness::var("INTEROP_MIT_OTHER_KDC")?,
    ))?)
}

/// A TEST.RSKRB5 user named by the env key `user` with the password under `password`.
fn user(user: &str, password: &str) -> Result<(Principal, Password), Box<dyn Error>> {
    Ok((
        Principal::user(harness::var("INTEROP_MIT_REALM")?, harness::var(user)?),
        Password::from_vec(harness::var(password)?.into_bytes()),
    ))
}

/// The enctype of the encrypted part of the DER `ticket`.
fn ticket_etype(ticket: &[u8]) -> Result<i32, Box<dyn Error>> {
    Ok(ticket::decode(ticket)?.enc_part.etype)
}

/// The TGT of `principal`, through the Tokio driver.
async fn tgt(
    config: &Config,
    (principal, password): (Principal, Password),
    sequence: u32,
) -> Result<AsRepSession, Box<dyn Error>> {
    let options = InitCredsOptions::from_config(config, SystemTime::now(), nonce(sequence)?)?;
    let mut exchange = InitCreds::with_password(principal, Some(password), options);
    Ok(drive_tokio(
        &transport(),
        (config, KdcProtocol::Tcp),
        &mut exchange,
        &mut NoResponder::default(),
    )
    .await?)
}

/// TGS options from the profile with a fresh nonce.
fn tgs_options(config: &Config, sequence: u32) -> Result<TgsReq, Box<dyn Error>> {
    Ok(TgsReq::from_libdefaults(
        SystemTime::now(),
        nonce(sequence)?,
        &config.libdefaults,
    )?)
}

/// Answers password prompts from one password and counts them.
struct Prompted {
    /// The password to answer with.
    password: Vec<u8>,
    /// The prompts seen.
    prompts: Vec<Prompt>,
}

impl Responder for Prompted {
    fn respond(&mut self, prompt: &Prompt) -> Result<Answer, ProviderError> {
        self.prompts.push(prompt.clone());
        Ok(Answer::Password(Password::from_vec(self.password.clone())))
    }
}

/// The `requires_preauth` user is prompted for once and preauthenticates.
///
/// Without a password up front the engine sends an unauthenticated AS-REQ, the
/// KDC answers `PREAUTH_REQUIRED`, the engine prompts once, and its next request
/// carries the encrypted timestamp the KDC accepts.
#[test]
fn as_exchange_prompts_and_answers_the_preauth_challenge() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "as_exchange_prompts_and_answers_the_preauth_challenge",
        &[MIT_KDC],
    )? {
        return Ok(());
    }
    runtime()?.block_on(async {
        // The realm also offers SPAKE first (plan 2 todo 9, `krb5.conf.d/30-spake.conf`),
        // which the engine would answer with the `spake` leaf; an empty group list
        // keeps this scenario on the encrypted-timestamp prompt flow it proves.
        let config = config(" spake_preauth_groups =\n")?;
        let client = Principal::user(
            harness::var("INTEROP_MIT_REALM")?,
            harness::var("INTEROP_MIT_PREAUTH_USER")?,
        );
        let mut responder = Prompted {
            password: harness::var("INTEROP_MIT_PREAUTH_USER_PASSWORD")?.into_bytes(),
            prompts: Vec::new(),
        };
        let options = InitCredsOptions::from_config(&config, SystemTime::now(), nonce(1)?)?;
        let mut exchange = InitCreds::with_password(client.clone(), None, options);
        let mut requests: Vec<Vec<i32>> = Vec::new();
        let mut reply: Option<Vec<u8>> = None;
        let mut answer: Option<Answer> = None;
        let session = loop {
            let input = match (answer.take(), &reply) {
                (Some(pending), _) => StepInput::Answer(pending),
                (None, Some(bytes)) => StepInput::Reply(bytes),
                (None, None) => StepInput::Start,
            };
            match exchange.step(input)? {
                ExchangeStep::Outbound(outbound) => {
                    let request: rasn_kerberos::AsReq = der::decode(outbound.message())?;
                    requests.push(
                        request
                            .0
                            .padata
                            .iter()
                            .flatten()
                            .map(|entry| entry.r#type)
                            .collect(),
                    );
                    reply = Some(
                        transport()
                            .send_to_realm(
                                &config,
                                KdcProtocol::Tcp,
                                outbound.realm(),
                                outbound.message(),
                            )
                            .await?,
                    );
                }
                ExchangeStep::Prompt(prompt) => {
                    answer = Some(
                        responder
                            .respond(&prompt)
                            .map_err(|error| error.to_string())?,
                    );
                }
                ExchangeStep::Complete(session) => break session,
                _ => return Err("unknown exchange step".into()),
            }
        };

        assert_eq!(
            responder.prompts,
            [Prompt::Password {
                client: client.clone()
            }],
            "one password prompt"
        );
        assert_eq!(
            requests.len(),
            2,
            "the unauthenticated and the preauthenticated request"
        );
        assert_negotiated_padata(
            "the second AS-REQ",
            PA_ENC_TIMESTAMP,
            requests.get(1).map_or(&[][..], Vec::as_slice),
        )?;
        assert_eq!(session.client(), &client);
        assert_eq!(
            session.service(),
            &Principal::tgt_service(client.realm.clone())
        );
        assert_negotiated_enctype("TGT", AES256_SHA2, ticket_etype(session.ticket())?)?;
        Ok::<_, Box<dyn Error>>(())
    })
}

/// A keytab exchange for the HTTP service principal through the Tokio driver.
#[test]
fn keytab_exchange_obtains_the_service_principal_tgt() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "keytab_exchange_obtains_the_service_principal_tgt",
        &[MIT_KDC],
    )? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let config = config("")?;
        let realm = harness::var("INTEROP_MIT_REALM")?;
        let service = harness::var("INTEROP_MIT_HTTP_SERVICE")?;
        let client = Principal::new(realm.clone(), 1, service.split('/'));
        let keytab = Keytab::load(harness::var("INTEROP_MIT_HTTP_KEYTAB")?)?;
        let options = InitCredsOptions::from_config(&config, SystemTime::now(), nonce(2)?)?;
        let mut exchange = InitCreds::with_keytab(client.clone(), keytab, options);

        let session = drive_tokio(
            &transport(),
            (&config, KdcProtocol::Tcp),
            &mut exchange,
            &mut NoResponder::default(),
        )
        .await?;

        assert_eq!(session.client().components, client.components);
        assert_eq!(session.service(), &Principal::tgt_service(realm));
        assert_negotiated_enctype("TGT", AES256_SHA2, ticket_etype(session.ticket())?)?;
        Ok::<_, Box<dyn Error>>(())
    })
}

/// `forwardable` and `renew_lifetime` of the profile reach the AS request through
/// `InitCredsOptions::from_config`; the KDC grants both flags, and the renewable
/// TGT renews with the same authentication time.
#[test]
fn profile_flags_reach_the_kdc_and_the_tgt_renews() -> Result<(), Box<dyn Error>> {
    if !harness::require("profile_flags_reach_the_kdc_and_the_tgt_renews", &[MIT_KDC])? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let config = config(" forwardable = true\n renew_lifetime = 1d\n ticket_lifetime = 2h\n")?;
        let first = tgt(
            &config,
            user("INTEROP_MIT_USER", "INTEROP_MIT_USER_PASSWORD")?,
            3,
        )
        .await?;

        assert_ticket_flag("forwardable", 1, first.ticket_flags())?;
        assert_ticket_flag("renewable", 8, first.ticket_flags())?;
        let renewed = transport()
            .renew_tgt_with_config(&config, KdcProtocol::Tcp, &first, tgs_options(&config, 4)?)
            .await?;
        assert_eq!(
            renewed.auth_time(),
            first.auth_time(),
            "a renewal keeps authtime"
        );
        assert_eq!(renewed.service(), first.service());
        assert_ticket_flag("renewable", 8, renewed.ticket_flags())?;
        Ok::<_, Box<dyn Error>>(())
    })
}

/// A plain TGS exchange for the HTTP service (opened with its keytab), and a
/// user-to-user exchange whose ticket is encrypted in the target user's TGT
/// session key (RFC 4120 section 3.7, ENC-TKT-IN-SKEY).
#[test]
fn ticket_exchange_plain_and_user_to_user() -> Result<(), Box<dyn Error>> {
    if !harness::require("ticket_exchange_plain_and_user_to_user", &[MIT_KDC])? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let config = config("")?;
        let realm = harness::var("INTEROP_MIT_REALM")?;
        let (alice, password) = user("INTEROP_MIT_USER", "INTEROP_MIT_USER_PASSWORD")?;
        let client = tgt(&config, (alice.clone(), password), 5).await?;

        let http = Principal::new(
            realm.clone(),
            2,
            harness::var("INTEROP_MIT_HTTP_SERVICE")?.split('/'),
        );
        let mut plain = TicketCreds::new(
            client.clone(),
            http.clone(),
            TicketOptions::new(tgs_options(&config, 6)?),
        )?;
        let service_ticket = drive_tokio(
            &transport(),
            (&config, KdcProtocol::Tcp),
            &mut plain,
            &mut NoResponder::default(),
        )
        .await
        .map_err(|error| format!("plain TGS exchange: {error}"))?;
        assert_eq!(service_ticket.service(), &http);
        let wire = ticket::decode(service_ticket.ticket())?;
        assert_negotiated_enctype("HTTP service ticket", AES256_SHA2, wire.enc_part.etype)?;
        let keytab = Keytab::load(harness::var("INTEROP_MIT_HTTP_KEYTAB")?)?;
        let key = keytab
            .entries()
            .iter()
            .map(keytab::Entry::key)
            .find(|key| key.etype() == wire.enc_part.etype)
            .ok_or("no HTTP key of the ticket's enctype")?;
        let opened = ticket::decrypt_ticket_enc_part(&wire, key)?;
        assert_eq!(
            opened.cname.string.first().map(GeneralString::as_bytes),
            alice.components.first().map(String::as_bytes)
        );

        // The requester is the preauthenticated user: MIT refuses a TGS request whose
        // TGT lacks the pre-authent flag for a +requires_preauth server
        // (kdc_tgs.c "NO PREAUTH"), so the requires_preauth user asks for a ticket to
        // the plain user, encrypted in the plain user's TGT session key.
        let (requester, requester_password) = user(
            "INTEROP_MIT_PREAUTH_USER",
            "INTEROP_MIT_PREAUTH_USER_PASSWORD",
        )?;
        let requester_tgt = tgt(&config, (requester.clone(), requester_password), 7).await?;
        let mut u2u = TicketCreds::new(
            requester_tgt,
            alice,
            TicketOptions::new(tgs_options(&config, 8)?).with_user_to_user(client.ticket())?,
        )?;
        let user_ticket = drive_tokio(
            &transport(),
            (&config, KdcProtocol::Tcp),
            &mut u2u,
            &mut NoResponder::default(),
        )
        .await
        .map_err(|error| format!("user-to-user TGS exchange: {error}"))?;
        let user_wire = ticket::decode(user_ticket.ticket())?;
        let user_opened = ticket::decrypt_ticket_enc_part(&user_wire, client.session_key())
            .map_err(|error| format!("not encrypted in the target TGT session key: {error}"))?;
        assert_eq!(
            user_opened
                .cname
                .string
                .first()
                .map(GeneralString::as_bytes),
            requester.components.first().map(String::as_bytes),
            "the user-to-user ticket names the requesting user"
        );
        Ok::<_, Box<dyn Error>>(())
    })
}

/// A TEST.RSKRB5 TGT reaches the OTHER.RSKRB5 HTTP service through one referral
/// TGT, which the exchange returns; with no referral allowed the chain stops.
#[test]
fn ticket_exchange_follows_the_referral_within_its_bound() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "ticket_exchange_follows_the_referral_within_its_bound",
        &[MIT_KDC, MIT_OTHER_KDC],
    )? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let config = config("")?;
        let realm = harness::var("INTEROP_MIT_REALM")?;
        let other = harness::var("INTEROP_MIT_OTHER_REALM")?;
        let client = tgt(
            &config,
            user("INTEROP_MIT_USER", "INTEROP_MIT_USER_PASSWORD")?,
            9,
        )
        .await?;
        let service = Principal::new(
            other.clone(),
            2,
            harness::var("INTEROP_MIT_OTHER_HTTP_SERVICE")?.split('/'),
        );

        let mut bounded = TicketCreds::new(
            client.clone(),
            service.clone(),
            TicketOptions::new(tgs_options(&config, 10)?).with_max_referrals(0),
        )?;
        let refused = drive_tokio(
            &transport(),
            (&config, KdcProtocol::Tcp),
            &mut bounded,
            &mut NoResponder::default(),
        )
        .await;
        assert!(
            matches!(refused, Err(ClientError::MaxReferralDepth { max: 0 })),
            "{refused:?}"
        );

        let mut exchange = TicketCreds::new(
            client,
            service.clone(),
            TicketOptions::new(tgs_options(&config, 11)?),
        )?;
        let ticket = drive_tokio(
            &transport(),
            (&config, KdcProtocol::Tcp),
            &mut exchange,
            &mut NoResponder::default(),
        )
        .await?;
        let referrals: Vec<_> = exchange
            .referral_tgts()
            .iter()
            .map(|referral| referral.service().clone())
            .collect();
        assert_eq!(
            referrals,
            [Principal::new(realm, 2, ["krbtgt", other.as_str()])],
            "one cross-realm TGT"
        );
        assert_eq!(ticket.service(), &service);
        assert_negotiated_enctype(
            "OTHER service ticket",
            AES256_SHA2,
            ticket_etype(ticket.ticket())?,
        )?;
        Ok::<_, Box<dyn Error>>(())
    })
}

/// The TEST.RSKRB5 KDC, as a registered locator names it (MIT-plugin-6).
struct Located(String, u16);

impl ServerLocator for Located {
    fn id(&self) -> &'static str {
        "interop"
    }

    fn locate(
        &self,
        request: &LocateRequest<'_>,
    ) -> Result<Option<Vec<ServerAddress>>, ProviderError> {
        Ok((request.service == LocateService::Kdc)
            .then(|| vec![ServerAddress::new(self.0.clone(), self.1)]))
    }
}

/// A login to a realm the profile does not list reaches the MIT KDC that a
/// registered locator names: the transport's registry is asked on the exchange
/// route (plan-2 todo 28, MIT-plugin-6).
#[test]
fn a_registered_locator_routes_the_login_to_the_mit_kdc() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "a_registered_locator_routes_the_login_to_the_mit_kdc",
        &[MIT_KDC],
    )? {
        return Ok(());
    }
    runtime()?.block_on(async {
        // Given a profile that does not list the realm and a locator that names its KDC.
        let kdc = harness::var("INTEROP_MIT_KDC")?;
        let (host, port) = kdc
            .rsplit_once(':')
            .map_or(Ok((kdc.as_str(), 88_u16)), |(name, number)| {
                number.parse().map(|parsed| (name, parsed))
            })?;
        let mut registry = Registry::new();
        registry.register(Extension::ServerLocator(Arc::new(Located(
            host.to_owned(),
            port,
        ))))?;
        let config = Config::parse("[libdefaults]\n dns_lookup_kdc = false\n")?;
        let (principal, password) = user("INTEROP_MIT_USER", "INTEROP_MIT_USER_PASSWORD")?;
        let options = InitCredsOptions::from_config(&config, SystemTime::now(), nonce(9)?)?;
        let mut exchange = InitCreds::with_password(principal.clone(), Some(password), options);
        // When the login runs through a transport carrying the registry.
        let session = drive_tokio(
            &transport().with_registry(Arc::new(registry)),
            (&config, KdcProtocol::Tcp),
            &mut exchange,
            &mut NoResponder::default(),
        )
        .await?;
        // Then the MIT KDC issued the TGT of the user.
        assert_eq!(session.client(), &principal);
        Ok::<_, Box<dyn Error>>(())
    })
}

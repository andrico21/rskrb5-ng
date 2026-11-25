//! PKINIT against MIT krb5 1.22.2: certificate logins (DH and ECDH),
//! anonymous PKINIT, and anonymous FAST armor through the FAST hook.

extern crate alloc;

use alloc::sync::Arc;
use core::{error::Error, fmt::Write as _, time::Duration};
use std::{
    fs,
    io::{self, Read as _, Write as _},
    net::TcpStream,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use rasn::der;
use rskrb5_ng::{
    client::{
        AsRepSession, KdcTransport, Password,
        options::TgsReq,
        principal::Principal,
        stepwise::{
            ExchangeStep, InitCreds, InitCredsOptions, NoResponder, StepInput, TicketCreds,
            TicketOptions, drive_tokio,
        },
        transport::{KdcProtocol, Tokio as TokioTransport},
    },
    config::Config,
    error::{Client as ClientError, Pkinit},
    preauth::{
        fast::{ArmorSource, Exchange as Fast, Outcome, PA_FX_FAST, Policy},
        pkinit::{
            AnonymousArmorSource, AnonymousOptions, CertificatePolicy, ConfiguredIdentities,
            DhGroup, Exchange, Identity, KdcTrust, PA_PK_AS_REQ,
        },
    },
};
use tokio::runtime::{Builder, Runtime};

use crate::harness::{self, Fixture, assert_negotiated_padata};

/// The TEST.RSKRB5 KDC (fixture `mit-kdc`).
const MIT_KDC: Fixture = Fixture::new("mit-kdc", "INTEROP_MIT_KDC");

/// The current-thread Tokio runtime the scenarios run on.
fn runtime() -> io::Result<Runtime> {
    Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
}

/// A Tokio KDC transport with a ten-second timeout.
fn transport() -> TokioTransport {
    TokioTransport::new().with_timeout(Duration::from_secs(10))
}

/// A nonce unique to `sequence` and the current time.
fn nonce(sequence: u32) -> Result<u32, Box<dyn Error>> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH)?;
    Ok(u32::try_from(elapsed.as_nanos() & 0x00ff_ffff)? | sequence.wrapping_shl(24))
}

/// The TEST.RSKRB5 realm.
///
/// The realm also offers SPAKE (`krb5.conf.d/30-spake.conf`); an empty group
/// list keeps every password login of these scenarios off SPAKE, so the FAST
/// one runs the encrypted challenge that earns `fast-ec`. A PKINIT login has
/// no password, so it can only run PKINIT.
fn config() -> Result<Config, Box<dyn Error>> {
    let realm = harness::var("INTEROP_MIT_REALM")?;
    Ok(Config::parse(&format!(
        "[libdefaults]\n default_realm = {realm}\n dns_lookup_kdc = false\n spake_preauth_groups =\n\
         [realms]\n {realm} = {{\n  kdc = {}\n }}\n",
        harness::var("INTEROP_MIT_KDC")?,
    ))?)
}

/// The anchor that signed the KDC certificate.
fn trust() -> Result<KdcTrust, Box<dyn Error>> {
    let pem = fs::read(harness::var("INTEROP_MIT_PKINIT_CA")?)?;
    Ok(KdcTrust::from_pem(&pem)?)
}

/// Run `exchange` over the Tokio transport, recording the PA types of every request.
async fn run(
    config: &Config,
    exchange: &mut InitCreds<'_>,
) -> Result<(AsRepSession, Vec<Vec<i32>>), Box<dyn Error>> {
    let mut requests = Vec::new();
    let mut reply: Option<Vec<u8>> = None;
    loop {
        let input = reply.as_deref().map_or(StepInput::Start, StepInput::Reply);
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
                            config,
                            KdcProtocol::Tcp,
                            outbound.realm(),
                            outbound.message(),
                        )
                        .await?,
                );
            }
            ExchangeStep::Complete(session) => return Ok((*session, requests)),
            ExchangeStep::Prompt(_) | _ => return Err("unexpected exchange step".into()),
        }
    }
}

/// pkinituser's certificate login proposing `group`.
async fn certificate_login(
    config: &Config,
    group: DhGroup,
    sequence: u32,
) -> Result<(AsRepSession, Vec<Vec<i32>>), Box<dyn Error>> {
    let realm = harness::var("INTEROP_MIT_REALM")?;
    let client = Principal::user(realm, harness::var("INTEROP_MIT_PKINIT_USER")?);
    let identity = Identity::from_files(
        Path::new(&harness::var("INTEROP_MIT_PKINIT_CERT")?),
        Some(Path::new(&harness::var("INTEROP_MIT_PKINIT_KEY")?)),
    )?;
    let exchange = Exchange::new(
        identity,
        trust()?,
        CertificatePolicy::from_config(config, &harness::var("INTEROP_MIT_REALM")?)?
            .with_group(group),
    );
    let options = InitCredsOptions::from_config(config, SystemTime::now(), nonce(sequence)?)?;
    run(
        config,
        &mut InitCreds::with_pkinit(client, exchange, options),
    )
    .await
}

/// A ticket for `service` (`name/host`) from `tgt`.
async fn service_ticket(
    config: &Config,
    tgt: AsRepSession,
    service: &str,
    sequence: u32,
) -> Result<AsRepSession, Box<dyn Error>> {
    let principal = Principal::new(harness::var("INTEROP_MIT_REALM")?, 2, service.split('/'));
    let options =
        TgsReq::from_libdefaults(SystemTime::now(), nonce(sequence)?, &config.libdefaults)?;
    let mut exchange = TicketCreds::new(tgt, principal, TicketOptions::new(options))?;
    Ok(drive_tokio(
        &transport(),
        (config, KdcProtocol::Tcp),
        &mut exchange,
        &mut NoResponder::default(),
    )
    .await?)
}

/// Both MODP 2048 Diffie-Hellman and P-256 ECDH certificate logins send
/// PA-PK-AS-REQ, authenticate pkinituser, and earn the `pkinit` indicator that
/// `pkinitrequired/svc.test.rskrb5` requires.
#[test]
fn certificate_login_earns_the_pkinit_indicator() -> Result<(), Box<dyn Error>> {
    if !harness::require("certificate_login_earns_the_pkinit_indicator", &[MIT_KDC])? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let config = config()?;
        for (sequence, group) in [(1_u32, DhGroup::Modp2048), (3, DhGroup::P256)] {
            let (session, requests) = certificate_login(&config, group, sequence).await?;
            let last = requests.last().ok_or("no request")?;
            assert_negotiated_padata("the PKINIT AS-REQ", PA_PK_AS_REQ, last)?;
            assert_eq!(
                session.client().components,
                vec![harness::var("INTEROP_MIT_PKINIT_USER")?],
                "{group:?}: the authenticated client"
            );
            let ticket = service_ticket(
                &config,
                session,
                &harness::var("INTEROP_MIT_PKINIT_REQUIRED_SERVICE")?,
                sequence.saturating_add(1),
            )
            .await?;
            assert_eq!(
                ticket.service().components.first().map(String::as_str),
                Some("pkinitrequired"),
                "{group:?}: the pkinit-indicator service ticket"
            );
        }
        Ok(())
    })
}

/// The anonymous TGT of the realm (RFC 6112).
async fn anonymous_tgt(
    config: &Config,
    sequence: u32,
) -> Result<(AsRepSession, Vec<Vec<i32>>), Box<dyn Error>> {
    let realm = harness::var("INTEROP_MIT_REALM")?;
    let options = InitCredsOptions::from_config(config, SystemTime::now(), nonce(sequence)?)?
        .with_anonymous(AnonymousOptions::Full);
    let exchange = Exchange::anonymous(trust()?, CertificatePolicy::from_config(config, &realm)?);
    run(
        config,
        &mut InitCreds::with_pkinit(AnonymousOptions::client(&realm), exchange, options),
    )
    .await
}

/// Anonymous PKINIT yields `WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS`, after the
/// KDC's certificate and its `PA-PKINIT-KX` session-key proof verified.
#[test]
fn anonymous_pkinit_issues_the_anonymous_principal() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "anonymous_pkinit_issues_the_anonymous_principal",
        &[MIT_KDC],
    )? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let config = config()?;
        let (session, requests) = anonymous_tgt(&config, 5).await?;
        assert_negotiated_padata(
            "the anonymous AS-REQ",
            PA_PK_AS_REQ,
            requests.last().ok_or("no request")?,
        )?;
        assert_eq!(
            session.client().realm,
            harness::var("INTEROP_MIT_ANONYMOUS_REALM")?,
            "realm"
        );
        assert_eq!(
            session.client().components.join("/"),
            harness::var("INTEROP_MIT_ANONYMOUS_PRINCIPAL")?,
            "the anonymous client"
        );
        assert_eq!(
            session.service(),
            &Principal::tgt_service(harness::var("INTEROP_MIT_REALM")?),
            "a TGT of the realm"
        );
        Ok(())
    })
}

/// A blocking TCP transport to the realm's KDC for the anonymous-armor hook.
struct Blocking(String);

impl KdcTransport for Blocking {
    fn send(&mut self, _realm: &str, request: &[u8]) -> Result<Vec<u8>, ClientError> {
        let failure = |error: io::Error| ClientError::Transport(error.to_string());
        let mut stream = TcpStream::connect(&self.0).map_err(failure)?;
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .map_err(failure)?;
        let length = u32::try_from(request.len())
            .map_err(|_overflow| ClientError::Transport("request too long".to_owned()))?;
        stream.write_all(&length.to_be_bytes()).map_err(failure)?;
        stream.write_all(request).map_err(failure)?;
        let mut header = [0_u8; 4];
        stream.read_exact(&mut header).map_err(failure)?;
        let mut reply = vec![0_u8; usize::try_from(u32::from_be_bytes(header)).unwrap_or(0)];
        stream.read_exact(&mut reply).map_err(failure)?;
        Ok(reply)
    }
}

/// fastuser's password login armored through `ArmorSource::Anonymous`: the
/// hook obtains an anonymous TGT by anonymous PKINIT, every request carries
/// only PA-FX-FAST, and the TGT earns `fast-ec`.
#[test]
fn anonymous_armor_carries_the_encrypted_challenge() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "anonymous_armor_carries_the_encrypted_challenge",
        &[MIT_KDC],
    )? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let config = config()?;
        let realm = harness::var("INTEROP_MIT_REALM")?;
        let source = AnonymousArmorSource::new(
            Blocking(harness::var("INTEROP_MIT_KDC")?),
            trust()?,
            CertificatePolicy::from_config(&config, &realm)?,
        );
        let mut fast = Fast::new(Policy::Required, ArmorSource::Anonymous(Box::new(source)));
        let client = Principal::user(realm, harness::var("INTEROP_MIT_FAST_USER")?);
        let password =
            Password::from_vec(harness::var("INTEROP_MIT_FAST_USER_PASSWORD")?.into_bytes());
        let options = InitCredsOptions::from_config(&config, SystemTime::now(), nonce(6)?)?;
        let mut login =
            InitCreds::with_password(client, Some(password), options).with_armor(&mut fast);
        let (session, requests) = run(&config, &mut login).await?;
        drop(login);
        assert_eq!(fast.outcome(), Some(Outcome::Armored), "the FAST outcome");
        for request in &requests {
            assert_negotiated_padata("an armored AS-REQ", PA_FX_FAST, request)?;
            assert_eq!(
                request.len(),
                1,
                "only PA-FX-FAST outside the armor: {request:?}"
            );
        }
        let ticket = service_ticket(
            &config,
            session,
            &harness::var("INTEROP_MIT_FAST_REQUIRED_SERVICE")?,
            7,
        )
        .await?;
        assert_eq!(
            ticket.service().components.first().map(String::as_str),
            Some("fastrequired"),
            "the fast-ec service ticket"
        );
        Ok(())
    })
}

/// pkinituser's login by a client that holds three identities.
///
/// A certificate the KDC does not trust (the `tests/pkinit` fixture, listed
/// first), the RSA certificate of `pkinitrsa` and the EC certificate of
/// `pkinituser`; the `pkinit_cert_match` `rules` choose among them.
async fn matched_login(rules: &[&str], sequence: u32) -> Result<AsRepSession, Box<dyn Error>> {
    let realm = harness::var("INTEROP_MIT_REALM")?;
    let decoy = format!("{}/tests/pkinit/fixtures", env!("CARGO_MANIFEST_DIR"));
    let mut lines = format!("  pkinit_identities = FILE:{decoy}/client.pem,{decoy}/client.key\n");
    for (cert, key) in [
        ("INTEROP_MIT_PKINIT_RSA_CERT", "INTEROP_MIT_PKINIT_RSA_KEY"),
        ("INTEROP_MIT_PKINIT_CERT", "INTEROP_MIT_PKINIT_KEY"),
    ] {
        writeln!(
            lines,
            "  pkinit_identities = FILE:{},{}",
            harness::var(cert)?,
            harness::var(key)?
        )?;
    }
    for rule in rules {
        writeln!(lines, "  pkinit_cert_match = {rule}")?;
    }
    let config = Config::parse(&format!(
        "[libdefaults]\n default_realm = {realm}\n dns_lookup_kdc = false\n spake_preauth_groups =\n\
         [realms]\n {realm} = {{\n  kdc = {}\n{lines} }}\n",
        harness::var("INTEROP_MIT_KDC")?,
    ))?;
    let identities = ConfiguredIdentities::from_config(&config, &realm)?;
    let exchange = Exchange::with_provider(
        Arc::new(identities),
        trust()?,
        CertificatePolicy::from_config(&config, &realm)?,
    );
    let client = Principal::user(realm, harness::var("INTEROP_MIT_PKINIT_USER")?);
    let options = InitCredsOptions::from_config(&config, SystemTime::now(), nonce(sequence)?)?;
    let (session, _requests) = run(
        &config,
        &mut InitCreds::with_pkinit(client, exchange, options),
    )
    .await?;
    Ok(session)
}

/// The `Pkinit` error behind a failed login, however the engine wrapped it.
fn pkinit_error<'error>(error: &'error (dyn Error + 'static)) -> Option<&'error Pkinit> {
    let ClientError::Pkinit(pkinit) = error.downcast_ref::<ClientError>()? else {
        return None;
    };
    if let Pkinit::Provider(inner) = pkinit {
        inner.downcast_ref::<Pkinit>()
    } else {
        Some(pkinit)
    }
}

/// `pkinit_cert_match` chooses which of three identities signs the request.
///
/// The rule that names pkinituser's certificate logs in; the rule that names
/// the certificate the KDC does not trust reaches the KDC and is refused there
/// (the first loadable identity would have been that one); the rule that names
/// the RSA certificate stops before any request (a software identity signs
/// with EC keys only); and no rule with several identities is ambiguous.
#[test]
fn certificate_rules_pick_the_identity_the_kdc_accepts() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "certificate_rules_pick_the_identity_the_kdc_accepts",
        &[MIT_KDC],
    )? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let accepted = matched_login(&["<SUBJECT>^CN=pkinituser$"], 8).await?;
        assert_eq!(
            accepted.client().components,
            vec![harness::var("INTEROP_MIT_PKINIT_USER")?],
            "the rule's identity authenticated"
        );
        let refused = matched_login(&["<SUBJECT>^O=RSKRB5 Test,CN=client$"], 9).await;
        let refusal = refused.err().ok_or("the untrusted identity logged in")?;
        assert!(
            pkinit_error(refusal.as_ref()).is_none(),
            "the KDC refused it, not the selection: {refusal}"
        );
        let rsa = matched_login(&["<SUBJECT>^CN=pkinitrsa$"], 10).await;
        let unsupported = rsa.err().ok_or("the RSA identity signed")?;
        assert!(
            matches!(
                pkinit_error(unsupported.as_ref()),
                Some(Pkinit::Provider(_) | Pkinit::Identity { reason: _ })
            ),
            "{unsupported}"
        );
        let ambiguous = matched_login(&[], 11).await;
        let failure = ambiguous.err().ok_or("several identities and no rule logged in")?;
        assert!(
            matches!(
                pkinit_error(failure.as_ref()),
                Some(Pkinit::AmbiguousCertificates { candidates: 3 })
            ),
            "{failure}"
        );
        Ok(())
    })
}

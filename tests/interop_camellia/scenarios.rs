//! Camellia against the MIT KDC: AS reply key, service ticket, session key and acceptor.

use core::{error::Error, time::Duration};
use std::{io, time::SystemTime};

use rskrb5_ng::{
    client::{
        Tokio, build_tgt_as_req,
        options::AsReq,
        principal::Principal,
        transport::{KdcProtocol, Tokio as KdcTransport},
    },
    config::Config,
    crypto::CryptoPolicy,
    kdc_rep,
    keytab::{Keytab, Principal as KeytabPrincipal},
    service::Validator,
    spnego::{self, InitiatorContextOptions},
    ticket,
};
use sha2::{Digest as _, Sha256};
use tokio::runtime::{Builder, Runtime};
use zeroize::Zeroizing;

use crate::harness::{self, Fixture, assert_negotiated_enctype};

/// Enctype ID of `camellia256-cts-cmac`.
const CAMELLIA256: i32 = 26;

/// Enctype ID of `aes256-cts-hmac-sha384-192`, the fixture's krbtgt key.
const AES256_SHA2: i32 = 20;

/// The fixture KDC, reached on `INTEROP_MIT_KDC` (TCP and UDP).
const MIT_KDC: Fixture = Fixture::new("mit-kdc", "INTEROP_MIT_KDC");

/// The Camellia-only user of `provision.d/55-camellia.sh`.
const USER: &str = "camelliauser";

/// The Camellia-only service of `provision.d/55-camellia.sh`.
const SERVICE: &str = "camelliasvc/svc.test.rskrb5";

/// The per-run password of `label`: the first 32 hex digits of
/// `sha256("rskrb5-interop camellia v1:<label>:<admin password>")`, as the
/// provisioning script derives it.
fn derived_password(label: &str) -> Result<Zeroizing<Vec<u8>>, Box<dyn Error>> {
    let admin = harness::var("INTEROP_MIT_ADMIN_PASSWORD")?;
    let digest = Sha256::digest(format!("rskrb5-interop camellia v1:{label}:{admin}"));
    Ok(Zeroizing::new(
        hex::encode(digest)
            .into_bytes()
            .into_iter()
            .take(32)
            .collect(),
    ))
}

/// A configuration that names Camellia in every enctype list.
fn config() -> Result<Config, Box<dyn Error>> {
    let (realm, kdc) = (
        harness::var("INTEROP_MIT_REALM")?,
        harness::var("INTEROP_MIT_KDC")?,
    );
    Ok(Config::parse(&format!(
        "
[libdefaults]
 default_realm = {realm}
 dns_lookup_kdc = false
 permitted_enctypes = camellia256-cts-cmac camellia128-cts-cmac aes256-cts-hmac-sha384-192
 default_tkt_enctypes = camellia256-cts-cmac camellia128-cts-cmac aes256-cts-hmac-sha384-192
 default_tgs_enctypes = camellia256-cts-cmac camellia128-cts-cmac

[realms]
 {realm} = {{
  kdc = {kdc}
 }}
"
    ))?)
}

/// The current-thread runtime of the scenario.
fn runtime() -> io::Result<Runtime> {
    Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
}

/// The enctype of the encrypted part of the DER `ticket`.
fn ticket_etype(der: &[u8]) -> Result<i32, Box<dyn Error>> {
    Ok(ticket::decode(der)?.enc_part.etype)
}

/// The Camellia negotiation with MIT.
///
/// The KDC encrypts the AS reply in the user's Camellia key and issues a Camellia
/// service ticket with a Camellia session key, and the acceptor opens it with a
/// Camellia keytab. Every step is asserted, so no fallback to AES can pass.
#[test]
fn camellia_is_negotiated_with_the_mit_realm() -> Result<(), Box<dyn Error>> {
    if !harness::require("camellia_is_negotiated_with_the_mit_realm", &[MIT_KDC])? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let (config, realm) = (config()?, harness::var("INTEROP_MIT_REALM")?);
        let kdc = harness::var("INTEROP_MIT_KDC")?;
        let transport = KdcTransport::new().with_timeout(Duration::from_secs(10));
        let user = Principal::user(realm.clone(), USER);
        // Given the user's AS-REQ with the configured enctype list, when MIT answers.
        let options = AsReq::from_libdefaults(SystemTime::now(), 0x0c4e_0001, &config.libdefaults)?;
        let request = build_tgt_as_req(user.clone(), options)?;
        let reply = transport
            .send(KdcProtocol::Tcp, kdc.as_str(), request.der())
            .await?;
        // Then the reply is encrypted in the user's Camellia key.
        let as_rep = kdc_rep::decode_as_rep(&reply)?;
        assert_negotiated_enctype("AS-REP reply key", CAMELLIA256, as_rep.0.enc_part.etype)?;
        // And the password login derives that key and gets a TGT under the krbtgt's AES key.
        let mut client = Tokio::with_password(
            config.clone(),
            KdcProtocol::Auto,
            user,
            derived_password("user")?.to_vec(),
        )
        .with_transport(transport);
        let tgt = client.login().await?.clone();
        assert_negotiated_enctype(
            "TGT (krbtgt key)",
            AES256_SHA2,
            ticket_etype(tgt.ticket().as_slice())?,
        )?;
        // When the client asks for the Camellia service, then ticket and session key are Camellia.
        let service = Principal::new(realm.clone(), 2, SERVICE.split('/'));
        let granted = client.get_service_ticket(service).await?;
        assert_negotiated_enctype(
            "service ticket (service key)",
            CAMELLIA256,
            ticket_etype(granted.ticket().as_slice())?,
        )?;
        assert_negotiated_enctype(
            "service ticket session key",
            CAMELLIA256,
            granted.session_key().etype(),
        )?;
        // And the acceptor, permitting Camellia by name, opens it with the service's Camellia key.
        let mut keytab = Keytab::new();
        keytab.add_entry_from_password(
            KeytabPrincipal::new(realm, 2, SERVICE.split('/')),
            derived_password("service")?,
            SystemTime::now(),
            1,
            CAMELLIA256,
        )?;
        let policy = CryptoPolicy::from_libdefaults(&config.libdefaults)?;
        let context = spnego::init_sec_context(
            &granted,
            InitiatorContextOptions::new().with_crypto_policy(policy.clone()),
        )
        .map_err(|error| format!("the initiator could not build the token: {error}"))?;
        let mut validator = Validator::new(&keytab)
            .with_now(SystemTime::now())
            .with_crypto_policy(policy);
        let accepted = spnego::accept_sec_context_header(&mut validator, context.header_ref())
            .map_err(|error| {
                format!("the acceptor refused the MIT-issued Camellia ticket: {error}")
            })?;
        assert_negotiated_enctype(
            "acceptor session key",
            CAMELLIA256,
            accepted.ap_req().session_key().etype(),
        )?;
        Ok::<_, Box<dyn Error>>(())
    })
}

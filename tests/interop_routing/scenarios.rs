//! The MIT routing scenarios: the `[capaths]` route to FAR.EXAMPLE and its
//! transited path, `verify_init_creds`, and a user-to-user ticket.

use core::{error::Error, time::Duration};
use std::{
    io,
    time::{SystemTime, UNIX_EPOCH},
};

use rskrb5_ng::{
    client::{
        TgsRepSession, Tokio,
        options::{AsReq, TgsReq},
        principal::Principal,
        transport::{KdcProtocol, Tokio as TokioKdcTransport},
    },
    config::Config,
    error::Client as ClientError,
    keytab::{Keytab, Principal as KeytabPrincipal},
    routing::{
        init_creds::{Verification, VerifyOptions},
        transited,
    },
    service::{CapathsTransit, TransitValidator as _, Validator},
    spnego, ticket,
};
use tokio::runtime::{Builder, Runtime};
use zeroize::Zeroizing;

use crate::harness::{self, Fixture, assert_ticket_flag};

/// The TEST.RSKRB5 KDC (fixture `mit-kdc`).
const MIT_KDC: Fixture = Fixture::new("mit-kdc", "INTEROP_MIT_KDC");

/// The OTHER.RSKRB5 and FAR.EXAMPLE KDC (fixture `mit-other`).
const MIT_OTHER_KDC: Fixture = Fixture::new("mit-other", "INTEROP_MIT_OTHER_KDC");

/// Enctype id of aes256-cts-hmac-sha384-192, the strongest key of the realms.
const AES256_SHA2: i32 = 20;

/// RFC 4120 ticket flag bit `transited-policy-checked`.
const FLAG_TRANSITED_POLICY_CHECKED: u32 = 12;

/// The current-thread Tokio runtime the scenarios run on.
fn runtime() -> io::Result<Runtime> {
    Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
}

/// A KDC transport with a ten-second timeout.
fn transport() -> TokioKdcTransport {
    TokioKdcTransport::new().with_timeout(Duration::from_secs(10))
}

/// The TEST.RSKRB5 test user and its password.
fn test_user() -> Result<(Principal, Vec<u8>), Box<dyn Error>> {
    Ok((
        Principal::user(
            harness::var("INTEROP_MIT_REALM")?,
            harness::var("INTEROP_MIT_USER")?,
        ),
        harness::var("INTEROP_MIT_USER_PASSWORD")?.into_bytes(),
    ))
}

/// A nonce unique to `sequence` and the current time.
fn nonce(sequence: u32) -> Result<u32, Box<dyn Error>> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH)?;
    Ok(u32::try_from(elapsed.as_nanos() & 0x00ff_ffff)? | sequence.wrapping_shl(24))
}

/// AS-REQ options with a one-hour lifetime and the AES-SHA2 enctype.
fn as_options(sequence: u32) -> Result<AsReq, Box<dyn Error>> {
    Ok(AsReq::new(SystemTime::now(), nonce(sequence)?)
        .with_ticket_lifetime(Duration::from_hours(1))
        .with_etypes(vec![AES256_SHA2]))
}

/// TGS-REQ options with a one-hour lifetime and the AES-SHA2 enctype.
fn tgs_options(sequence: u32) -> Result<TgsReq, Box<dyn Error>> {
    Ok(TgsReq::new(SystemTime::now(), nonce(sequence)?)
        .with_ticket_lifetime(Duration::from_hours(1))
        .with_etypes(vec![AES256_SHA2]))
}

/// The three realms with their KDCs, and `extra` appended (a `[capaths]`).
fn three_realms(extra: &str) -> Result<Config, Box<dyn Error>> {
    let test = harness::var("INTEROP_MIT_REALM")?;
    let other = harness::var("INTEROP_MIT_OTHER_REALM")?;
    let far = harness::var("INTEROP_MIT_OTHER_FAR_REALM")?;
    Ok(Config::parse(&format!(
        "[libdefaults]\n default_realm = {test}\n dns_lookup_kdc = false\n dns_lookup_realm = false\n\
         [realms]\n {test} = {{\n  kdc = {}\n }}\n {other} = {{\n  kdc = {}\n }}\n {far} = {{\n  kdc = {}\n }}\n{extra}",
        harness::var("INTEROP_MIT_KDC")?,
        harness::var("INTEROP_MIT_OTHER_KDC")?,
        harness::var("INTEROP_MIT_OTHER_FAR_KDC")?,
    ))?)
}

/// The non-hierarchical route of the client.
fn capaths() -> Result<String, Box<dyn Error>> {
    Ok(format!(
        "[capaths]\n {} = {{\n  {} = {}\n }}\n",
        harness::var("INTEROP_MIT_REALM")?,
        harness::var("INTEROP_MIT_OTHER_FAR_REALM")?,
        harness::var("INTEROP_MIT_OTHER_REALM")?,
    ))
}

/// MIT-client-5 and MIT-config-53: a TEST user reaches `HTTP/http.far.example`
/// only through its `[capaths]` route (the TEST KDC has none: it refuses
/// `krbtgt/FAR.EXAMPLE`, and the client backs off to `krbtgt/OTHER.RSKRB5`).
/// The FAR KDC records OTHER.RSKRB5 as transited; the acceptor decodes that
/// DOMAIN-X500-COMPRESS path and the profile's `[capaths]` admits it, while
/// the realm hierarchy alone does not. Without the route the KDC error stops
/// the client.
#[test]
fn capaths_route_reaches_the_far_realm_and_its_transit_is_validated() -> Result<(), Box<dyn Error>>
{
    if !harness::require(
        "capaths_route_reaches_the_far_realm_and_its_transit_is_validated",
        &[MIT_KDC, MIT_OTHER_KDC],
    )? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let (user, password) = test_user()?;
        let test = user.realm.clone();
        let other = harness::var("INTEROP_MIT_OTHER_REALM")?;
        let far = harness::var("INTEROP_MIT_OTHER_FAR_REALM")?;
        let routed = three_realms(&capaths()?)?;
        let unrouted = three_realms("")?;
        let http = harness::var("INTEROP_MIT_OTHER_FAR_HTTP_SERVICE")?;
        let service = Principal::new(far.clone(), 2, http.split('/'));
        let tgt = transport()
            .login_tgt_with_password_config(
                &routed,
                KdcProtocol::Tcp,
                user.clone(),
                &password,
                as_options(1)?,
            )
            .await?;
        // Without a route the TEST KDC's refusal of the far TGT ends the exchange.
        let refused = transport()
            .get_service_ticket_with_referral_trace(
                &unrouted,
                KdcProtocol::Tcp,
                &tgt,
                service.clone(),
                tgs_options(2)?,
            )
            .await
            .err()
            .ok_or("FAR.EXAMPLE must be unreachable without [capaths]")?;
        assert!(
            matches!(&refused, ClientError::Kdc(_)),
            "expected the KDC refusal, got {refused}"
        );
        // With the route the client crosses OTHER.RSKRB5.
        let result = transport()
            .get_service_ticket_with_referral_trace(
                &routed,
                KdcProtocol::Tcp,
                &tgt,
                service.clone(),
                tgs_options(3)?,
            )
            .await?;
        let hops: Vec<Principal> = result
            .referral_tgts()
            .iter()
            .map(|hop| hop.service().clone())
            .collect();
        assert_eq!(
            hops,
            vec![
                Principal::new(test.clone(), 2, ["krbtgt", other.as_str()]),
                Principal::new(other.clone(), 2, ["krbtgt", far.as_str()]),
            ],
            "the configured path TEST -> OTHER -> FAR"
        );
        let ticket = result.ticket();
        assert_eq!(ticket.service(), &service, "the FAR service ticket");
        assert_far_acceptance(ticket, (&routed, &unrouted), (&test, &other, &far), &http)?;
        Ok::<_, Box<dyn Error>>(())
    })
}

/// The FAR acceptor decrypts the ticket and sees the path the FAR KDC recorded;
/// the routed profile's `[capaths]` admits it, the hierarchy alone does not, and
/// the FAR service accepts the AP-REQ.
fn assert_far_acceptance(
    ticket: &TgsRepSession,
    profiles: (&Config, &Config),
    realms: (&str, &str, &str),
    http: &str,
) -> Result<(), Box<dyn Error>> {
    let (routed, unrouted) = profiles;
    let (test, other, far) = realms;
    let keytab = Keytab::load(harness::var("INTEROP_MIT_OTHER_FAR_HTTP_KEYTAB")?)?;
    let wire = ticket::decode(ticket.ticket().as_slice())?;
    let components: Vec<&str> = http.split('/').collect();
    let (key, _) = keytab.find_key(
        &components,
        far,
        wire.enc_part.kvno.unwrap_or_default(),
        wire.enc_part.etype,
    )?;
    let part = ticket::decrypt_ticket_enc_part(&wire, key)?;
    assert_eq!(part.transited.r#type, transited::DOMAIN_X500_COMPRESS);
    assert_eq!(
        transited::decode(&part.transited.contents, test, far)?,
        [other],
        "the FAR KDC recorded OTHER.RSKRB5"
    );
    let flags = u32::from_be_bytes(
        part.flags
            .0
            .as_raw_slice()
            .get(..4)
            .ok_or("flags")?
            .try_into()?,
    );
    assert_ticket_flag(
        "transited-policy-checked",
        FLAG_TRANSITED_POLICY_CHECKED,
        flags.to_be_bytes(),
    )?;
    assert!(
        CapathsTransit::from_config(routed).accepts(test, far, &part.transited),
        "the [capaths] route admits the recorded path"
    );
    assert!(
        !CapathsTransit::from_config(unrouted).accepts(test, far, &part.transited),
        "the realm hierarchy does not name OTHER.RSKRB5"
    );
    // And the far service accepts the AP-REQ.
    let context = spnego::init_sec_context(ticket, spnego::InitiatorContextOptions::new())?;
    let mut validator = Validator::new(&keytab).with_now(SystemTime::now());
    let accepted = spnego::accept_sec_context_header(&mut validator, context.header_ref())?;
    assert_eq!(
        accepted.ap_req().client().realm,
        test,
        "the FAR acceptor sees the TEST user"
    );
    Ok(())
}

/// MIT-client-12 and MIT-config-42: `verify_init_creds` obtains a ticket for
/// the keytab's host principal with the new TGT and verifies the AP-REQ with
/// the host key (MIT `vfy_increds.c:259-321`). A keytab with a wrong key for
/// the same host principal is rejected whatever `verify_ap_req_nofail` says;
/// a keytab without a host key is an error unless nofail is explicitly false.
#[test]
fn verify_init_creds_accepts_the_host_keytab_and_rejects_a_wrong_one() -> Result<(), Box<dyn Error>>
{
    if !harness::require(
        "verify_init_creds_accepts_the_host_keytab_and_rejects_a_wrong_one",
        &[MIT_KDC],
    )? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let (user, password) = test_user()?;
        let realm = user.realm.clone();
        let config = Config::parse(&format!(
            "[libdefaults]\n default_realm = {realm}\n dns_lookup_kdc = false\n\
             [realms]\n {realm} = {{\n  kdc = {}\n }}\n",
            harness::var("INTEROP_MIT_KDC")?,
        ))?;
        let host = harness::var("INTEROP_MIT_HOST_SERVICE")?;
        let host_keytab = Keytab::load(harness::var("INTEROP_MIT_HOST_KEYTAB")?)?;
        let mut client =
            Tokio::with_password(config.clone(), KdcProtocol::Tcp, user.clone(), password);
        // The real host key verifies the credentials.
        let verified = client
            .verify_init_creds(&host_keytab, VerifyOptions::new())
            .await?;
        assert_eq!(
            verified,
            Verification::Verified(Principal::new(realm.clone(), 2, host.split('/'))),
            "verified against the host principal"
        );
        // A wrong key for the same host principal is rejected, nofail or not.
        let mut wrong = Keytab::default();
        wrong.add_entry_from_password(
            KeytabPrincipal::new(realm.as_str(), 1, host.split('/')),
            Zeroizing::new(b"not-the-host-password".to_vec()),
            SystemTime::now(),
            1,
            AES256_SHA2,
        )?;
        for nofail in [true, false] {
            let rejected = client
                .verify_init_creds(&wrong, VerifyOptions::new().with_nofail(nofail))
                .await;
            assert!(
                rejected.is_err(),
                "the wrong host keytab must reject (nofail {nofail}): {rejected:?}"
            );
        }
        // No host key: an error by default, a skip only when nofail is false.
        let http_only = Keytab::load(harness::var("INTEROP_MIT_HTTP_KEYTAB")?)?;
        let missing = client
            .verify_init_creds(&http_only, VerifyOptions::new())
            .await;
        assert!(
            matches!(missing, Err(ClientError::VerifyInitCredsNoHostKey)),
            "expected the missing host key error, got {missing:?}"
        );
        let skipped = client
            .verify_init_creds(&http_only, VerifyOptions::new().with_nofail(false))
            .await?;
        assert_eq!(
            skipped,
            Verification::Skipped,
            "nofail false tolerates the missing key"
        );
        Ok::<_, Box<dyn Error>>(())
    })
}

/// GO-client-3 and GO-messages-1: a user-to-user ticket for the target user is
/// sealed in the session key of the target's TGT (RFC 4120 section 3.7,
/// ENC-TKT-IN-SKEY), so the target decrypts it with that session key and not
/// with its long-term key.
#[test]
fn user_to_user_ticket_is_sealed_in_the_target_session_key() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "user_to_user_ticket_is_sealed_in_the_target_session_key",
        &[MIT_KDC],
    )? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let (user, password) = test_user()?;
        let realm = user.realm.clone();
        let config = Config::parse(&format!(
            "[libdefaults]\n default_realm = {realm}\n dns_lookup_kdc = false\n\
             [realms]\n {realm} = {{\n  kdc = {}\n }}\n",
            harness::var("INTEROP_MIT_KDC")?,
        ))?;
        let target = Principal::user(realm.as_str(), harness::var("INTEROP_MIT_PREAUTH_USER")?);
        let target_keytab = Keytab::load(harness::var("INTEROP_MIT_PREAUTH_USER_KEYTAB")?)?;
        let mut target_client = Tokio::with_keytab(
            config.clone(),
            KdcProtocol::Tcp,
            target.clone(),
            target_keytab.clone(),
        );
        let target_tgt = target_client.login().await?.clone();
        let mut client = Tokio::with_password(config, KdcProtocol::Tcp, user.clone(), password);
        let u2u = client
            .user_to_user_ticket(target.clone(), target_tgt.ticket().as_slice())
            .await?;
        assert_eq!(u2u.service(), &target, "the ticket names the target user");
        let wire = ticket::decode(u2u.ticket().as_slice())?;
        let part =
            ticket::decrypt_ticket_enc_part(&wire, target_tgt.session_key()).map_err(|error| {
                format!("the target's TGT session key does not open the ticket: {error}")
            })?;
        assert_eq!(
            String::from_utf8(part.crealm.as_bytes().to_vec())?,
            realm,
            "the ticket names the client realm"
        );
        let components: Vec<&str> = target.components.iter().map(String::as_str).collect();
        let (long_term, _) = target_keytab.find_key(&components, &realm, 0, wire.enc_part.etype)?;
        assert!(
            ticket::decrypt_ticket_enc_part(&wire, long_term).is_err(),
            "a user-to-user ticket is not sealed in the long-term key"
        );
        Ok::<_, Box<dyn Error>>(())
    })
}

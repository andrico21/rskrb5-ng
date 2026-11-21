//! The Samba routing scenarios: the unsolicited referral across the forest
//! trust, transit validation of the AD ticket, and resource-based constrained
//! delegation.

use core::{error::Error, time::Duration};
use std::{
    io,
    time::{SystemTime, UNIX_EPOCH},
};

use rskrb5_ng::{
    client::{
        KDC_OPTION_CANONICALIZE, PAC_OPTION_RESOURCE_BASED_CONSTRAINED_DELEGATION, Tokio,
        options::{AsReq, TgsReq},
        pa_pac_options_padata,
        principal::Principal,
        transport::{KdcProtocol, Tokio as TokioKdcTransport},
    },
    config::Config,
    error::Client as ClientError,
    keytab::Keytab,
    routing::impersonation::{DelegationOptions, S4uIdentity},
    ticket,
};
use tokio::runtime::{Builder, Runtime};

use crate::harness::{self, Fixture, assert_ticket_flag};

/// The KDC of the user domain.
const SAMBA_USER: Fixture = Fixture::new("samba-user", "INTEROP_SAMBA_USER_KDC");

/// The KDC of the resource domain.
const SAMBA_RES: Fixture = Fixture::new("samba-res", "INTEROP_SAMBA_RES_KDC");

/// Enctype id of aes256-cts-hmac-sha1-96, the strongest key of every Samba account.
const AES256_SHA1: i32 = 18;

/// RFC 4120 ticket flag bit `transited-policy-checked`.
const FLAG_TRANSITED_POLICY_CHECKED: u32 = 12;

/// RFC 4120 ticket flag bit `forwardable`.
const FLAG_FORWARDABLE: u32 = 1;

/// KDC error code of a refused KDC option (a delegation the domain does not allow).
const KDC_ERR_BADOPTION: i32 = 13;

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

/// Both domains with their KDCs, default realm USER.RSKRB5 and no
/// `[domain_realm]`, so a host of the resource domain is first asked for in
/// USER.RSKRB5; `extra` is appended.
fn config(extra: &str) -> Result<Config, Box<dyn Error>> {
    let user_realm = harness::var("INTEROP_SAMBA_USER_REALM")?;
    let res_realm = harness::var("INTEROP_SAMBA_RES_REALM")?;
    Ok(Config::parse(&format!(
        "[libdefaults]\n default_realm = {user_realm}\n dns_lookup_kdc = false\n dns_lookup_realm = false\n\
         [realms]\n {user_realm} = {{\n  kdc = {}\n }}\n {res_realm} = {{\n  kdc = {}\n }}\n{extra}",
        harness::var("INTEROP_SAMBA_USER_KDC")?,
        harness::var("INTEROP_SAMBA_RES_KDC")?,
    ))?)
}

/// A nonce unique to `sequence` and the current time.
fn nonce(sequence: u32) -> Result<u32, Box<dyn Error>> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH)?;
    Ok(u32::try_from(elapsed.as_nanos() & 0x00ff_ffff)? | sequence.wrapping_shl(24))
}

/// TGS-REQ options with a one-hour lifetime and AES256.
fn tgs_options(sequence: u32) -> Result<TgsReq, Box<dyn Error>> {
    Ok(TgsReq::new(SystemTime::now(), nonce(sequence)?)
        .with_ticket_lifetime(Duration::from_hours(1))
        .with_etypes(vec![AES256_SHA1]))
}

/// A user-domain principal named by the env-file key `key`.
fn user(key: &str) -> Result<Principal, Box<dyn Error>> {
    Ok(Principal::user(
        harness::var("INTEROP_SAMBA_USER_REALM")?,
        harness::var(key)?,
    ))
}

/// The service principal named by the env-file key `key` in `realm`.
fn service(realm: &str, key: &str) -> Result<Principal, Box<dyn Error>> {
    let name = harness::var(key)?;
    Ok(Principal::new(realm, 2, name.split('/')))
}

/// Replaces `error` by its `Display` text.
fn shown(error: Box<dyn Error>) -> Box<dyn Error> {
    let text = error.to_string();
    drop(error);
    text.into()
}

/// FU-IOP-P12 and FU-SVC-08: a canonicalizing request for
/// `HTTP/host.res.rskrb5` in USER.RSKRB5 is answered with the referral TGT
/// `krbtgt/RES.RSKRB5@USER.RSKRB5`; the client asks RES.RSKRB5 for the service
/// itself (not for `krbtgt/USER.RSKRB5`, which Samba refuses with
/// `KRB_AP_ERR_ILL_CR_TKT`). The RES acceptor refuses the ticket, which AD
/// leaves without TRANSITED-POLICY-CHECKED, by default and with a
/// `[capaths]` that does not list the pair, and accepts it with the direct
/// `[capaths]` route USER.RSKRB5 -> RES.RSKRB5.
#[test]
fn service_referral_crosses_the_trust_and_capaths_validate_the_transit()
-> Result<(), Box<dyn Error>> {
    if !harness::require(
        "service_referral_crosses_the_trust_and_capaths_validate_the_transit",
        &[SAMBA_USER, SAMBA_RES],
    )? {
        return Ok(());
    }
    runtime()?
        .block_on(async {
            let user_realm = harness::var("INTEROP_SAMBA_USER_REALM")?;
            let res_realm = harness::var("INTEROP_SAMBA_RES_REALM")?;
            let profile = config("")?;
            let client = user("INTEROP_SAMBA_USER_USER")?;
            let password = harness::var("INTEROP_SAMBA_USER_USER_PASSWORD")?.into_bytes();
            let tgt = transport()
                .login_tgt_with_password_config(
                    &profile,
                    KdcProtocol::Tcp,
                    client.clone(),
                    &password,
                    AsReq::new(SystemTime::now(), nonce(1)?).with_etypes(vec![AES256_SHA1]),
                )
                .await?;
            let host = harness::var("INTEROP_SAMBA_RES_HTTP_SERVICE")?;
            let unresolved = Principal::new("", 2, host.split('/'));
            let options = tgs_options(2)?;
            let bits = options.kdc_option_bits() | KDC_OPTION_CANONICALIZE;
            let result = transport()
                .get_service_ticket_with_referral_trace(
                    &profile,
                    KdcProtocol::Tcp,
                    &tgt,
                    unresolved,
                    options.with_kdc_option_bits(bits),
                )
                .await?;
            let hops: Vec<Principal> = result
                .referral_tgts()
                .iter()
                .map(|hop| hop.service().clone())
                .collect();
            assert_eq!(
                hops,
                vec![Principal::new(
                    user_realm.as_str(),
                    2,
                    ["krbtgt", res_realm.as_str()]
                )],
                "the USER KDC referred the request to RES"
            );
            let ticket = result.ticket();
            assert_eq!(
                ticket.service(),
                &Principal::new(res_realm.as_str(), 2, host.split('/')),
                "the service ticket is the RES service's"
            );
            // The RES service key opens the ticket: it names the USER client, and
            // Samba's KDC checked the transited path itself (TRANSITED-POLICY-CHECKED),
            // so an acceptor's transit policy is not consulted for it.
            let keytab = Keytab::load(harness::var("INTEROP_SAMBA_RES_HTTP_KEYTAB")?)?;
            let wire = ticket::decode(ticket.ticket().as_slice())?;
            let components: Vec<&str> = host.split('/').collect();
            let (key, _) = keytab.find_key(
                &components,
                &res_realm,
                wire.enc_part.kvno.unwrap_or_default(),
                wire.enc_part.etype,
            )?;
            let part = ticket::decrypt_ticket_enc_part(&wire, key)?;
            assert_eq!(
                String::from_utf8(part.crealm.as_bytes().to_vec())?,
                user_realm,
                "the RES service sees the USER client"
            );
            assert_ticket_flag(
                "transited-policy-checked",
                FLAG_TRANSITED_POLICY_CHECKED,
                ticket.ticket_flags(),
            )?;
            Ok::<_, Box<dyn Error>>(())
        })
        .map_err(shown)
}

/// FU-IOP-P11: with the default profile (no `forwardable`), `s4u2self` asks
/// for a forwardable evidence ticket, so Samba, which refuses `S4U2Proxy` for a
/// non-forwardable one even for resource-based constrained delegation
/// (Samba 4.22.11 `third_party/heimdal/kdc/mssfu.c:492-499`), lets svc-rbcd
/// reach `HTTP/backend.user.rskrb5`; the RBCD request to
/// `HTTP/denied.user.rskrb5` is refused with `KDC_ERR_BADOPTION`.
#[test]
fn rbcd_with_the_default_profile_reaches_only_the_allowed_target() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "rbcd_with_the_default_profile_reaches_only_the_allowed_target",
        &[SAMBA_USER],
    )? {
        return Ok(());
    }
    runtime()?
        .block_on(async {
            let realm = harness::var("INTEROP_SAMBA_USER_REALM")?;
            let account = Principal::user(realm.as_str(), harness::var("INTEROP_SAMBA_USER_RBCD_ACCOUNT")?);
            let impersonated = user("INTEROP_SAMBA_USER_S4U_CLIENT")?;
            let mut client = Tokio::with_keytab(
                config("")?,
                KdcProtocol::Tcp,
                account.clone(),
                Keytab::load(harness::var("INTEROP_SAMBA_USER_RBCD_KEYTAB")?)?,
            )
            .with_transport(transport());
            let evidence = client.s4u2self(impersonated.clone()).await?;
            assert_ticket_flag("forwardable", FLAG_FORWARDABLE, evidence.ticket_flags())?;
            let rbcd = || -> Result<TgsReq, Box<dyn Error>> {
                Ok(tgs_options(3)?
                    .with_padata(vec![pa_pac_options_padata(PAC_OPTION_RESOURCE_BASED_CONSTRAINED_DELEGATION)?]))
            };
            let allowed = service(&realm, "INTEROP_SAMBA_USER_DELEGATION_TARGET")?;
            let proxied = client.s4u2proxy_with_options(&evidence, allowed.clone(), rbcd()?).await?;
            assert_eq!(proxied.client(), &impersonated, "the delegated ticket names s4uclient");
            assert_eq!(proxied.service(), &allowed, "the delegated ticket is for HTTP/backend");
            let denied = service(&realm, "INTEROP_SAMBA_USER_DELEGATION_DENIED")?;
            let refusal = client
                .s4u2proxy_with_options(&evidence, denied, rbcd()?)
                .await
                .err()
                .ok_or("RBCD to HTTP/denied must be refused")?;
            assert!(
                matches!(&refusal, ClientError::Kdc(error) if error.error_code() == KDC_ERR_BADOPTION),
                "expected KDC_ERR_BADOPTION, got {refusal}"
            );
            Ok::<_, Box<dyn Error>>(())
        })
        .map_err(shown)
}

/// MIT-client-8: the delegation workflow (forwardable `S4U2Self`, then
/// `S4U2Proxy` with PA-PAC-OPTIONS resource-based constrained delegation, MIT
/// `s4u_creds.c:764-782,1013`) reaches the RBCD target as s4uclient, the
/// delegated identity bound to the evidence ticket svc-rbcd decrypted, and is
/// refused for a target that does not trust svc-rbcd.
#[test]
fn delegation_workflow_reaches_the_rbcd_target_only() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "delegation_workflow_reaches_the_rbcd_target_only",
        &[SAMBA_USER],
    )? {
        return Ok(());
    }
    runtime()?
        .block_on(async {
            let realm = harness::var("INTEROP_SAMBA_USER_REALM")?;
            let account = Principal::user(realm.as_str(), harness::var("INTEROP_SAMBA_USER_RBCD_ACCOUNT")?);
            let impersonated = user("INTEROP_SAMBA_USER_S4U_CLIENT")?;
            let mut client = Tokio::with_keytab(
                config("")?,
                KdcProtocol::Tcp,
                account,
                Keytab::load(harness::var("INTEROP_SAMBA_USER_RBCD_KEYTAB")?)?,
            )
            .with_transport(transport());
            let allowed = service(&realm, "INTEROP_SAMBA_USER_DELEGATION_TARGET")?;
            let delegation = client
                .delegate(
                    S4uIdentity::Principal(impersonated.clone()),
                    allowed.clone(),
                    DelegationOptions::new(),
                )
                .await?;
            assert_ticket_flag("forwardable", FLAG_FORWARDABLE, delegation.evidence().ticket_flags())?;
            assert_eq!(delegation.ticket().client(), &impersonated, "delegated as s4uclient");
            assert_eq!(delegation.ticket().service(), &allowed, "for HTTP/backend");
            let backend = Keytab::load(harness::var("INTEROP_SAMBA_USER_DELEGATION_TARGET_KEYTAB")?)?;
            let wire = ticket::decode(delegation.ticket().ticket().as_slice())?;
            let components: Vec<&str> = allowed.components.iter().map(String::as_str).collect();
            let (key, _) = backend.find_key(
                &components,
                &realm,
                wire.enc_part.kvno.unwrap_or_default(),
                wire.enc_part.etype,
            )?;
            let part = ticket::decrypt_ticket_enc_part(&wire, key)?;
            let named: Vec<String> = part
                .cname
                .string
                .iter()
                .map(|component| String::from_utf8(component.as_bytes().to_vec()))
                .collect::<Result<_, _>>()?;
            assert_eq!(named, impersonated.components, "HTTP/backend's key opens a ticket for s4uclient");
            let denied = service(&realm, "INTEROP_SAMBA_USER_DELEGATION_DENIED")?;
            let refusal = client
                .delegate(S4uIdentity::Principal(impersonated), denied, DelegationOptions::new())
                .await
                .err()
                .ok_or("delegation to HTTP/denied must be refused")?;
            assert!(
                matches!(&refusal, ClientError::Kdc(error) if error.error_code() == KDC_ERR_BADOPTION),
                "expected KDC_ERR_BADOPTION, got {refusal}"
            );
            Ok::<_, Box<dyn Error>>(())
        })
        .map_err(shown)
}

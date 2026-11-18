//! The Active Directory scenarios of `tests/client_ad_integration.rs`
//! (gokrb5 v8.4.4 `TestClient_*_AD*`), re-pointed at the Samba domains.
//!
//! Each keeps its original assertions (client, service, session-key enctype,
//! PAC logon domain or effective name) and adds the negotiated values. The
//! account names match the gokrb5 contract: `testuser1` (client), `testuser2`
//! (account of `HTTP/user2.user.rskrb5`), `testuser3` (no
//! pre-authentication), `sysHTTP` (account of `HTTP/host.res.rskrb5`).

use core::{error::Error, time::Duration};
use std::time::SystemTime;

use rskrb5_ng::{
    client::{
        AsRepSession, TgsRepSession, Tokio, build_ap_req_with_confounder, options::ApReq,
        principal::Principal, transport::KdcProtocol,
    },
    config::Config,
    crypto::{CryptoPolicy, KerberosEtype},
    keytab::Keytab,
    service::{ValidatedApReq, Validator},
};

use super::{
    AES256_SHA1, FLAG_PRE_AUTHENT, RC4_HMAC, SAMBA_RES, SAMBA_USER, res_realm, runtime, service,
    ticket_etype, transport, user_kdc, user_realm,
};
use crate::harness::{self, assert_negotiated_enctype, assert_ticket_flag};

/// The two-domain configuration of `client_ad_integration.rs`, optionally
/// restricted to RC4-HMAC (opted in with `allow_rc4`) for the trust path.
fn ad_config(rc4: bool) -> Result<Config, Box<dyn Error>> {
    let user_realm = user_realm()?;
    let res_realm = res_realm()?;
    let user_kdc = user_kdc()?;
    let user_admin = harness::var("INTEROP_SAMBA_USER_KPASSWD")?;
    let res_kdc = harness::var("INTEROP_SAMBA_RES_KDC")?;
    let res_admin = harness::var("INTEROP_SAMBA_RES_KPASSWD")?;
    let user_domain = harness::var("INTEROP_SAMBA_USER_DNS_DOMAIN")?;
    let res_domain = harness::var("INTEROP_SAMBA_RES_DNS_DOMAIN")?;
    let rc4_options = if rc4 {
        "
  allow_weak_crypto = false
  canonicalize = true
  default_tkt_enctypes = rc4-hmac
  allow_rc4 = true
  default_tgs_enctypes = rc4-hmac
  permitted_enctypes = rc4-hmac
"
    } else {
        ""
    };
    Ok(Config::parse(&format!(
        "[libdefaults]
  default_realm = {user_realm}
  dns_lookup_realm = false
  dns_lookup_kdc = false
  ticket_lifetime = 24h
  forwardable = yes
{rc4_options}
  default_tkt_enctypes = aes256-cts-hmac-sha1-96
  default_tgs_enctypes = aes256-cts-hmac-sha1-96
  noaddresses = true

[realms]
 {user_realm} = {{
  kdc = {user_kdc}
  admin_server = {user_admin}
  default_domain = {user_domain}
 }}
 {res_realm} = {{
  kdc = {res_kdc}
  admin_server = {res_admin}
  default_domain = {res_domain}
 }}

[domain_realm]
 .{user_domain} = {user_realm}
 {user_domain} = {user_realm}
 .{res_domain} = {res_realm}
 {res_domain} = {res_realm}
"
    ))?)
}

/// A keytab client of the user-domain account named by the env-file key `key`.
fn ad_client(key: &str, keytab_key: &str, rc4: bool) -> Result<Tokio, Box<dyn Error>> {
    Ok(Tokio::with_keytab(
        ad_config(rc4)?,
        KdcProtocol::Auto,
        Principal::user(user_realm()?, harness::var(key)?),
        Keytab::load(harness::var(keytab_key)?)?,
    )
    .with_transport(transport()))
}

/// Validates `ticket` as an AP-REQ (fixed confounder) against `keytab`, matching
/// the keytab principal `account`, under the crypto policy of `ad_config(rc4)`.
fn validate_service_ticket(
    ticket: &TgsRepSession,
    keytab: &Keytab,
    account: &str,
    rc4: bool,
) -> Result<ValidatedApReq, Box<dyn Error>> {
    let now = SystemTime::now();
    let etype = KerberosEtype::from_etype_id(ticket.session_key().etype())
        .ok_or("ticket etype is supported")?;
    let confounder = vec![0x42_u8; etype.confounder_len()];
    let elapsed = now.duration_since(SystemTime::UNIX_EPOCH)?;
    let seconds = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(elapsed.as_secs()))
        .ok_or("time overflow")?;
    let policy = CryptoPolicy::from_libdefaults(&ad_config(rc4)?.libdefaults)?;
    let mut options = ApReq::new();
    options.set_crypto_policy(Some(policy.clone()));
    let ap_req = build_ap_req_with_confounder(
        ticket,
        options,
        seconds,
        elapsed.subsec_micros(),
        &confounder,
    )?;
    let mut validator = Validator::new(keytab)
        .with_crypto_policy(policy)
        .with_now(now)
        .with_keytab_principal([account]);
    Ok(validator.validate_ap_req(ap_req.der())?)
}

/// `active_directory_keytab_login`: testuser1 logs in with its exported keytab
/// and gets a pre-authenticated aes256-cts-hmac-sha1-96 TGT.
#[test]
fn keytab_login_gets_a_preauthenticated_aes256_tgt() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "keytab_login_gets_a_preauthenticated_aes256_tgt",
        &[SAMBA_USER],
    )? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let realm = user_realm()?;
        let mut client = ad_client(
            "INTEROP_SAMBA_USER_USER",
            "INTEROP_SAMBA_USER_USER_KEYTAB",
            false,
        )?;
        let tgt = client.login().await?;
        assert_eq!(
            tgt.client(),
            &Principal::user(realm.as_str(), harness::var("INTEROP_SAMBA_USER_USER")?)
        );
        assert_eq!(tgt.service(), &Principal::tgt_service(realm.as_str()));
        assert_negotiated_enctype("TGT session key", AES256_SHA1, tgt.session_key().etype())?;
        assert_ticket_flag("pre-authent", FLAG_PRE_AUTHENT, tgt.ticket_flags())?;
        Ok::<_, Box<dyn Error>>(())
    })
}

/// `active_directory_keytab_login_without_preauth`: testuser3, which does not
/// require pre-authentication, logs in with its keytab; the KDC issues the
/// aes256-cts-hmac-sha1-96 TGT without pre-authentication.
#[test]
fn keytab_login_without_preauth_gets_an_aes256_tgt() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "keytab_login_without_preauth_gets_an_aes256_tgt",
        &[SAMBA_USER],
    )? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let realm = user_realm()?;
        let mut client = ad_client(
            "INTEROP_SAMBA_USER_NOPREAUTH_USER",
            "INTEROP_SAMBA_USER_NOPREAUTH_USER_KEYTAB",
            false,
        )?;
        let tgt = client.login().await?;
        assert_eq!(
            tgt.client(),
            &Principal::user(
                realm.as_str(),
                harness::var("INTEROP_SAMBA_USER_NOPREAUTH_USER")?
            )
        );
        assert_eq!(tgt.service(), &Principal::tgt_service(realm.as_str()));
        assert_negotiated_enctype("TGT session key", AES256_SHA1, tgt.session_key().etype())?;
        assert!(
            assert_ticket_flag("pre-authent", FLAG_PRE_AUTHENT, tgt.ticket_flags()).is_err(),
            "the TGT of an account without pre-authentication must not be pre-authenticated"
        );
        Ok::<_, Box<dyn Error>>(())
    })
}

/// `active_directory_service_ticket_validates_user_domain_pac`: a user-domain
/// service ticket (aes256-cts-hmac-sha1-96 session key and ticket key)
/// validates with the account keytab of testuser2 and carries a PAC of the
/// USER domain naming testuser1.
#[test]
fn service_ticket_validates_user_domain_pac() -> Result<(), Box<dyn Error>> {
    if !harness::require("service_ticket_validates_user_domain_pac", &[SAMBA_USER])? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let mut client = ad_client(
            "INTEROP_SAMBA_USER_USER",
            "INTEROP_SAMBA_USER_USER_KEYTAB",
            false,
        )?;
        let _: &AsRepSession = client.login().await?;
        let http = service(user_realm()?, "INTEROP_SAMBA_USER_HTTP_SERVICE")?;
        let ticket = client.get_service_ticket(http.clone()).await?;
        assert_eq!(ticket.service().name(), http.name());
        assert_negotiated_enctype(
            "service ticket session key",
            AES256_SHA1,
            ticket.session_key().etype(),
        )?;
        assert_negotiated_enctype(
            "service ticket (testuser2 key)",
            AES256_SHA1,
            ticket_etype(ticket.ticket().as_slice())?,
        )?;
        let keytab = Keytab::load(harness::var("INTEROP_SAMBA_USER_HTTP_ACCOUNT_KEYTAB")?)?;
        let account = harness::var("INTEROP_SAMBA_USER_HTTP_ACCOUNT")?;
        let validated = validate_service_ticket(&ticket, &keytab, &account, false)?;
        let pac = validated.pac().ok_or("a Samba service ticket has a PAC")?;
        let credentials = pac.ad_credentials().ok_or("the PAC has validation info")?;
        assert_eq!(
            credentials.logon_domain_name,
            harness::var("INTEROP_SAMBA_USER_NETBIOS")?
        );
        assert_eq!(
            credentials.effective_name,
            harness::var("INTEROP_SAMBA_USER_USER")?
        );
        Ok::<_, Box<dyn Error>>(())
    })
}

/// `active_directory_trust_resource_domain_service_ticket_validates_pac`:
/// across the forest trust, with RC4-HMAC opted in, testuser1 gets a ticket
/// for `HTTP/host.res.rskrb5@RES.RSKRB5` with an rc4-hmac session key; it
/// validates with the account keytab of sysHTTP and its PAC names testuser1.
#[test]
fn trust_resource_domain_rc4_service_ticket_validates_pac() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "trust_resource_domain_rc4_service_ticket_validates_pac",
        &[SAMBA_USER, SAMBA_RES],
    )? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let mut client = ad_client(
            "INTEROP_SAMBA_USER_USER",
            "INTEROP_SAMBA_USER_USER_KEYTAB",
            true,
        )?;
        let _: &AsRepSession = client.login().await?;
        let http = service(res_realm()?, "INTEROP_SAMBA_RES_HTTP_SERVICE")?;
        let ticket = client.get_service_ticket(http.clone()).await?;
        assert_eq!(ticket.service().name(), http.name());
        assert_eq!(ticket.service().realm, res_realm()?);
        assert_negotiated_enctype(
            "service ticket session key",
            RC4_HMAC,
            ticket.session_key().etype(),
        )?;
        let keytab = Keytab::load(harness::var("INTEROP_SAMBA_RES_HTTP_ACCOUNT_KEYTAB")?)?;
        let account = harness::var("INTEROP_SAMBA_RES_HTTP_ACCOUNT")?;
        let validated = validate_service_ticket(&ticket, &keytab, &account, true)?;
        let pac = validated.pac().ok_or("a Samba service ticket has a PAC")?;
        let credentials = pac.ad_credentials().ok_or("the PAC has validation info")?;
        assert_eq!(
            credentials.effective_name,
            harness::var("INTEROP_SAMBA_USER_USER")?
        );
        assert_eq!(
            credentials.logon_domain_name,
            harness::var("INTEROP_SAMBA_USER_NETBIOS")?
        );
        Ok::<_, Box<dyn Error>>(())
    })
}

/// `active_directory_trust_user_domain_service_ticket_validates_pac`: under
/// the RC4 trust configuration, a user-domain service ticket validates and
/// its PAC names testuser1.
#[test]
fn trust_configuration_user_domain_service_ticket_validates_pac() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "trust_configuration_user_domain_service_ticket_validates_pac",
        &[SAMBA_USER],
    )? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let mut client = ad_client(
            "INTEROP_SAMBA_USER_USER",
            "INTEROP_SAMBA_USER_USER_KEYTAB",
            true,
        )?;
        let _: &AsRepSession = client.login().await?;
        let http = service(user_realm()?, "INTEROP_SAMBA_USER_HTTP_SERVICE")?;
        let ticket = client.get_service_ticket(http.clone()).await?;
        assert_eq!(ticket.service().name(), http.name());
        assert_negotiated_enctype(
            "service ticket session key",
            RC4_HMAC,
            ticket.session_key().etype(),
        )?;
        let keytab = Keytab::load(harness::var("INTEROP_SAMBA_USER_HTTP_ACCOUNT_KEYTAB")?)?;
        let account = harness::var("INTEROP_SAMBA_USER_HTTP_ACCOUNT")?;
        let validated = validate_service_ticket(&ticket, &keytab, &account, true)?;
        let pac = validated.pac().ok_or("a Samba service ticket has a PAC")?;
        let credentials = pac.ad_credentials().ok_or("the PAC has validation info")?;
        assert_eq!(
            credentials.effective_name,
            harness::var("INTEROP_SAMBA_USER_USER")?
        );
        Ok::<_, Box<dyn Error>>(())
    })
}

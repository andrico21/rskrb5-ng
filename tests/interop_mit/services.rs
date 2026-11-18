//! kpasswd and MIT credential-cache scenarios.

use core::{error::Error, net::Ipv4Addr};

use rskrb5_ng::{
    ccache::CCache,
    client::{Password, Tokio, transport::KdcProtocol},
    error::Client as ClientError,
    kadmin::KPASSWD_SUCCESS,
    krb_priv::ipv4_host_address,
};

use super::{
    AES128_SHA2, AES256_SHA2, MIT_KDC, MIT_KPASSWD, config, password, realm, runtime, service,
    ticket_etype, transport, user,
};
use crate::harness::{self, assert_negotiated_enctype, assert_ticket_flag};

/// KDC error code of failed pre-authentication (the replaced password).
const KDC_ERR_PREAUTH_FAILED: i32 = 24;

/// RFC 4120 ticket flag bit `pre-authent`.
const FLAG_PRE_AUTHENT: u32 = 10;

/// The client changes the disposable account's password through MIT kadmind's
/// kpasswd service; afterwards the KDC refuses the old password with
/// `KDC_ERR_PREAUTH_FAILED` and issues a pre-authenticated TGT for the new one.
#[test]
fn kpasswd_changes_the_password_of_the_disposable_account() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "kpasswd_changes_the_password_of_the_disposable_account",
        &[MIT_KDC, MIT_KPASSWD],
    )? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let config = config("")?;
        let account = user("INTEROP_MIT_KPASSWD_USER")?;
        let old = password("INTEROP_MIT_KPASSWD_USER_PASSWORD")?;
        let new = password("INTEROP_MIT_KPASSWD_USER_NEW_PASSWORD")?;
        let mut client =
            Tokio::with_password(config.clone(), KdcProtocol::Tcp, account.clone(), old.clone())
                .with_transport(transport());
        let result = client
            .change_password(
                Password::from_vec(new.clone()),
                ipv4_host_address(Ipv4Addr::LOCALHOST.octets()),
            )
            .await?;
        assert_eq!(
            result.code, KPASSWD_SUCCESS,
            "kpasswd result code {}: {}",
            result.code, result.text
        );

        let mut stale = Tokio::with_password(config.clone(), KdcProtocol::Tcp, account.clone(), old)
            .with_transport(transport());
        let error = stale
            .login()
            .await
            .err()
            .ok_or("the replaced password must not log in")?;
        assert!(
            matches!(&error, ClientError::Kdc(kdc_error) if kdc_error.error_code() == KDC_ERR_PREAUTH_FAILED),
            "expected KDC_ERR_PREAUTH_FAILED for the old password, got {error}"
        );
        let mut changed = Tokio::with_password(config, KdcProtocol::Tcp, account, new)
            .with_transport(transport());
        let session = changed.login().await?;
        assert_ticket_flag("pre-authent", FLAG_PRE_AUTHENT, session.ticket_flags())?;
        Ok::<_, Box<dyn Error>>(())
    })
}

/// A FILE credential cache written by MIT 1.22.2 `kinit` loads with its
/// aes256-cts-hmac-sha384-192 TGT, and a client built from it gets a service
/// ticket with the configured aes128-cts-hmac-sha256-128 session key.
#[test]
fn mit_kinit_ccache_tgt_gets_a_service_ticket() -> Result<(), Box<dyn Error>> {
    if !harness::require("mit_kinit_ccache_tgt_gets_a_service_ticket", &[MIT_KDC])? {
        return Ok(());
    }
    let realm = realm()?;
    let cache = CCache::load_name(harness::var("INTEROP_MIT_KINIT_CCACHE")?)?;
    assert_eq!(
        cache.default_principal().name_string(),
        harness::var("INTEROP_MIT_USER")?,
        "the MIT cache belongs to the test user"
    );
    assert_eq!(
        cache.default_principal().realm,
        realm,
        "the MIT cache is of the fixture realm"
    );
    let tgt = cache
        .get_entry(&["krbtgt", realm.as_str()])
        .ok_or("the MIT cache holds the TGT")?;
    assert_negotiated_enctype("MIT kinit TGT session key", AES256_SHA2, tgt.key().etype())?;

    runtime()?.block_on(async {
        let http = service("INTEROP_MIT_HTTP_SERVICE")?;
        let mut client = Tokio::from_ccache(
            config(" default_tgs_enctypes = aes128-cts-hmac-sha256-128")?,
            KdcProtocol::Auto,
            &cache,
        )
        .with_transport(transport());
        let ticket = client.get_service_ticket(http.clone()).await?;
        assert_eq!(
            ticket.service(),
            &http,
            "the service ticket names the HTTP service"
        );
        assert_negotiated_enctype(
            "service ticket session key",
            AES128_SHA2,
            ticket.session_key().etype(),
        )?;
        assert_negotiated_enctype(
            "service ticket (HTTP key)",
            AES256_SHA2,
            ticket_etype(ticket.ticket().as_slice())?,
        )?;
        Ok::<_, Box<dyn Error>>(())
    })
}

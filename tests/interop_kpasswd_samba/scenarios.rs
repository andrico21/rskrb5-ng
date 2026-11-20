//! An ordinary user's own password change and an administrator's targeted reset, on Samba.

use core::{error::Error, net::Ipv4Addr, time::Duration};
use std::io;

use rskrb5_ng::{
    client::{
        Password, Tokio,
        principal::Principal,
        transport::{KdcProtocol, Tokio as TokioKdcTransport},
    },
    config::Config,
    error::Client as ClientError,
    kadmin::KPASSWD_SUCCESS,
    krb_priv::ipv4_host_address,
};
use tokio::runtime::{Builder, Runtime};

use crate::harness::{self, Fixture, assert_negotiated_enctype, assert_ticket_flag};

/// The KDC of the user domain, reached on `INTEROP_SAMBA_USER_KDC`.
const SAMBA_USER: Fixture = Fixture::new("samba-user", "INTEROP_SAMBA_USER_KDC");

/// The kpasswd service of the user domain, on `INTEROP_SAMBA_USER_KPASSWD`.
const SAMBA_USER_KPASSWD: Fixture = Fixture::new("samba-user", "INTEROP_SAMBA_USER_KPASSWD");

/// Enctype id of aes256-cts-hmac-sha1-96, the strongest key of every Samba account.
const AES256_SHA1: i32 = 18;

/// RFC 4120 ticket flag bit `pre-authent`.
const FLAG_PRE_AUTHENT: u32 = 10;

/// KDC error code of failed pre-authentication (the replaced password).
const KDC_ERR_PREAUTH_FAILED: i32 = 24;

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

/// The user domain's KDC and kpasswd server.
fn config() -> Result<Config, Box<dyn Error>> {
    let realm = harness::var("INTEROP_SAMBA_USER_REALM")?;
    Ok(Config::parse(&format!(
        "[libdefaults]\n default_realm = {realm}\n dns_lookup_kdc = false\n dns_lookup_realm = false\n\
         [realms]\n {realm} = {{\n  kdc = {}\n  kpasswd_server = {}\n }}\n",
        harness::var("INTEROP_SAMBA_USER_KDC")?,
        harness::var("INTEROP_SAMBA_USER_KPASSWD")?,
    ))?)
}

/// The user-domain principal named by the env-file key `key`.
fn user(key: &str) -> Result<Principal, Box<dyn Error>> {
    Ok(Principal::user(
        harness::var("INTEROP_SAMBA_USER_REALM")?,
        harness::var(key)?,
    ))
}

/// The password in the env-file key `key`.
fn password(key: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(harness::var(key)?.into_bytes())
}

/// The old password is refused and the new one logs in with a pre-authenticated TGT.
async fn assert_replaced(
    config: &Config,
    account: &Principal,
    old: Vec<u8>,
    new: Vec<u8>,
) -> Result<(), Box<dyn Error>> {
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
    let mut changed = Tokio::with_password(config.clone(), KdcProtocol::Tcp, account.clone(), new)
        .with_transport(transport());
    let session = changed.login().await?;
    assert_ticket_flag("pre-authent", FLAG_PRE_AUTHENT, session.ticket_flags())?;
    assert_negotiated_enctype(
        "TGT session key",
        AES256_SHA1,
        session.session_key().etype(),
    )?;
    Ok(())
}

/// FU-IOP-P13: an ordinary user changes their own password through the high-level
/// `change_password`. The request carries no RFC 3244 target fields, so Samba takes its
/// change path (`kpasswd-service-heimdal.c:165-173`) and needs no Reset-Password right;
/// afterwards the old password fails and the new one works.
#[test]
fn an_ordinary_user_changes_their_own_password() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "an_ordinary_user_changes_their_own_password",
        &[SAMBA_USER, SAMBA_USER_KPASSWD],
    )? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let config = config()?;
        let account = user("INTEROP_SAMBA_USER_KPASSWD_SELF")?;
        let old = password("INTEROP_SAMBA_USER_KPASSWD_SELF_PASSWORD")?;
        let new = password("INTEROP_SAMBA_USER_KPASSWD_SELF_NEW_PASSWORD")?;
        let mut client = Tokio::with_password(
            config.clone(),
            KdcProtocol::Tcp,
            account.clone(),
            old.clone(),
        )
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
        assert_replaced(&config, &account, old, new).await
    })
}

/// The domain administrator resets another account's password with the RFC 3244 target
/// fields (the targeted set-password); the old password then fails and the new one works.
/// This stays a separate scenario from the user's own change.
#[test]
fn an_administrators_targeted_reset_sets_another_accounts_password() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "an_administrators_targeted_reset_sets_another_accounts_password",
        &[SAMBA_USER, SAMBA_USER_KPASSWD],
    )? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let config = config()?;
        let target = user("INTEROP_SAMBA_USER_SETPW_TARGET")?;
        let old = password("INTEROP_SAMBA_USER_SETPW_TARGET_PASSWORD")?;
        let new = password("INTEROP_SAMBA_USER_SETPW_TARGET_NEW_PASSWORD")?;
        let mut administrator = Tokio::with_password(
            config.clone(),
            KdcProtocol::Tcp,
            user("INTEROP_SAMBA_USER_ADMIN_PRINCIPAL")?,
            password("INTEROP_SAMBA_USER_ADMIN_PASSWORD")?,
        )
        .with_transport(transport());

        let result = administrator
            .change_password_for(
                target.clone(),
                Password::from_vec(new.clone()),
                ipv4_host_address(Ipv4Addr::LOCALHOST.octets()),
            )
            .await?;

        assert_eq!(
            result.code, KPASSWD_SUCCESS,
            "kpasswd result code {}: {}",
            result.code, result.text
        );
        assert_replaced(&config, &target, old, new).await
    })
}

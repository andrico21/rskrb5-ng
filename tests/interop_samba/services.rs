//! kpasswd (FU-TST-06) and constrained-delegation scenarios against Samba.

use core::{error::Error, net::Ipv4Addr};

use rskrb5_ng::{
    client::{Password, Tokio, principal::Principal, transport::KdcProtocol},
    error::Client as ClientError,
    kadmin::KPASSWD_SUCCESS,
    keytab::Keytab,
    krb_priv::ipv4_host_address,
};

use super::{
    AES256_SHA1, FLAG_PRE_AUTHENT, SAMBA_USER, SAMBA_USER_KPASSWD, config, password, runtime,
    service, shown, ticket_etype, transport, user, user_realm,
};
use crate::harness::{self, assert_negotiated_enctype, assert_ticket_flag};

/// KDC error code of failed pre-authentication (the replaced password).
const KDC_ERR_PREAUTH_FAILED: i32 = 24;

/// KDC error code of a refused KDC option (here: a delegation the domain does
/// not allow).
const KDC_ERR_BADOPTION: i32 = 13;

/// RFC 4120 ticket flag bit `forwardable`.
const FLAG_FORWARDABLE: u32 = 1;

/// FU-TST-06: the high-level password change of the crate
/// (`Tokio::change_password_for`) sets a new password on the disposable
/// account kpasswduser as the domain Administrator through Samba's kpasswd
/// service. Samba's reply passes every RSK-789A6FBB reply control (AP-REP
/// server sequence, timestamp, sender address); afterwards the KDC refuses
/// the old password with `KDC_ERR_PREAUTH_FAILED` and issues a
/// pre-authenticated TGT for the new one. (The self-change `change_password`
/// names the client as the RFC 3244 target, which Samba treats as an
/// administrative reset and refuses for a plain user: register row
/// FU-IOP-P13, todo 23.)
#[test]
fn kpasswd_changes_the_samba_disposable_account_password() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "kpasswd_changes_the_samba_disposable_account_password",
        &[SAMBA_USER, SAMBA_USER_KPASSWD],
    )? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let config = config("")?;
        let account = user("INTEROP_SAMBA_USER_KPASSWD_USER")?;
        let old = password("INTEROP_SAMBA_USER_KPASSWD_USER_PASSWORD")?;
        let new = password("INTEROP_SAMBA_USER_KPASSWD_USER_NEW_PASSWORD")?;
        let mut administrator = Tokio::with_password(
            config.clone(),
            KdcProtocol::Tcp,
            user("INTEROP_SAMBA_USER_ADMIN_PRINCIPAL")?,
            password("INTEROP_SAMBA_USER_ADMIN_PASSWORD")?,
        )
        .with_transport(transport());
        let result = administrator
            .change_password_for(
                account.clone(),
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
        assert_negotiated_enctype("TGT session key", AES256_SHA1, session.session_key().etype())?;
        Ok::<_, Box<dyn Error>>(())
    })
    .map_err(shown)
}

/// Classic constrained delegation: svc-s4u (protocol transition, allowed to
/// delegate to `HTTP/backend.user.rskrb5` only) gets a forwardable `S4U2Self`
/// evidence ticket for s4uclient, an `S4U2Proxy` ticket for the allowed target
/// in s4uclient's name, and `KDC_ERR_BADOPTION` for `HTTP/denied.user.rskrb5`.
#[test]
fn s4u_constrained_delegation_reaches_only_the_allowed_target() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "s4u_constrained_delegation_reaches_only_the_allowed_target",
        &[SAMBA_USER],
    )? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let realm = user_realm()?;
        let account = Principal::user(realm.as_str(), harness::var("INTEROP_SAMBA_USER_S4U_ACCOUNT")?);
        let impersonated = user("INTEROP_SAMBA_USER_S4U_CLIENT")?;
        let mut client = Tokio::with_keytab(
            config(" forwardable = true")?,
            KdcProtocol::Tcp,
            account.clone(),
            Keytab::load(harness::var("INTEROP_SAMBA_USER_S4U_KEYTAB")?)?,
        )
        .with_transport(transport());
        let evidence = client.s4u2self(impersonated.clone()).await?;
        assert_eq!(evidence.client(), &impersonated, "the evidence ticket names s4uclient");
        assert_eq!(evidence.service(), &account, "the evidence ticket is for svc-s4u itself");
        assert_ticket_flag("forwardable", FLAG_FORWARDABLE, evidence.ticket_flags())?;

        let allowed = service(realm.clone(), "INTEROP_SAMBA_USER_DELEGATION_TARGET")?;
        let proxied = client.s4u2proxy(&evidence, allowed.clone()).await?;
        assert_eq!(proxied.client(), &impersonated, "the delegated ticket names s4uclient");
        assert_eq!(proxied.service(), &allowed, "the delegated ticket is for HTTP/backend");
        assert_negotiated_enctype(
            "delegated ticket (svc-backend key)",
            AES256_SHA1,
            ticket_etype(proxied.ticket().as_slice())?,
        )?;

        let denied = service(realm, "INTEROP_SAMBA_USER_DELEGATION_DENIED")?;
        let refusal = client
            .s4u2proxy(&evidence, denied)
            .await
            .err()
            .ok_or("delegation to HTTP/denied must be refused")?;
        assert!(
            matches!(&refusal, ClientError::Kdc(kdc_error) if kdc_error.error_code() == KDC_ERR_BADOPTION),
            "expected KDC_ERR_BADOPTION for HTTP/denied, got {refusal}"
        );
        Ok::<_, Box<dyn Error>>(())
    })
    .map_err(shown)
}

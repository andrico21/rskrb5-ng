//! AS, TGS, pre-authentication, discovery, error and renewal scenarios.

use core::{error::Error, time::Duration};
use std::io::{self, Write as _};

use rskrb5_ng::{
    client::{
        Tokio, build_tgs_req, build_tgt_as_req,
        transport::{KdcEndpointSource, KdcProtocol},
    },
    error::Client as ClientError,
    keytab::Keytab,
    krb_error,
};

use super::{
    AES128_SHA1, AES128_SHA2, AES256_SHA1, AES256_SHA2, MIT_KDC, as_options, config, kdc, label,
    password, realm, runtime, service, tgs_options, ticket_etype, transport, user,
};
use crate::harness::{
    self, assert_negotiated_enctype, assert_negotiated_padata, assert_ticket_flag,
};

/// PA-DATA type of PA-ENC-TIMESTAMP (RFC 4120).
const PA_ENC_TIMESTAMP: i32 = 2;

/// PA-DATA type of PA-ETYPE-INFO2 (RFC 4120).
const PA_ETYPE_INFO2: i32 = 19;

/// KDC error code of an unknown server principal.
const KDC_ERR_S_PRINCIPAL_UNKNOWN: i32 = 7;

/// KDC error code of failed pre-authentication (a wrong password).
const KDC_ERR_PREAUTH_FAILED: i32 = 24;

/// KDC error code of required pre-authentication.
const KDC_ERR_PREAUTH_REQUIRED: i32 = 25;

/// RFC 4120 ticket flag bit `renewable`.
const FLAG_RENEWABLE: u32 = 8;

/// RFC 4120 ticket flag bit `initial`.
const FLAG_INITIAL: u32 = 9;

/// RFC 4120 ticket flag bit `pre-authent`.
const FLAG_PRE_AUTHENT: u32 = 10;

/// A configuration that makes the client ask for AES-SHA2 keys:
/// aes256-cts-hmac-sha384-192 TGT session keys and aes128-cts-hmac-sha256-128
/// service session keys.
const SHA2_LIBDEFAULTS: &str = " default_tkt_enctypes = aes256-cts-hmac-sha384-192
 default_tgs_enctypes = aes128-cts-hmac-sha256-128";

/// The KDC demands pre-authentication from `preauthuser` and offers
/// PA-ENC-TIMESTAMP with PA-ETYPE-INFO2; the password login then carries the
/// encrypted timestamp, and the TGT has the pre-authent and initial flags.
#[test]
fn preauth_required_principal_negotiates_encrypted_timestamp() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "preauth_required_principal_negotiates_encrypted_timestamp",
        &[MIT_KDC],
    )? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let kdc = kdc()?;
        let client = user("INTEROP_MIT_PREAUTH_USER")?;
        for (sequence, protocol) in [(1, KdcProtocol::Udp), (3, KdcProtocol::Tcp)] {
            writeln!(
                io::stderr(),
                "interop: pre-authentication over {}",
                label(protocol)
            )?;
            // Given an AS-REQ without PA-DATA, when the KDC answers, then it
            // requires pre-authentication and offers the encrypted timestamp.
            let probe = build_tgt_as_req(
                client.clone(),
                as_options(protocol, sequence, vec![AES256_SHA2])?,
            )?;
            let reply = transport()
                .send(protocol, kdc.as_str(), probe.der())
                .await?;
            let error = krb_error::decode(&reply)?;
            assert_eq!(
                krb_error::info(&error)?.error_code(),
                KDC_ERR_PREAUTH_REQUIRED,
                "the KDC must require pre-authentication"
            );
            let offered = krb_error::preauth_method_data(&error, KDC_ERR_PREAUTH_REQUIRED)?
                .iter()
                .map(|padata| padata.r#type)
                .collect::<Vec<_>>();
            assert_negotiated_padata("KDC_ERR_PREAUTH_REQUIRED", PA_ENC_TIMESTAMP, &offered)?;
            assert_negotiated_padata("KDC_ERR_PREAUTH_REQUIRED", PA_ETYPE_INFO2, &offered)?;
            // When the password login answers it, then the TGT is pre-authenticated.
            let session = transport()
                .login_tgt_with_password(
                    protocol,
                    kdc.as_str(),
                    client.clone(),
                    &password("INTEROP_MIT_PREAUTH_USER_PASSWORD")?,
                    as_options(protocol, sequence.wrapping_add(1), vec![AES256_SHA2])?,
                )
                .await?;
            assert_ticket_flag("pre-authent", FLAG_PRE_AUTHENT, session.ticket_flags())?;
            assert_ticket_flag("initial", FLAG_INITIAL, session.ticket_flags())?;
            assert_negotiated_enctype(
                "TGT session key",
                AES256_SHA2,
                session.session_key().etype(),
            )?;
        }
        Ok::<_, Box<dyn Error>>(())
    })
}

/// AS and TGS exchanges restricted to each AES enctype yield session keys of
/// exactly that enctype over UDP and TCP; the tickets are encrypted with the
/// fixture's aes256-cts-hmac-sha384-192 krbtgt and service keys.
#[test]
fn as_and_tgs_negotiate_each_aes_enctype_over_udp_and_tcp() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "as_and_tgs_negotiate_each_aes_enctype_over_udp_and_tcp",
        &[MIT_KDC],
    )? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let kdc = kdc()?;
        let client = user("INTEROP_MIT_USER")?;
        let secret = password("INTEROP_MIT_USER_PASSWORD")?;
        let http = service("INTEROP_MIT_HTTP_SERVICE")?;
        let mut sequence = 0_u32;
        for etype in [AES128_SHA1, AES256_SHA1, AES128_SHA2, AES256_SHA2] {
            for protocol in [KdcProtocol::Udp, KdcProtocol::Tcp] {
                sequence = sequence.wrapping_add(2);
                writeln!(
                    io::stderr(),
                    "interop: AS/TGS enctype {etype} over {}",
                    label(protocol)
                )?;
                let tgt = transport()
                    .login_tgt_with_password(
                        protocol,
                        kdc.as_str(),
                        client.clone(),
                        secret.as_slice(),
                        as_options(protocol, sequence, vec![etype])?,
                    )
                    .await?;
                assert_negotiated_enctype("TGT session key", etype, tgt.session_key().etype())?;
                assert_negotiated_enctype(
                    "TGT (krbtgt key)",
                    AES256_SHA2,
                    ticket_etype(tgt.ticket().as_slice())?,
                )?;
                let request = build_tgs_req(
                    &tgt,
                    http.clone(),
                    tgs_options(protocol, sequence.wrapping_add(1), vec![etype])?,
                )?;
                let ticket = transport()
                    .exchange_tgs_req(protocol, kdc.as_str(), &request, tgt.session_key())
                    .await?;
                assert_eq!(
                    ticket.service(),
                    &http,
                    "the service ticket names the HTTP service"
                );
                assert_negotiated_enctype(
                    "service ticket session key",
                    etype,
                    ticket.session_key().etype(),
                )?;
                assert_negotiated_enctype(
                    "service ticket (HTTP key)",
                    AES256_SHA2,
                    ticket_etype(ticket.ticket().as_slice())?,
                )?;
            }
        }
        Ok::<_, Box<dyn Error>>(())
    })
}

/// Configuration discovery finds exactly the configured KDC, and password and
/// keytab clients honour the configured AES-SHA2 enctypes.
#[test]
fn configured_kdc_password_and_keytab_logins_honour_configured_enctypes()
-> Result<(), Box<dyn Error>> {
    if !harness::require(
        "configured_kdc_password_and_keytab_logins_honour_configured_enctypes",
        &[MIT_KDC],
    )? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let config = config(SHA2_LIBDEFAULTS)?;
        let realm = realm()?;
        let kdc = kdc()?;
        for protocol in [KdcProtocol::Udp, KdcProtocol::Tcp] {
            let endpoints = transport().discover_kdcs(&config, &realm, protocol).await?;
            assert_eq!(
                endpoints.len(),
                1,
                "exactly the configured KDC is discovered"
            );
            assert!(
                endpoints.iter().all(|endpoint| {
                    matches!(endpoint.source, KdcEndpointSource::Config)
                        && endpoint.authority() == kdc
                }),
                "the discovered KDC is the configured one"
            );
        }
        let http = service("INTEROP_MIT_HTTP_SERVICE")?;
        let keytab = Keytab::load(harness::var("INTEROP_MIT_USER_KEYTAB")?)?;
        let mut clients = [
            Tokio::with_password(
                config.clone(),
                KdcProtocol::Auto,
                user("INTEROP_MIT_USER")?,
                password("INTEROP_MIT_USER_PASSWORD")?,
            ),
            Tokio::with_keytab(
                config.clone(),
                KdcProtocol::Tcp,
                user("INTEROP_MIT_USER")?,
                keytab,
            ),
        ];
        for client in &mut clients {
            let tgt = client.login().await?.clone();
            assert_negotiated_enctype("TGT session key", AES256_SHA2, tgt.session_key().etype())?;
            let ticket = client.get_service_ticket(http.clone()).await?;
            assert_negotiated_enctype(
                "service ticket session key",
                AES128_SHA2,
                ticket.session_key().etype(),
            )?;
        }
        Ok::<_, Box<dyn Error>>(())
    })
}

/// The pre-authentication principal logs in with the keytab MIT exported, and
/// its TGT is pre-authenticated.
#[test]
fn preauth_principal_logs_in_with_mit_exported_keytab() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "preauth_principal_logs_in_with_mit_exported_keytab",
        &[MIT_KDC],
    )? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let keytab = Keytab::load(harness::var("INTEROP_MIT_PREAUTH_USER_KEYTAB")?)?;
        for protocol in [KdcProtocol::Auto, KdcProtocol::Tcp] {
            let mut client = Tokio::with_keytab(
                config(SHA2_LIBDEFAULTS)?,
                protocol,
                user("INTEROP_MIT_PREAUTH_USER")?,
                keytab.clone(),
            )
            .with_transport(transport());
            let session = client.login().await?;
            assert_ticket_flag("pre-authent", FLAG_PRE_AUTHENT, session.ticket_flags())?;
            assert_negotiated_enctype(
                "TGT session key",
                AES256_SHA2,
                session.session_key().etype(),
            )?;
        }
        Ok::<_, Box<dyn Error>>(())
    })
}

/// A wrong password fails with `KDC_ERR_PREAUTH_FAILED`, and a TGS request for
/// an unknown service with `KDC_ERR_S_PRINCIPAL_UNKNOWN`.
#[test]
fn wrong_password_and_unknown_service_return_kdc_errors() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "wrong_password_and_unknown_service_return_kdc_errors",
        &[MIT_KDC],
    )? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let mut wrong = Tokio::with_password(
            config("")?,
            KdcProtocol::Tcp,
            user("INTEROP_MIT_PREAUTH_USER")?,
            b"not-the-password".to_vec(),
        )
        .with_transport(transport());
        let error = wrong.login().await.err().ok_or("a wrong password must not log in")?;
        assert!(
            matches!(&error, ClientError::Kdc(kdc_error) if kdc_error.error_code() == KDC_ERR_PREAUTH_FAILED),
            "expected KDC_ERR_PREAUTH_FAILED, got {error}"
        );

        let mut client = Tokio::with_password(
            config("")?,
            KdcProtocol::Auto,
            user("INTEROP_MIT_USER")?,
            password("INTEROP_MIT_USER_PASSWORD")?,
        )
        .with_transport(transport());
        let missing = rskrb5_ng::Principal::new(realm()?, 2, ["HTTP", "missing.test.rskrb5"]);
        let unknown = client
            .get_service_ticket(missing)
            .await
            .err()
            .ok_or("an unknown service must be rejected")?;
        assert!(
            matches!(&unknown, ClientError::Kdc(kdc_error) if kdc_error.error_code() == KDC_ERR_S_PRINCIPAL_UNKNOWN),
            "expected KDC_ERR_S_PRINCIPAL_UNKNOWN, got {unknown}"
        );
        Ok::<_, Box<dyn Error>>(())
    })
}

/// A renewable TGT renews over UDP and TCP, keeping its renew-till, its
/// renewable flag and its aes256-cts-hmac-sha384-192 session key.
#[test]
fn renewable_tgt_renews_over_udp_and_tcp() -> Result<(), Box<dyn Error>> {
    if !harness::require("renewable_tgt_renews_over_udp_and_tcp", &[MIT_KDC])? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let kdc = kdc()?;
        for (sequence, protocol) in [(41, KdcProtocol::Udp), (43, KdcProtocol::Tcp)] {
            let tgt = transport()
                .login_tgt_with_password(
                    protocol,
                    kdc.as_str(),
                    user("INTEROP_MIT_USER")?,
                    &password("INTEROP_MIT_USER_PASSWORD")?,
                    as_options(protocol, sequence, vec![AES256_SHA2])?
                        .with_renew_lifetime(Some(Duration::from_hours(2))),
                )
                .await?;
            assert_ticket_flag("renewable", FLAG_RENEWABLE, tgt.ticket_flags())?;
            let renew_till = tgt.renew_till().ok_or("a renewable TGT has a renew-till")?;
            let renewed = transport()
                .renew_tgt(
                    protocol,
                    kdc.as_str(),
                    &tgt,
                    tgs_options(protocol, sequence.wrapping_add(1), vec![AES256_SHA2])?,
                )
                .await?;
            assert_ticket_flag("renewable", FLAG_RENEWABLE, renewed.ticket_flags())?;
            assert_eq!(
                renewed.renew_till(),
                Some(renew_till),
                "renewal keeps the renew-till"
            );
            assert!(
                renewed.end_time() <= renew_till,
                "the renewed TGT ends by its renew-till"
            );
            assert_negotiated_enctype(
                "renewed TGT session key",
                AES256_SHA2,
                renewed.session_key().etype(),
            )?;
        }
        Ok::<_, Box<dyn Error>>(())
    })
}

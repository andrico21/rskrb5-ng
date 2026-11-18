//! AS, TGS, pre-authentication, referral and error scenarios against Samba.

use core::error::Error;
use std::io::{self, Write as _};

use rskrb5_ng::{
    client::{
        KDC_OPTION_CANONICALIZE, Tokio, build_tgs_req, build_tgt_as_req, principal::Principal,
        transport::KdcProtocol,
    },
    error::Client as ClientError,
    krb_error,
};

use super::{
    AES128_SHA1, AES256_SHA1, FLAG_PRE_AUTHENT, SAMBA_RES, SAMBA_USER, as_options, config, label,
    password, res_realm, runtime, service, tgs_options, ticket_etype, transport, user, user_kdc,
    user_realm,
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

/// RFC 4120 ticket flag bit `initial`.
const FLAG_INITIAL: u32 = 9;

/// Samba demands pre-authentication from testuser1 and offers
/// PA-ENC-TIMESTAMP with PA-ETYPE-INFO2 over UDP and TCP; the password login
/// then carries the encrypted timestamp, and the TGT has the pre-authent and
/// initial flags and an aes256-cts-hmac-sha1-96 session key.
#[test]
fn samba_requires_and_accepts_encrypted_timestamp_preauth() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "samba_requires_and_accepts_encrypted_timestamp_preauth",
        &[SAMBA_USER],
    )? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let kdc = user_kdc()?;
        let client = user("INTEROP_SAMBA_USER_USER")?;
        for (sequence, protocol) in [(1, KdcProtocol::Udp), (3, KdcProtocol::Tcp)] {
            writeln!(
                io::stderr(),
                "interop: Samba pre-authentication over {}",
                label(protocol)
            )?;
            let probe = build_tgt_as_req(
                client.clone(),
                as_options(protocol, sequence, vec![AES256_SHA1])?,
            )?;
            let reply = transport()
                .send(protocol, kdc.as_str(), probe.der())
                .await?;
            let error = krb_error::decode(&reply)?;
            assert_eq!(
                krb_error::info(&error)?.error_code(),
                KDC_ERR_PREAUTH_REQUIRED,
                "Samba must require pre-authentication"
            );
            let offered = krb_error::preauth_method_data(&error, KDC_ERR_PREAUTH_REQUIRED)?
                .iter()
                .map(|padata| padata.r#type)
                .collect::<Vec<_>>();
            assert_negotiated_padata("KDC_ERR_PREAUTH_REQUIRED", PA_ENC_TIMESTAMP, &offered)?;
            assert_negotiated_padata("KDC_ERR_PREAUTH_REQUIRED", PA_ETYPE_INFO2, &offered)?;
            let session = transport()
                .login_tgt_with_password(
                    KdcProtocol::Tcp,
                    kdc.as_str(),
                    client.clone(),
                    &password("INTEROP_SAMBA_USER_USER_PASSWORD")?,
                    as_options(
                        KdcProtocol::Tcp,
                        sequence.wrapping_add(1),
                        vec![AES256_SHA1],
                    )?,
                )
                .await?;
            assert_ticket_flag("pre-authent", FLAG_PRE_AUTHENT, session.ticket_flags())?;
            assert_ticket_flag("initial", FLAG_INITIAL, session.ticket_flags())?;
            assert_negotiated_enctype(
                "TGT session key",
                AES256_SHA1,
                session.session_key().etype(),
            )?;
        }
        Ok::<_, Box<dyn Error>>(())
    })
}

/// AS and TGS exchanges restricted to each AES-SHA1 enctype yield session keys
/// of exactly that enctype; the TGT and the HTTP service ticket are encrypted
/// with the accounts' aes256-cts-hmac-sha1-96 keys.
#[test]
fn samba_as_and_tgs_negotiate_each_aes_enctype() -> Result<(), Box<dyn Error>> {
    if !harness::require("samba_as_and_tgs_negotiate_each_aes_enctype", &[SAMBA_USER])? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let kdc = user_kdc()?;
        let client = user("INTEROP_SAMBA_USER_USER")?;
        let secret = password("INTEROP_SAMBA_USER_USER_PASSWORD")?;
        let http = service(user_realm()?, "INTEROP_SAMBA_USER_HTTP_SERVICE")?;
        let mut sequence = 10_u32;
        for etype in [AES128_SHA1, AES256_SHA1] {
            sequence = sequence.wrapping_add(2);
            writeln!(io::stderr(), "interop: Samba AS/TGS enctype {etype}")?;
            let tgt = transport()
                .login_tgt_with_password(
                    KdcProtocol::Tcp,
                    kdc.as_str(),
                    client.clone(),
                    secret.as_slice(),
                    as_options(KdcProtocol::Tcp, sequence, vec![etype])?,
                )
                .await?;
            assert_negotiated_enctype("TGT session key", etype, tgt.session_key().etype())?;
            assert_negotiated_enctype(
                "TGT (krbtgt key)",
                AES256_SHA1,
                ticket_etype(tgt.ticket().as_slice())?,
            )?;
            let request = build_tgs_req(
                &tgt,
                http.clone(),
                tgs_options(KdcProtocol::Tcp, sequence.wrapping_add(1), vec![etype])?,
            )?;
            let ticket = transport()
                .exchange_tgs_req(KdcProtocol::Tcp, kdc.as_str(), &request, tgt.session_key())
                .await?;
            assert_eq!(ticket.service(), &http, "the ticket names the HTTP service");
            assert_negotiated_enctype(
                "service ticket session key",
                etype,
                ticket.session_key().etype(),
            )?;
            assert_negotiated_enctype(
                "service ticket (HTTP key)",
                AES256_SHA1,
                ticket_etype(ticket.ticket().as_slice())?,
            )?;
        }
        Ok::<_, Box<dyn Error>>(())
    })
}

/// A canonicalizing TGS request for `HTTP/host.res.rskrb5` in the client's
/// own realm is referred across the forest trust: the user-domain KDC answers
/// with the referral TGT `krbtgt/RES.RSKRB5@USER.RSKRB5`, and the
/// resource-domain KDC issues the ticket in `RES.RSKRB5`.
#[test]
fn referral_across_the_forest_trust_reaches_the_resource_domain() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "referral_across_the_forest_trust_reaches_the_resource_domain",
        &[SAMBA_USER, SAMBA_RES],
    )? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let config = config("")?;
        let user_realm = user_realm()?;
        let res_realm = res_realm()?;
        let tgt = transport()
            .login_tgt_with_password(
                KdcProtocol::Tcp,
                user_kdc()?.as_str(),
                user("INTEROP_SAMBA_USER_USER")?,
                &password("INTEROP_SAMBA_USER_USER_PASSWORD")?,
                as_options(KdcProtocol::Tcp, 21, vec![AES256_SHA1])?,
            )
            .await?;
        let requested = service(user_realm.clone(), "INTEROP_SAMBA_RES_HTTP_SERVICE")?;
        let result = transport()
            .get_service_ticket_with_referral_trace(
                &config,
                KdcProtocol::Tcp,
                &tgt,
                requested,
                tgs_options(KdcProtocol::Tcp, 22, vec![AES256_SHA1])?
                    .with_kdc_option_bits(KDC_OPTION_CANONICALIZE),
            )
            .await?;
        let referrals = result.referral_tgts();
        assert_eq!(referrals.len(), 1, "exactly one referral crosses the trust");
        let referral = referrals.first().ok_or("one referral TGT")?;
        assert_eq!(
            referral.service(),
            &Principal::new(user_realm.as_str(), 2, ["krbtgt", res_realm.as_str()]),
            "the referral TGT is the inter-realm TGT of the trust"
        );
        let ticket = result.ticket();
        assert_eq!(
            ticket.service().realm,
            res_realm,
            "the ticket is issued in RES.RSKRB5"
        );
        assert_eq!(
            ticket.service().name(),
            harness::var("INTEROP_SAMBA_RES_HTTP_SERVICE")?,
            "the referred ticket names the resource-domain HTTP service"
        );
        assert_negotiated_enctype(
            "referred ticket session key",
            AES256_SHA1,
            ticket.session_key().etype(),
        )?;
        assert_negotiated_enctype(
            "referred ticket (sysHTTP key)",
            AES256_SHA1,
            ticket_etype(ticket.ticket().as_slice())?,
        )?;
        Ok::<_, Box<dyn Error>>(())
    })
}

/// A wrong password fails with `KDC_ERR_PREAUTH_FAILED`, and a TGS request for
/// an unknown service with `KDC_ERR_S_PRINCIPAL_UNKNOWN`.
#[test]
fn samba_wrong_password_and_unknown_service_return_kdc_errors() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "samba_wrong_password_and_unknown_service_return_kdc_errors",
        &[SAMBA_USER],
    )? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let mut wrong = Tokio::with_password(
            config("")?,
            KdcProtocol::Tcp,
            user("INTEROP_SAMBA_USER_USER")?,
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
            KdcProtocol::Tcp,
            user("INTEROP_SAMBA_USER_USER")?,
            password("INTEROP_SAMBA_USER_USER_PASSWORD")?,
        )
        .with_transport(transport());
        let missing = Principal::new(user_realm()?, 2, ["HTTP", "missing.user.rskrb5"]);
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

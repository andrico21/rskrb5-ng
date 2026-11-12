//! Functional cached-TGT renewal replacement in the private service-acquisition step.

use core::time::Duration;
use std::time::SystemTime;

use rasn::types::Integer;
use rasn_kerberos::{EncryptedData, Ticket};
use tokio::{net::TcpListener, runtime::Builder, time::timeout};

use super::{TestError, service::answer_service};
use crate::{
    Config,
    client::{
        AsRepSession, KDC_OPTION_RENEWABLE, Principal, Tokio, principal_to_rasn,
        transport::KdcProtocol,
    },
    keytab::EncryptionKey,
    ticket,
};

/// A current renewable session whose key lets the loopback peer read its authenticator.
fn renewable(service: Principal) -> Result<AsRepSession, TestError> {
    let wire = Ticket {
        tkt_vno: Integer::from(5_i32),
        realm: "EXAMPLE.COM".try_into()?,
        sname: principal_to_rasn(&service)?,
        enc_part: EncryptedData {
            etype: 18,
            kvno: None,
            cipher: vec![0x52; 16].into(),
        },
    };
    let now = SystemTime::now();
    let start = now
        .checked_sub(Duration::from_mins(1))
        .ok_or("start time")?;
    let end = now.checked_add(Duration::from_hours(1)).ok_or("end time")?;
    let renew_till = now
        .checked_add(Duration::from_hours(10))
        .ok_or("renew till")?;
    Ok(AsRepSession::new(
        Principal::user("EXAMPLE.COM", "alice"),
        service,
        EncryptionKey::new(18, vec![0x41; 32]),
        ticket::encode(&wire)?.into(),
        KDC_OPTION_RENEWABLE.to_be_bytes(),
        start,
        end,
    )
    .with_renew_till(Some(renew_till)))
}

/// Renews the cached session for `realm` against a loopback issuer KDC.
fn renew(
    primary: AsRepSession,
    referral: Option<AsRepSession>,
    realm: &str,
) -> Result<(Tokio, AsRepSession), TestError> {
    Builder::new_current_thread().enable_all().build()?.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let config = Config::parse(&format!("[libdefaults]\n dns_lookup_kdc = false\n[realms]\n EXAMPLE.COM = {{\n kdc = {}\n }}\n", listener.local_addr()?))?;
        let mut client = Tokio::from_tgt_session(config, KdcProtocol::Tcp, primary);
        if let Some(session) = referral {
            client.cache_tgt_session(session)?;
        }
        let (renewed, ()) = timeout(Duration::from_secs(10), async {
            tokio::try_join!(async { client.renew_cached_tgt_session_for_realm(realm, SystemTime::now()).await.map_err(|err| TestError::from(format!("renewal: {err} ({err:?})"))) }, answer_service(listener))
        }).await??;
        Ok((client, renewed.ok_or("cached session was not renewed")?))
    })
}

/// Renewal replaces the cached referral TGT of its realm with the authenticated reply.
#[test]
fn cached_referral_renewal_replaces_realm_session() -> Result<(), TestError> {
    let referral = renewable(Principal::new("EXAMPLE.COM", 2, ["krbtgt", "RESDOM.COM"]))?;
    let primary = renewable(Principal::tgt_service("EXAMPLE.COM"))?;
    let (client, renewed) = renew(primary, Some(referral), "RESDOM.COM")?;
    assert_eq!(renewed.session_key().value().as_ref(), &[0x63; 32]);
    let cached = client
        .tgt_session_for_realm("RESDOM.COM")
        .ok_or("referral missing")?;
    assert_eq!(cached.session_key().value().as_ref(), &[0x63; 32]);
    Ok(())
}

/// Renewal in the client realm replaces the primary TGT and its realm entry.
#[test]
fn cached_primary_renewal_replaces_primary_tgt() -> Result<(), TestError> {
    let primary = renewable(Principal::tgt_service("EXAMPLE.COM"))?;
    let (client, _) = renew(primary, None, "EXAMPLE.COM")?;
    let current = client.tgt_session().ok_or("primary missing")?;
    assert_eq!(current.session_key().value().as_ref(), &[0x63; 32]);
    let keyed = client
        .tgt_session_for_realm("EXAMPLE.COM")
        .ok_or("realm entry missing")?;
    assert_eq!(keyed.session_key().value().as_ref(), &[0x63; 32]);
    Ok(())
}

//! `disable_encrypted_timestamp` on the raw configured AS route (FU-SPK-P01).

use core::{error::Error as StdError, time::Duration};
use std::time::SystemTime;

use super::{Error, KdcProtocol, Tokio};
use crate::{
    client::{AsReq, Principal, build_preauthenticated_tgt_as_req, build_tgt_as_req},
    config::Config,
    keytab::EncryptionKey,
};

/// A realm that disables the encrypted timestamp and names no KDC: a request that
/// passes the checks fails at discovery, never on the network.
fn config(disabled: &str) -> Result<Config, Box<dyn StdError>> {
    Ok(Config::parse(&format!(
        "[libdefaults]\ndns_lookup_kdc = false\n[realms]\nTEST.GOKRB5 = {{\ndisable_encrypted_timestamp = {disabled}\n}}\n"
    ))?)
}

/// The AES-256 key the requests are built with.
fn key() -> EncryptionKey {
    EncryptionKey::new(18, vec![0x42; 32])
}

/// A caller-built PA-ENC-TIMESTAMP is refused before discovery for a realm that disables it.
#[tokio::test]
async fn caller_built_timestamp_is_refused_when_disabled() -> Result<(), Box<dyn StdError>> {
    // Given an AS-REQ that carries PA-ENC-TIMESTAMP for a realm that disables it.
    let config = config("true")?;
    let request = build_preauthenticated_tgt_as_req(
        Principal::user("TEST.GOKRB5", "testuser1"),
        AsReq::new(SystemTime::now(), 0x1122_3344),
        &key(),
        None,
    )?;
    // When it goes through the raw configured AS route.
    let outcome = Tokio::new()
        .with_timeout(Duration::from_secs(2))
        .exchange_as_req_with_config(&config, KdcProtocol::Tcp, &request, &key())
        .await;
    // Then it is refused with the typed error naming the realm, as the engine refuses it.
    match outcome {
        Err(Error::EncryptedTimestampDisabled { realm }) => assert_eq!(realm, "TEST.GOKRB5"),
        other => return Err(format!("expected EncryptedTimestampDisabled, got {other:?}").into()),
    }
    Ok(())
}

/// Without the timestamp, or with the relation `false`, the request reaches discovery.
#[tokio::test]
async fn other_requests_reach_discovery() -> Result<(), Box<dyn StdError>> {
    let plain = build_tgt_as_req(
        Principal::user("TEST.GOKRB5", "testuser1"),
        AsReq::new(SystemTime::now(), 0x1122_3344),
    )?;
    let stamped = build_preauthenticated_tgt_as_req(
        Principal::user("TEST.GOKRB5", "testuser1"),
        AsReq::new(SystemTime::now(), 0x1122_3344),
        &key(),
        None,
    )?;
    for (disabled, request) in [("true", &plain), ("false", &stamped)] {
        // Given a request the relation does not refuse.
        let config = config(disabled)?;
        // When it goes through the raw configured AS route.
        let outcome = Tokio::new()
            .with_timeout(Duration::from_secs(2))
            .exchange_as_req_with_config(&config, KdcProtocol::Tcp, request, &key())
            .await;
        // Then it fails only because the realm names no KDC.
        assert!(
            matches!(
                outcome,
                Err(Error::NoKdcEndpoints {
                    realm: _,
                    protocol: _
                })
            ),
            "disable_encrypted_timestamp = {disabled}: {outcome:?}"
        );
    }
    Ok(())
}

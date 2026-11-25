//! Authentication indicators of the MIT KDC on the Rust acceptor (MIT-gss-8).
//!
//! The fixture's KDC asserts the indicator `spake` for a SPAKE login
//! (`kdc.conf.d/30-spake.conf`) and copies a TGT's indicators into an
//! AD-CAMMAC of every ticket for a service with the default authorization
//! data, with a service verifier under the service's key
//! (`src/kdc/kdc_authdata.c:298-336,479-494`). The Rust acceptor verifies that
//! CAMMAC and reports the indicators under `auth-indicators` (MIT
//! `ai_authdata.c`); a login without SPAKE gives a ticket without any.

use core::{error::Error, time::Duration};

use rskrb5_ng::{
    error::Gss,
    gss::{
        Acceptor, AcceptorOptions, CredStore, Credential, CredentialUsage, EstablishedContext,
        InitStep, Initiator, InitiatorOptions, Name, NameType,
    },
    spnego::oid::ObjectIdentifier,
};
use tokio::time::timeout;

use super::support::{MIT_KDC, config, runtime};
use crate::harness;

/// The Rust acceptor's context of a ticket for the indicator service that the
/// SPAKE user obtained under the `[libdefaults]` line `preauth`.
fn accepted(preauth: &str) -> Result<EstablishedContext, Box<dyn Error>> {
    let config = config(preauth)?;
    let service = harness::var("INTEROP_MIT_AUTHIND_SERVICE")?;
    let (kind, host) = service
        .split_once('/')
        .ok_or("the service is service/host")?;
    let target = Name::import(
        format!("{kind}@{host}").as_bytes(),
        NameType::HostbasedService,
    )?;
    let principal = format!(
        "{}@{}",
        harness::var("INTEROP_MIT_SPAKE_USER")?,
        harness::var("INTEROP_MIT_REALM")?
    );
    let user = Name::import(principal.as_bytes(), NameType::Principal)?;
    let password = CredStore::new().with(
        "password",
        &harness::var("INTEROP_MIT_SPAKE_USER_PASSWORD")?,
    )?;
    let mut credential =
        Credential::acquire_cred_from(Some(&user), CredentialUsage::Initiate, &password)?;
    runtime()?.block_on(async {
        timeout(
            Duration::from_secs(30),
            credential.acquire_service_ticket(&target, &config),
        )
        .await
    })??;
    let mut initiator = Initiator::new(target.clone(), InitiatorOptions::new());
    let InitStep::Continue(token) = initiator.init_sec_context(&credential, None)? else {
        return Err("mutual authentication waits for the AP-REP".into());
    };
    let keytab = CredStore::new().with(
        "keytab",
        &format!("FILE:{}", harness::var("INTEROP_MIT_AUTHIND_KEYTAB")?),
    )?;
    let own = Credential::acquire_cred_from(Some(&target), CredentialUsage::Accept, &keytab)?;
    let mut acceptor = Acceptor::new(&own, AcceptorOptions::new())?;
    let context = acceptor.accept_sec_context(&token)?.into_context();
    harness::assert_negotiated_mechanism(
        ObjectIdentifier::krb5().arcs(),
        context.inquire().mechanism().arcs(),
    )?;
    Ok(context)
}

/// A SPAKE login's indicator reaches the Rust acceptor authenticated, through
/// the AD-CAMMAC the MIT KDC put into the service ticket; an
/// encrypted-timestamp login's ticket carries none.
#[test]
fn the_rust_acceptor_reads_the_kdc_issued_auth_indicators() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "the_rust_acceptor_reads_the_kdc_issued_auth_indicators",
        &[MIT_KDC],
    )? {
        return Ok(());
    }
    // SPAKE answers first when the profile names a group (worker-rules C8).
    let spake = accepted(" spake_preauth_groups = edwards25519")?;
    assert!(
        spake
            .source_attributes()
            .iter()
            .any(|name| name == "auth-indicators")
    );
    let attribute = spake.source_attribute("auth-indicators")?;
    assert_eq!(
        attribute.values(),
        [harness::var("INTEROP_MIT_SPAKE_INDICATOR")?.into_bytes()]
    );
    assert!(attribute.authenticated());
    // Without SPAKE the encrypted timestamp answers, which asserts no indicator.
    let plain = accepted(" spake_preauth_groups =")?;
    assert!(matches!(
        plain.source_attribute("auth-indicators"),
        Err(Gss::NameAttributeUnavailable(_))
    ));
    Ok(())
}

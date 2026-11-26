//! Host-based targets named by explicit acquisition (MIT-dns-4, the GSS route).
//!
//! `Name::import` never canonicalizes. `Credential::acquire_host_service_ticket`
//! is the explicit operation: the profile's canonicalization proposes names and
//! the caller's policy approves them, and the name it returns is the target.

use std::{env, fs, path::PathBuf, process, time::SystemTime};

use rskrb5_ng::{
    Config,
    ccache::{file_store::collection, stores::CacheVersion},
    error::{Client as ClientError, Gss},
    gss::{
        CredStore, Credential, CredentialUsage, InitStep, Initiator, InitiatorOptions, Name,
        NameType,
    },
};
use tokio::runtime::Builder;

use super::{
    context::TestError,
    support::{HOST, cache, cached, target, tgt, ticket_for},
};

/// The profile: no DNS, and the suffix `example.com` for one-label hosts.
fn profile() -> Result<Config, TestError> {
    Ok(Config::parse(
        "[libdefaults]\n default_realm = EXAMPLE.COM\n dns_lookup_kdc = false\n\
         dns_lookup_realm = false\n dns_canonicalize_hostname = false\n\
         qualify_shortname = example.com\n[realms]\n EXAMPLE.COM = {\n kdc = 127.0.0.1:1\n }\n",
    )?)
}

/// A credential whose cache holds the client's TGT and a ticket for `HTTP/<HOST>`.
fn credential(label: &str) -> Result<(Credential, PathBuf), TestError> {
    let directory = env::temp_dir().join(format!(
        "gss-host-{label}-{}-{}",
        process::id(),
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_nanos()
    ));
    fs::create_dir_all(&directory)?;
    let name = format!("DIR:{}", directory.join("collection").display());
    collection(&name, CacheVersion::V4)?
        .primary()?
        .replace(&cache(vec![tgt(&[])?, cached(&ticket_for(HOST, &[])?)?]))?;
    let store = CredStore::new().with("ccache", &name)?;
    let credential = Credential::acquire_cred_from(None, CredentialUsage::Initiate, &store)?;
    Ok((credential, directory))
}

/// The explicit operation names the qualified host when the policy approves it,
/// and the initiator built for that name completes its first step.
#[test]
fn gss_host_target_uses_explicit_canonicalization() -> Result<(), TestError> {
    let (mut credential, directory) = credential("approved")?;
    let approve = |_requested: &str, candidate: &str| candidate == HOST;
    let name = Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(credential.acquire_host_service_ticket(("HTTP", "www"), &approve, &profile()?))?;
    assert_eq!(name.display().0, format!("HTTP/{HOST}@EXAMPLE.COM"));
    let mut initiator = Initiator::new(name, InitiatorOptions::new());
    assert!(matches!(
        initiator.init_sec_context(&credential, None)?,
        InitStep::Continue(_) | InitStep::Complete(_)
    ));
    fs::remove_dir_all(&directory)?;
    Ok(())
}

/// A policy that approves nothing leaves the host unnamed, and the plain import
/// of the same host never qualifies it.
#[test]
fn gss_host_target_refuses_an_unapproved_name_and_import_stays_pure() -> Result<(), TestError> {
    let (mut credential, directory) = credential("refused")?;
    let refuse = |_requested: &str, _candidate: &str| false;
    let refused = Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(credential.acquire_host_service_ticket(("HTTP", "www"), &refuse, &profile()?));
    assert!(
        matches!(
            &refused,
            Err(Gss::Client(ClientError::HostNameNotApproved { host })) if host == "www"
        ),
        "{refused:?}"
    );
    let imported = Name::import(b"HTTP@www", NameType::HostbasedService)?;
    assert!(imported.is_hostbased());
    let mut initiator = Initiator::new(target("www")?, InitiatorOptions::new());
    assert!(matches!(
        initiator.init_sec_context(&credential, None),
        Err(Gss::NoCredential(_))
    ));
    fs::remove_dir_all(&directory)?;
    Ok(())
}

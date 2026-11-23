//! Impersonation, proxy credentials and the `verify` credential-store key.
//!
//! MIT 1.22.2 `s4u_gss_glue.c`: `gss_acquire_cred_impersonate_name` makes a
//! credential for a user from the impersonator's `S4U2Self` evidence ticket,
//! and an acceptor whose credential can also initiate composes such a proxy
//! credential from the ticket it accepted (`kg_compose_deleg_cred`,
//! `accept_sec_context.c:943-952`); a proxy credential gets its service tickets
//! by `S4U2Proxy`. The `verify` key (`acquire_cred.c:1298-1320`) verifies
//! password-acquired initial credentials against a keytab and needs a password.
//! The KDC exchanges are proven live in `tests/interop_gss_ext.rs`.

use std::{env, fs, process};

use rskrb5_ng::{
    error::Gss,
    gss::{
        Acceptor, AcceptorOptions, ContextFlags, CredStore, Credential, CredentialUsage, InitStep,
        Initiator, InitiatorOptions, MemoryTransferLedger, Name, NameType, TransferKey,
    },
};

use super::{
    context::{Context as _, TestError},
    support::{AES256_SHA1, HOST, REALM, USER, credential, keytab, target},
};

/// A scratch directory of this test process.
fn scratch(label: &str) -> Result<std::path::PathBuf, TestError> {
    let directory = env::temp_dir().join(format!("gss-ext-{label}-{}", process::id()));
    fs::create_dir_all(&directory)?;
    Ok(directory)
}

/// The service's own name as a Kerberos principal name.
fn service_name() -> Result<Name, TestError> {
    Ok(Name::import(
        format!("HTTP/{HOST}@{REALM}").as_bytes(),
        NameType::Principal,
    )?)
}

/// An acceptor credential of the service that can also initiate (`GSS_C_BOTH`)
/// composes a proxy credential for the client from the ticket it accepts.
#[test]
fn a_both_credential_composes_a_proxy_credential() -> Result<(), TestError> {
    let directory = scratch("both")?;
    let path = directory.join("service.keytab");
    keytab().save(&path)?;
    let file = format!("FILE:{}", path.display());
    let store = CredStore::new()
        .with("client_keytab", &file)?
        .with("keytab", &file)?;
    let both = Credential::acquire_cred_from(Some(&service_name()?), CredentialUsage::Both, &store)?;
    fs::remove_dir_all(&directory)?;
    let client = credential(AES256_SHA1)?;
    let mut init = Initiator::new(target()?, InitiatorOptions::new());
    let InitStep::Continue(token) = init.init_sec_context(&client, None)? else {
        return Err("a mutual initiator waits".into());
    };
    let mut accept = Acceptor::new(&both, AcceptorOptions::new())?;
    let accepted = accept.accept_sec_context(&token)?;
    let context = accepted.context();
    assert!(context.inquire().flags().contains(ContextFlags::DELEG));
    let proxy = context
        .delegated_credential()
        .context("a composed proxy credential")?;
    let inquiry = proxy.inquire();
    assert_eq!(inquiry.usage(), CredentialUsage::Initiate);
    assert_eq!(
        inquiry.name().context("a name")?.principal().components,
        [USER]
    );
    let impersonator = proxy.impersonator().context("an impersonator")?;
    assert_eq!(
        impersonator.principal().components,
        ["HTTP", HOST]
    );
    // An acceptor-only credential composes nothing.
    let only = Credential::from_keytab(keytab());
    let mut plain = Acceptor::new(&only, AcceptorOptions::new())?;
    let mut again = Initiator::new(target()?, InitiatorOptions::new());
    let InitStep::Continue(second) = again.init_sec_context(&client, None)? else {
        return Err("a mutual initiator waits".into());
    };
    let accepted = plain.accept_sec_context(&second)?;
    assert!(accepted.context().delegated_credential().is_none());
    Ok(())
}

/// A proxy credential transfers with its impersonator.
#[test]
fn a_proxy_credential_transfers_with_its_impersonator() -> Result<(), TestError> {
    let directory = scratch("proxy")?;
    let path = directory.join("service.keytab");
    keytab().save(&path)?;
    let file = format!("FILE:{}", path.display());
    let store = CredStore::new()
        .with("client_keytab", &file)?
        .with("keytab", &file)?;
    let both = Credential::acquire_cred_from(Some(&service_name()?), CredentialUsage::Both, &store)?;
    fs::remove_dir_all(&directory)?;
    let client = credential(AES256_SHA1)?;
    let mut init = Initiator::new(target()?, InitiatorOptions::new());
    let InitStep::Continue(token) = init.init_sec_context(&client, None)? else {
        return Err("a mutual initiator waits".into());
    };
    let mut accept = Acceptor::new(&both, AcceptorOptions::new())?;
    let mut context = accept.accept_sec_context(&token)?.into_context();
    let proxy = context
        .take_delegated_credential()
        .context("a proxy credential")?;
    let key = TransferKey::new([7; 32]);
    let mut ledger = MemoryTransferLedger::new();
    let imported = Credential::import(&proxy.export(&key)?, &key, &mut ledger)?;
    assert_eq!(
        imported
            .impersonator()
            .context("the impersonator survives")?
            .principal()
            .components,
        ["HTTP", HOST]
    );
    Ok(())
}

#[cfg(feature = "tokio")]
/// Only a credential that can initiate impersonates (`kg_is_initiator_cred`,
/// `s4u_gss_glue.c:33-38`), and a certificate name is refused for a credential
/// without the impersonator's keytab; no KDC is reached.
#[test]
fn impersonation_needs_an_initiator_credential() -> Result<(), TestError> {
    let runtime = tokio::runtime::Builder::new_current_thread().build()?;
    let config = rskrb5_ng::config::Config::parse("[libdefaults]\n default_realm = EXAMPLE.COM\n")?;
    let user = Name::import(b"bob@EXAMPLE.COM", NameType::User)?;
    let acceptor = Credential::from_keytab(keytab());
    let refused = runtime.block_on(acceptor.acquire_impersonate_name(&user, &config));
    assert!(matches!(refused, Err(Gss::WrongCredentialUsage(_))));
    let initiator = credential(AES256_SHA1)?;
    let without_keytab = runtime.block_on(initiator.acquire_impersonate_name(&user, &config));
    assert!(without_keytab.is_err());
    Ok(())
}

/// The `verify` key is accepted with a password, refused without one, and
/// given twice is a duplicate.
#[test]
fn the_verify_key_needs_a_password() -> Result<(), TestError> {
    let directory = scratch("verify")?;
    let path = directory.join("host.keytab");
    keytab().save(&path)?;
    let file = format!("FILE:{}", path.display());
    let user = Name::import(b"alice@EXAMPLE.COM", NameType::User)?;
    let with_password = CredStore::new()
        .with("password", "secret")?
        .with("keytab", &file)?
        .with("verify", "")?;
    let acquired = Credential::acquire_cred_from(Some(&user), CredentialUsage::Initiate, &with_password)?;
    assert_eq!(acquired.inquire().usage(), CredentialUsage::Initiate);
    let without = CredStore::new().with("keytab", &file)?.with("verify", "host/x@EXAMPLE.COM")?;
    assert!(matches!(
        Credential::acquire_cred_from(Some(&user), CredentialUsage::Initiate, &without),
        Err(Gss::NoCredential(_))
    ));
    let bad = CredStore::new()
        .with("password", "secret")?
        .with("verify", "not a principal@@")?;
    assert!(Credential::acquire_cred_from(Some(&user), CredentialUsage::Initiate, &bad).is_err());
    assert!(matches!(
        CredStore::new().with("verify", "")?.with("verify", ""),
        Err(Gss::DuplicateCredStoreKey(_))
    ));
    fs::remove_dir_all(&directory)?;
    Ok(())
}

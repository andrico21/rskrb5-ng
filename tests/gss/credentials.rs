//! Credential acquisition and storage.
//!
//! Credential acquisition from explicit stores and `store_cred_into` (MIT
//! `acquire_cred.c:150-215,1150-1370`, `store_cred.c`, `cred_store.c`): the
//! store keys `ccache`, `client_keytab`, `keytab`, `rcache` and `password`.

use std::{
    env, fs,
    path::{Path, PathBuf},
    process,
    time::{SystemTime, UNIX_EPOCH},
};

use rskrb5_ng::{
    ccache::{self, file_store::collection, stores::CacheVersion},
    error::{Gss, Service},
    gss::{
        Acceptor, AcceptorOptions, CredStore, Credential, CredentialUsage, InitStep, Initiator,
        InitiatorOptions, Name, NameType,
    },
    keytab::{EncryptionKey, Entry, Principal as KeytabPrincipal},
};

use super::{
    context::{Context as _, TestError},
    support::{HOST, REALM, cache, cached, keytab, target, ticket_for},
};

/// A fresh scratch directory.
fn scratch(label: &str) -> Result<PathBuf, TestError> {
    let directory = env::temp_dir().join(format!(
        "gss-{label}-{}-{}",
        process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    fs::create_dir_all(&directory)?;
    Ok(directory)
}

/// Unknown and repeated store keys are refused when the store is built.
#[test]
fn store_keys_are_checked() -> Result<(), TestError> {
    // Given a key MIT's krb5 mechanism does not know, it is refused.
    assert!(matches!(
        CredStore::new().with("impersonator", "x"),
        Err(Gss::UnsupportedCredStoreKey(key)) if key == "impersonator"
    ));
    // Given a key twice, the second is refused.
    assert!(matches!(
        CredStore::new().with("keytab", "FILE:/a")?.with("keytab", "FILE:/b"),
        Err(Gss::DuplicateCredStoreKey(key)) if key == "keytab"
    ));
    // The password value never appears in the store's debug output.
    let store = CredStore::new().with("password", "hunter2-canary")?;
    assert!(!format!("{store:?}").contains("hunter2-canary"));
    Ok(())
}

/// An acceptor credential comes from the `keytab` key, an initiator one from
/// the `ccache` key; each refuses the other usage.
#[test]
fn credentials_come_from_the_named_stores() -> Result<(), TestError> {
    let directory = scratch("stores")?;
    let keytab_path = directory.join("service.keytab");
    keytab(&[HOST]).save(&keytab_path)?;
    let cache_path = directory.join("client.ccache");
    cache(vec![cached(&ticket_for(HOST, &[])?)?]).save(&cache_path)?;
    let store = CredStore::new()
        .with("keytab", &format!("FILE:{}", keytab_path.display()))?
        .with("ccache", &format!("FILE:{}", cache_path.display()))?
        .with("rcache", "memory:gss-test")?;
    // Given the store, an acceptor credential and an initiator credential are acquired,
    let acceptor = Credential::acquire_cred_from(None, CredentialUsage::Accept, &store)?;
    let initiator = Credential::acquire_cred_from(None, CredentialUsage::Initiate, &store)?;
    assert_eq!(
        initiator
            .inquire()
            .name()
            .context("the cache's client")?
            .display()
            .0,
        "alice@EXAMPLE.COM"
    );
    assert_eq!(initiator.inquire().usage(), CredentialUsage::Initiate);
    // and they establish a context together.
    let mut init = Initiator::new(target(HOST)?, InitiatorOptions::new());
    let InitStep::Continue(first) = init.init_sec_context(&initiator, None)? else {
        return Err("mutual authentication sends a token and waits".into());
    };
    drop(Acceptor::new(&acceptor, AcceptorOptions::new())?.accept_sec_context(&first)?);
    // Used the wrong way round, each is refused.
    assert!(matches!(
        Acceptor::new(&initiator, AcceptorOptions::new()),
        Err(Gss::WrongCredentialUsage(_))
    ));
    let mut wrong = Initiator::new(target(HOST)?, InitiatorOptions::new());
    assert!(matches!(
        wrong.init_sec_context(&acceptor, None),
        Err(Gss::WrongCredentialUsage(_))
    ));
    fs::remove_dir_all(&directory)?;
    Ok(())
}

/// A desired name must match the cache's client, and an unknown replay cache
/// type is refused.
#[test]
fn desired_names_and_replay_caches_are_checked() -> Result<(), TestError> {
    let directory = scratch("names")?;
    let cache_path = directory.join("client.ccache");
    cache(vec![cached(&ticket_for(HOST, &[])?)?]).save(&cache_path)?;
    let store = CredStore::new().with("ccache", &format!("FILE:{}", cache_path.display()))?;
    // Given a desired name that is not the cache's client, there is no credential.
    let bob = Name::import(b"bob@EXAMPLE.COM", NameType::Principal)?;
    assert!(matches!(
        Credential::acquire_cred_from(Some(&bob), CredentialUsage::Initiate, &store),
        Err(Gss::NoCredential(_))
    ));
    // Given the cache's own client, the credential is acquired.
    let alice = Name::import(b"alice@EXAMPLE.COM", NameType::Principal)?;
    drop(Credential::acquire_cred_from(
        Some(&alice),
        CredentialUsage::Initiate,
        &store,
    )?);
    // Given an `rcache` of an unknown type, there is no replay cache to use.
    let keytab_path = directory.join("service.keytab");
    keytab(&[HOST]).save(&keytab_path)?;
    let unknown = CredStore::new()
        .with("keytab", &format!("FILE:{}", keytab_path.display()))?
        .with("rcache", "bogus:")?;
    assert!(matches!(
        Credential::acquire_cred_from(None, CredentialUsage::Accept, &unknown),
        Err(Gss::UnsupportedReplayCache(_))
    ));
    fs::remove_dir_all(&directory)?;
    Ok(())
}

/// `rcache` names select shared or no replay evidence.
///
/// `file2:<path>` keeps its evidence in a shared file: a second acceptor
/// credential on the same file refuses what the first accepted. `none:` is a
/// deliberate opt-out that accepts a repeat.
#[test]
fn rcache_names_select_shared_or_no_replay_evidence() -> Result<(), TestError> {
    let directory = scratch("rcache")?;
    let keytab_path = directory.join("service.keytab");
    keytab(&[HOST]).save(&keytab_path)?;
    let cache_path = directory.join("client.ccache");
    cache(vec![cached(&ticket_for(HOST, &[])?)?]).save(&cache_path)?;
    let keytab_name = format!("FILE:{}", keytab_path.display());
    let client = CredStore::new().with("ccache", &format!("FILE:{}", cache_path.display()))?;
    let initiator = Credential::acquire_cred_from(None, CredentialUsage::Initiate, &client)?;
    let mut init = Initiator::new(target(HOST)?, InitiatorOptions::new());
    let InitStep::Continue(token) = init.init_sec_context(&initiator, None)? else {
        return Err("mutual authentication sends a token and waits".into());
    };

    // Given two acceptor credentials on one file2 cache, the second refuses the replay.
    let shared = CredStore::new().with("keytab", &keytab_name)?.with(
        "rcache",
        &format!("file2:{}", directory.join("replay.rcache2").display()),
    )?;
    let first = Credential::acquire_cred_from(None, CredentialUsage::Accept, &shared)?;
    let second = Credential::acquire_cred_from(None, CredentialUsage::Accept, &shared)?;
    drop(Acceptor::new(&first, AcceptorOptions::new())?.accept_sec_context(&token)?);
    assert!(matches!(
        Acceptor::new(&second, AcceptorOptions::new())?.accept_sec_context(&token),
        Err(Gss::Service(Service::Replay))
    ));

    // Given `none:`, the opt-out accepts the same token twice.
    let open = CredStore::new()
        .with("keytab", &keytab_name)?
        .with("rcache", "none:")?;
    let unprotected = Credential::acquire_cred_from(None, CredentialUsage::Accept, &open)?;
    drop(Acceptor::new(&unprotected, AcceptorOptions::new())?.accept_sec_context(&token)?);
    drop(Acceptor::new(&unprotected, AcceptorOptions::new())?.accept_sec_context(&token)?);
    fs::remove_dir_all(&directory)?;
    Ok(())
}

/// The `client_keytab` and `password` keys need the desired name.
///
/// They make an initiator credential for it, which acquires its tickets from
/// the KDC when it is used; a client keytab must hold its key (MIT
/// `can_get_initial_creds`, `acquire_cred.c:324-350`).
#[test]
fn keytab_and_password_initiators_need_a_name() -> Result<(), TestError> {
    let directory = scratch("client-keytab")?;
    let keytab_path = directory.join("client.keytab");
    let mut client_keys = keytab(&[]);
    client_keys.entries_mut().push(Entry::new(
        KeytabPrincipal::new("EXAMPLE.COM", 1, ["alice"]),
        0,
        1,
        EncryptionKey::new(18, vec![0x41; 32]),
        1,
    ));
    client_keys.save(&keytab_path)?;
    let alice = Name::import(b"alice@EXAMPLE.COM", NameType::Principal)?;
    for store in [
        CredStore::new().with("client_keytab", &format!("FILE:{}", keytab_path.display()))?,
        CredStore::new().with("password", "not-a-real-password")?,
    ] {
        // Given no desired name, there is nothing to acquire for.
        assert!(matches!(
            Credential::acquire_cred_from(None, CredentialUsage::Initiate, &store),
            Err(Gss::NoCredential(_))
        ));
        // Given the name, the credential names it and holds no ticket yet.
        let credential =
            Credential::acquire_cred_from(Some(&alice), CredentialUsage::Initiate, &store)?;
        assert!(
            credential
                .inquire()
                .name()
                .context("the name")?
                .compare(&alice)
        );
        let mut init = Initiator::new(target(HOST)?, InitiatorOptions::new());
        assert!(matches!(
            init.init_sec_context(&credential, None),
            Err(Gss::NoCredential(_))
        ));
    }
    // A client keytab without the name's key is no credential.
    let service_keys = directory.join("service.keytab");
    keytab(&[HOST]).save(&service_keys)?;
    let wrong =
        CredStore::new().with("client_keytab", &format!("FILE:{}", service_keys.display()))?;
    assert!(matches!(
        Credential::acquire_cred_from(Some(&alice), CredentialUsage::Initiate, &wrong),
        Err(Gss::NoCredential(_))
    ));
    fs::remove_dir_all(&directory)?;
    Ok(())
}

/// A `DIR` collection in `directory`: the primary cache holds alice's ticket,
/// a second cache is bob's (MIT `krb5_cc_new_unique`). Returns its name.
fn two_client_collection(directory: &Path) -> Result<String, TestError> {
    let name = format!("DIR:{}", directory.join("collection").display());
    let caches = collection(&name, CacheVersion::V4)?;
    caches
        .primary()?
        .replace(&cache(vec![cached(&ticket_for(HOST, &[])?)?]))?;
    caches.new_unique()?.initialize(&ccache::Principal::new(
        REALM.to_owned(),
        1,
        vec!["bob".to_owned()],
    ))?;
    Ok(name)
}

/// The display form of a credential's name.
fn display_name(credential: &Credential) -> Result<String, TestError> {
    Ok(credential.inquire().name().context("a name")?.display().0)
}

/// A desired name selects its cache from the named collection (MIT
/// `krb5_cc_cache_match`, `cccursor.c:184-219`) without switching the primary.
#[test]
fn acquire_from_collection_selects_desired_principal() -> Result<(), TestError> {
    let directory = scratch("collection")?;
    let name = two_client_collection(&directory)?;
    let store = CredStore::new().with("ccache", &name)?;
    // Given bob, the collection's second cache is selected.
    let bob = Name::import(b"bob@EXAMPLE.COM", NameType::Principal)?;
    let selected = Credential::acquire_cred_from(Some(&bob), CredentialUsage::Initiate, &store)?;
    assert_eq!(display_name(&selected)?, "bob@EXAMPLE.COM");
    // Given alice, the primary cache, with her ticket.
    let alice = Name::import(b"alice@EXAMPLE.COM", NameType::Principal)?;
    let primary = Credential::acquire_cred_from(Some(&alice), CredentialUsage::Initiate, &store)?;
    assert_eq!(display_name(&primary)?, "alice@EXAMPLE.COM");
    let mut init = Initiator::new(target(HOST)?, InitiatorOptions::new());
    assert!(matches!(
        init.init_sec_context(&primary, None)?,
        InitStep::Continue(_)
    ));
    // Without a desired name, the primary cache; the primary never switched.
    let default = Credential::acquire_cred_from(None, CredentialUsage::Initiate, &store)?;
    assert_eq!(display_name(&default)?, "alice@EXAMPLE.COM");
    let caches = collection(&name, CacheVersion::V4)?;
    assert_eq!(caches.primary()?.load()?.client_name(), "alice");
    fs::remove_dir_all(&directory)?;
    Ok(())
}

/// A desired name no cache of the collection holds has no credential.
///
/// The primary cache's identity is never put in its place; realm and ordered
/// components match exactly; collection failures are returned.
#[test]
fn missing_desired_principal_never_uses_primary() -> Result<(), TestError> {
    let directory = scratch("missing")?;
    let name = two_client_collection(&directory)?;
    let store = CredStore::new().with("ccache", &name)?;
    for missing in [
        "carol@EXAMPLE.COM",
        "bob@OTHER.EXAMPLE",
        "bob/admin@EXAMPLE.COM",
        "ALICE@EXAMPLE.COM",
    ] {
        let desired = Name::import(missing.as_bytes(), NameType::Principal)?;
        assert!(
            matches!(
                Credential::acquire_cred_from(Some(&desired), CredentialUsage::Initiate, &store),
                Err(Gss::NoCredential(_))
            ),
            "{missing}"
        );
    }
    // A collection that cannot be opened is an error, not a missing credential.
    let bob = Name::import(b"bob@EXAMPLE.COM", NameType::Principal)?;
    let broken = CredStore::new().with("ccache", "DIR:")?;
    assert!(matches!(
        Credential::acquire_cred_from(Some(&bob), CredentialUsage::Initiate, &broken),
        Err(Gss::Ccache(_))
    ));
    fs::remove_dir_all(&directory)?;
    Ok(())
}

/// `gss_acquire_cred` with a desired name selects its cache from the default
/// collection (MIT `get_cache_for_name`, `acquire_cred.c:446-500`).
#[cfg(feature = "tokio")]
#[test]
fn default_acquire_selects_desired_principal() -> Result<(), TestError> {
    use rskrb5_ng::config::Config;

    use crate::env::{in_child, run_in_child};

    const TEST_PATH: &str = "tests::credentials::default_acquire_selects_desired_principal";
    if !in_child(TEST_PATH) {
        run_in_child(
            TEST_PATH,
            &[("KRB5CCNAME", None), ("KRB5_CLIENT_KTNAME", None)],
        );
        return Ok(());
    }
    let directory = scratch("default")?;
    let name = two_client_collection(&directory)?;
    // The default client keytab holds no client key, so it cannot stand in.
    let service_keys = directory.join("service.keytab");
    keytab(&[HOST]).save(&service_keys)?;
    let config = Config::parse(&format!(
        "[libdefaults]\n default_realm = {REALM}\n default_ccache_name = {name}\n \
         default_client_keytab_name = FILE:{}\n",
        service_keys.display()
    ))?;
    let bob = Name::import(b"bob@EXAMPLE.COM", NameType::Principal)?;
    let selected = Credential::acquire_cred(Some(&bob), CredentialUsage::Initiate, &config)?;
    assert_eq!(display_name(&selected)?, "bob@EXAMPLE.COM");
    let carol = Name::import(b"carol@EXAMPLE.COM", NameType::Principal)?;
    assert!(matches!(
        Credential::acquire_cred(Some(&carol), CredentialUsage::Initiate, &config),
        Err(Gss::NoCredential(_))
    ));
    let default = Credential::acquire_cred(None, CredentialUsage::Initiate, &config)?;
    assert_eq!(display_name(&default)?, "alice@EXAMPLE.COM");
    assert_eq!(
        collection(&name, CacheVersion::V4)?
            .primary()?
            .load()?
            .client_name(),
        "alice"
    );
    fs::remove_dir_all(&directory)?;
    Ok(())
}

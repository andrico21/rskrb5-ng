//! Cache operations against the in-memory kernel.

use super::{TestError, cache, credential, kernel, now, principal, ring_of};
use crate::ccache::{
    CCache, Error,
    keyring::{
        backend::{Kind, Ring},
        index::encode as primary_payload,
    },
};

/// Resolving creates the collection and its primary-name key, once, and names
/// the primary cache (`cc_keyring.c:513-535,604-646`).
#[test]
fn resolve_creates_the_collection_and_primary_name() -> Result<(), TestError> {
    let (fake, engine) = kernel();
    let handle = cache(&engine, "process:krb")?;
    assert_eq!(handle.name(), "KEYRING:process:krb:krb", "full name");
    let again = cache(&engine, "process:krb")?;
    assert_eq!(again.name(), handle.name(), "second resolve");
    assert_eq!(
        fake.contents(Ring::Process),
        [(Kind::Keyring, "_krb_krb".to_owned())],
        "one collection keyring in the process keyring"
    );
    let collection = ring_of(&fake, Ring::Process, "_krb_krb")?;
    assert_eq!(
        fake.contents(collection),
        [(Kind::User, "krb_ccache:primary".to_owned())],
        "only the primary-name key; the cache keyring is created by initialize"
    );
    assert_eq!(
        fake.payload(collection, "krb_ccache:primary"),
        Some(primary_payload("krb")),
        "primary payload"
    );
    Ok(())
}

/// The empty collection has the primary cache `tkt` (`cc_keyring.c:604-609`).
#[test]
fn empty_collection_names_tkt() -> Result<(), TestError> {
    let (_fake, engine) = kernel();
    assert_eq!(cache(&engine, "process:")?.name(), "KEYRING:process::tkt");
    Ok(())
}

/// A cache that was never initialized is not found (`KRB5_FCC_NOFILE`).
#[test]
fn uninitialized_cache_is_not_found() -> Result<(), TestError> {
    let (_fake, engine) = kernel();
    let handle = cache(&engine, "process:krb")?;
    assert!(
        matches!(handle.load(), Err(Error::CacheNotFound { name: _ })),
        "load"
    );
    assert!(
        matches!(
            handle.store(credential("krbtgt/EXAMPLE.COM", 0, b"t")),
            Err(Error::CacheNotFound { name: _ })
        ),
        "store"
    );
    assert!(
        matches!(handle.destroy(), Err(Error::CacheNotFound { name: _ })),
        "destroy"
    );
    Ok(())
}

/// The principal key holds the principal in the version 4 file encoding
/// (`cc_keyring.c:1331-1371`).
#[test]
fn initialize_writes_the_principal_key() -> Result<(), TestError> {
    let (fake, engine) = kernel();
    let handle = cache(&engine, "process:krb")?;
    handle.initialize(&principal("alice"))?;
    let collection = ring_of(&fake, Ring::Process, "_krb_krb")?;
    let ring = ring_of(&fake, collection, "krb")?;
    let mut expected = vec![0, 0, 0, 1, 0, 0, 0, 1];
    expected.extend_from_slice(&[0, 0, 0, 11]);
    expected.extend_from_slice(b"EXAMPLE.COM");
    expected.extend_from_slice(&[0, 0, 0, 5]);
    expected.extend_from_slice(b"alice");
    assert_eq!(
        fake.payload(ring, "__krb5_princ__"),
        Some(expected),
        "principal bytes"
    );
    assert_eq!(
        handle.load()?.default_principal(),
        &principal("alice"),
        "loaded"
    );
    Ok(())
}

/// A credential is one key named by its server, in the version 4 encoding, of
/// type `big_key` (`cc_keyring.c:112-123,725-745`); the key and the cache expire
/// with the credential.
#[test]
fn store_adds_one_key_per_credential() -> Result<(), TestError> {
    let (fake, engine) = kernel();
    let handle = cache(&engine, "process:krb")?;
    handle.initialize(&principal("alice"))?;
    let end = now().saturating_add(3600);
    handle.store(credential("krbtgt/EXAMPLE.COM", end, b"ticket"))?;
    let collection = ring_of(&fake, Ring::Process, "_krb_krb")?;
    let ring = ring_of(&fake, collection, "krb")?;
    assert_eq!(
        fake.contents(ring),
        [
            (Kind::User, "__krb5_princ__".to_owned()),
            (Kind::BigKey, "krbtgt/EXAMPLE.COM@EXAMPLE.COM".to_owned())
        ],
        "keys"
    );
    let file = {
        let mut loaded = CCache::new(principal("alice"));
        loaded
            .credentials_mut()
            .push(credential("krbtgt/EXAMPLE.COM", end, b"ticket"));
        loaded.to_bytes()?
    };
    let principal_length = 4 + 4 + 4 + 11 + 4 + 5;
    assert_eq!(
        fake.payload(ring, "krbtgt/EXAMPLE.COM@EXAMPLE.COM")
            .as_deref(),
        file.get(2 + 2 + principal_length..),
        "the payload is the credential of a version 4 file"
    );
    let remaining = fake
        .timeout(ring, Kind::BigKey, "krbtgt/EXAMPLE.COM@EXAMPLE.COM")
        .ok_or("no key timeout")?;
    assert!(
        (3590..=3600).contains(&remaining),
        "key timeout {remaining}"
    );
    let cache_timeout = fake
        .timeout(collection, Kind::Keyring, "krb")
        .ok_or("no cache timeout")?;
    assert!(
        (3590..=3600).contains(&cache_timeout),
        "cache timeout {cache_timeout}"
    );
    let loaded = handle.load()?;
    assert_eq!(loaded.credentials().len(), 1, "credentials");
    assert_eq!(
        loaded
            .credentials()
            .first()
            .map(|item| item.ticket().to_vec()),
        Some(b"ticket".to_vec())
    );
    Ok(())
}

/// A credential for the same server replaces the key; an expired credential
/// leaves its key without a timeout and the cache expiring in a second
/// (`cc_keyring.c:340-381,1349-1357`).
#[test]
fn store_replaces_by_server_and_expires_stale_caches() -> Result<(), TestError> {
    let (fake, engine) = kernel();
    let handle = cache(&engine, "process:krb")?;
    handle.initialize(&principal("alice"))?;
    handle.store(credential("host/a", 1, b"old"))?;
    handle.store(credential("host/a", 1, b"new"))?;
    let loaded = handle.load()?;
    assert_eq!(loaded.credentials().len(), 1, "one credential");
    assert_eq!(
        loaded
            .credentials()
            .first()
            .map(|item| item.ticket().to_vec()),
        Some(b"new".to_vec())
    );
    let collection = ring_of(&fake, Ring::Process, "_krb_krb")?;
    assert_eq!(
        fake.timeout(collection, Kind::Keyring, "krb"),
        Some(1),
        "expired cache lingers one second"
    );
    Ok(())
}

/// Removing a server unlinks its keys and keeps configuration entries.
#[test]
fn remove_unlinks_matching_credentials() -> Result<(), TestError> {
    let (_fake, engine) = kernel();
    let handle = cache(&engine, "process:krb")?;
    handle.initialize(&principal("alice"))?;
    handle.store(credential("host/a", 0, b"a"))?;
    handle.store(credential("host/b", 0, b"b"))?;
    handle.set_config("fast_avail", None, zeroize::Zeroizing::new(b"yes".to_vec()))?;
    assert_eq!(handle.remove(&principal("host/a"))?, 1, "removed");
    assert_eq!(handle.remove(&principal("host/a"))?, 0, "nothing left");
    let loaded = handle.load()?;
    assert_eq!(
        loaded.credentials().len(),
        2,
        "host/b and the configuration entry"
    );
    assert!(
        handle.get_config("fast_avail", None)?.is_some(),
        "configuration entry kept"
    );
    Ok(())
}

/// Initializing again empties the cache; destroying removes it from the
/// collection (`cc_keyring.c:442-476,517-541`).
#[test]
fn initialize_clears_and_destroy_unlinks() -> Result<(), TestError> {
    let (fake, engine) = kernel();
    let handle = cache(&engine, "process:krb")?;
    handle.initialize(&principal("alice"))?;
    handle.store(credential("host/a", 0, b"a"))?;
    handle.initialize(&principal("bob"))?;
    let loaded = handle.load()?;
    assert!(loaded.credentials().is_empty(), "cleared");
    assert_eq!(
        loaded.default_principal(),
        &principal("bob"),
        "new principal"
    );
    handle.destroy()?;
    assert!(
        matches!(handle.load(), Err(Error::CacheNotFound { name: _ })),
        "gone"
    );
    let collection = ring_of(&fake, Ring::Process, "_krb_krb")?;
    assert_eq!(
        fake.contents(collection),
        [(Kind::User, "krb_ccache:primary".to_owned())],
        "unlinked from the collection"
    );
    Ok(())
}

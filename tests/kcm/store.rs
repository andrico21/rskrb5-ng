//! The store against a stateful fake daemon: round trips, replacement,
//! removal, fallbacks for daemons without `REPLACE` or `GET_CRED_LIST`, and
//! collections.

use std::fs;

use rskrb5_ng::{
    ccache::{
        CCache, Credential, CredentialTimes, EncryptionKey, HeaderField, Principal,
        file_store::{self, FileStore},
        kcm::Store,
        stores::{self, CacheVersion, CredentialStore as _},
    },
    error::Ccache as CcacheError,
};
use zeroize::Zeroizing;

use super::{
    fake::{Fake, Features},
    mock::TestError,
    transport,
};

/// A daemon with every opcode.
const FULL: Features = Features {
    replace: true,
    cred_list: true,
};

/// A principal of `TEST.RSKRB5`.
fn principal(name: &str) -> Principal {
    Principal::new("TEST.RSKRB5", 1, vec![name.to_owned()])
}

/// A credential of `client` for the service `service`, tagged by `tag`.
fn credential(client: &Principal, service: &str, tag: u8) -> Credential {
    let mut times = CredentialTimes::default();
    times.auth_time = 1000;
    times.end_time = 2_000_000_000;
    Credential::new(
        client.clone(),
        Principal::new(
            "TEST.RSKRB5",
            1,
            vec![service.to_owned(), "TEST.RSKRB5".to_owned()],
        ),
        EncryptionKey::new(18, vec![tag; 32]),
        times,
        [0x40, 0, 0, 0],
        vec![tag; 24].into(),
    )
}

/// A store for `fake`.
fn store(fake: &Fake) -> Result<Store, TestError> {
    transport::store(fake.path())
}

/// Initialize, store, load, replace, destroy.
#[test]
fn a_cache_round_trips_through_the_daemon() -> Result<(), TestError> {
    let fake = Fake::start(FULL)?;
    let cache = store(&fake)?.resolve("0:1")?;
    let alice = principal("alice");
    assert!(matches!(cache.load(), Err(CcacheError::CacheNotFound { name }) if name == "KCM:0:1"));
    cache.initialize(&alice)?;
    cache.store(credential(&alice, "krbtgt", 1))?;
    cache.store(credential(&alice, "host", 2))?;
    let loaded = cache.load()?;
    assert_eq!(loaded.default_principal(), &alice);
    assert_eq!(loaded.credentials().len(), 2);
    assert_eq!(
        loaded.credentials().first(),
        Some(&credential(&alice, "krbtgt", 1))
    );
    cache.set_config("fast_avail", None, Zeroizing::new(b"yes".to_vec()))?;
    assert_eq!(
        cache
            .get_config("fast_avail", None)?
            .as_deref()
            .map(Vec::as_slice),
        Some(&b"yes"[..])
    );
    let bob = principal("bob");
    cache.replace(&CCache::new(bob.clone()))?;
    assert_eq!(cache.load()?.default_principal(), &bob);
    cache.destroy()?;
    assert!(matches!(
        cache.destroy(),
        Err(CcacheError::CacheNotFound { name: _ })
    ));
    assert!(matches!(
        cache.store(credential(&alice, "krbtgt", 1)),
        Err(CcacheError::CacheNotFound { name: _ })
    ));
    Ok(())
}

/// A credential for the same client and server replaces the old one in one
/// `REPLACE`; a new one is a `STORE`.
#[test]
fn storing_for_the_same_server_replaces_it() -> Result<(), TestError> {
    let fake = Fake::start(FULL)?;
    let cache = store(&fake)?.resolve("0:1")?;
    let alice = principal("alice");
    cache.initialize(&alice)?;
    cache.store(credential(&alice, "krbtgt", 1))?;
    cache.store(credential(&alice, "krbtgt", 9))?;
    let loaded = cache.load()?;
    assert_eq!(loaded.credentials(), [credential(&alice, "krbtgt", 9)]);
    let seen = fake.seen();
    assert_eq!(seen.iter().filter(|opcode| **opcode == 6).count(), 1);
    assert_eq!(seen.iter().filter(|opcode| **opcode == 13_002).count(), 1);
    Ok(())
}

/// Without `REPLACE` (SSSD), a replacement is `INITIALIZE` and `STORE`.
#[test]
fn a_daemon_without_replace_gets_initialize_and_store() -> Result<(), TestError> {
    let fake = Fake::start(Features {
        replace: false,
        cred_list: true,
    })?;
    let cache = store(&fake)?.resolve("0:1")?;
    let alice = principal("alice");
    cache.initialize(&alice)?;
    cache.store(credential(&alice, "krbtgt", 1))?;
    cache.store(credential(&alice, "host", 2))?;
    assert_eq!(
        cache.remove(&Principal::new(
            "TEST.RSKRB5",
            2,
            vec!["host".into(), "TEST.RSKRB5".into()]
        ))?,
        1
    );
    assert_eq!(
        cache.load()?.credentials(),
        [credential(&alice, "krbtgt", 1)]
    );
    assert!(fake.seen().contains(&13_002));
    Ok(())
}

/// Removal keeps configuration entries, counts what it removed, and sends
/// nothing when nothing matched.
#[test]
fn removal_counts_and_keeps_configuration_entries() -> Result<(), TestError> {
    let fake = Fake::start(FULL)?;
    let cache = store(&fake)?.resolve("0:1")?;
    let alice = principal("alice");
    cache.initialize(&alice)?;
    cache.store(credential(&alice, "krbtgt", 1))?;
    cache.set_config("pa_type", None, Zeroizing::new(b"2".to_vec()))?;
    let server = Principal::new(
        "TEST.RSKRB5",
        2,
        vec!["krbtgt".into(), "TEST.RSKRB5".into()],
    );
    assert_eq!(cache.remove(&server)?, 1);
    assert_eq!(cache.remove(&server)?, 0);
    assert_eq!(cache.load()?.config_entries().len(), 1);
    Ok(())
}

/// A daemon without `GET_CRED_LIST` is read credential by credential.
#[test]
fn a_daemon_without_a_credential_list_is_read_by_uuid() -> Result<(), TestError> {
    let fake = Fake::start(Features {
        replace: true,
        cred_list: false,
    })?;
    let cache = store(&fake)?.resolve("0:1")?;
    let alice = principal("alice");
    cache.initialize(&alice)?;
    cache.store(credential(&alice, "krbtgt", 1))?;
    cache.store(credential(&alice, "host", 2))?;
    assert_eq!(cache.load()?.credentials().len(), 2);
    let seen = fake.seen();
    assert!(seen.contains(&9), "{seen:?}");
    // One credential at the second store, two at the final load.
    assert_eq!(
        seen.iter().filter(|opcode| **opcode == 10).count(),
        3,
        "{seen:?}"
    );
    Ok(())
}

/// The KDC offset of a cache survives a replacement and an empty one adds no header.
#[test]
fn the_kdc_offset_travels_in_the_header() -> Result<(), TestError> {
    let fake = Fake::start(FULL)?;
    let cache = store(&fake)?.resolve("0:1")?;
    let mut source = CCache::new(principal("alice"));
    cache.replace(&source)?;
    assert_eq!(cache.load()?.header().fields, []);
    source
        .header_mut()
        .fields
        .push(HeaderField::new(1, [0_u8, 0, 0, 7, 0, 0, 0, 0].to_vec())?);
    cache.replace(&source)?;
    assert_eq!(
        cache
            .load()?
            .header()
            .fields
            .first()
            .map(|field| field.value.clone()),
        Some(vec![0_u8, 0, 0, 7, 0, 0, 0, 0])
    );
    Ok(())
}

/// Caches list primary first, deleted ones are skipped, switching moves the
/// primary, and a cache of another store is outside the collection.
#[test]
fn a_collection_lists_switches_and_creates() -> Result<(), TestError> {
    let fake = Fake::start(FULL)?;
    let store = store(&fake)?;
    let collection = store.collection("")?;
    assert_eq!(collection.name(), "KCM:");
    assert!(!collection.has_content()?);
    assert_eq!(collection.caches()?.count(), 0);
    let (alice, bob) = (principal("alice"), principal("bob"));
    store.resolve("0:1")?.initialize(&alice)?;
    let fresh = collection.new_unique()?;
    fresh.initialize(&bob)?;
    let names: Vec<String> = collection.caches()?.map(|cache| cache.name()).collect();
    assert_eq!(names.len(), 2);
    assert_eq!(names.first().map(String::as_str), Some("KCM:0:1"));
    assert_eq!(collection.primary()?.name(), "KCM:0:1");
    collection.switch(fresh.as_ref())?;
    assert_eq!(collection.primary()?.name(), fresh.name());
    assert_eq!(
        collection.caches()?.next().map(|cache| cache.name()),
        Some(fresh.name())
    );
    assert_eq!(
        collection.cache_match(&alice)?.map(|cache| cache.name()),
        Some("KCM:0:1".to_owned())
    );
    assert!(collection.has_content()?);
    let outside = FileStore::new(CacheVersion::V4).resolve("/tmp/kcm-outside")?;
    assert!(matches!(
        collection.switch(outside.as_ref()),
        Err(CcacheError::OutsideCollection {
            name: _,
            collection: _
        })
    ));
    fresh.destroy()?;
    assert_eq!(collection.caches()?.count(), 1);
    Ok(())
}

/// `KCM:<uid>:<name>` is a collection of one cache.
#[test]
fn a_named_collection_holds_one_cache() -> Result<(), TestError> {
    let fake = Fake::start(FULL)?;
    let store = store(&fake)?;
    let one = store.collection("0:solo")?;
    assert_eq!(one.name(), "KCM:0:solo");
    assert_eq!(one.caches()?.count(), 0);
    store.resolve("0:solo")?.initialize(&principal("alice"))?;
    assert_eq!(one.caches()?.count(), 1);
    assert_eq!(one.primary()?.name(), "KCM:0:solo");
    let other = store.resolve("0:other")?;
    assert!(matches!(
        one.switch(other.as_ref()),
        Err(CcacheError::OutsideCollection {
            name: _,
            collection: _
        })
    ));
    Ok(())
}

/// Moving between stores goes through the daemon unchanged.
#[test]
fn a_cache_moves_between_a_file_and_the_daemon() -> Result<(), TestError> {
    let fake = Fake::start(FULL)?;
    let kcm = store(&fake)?.resolve("0:1")?;
    let alice = principal("alice");
    let mut source = CCache::new(alice.clone());
    source
        .credentials_mut()
        .push(credential(&alice, "krbtgt", 3));
    let directory = super::mock::scratch("move")?;
    let file = file_store::resolve(
        &format!("FILE:{}", directory.join("cc").display()),
        CacheVersion::V4,
    )?;
    file.replace(&source)?;
    stores::move_cache(file.as_ref(), kcm.as_ref())?;
    assert_eq!(kcm.load()?.credentials(), source.credentials());
    stores::move_cache(kcm.as_ref(), file.as_ref())?;
    assert_eq!(file.load()?.credentials(), source.credentials());
    fs::remove_dir_all(directory)?;
    Ok(())
}

/// A residual the wire cannot carry is a bad name; a `KCM:` name reaches
/// the store through the built-in dispatch.
#[test]
fn names_are_validated_and_dispatched() -> Result<(), TestError> {
    let store = Store::default();
    assert!(matches!(
        store.resolve("0:a\0b"),
        Err(CcacheError::InvalidCacheName)
    ));
    assert!(matches!(
        store.resolve(&"x".repeat(5000)),
        Err(CcacheError::InvalidCacheName)
    ));
    assert_eq!(
        file_store::resolve("KCM:1000:work", CacheVersion::V4)?.name(),
        "KCM:1000:work"
    );
    assert_eq!(
        file_store::collection("kcm:1000", CacheVersion::V4)?.name(),
        "KCM:1000"
    );
    assert_eq!(store.cache_type(), "KCM");
    Ok(())
}

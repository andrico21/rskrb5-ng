//! The KCM store against the in-memory KCM server.

use rskrb5_ng::{
    ccache::{CCache, Credential, CredentialTimes, EncryptionKey, Principal},
    error::Ccache as Error,
};

use super::{Exchange, Kcm};
use crate::{Secret, error::Platform, kcm_fixture::Fixture};

/// A principal of `EXAMPLE.ORG`.
fn principal(components: &[&str]) -> Principal {
    let parts = components.iter().map(|part| (*part).to_owned()).collect();
    Principal::new("EXAMPLE.ORG", 1, parts)
}

/// A credential of alice for `server`.
fn credential(server: &[&str]) -> Credential {
    let mut times = CredentialTimes::default();
    times.end_time = 2_000_000_000;
    Credential::new(
        principal(&["alice"]),
        principal(server),
        EncryptionKey::new(18, vec![9; 32]),
        times,
        [0x40, 0, 0, 0],
        vec![0x61, 0x01, 0x00].into(),
    )
}

/// Initialize, store, load, remove and destroy round-trip through KCM.
#[test]
fn cache_operations_round_trip() -> Result<(), Error> {
    // Given a KCM server and the primary cache.
    let kcm = Kcm::new(Fixture::default());
    let cache = kcm.resolve("")?;
    assert_eq!(cache.name(), "KCM:fixture");
    assert!(
        matches!(cache.load(), Err(Error::CacheNotFound { name: _ })),
        "absent"
    );
    // When it is initialized and given two credentials, then one is removed.
    cache.initialize(&principal(&["alice"]))?;
    cache.store(credential(&["krbtgt", "EXAMPLE.ORG"]))?;
    cache.store(credential(&["HTTP", "web"]))?;
    let loaded = cache.load()?;
    let removed = cache.remove(&principal(&["HTTP", "web"]))?;
    let none = cache.remove(&principal(&["HTTP", "other"]))?;
    let after = cache.load()?;
    cache.destroy()?;
    // Then every step reads back and the destroyed cache is gone.
    assert_eq!(loaded.default_principal(), &principal(&["alice"]));
    assert_eq!(
        loaded.credentials(),
        [
            credential(&["krbtgt", "EXAMPLE.ORG"]),
            credential(&["HTTP", "web"])
        ]
    );
    assert_eq!((removed, none), (1, 0));
    assert_eq!(
        after.credentials(),
        [credential(&["krbtgt", "EXAMPLE.ORG"])]
    );
    assert!(
        matches!(cache.load(), Err(Error::CacheNotFound { name: _ })),
        "destroyed"
    );
    assert!(
        matches!(cache.destroy(), Err(Error::CacheNotFound { name: _ })),
        "twice"
    );
    Ok(())
}

/// Replace rewrites the principal and the credentials.
#[test]
fn replace_rewrites_the_cache() -> Result<(), Error> {
    // Given a cache holding one credential and a replacement.
    let kcm = Kcm::new(Fixture::default());
    let cache = kcm.resolve("work")?;
    cache.initialize(&principal(&["bob"]))?;
    cache.store(credential(&["HTTP", "old"]))?;
    let mut replacement = CCache::new(principal(&["alice"]));
    replacement
        .credentials_mut()
        .push(credential(&["HTTP", "web"]));
    // When the cache is replaced.
    cache.replace(&replacement)?;
    // Then it holds exactly the replacement.
    let loaded = cache.load()?;
    assert_eq!(loaded.default_principal(), &principal(&["alice"]));
    assert_eq!(loaded.credentials(), [credential(&["HTTP", "web"])]);
    Ok(())
}

/// The collection lists the primary first, switches and creates caches.
#[test]
fn collection_switch_and_new_unique() -> Result<(), Error> {
    // Given a server with the primary cache initialized.
    let kcm = Kcm::new(Fixture::default());
    kcm.resolve("")?.initialize(&principal(&["alice"]))?;
    let collection = kcm.collection();
    // When a unique cache is created and made primary.
    let fresh = collection.new_unique()?;
    fresh.initialize(&principal(&["bob"]))?;
    let before: Vec<String> = collection.caches()?.map(|cache| cache.name()).collect();
    collection.switch(fresh.as_ref())?;
    // Then the listing and the primary follow, and foreign caches are refused.
    assert_eq!(before.first().map(String::as_str), Some("KCM:fixture"));
    assert!(before.contains(&fresh.name()), "{before:?}");
    assert_eq!(collection.primary()?.name(), fresh.name());
    assert_eq!(
        collection.caches()?.next().map(|cache| cache.name()),
        Some(fresh.name())
    );
    let foreign = kcm.resolve("x")?;
    assert!(
        collection.switch(foreign.as_ref()).is_ok(),
        "KCM names switch"
    );
    assert!(
        collection.cache_match(&principal(&["bob"]))?.is_some(),
        "match"
    );
    Ok(())
}

/// A server that answers every request with fixed bytes.
#[derive(Debug)]
struct Canned(&'static [u8]);

impl Exchange for Canned {
    fn call(&self, _request: &[u8]) -> Result<Secret, Platform> {
        Ok(Secret::from(self.0.to_vec()))
    }
}

/// Malformed replies and server errors are typed failures.
#[test]
fn malformed_replies_are_refused() -> Result<(), Error> {
    // Given servers with a short reply, an unterminated name and an error status.
    let short = Kcm::new(Canned(&[0, 0]));
    let unterminated = Kcm::new(Canned(&[0, 0, 0, 0, b'x']));
    let failing = Kcm::new(Canned(&[0x96, 0xc7, 0x3a, 0xc4]));
    // When they are used.
    // Then each failure is typed.
    for result in [short.resolve(""), unterminated.resolve("")] {
        let error = result.err().ok_or(Error::InvalidCacheName)?;
        assert!(
            matches!(&error, Error::Io(io) if io.get_ref().and_then(|inner| inner.downcast_ref::<Platform>()).is_some_and(|platform| matches!(platform, Platform::MalformedReply { cache_type: _, reason: _ }))),
            "{error}"
        );
    }
    let error = failing
        .resolve("c")?
        .load()
        .err()
        .ok_or(Error::InvalidCacheName)?;
    assert!(
        matches!(&error, Error::Io(io) if io.get_ref().and_then(|inner| inner.downcast_ref::<Platform>()) == Some(&Platform::Kcm { code: -1_765_328_188_i32 })),
        "{error}"
    );
    let empty = Kcm::new(Canned(&[0, 0, 0, 0])).resolve("c")?.load();
    assert!(
        matches!(empty, Err(Error::CacheNotFound { name: _ })),
        "empty principal"
    );
    Ok(())
}

//! The legacy anchor, an old kernel and the KDC time offsets.

use super::{TestError, cache, credential, kernel, principal, ring_of};
use crate::ccache::{
    CCache, Error, HeaderField,
    keyring::backend::{Kind, Ring},
};

/// The legacy cache is visible to old code.
///
/// It is linked into the session keyring, holds `user` keys and no time
/// offsets, and destroy unlinks it again (`cc_keyring.c:325-350,442-476`).
#[test]
fn legacy_cache_is_visible_to_old_code() -> Result<(), TestError> {
    let (fake, engine) = kernel();
    fake.share_session();
    let handle = cache(&engine, "login")?;
    assert_eq!(handle.name(), "KEYRING:legacy:login:login", "legacy name");
    handle.initialize(&principal("alice"))?;
    handle.store(credential("host/a", 0, b"a"))?;
    assert_eq!(
        fake.contents(Ring::UserSession),
        [
            (Kind::Keyring, "_krb_login".to_owned()),
            (Kind::Keyring, "login".to_owned())
        ],
        "the collection and the cache are in the session anchor"
    );
    let ring = ring_of(&fake, Ring::UserSession, "login")?;
    assert!(
        fake.contents(ring)
            .contains(&(Kind::User, "host/a@EXAMPLE.COM".to_owned())),
        "legacy credentials are user keys"
    );
    let mut with_offset = handle.load()?;
    with_offset
        .header_mut()
        .fields
        .push(HeaderField::new(1, vec![0; 8])?);
    handle.replace(&with_offset)?;
    assert!(
        !fake
            .contents(ring)
            .iter()
            .any(|(_, name)| name == "__krb5_time_offsets__"),
        "no time offsets in a legacy cache"
    );
    handle.destroy()?;
    assert_eq!(
        fake.contents(Ring::UserSession),
        [(Kind::Keyring, "_krb_login".to_owned())],
        "the session link is gone"
    );
    Ok(())
}

/// A cache of an old kernel without `big_key` is stored in user keys.
#[test]
fn old_kernel_falls_back_to_user_keys() -> Result<(), TestError> {
    let (fake, engine) = kernel();
    fake.old_kernel();
    let handle = cache(&engine, "process:krb")?;
    handle.initialize(&principal("alice"))?;
    handle.store(credential("host/a", 0, b"a"))?;
    let collection = ring_of(&fake, Ring::Process, "_krb_krb")?;
    let ring = ring_of(&fake, collection, "krb")?;
    assert!(
        fake.contents(ring)
            .contains(&(Kind::User, "host/a@EXAMPLE.COM".to_owned())),
        "user key"
    );
    Ok(())
}

/// The old legacy cache in the session keyring joins a new legacy collection
/// (`cc_keyring.c:611-621`).
#[test]
fn legacy_collection_adopts_the_old_cache() -> Result<(), TestError> {
    use crate::ccache::keyring::backend::Backend as _;
    let (fake, engine) = kernel();
    let _planted = fake.add(Ring::Session, Kind::Keyring, "login", &[])?;
    let handle = cache(&engine, "login")?;
    let collection = ring_of(&fake, Ring::Session, "_krb_login")?;
    assert!(
        fake.contents(collection)
            .contains(&(Kind::Keyring, "login".to_owned())),
        "linked into the collection"
    );
    assert!(
        matches!(handle.load(), Err(Error::CacheNotFound { name: _ })),
        "still without a principal"
    );
    Ok(())
}

/// The KDC time offsets travel in a key of their own (`cc_keyring.c:1397-1414`).
#[test]
fn replace_keeps_the_time_offsets() -> Result<(), TestError> {
    let (fake, engine) = kernel();
    let handle = cache(&engine, "process:krb")?;
    let mut offsets = CCache::new(principal("alice"));
    offsets
        .header_mut()
        .fields
        .push(HeaderField::new(1, vec![0, 0, 0, 5, 0, 0, 0, 9])?);
    offsets
        .credentials_mut()
        .push(credential("host/a", 0, b"a"));
    handle.replace(&offsets)?;
    let collection = ring_of(&fake, Ring::Process, "_krb_krb")?;
    let ring = ring_of(&fake, collection, "krb")?;
    assert_eq!(
        fake.payload(ring, "__krb5_time_offsets__"),
        Some(vec![0, 0, 0, 5, 0, 0, 0, 9]),
        "offsets key"
    );
    let loaded = handle.load()?;
    assert_eq!(loaded.header(), offsets.header(), "header round trip");
    assert_eq!(loaded.credentials().len(), 1, "credentials");
    Ok(())
}

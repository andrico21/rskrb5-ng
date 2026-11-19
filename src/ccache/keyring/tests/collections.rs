//! Anchors, collections, primary switching and unique caches.

use super::{TestError, cache, collection, kernel, principal};
use crate::ccache::{
    Error,
    keyring::{
        Fault, KernelError,
        backend::{Backend as _, Kind, Ring},
        fake::Fake,
    },
};

/// The names of the keyrings `ring` links.
fn keyrings(fake: &Fake, ring: Ring) -> Vec<String> {
    fake.contents(ring)
        .into_iter()
        .filter(|(kind, _)| *kind == Kind::Keyring)
        .map(|(_, name)| name)
        .collect()
}

/// Each anchor puts the collection keyring where MIT does
/// (`cc_keyring.c:476-523`): the user and persistent anchors also link it from
/// the process keyring to keep possession rights.
#[test]
fn anchors_place_the_collection() -> Result<(), TestError> {
    let (fake, engine) = kernel();
    for residual in [
        "process:a",
        "thread:b",
        "user:c",
        "session:d",
        "persistent:1000",
        "persistent:",
    ] {
        drop(cache(&engine, residual)?);
    }
    assert!(
        keyrings(&fake, Ring::Process).contains(&"_krb_a".to_owned()),
        "process"
    );
    assert_eq!(keyrings(&fake, Ring::Thread), ["_krb_b"], "thread");
    assert_eq!(keyrings(&fake, Ring::User), ["_krb_c"], "user");
    assert!(
        keyrings(&fake, Ring::Process).contains(&"_krb_c".to_owned()),
        "user: possession link"
    );
    assert!(
        keyrings(&fake, Ring::Session).contains(&"_krb_d".to_owned()),
        "session"
    );
    let persistent = Ring::Key(fake.persistent(None)?);
    assert_eq!(
        keyrings(&fake, persistent),
        ["_krb"],
        "persistent: one keyring, one per user"
    );
    assert!(
        keyrings(&fake, Ring::Process).contains(&"_krb".to_owned()),
        "persistent: possession link"
    );
    Ok(())
}

/// The session anchor writes the user session keyring when the process has
/// no session of its own (`cc_keyring.c:197-207`).
#[test]
fn session_anchor_avoids_creating_a_private_session() -> Result<(), TestError> {
    let (fake, engine) = kernel();
    fake.share_session();
    drop(cache(&engine, "session:x")?);
    assert_eq!(keyrings(&fake, Ring::UserSession), ["_krb_x"]);
    Ok(())
}

/// The persistent keyring of another user is refused by the kernel, and a
/// name that is not a user id is MIT `KRB5_KCC_INVALID_UID`
/// (`cc_keyring.c:456-473`).
#[test]
fn persistent_keyring_of_another_user_is_refused() -> Result<(), TestError> {
    let (_fake, engine) = kernel();
    let refused = cache(&engine, "persistent:2000").err().ok_or("opened")?;
    assert!(
        matches!(
            refused,
            Error::Keyring(Fault::Kernel {
                operation: "keyctl_get_persistent",
                error: KernelError::PermissionDenied,
            })
        ),
        "another user"
    );
    for text in [
        "persistent:abc",
        "persistent:-1",
        "persistent:+5",
        "persistent:99999999999",
    ] {
        assert!(
            matches!(cache(&engine, text), Err(Error::Keyring(Fault::InvalidUid))),
            "{text}"
        );
    }
    Ok(())
}

/// Without a persistent keyring the user keyring serves the caller's own id
/// and no other (`cc_keyring.c:182-195`).
#[test]
fn persistent_keyring_falls_back_to_the_user_keyring() -> Result<(), TestError> {
    let (fake, engine) = kernel();
    fake.old_kernel();
    drop(cache(&engine, "persistent:")?);
    drop(cache(&engine, "persistent:1000")?);
    assert_eq!(
        keyrings(&fake, Ring::User),
        ["_krb"],
        "the caller's user keyring"
    );
    assert!(
        matches!(
            cache(&engine, "persistent:2000"),
            Err(Error::Keyring(Fault::InvalidUid))
        ),
        "another user"
    );
    Ok(())
}

/// A new cache is an empty keyring with the name `krb_ccache_` and eight
/// letters or digits, uninitialized until it has a principal
/// (`cc_keyring.c:575-640`).
#[test]
fn new_unique_reserves_a_name() -> Result<(), TestError> {
    let (fake, engine) = kernel();
    let collection = collection(&engine, "process:krb")?;
    let first = collection.new_unique()?;
    let second = collection.new_unique()?;
    assert_ne!(first.name(), second.name(), "distinct names");
    let name = first.name();
    let subsidiary = name
        .strip_prefix("KEYRING:process:krb:krb_ccache_")
        .ok_or("name")?;
    assert_eq!(subsidiary.len(), 8, "random part");
    assert!(
        subsidiary.bytes().all(|byte| byte.is_ascii_alphanumeric()),
        "alphanumeric"
    );
    assert!(
        matches!(first.load(), Err(Error::CacheNotFound { name: _ })),
        "uninitialized"
    );
    first.initialize(&principal("alice"))?;
    assert_eq!(first.load()?.default_principal(), &principal("alice"));
    assert_eq!(
        keyrings(&fake, Ring::Process),
        ["_krb_krb"],
        "nothing leaked"
    );
    Ok(())
}

/// The primary cache comes first; the other cache keyrings follow and keys
/// that are not keyrings are skipped (`krcc_ptcursor_next`).
#[test]
fn caches_list_the_primary_first() -> Result<(), TestError> {
    let (_fake, engine) = kernel();
    let collection = collection(&engine, "process:krb")?;
    assert_eq!(collection.caches()?.count(), 0, "no cache keyring yet");
    let other = collection.new_unique()?;
    other.initialize(&principal("bob"))?;
    let primary = collection.primary()?;
    primary.initialize(&principal("alice"))?;
    let names: Vec<String> = collection.caches()?.map(|item| item.name()).collect();
    assert_eq!(names, [primary.name(), other.name()], "primary first");
    assert_eq!(collection.name(), "KEYRING:process:krb");
    assert_eq!(
        collection
            .cache_match(&principal("bob"))?
            .map(|item| item.name()),
        Some(other.name()),
        "cache_match"
    );
    assert!(collection.has_content()?, "has content");
    Ok(())
}

/// Switching names another cache primary; a cache of another collection is
/// refused (`krcc_switch_to`).
#[test]
fn switch_changes_the_primary() -> Result<(), TestError> {
    let (_fake, engine) = kernel();
    let collection = collection(&engine, "process:krb")?;
    let other = collection.new_unique()?;
    other.initialize(&principal("bob"))?;
    collection.switch(other.as_ref())?;
    assert_eq!(collection.primary()?.name(), other.name(), "switched");
    assert_eq!(
        cache(&engine, "process:krb")?.name(),
        other.name(),
        "resolve follows the primary"
    );
    let foreign = cache(&engine, "process:elsewhere")?;
    assert!(
        matches!(
            collection.switch(foreign.as_ref()),
            Err(Error::OutsideCollection {
                name: _,
                collection: _
            })
        ),
        "foreign"
    );
    Ok(())
}

/// A residual that names a cache is a collection of that cache, in which a
/// new cache cannot be created (`cc_keyring.c:944-951`).
#[test]
fn subsidiary_residual_is_a_single_cache() -> Result<(), TestError> {
    let (_fake, engine) = kernel();
    let single = collection(&engine, "process:krb:one")?;
    assert_eq!(single.name(), "KEYRING:process:krb:one", "name");
    assert_eq!(single.caches()?.count(), 0, "absent");
    single.primary()?.initialize(&principal("alice"))?;
    assert_eq!(single.caches()?.count(), 1, "present");
    assert!(
        matches!(
            single.new_unique(),
            Err(Error::Keyring(Fault::SubsidiaryCollection))
        ),
        "new cache"
    );
    Ok(())
}

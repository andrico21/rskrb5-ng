//! Lifecycle, collections and failures against the real kernel.

use std::{
    fs,
    io::{self, Write as _},
};

use rskrb5_ng::{
    ccache::{
        file_store,
        keyring::{Fault, KernelError},
        stores::CacheVersion,
    },
    error::Ccache as Error,
};

use crate::support::{TestError, available, credential, open, principal, required, uid};

/// Every anchor stores, loads, removes and destroys a cache by its MIT name.
///
/// The names are fixed so that a repeated local run reuses the collection
/// keyrings, which no API removes, instead of adding to the user's key quota.
#[test]
fn every_anchor_round_trips() -> Result<(), TestError> {
    if !available("every_anchor_round_trips")? {
        return Ok(());
    }
    for anchor in [
        "process",
        "thread",
        "session",
        "user",
        "persistent",
        "legacy",
    ] {
        // A persistent collection is named by a user id; the empty name is the caller's.
        let name = if anchor == "persistent" {
            "persistent:".to_owned()
        } else {
            format!("{anchor}:rskrb5ng-test-{anchor}")
        };
        let cache = open(&name)?;
        cache.initialize(&principal("alice"))?;
        cache.store(credential("krbtgt/EXAMPLE.COM", b"tgt".to_vec()))?;
        cache.store(credential("host/server.example.com", b"service".to_vec()))?;
        let loaded = cache.load()?;
        assert_eq!(
            loaded.default_principal(),
            &principal("alice"),
            "{anchor}: principal"
        );
        assert_eq!(loaded.credentials().len(), 2, "{anchor}: credentials");
        assert_eq!(
            loaded
                .get_entry(&["krbtgt", "EXAMPLE.COM"])
                .map(|item| item.ticket().to_vec()),
            Some(b"tgt".to_vec()),
            "{anchor}: ticket bytes"
        );
        assert_eq!(
            cache.remove(&principal("host/server.example.com"))?,
            1,
            "{anchor}: remove"
        );
        assert_eq!(
            cache.load()?.credentials().len(),
            1,
            "{anchor}: after remove"
        );
        cache.destroy()?;
        assert!(
            matches!(cache.load(), Err(Error::CacheNotFound { name: _ })),
            "{anchor}: destroyed"
        );
    }
    Ok(())
}

/// A collection lists, switches and creates caches in the kernel.
#[test]
fn collection_lists_switches_and_creates() -> Result<(), TestError> {
    if !available("collection_lists_switches_and_creates")? {
        return Ok(());
    }
    let collection =
        file_store::collection("KEYRING:process:rskrb5ng-test-collection", CacheVersion::V4)?;
    let primary = collection.primary()?;
    primary.initialize(&principal("alice"))?;
    let other = collection.new_unique()?;
    other.initialize(&principal("bob"))?;
    let names: Vec<String> = collection.caches()?.map(|item| item.name()).collect();
    assert_eq!(names, [primary.name(), other.name()], "primary first");
    collection.switch(other.as_ref())?;
    assert_eq!(collection.primary()?.name(), other.name(), "switched");
    assert_eq!(
        collection
            .cache_match(&principal("alice"))?
            .map(|item| item.name()),
        Some(primary.name()),
        "cache_match"
    );
    other.destroy()?;
    primary.destroy()?;
    Ok(())
}

/// The persistent keyring of another user is refused: `EPERM` from the
/// kernel, typed; a kernel without persistent keyrings has none to open, which
/// is an invalid user id for any user but the caller.
#[test]
fn another_users_persistent_keyring_is_refused() -> Result<(), TestError> {
    if !available("another_users_persistent_keyring_is_refused")? {
        return Ok(());
    }
    let own = uid()?;
    if own == 0 {
        assert!(
            !required(),
            "required mode needs an unprivileged user: root holds CAP_SETUID"
        );
        writeln!(
            io::stderr(),
            "keyring: SKIP another_users_persistent_keyring_is_refused: running as root, which may open any persistent keyring"
        )?;
        return Ok(());
    }
    let refused = open(&format!("persistent:{}", own.saturating_add(1)));
    match refused {
        Err(Error::Keyring(Fault::Kernel {
            operation: _,
            error: KernelError::PermissionDenied,
        })) => {}
        Err(Error::Keyring(Fault::InvalidUid)) if !required() => {}
        other => {
            return Err(format!(
                "another user's persistent keyring: {:?}",
                other.map(|cache| cache.name())
            )
            .into());
        }
    }
    assert!(
        matches!(
            open("persistent:not-a-uid"),
            Err(Error::Keyring(Fault::InvalidUid))
        ),
        "a name that is not a user id"
    );
    Ok(())
}

/// A credential larger than the user's key quota is `EDQUOT`, typed, in a
/// legacy cache, whose credentials are `user` keys (the `big_key` type is not
/// charged by its size).
#[test]
fn credential_over_the_key_quota_is_refused() -> Result<(), TestError> {
    if !available("credential_over_the_key_quota_is_refused")? {
        return Ok(());
    }
    let quota: usize = fs::read_to_string("/proc/sys/kernel/keys/maxbytes")?
        .trim()
        .parse()?;
    let size = quota.saturating_add(2_000);
    if uid()? == 0 || size > 32_000 {
        assert!(
            !required(),
            "required mode needs the default key quota of an unprivileged user"
        );
        writeln!(
            io::stderr(),
            "keyring: SKIP credential_over_the_key_quota_is_refused: the quota {quota} does not suit a user key"
        )?;
        return Ok(());
    }
    let cache = open("legacy:rskrb5ng-test-quota")?;
    cache.initialize(&principal("alice"))?;
    let stored = cache.store(credential("krbtgt/EXAMPLE.COM", vec![1; size]));
    cache.destroy()?;
    assert!(
        matches!(
            stored,
            Err(Error::Keyring(Fault::Kernel {
                operation: _,
                error: KernelError::QuotaExceeded
            }))
        ),
        "{:?}",
        stored.map(|()| "stored")
    );
    Ok(())
}

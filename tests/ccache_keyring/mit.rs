//! MIT's own tools against the kernel keyring.
//!
//! A cache `kinit` wrote is read by this crate, a cache this crate wrote is read
//! and destroyed by `klist` and `kdestroy`. The steps of the `keyring` job in
//! `.github/workflows/ci.yml` set the variables; without them the tests print a
//! skip notice.

use std::{
    env,
    io::{self, Write as _},
};

use rskrb5_ng::{
    ccache::{file_store, stores::CacheVersion},
    error::Ccache as Error,
};

use crate::support::{TestError, available, credential, principal, required};

/// The value of a variable of the MIT steps, or the skip notice.
fn variable(test: &str, name: &str) -> Result<Option<String>, TestError> {
    match env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(_) if required() && env::var("RSKRB5_KEYRING_MIT").as_deref() == Ok("1") => {
            Err(format!("{name} is not set").into())
        }
        Err(_) => {
            writeln!(io::stderr(), "keyring: SKIP {test}: {name} is not set")?;
            Ok(None)
        }
    }
}

/// A cache that `kinit -c KEYRING:...` wrote is read, and copied into a cache
/// that `klist` then lists like the original.
#[test]
fn mit_written_cache_is_read_and_copied() -> Result<(), TestError> {
    if !available("mit_written_cache_is_read_and_copied")? {
        return Ok(());
    }
    let (Some(source), Some(copy), Some(principal)) = (
        variable(
            "mit_written_cache_is_read_and_copied",
            "RSKRB5_KEYRING_MIT_SOURCE",
        )?,
        variable(
            "mit_written_cache_is_read_and_copied",
            "RSKRB5_KEYRING_MIT_COPY",
        )?,
        variable(
            "mit_written_cache_is_read_and_copied",
            "RSKRB5_KEYRING_MIT_PRINCIPAL",
        )?,
    ) else {
        return Ok(());
    };
    let written = file_store::resolve(&source, CacheVersion::V4)?.load()?;
    assert_eq!(
        format!(
            "{}@{}",
            written.default_principal().name_string(),
            written.default_principal().realm
        ),
        principal,
        "the default principal kinit wrote"
    );
    assert!(
        written.credentials().iter().any(|credential| credential
            .server()
            .principal_string()
            .starts_with("krbtgt/")),
        "the ticket-granting ticket kinit wrote"
    );
    let target = file_store::resolve(&copy, CacheVersion::V4)?;
    target.replace(&written)?;
    assert_eq!(
        target.load()?.credentials().len(),
        written.credentials().len(),
        "the copy holds every credential"
    );
    Ok(())
}

/// A cache that `kdestroy` removed is gone for this crate too.
#[test]
fn mit_destroyed_cache_is_not_found() -> Result<(), TestError> {
    if !available("mit_destroyed_cache_is_not_found")? {
        return Ok(());
    }
    let Some(destroyed) = variable(
        "mit_destroyed_cache_is_not_found",
        "RSKRB5_KEYRING_MIT_DESTROYED",
    )?
    else {
        return Ok(());
    };
    let loaded = file_store::resolve(&destroyed, CacheVersion::V4)?.load();
    assert!(
        matches!(loaded, Err(Error::CacheNotFound { name: _ })),
        "{:?}",
        loaded.map(|cache| cache.credentials().len())
    );
    Ok(())
}

/// A cache written here, with a ticket-granting ticket and a service ticket,
/// is what `klist -c` lists in the next step.
#[test]
fn cache_written_here_is_listed_by_klist() -> Result<(), TestError> {
    if !available("cache_written_here_is_listed_by_klist")? {
        return Ok(());
    }
    let Some(name) = variable(
        "cache_written_here_is_listed_by_klist",
        "RSKRB5_KEYRING_MIT_WRITE",
    )?
    else {
        return Ok(());
    };
    let cache = file_store::resolve(&name, CacheVersion::V4)?;
    cache.initialize(&principal("alice"))?;
    cache.store(credential("krbtgt/EXAMPLE.COM", b"tgt".to_vec()))?;
    cache.store(credential("host/service.example.com", b"service".to_vec()))?;
    assert_eq!(cache.load()?.credentials().len(), 2, "written");
    Ok(())
}

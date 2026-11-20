//! KCM caches between the crate's `KCM` store and MIT's tools, through SSSD.

use core::error::Error;
use std::{
    env,
    io::{self, Write as _},
};

use rskrb5_ng::{
    ccache::{
        Principal as CachePrincipal,
        kcm::{async_client::Client, socket::Trust, wire::calls},
        stores::CredentialStore as _,
    },
    error::Ccache as CcacheError,
};
use tokio::runtime::Builder;

use crate::{
    harness,
    support::{
        MIT_KDC, REALM, USER, daemon_age, mechanism, mit, residual, socket, store, tgt_cache,
    },
};

/// The service the scenarios ask MIT `kvno` for.
const SERVICE: &str = "host/mit-kdc.test.rskrb5";

/// The crate writes a cache into the daemon; MIT reads it and adds a service
/// ticket the crate then reads.
///
/// The crate's `INTEROP_KCM_SOCKET` connection is the only way the cache gets
/// to MIT (its `kcm_socket` names the same socket), and SSSD has no `REPLACE`,
/// so the crate's whole-cache write goes through the `INITIALIZE` and `STORE`
/// fallback.
#[test]
fn rust_cache_in_the_daemon_is_read_by_mit() -> Result<(), Box<dyn Error>> {
    if !harness::require("rust_cache_in_the_daemon_is_read_by_mit", &[MIT_KDC])? {
        return Ok(());
    }
    let name = residual("rustcache")?;
    let cache = store()?.resolve(&name)?;
    drop(cache.destroy());
    let tgt = tgt_cache()?;
    cache.replace(&tgt)?;
    mechanism("cache name", &format!("KCM:{name}"), &cache.name())?;
    let listing = mit(&format!("klist -c KCM:{name}"))?;
    mechanism(
        "cache MIT reads",
        &format!("KCM:{name}"),
        listing
            .split("Ticket cache: ")
            .nth(1)
            .and_then(|rest| rest.lines().next())
            .unwrap_or_default(),
    )?;
    assert!(
        listing.contains(&format!("Default principal: {USER}@{REALM}")),
        "{listing}"
    );
    assert!(
        listing.contains(&format!("krbtgt/{REALM}@{REALM}")),
        "{listing}"
    );
    drop(mit(&format!("kvno -c KCM:{name} {SERVICE}@{REALM}"))?);
    assert!(
        cache
            .load()?
            .contains_server(&["host", "mit-kdc.test.rskrb5"]),
        "the service ticket MIT stored is not in the crate's view"
    );
    Ok(())
}

/// MIT `kinit` writes a cache into the daemon; the crate lists the collection,
/// matches the principal and reads the TGT.
#[test]
fn mit_cache_in_the_daemon_is_read_by_the_crate() -> Result<(), Box<dyn Error>> {
    if !harness::require("mit_cache_in_the_daemon_is_read_by_the_crate", &[MIT_KDC])? {
        return Ok(());
    }
    let name = residual("mitcache")?;
    let store = store()?;
    drop(store.resolve(&name)?.destroy());
    drop(mit(&format!(
        "kinit -k -t /kcm-mit/{USER}.keytab -c KCM:{name} {USER}@{REALM}"
    ))?);
    let cache = store.resolve(&name)?;
    let loaded = cache.load()?;
    assert_eq!(loaded.client_name(), USER);
    assert!(loaded.contains_server(&["krbtgt", REALM]), "no TGT");
    let collection = store.collection("")?;
    assert!(
        collection
            .caches()?
            .any(|listed| listed.name() == format!("KCM:{name}")),
        "the collection does not list KCM:{name}"
    );
    let principal = CachePrincipal::new(REALM, 1, vec![USER.to_owned()]);
    assert!(collection.cache_match(&principal)?.is_some());
    assert!(collection.has_content()?);
    Ok(())
}

/// Replacing and removing credentials and destroying the cache are what MIT
/// sees: one TGT after a replacement, no service ticket after a removal, and a
/// missing cache after the destroy.
#[test]
fn store_remove_and_destroy_agree_with_mit() -> Result<(), Box<dyn Error>> {
    if !harness::require("store_remove_and_destroy_agree_with_mit", &[MIT_KDC])? {
        return Ok(());
    }
    let name = residual("editcache")?;
    let cache = store()?.resolve(&name)?;
    drop(cache.destroy());
    let tgt = tgt_cache()?;
    cache.replace(&tgt)?;
    drop(mit(&format!("kvno -c KCM:{name} {SERVICE}@{REALM}"))?);
    let before = cache.load()?.credentials().len();
    assert_eq!(before, 2, "TGT and service ticket");
    // A credential for the same client and server replaces it.
    let again = tgt
        .credentials()
        .first()
        .ok_or("the TGT cache holds no credential")?
        .clone();
    cache.store(again)?;
    assert_eq!(cache.load()?.credentials().len(), 2);
    let service = CachePrincipal::new(
        REALM,
        2,
        vec!["host".to_owned(), "mit-kdc.test.rskrb5".to_owned()],
    );
    assert_eq!(cache.remove(&service)?, 1);
    let listing = mit(&format!("klist -c KCM:{name}"))?;
    assert!(
        listing.contains(&format!("krbtgt/{REALM}@{REALM}")),
        "{listing}"
    );
    assert!(!listing.contains("mit-kdc.test.rskrb5"), "{listing}");
    cache.destroy()?;
    let gone = mit(&format!("klist -c KCM:{name}"));
    assert!(
        gone.as_ref()
            .is_err_and(|failure| failure.to_string().contains("not found")),
        "MIT still reads the destroyed cache: {gone:?}"
    );
    assert!(matches!(
        cache.load(),
        Err(CcacheError::CacheNotFound { name: _ })
    ));
    Ok(())
}

/// A new unique cache, `switch` and the primary agree between the crate and
/// MIT in both directions, and the Tokio client reads the same primary name.
#[test]
fn collection_primary_and_switch_agree_with_mit() -> Result<(), Box<dyn Error>> {
    if !harness::require("collection_primary_and_switch_agree_with_mit", &[MIT_KDC])? {
        return Ok(());
    }
    let store = store()?;
    let collection = store.collection("")?;
    let tgt = tgt_cache()?;
    let fresh = collection.new_unique()?;
    fresh.replace(&tgt)?;
    collection.switch(fresh.as_ref())?;
    mechanism("primary", &fresh.name(), &collection.primary()?.name())?;
    let default = mit("klist")?;
    assert!(
        default.contains(&format!("Ticket cache: {}", fresh.name())),
        "MIT's default cache is not the one the crate switched to: {default}"
    );
    let other = residual("switchedbymit")?;
    let kept = store.resolve(&other)?;
    drop(kept.destroy());
    kept.replace(&tgt)?;
    drop(mit(&format!("kswitch -c KCM:{other}"))?);
    mechanism(
        "primary after kswitch",
        &format!("KCM:{other}"),
        &collection.primary()?.name(),
    )?;
    let listed = mit("klist -l")?;
    for cache in collection.caches()? {
        assert!(
            listed.contains(&cache.name()),
            "klist -l misses {}: {listed}",
            cache.name()
        );
    }
    let async_primary = Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?
        .block_on(async {
            let mut client = Client::connect(&socket()?, &Trust::new()).await?;
            let name = client.call(&calls::get_default_cache()).await?;
            Result::<String, Box<dyn Error>>::Ok(format!("KCM:{}", name.as_str()))
        })?;
    mechanism(
        "primary through the Tokio client",
        &format!("KCM:{other}"),
        &async_primary,
    )?;
    fresh.destroy()?;
    kept.destroy()?;
    Ok(())
}

/// FU-IOP-P04: the daemon is still alive, and still serves requests, when
/// the suite ends.
///
/// libtest runs the scenarios of a target one after another in name order
/// (`run.sh test` passes `--test-threads=1`) and this name sorts after every
/// other scenario's, so this is the suite's last act. The daemon's age is
/// printed; `INTEROP_KCM_MIN_UPTIME_SECS` makes it a requirement, which is how
/// a run longer than the daemon's old five-minute idle timeout proves the
/// fixture stays up.
#[test]
fn the_daemon_is_still_alive_at_the_end_of_the_suite() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "the_daemon_is_still_alive_at_the_end_of_the_suite",
        &[MIT_KDC],
    )? {
        return Ok(());
    }
    let age = daemon_age()?;
    let cache = store()?.resolve(&residual("liveness")?)?;
    drop(cache.destroy());
    let user = CachePrincipal::new(REALM, 1, vec![USER.to_owned()]);
    cache.initialize(&user)?;
    mechanism(
        "principal read back",
        &user.name_string(),
        &cache.load()?.default_principal().name_string(),
    )?;
    cache.destroy()?;
    writeln!(
        io::stderr(),
        "interop: kcm daemon alive {age} s after its start, at the end of the suite"
    )?;
    if let Ok(required) = env::var("INTEROP_KCM_MIN_UPTIME_SECS") {
        let minimum: u64 = required.parse()?;
        assert!(
            age >= minimum,
            "the suite ended {age} s after the daemon started, under the {minimum} s the proof needs"
        );
    }
    Ok(())
}

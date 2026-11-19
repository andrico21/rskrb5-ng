//! DIR collections and cache versions between the crate's stores and MIT's tools.

use core::{error::Error, time::Duration};
use std::{
    fs, io,
    path::{Path, PathBuf},
    process::Command,
};

use rskrb5_ng::{
    ccache::{
        CCache, CacheVersion, CredentialStore as _, DirStore, FileStore,
        Principal as CachePrincipal,
    },
    client::{
        AsRepSession, Tokio,
        principal::Principal,
        transport::{KdcProtocol, Tokio as KdcTransport},
    },
    config::Config,
};
use tokio::runtime::Builder;

use crate::harness::{self, Fixture};

/// The fixture KDC the TGT comes from, reached on `INTEROP_MIT_KDC`.
const MIT_KDC: Fixture = Fixture::new("mit-kdc", "INTEROP_MIT_KDC");

/// The fixture realm.
const REALM: &str = "TEST.RSKRB5";

/// The MIT user whose keytab the fixture exports.
const USER: &str = "testuser1";

/// Fail unless `actual` is the `expected` mechanism; a fallback must not pass.
fn mechanism(what: &str, expected: &str, actual: &str) -> Result<(), Box<dyn Error>> {
    if expected == actual {
        return Ok(());
    }
    Err(format!("{what}: expected {expected:?}, got {actual:?} (a fallback must not pass)").into())
}

/// Run `script` with bash in the MIT container as the exec user; its output.
fn mit(script: &str) -> Result<String, Box<dyn Error>> {
    let user = harness::var("INTEROP_CCACHE_MIT_EXEC_USER")?;
    let container = harness::var("INTEROP_CCACHE_MIT_CONTAINER")?;
    let output = Command::new(harness::var("INTEROP_RUNTIME")?)
        .args([
            "exec",
            "--user",
            user.as_str(),
            "-e",
            "KRB5_CONFIG=/ccache/krb5.conf",
        ])
        .args([container.as_str(), "bash", "-c", script])
        .output()?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if output.status.success() {
        Ok(text)
    } else {
        Err(format!("MIT `{script}` failed ({}): {text}", output.status).into())
    }
}

/// A fresh, empty entry `name` of the shared directory.
fn fresh(name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let path = PathBuf::from(harness::var("INTEROP_CCACHE_MIT_SHARE")?).join(name);
    match fs::remove_dir_all(&path).or_else(|_| fs::remove_file(&path)) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(path)
}

/// The two version bytes a cache file starts with, as hex.
fn version_bytes(path: &Path) -> Result<String, Box<dyn Error>> {
    Ok(hex::encode(
        fs::read(path)?
            .get(..2)
            .ok_or("cache file shorter than two bytes")?,
    ))
}

/// A TGT of the fixture user, obtained by the crate with the exported keytab.
fn tgt_cache() -> Result<CCache, Box<dyn Error>> {
    let kdc = harness::var("INTEROP_MIT_KDC")?;
    let keytab = harness::var("INTEROP_MIT_USER_KEYTAB")?;
    let config = Config::parse(&format!(
        "[libdefaults]\n default_realm = {REALM}\n dns_lookup_kdc = false\n[realms]\n {REALM} = {{\n  kdc = {kdc}\n }}\n"
    ))?;
    Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?
        .block_on(async {
            let mut client = Tokio::with_keytab_name(
                config,
                KdcProtocol::Tcp,
                Principal::user(REALM, USER),
                keytab,
            )?
            .with_transport(KdcTransport::new().with_timeout(Duration::from_secs(10)));
            let _: &AsRepSession = client.login().await?;
            Ok(client.to_ccache()?)
        })
}

/// The crate writes a DIR collection and switches its primary; MIT reads it.
///
/// MIT `klist -A` lists it primary first, `klist` resolves the primary, and MIT
/// `kvno` uses the crate's TGT and stores a service ticket the crate then reads.
#[test]
fn rust_dir_collection_is_read_by_mit() -> Result<(), Box<dyn Error>> {
    if !harness::require("rust_dir_collection_is_read_by_mit", &[MIT_KDC])? {
        return Ok(());
    }
    let directory = fresh("rustdir")?;
    let tgt = tgt_cache()?;
    let collection = DirStore::default().collection(&directory.to_string_lossy())?;
    collection.primary()?.initialize(tgt.default_principal())?;
    let switched = collection.new_unique()?;
    switched.replace(&tgt)?;
    collection.switch(switched.as_ref())?;
    let name = switched.name();
    let file = name.rsplit('/').next().ok_or("subsidiary name")?;
    // The mechanism: the pointer file names the new cache, written in version 4.
    mechanism(
        "primary pointer",
        &format!("{file}\n"),
        &fs::read_to_string(directory.join("primary"))?,
    )?;
    mechanism(
        "cache version bytes",
        "0504",
        &version_bytes(&directory.join(file))?,
    )?;
    // MIT lists the collection primary first and resolves the collection to it.
    let listing = mit("klist -A -c DIR:/ccache/rustdir")?;
    let first = listing
        .split("Ticket cache: ")
        .nth(1)
        .and_then(|rest| rest.lines().next())
        .unwrap_or_default();
    mechanism(
        "first cache MIT lists",
        &format!("DIR::/ccache/rustdir/{file}"),
        first,
    )?;
    assert!(
        listing.contains(&format!("Default principal: {USER}@{REALM}")),
        "{listing}"
    );
    assert!(
        listing.contains(&format!("krbtgt/{REALM}@{REALM}")),
        "{listing}"
    );
    let primary = mit("klist -c DIR:/ccache/rustdir")?;
    assert!(
        primary.contains(&format!("Ticket cache: DIR::/ccache/rustdir/{file}")),
        "{primary}"
    );
    // MIT uses the crate's TGT and adds a service ticket to the crate's cache.
    drop(mit(&format!(
        "kvno -c DIR::/ccache/rustdir/{file} host/mit-kdc.test.rskrb5@{REALM}"
    ))?);
    assert!(
        switched
            .load()?
            .contains_server(&["host", "mit-kdc.test.rskrb5"])
    );
    Ok(())
}

/// MIT `kinit` writes a DIR collection of two caches and `kswitch` moves the
/// primary; the crate enumerates it primary first and matches its principals.
#[test]
fn mit_dir_collection_is_read_by_the_crate() -> Result<(), Box<dyn Error>> {
    if !harness::require("mit_dir_collection_is_read_by_the_crate", &[MIT_KDC])? {
        return Ok(());
    }
    let directory = fresh("mitdir")?;
    let second = harness::var("INTEROP_CCACHE_MIT_SECOND_USER")?;
    drop(mit(&format!(
        "set -e; kinit -k -t /ccache/{USER}.keytab -c DIR:/ccache/mitdir {USER}@{REALM}; \
         kinit -k -t /ccache/{second}.keytab -c DIR::/ccache/mitdir/tktsecond {second}@{REALM}; \
         kswitch -c DIR::/ccache/mitdir/tktsecond"
    ))?);
    // The mechanism: MIT's pointer file and the version of both caches.
    mechanism(
        "primary pointer",
        "tktsecond\n",
        &fs::read_to_string(directory.join("primary"))?,
    )?;
    for file in ["tkt", "tktsecond"] {
        mechanism(
            "cache version bytes",
            "0504",
            &version_bytes(&directory.join(file))?,
        )?;
    }
    let collection = DirStore::default().collection(&directory.to_string_lossy())?;
    let listed: Vec<(String, String)> = collection
        .caches()?
        .map(|cache| {
            Ok((
                cache.name(),
                cache.load()?.default_principal().name_string(),
            ))
        })
        .collect::<Result<_, Box<dyn Error>>>()?;
    let path = |file: &str| format!("DIR::{}", directory.join(file).display());
    assert_eq!(
        listed,
        [(path("tktsecond"), second), (path("tkt"), USER.to_owned())]
    );
    mechanism(
        "primary cache",
        &path("tktsecond"),
        &collection.primary()?.name(),
    )?;
    let principal = CachePrincipal::new(REALM, 1, vec![USER.to_owned()]);
    let matched = collection
        .cache_match(&principal)?
        .ok_or("no cache of the user")?;
    mechanism("matched cache", &path("tkt"), &matched.name())?;
    Ok(())
}

/// MIT writes caches of versions 1 to 4 (`ccache_type`); the crate reads each
/// and writes it back in the same version, which MIT `klist` reads.
#[test]
fn cache_versions_round_trip_with_mit() -> Result<(), Box<dyn Error>> {
    if !harness::require("cache_versions_round_trip_with_mit", &[MIT_KDC])? {
        return Ok(());
    }
    for number in 1_u8..=4 {
        let (written, rewritten) = (
            fresh(&format!("mit-v{number}"))?,
            fresh(&format!("rust-v{number}"))?,
        );
        drop(mit(&format!(
            "KRB5_CONFIG=/ccache/krb5-v{number}.conf kinit -k -t /ccache/{USER}.keytab \
             -c FILE:/ccache/mit-v{number} {USER}@{REALM}"
        ))?);
        mechanism(
            "MIT cache version bytes",
            &format!("050{number}"),
            &version_bytes(&written)?,
        )?;
        let version = CacheVersion::new(i32::from(number))?;
        let cache = FileStore::new(version)
            .resolve(&written.to_string_lossy())?
            .load()?;
        assert_eq!(
            (cache.version(), cache.client_name()),
            (number, USER.to_owned())
        );
        assert!(
            cache.contains_server(&["krbtgt", REALM]),
            "v{number}: no TGT"
        );
        FileStore::new(version)
            .resolve(&rewritten.to_string_lossy())?
            .replace(&cache)?;
        mechanism(
            "crate cache version bytes",
            &format!("050{number}"),
            &version_bytes(&rewritten)?,
        )?;
        let listing = mit(&format!("klist -c FILE:/ccache/rust-v{number}"))?;
        assert!(
            listing.contains(&format!("Default principal: {USER}@{REALM}")),
            "{listing}"
        );
        assert!(
            listing.contains(&format!("krbtgt/{REALM}@{REALM}")),
            "{listing}"
        );
    }
    Ok(())
}

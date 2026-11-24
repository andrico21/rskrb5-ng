//! MIT's `dfl` file: its name, its location and its safety checks.

use std::{fs, path::Path};

use rskrb5_ng::replay::{Admission, File2ReplayStore, Store as _};

use super::support::{TempDir, evidence};
use crate::{
    context::{Context as _, TestError},
    env::{in_child, run_in_child},
};

/// The variable that tells the child where the cache directory is.
const DIRECTORY: &str = "KRB5RCACHEDIR";

/// The user id that owns the files this process creates in `directory`.
#[cfg(unix)]
fn own_uid(directory: &Path) -> Result<u32, TestError> {
    use std::os::unix::fs::MetadataExt as _;

    let probe = directory.join("owner-probe");
    fs::write(&probe, b"")?;
    let uid = fs::metadata(&probe)?.uid();
    fs::remove_file(&probe)?;
    Ok(uid)
}

/// The file name `dfl:` uses in this process.
#[cfg(unix)]
fn dfl_name(directory: &Path) -> Result<String, TestError> {
    Ok(format!("krb5_{}.rcache2", own_uid(directory)?))
}

/// The file name `dfl:` uses in this process.
#[cfg(not(unix))]
fn dfl_name(directory: &Path) -> Result<String, TestError> {
    assert!(
        fs::metadata(directory)?.is_dir(),
        "the cache directory exists"
    );
    Ok("krb5.rcache2".to_owned())
}

/// Pins that `dfl:` keeps `krb5_<euid>.rcache2` in `KRB5RCACHEDIR`, owner-only, shared by two opens.
#[test]
fn dfl_uses_the_user_file_in_the_cache_directory() -> Result<(), TestError> {
    const NAME: &str = "replay_store::dfl::dfl_uses_the_user_file_in_the_cache_directory";
    if !in_child(NAME) {
        let directory = TempDir::new("dfl")?;
        run_in_child(NAME, &[(DIRECTORY, Some(directory.path().as_os_str()))]);
        let file = directory.path().join(dfl_name(directory.path())?);
        assert!(file.is_file(), "{} exists", file.display());
        return Ok(());
    }
    let first = File2ReplayStore::dfl()?.admit(&evidence(1, 1_000_000)?)?;
    let second = File2ReplayStore::dfl()?.admit(&evidence(1, 1_000_000)?)?;
    assert_eq!(first, Admission::Fresh);
    assert_eq!(second, Admission::Replayed);
    Ok(())
}

/// Pins that `dfl:` refuses a cache file that is a symlink, as MIT's `O_NOFOLLOW` does.
#[cfg(unix)]
#[test]
fn dfl_refuses_a_symlinked_cache_file() -> Result<(), TestError> {
    use std::os::unix::fs::symlink;

    use rskrb5_ng::error::Replay as Error;

    const NAME: &str = "replay_store::dfl::dfl_refuses_a_symlinked_cache_file";
    if !in_child(NAME) {
        let directory = TempDir::new("dfl-link")?;
        let target = directory.path().join("elsewhere");
        fs::write(&target, b"")?;
        symlink(&target, directory.path().join(dfl_name(directory.path())?))?;
        run_in_child(NAME, &[(DIRECTORY, Some(directory.path().as_os_str()))]);
        assert_eq!(
            fs::metadata(&target)?.len(),
            0,
            "the target was not written"
        );
        return Ok(());
    }
    let outcome = File2ReplayStore::dfl()?.admit(&evidence(1, 1_000_000)?);
    assert!(
        matches!(outcome, Err(Error::UnsafeFile { path: _, reason: _ })),
        "{outcome:?}"
    );
    Ok(())
}

/// Pins that a `file2:` store, unlike `dfl:`, does not apply the owner check and follows its path as given.
#[test]
fn file2_stores_use_the_path_as_given() -> Result<(), TestError> {
    let directory = TempDir::new("file2-path")?;
    let path = directory.path().join("given.rcache2");
    let store = File2ReplayStore::new(path.clone());

    assert_eq!(store.path(), path.as_path());
    assert_eq!(store.admit(&evidence(2, 1_000_000)?)?, Admission::Fresh);
    assert!(fs::metadata(&path).context("the file exists")?.len() >= 32);
    Ok(())
}

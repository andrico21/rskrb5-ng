//! Cross-thread and cross-process atomicity of the file store, on real files.

use std::{
    env::current_exe,
    fs,
    process::{Command, Stdio},
    sync::Barrier,
    thread,
};

use rskrb5_ng::replay::{Admission, File2ReplayStore, Store};

use crate::context::{Context as _, TestError};
use super::{
    support::{TempDir, evidence},
};

/// Tags every worker presents.
const TAGS: u32 = 60;
/// Environment variable that points a child worker at the shared directory.
const DIRECTORY_ENV: &str = "RSKRB5_REPLAY_TEST_DIR";
/// Marks every line a worker prints.
const MARKER: &str = "ADMISSION";

/// Presents every tag to a store opened on `path` and lists the fresh ones.
fn present_all(path: &std::path::Path) -> Result<Vec<u32>, TestError> {
    let store = File2ReplayStore::new(path.join("replay.rcache2"));
    let mut fresh = Vec::new();
    for index in 0..TAGS {
        if store.admit(&evidence(index, 1_000_000)?)? == Admission::Fresh {
            fresh.push(index);
        }
    }
    Ok(fresh)
}

/// Pins that the first presentation is fresh and the second, from a new store on the same file, a replay.
#[test]
fn a_second_store_on_the_same_file_sees_the_evidence() -> Result<(), TestError> {
    let directory = TempDir::new("restart")?;
    let path = directory.path().join("replay.rcache2");

    let first = File2ReplayStore::new(path.clone()).admit(&evidence(1, 1_000_000)?)?;
    let second = File2ReplayStore::new(path.clone()).admit(&evidence(1, 1_000_000)?)?;

    assert_eq!(first, Admission::Fresh);
    assert_eq!(second, Admission::Replayed);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = fs::metadata(&path)?.permissions().mode();
        assert_eq!(mode & 0o077, 0, "the cache file is owner-only: {mode:o}");
    }
    Ok(())
}

/// Pins that of eight threads racing on separate stores over one file exactly one admits each tag.
#[test]
fn threads_on_separate_stores_admit_each_tag_once() -> Result<(), TestError> {
    let directory = TempDir::new("threads")?;
    let barrier = Barrier::new(8);

    let results = thread::scope(|scope| {
        let workers: Vec<_> = (0..8)
            .map(|_worker| {
                scope.spawn(|| {
                    let _leader = barrier.wait();
                    present_all(directory.path()).map_err(|error| error.to_string())
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().map_err(|_panic| "worker panicked".to_owned())?)
            .collect::<Result<Vec<_>, String>>()
    })?;

    let mut counts = [0_u32; TAGS as usize];
    for fresh in results {
        for index in fresh {
            *counts.get_mut(usize::try_from(index)?).context("tag index")? += 1;
        }
    }
    assert!(counts.iter().all(|count| *count == 1), "{counts:?}");
    Ok(())
}

/// Child worker of the multi-process test: presents every tag and prints the fresh ones.
#[test]
fn replay_worker_process() -> Result<(), TestError> {
    let Some(directory) = std::env::var_os(DIRECTORY_ENV) else {
        return Ok(());
    };
    for index in present_all(directory.as_ref())? {
        println!("{MARKER} {index}");
    }
    Ok(())
}

/// Pins that of four processes racing on one cache file exactly one admits each tag.
#[test]
fn processes_sharing_one_file_admit_each_tag_once() -> Result<(), TestError> {
    let directory = TempDir::new("processes")?;
    let executable = current_exe()?;
    let mut children = Vec::new();
    for _worker in 0..4 {
        let child = Command::new(&executable)
            .args(["replay_worker_process", "--exact", "--nocapture", "--test-threads=1"])
            .env(DIRECTORY_ENV, directory.path())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        children.push(child);
    }

    let mut counts = [0_u32; TAGS as usize];
    for child in children {
        let output = child.wait_with_output()?;
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        for line in String::from_utf8(output.stdout)?.lines() {
            if let Some(index) = line.strip_prefix(MARKER).map(str::trim) {
                *counts
                    .get_mut(index.parse::<usize>()?)
                    .context("tag index")? += 1;
            }
        }
    }

    assert!(counts.iter().all(|count| *count == 1), "{counts:?}");
    Ok(())
}

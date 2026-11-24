//! Cross-thread and cross-process atomicity of the file store, on real files.

use core::iter::repeat_with;
use std::{
    env::{current_exe, var_os},
    io::{Write as _, stdout},
    path::Path,
    process::{Command, Stdio},
    sync::Barrier,
    thread,
};

use rskrb5_ng::replay::{Admission, File2ReplayStore, Store as _};

use super::support::{TempDir, evidence};
use crate::context::{Context as _, TestError};

/// Tags every worker presents.
const TAGS: u32 = 60;
/// Environment variable that points a child worker at the shared directory.
const DIRECTORY_ENV: &str = "RSKRB5_REPLAY_TEST_DIR";
/// Marks every line a worker prints.
const MARKER: &str = "ADMISSION";

/// Presents every tag to a store opened on `path` and lists the fresh ones.
fn present_all(path: &Path) -> Result<Vec<u32>, TestError> {
    let store = File2ReplayStore::new(path.join("replay.rcache2"));
    let mut fresh = Vec::new();
    for index in 0..TAGS {
        if store.admit(&evidence(index, 1_000_000)?)? == Admission::Fresh {
            fresh.push(index);
        }
    }
    Ok(fresh)
}

/// Count one fresh admission of tag `index`.
fn tally(counts: &mut [u32], index: usize) -> Result<(), TestError> {
    let slot = counts.get_mut(index).context("tag index")?;
    *slot = slot.saturating_add(1);
    Ok(())
}

/// Pins that the first presentation is fresh and the second, from a new store on the same file, a replay.
#[test]
fn a_second_store_on_the_same_file_sees_the_evidence() -> Result<(), TestError> {
    let directory = TempDir::new("restart")?;
    let path = directory.path().join("replay.rcache2");

    let first = File2ReplayStore::new(path.clone()).admit(&evidence(1, 1_000_000)?)?;
    let second = File2ReplayStore::new(path).admit(&evidence(1, 1_000_000)?)?;

    assert_eq!(first, Admission::Fresh);
    assert_eq!(second, Admission::Replayed);
    #[cfg(unix)]
    {
        use std::{fs, os::unix::fs::PermissionsExt as _};
        let mode = fs::metadata(directory.path().join("replay.rcache2"))?
            .permissions()
            .mode();
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
        let workers: Vec<_> = repeat_with(|| {
            scope.spawn(|| {
                let _leader = barrier.wait();
                present_all(directory.path()).map_err(|error| error.to_string())
            })
        })
        .take(8)
        .collect();
        workers
            .into_iter()
            .map(|worker| {
                worker
                    .join()
                    .map_err(|_panic| "worker panicked".to_owned())?
            })
            .collect::<Result<Vec<_>, String>>()
    })?;

    let mut counts = vec![0_u32; usize::try_from(TAGS)?];
    for fresh in results {
        for index in fresh {
            tally(&mut counts, usize::try_from(index)?)?;
        }
    }
    assert!(counts.iter().all(|count| *count == 1), "{counts:?}");
    Ok(())
}

/// Child worker of the multi-process test: presents every tag and prints the fresh ones.
#[test]
fn replay_worker_process() -> Result<(), TestError> {
    let Some(directory) = var_os(DIRECTORY_ENV) else {
        return Ok(());
    };
    for index in present_all(directory.as_ref())? {
        writeln!(stdout(), "{MARKER} {index}")?;
    }
    Ok(())
}

/// Pins that of four processes racing on one cache file exactly one admits each tag.
#[test]
fn processes_sharing_one_file_admit_each_tag_once() -> Result<(), TestError> {
    let directory = TempDir::new("processes")?;
    let executable = current_exe()?;
    let mut children = Vec::new();
    for _worker in 0_u8..4 {
        let child = Command::new(&executable)
            .args([
                "replay_store::concurrency::replay_worker_process",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(DIRECTORY_ENV, directory.path())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        children.push(child);
    }

    let mut counts = vec![0_u32; usize::try_from(TAGS)?];
    for child in children {
        let output = child.wait_with_output()?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout)?;
        assert!(stdout.contains("1 passed"), "the worker ran: {stdout}");
        for line in stdout.lines() {
            if let Some((_, index)) = line
                .split_once(MARKER)
                .map(|(head, tail)| (head, tail.trim()))
            {
                tally(&mut counts, index.parse::<usize>()?)?;
            }
        }
    }

    assert!(counts.iter().all(|count| *count == 1), "{counts:?}");
    Ok(())
}

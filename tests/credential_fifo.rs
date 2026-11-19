//! A FIFO or another non-regular file at a credential path is refused instead
//! of blocking the reader (supervisor validation Y4-07).

/// FIFO tests, run in a bounded child process so a blocking open fails the
/// test instead of hanging the run.
#[cfg(test)]
#[cfg(unix)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::{error, time::Duration};
    use std::{
        env, fs,
        io::{self, Write as _},
        path::{Path, PathBuf},
        process::{self, Command, Output, Stdio},
        sync::mpsc,
        thread::{self, JoinHandle},
        time::{SystemTime, UNIX_EPOCH},
    };

    use rskrb5_ng::{
        ccache::{
            CCache, Principal, dir_store::DirStore, file_store::FileStore,
            stores::CredentialStore as _,
        },
        keytab::stores as keytab_stores,
    };

    /// Error type of the `Result`-returning tests.
    type TestError = Box<dyn error::Error>;

    /// The variable that names the fixture directory to the child.
    const CHILD: &str = "RSKRB5_TEST_FIFO_CHILD";
    /// This test's name, for the child's test filter.
    const NAME: &str = "tests::fifo_paths_are_refused_without_blocking";
    /// How long the child may take; it needs well under a second.
    const BOUND: Duration = Duration::from_secs(60);

    /// A fresh fixture directory.
    fn scratch() -> Result<PathBuf, TestError> {
        let directory = env::temp_dir().join(format!(
            "credential-fifo-{}-{}",
            process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        fs::create_dir_all(&directory)?;
        Ok(directory)
    }

    /// Make a FIFO at `path`.
    fn mkfifo(path: &Path) -> Result<(), TestError> {
        let status = Command::new("mkfifo").arg(path).status()?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("mkfifo {}: {status}", path.display()).into())
        }
    }

    /// Whether `result` is an error; the child reports each step on stderr.
    fn refused<T, E>(step: &str, result: &Result<T, E>) -> Result<bool, TestError> {
        let verdict = if result.is_err() {
            "refused"
        } else {
            "accepted"
        };
        writeln!(io::stderr().lock(), "step {step}: {verdict}")?;
        Ok(result.is_err())
    }

    /// The child: every reader of a FIFO path returns an error at once.
    fn child(directory: &Path) -> Result<(), TestError> {
        let fifo = directory.join("tktfifo");
        let name = fifo.to_string_lossy().into_owned();
        let cache = FileStore::default().resolve(&name)?;
        assert!(refused("FILE load", &cache.load())?);
        let alice = Principal::new("TEST", 1, vec!["alice".to_owned()]);
        assert!(refused("FILE initialize", &cache.initialize(&alice))?);
        assert!(refused(
            "FILE keytab load",
            &keytab_stores::resolve(&name)?.load()
        )?);

        let collection = DirStore::default().collection(&directory.to_string_lossy())?;
        let listed: Vec<String> = collection.caches()?.map(|handle| handle.name()).collect();
        writeln!(
            io::stderr().lock(),
            "step DIR caches: [{}]",
            listed.join(" ")
        )?;
        assert_eq!(listed, Vec::<String>::new());
        assert!(!collection.has_content()?);

        mkfifo(&directory.join("primary"))?;
        assert!(refused("DIR primary", &collection.primary())?);
        let by_name = CCache::load_name(format!("DIR:{}", directory.display()));
        assert!(refused("DIR name load", &by_name)?);
        Ok(())
    }

    /// A FIFO cache file, a FIFO keytab, a FIFO in a DIR collection and a FIFO
    /// `primary` pointer are refused or skipped without blocking.
    #[test]
    fn fifo_paths_are_refused_without_blocking() -> Result<(), TestError> {
        if let Some(directory) = env::var_os(CHILD) {
            return child(Path::new(&directory));
        }
        let directory = scratch()?;
        mkfifo(&directory.join("tktfifo"))?;
        let started = Command::new(env::current_exe()?)
            .args([NAME, "--exact", "--nocapture", "--test-threads=1"])
            .env(CHILD, &directory)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let pid = started.id().to_string();
        let (sender, receiver) = mpsc::channel::<io::Result<Output>>();
        let waiter: JoinHandle<Result<(), mpsc::SendError<io::Result<Output>>>> =
            thread::spawn(move || sender.send(started.wait_with_output()));
        let finished = receiver.recv_timeout(BOUND);
        let killed = if finished.is_err() {
            Some(Command::new("kill").args(["-KILL", &pid]).status()?)
        } else {
            None
        };
        waiter
            .join()
            .map_err(|_panic| "the child waiter panicked")??;
        fs::remove_dir_all(&directory)?;
        let output = match (finished, killed) {
            (Ok(output), _) => output?,
            (Err(_bound), kill) => {
                let late = receiver.recv()??;
                let status = kill.map_or_else(String::new, |status| status.to_string());
                return Err(format!(
                    "the child blocked on a FIFO and was killed ({status}); its steps: {}",
                    String::from_utf8_lossy(&late.stderr)
                )
                .into());
            }
        };
        assert!(
            output.status.success(),
            "child {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(())
    }
}

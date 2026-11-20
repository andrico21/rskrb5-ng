//! The file sink: MIT's `krb5_set_trace_filename`.

use std::{
    fs::{File, OpenOptions},
    io::Write as _,
    path::Path,
    process,
    sync::{Mutex, PoisonError},
    time::{SystemTime, UNIX_EPOCH},
};

use super::{Event, Sink};
use crate::error::Trace as Error;

/// Appends `[pid] seconds.micros: line` to a file, the frame of MIT 1.22.2
/// `src/lib/krb5/os/trace.c:411`.
///
/// The file is opened for append and created with mode 0600 on Unix
/// (`trace.c:454`, `O_WRONLY|O_CREAT|O_APPEND`, 0600); a line is one write.
#[derive(Debug)]
pub struct Append {
    /// The open file; one writer at a time keeps lines whole.
    file: Mutex<File>,
}

impl Append {
    /// Open `path` for appending.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Open`] when the file cannot be opened.
    #[inline]
    pub fn open(path: &Path) -> Result<Self, Error> {
        let mut options = OpenOptions::new();
        let _: &mut OpenOptions = options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            let _: &mut OpenOptions = options.mode(0o600);
        }
        let file = options.open(path).map_err(|source| Error::Open {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(Self {
            file: Mutex::new(file),
        })
    }
}

impl Sink for Append {
    #[inline]
    fn write(&self, _event: &Event<'_>, text: &str) -> Result<(), Error> {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let line = format!(
            "[{}] {}.{:06}: {text}\n",
            process::id(),
            elapsed.as_secs(),
            elapsed.subsec_micros()
        );
        self.file
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .write_all(line.as_bytes())
            .map_err(Error::Write)?;
        Ok(())
    }

    #[inline]
    fn flush(&self) -> Result<(), Error> {
        self.file
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .flush()
            .map_err(Error::Write)?;
        Ok(())
    }
}

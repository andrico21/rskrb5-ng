//! Locked rewrites serialize the creation of an absent file (supervisor
//! validation Y4-02).

/// Creation serialization of [`super::rewrite`].
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error::Error;
    use std::{
        env,
        fs::{self, File, TryLockError},
        io,
        path::PathBuf,
    };

    use super::super::{Change, rewrite};
    use crate::file_name::SecretBytes;

    /// A fresh fixture directory.
    fn fixture() -> Result<PathBuf, Box<dyn Error>> {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random)?;
        let path = env::temp_dir().join(format!(
            "locked-creation-{:032x}",
            u128::from_be_bytes(random)
        ));
        fs::create_dir_all(&path)?;
        Ok(path)
    }

    /// After the first writer observes that the file is absent, a second
    /// writer finds the file and cannot lock it, so it cannot observe absence
    /// and publish over the first writer's update.
    #[test]
    fn a_second_writer_cannot_observe_absence_during_a_first_write() -> Result<(), Box<dyn Error>> {
        let directory = fixture()?;
        let path = directory.join("keytab");
        let second_writer_blocked = rewrite(&path, |current| -> io::Result<_> {
            assert!(current.is_none(), "the first writer observes absence");
            let second = File::open(&path)?;
            let blocked = matches!(second.try_lock(), Err(TryLockError::WouldBlock));
            Ok((Change::Write(SecretBytes::new(b"first".to_vec())), blocked))
        })?;
        assert!(second_writer_blocked);
        assert_eq!(fs::read(&path)?, b"first");
        fs::remove_dir_all(directory)?;
        Ok(())
    }

    /// A first write that fails leaves no file behind.
    #[test]
    fn a_failed_first_write_leaves_no_file() -> Result<(), Box<dyn Error>> {
        let directory = fixture()?;
        let path = directory.join("keytab");
        let result = rewrite(&path, |_current| -> io::Result<(Change, ())> {
            Err(io::Error::other("refused"))
        });
        assert_eq!(
            result.err().map(|error| error.to_string()).as_deref(),
            Some("refused")
        );
        assert!(!path.try_exists()?);
        fs::remove_dir_all(directory)?;
        Ok(())
    }
}

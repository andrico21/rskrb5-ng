//! Filesystem error propagation at the credential publication boundary.

/// Real filesystem failures without permissions or scheduling assumptions.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error::Error;
    #[cfg(unix)]
    use std::io::{self, Write as _};
    use std::{
        env, fs,
        path::{Path, PathBuf},
        process::Command,
    };

    use crate::file_name;

    /// Create a unique filesystem fixture using the existing randomness dependency.
    fn fixture_directory() -> Result<PathBuf, Box<dyn Error>> {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random)?;
        let path = env::temp_dir().join(format!(
            "mutants-b-files-{:032x}",
            u128::from_be_bytes(random)
        ));
        fs::create_dir_all(&path)?;
        Ok(path)
    }

    /// Metadata errors other than absence must survive the symlink check.
    #[test]
    fn symlink_check_preserves_non_directory_error() -> Result<(), Box<dyn Error>> {
        let directory = fixture_directory()?;
        let parent = directory.join("file");
        fs::write(&parent, b"not a directory")?;
        let path = parent.join("child");
        let expected = fs::symlink_metadata(&path)
            .err()
            .ok_or("metadata must fail")?
            .kind();
        let actual = file_name::reject_symlink(&path)
            .err()
            .ok_or("metadata error swallowed")?;
        assert_eq!(actual.kind(), expected);
        fs::remove_dir_all(directory)?;
        Ok(())
    }

    /// Publication preserves a hard-link failure instead of a secondary cleanup error.
    #[test]
    #[cfg(unix)]
    fn primary_publication_preserves_missing_stage_error() -> Result<(), Box<dyn Error>> {
        let directory = fixture_directory()?;
        let path = directory.join("primary");
        let result = file_name::create_primary_with(&path, |file| {
            file.write_all(b"tkt\n")?;
            for entry in fs::read_dir(&directory)? {
                let stage = entry?.path();
                fs::remove_file(&stage)?;
                fs::create_dir_all(stage)?;
            }
            Ok(())
        });
        assert_eq!(
            result.err().ok_or("publication error swallowed")?.kind(),
            io::ErrorKind::PermissionDenied
        );
        fs::remove_dir_all(directory)?;
        Ok(())
    }

    /// Relative names retain their actual parent rather than falling back to the working directory.
    #[test]
    fn private_write_uses_destination_parent() -> Result<(), Box<dyn Error>> {
        if env::var_os("RSKRB5_MUTATION_RELATIVE_WRITE").is_some() {
            file_name::write_private(Path::new("cache"), b"credential")?;
            assert_eq!(fs::read("cache")?, b"credential");
        } else {
            let directory = fixture_directory()?;
            let output = Command::new(env::current_exe()?)
                .args([
                    "--exact",
                    "file_name::mutation_tests::tests::private_write_uses_destination_parent",
                ])
                .env("RSKRB5_MUTATION_RELATIVE_WRITE", "1")
                .current_dir(&directory)
                .output()?;
            assert!(
                output.status.success(),
                "relative write failed: {}",
                String::from_utf8(output.stdout)?
            );
            fs::remove_dir_all(directory)?;
        }
        Ok(())
    }
}

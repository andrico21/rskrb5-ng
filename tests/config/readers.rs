//! Bounded reader adapters and dynamic-provider rejection.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::{error::Error, iter::repeat_n};
    use std::{env, fs, io, path::PathBuf, process};

    use rskrb5_ng::{
        Config,
        config::{MAX_INCLUDE_BYTES, ParseMode},
        error::Config as Failure,
    };

    /// Readers must stop at the size sentinel rather than drain their input.
    #[test]
    fn reader_stops_at_limit_plus_one() -> Result<(), Box<dyn Error>> {
        // Given a finite oversized reader with observable remaining bytes.
        let bytes = vec![b' '; MAX_INCLUDE_BYTES.saturating_add(100)];
        let mut reader = bytes.as_slice();
        // When attempting composition.
        let failure = Config::from_reader(&mut reader)
            .err()
            .ok_or("oversize accepted")?;
        // Then the typed limit wins and the rest was never consumed.
        assert!(
            matches!(failure, Failure::IncludeTooLarge { bytes: observed, limit } if observed == MAX_INCLUDE_BYTES.saturating_add(1) && limit == MAX_INCLUDE_BYTES)
        );
        assert_eq!(reader.len(), 99);
        Ok(())
    }

    /// The inclusive byte boundary permits a complete valid profile.
    #[test]
    fn reader_accepts_exact_limit() -> Result<(), Box<dyn Error>> {
        // Given exactly four MiB of valid comment text.
        let mut bytes = vec![b'#'];
        bytes.extend(repeat_n(b' ', MAX_INCLUDE_BYTES.saturating_sub(1)));
        // When composing from a reader.
        let config = Config::from_reader(bytes.as_slice())?;
        // Then ordinary defaults survive.
        assert_eq!(config, Config::new());
        Ok(())
    }

    /// Reader failures and invalid UTF-8 retain their causal I/O classification.
    #[test]
    fn reader_errors_remain_typed() -> Result<(), Box<dyn Error>> {
        // Given invalid UTF-8 and a reader that fails immediately.
        let cases: [(Box<dyn io::Read>, io::ErrorKind); 2] = [
            (Box::new(b"\xff".as_slice()), io::ErrorKind::InvalidData),
            (Box::new(Broken), io::ErrorKind::PermissionDenied),
        ];
        for (reader, expected) in cases {
            // When reading the profile.
            let failure = Config::from_reader(reader)
                .err()
                .ok_or("bad reader accepted")?;
            // Then the cause survives without fabricated path information.
            assert!(matches!(failure, Failure::Io(source) if source.kind() == expected));
        }
        Ok(())
    }

    /// Deterministic failing reader, independent of host permissions.
    struct Broken;
    impl io::Read for Broken {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::ErrorKind::PermissionDenied.into())
        }
    }

    /// Reader includes use the same first-wins composition and cumulative budget.
    #[test]
    fn reader_composes_absolute_includes() -> Result<(), Box<dyn Error>> {
        // Given a unique child file and a reader with an absolute include.
        let path: PathBuf = env::temp_dir().join(format!("b2-reader-{}.conf", process::id()));
        fs::write(&path, "[libdefaults]\ndefault_realm = CHILD\n")?;
        let text = format!(
            "include {}\n[libdefaults]\ndefault_realm = PARENT\n",
            path.display()
        );
        // When each adapter loads the same composition.
        let result = Config::from_reader(io::Cursor::new(text.as_bytes()));
        let file_result = Config::from_path(&path);
        fs::remove_file(&path)?;
        // Then reader and path both select the independent child's first scalar.
        assert_eq!(result?.libdefaults.default_realm, "CHILD");
        assert_eq!(file_result?.libdefaults.default_realm, "CHILD");
        assert_eq!(
            Config::from_string("[libdefaults]\ndefault_realm = TEXT\n")?
                .libdefaults
                .default_realm,
            "TEXT"
        );
        Ok(())
    }

    /// Relative includes cannot acquire an implicit reader base directory.
    #[test]
    fn reader_rejects_relative_include() -> Result<(), Box<dyn Error>> {
        // Given a relative include in caller-provided bytes.
        let reader = &b"include relative.conf\n"[..];
        // When composing the source.
        let failure = Config::from_reader(reader)
            .err()
            .ok_or("relative include accepted")?;
        // Then the include boundary refuses it before filesystem access.
        assert!(
            matches!(failure, Failure::IncludeFile { source, path: _ } if source.kind() == io::ErrorKind::InvalidInput)
        );
        Ok(())
    }

    /// Root-reader bytes and included bytes share one budget.
    #[test]
    fn reader_and_child_share_the_byte_budget() -> Result<(), Box<dyn Error>> {
        // Given a root exactly at the cap and a nonempty included file.
        let path = env::temp_dir().join(format!("b2-budget-{}.conf", process::id()));
        fs::write(&path, "# child\n")?;
        let mut text = format!("include {}\n#", path.display());
        text.extend(repeat_n(' ', MAX_INCLUDE_BYTES.saturating_sub(text.len())));
        // When the child attempts to contribute one more byte.
        let result = Config::from_reader(text.as_bytes());
        fs::remove_file(path)?;
        // Then the global limit rejects the composition.
        let failure = result.err().ok_or("combined budget ignored")?;
        assert!(
            matches!(failure, Failure::IncludeTooLarge { bytes, limit } if bytes == limit.saturating_add(1))
        );
        Ok(())
    }

    /// Included sources cannot evade dynamic-provider rejection.
    #[test]
    fn reader_rejects_modules_in_included_files() -> Result<(), Box<dyn Error>> {
        // Given a plugin registration in an absolute included source.
        let path = env::temp_dir().join(format!("b2-module-{}.conf", process::id()));
        fs::write(&path, "[plugins]\nmodule = never:load\n")?;
        let text = format!("include {}\n", path.display());
        // When the reader enters the independent child source.
        let result = Config::from_reader(text.as_bytes());
        fs::remove_file(path)?;
        // Then it reports the same typed refusal as a root module.
        let failure = result.err().ok_or("included module ignored")?;
        assert!(matches!(failure, Failure::UnsupportedDynamicModule));
        Ok(())
    }

    /// A dynamic provider cannot hide in ignored/finalized sections or plugin blocks.
    #[test]
    fn dynamic_modules_fail_in_every_mode() -> Result<(), Box<dyn Error>> {
        // Given every supported syntax position, including discarded scopes.
        for text in [
            "module /never/load.so:residual\n",
            "[libdefaults]\nmodule = /never/load.so\n",
            "[plugins]\nclpreauth = {\nmodule = test:/never/load.so\n}\n",
            "[plugins]*\n[plugins]\nmodule* = /never/load.so\n",
            "[unknown]\nmodule = /never/load.so\n",
            "[realms]\nR = {\nmodule=/never/load.so\n}\n",
            "[plugins]\nR = {\nauth_to_local_names = {\nmodule=local\n}\n}\n",
            "[realms]\nR = {\nother = {\nauth_to_local_names = {\nmodule=local\n}\n}\n}\n",
            "[realms]\nR = {\nauth_to_local_names = {\nmodule = {\nname = local\n}\n}\n}\n",
            "[realms]*\nR = {\n}\n[realms]\nR = {\nmodule=/never/load.so\n}\n",
        ] {
            for mode in [ParseMode::Compatible, ParseMode::Strict] {
                // When parsing under either mode.
                let failure = Config::parse_with_mode(text, mode)
                    .err()
                    .ok_or("dynamic module ignored")?;
                // Then the specific refusal is independent of parsing mode.
                assert!(matches!(failure, Failure::UnsupportedDynamicModule));
            }
        }
        Ok(())
    }
}

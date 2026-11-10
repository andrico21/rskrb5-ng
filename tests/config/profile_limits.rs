//! Filesystem boundaries and independent MIT documentation fixtures.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::{
        error::Error,
        iter::repeat_n,
        sync::atomic::{AtomicU64, Ordering},
    };
    use std::{env, fs, io::ErrorKind, path::PathBuf, process};

    use rskrb5_ng::{Config, error::Config as ConfigError};

    /// Invocation sequence independent of platform clock resolution.
    static NEXT: AtomicU64 = AtomicU64::new(0);

    /// Create a fixture root for the current process and invocation.
    fn directory() -> Result<PathBuf, Box<dyn Error>> {
        let path = env::temp_dir().join(format!(
            "profile-limits-{}-{}",
            process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path)?;
        Ok(path)
    }

    /// Exactly 256 top-level files fit; the 257th fails before reading.
    #[test]
    fn file_budget_covers_root_sources() -> Result<(), Box<dyn Error>> {
        // Given a repeated root source, which is not an active-chain cycle.
        let dir = directory()?;
        let file = dir.join("root.conf");
        fs::write(&file, "[realms]\n A = {\n kdc = first\n }\n")?;
        // When loading at and just beyond the file budget.
        let accepted = Config::load_paths(repeat_n(&file, 256))?;
        let failure = Config::load_paths(repeat_n(&file, 257))
            .err()
            .ok_or("257 roots accepted")?;
        fs::remove_dir_all(dir)?;
        // Then duplicates accumulate and excess is a typed count error.
        assert_eq!(accepted.configured_kdcs("A")?.len(), 256);
        assert!(matches!(
            failure,
            ConfigError::IncludeTooMany {
                count: 257,
                limit: 256
            }
        ));
        Ok(())
    }

    /// Root and child byte counts share one inclusive four-MiB budget.
    #[test]
    fn total_bytes_include_root_and_child() -> Result<(), Box<dyn Error>> {
        // Given a child whose exact bytes fill the budget after the root directive.
        let dir = directory()?;
        let child = dir.join("child.conf");
        let root = format!("include {}\n", child.display());
        let remaining = 0x0040_0000_usize
            .checked_sub(root.len())
            .ok_or("root fits budget")?;
        fs::write(
            &child,
            format!("#{}", "x".repeat(remaining.saturating_sub(1))),
        )?;
        // When reading at the boundary, then with one extra root byte.
        let accepted = Config::parse(&root)?;
        let failure = Config::parse(&format!("{root}\n"))
            .err()
            .ok_or("oversize composition accepted")?;
        fs::remove_dir_all(dir)?;
        // Then only the extra byte fails.
        assert_eq!(accepted, Config::new());
        assert!(matches!(
            failure,
            ConfigError::IncludeTooLarge {
                bytes: 0x0040_0001,
                limit: 0x0040_0000
            }
        ));
        Ok(())
    }

    /// Eight include edges are accepted, a ninth fails with its depth.
    #[test]
    fn include_depth_boundary_is_inclusive() -> Result<(), Box<dyn Error>> {
        // Given eight nested includes from an in-memory root.
        let dir = directory()?;
        let paths: Vec<PathBuf> = (0..9_u8)
            .map(|index| dir.join(format!("{index}.conf")))
            .collect();
        for pair in paths.windows(2).take(7) {
            if let [file, next] = pair {
                fs::write(file, format!("include {}\n", next.display()))?;
            }
        }
        let first = paths.first().ok_or("first file")?;
        let eighth = paths.get(7).ok_or("eighth file")?;
        let ninth = paths.get(8).ok_or("ninth file")?;
        fs::write(eighth, "[libdefaults]\n default_realm = EIGHT\n")?;
        let root = format!("include {}\n", first.display());
        // When loading at and beyond the depth boundary.
        let accepted = Config::parse(&root)?;
        fs::write(eighth, format!("include {}\n", ninth.display()))?;
        fs::write(ninth, "[libdefaults]\n")?;
        let failure = Config::parse(&root).err().ok_or("ninth include accepted")?;
        fs::remove_dir_all(dir)?;
        // Then the exact boundary is retained.
        assert_eq!(accepted.libdefaults.default_realm, "EIGHT");
        assert!(matches!(
            failure,
            ConfigError::IncludeTooDeep { depth: 9, limit: 8 }
        ));
        Ok(())
    }

    /// Directory directives obey the depth cap even without eligible entries.
    #[test]
    fn includedir_depth_boundary_without_eligible_files() -> Result<(), Box<dyn Error>> {
        // Given empty and ignored-only directories at the eighth and ninth edges.
        for ignored in [false, true] {
            for depth in [8_usize, 9] {
                let dir = directory()?;
                let included = dir.join("included");
                fs::create_dir_all(&included)?;
                if ignored {
                    fs::write(included.join(".hidden.conf"), "not a profile")?;
                    fs::write(included.join("backup.conf~"), "not a profile")?;
                }
                let mut input = format!("includedir {}\n", included.display());
                for index in 1..depth {
                    let file = dir.join(format!("{index}.conf"));
                    fs::write(&file, input)?;
                    input = format!("include {}\n", file.display());
                }
                // When the real profile loader follows the directive chain.
                let result = Config::parse(&input);
                fs::remove_dir_all(dir)?;
                // Then eight edges succeed and the ninth has the typed depth error.
                match depth {
                    8 => assert_eq!(result?, Config::new()),
                    9 => assert!(matches!(
                        result,
                        Err(ConfigError::IncludeTooDeep { depth: 9, limit: 8 })
                    )),
                    _ => return Err("unexpected fixture depth".into()),
                }
            }
        }
        Ok(())
    }

    /// Final scopes block later sources and includes within their defining scopes.
    #[test]
    fn finals_cross_file_boundaries() -> Result<(), Box<dyn Error>> {
        // Given a later source attempting to append a route.
        let dir = directory()?;
        let first = dir.join("first.conf");
        let later = dir.join("later.conf");
        fs::write(&later, "[realms]\n A = {\n kdc = later\n }\n")?;
        for body in [
            format!(
                "[realms]*\n A = {{\n kdc = first\n }}\ninclude {}\n",
                later.display()
            ),
            format!(
                "[realms]\n A* = {{\n kdc = first\n include {}\n }}\n",
                later.display()
            ),
            "[realms]\n A = {\n kdc = first\n }*\n".to_owned(),
            "[realms]\n A = {\n kdc* = first\n }\n".to_owned(),
        ] {
            fs::write(&first, body)?;
            // When the source list composes.
            let config = Config::load_paths([&first, &later])?;
            // Then only the route inside the final definition is visible.
            assert_eq!(config.configured_kdcs("A")?, ["first:88"]);
        }
        fs::remove_dir_all(dir)?;
        Ok(())
    }

    /// Parent braces cannot be closed by a separate source.
    #[test]
    fn sources_cannot_balance_each_others_braces() -> Result<(), Box<dyn Error>> {
        // Given syntactically complementary but independently malformed files.
        let dir = directory()?;
        let first = dir.join("first.conf");
        let second = dir.join("second.conf");
        fs::write(&first, "[unknown]\n group = {\n")?;
        fs::write(&second, "}\n[libdefaults]\n default_realm = LATER\n")?;
        // When composing them as a source list.
        let failure = Config::load_paths([&first, &second])
            .err()
            .ok_or("cross-file brace accepted")?;
        fs::remove_dir_all(dir)?;
        // Then the unclosed first file fails independently.
        assert!(matches!(failure, ConfigError::InvalidRealmsSection(_)));
        Ok(())
    }

    /// Relative include paths are rejected before filesystem lookup.
    #[test]
    fn include_paths_must_be_absolute() -> Result<(), Box<dyn Error>> {
        // Given directives that would depend on process cwd.
        for directive in ["include relative.conf", "includedir relative"] {
            // When parsing the directive.
            let failure = Config::parse(directive)
                .err()
                .ok_or("relative include accepted")?;
            // Then the typed I/O error identifies invalid input, not a missing file.
            assert!(
                matches!(failure, ConfigError::IncludeFile { source, path: _ } if source.kind() == ErrorKind::InvalidInput)
            );
        }
        Ok(())
    }

    /// MIT's own sample supplies ordered KDCs and scalar defaults.
    #[test]
    fn mit_documentation_sample_matches_expected_values() -> Result<(), Box<dyn Error>> {
        // Given the verbatim sample from krb5-1.22.2-final krb5_conf.rst:1237-1256.
        let input = include_str!("../fixtures/profile/mit-sample.conf");
        // When reading the independent reference fixture.
        let config = Config::parse(input)?;
        // Then prof_get.c scalar selection and locate_kdc.c list selection agree.
        assert_eq!(config.libdefaults.default_realm, "ATHENA.MIT.EDU");
        assert!(config.libdefaults.dns_lookup_kdc.is_enabled());
        assert!(!config.libdefaults.dns_lookup_realm.is_enabled());
        assert_eq!(
            config.configured_kdcs("ATHENA.MIT.EDU")?,
            [
                "kerberos.mit.edu:88",
                "kerberos-1.mit.edu:88",
                "kerberos-2.mit.edu:88"
            ]
        );
        assert_eq!(
            config.configured_kdcs("EXAMPLE.COM")?,
            ["kerberos.example.com:88", "kerberos-1.example.com:88"]
        );
        Ok(())
    }
}

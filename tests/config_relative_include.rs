//! A relative `include` or `includedir` path resolves against the process's
//! working directory, as MIT's `fopen` on the token and v0.2.2 do.
//!
//! The working directory is process-global, so no test here changes it: the one
//! test re-runs itself in a child process whose working directory is a scratch
//! tree, and the child makes the assertions.

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
        env, fs, io,
        path::Path,
        process::{self, Command},
    };

    use rskrb5_ng::{Config, error::Config as Failure};

    /// Marks the child run, whose working directory is the scratch tree.
    const CHILD_ENV: &str = "RSKRB5_RELATIVE_INCLUDE_CHILD";

    /// The libtest name of the one test in this binary.
    const TEST_NAME: &str = "tests::relative_includes_follow_the_working_directory";

    /// Writes `text` to `root/name`, creating the parent directory.
    fn write(root: &Path, name: &str, text: &str) -> io::Result<()> {
        let path = root.join(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, text)
    }

    /// A `[libdefaults]` section that names the file it came from.
    fn realm(name: &str) -> String {
        format!("[libdefaults]\n default_realm = {name}\n")
    }

    /// Builds the scratch tree the child runs in.
    fn build_tree(root: &Path) -> io::Result<()> {
        write(root, "inc.conf", &realm("FROM.INC"))?;
        write(root, "dir.d/a.conf", &realm("FROM.DIR"))?;
        write(root, "main.conf", "include inc.conf\n")?;
        write(root, "sub/leaf.conf", &realm("LEAF"))?;
        // Names its target from the working directory, not from `sub/`.
        write(root, "sub/outer.conf", "include sub/leaf.conf\n")?;
        // Names its target from its own directory: `sub/leaf.conf` is not in `.`.
        write(root, "sub/sibling.conf", "include leaf.conf\n")?;
        write(root, "sub/inner.d/b.conf", &realm("INNER"))?;
        write(root, "sub/sibling_dir.conf", "includedir inner.d\n")?;
        write(root, "cyc_a.conf", "include cyc_b.conf\n")?;
        write(root, "cyc_b.conf", "include cyc_a.conf\n")?;
        for index in 0_u8..10 {
            let next = index.saturating_add(1);
            write(
                root,
                &format!("d{index}.conf"),
                &format!("include d{next}.conf\n"),
            )?;
        }
        Ok(())
    }

    /// The assertions, run with the scratch tree as the working directory.
    fn assert_cwd_resolution() -> Result<(), Box<dyn Error>> {
        // A relative `include` and `includedir` resolve against the working directory.
        assert_eq!(
            Config::parse("include inc.conf")?.libdefaults.default_realm,
            "FROM.INC"
        );
        assert_eq!(
            Config::parse("includedir dir.d")?.libdefaults.default_realm,
            "FROM.DIR"
        );
        // A reader has no base directory of its own: the working directory applies.
        assert_eq!(
            Config::from_reader(&b"include inc.conf\n"[..])?
                .libdefaults
                .default_realm,
            "FROM.INC"
        );
        // A top-level relative path and the include inside it both use the working directory.
        assert_eq!(
            Config::load_paths(["main.conf"])?.libdefaults.default_realm,
            "FROM.INC"
        );
        // A nested relative include is relative to the working directory, not the including file.
        assert_eq!(
            Config::parse("include sub/outer.conf")?
                .libdefaults
                .default_realm,
            "LEAF"
        );
        let sibling = Config::parse("include sub/sibling.conf")
            .err()
            .ok_or("sibling include resolved")?;
        assert!(
            matches!(&sibling, Failure::IncludeFile { path, source }
                if path == Path::new("leaf.conf") && source.kind() == io::ErrorKind::NotFound),
            "{sibling:?}"
        );
        let sibling_dir = Config::parse("include sub/sibling_dir.conf")
            .err()
            .ok_or("sibling includedir resolved")?;
        assert!(
            matches!(&sibling_dir, Failure::IncludeDir { path, source }
                if path == Path::new("inner.d") && source.kind() == io::ErrorKind::NotFound),
            "{sibling_dir:?}"
        );
        // A missing relative target is a not-found error of the directive's own kind.
        let missing_file = Config::parse("include missing.conf")
            .err()
            .ok_or("missing file accepted")?;
        assert!(
            matches!(&missing_file, Failure::IncludeFile { path, source }
                if path == Path::new("missing.conf") && source.kind() == io::ErrorKind::NotFound),
            "{missing_file:?}"
        );
        let missing_dir = Config::parse("includedir missing.d")
            .err()
            .ok_or("missing dir accepted")?;
        assert!(
            matches!(&missing_dir, Failure::IncludeDir { path, source }
                if path == Path::new("missing.d") && source.kind() == io::ErrorKind::NotFound),
            "{missing_dir:?}"
        );
        // Cycle detection and the depth limit hold for relative spellings.
        let cycle = Config::parse("include cyc_a.conf")
            .err()
            .ok_or("cycle accepted")?;
        assert!(
            matches!(&cycle, Failure::IncludeCycle { path: _ }),
            "{cycle:?}"
        );
        let deep = Config::parse("include d0.conf")
            .err()
            .ok_or("deep chain accepted")?;
        assert!(
            matches!(&deep, Failure::IncludeTooDeep { depth: _, limit: _ }),
            "{deep:?}"
        );
        Ok(())
    }

    /// Relative include paths use the process's working directory.
    #[test]
    fn relative_includes_follow_the_working_directory() -> Result<(), Box<dyn Error>> {
        if env::var_os(CHILD_ENV).is_some() {
            return assert_cwd_resolution();
        }
        // Given a scratch tree and a child run of this test inside it.
        let root = env::temp_dir().join(format!("rskrb5-relative-include-{}", process::id()));
        drop(fs::remove_dir_all(&root));
        build_tree(&root)?;
        // When the child resolves relative includes with the tree as its working directory.
        let output = Command::new(env::current_exe()?)
            .args([TEST_NAME, "--exact", "--nocapture", "--test-threads=1"])
            .env(CHILD_ENV, "1")
            .current_dir(&root)
            .output()?;
        fs::remove_dir_all(&root)?;
        // Then the child ran exactly this test and it passed.
        let report = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output.status.success() && report.contains("1 passed"),
            "{report}"
        );
        Ok(())
    }
}

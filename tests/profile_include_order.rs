//! Deferred profile lookahead preserves source ordering across file directives.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error::Error;
    use std::{env, fs, process};

    use rskrb5_ng::Config;

    /// Empty scalars precede included values at EOF and before another relation.
    #[test]
    fn pending_empty_scalars_precede_includes() -> Result<(), Box<dyn Error>> {
        let directory = env::temp_dir().join(format!("rskrb5-order-{}", process::id()));
        fs::create_dir_all(&directory)?;
        let child = directory.join("child.conf");
        fs::write(
            &child,
            "[libdefaults]\ndefault_realm = CHILD\n[domain_realm]\n.example = CHILD\n",
        )?;
        for (directive, path) in [
            ("include", child.as_path()),
            ("includedir", directory.as_path()),
        ] {
            for ending in ["", "other = value\n"] {
                for (section, key) in [
                    ("libdefaults", "default_realm"),
                    ("domain_realm", ".example"),
                ] {
                    for empty in ["", "\"\""] {
                        let input = format!(
                            "[{section}]\n{key} = {empty}\n{directive} {}\n{ending}",
                            path.display()
                        );
                        let config = Config::parse(&input)?;
                        let selected = if section == "libdefaults" {
                            &config.libdefaults.default_realm
                        } else {
                            config.domain_realm.get(key).ok_or("domain")?
                        };
                        assert!(
                            selected.is_empty(),
                            "earlier empty scalar lost to include: {input}"
                        );
                    }
                }
            }
        }
        fs::remove_dir_all(directory)?;
        Ok(())
    }

    /// An intervening include does not turn a next-line subsection into a scalar.
    #[test]
    fn includes_preserve_pending_subsections() -> Result<(), Box<dyn Error>> {
        let directory = env::temp_dir().join(format!("rskrb5-brace-{}", process::id()));
        fs::create_dir_all(&directory)?;
        let child = directory.join("child.conf");
        fs::write(&child, "[libdefaults]\ndefault_realm = CHILD\n")?;
        let input = format!(
            "[appdefaults]\napp =\ninclude {}\n{{\nvalue = parent\n}}\n",
            child.display()
        );
        let config = Config::parse(&input)?;
        assert_eq!(config.libdefaults.default_realm, "CHILD");
        assert_eq!(config.applications.get("app", "R", "value"), Some("parent"));
        let generic = Config::parse(&format!(
            "[custom]\nparent =\ninclude {}\ninclude {}\n{{\nvalue = retained\n}}\n",
            child.display(),
            child.display()
        ))?;
        assert_eq!(generic.libdefaults.default_realm, "CHILD");
        fs::remove_dir_all(directory)?;
        Ok(())
    }
}

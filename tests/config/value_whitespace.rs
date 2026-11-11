//! C-locale profile value and source-selection boundaries.

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

    use rskrb5_ng::{Config, error::Config as Failure};

    const UNICODE: [char; 7] = [
        '\u{a0}', '\u{2003}', '\u{202f}', '\u{3000}', '\u{85}', '\u{2028}', '\u{2029}',
    ];
    const ASCII: [char; 5] = [' ', '\t', '\r', '\u{b}', '\u{c}'];

    #[test]
    fn value_padding_uses_c_locale() -> Result<(), Box<dyn Error>> {
        for (spaces, preserves) in [(UNICODE.as_slice(), true), (ASCII.as_slice(), false)] {
            for space in spaces {
                for value in [format!("{space}Alice"), format!("Alice{space}")] {
                    let config = Config::parse(&format!("[appdefaults]\nlabel = {value}\n"))?;
                    assert_eq!(
                        config.appdefault("app", "R", "label"),
                        Some(if preserves { value.as_str() } else { "Alice" }),
                        "{value:?}"
                    );
                }
            }
        }
        Ok(())
    }

    #[test]
    fn whitespace_only_values_keep_scalar_or_scope() -> Result<(), Box<dyn Error>> {
        for space in UNICODE {
            let value = space.to_string();
            let config = Config::parse(&format!("[appdefaults]\nlabel = {space}\n"))?;
            assert_eq!(config.appdefault("app", "R", "label"), Some(value.as_str()));
        }
        for space in ASCII {
            let config = Config::parse(&format!(
                "[appdefaults]\napp = {space}\n{{\nlabel = nested\n}}\n"
            ))?;
            assert_eq!(config.appdefault("app", "R", "label"), Some("nested"));
        }
        Ok(())
    }

    #[test]
    fn subsection_openers_use_c_locale() -> Result<(), Box<dyn Error>> {
        for space in UNICODE {
            for value in [format!("{space}{{"), format!("{{{space}")] {
                let config = Config::parse(&format!("[appdefaults]\nlabel = {value}\n"))?;
                assert_eq!(config.appdefault("app", "R", "label"), Some(value.as_str()));
            }
        }
        for space in ASCII {
            let config = Config::parse(&format!(
                "[appdefaults]\napp = {space}{{{space}\nlabel = nested\n}}\n"
            ))?;
            assert_eq!(config.appdefault("app", "R", "label"), Some("nested"));
        }
        Ok(())
    }

    #[test]
    fn quoted_values_preserve_whitespace() -> Result<(), Box<dyn Error>> {
        for space in UNICODE.into_iter().chain(ASCII) {
            for value in [
                space.to_string(),
                format!("{space}Alice{space}"),
                format!("{space}{{"),
            ] {
                let config = Config::parse(&format!("[appdefaults]\nlabel = \"{value}\"\n"))?;
                assert_eq!(config.appdefault("app", "R", "label"), Some(value.as_str()));
            }
        }
        Ok(())
    }

    #[test]
    fn local_mapping_values_keep_unicode_structure() -> Result<(), Box<dyn Error>> {
        for space in UNICODE {
            for key in ["module", "include", "includedir", "krb4_get_tickets"] {
                for value in [
                    space.to_string(),
                    format!("{space}{{"),
                    format!("{{{space}"),
                ] {
                    let config = Config::parse(&format!(
                        "[realms]\nR = {{\nauth_to_local_names = {{\n{key} = {value}\n}}\n}}\n"
                    ))?;
                    assert_eq!(
                        config
                            .realm("R")
                            .ok_or("realm")?
                            .auth_to_local_names
                            .get(key),
                        Some(&value)
                    );
                }
            }
        }
        Ok(())
    }

    #[test]
    fn include_lookahead_preserves_unicode_scalars() -> Result<(), Box<dyn Error>> {
        let root = env::temp_dir().join(format!("t64-lookahead-{}", process::id()));
        fs::create_dir_all(&root)?;
        let child = root.join("child");
        fs::write(&child, "module /never/load.so\n")?;
        let mut errors = Vec::new();
        for space in UNICODE {
            let result = Config::parse(&format!(
                "[libdefaults]\nkrb4_get_tickets =\ninclude {}\n{space}\n{{\n",
                child.display()
            ));
            if !matches!(result, Err(Failure::UnsupportedDynamicModule)) {
                errors.push(format!("{space:?}: {result:?}"));
            }
        }
        fs::remove_dir_all(root)?;
        assert!(errors.is_empty(), "lookahead erased scalar: {errors:?}");
        Ok(())
    }

    #[test]
    fn include_arguments_preserve_exact_unicode_paths() -> Result<(), Box<dyn Error>> {
        let root = env::temp_dir().join(format!("t64-exact-path-{}", process::id()));
        fs::create_dir_all(&root)?;
        let mut missed = Vec::new();
        for (index, space) in UNICODE.into_iter().enumerate() {
            for directive in ["include", "includedir"] {
                let leading = format!("{space}{}", root.display());
                if !matches!(
                    Config::parse(&format!("{directive} {leading}\n")),
                    Err(Failure::IncludeFile { path, source: _ }) if path.to_str() == Some(leading.as_str())
                ) {
                    missed.push(format!("{directive}/{space:?}: leading argument changed"));
                }
                for sibling in [true, false] {
                    let plain = root.join(format!("{directive}-{index}-{sibling}"));
                    let exact = root.join(format!("{directive}-{index}-{sibling}{space}"));
                    if directive == "include" {
                        fs::write(&exact, "module /never/load.so\n")?;
                        if sibling {
                            fs::write(&plain, "[libdefaults]\ndefault_realm = WRONG\n")?;
                        }
                    } else {
                        fs::create_dir_all(&exact)?;
                        fs::write(exact.join("child.conf"), "module /never/load.so\n")?;
                        if sibling {
                            fs::create_dir_all(&plain)?;
                            fs::write(
                                plain.join("child.conf"),
                                "[libdefaults]\ndefault_realm = WRONG\n",
                            )?;
                        }
                    }
                    let result = Config::parse(&format!("{directive} {}\n", exact.display()));
                    if !matches!(result, Err(Failure::UnsupportedDynamicModule)) {
                        missed.push(format!(
                            "{directive}/{space:?}/sibling={sibling}: {result:?}"
                        ));
                    }
                }
            }
        }
        fs::remove_dir_all(root)?;
        assert!(missed.is_empty(), "wrong object selected: {missed:?}");
        Ok(())
    }

    #[test]
    fn include_arguments_accept_ascii_padding() -> Result<(), Box<dyn Error>> {
        let root = env::temp_dir().join(format!("t64-ascii-path-{}", process::id()));
        fs::create_dir_all(&root)?;
        let child = root.join("child.conf");
        fs::write(&child, "module /never/load.so\n")?;
        let mut missed = Vec::new();
        for space in ASCII {
            for (directive, target) in [("include", &child), ("includedir", &root)] {
                let result =
                    Config::parse(&format!("{directive}{space}{}{space}\n", target.display()));
                if !matches!(result, Err(Failure::UnsupportedDynamicModule)) {
                    missed.push(format!("{directive}/{space:?}: {result:?}"));
                }
            }
        }
        fs::remove_dir_all(root)?;
        assert!(missed.is_empty(), "ASCII padding: {missed:?}");
        Ok(())
    }

    #[test]
    fn profile_typed_values_reject_unicode_padding() {
        for space in UNICODE {
            for (key, value) in [
                ("allow_rc4", "true"),
                ("clockskew", "1h"),
                ("preferred_preauth_types", "17"),
            ] {
                for padded in [format!("{space}{value}"), format!("{value}{space}")] {
                    assert!(
                        Config::parse(&format!("[libdefaults]\n{key} = {padded}\n")).is_err(),
                        "{key}: {padded:?}"
                    );
                }
            }
        }
    }
}

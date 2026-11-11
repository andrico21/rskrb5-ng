//! Directive paths cannot become local principal assignments at an equals sign.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error::Error;
    use std::{env, fs, io, path::Path, process};

    use rskrb5_ng::{Config, config::ParseMode, error::Config as Failure};

    /// Exact maps and lookalike scopes must all retain real directives.
    const SCOPES: [(&str, &str); 5] = [
        ("", ""),
        ("[realms]\nR = {\nauth_to_local_names = {\n", "}\n}\n"),
        ("[plugins]\nR = {\nauth_to_local_names = {\n", "}\n}\n"),
        (
            "[realms]\nR = {\nother = {\nauth_to_local_names = {\n",
            "}\n}\n}\n",
        ),
        ("[unknown]\nouter = {\ninner = {\n", "}\n}\n"),
    ];

    /// Both include kinds enforce restrictive child policy even with equals in paths.
    #[test]
    fn include_paths_preserve_child_policy() -> Result<(), Box<dyn Error>> {
        let root = env::temp_dir().join(format!("t52-include-policy-{}", process::id()));
        let mut missed = Vec::new();
        for name in ["plain", "child=policy"] {
            let directory = root.join(name);
            fs::create_dir_all(&directory)?;
            let child = directory.join(format!("{name}.conf"));
            fs::write(&child, "[libdefaults]\nnoaddresses = false\n")?;
            for (directive, target) in [("include", &child), ("includedir", &directory)] {
                for separator in [" ", "\t"] {
                    for indent in ["", " \t"] {
                        for (prefix, suffix) in SCOPES {
                            let text = format!(
                                "{prefix}{indent}{directive}{separator}{}\n{suffix}",
                                target.display()
                            );
                            for mode in [ParseMode::Compatible, ParseMode::Strict] {
                                if !matches!(
                                    Config::parse_with_mode(&text, mode),
                                    Err(Failure::NotYetEffective {
                                        relation: "noaddresses",
                                        package: "plan 2 WP-04",
                                    })
                                ) {
                                    missed.push(format!("{mode:?}: {text}"));
                                }
                            }
                        }
                    }
                }
            }
        }
        fs::remove_dir_all(root)?;
        assert!(missed.is_empty(), "child policy bypassed: {missed:?}");
        Ok(())
    }

    /// Quoted and relative include arguments remain directives with typed path errors.
    #[test]
    fn include_arguments_remain_directives() -> Result<(), Box<dyn Error>> {
        let absolute = env::temp_dir().join("t52-policy");
        for path in [
            "relative.conf".to_owned(),
            "relative=policy.conf".to_owned(),
            format!("\"{}\"", absolute.display()),
            format!("\"{}=policy\"", absolute.display()),
        ] {
            for directive in ["include", "includedir"] {
                for separator in [" ", "\t"] {
                    for (prefix, suffix) in SCOPES {
                        let text = format!("{prefix}{directive}{separator}{path}\n{suffix}");
                        let failure = Config::parse(&text)
                            .err()
                            .ok_or_else(|| format!("directive accepted: {text}"))?;
                        assert!(
                            matches!(&failure, Failure::IncludeFile { path: actual, source }
                                if actual == Path::new(&path) && source.kind() == io::ErrorKind::InvalidInput),
                            "directive lost its path error: {text}: {failure:?}"
                        );
                    }
                }
            }
        }
        Ok(())
    }

    /// A module path containing equals is a provider declaration, not a principal.
    #[test]
    fn module_paths_remain_directives() -> Result<(), Box<dyn Error>> {
        for path in ["/never/load", "/never/load=provider"] {
            for separator in [" ", "\t"] {
                for (prefix, suffix) in SCOPES {
                    let text = format!("{prefix}module{separator}{path}\n{suffix}");
                    let failure = Config::parse(&text)
                        .err()
                        .ok_or_else(|| format!("provider declaration admitted: {text}"))?;
                    assert!(
                        matches!(failure, Failure::UnsupportedDynamicModule),
                        "provider declaration admitted: {text}"
                    );
                }
            }
        }
        Ok(())
    }
}

//! MIT bytewise section names and relation-keyword boundaries.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error::Error;

    use rskrb5_ng::{
        config::{Config, ConfigDiagnostic, ParseMode},
        error::Config as ConfigError,
    };

    const UNICODE_SPACES: [char; 19] = [
        '\u{85}', '\u{a0}', '\u{1680}', '\u{2000}', '\u{2001}', '\u{2002}', '\u{2003}', '\u{2004}',
        '\u{2005}', '\u{2006}', '\u{2007}', '\u{2008}', '\u{2009}', '\u{200a}', '\u{2028}',
        '\u{2029}', '\u{202f}', '\u{205f}', '\u{3000}',
    ];

    /// Unicode whitespace belongs to tag data, while ASCII whitespace delimits directives.
    #[test]
    fn module_keyword_uses_ascii_tag_boundaries() -> Result<(), Box<dyn Error>> {
        for space in UNICODE_SPACES {
            for keyword in ["module", "include", "includedir"] {
                let tag = format!("{keyword}{space}Alice");
                for mode in [ParseMode::Compatible, ParseMode::Strict] {
                    let config =
                        Config::parse_with_mode(&format!("[appdefaults]\n{tag} = local\n"), mode)?;
                    assert_eq!(config.appdefault("app", "R", &tag), Some("local"));
                }
            }
        }
        for space in [' ', '\t', '\u{b}', '\u{c}', '\r'] {
            for section in ["appdefaults", "unknown", "libdefaults\u{a0}"] {
                for mode in [ParseMode::Compatible, ParseMode::Strict] {
                    assert!(matches!(
                        Config::parse_with_mode(
                            &format!("[{section}]\nmodule{space}/never/load.so\n"),
                            mode,
                        ),
                        Err(ConfigError::UnsupportedDynamicModule)
                    ));
                }
            }
        }
        Ok(())
    }

    /// Padding inside brackets is section-name data and must never activate policy.
    #[test]
    fn section_names_preserve_padding_bytes() -> Result<(), Box<dyn Error>> {
        for space in [' ', '\t', '\u{b}', '\u{c}', '\r']
            .into_iter()
            .chain(UNICODE_SPACES)
        {
            for section in ["libdefaults", "appdefaults"] {
                for name in [
                    format!("{space}{section}"),
                    format!("{section}{space}"),
                    format!("{space}{section}{space}"),
                ] {
                    let text = format!("[{name}]\nallow_rc4 = true\n");
                    let config = Config::parse(&text)?;
                    assert!(!config.libdefaults.allow_rc4.is_enabled(), "{name:?}");
                    assert!(
                        config
                            .diagnostics()
                            .contains(&ConfigDiagnostic::UnknownSection {
                                section: name.clone(),
                            })
                    );
                    drop(
                        Config::parse_with_mode(&text, ParseMode::Strict)
                            .err()
                            .ok_or("strict accepted padded section")?,
                    );
                    let combined = Config::parse(&format!("{text}module\u{a0}Alice = local\n"))?;
                    assert!(
                        combined
                            .diagnostics()
                            .contains(&ConfigDiagnostic::UnknownSection { section: name })
                    );
                }
            }
        }
        for padding in ["", " ", "\t", "\u{b}", "\u{c}", "\r"] {
            let config = Config::parse_with_mode(
                &format!("{padding}[libdefaults]{padding}\nallow_rc4 = true\n"),
                ParseMode::Strict,
            )?;
            assert!(config.libdefaults.allow_rc4.is_enabled());
        }
        Ok(())
    }

    /// Only an immediate final marker and ASCII whitespace may follow a section header.
    #[test]
    fn section_header_suffix_uses_ascii_grammar() -> Result<(), Box<dyn Error>> {
        for space in UNICODE_SPACES {
            for suffix in [format!("{space}"), format!("{space}*"), format!("*{space}")] {
                for mode in [ParseMode::Compatible, ParseMode::Strict] {
                    assert!(matches!(
                        Config::parse_with_mode(&format!("[libdefaults]{suffix}\n"), mode),
                        Err(ConfigError::InvalidLine {
                            line: 1,
                            section: _,
                            text: _
                        })
                    ));
                }
            }
        }
        for space in [" ", "\t", "\u{b}", "\u{c}", "\r"] {
            assert!(matches!(
                Config::parse(&format!("[libdefaults]{space}*\n")),
                Err(ConfigError::InvalidLine {
                    line: 1,
                    section: _,
                    text: _
                })
            ));
            drop(Config::parse_with_mode(
                &format!("[libdefaults]*{space}\n"),
                ParseMode::Strict,
            )?);
        }
        Ok(())
    }
}

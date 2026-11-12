//! C-locale whitespace at the remaining profile-parser decision sites.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::{error::Error, net::IpAddr};

    use rskrb5_ng::{
        Config,
        config::section_values::Route,
        error::{Config as Failure, Policy},
    };

    const UNICODE: [char; 7] = [
        '\u{a0}', '\u{2003}', '\u{202f}', '\u{3000}', '\u{85}', '\u{2028}', '\u{2029}',
    ];
    const ASCII: [char; 5] = [' ', '\t', '\r', '\u{b}', '\u{c}'];

    /// Unicode-only or Unicode-quoted selector values are enabled, ASCII padding is disabled.
    #[test]
    fn protocol_selector_values_use_c_locale() -> Result<(), Box<dyn Error>> {
        for key in ["v4_realm", "kpasswd_unprotected"] {
            for space in UNICODE {
                for value in [space.to_string(), format!("\"{space}\"")] {
                    let result = Config::parse(&format!("[libdefaults]\n{key} = {value}\n"));
                    assert!(
                        matches!(
                            result,
                            Err(Failure::Policy(Policy::RejectedFeature {
                                feature: _,
                                reason: _
                            }))
                        ),
                        "{key} = {value:?}: {result:?}"
                    );
                }
            }
            for space in ASCII {
                let config = Config::parse(&format!("[libdefaults]\n{key} = {space}\n"))?;
                assert_eq!(config.libdefaults.default_realm, "", "{key} {space:?}");
            }
        }
        Ok(())
    }

    /// A non-structural section keeps a Unicode-only value; ASCII-only is the empty value.
    #[test]
    fn deferred_scalar_values_use_c_locale() -> Result<(), Box<dyn Error>> {
        for space in UNICODE {
            let config = Config::parse(&format!("[libdefaults]\ndefault_realm = {space}\n"))?;
            assert_eq!(config.libdefaults.default_realm, space.to_string());
        }
        for space in ASCII {
            let config = Config::parse(&format!("[libdefaults]\ndefault_realm = {space}\n"))?;
            assert_eq!(config.libdefaults.default_realm, "", "{space:?}");
        }
        Ok(())
    }

    /// A key edged by Unicode space is a different, unmatched key; ASCII padding is stripped.
    #[test]
    fn assignment_keys_use_c_locale() -> Result<(), Box<dyn Error>> {
        for space in UNICODE {
            for key in [
                format!("{space}default_realm"),
                format!("default_realm{space}"),
            ] {
                let config = Config::parse(&format!("[libdefaults]\n{key} = X\n"))?;
                assert_eq!(config.libdefaults.default_realm, "", "{key:?}");
            }
            for key in [format!("{space}kdc"), format!("kdc{space}")] {
                let config = Config::parse(&format!("[realms]\nR = {{\n{key} = host\n}}\n"))?;
                assert!(config.realm("R").ok_or("realm")?.kdc.is_empty(), "{key:?}");
            }
        }
        for space in ASCII {
            let config = Config::parse(&format!(
                "[libdefaults]\n{space}default_realm{space} = X\n[realms]\nR = {{\n{space}kdc{space} = host\n}}\n"
            ))?;
            assert_eq!(config.libdefaults.default_realm, "X", "{space:?}");
            assert_eq!(config.realm("R").ok_or("realm")?.kdc, ["host:88"]);
        }
        Ok(())
    }

    /// Capath and plugin names keep one Unicode space as bytes and reject an ASCII space.
    #[test]
    fn capath_and_plugin_names_use_c_locale() -> Result<(), Box<dyn Error>> {
        for space in UNICODE {
            let name = format!("C{space}D");
            let config = Config::parse(&format!(
                "[capaths]\nA = {{\nB = {name}\n}}\n[plugins]\nkdcpreauth = {{\ndisable = {name}\n}}\n"
            ))?;
            assert_eq!(
                config.capath("A", "B"),
                Some(&Route::Via(vec![name.clone()]))
            );
            assert_eq!(
                config
                    .plugins
                    .get("kdcpreauth")
                    .map(|plugin| plugin.disable.as_slice()),
                Some([name].as_slice())
            );
        }
        for space in ASCII {
            for text in [
                format!("[capaths]\nA = {{\nB = C{space}D\n}}\n"),
                format!("[plugins]\nkdcpreauth = {{\ndisable = C{space}D\n}}\n"),
            ] {
                let result = Config::parse(&text);
                assert!(
                    matches!(
                        result,
                        Err(Failure::InvalidLine {
                            section: _,
                            line: _,
                            text: _
                        })
                    ),
                    "{text:?}: {result:?}"
                );
            }
        }
        Ok(())
    }

    /// An inline comment starts after C-locale whitespace only; Unicode space is data.
    #[test]
    fn inline_comment_boundary_uses_c_locale() -> Result<(), Box<dyn Error>> {
        for marker in ['#', ';'] {
            for space in UNICODE {
                let value = format!("A{space}{marker}B");
                let config = Config::parse(&format!("[libdefaults]\ndefault_realm = {value}\n"))?;
                assert_eq!(config.libdefaults.default_realm, value);
            }
            for space in ASCII {
                let config = Config::parse(&format!(
                    "[libdefaults]\ndefault_realm = A{space}{marker}B\n"
                ))?;
                assert_eq!(config.libdefaults.default_realm, "A", "{space:?}");
            }
        }
        Ok(())
    }

    /// Only C-locale space before a final `*` marker is stripped; Unicode space is value data.
    #[test]
    fn final_marker_padding_uses_c_locale() -> Result<(), Box<dyn Error>> {
        for space in UNICODE {
            let config = Config::parse(&format!("[libdefaults]\ndefault_realm = A{space}*\n"))?;
            assert_eq!(config.libdefaults.default_realm, format!("A{space}"));
        }
        for space in ASCII {
            let config = Config::parse(&format!("[libdefaults]\ndefault_realm = A{space}*\n"))?;
            assert_eq!(config.libdefaults.default_realm, "A", "{space:?}");
        }
        Ok(())
    }

    /// A Unicode-only integer-list element is an invalid integer, never a dropped element.
    #[test]
    fn integer_list_elements_use_c_locale() -> Result<(), Box<dyn Error>> {
        for space in UNICODE {
            let result = Config::parse(&format!(
                "[libdefaults]\npreferred_preauth_types = 17,{space},18\n"
            ));
            assert!(
                matches!(
                    result,
                    Err(Failure::InvalidInteger {
                        line: _,
                        key: _,
                        value: _
                    })
                ),
                "{space:?}: {result:?}"
            );
        }
        for space in ASCII {
            let config = Config::parse(&format!(
                "[libdefaults]\npreferred_preauth_types = 17,{space},18\n"
            ))?;
            assert_eq!(config.libdefaults.preferred_preauth_types, [17_i32, 18_i32]);
        }
        Ok(())
    }

    /// `extra_addresses` splits on every C-locale space (MIT `isspace`), vertical tab included.
    #[test]
    fn address_list_separators_use_c_locale() -> Result<(), Box<dyn Error>> {
        let expected = [IpAddr::from([1, 2, 3, 4]), IpAddr::from([5, 6, 7, 8])];
        for space in ASCII {
            let config = Config::parse(&format!(
                "[libdefaults]\nextra_addresses = 1.2.3.4{space}5.6.7.8\n"
            ))?;
            assert_eq!(config.libdefaults.extra_addresses, expected, "{space:?}");
        }
        for space in UNICODE {
            let result = Config::parse(&format!(
                "[libdefaults]\nextra_addresses = 1.2.3.4{space}5.6.7.8\n"
            ));
            assert!(
                matches!(result, Err(Failure::InvalidAddress(_))),
                "{space:?}: {result:?}"
            );
        }
        Ok(())
    }

    /// A closing quote may be followed only by C-locale whitespace; Unicode space is text.
    #[test]
    fn closing_quote_tail_uses_c_locale() -> Result<(), Box<dyn Error>> {
        for space in UNICODE {
            let result = Config::parse(&format!("[libdefaults]\ndefault_realm = \"X\"{space}\n"));
            assert!(
                matches!(
                    result,
                    Err(Failure::InvalidLine {
                        section: _,
                        line: _,
                        text: _
                    })
                ),
                "{space:?}: {result:?}"
            );
        }
        for space in ASCII {
            let config = Config::parse(&format!("[libdefaults]\ndefault_realm = \"X\"{space}\n"))?;
            assert_eq!(config.libdefaults.default_realm, "X", "{space:?}");
        }
        Ok(())
    }
}

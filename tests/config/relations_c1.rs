//! One named table-driven contract per C1 relation.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error::Error;

    use rskrb5_ng::config::{Config, ConfigDiagnostic, ParseMode, hostname::Canonicalization};

    /// Effective relations: the first value is decoded into the typed field, later duplicates are
    /// ignored, and no deferred-consumer diagnostic is raised, so strict mode accepts them.
    fn effective(name: &str, values: &[&str]) -> Result<(), Box<dyn Error>> {
        for value in values {
            // Given a selected scalar followed by a value that must not override it.
            let text = format!("[libdefaults]\n {name} = {value}\n {name} = invalid-later\n");
            // When the profile is parsed in both modes.
            let config = Config::parse(&text)?;
            let strict = Config::parse_with_mode(&text, ParseMode::Strict)?;
            let defaults = &config.libdefaults;
            match name {
                "default_rcache_name" => assert_eq!(defaults.default_rcache_name, *value),
                "dns_canonicalize_hostname" => assert_eq!(
                    defaults.dns_canonicalize_hostname,
                    Canonicalization::parse(value)?
                ),
                "dns_lookup_realm" => {
                    assert_eq!(defaults.dns_lookup_realm.is_enabled(), *value == "true");
                }
                "dns_uri_lookup" => {
                    assert_eq!(defaults.dns_uri_lookup.is_enabled(), *value == "on");
                }
                "enforce_ok_as_delegate" => assert_eq!(
                    defaults.enforce_ok_as_delegate.is_enabled(),
                    *value == "true"
                ),
                "ignore_acceptor_hostname" => assert_eq!(
                    defaults.ignore_acceptor_hostname.is_enabled(),
                    *value == "true"
                ),
                _ => return Err(format!("unreviewed effective relation {name}").into()),
            }
            // Then no diagnostic names the relation.
            for parsed in [&config, &strict] {
                assert!(!parsed.diagnostics().iter().any(|item| matches!(item,
                    ConfigDiagnostic::NotYetEffective { relation, package: _ } if *relation == name)));
            }
        }
        Ok(())
    }

    /// `canonicalize` is effective (WP-05): it parses, raises no deferred
    /// diagnostic and strict mode accepts it; the armored AS request asks for
    /// it (tests/fast.rs `canonicalization_is_accepted_only_under_fast`).
    #[test]
    fn canonicalize() -> Result<(), Box<dyn Error>> {
        for (value, enabled) in [("true", true), ("false", false)] {
            let text = format!("[libdefaults]\n canonicalize = {value}\n");
            let config = Config::parse_with_mode(&text, ParseMode::Strict)?;
            assert_eq!(
                config.libdefaults.canonicalize.is_enabled(),
                enabled,
                "{value}"
            );
            assert!(
                !config.diagnostics().iter().any(|item| matches!(item,
                    ConfigDiagnostic::NotYetEffective { relation, package: _ } if *relation == "canonicalize")),
                "{value}"
            );
        }
        Ok(())
    }

    /// Declare independent test cases over the effective relations.
    macro_rules! effective_cases {
        ($($name:ident, [$($value:literal),+];)+) => {$ (
            /// Typed scalar contract for the named effective relation.
            #[test]
            fn $name() -> Result<(), Box<dyn Error>> {
                effective(stringify!($name), &[$($value),+])
            }
        )+};
    }

    effective_cases! {
        default_rcache_name, ["dfl:", "none:", "memory:", "file2:/var/tmp/service.rcache"];
        dns_canonicalize_hostname, ["true", "false", "FaLlBaCk"];
        dns_lookup_realm, ["true", "false"];
        dns_uri_lookup, ["on", "nil"];
        enforce_ok_as_delegate, ["true", "false"];
        ignore_acceptor_hostname, ["true", "false"];
    }

    /// Legacy permission reaches the resolved runtime policy, not just its field.
    fn legacy(name: &str, family: &str, id: i32) -> Result<(), Box<dyn Error>> {
        for (value, allowed) in [("true", true), ("false", false)] {
            // Given an explicit legacy request and matching permitted list.
            let text = format!(
                "[libdefaults]\n {name} = {value}\n permitted_enctypes = {family}\n default_tkt_enctypes = {family}\n"
            );
            // When parsing and resolving the policy.
            let result = Config::parse(&text);
            // Then the disabled branch fails and the enabled branch selects the ID.
            if allowed {
                assert_eq!(result?.libdefaults.default_tkt_enctype_ids(), [id]);
            } else {
                assert!(result.err().is_some());
            }
        }
        Ok(())
    }

    /// DES3 permission is applied by the policy consumer.
    #[test]
    fn allow_des3() -> Result<(), Box<dyn Error>> {
        legacy("allow_des3", "des3", 16)
    }
    /// RC4 permission is applied by the policy consumer.
    #[test]
    fn allow_rc4() -> Result<(), Box<dyn Error>> {
        legacy("allow_rc4", "rc4", 23)
    }

    /// Blanket weakening remains permanently refused, including MIT boolean aliases.
    #[test]
    fn allow_weak_crypto() -> Result<(), Box<dyn Error>> {
        for (value, allowed) in [("off", true), ("on", false)] {
            let result = Config::parse(&format!("[libdefaults]\n allow_weak_crypto = {value}\n"));
            if allowed {
                assert!(!result?.libdefaults.allow_weak_crypto.is_enabled());
            } else {
                assert!(result.err().is_some());
            }
        }
        Ok(())
    }

    /// Configured realm affects host resolution without replacing explicit mappings.
    #[test]
    fn default_realm() -> Result<(), Box<dyn Error>> {
        for value in ["EXAMPLE", "OTHER"] {
            let config = Config::parse(&format!(
                "[libdefaults]\n default_realm = {value}\n[domain_realm]\n host.example = MAPPED\n"
            ))?;
            assert_eq!(config.realm_for_host("unmapped.example"), Some(value));
            assert_eq!(config.realm_for_host("host.example"), Some("MAPPED"));
        }
        Ok(())
    }

    /// B2 template consumers preserve the selected typed names and expand once.
    fn name_template(name: &str) -> Result<(), Box<dyn Error>> {
        use rskrb5_ng::config::parameters::{DefaultName, ExpansionContext};
        for value in ["FILE:/first%{null}", "FILE:/second%{null}"] {
            let config = Config::parse(&format!("[libdefaults]\n {name} = {value}\n"))?;
            let kind = match name {
                "default_ccache_name" => DefaultName::Ccache,
                "default_client_keytab_name" => DefaultName::ClientKeytab,
                _ => DefaultName::Keytab,
            };
            assert_eq!(
                kind.expand(&config.libdefaults, &ExpansionContext::default())?,
                value.replace("%{null}", "")
            );
        }
        Ok(())
    }
    /// Ccache templates reach the expansion consumer.
    #[test]
    fn default_ccache_name() -> Result<(), Box<dyn Error>> {
        name_template("default_ccache_name")
    }
    /// Client keytab templates reach the expansion consumer.
    #[test]
    fn default_client_keytab_name() -> Result<(), Box<dyn Error>> {
        name_template("default_client_keytab_name")
    }
    /// Service keytab templates reach the expansion consumer.
    #[test]
    fn default_keytab_name() -> Result<(), Box<dyn Error>> {
        name_template("default_keytab_name")
    }

    /// Clock parsing reaches both available reply-validation option consumers.
    #[test]
    fn clockskew() -> Result<(), Box<dyn Error>> {
        use core::time::Duration;
        for (value, seconds) in [("1-02:03:04", 93_784), ("1h-30m", 1_800)] {
            let config = Config::parse(&format!("[libdefaults]\n clockskew = {value}\n"))?;
            assert_eq!(config.libdefaults.clockskew, Duration::from_secs(seconds));
            #[cfg(feature = "messages")]
            {
                use std::time::UNIX_EPOCH;

                use rskrb5_ng::client::options::{AsReq, TgsReq};
                assert_eq!(
                    AsReq::from_libdefaults(UNIX_EPOCH, 1, &config.libdefaults)?.clock_skew(),
                    Duration::from_secs(seconds)
                );
                assert_eq!(
                    TgsReq::from_libdefaults(UNIX_EPOCH, 1, &config.libdefaults)?.clock_skew(),
                    Duration::from_secs(seconds)
                );
            }
        }
        Ok(())
    }

    /// Enctype relations resolve ordered expressions into request selections.
    fn enctypes(name: &str) -> Result<(), Box<dyn Error>> {
        for (value, expected) in [
            ("aes128-sha1", vec![17_i32]),
            ("DEFAULT -aes256-sha2", vec![19_i32, 18_i32, 17_i32]),
        ] {
            let config = Config::parse(&format!("[libdefaults]\n {name} = {value}\n"))?;
            let ids = if name == "default_tkt_enctypes" {
                config.libdefaults.default_tkt_enctype_ids()
            } else {
                config.libdefaults.default_tgs_enctype_ids()
            };
            assert_eq!(ids, expected);
            #[cfg(feature = "messages")]
            {
                use std::time::UNIX_EPOCH;

                use rskrb5_ng::client::options::{AsReq, TgsReq};
                let request_ids = if name == "default_tkt_enctypes" {
                    AsReq::from_libdefaults(UNIX_EPOCH, 1, &config.libdefaults)?
                        .etypes()
                        .to_vec()
                } else {
                    TgsReq::from_libdefaults(UNIX_EPOCH, 1, &config.libdefaults)?
                        .etypes()
                        .to_vec()
                };
                assert_eq!(request_ids, expected);
            }
        }
        Ok(())
    }
    /// AS encryption expressions reach checked request IDs.
    #[test]
    fn default_tkt_enctypes() -> Result<(), Box<dyn Error>> {
        enctypes("default_tkt_enctypes")
    }
    /// TGS encryption expressions reach checked request IDs.
    #[test]
    fn default_tgs_enctypes() -> Result<(), Box<dyn Error>> {
        enctypes("default_tgs_enctypes")
    }

    /// DNS lookup policy retains both branches for the SRV consumer.
    #[test]
    fn dns_lookup_kdc() -> Result<(), Box<dyn Error>> {
        for (value, expected) in [("on", true), ("off", false)] {
            let config = Config::parse(&format!("[libdefaults]\n dns_lookup_kdc = {value}\n"))?;
            assert_eq!(config.libdefaults.dns_lookup_kdc.is_enabled(), expected);
            assert!(
                config.diagnostics().is_empty(),
                "effective relation must not be diagnosed"
            );
        }
        Ok(())
    }

    /// Forwardable's scalar supports the full MIT vocabulary.
    #[test]
    fn forwardable() -> Result<(), Box<dyn Error>> {
        for (value, expected) in [("on", true), ("nil", false)] {
            let config = Config::parse(&format!("[libdefaults]\n forwardable = {value}\n"))?;
            assert_eq!(config.libdefaults.forwardable.is_enabled(), expected);
        }
        Ok(())
    }

    /// `ccache_type` is effective: undiagnosed in both modes, and the output
    /// version of new caches (`CacheVersion::from_libdefaults`) is 1 to 4 only.
    #[test]
    fn ccache_type() -> Result<(), Box<dyn Error>> {
        use rskrb5_ng::ccache::stores::CacheVersion;
        for (value, expected) in [
            ("4", Some(4_u8)),
            ("+3", Some(3)),
            ("1", Some(1)),
            ("-1", None),
            ("2147483647", None),
        ] {
            let text = format!("[libdefaults]\n ccache_type = {value}\n");
            let config = Config::parse_with_mode(&text, ParseMode::Strict)?;
            assert!(config.diagnostics().is_empty(), "{value} was diagnosed");
            let version = CacheVersion::from_libdefaults(&config.libdefaults).ok();
            assert_eq!(version.map(CacheVersion::get), expected, "{value}");
        }
        Ok(())
    }
}

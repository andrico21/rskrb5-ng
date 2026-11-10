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

    use rskrb5_ng::config::{Config, ConfigDiagnostic, ParseMode};

    /// Exercise production diagnostics, strict promotion, and first-value selection.
    fn deferred(name: &str, values: &[&str], package: &str) -> Result<(), Box<dyn Error>> {
        for value in values {
            // Given a selected scalar followed by a value that must not override it.
            let text = format!("[libdefaults]\n {name} = {value}\n {name} = invalid-later\n");
            // When the compatible parser classifies the selected relation.
            let config = Config::parse(&text)?;
            let defaults = &config.libdefaults;
            match name {
                "canonicalize" => assert_eq!(defaults.canonicalize.is_enabled(), *value == "true"),
                "ccache_type" => assert_eq!(defaults.ccache_type, value.parse::<i32>()?),
                "default_rcache_name" => assert_eq!(defaults.default_rcache_name, *value),
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
                "err_fmt" => assert_eq!(defaults.err_fmt, *value),
                "ignore_acceptor_hostname" => assert_eq!(
                    defaults.ignore_acceptor_hostname.is_enabled(),
                    *value == "true"
                ),
                "extra_addresses" => assert_eq!(defaults.extra_addresses.len(), 2),
                _ => {}
            }
            // Then the precise deferred package is exposed and strict mode refuses it.
            assert!(config.diagnostics().iter().any(|item| matches!(item,
                ConfigDiagnostic::NotYetEffective { relation, package: owner } if *relation == name && *owner == package)));
            assert!(
                Config::parse_with_mode(&text, ParseMode::Strict)
                    .err()
                    .is_some()
            );
        }
        Ok(())
    }

    /// Declare independent test cases over the same diagnostic contract.
    macro_rules! deferred_cases {
        ($($name:ident, $package:literal, [$($value:literal),+];)+) => {$ (
            /// Typed scalar and diagnostic contract for the named relation.
            #[test]
            fn $name() -> Result<(), Box<dyn Error>> {
                deferred(stringify!($name), &[$($value),+], $package)
            }
        )+};
    }

    deferred_cases! {
        canonicalize, "plan 2 WP-04", ["true", "false"];
        ccache_type, "plan 2 WP-09", ["4", "+3", "-1", "2147483647"];
        default_rcache_name, "plan 2 WP-20", ["none:"];
        dns_canonicalize_hostname, "plan 2 WP-10", ["true", "false", "FaLlBaCk"];
        dns_lookup_realm, "plan 2 WP-10", ["true", "false"];
        dns_uri_lookup, "plan 2 WP-10", ["on", "nil"];
        enforce_ok_as_delegate, "plan 2 WP-12", ["true", "false"];
        err_fmt, "plan 2 WP-18", ["%C: %M", "custom"];
        extra_addresses, "plan 2 WP-04", ["127.0.0.1, ::1", "192.0.2.1 192.0.2.2"];
        ignore_acceptor_hostname, "plan 2 WP-12", ["true", "false"];
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
}

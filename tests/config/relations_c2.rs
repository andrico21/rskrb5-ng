//! Table-driven C2 scalar, diagnostic and existing-consumer contracts.

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

    /// Selected deferred values retain their type and name the missing package.
    fn deferred(name: &str, values: &[&str], package: &str) -> Result<(), Box<dyn Error>> {
        for value in values {
            // Given a first scalar and an ignored duplicate, when parsed, then diagnose.
            let text = format!("[libdefaults]\n {name} = {value}\n {name} = invalid-later\n");
            let config = Config::parse(&text)?;
            assert!(config.diagnostics().iter().any(|item| matches!(item, ConfigDiagnostic::NotYetEffective { relation, package: owner } if *relation == name && *owner == package)));
            drop(
                Config::parse_with_mode(&text, ParseMode::Strict)
                    .err()
                    .ok_or("strict accepted deferred relation")?,
            );
            let defaults = &config.libdefaults;
            match name {
                "k5login_authoritative" => assert_eq!(
                    defaults.k5login_authoritative.is_enabled(),
                    *value == "true"
                ),
                "k5login_directory" => assert_eq!(defaults.k5login_directory, *value),
                "plugin_base_dir" => assert_eq!(defaults.plugin_base_dir, *value),
                "kdc_timesync" => assert_eq!(defaults.kdc_time_sync, value.parse::<i32>()?),
                "noaddresses" => assert!(defaults.no_addresses.is_enabled()),
                "spake_preauth_groups" => {
                    assert_eq!(defaults.spake_preauth_groups, ["edwards25519", "P-256"]);
                }
                "preferred_preauth_types" => {
                    assert_eq!(defaults.preferred_preauth_types, [17_i32, 16_i32]);
                    assert!(
                        config
                            .diagnostics()
                            .contains(&ConfigDiagnostic::IgnoredPreauthType { id: 14_i32 })
                    );
                    assert!(
                        config
                            .diagnostics()
                            .contains(&ConfigDiagnostic::IgnoredPreauthType { id: 15_i32 })
                    );
                }
                _ => return Err(format!("missing typed assertion {name}").into()),
            }
        }
        Ok(())
    }

    /// Effective relations: typed value, ignored duplicates, no diagnostic in either mode.
    fn effective(name: &str, values: &[&str]) -> Result<(), Box<dyn Error>> {
        for value in values {
            // Given a first scalar and an ignored duplicate.
            let text = format!("[libdefaults]\n {name} = {value}\n {name} = invalid-later\n");
            // When parsed in both modes, then the typed field holds the first value.
            let config = Config::parse(&text)?;
            let strict = Config::parse_with_mode(&text, ParseMode::Strict)?;
            let defaults = &config.libdefaults;
            match name {
                "qualify_shortname" => {
                    assert_eq!(defaults.qualify_shortname.as_deref(), Some(*value));
                }
                "realm_try_domains" => {
                    assert_eq!(defaults.realm_try_domains, value.parse::<i32>()?);
                }
                "kcm_mach_service" => assert_eq!(defaults.kcm_mach_service, *value),
                "rdns" => assert_eq!(defaults.rdns.is_enabled(), *value == "true"),
                "request_timeout" => assert_eq!(
                    defaults.request_timeout.as_secs(),
                    u64::from(*value == "1s")
                ),
                _ => return Err(format!("unreviewed effective relation {name}").into()),
            }
            // And no diagnostic names the relation.
            for parsed in [&config, &strict] {
                assert!(!parsed.diagnostics().iter().any(|item| matches!(item, ConfigDiagnostic::NotYetEffective { relation, package: _ } if *relation == name)));
            }
        }
        Ok(())
    }

    /// Independent named tests over the effective scalar contract.
    macro_rules! effective_cases {
        ($($name:ident, [$($value:literal),+];)+) => {$ (
            /// The named effective relation retains its typed scalar.
            #[test]
            fn $name() -> Result<(), Box<dyn Error>> {
                effective(stringify!($name), &[$($value),+])
            }
        )+};
    }
    effective_cases! {
        kcm_mach_service, ["org.example.kcm", "-"];
        qualify_shortname, ["", "example.test"];
        rdns, ["true", "false"];
        realm_try_domains, ["-1", "0", "2"];
        request_timeout, ["0", "0s", "1s"];
    }

    /// Independent named tests over the common scalar/diagnostic contract.
    macro_rules! deferred_cases {
        ($($name:ident, $package:literal, [$($value:literal),+];)+) => {$ (
            /// The named relation retains its typed scalar and deferred package.
            #[test]
            fn $name() -> Result<(), Box<dyn Error>> {
                deferred(stringify!($name), &[$($value),+], $package)
            }
        )+};
    }
    deferred_cases! {
        plugin_base_dir, "plan 2 WP-16", ["/never-load", "%{LIBDIR}/krb5/plugins"];
    }

    /// `client_aware_channel_bindings` is effective (consumer
    /// `gss::InitiatorOptions::from_config`): both values parse in both modes
    /// without a deferred diagnostic.
    #[test]
    fn client_aware_channel_bindings() -> Result<(), Box<dyn Error>> {
        for mode in [ParseMode::Compatible, ParseMode::Strict] {
            for (value, enabled) in [("true", true), ("false", false), ("off", false)] {
                // Given an explicit value, when parsed, then it is kept with no diagnostic.
                let config = Config::parse_with_mode(
                    &format!("[libdefaults]\n client_aware_channel_bindings = {value}\n"),
                    mode,
                )?;
                assert_eq!(
                    config
                        .libdefaults
                        .client_aware_channel_bindings
                        .is_enabled(),
                    enabled,
                    "{value}"
                );
                assert!(!config.diagnostics().iter().any(|item| matches!(
                    item,
                    ConfigDiagnostic::NotYetEffective {
                        relation: "client_aware_channel_bindings",
                        package: _
                    }
                )));
            }
        }
        Ok(())
    }

    /// `verify_ap_req_nofail` is effective (consumer `Tokio::verify_init_creds`).
    ///
    /// Both values parse in both modes without a deferred diagnostic, and the
    /// profile records that it was set, since unset requires verification.
    #[test]
    fn verify_ap_req_nofail() -> Result<(), Box<dyn Error>> {
        for mode in [ParseMode::Compatible, ParseMode::Strict] {
            for (value, enabled) in [("true", true), ("false", false), ("off", false)] {
                // Given an explicit value, when parsed, then it is kept and marked explicit.
                let config = Config::parse_with_mode(
                    &format!("[libdefaults]\n verify_ap_req_nofail = {value}\n"),
                    mode,
                )?;
                let defaults = &config.libdefaults;
                assert_eq!(
                    defaults.verify_ap_req_nofail.is_enabled(),
                    enabled,
                    "{value}"
                );
                assert!(
                    defaults.verify_ap_req_nofail_explicit.is_enabled(),
                    "{value}"
                );
                assert!(!config.diagnostics().iter().any(|item| matches!(
                    item,
                    ConfigDiagnostic::NotYetEffective {
                        relation: "verify_ap_req_nofail",
                        package: _
                    }
                )));
            }
        }
        // And an unset relation stays unset.
        assert!(
            !Config::parse("")?
                .libdefaults
                .verify_ap_req_nofail_explicit
                .is_enabled()
        );
        Ok(())
    }

    /// Profile bit masks enter the request-options consumer.
    #[test]
    fn kdc_default_options() -> Result<(), Box<dyn Error>> {
        for (text, expected) in [("16", 16_u32), ("0x20", 32_u32), ("32", 32_u32)] {
            let config = Config::parse(&format!("[libdefaults]\n kdc_default_options = {text}\n"))?;
            assert_eq!(config.libdefaults.kdc_default_options, expected);
            #[cfg(feature = "messages")]
            {
                use std::time::UNIX_EPOCH;

                use rskrb5_ng::client::options::AsReq;
                assert_eq!(
                    AsReq::from_libdefaults(UNIX_EPOCH, 1, &config.libdefaults)?.kdc_option_bits(),
                    expected
                );
            }
        }
        Ok(())
    }

    /// Permitted expressions constrain both default request lists.
    #[test]
    fn permitted_enctypes() -> Result<(), Box<dyn Error>> {
        for (text, expected) in [("aes128-sha1", vec![17_i32]), ("aes256-sha2", vec![20_i32])] {
            let config = Config::parse(&format!("[libdefaults]\n permitted_enctypes = {text}\n"))?;
            assert_eq!(config.libdefaults.default_tkt_enctype_ids(), expected);
            assert_eq!(config.libdefaults.default_tgs_enctype_ids(), expected);
        }
        Ok(())
    }

    /// Lifetimes retain MIT intervals and reach the existing options consumers.
    fn lifetime(name: &str) -> Result<(), Box<dyn Error>> {
        for (text, seconds) in [("1-02:03:04", 93_784_u64), ("2h", 7_200_u64)] {
            let config = Config::parse(&format!("[libdefaults]\n {name} = {text}\n"))?;
            let actual = if name == "ticket_lifetime" {
                config.libdefaults.ticket_lifetime
            } else {
                config.libdefaults.renew_lifetime
            };
            assert_eq!(actual.as_secs(), seconds);
            #[cfg(feature = "messages")]
            {
                use std::time::UNIX_EPOCH;

                use rskrb5_ng::client::options::{AsReq, TgsReq};
                let initial = AsReq::from_libdefaults(UNIX_EPOCH, 1, &config.libdefaults)?;
                let service = TgsReq::from_libdefaults(UNIX_EPOCH, 1, &config.libdefaults)?;
                if name == "ticket_lifetime" {
                    assert_eq!(initial.ticket_lifetime(), actual);
                    assert_eq!(service.ticket_lifetime(), actual);
                } else {
                    assert_eq!(initial.renew_lifetime(), Some(actual));
                    assert_eq!(service.renew_lifetime(), Some(actual));
                }
            }
        }
        Ok(())
    }
    /// Ticket lifetime is consumed by initial and service requests.
    #[test]
    fn ticket_lifetime() -> Result<(), Box<dyn Error>> {
        lifetime("ticket_lifetime")
    }
    /// Renewable lifetime is consumed by initial and service requests.
    #[test]
    fn renew_lifetime() -> Result<(), Box<dyn Error>> {
        lifetime("renew_lifetime")
    }

    /// Proxiable retains the configured bit; request/wire tests cover application.
    #[test]
    fn proxiable() -> Result<(), Box<dyn Error>> {
        for (text, expected) in [("on", true), ("nil", false)] {
            let config = Config::parse(&format!("[libdefaults]\n proxiable = {text}\n"))?;
            assert_eq!(config.libdefaults.proxiable.is_enabled(), expected);
        }
        Ok(())
    }

    /// UDP preference remains a signed integer, interpreted by Auto transport.
    #[test]
    fn udp_preference_limit() -> Result<(), Box<dyn Error>> {
        for value in [-1_i32, 0_i32, 1_i32, 1465_i32, 32_701_i32] {
            let config =
                Config::parse(&format!("[libdefaults]\n udp_preference_limit = {value}\n"))?;
            assert_eq!(config.libdefaults.udp_preference_limit, value);
        }
        Ok(())
    }

    /// `kcm_socket` is effective: undiagnosed in both modes, `-` disables the
    /// Unix socket transport, and any other value names the daemon socket.
    #[cfg(unix)]
    #[test]
    fn kcm_socket() -> Result<(), Box<dyn Error>> {
        use std::path::Path;

        use rskrb5_ng::{ccache::kcm::Store, error::Kcm};
        for (value, expected) in [("/run/kcm.sock", Some("/run/kcm.sock")), ("-", None)] {
            let text = format!("[libdefaults]\n kcm_socket = {value}\n");
            let config = Config::parse_with_mode(&text, ParseMode::Strict)?;
            assert!(config.diagnostics().is_empty(), "{value} was diagnosed");
            match (Store::from_libdefaults(&config.libdefaults), expected) {
                (Ok(store), Some(path)) => {
                    assert_eq!(store.socket().and_then(Path::to_str), Some(path));
                }
                (Err(Kcm::NoServer), None) => {}
                (other, _) => return Err(format!("{value}: {other:?}").into()),
            }
        }
        Ok(())
    }
}

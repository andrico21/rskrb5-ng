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
                "kcm_mach_service" => assert_eq!(defaults.kcm_mach_service, *value),
                "kcm_socket" => assert_eq!(defaults.kcm_socket, *value),
                "plugin_base_dir" => assert_eq!(defaults.plugin_base_dir, *value),
                "qualify_shortname" => {
                    assert_eq!(defaults.qualify_shortname.as_deref(), Some(*value));
                }
                "kdc_timesync" => assert_eq!(defaults.kdc_time_sync, value.parse::<i32>()?),
                "realm_try_domains" => {
                    assert_eq!(defaults.realm_try_domains, value.parse::<i32>()?);
                }
                "rdns" => assert_eq!(defaults.rdns.is_enabled(), *value == "true"),
                "noaddresses" => assert!(defaults.no_addresses.is_enabled()),
                "request_timeout" => assert_eq!(defaults.request_timeout.as_secs(), 0),
                "verify_ap_req_nofail" => assert!(!defaults.verify_ap_req_nofail.is_enabled()),
                "client_aware_channel_bindings" => {
                    assert!(!defaults.client_aware_channel_bindings.is_enabled());
                }
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
        k5login_authoritative, "plan 2 WP-17", ["true", "false"];
        k5login_directory, "plan 2 WP-17", ["/first", "/second"];
        kcm_mach_service, "plan 2 WP-09", ["org.example.kcm", "-"];
        kcm_socket, "plan 2 WP-09", ["/socket", "-"];
        kdc_timesync, "plan 2 WP-04", ["0", "1", "2"];
        noaddresses, "plan 2 WP-04", ["true", "yes"];
        plugin_base_dir, "plan 2 WP-16", ["/never-load", "%{LIBDIR}/krb5/plugins"];
        preferred_preauth_types, "plan 2 WP-04", ["17,16,15,14", "17 16 14 15"];
        qualify_shortname, "plan 2 WP-10", ["", "example.test"];
        rdns, "plan 2 WP-10", ["true", "false"];
        realm_try_domains, "plan 2 WP-10", ["-1", "0", "2"];
        request_timeout, "plan 2 WP-10", ["0", "0s"];
        spake_preauth_groups, "plan 2 WP-07", ["edwards25519,P-256", "EDWARDS25519 p-256"];
        verify_ap_req_nofail, "plan 2 WP-11", ["false", "off"];
        client_aware_channel_bindings, "plan 2 WP-12", ["false", "off"];
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
}

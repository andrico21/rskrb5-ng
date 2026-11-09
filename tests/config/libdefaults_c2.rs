//! C2 fail-closed and typed parsing regressions.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error::Error;

    use rskrb5_ng::config::{Config, ParseMode};

    /// Unsupported restrictions cannot silently disappear in either mode.
    #[test]
    fn restrictions_fail_closed() -> Result<(), Box<dyn Error>> {
        for mode in [ParseMode::Compatible, ParseMode::Strict] {
            for assignment in [
                "noaddresses = false",
                "request_timeout = 1s",
                "verify_ap_req_nofail = true",
                "client_aware_channel_bindings = true",
            ] {
                // Given a stronger requested policy, when parsed, then reject it.
                drop(
                    Config::parse_with_mode(&format!("[libdefaults]\n {assignment}\n"), mode)
                        .err()
                        .ok_or_else(|| format!("accepted {assignment}"))?,
                );
            }
        }
        Ok(())
    }

    /// New scalar relations and MIT intervals reject malformed values.
    #[test]
    fn malformed_values_fail_at_boundary() -> Result<(), Box<dyn Error>> {
        for assignment in [
            "request_timeout = nonsense",
            "client_aware_channel_bindings = maybe",
            "spake_preauth_groups = unknown",
            "ticket_lifetime = 1h2h",
            "renew_lifetime = 1 2",
        ] {
            drop(
                Config::parse(&format!("[libdefaults]\n {assignment}\n"))
                    .err()
                    .ok_or_else(|| format!("accepted {assignment}"))?,
            );
        }
        Ok(())
    }

    /// Every C2 numeric and boolean boundary rejects malformed scalars in both modes.
    #[test]
    fn all_scalar_errors_are_typed() -> Result<(), Box<dyn Error>> {
        use rskrb5_ng::error::Config as Failure;
        for mode in [ParseMode::Compatible, ParseMode::Strict] {
            for name in [
                "k5login_authoritative",
                "noaddresses",
                "proxiable",
                "rdns",
                "verify_ap_req_nofail",
                "client_aware_channel_bindings",
            ] {
                let failure =
                    Config::parse_with_mode(&format!("[libdefaults]\n {name} = maybe\n"), mode)
                        .err()
                        .ok_or("boolean accepted")?;
                assert!(matches!(failure, Failure::InvalidBoolean(value) if value == "maybe"));
            }
            for name in [
                "kdc_default_options",
                "kdc_timesync",
                "realm_try_domains",
                "udp_preference_limit",
                "preferred_preauth_types",
            ] {
                let failure = Config::parse_with_mode(
                    &format!("[libdefaults]\n {name} = 2147483648\n"),
                    mode,
                )
                .err()
                .ok_or("integer accepted")?;
                assert!(
                    matches!(failure, Failure::InvalidInteger { line: 2, key, value } if key == name && value == "2147483648")
                );
            }
            for name in ["renew_lifetime", "request_timeout", "ticket_lifetime"] {
                for value in ["-1", "1:000", "1m2h", "2147483648"] {
                    let failure = Config::parse_with_mode(
                        &format!("[libdefaults]\n {name} = {value}\n"),
                        mode,
                    )
                    .err()
                    .ok_or("duration accepted")?;
                    assert!(matches!(failure, Failure::InvalidDuration(text) if text == value));
                }
            }
        }
        Ok(())
    }

    /// Explicit empty suffix/group selections remain distinct from omitted defaults.
    #[test]
    fn empty_lists_and_suffixes_are_preserved() -> Result<(), Box<dyn Error>> {
        for body in [
            "qualify_shortname = \"\"\n spake_preauth_groups = \"\"",
            "qualify_shortname =\n spake_preauth_groups =",
        ] {
            let config = Config::parse(&format!("[libdefaults]\n {body}\n"))?;
            assert_eq!(config.libdefaults.qualify_shortname.as_deref(), Some(""));
            assert!(
                config.libdefaults.spake_preauth_groups.is_empty(),
                "empty group policy retained"
            );
        }
        Ok(())
    }

    /// Decimal KDC options match MIT's integer profile getter.
    #[test]
    fn options_are_decimal() -> Result<(), Box<dyn Error>> {
        for (value, expected) in [("16", 16_u32), ("32", 32_u32)] {
            let config =
                Config::parse(&format!("[libdefaults]\n kdc_default_options = {value}\n"))?;
            assert_eq!(config.libdefaults.kdc_default_options, expected);
        }
        Ok(())
    }

    /// Proxiable reaches both request consumers instead of remaining parse-only.
    #[cfg(feature = "messages")]
    #[test]
    fn proxiable_reaches_requests() -> Result<(), Box<dyn Error>> {
        use std::time::UNIX_EPOCH;

        use rasn::der;
        use rskrb5_ng::{
            Principal,
            client::{
                build_tgt_as_req,
                options::{AsReq, TgsReq},
            },
        };
        for (value, expected) in [("on", 0x1000_0000_u32), ("off", 0)] {
            let config = Config::parse(&format!("[libdefaults]\n proxiable = {value}\n"))?;
            assert_eq!(
                AsReq::from_libdefaults(UNIX_EPOCH, 1, &config.libdefaults).kdc_option_bits()
                    & 0x1000_0000,
                expected
            );
            assert_eq!(
                TgsReq::from_libdefaults(UNIX_EPOCH, 1, &config.libdefaults).kdc_option_bits()
                    & 0x1000_0000,
                expected
            );
            let request = build_tgt_as_req(
                Principal::user("EXAMPLE", "user"),
                AsReq::from_libdefaults(UNIX_EPOCH, 1, &config.libdefaults),
            )?;
            let decoded: rasn_kerberos::AsReq = der::decode(request.der())?;
            assert_eq!(
                decoded.0.req_body.kdc_options.0.get(3).map(|bit| *bit),
                Some(expected != 0)
            );
        }
        Ok(())
    }
}

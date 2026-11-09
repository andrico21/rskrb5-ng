//! C1 typed boundary failures and wire-option consumers.

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
        config::{Config, ParseMode, hostname::Canonicalization},
        error::Config as Failure,
    };

    /// Every C1 boolean relation rejects malformed input before classification.
    #[test]
    fn booleans_reject_invalid_values() -> Result<(), Box<dyn Error>> {
        for name in [
            "allow_des3",
            "allow_rc4",
            "allow_weak_crypto",
            "canonicalize",
            "dns_lookup_kdc",
            "dns_lookup_realm",
            "dns_uri_lookup",
            "enforce_ok_as_delegate",
            "forwardable",
            "ignore_acceptor_hostname",
        ] {
            for value in ["maybe", "2", "", "enabled"] {
                let result = Config::parse(&format!("[libdefaults]\n {name} = {value}\n"));
                let failure = result.err().ok_or("invalid boolean accepted")?;
                assert!(
                    matches!(failure, Failure::InvalidBoolean(text) if text == value),
                    "{name}={value}"
                );
            }
        }
        Ok(())
    }

    /// Cache version syntax is signed decimal i32, not a version enum or hex.
    #[test]
    fn cache_integers_reject_invalid_values() -> Result<(), Box<dyn Error>> {
        for value in ["0x4", "4junk", "2147483648", "-2147483649", ""] {
            let result = Config::parse(&format!("[libdefaults]\n ccache_type = {value}\n"));
            let failure = result.err().ok_or("invalid integer accepted")?;
            assert!(
                matches!(failure, Failure::InvalidInteger { line: 2, key, value: text } if key == "ccache_type" && text == value)
            );
        }
        Ok(())
    }

    /// Persistent replay and address binding fail closed independently of mode/order.
    #[test]
    fn stricter_policies_name_the_missing_consumer() -> Result<(), Box<dyn Error>> {
        for mode in [ParseMode::Compatible, ParseMode::Strict] {
            for (body, relation, package) in [
                (
                    "default_rcache_name = dfl:",
                    "default_rcache_name",
                    "plan 2 WP-20",
                ),
                (
                    "default_rcache_name = file2:/cache",
                    "default_rcache_name",
                    "plan 2 WP-20",
                ),
                (
                    "noaddresses = false\n extra_addresses = 192.0.2.1",
                    "extra_addresses",
                    "plan 2 WP-04",
                ),
                (
                    "extra_addresses = 192.0.2.1\n noaddresses = false",
                    "extra_addresses",
                    "plan 2 WP-04",
                ),
            ] {
                let result = Config::parse_with_mode(&format!("[libdefaults]\n {body}\n"), mode);
                let failure = result.err().ok_or("stricter policy accepted")?;
                assert!(
                    matches!(failure, Failure::NotYetEffective { relation: key, package: owner } if key == relation && owner == package)
                );
            }
        }
        Ok(())
    }

    /// The third hostname mode survives both the typed boundary and serde.
    #[test]
    fn hostname_modes_remain_distinct() -> Result<(), Box<dyn Error>> {
        for (value, expected) in [
            ("false", Canonicalization::Never),
            ("true", Canonicalization::Always),
            ("FaLlBaCk", Canonicalization::Fallback),
        ] {
            let config = Config::parse(&format!(
                "[libdefaults]\n dns_canonicalize_hostname = {value}\n"
            ))?;
            assert_eq!(config.libdefaults.dns_canonicalize_hostname, expected);
            #[cfg(feature = "serde")]
            {
                let text = serde_json::to_string(&expected)?;
                assert_eq!(serde_json::from_str::<Canonicalization>(&text)?, expected);
            }
        }
        assert!(
            Config::parse("[libdefaults]\n dns_canonicalize_hostname = sometimes\n")
                .err()
                .is_some()
        );
        Ok(())
    }

    /// A disabled DNS relation stops endpoint discovery before resolver access.
    #[cfg(feature = "tokio")]
    #[test]
    fn disabled_dns_reaches_discovery_consumer() -> Result<(), Box<dyn Error>> {
        use rskrb5_ng::{
            client::transport::{KdcProtocol, Tokio},
            error::Client as ClientFailure,
        };
        use tokio::runtime::Builder;
        let runtime = Builder::new_current_thread().enable_all().build()?;
        for value in ["false", "off", "nil"] {
            let config = Config::parse(&format!("[libdefaults]\n dns_lookup_kdc = {value}\n"))?;
            let result = runtime.block_on(Tokio::new().discover_kdcs(
                &config,
                "UNCONFIGURED",
                KdcProtocol::Tcp,
            ));
            assert!(
                matches!(result, Err(ClientFailure::Config(Failure::NoRealm(realm))) if realm == "UNCONFIGURED")
            );
        }
        Ok(())
    }

    /// Profile options affect encoded AS requests, not only intermediate fields.
    #[cfg(feature = "messages")]
    #[test]
    fn profile_options_reach_as_wire() -> Result<(), Box<dyn Error>> {
        use std::time::UNIX_EPOCH;

        use rasn::der;
        use rskrb5_ng::{
            Principal,
            client::{build_tgt_as_req, options::AsReq},
        };
        for (value, enabled) in [("true", true), ("false", false)] {
            let config = Config::parse(&format!(
                "[libdefaults]\n forwardable = {value}\n canonicalize = {value}\n default_tkt_enctypes = aes128-sha1\n"
            ))?;
            let request = build_tgt_as_req(
                Principal::user("EXAMPLE", "user"),
                AsReq::from_libdefaults(UNIX_EPOCH, 7, &config.libdefaults),
            )?;
            let decoded: rasn_kerberos::AsReq = der::decode(request.der())?;
            assert_eq!(decoded.0.req_body.etype, vec![17_i32]);
            assert_eq!(
                decoded.0.req_body.kdc_options.0.get(1).map(|bit| *bit),
                Some(enabled)
            );
            assert_eq!(
                decoded.0.req_body.kdc_options.0.get(15).map(|bit| *bit),
                Some(false)
            );
        }
        Ok(())
    }
}

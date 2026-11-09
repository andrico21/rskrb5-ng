//! C1 profile parsing regressions against MIT's scalar grammar.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::{error::Error as StdError, time::Duration};

    use rskrb5_ng::config::{Config, ParseMode};

    /// MIT's on/off/nil spellings must reach the typed field.
    #[test]
    fn boolean_vocabulary_when_profile_scalar() -> Result<(), Box<dyn StdError>> {
        // Given MIT booleans and the retained gokrb5 f spelling.
        for (text, expected) in [("ON", true), ("off", false), ("nil", false), ("f", false)] {
            // When parsing a real relation.
            let config = Config::parse(&format!("[libdefaults]\n forwardable = {text}\n"))?;
            // Then the boolean is not ignored or inverted.
            assert_eq!(config.libdefaults.forwardable.is_enabled(), expected);
        }
        Ok(())
    }

    /// MIT's day-clock form must not be mistaken for an invalid suffix.
    #[test]
    fn clockskew_when_mit_day_clock() -> Result<(), Box<dyn StdError>> {
        // Given equivalent MIT time syntax.
        for text in ["1-02:03:04", "1d 2h 3m 4s"] {
            // When parsing the configured tolerance.
            let config = Config::parse(&format!("[libdefaults]\n clockskew = {text}\n"))?;
            // Then the typed tolerance preserves all components.
            assert_eq!(config.libdefaults.clockskew, Duration::from_secs(93_784));
        }
        Ok(())
    }

    /// Invalid newly recognized booleans cannot disappear as unknown keys.
    #[test]
    fn new_booleans_when_malformed() -> Result<(), Box<dyn StdError>> {
        // Given C1 relations that were previously ignored.
        for relation in ["dns_uri_lookup", "enforce_ok_as_delegate"] {
            // When parsing malformed boolean input.
            let result = Config::parse(&format!("[libdefaults]\n {relation} = maybe\n"));
            // Then the boundary rejects it.
            drop(result.err().ok_or_else(|| format!("{relation} accepted"))?);
        }
        Ok(())
    }

    /// A malformed address must not silently narrow the configured list.
    #[test]
    fn extra_addresses_when_malformed() -> Result<(), Box<dyn StdError>> {
        // Given a valid address followed by an invalid address.
        let input = "[libdefaults]\n extra_addresses = 127.0.0.1,not-an-ip\n";
        // When parsing the list.
        let result = Config::parse(input);
        // Then no partial success is returned.
        drop(result.err().ok_or("malformed address accepted")?);
        Ok(())
    }

    /// Strict mode rejects deferred relations even when the value is satisfied.
    #[test]
    fn deferred_relations_when_strict() -> Result<(), Box<dyn StdError>> {
        // Given recognized but not implemented behavior.
        for assignment in [
            "dns_canonicalize_hostname = false",
            "dns_lookup_realm = false",
            "dns_uri_lookup = false",
            "enforce_ok_as_delegate = true",
            "err_fmt = %C: %M",
            "ignore_acceptor_hostname = false",
        ] {
            // When parsing in strict mode.
            let result = Config::parse_with_mode(
                &format!("[libdefaults]\n {assignment}\n"),
                ParseMode::Strict,
            );
            // Then the deferred contract is not claimed effective.
            drop(
                result
                    .err()
                    .ok_or_else(|| format!("{assignment} accepted"))?,
            );
        }
        Ok(())
    }

    /// Persistence and address restrictions cannot be satisfied by memory/omission.
    #[test]
    fn stricter_relations_when_compatible() -> Result<(), Box<dyn StdError>> {
        // Given policies stricter than the current replay/address behavior.
        for assignment in [
            "default_rcache_name = dfl:",
            "extra_addresses = 192.0.2.1\n noaddresses = false",
        ] {
            // When parsing in the default compatible mode.
            let result = Config::parse(&format!("[libdefaults]\n {assignment}\n"));
            // Then it fails closed rather than pretending to enforce the policy.
            drop(
                result
                    .err()
                    .ok_or_else(|| format!("{assignment} accepted"))?,
            );
        }
        Ok(())
    }

    /// MIT accepts ordered units, not duplicate units or concatenated digits.
    #[test]
    fn clockskew_when_invalid_mit_syntax() -> Result<(), Box<dyn StdError>> {
        // Given malformed intervals and values beyond MIT's signed time range.
        for value in [
            "1 2",
            "1h2h",
            "1m2h",
            "1:000",
            "2147483648",
            "-1",
            "1hgarbage",
        ] {
            // When decoding clock tolerance.
            let result = Config::parse(&format!("[libdefaults]\n clockskew = {value}\n"));
            // Then no widened tolerance is admitted.
            drop(result.err().ok_or_else(|| format!("{value} accepted"))?);
        }
        Ok(())
    }

    /// Forwardability reaches both request option consumers.
    #[cfg(feature = "messages")]
    #[test]
    fn forwardable_when_request_options() -> Result<(), Box<dyn StdError>> {
        use std::time::UNIX_EPOCH;

        use rskrb5_ng::client::options::{AsReq, TgsReq};
        // Given both explicit policy values, including an overriding raw bit.
        for (value, expected) in [("true", 0x4000_0000_u32), ("false", 0)] {
            let config = Config::parse(&format!(
                "[libdefaults]\n forwardable = {value}\n kdc_default_options = 40000010\n"
            ))?;
            // When deriving actual request options.
            let initial = AsReq::from_libdefaults(UNIX_EPOCH, 1, &config.libdefaults);
            let service = TgsReq::from_libdefaults(UNIX_EPOCH, 1, &config.libdefaults);
            // Then the profile value governs the forwardable bit in both paths.
            assert_eq!(initial.kdc_option_bits() & 0x4000_0000, expected);
            assert_eq!(service.kdc_option_bits() & 0x4000_0000, expected);
        }
        Ok(())
    }
}

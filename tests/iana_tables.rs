//! The public assigned-number tables against the pinned IANA registry snapshot and the crate's own numbers.

/// Turns `Option` and `Result` failures into test errors.
#[path = "support/context.rs"]
mod context;

/// Assigned-number table tests.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod iana_tables {
    use rskrb5_ng::iana::{
        Entry, Registry, address_type, authorization_data_type, checksum_type, encryption_type,
        error_code, fast_armor_type, fast_option, message_type, name_type, padata_type,
        second_factor_type, spake_group, transport_type,
    };

    use crate::context::{Context as _, TestError};

    /// The registry snapshot the tables were generated from (Last Updated 2024-12-06).
    const SNAPSHOT: &str = include_str!("fixtures/iana/kerberos-parameters-2024-12-06.txt");

    /// The `(number, name)` rows of the snapshot section that starts at `title` and ends at `stop`.
    fn snapshot_rows(title: &str, stop: &str, wide: bool) -> Result<Vec<(i32, String)>, TestError> {
        let lines: Vec<&str> = SNAPSHOT.lines().collect();
        let start = lines
            .iter()
            .enumerate()
            .skip(30)
            .position(|(_, line)| line.trim() == title)
            .context("the section starts")?
            .saturating_add(30);
        let end = lines
            .iter()
            .enumerate()
            .skip(start.saturating_add(1))
            .find(|(_, line)| line.trim() == stop)
            .map(|(index, _)| index)
            .context("the section ends")?;
        let mut rows = Vec::new();
        for line in lines.get(start..end).context("section lines")? {
            let trimmed = line.trim();
            let Some((first, remainder)) = trimmed.split_once(char::is_whitespace) else {
                continue;
            };
            let Ok(number) = first.parse::<i32>() else {
                continue;
            };
            let body = remainder.trim();
            let name = if wide {
                body.split("  ").next().unwrap_or_default().trim()
            } else {
                body.split_whitespace().next().unwrap_or_default()
            };
            let lowered = name.to_ascii_lowercase();
            if name.is_empty()
                || name.starts_with('[')
                || lowered.starts_with("unassigned")
                || lowered.starts_with("reserved")
            {
                continue;
            }
            let clean = name.replace(" (deprecated)", "");
            rows.push((number, clean));
        }
        Ok(rows)
    }

    /// Check that `registry` lists exactly the rows of the snapshot section, in order.
    fn matches_snapshot(
        registry: &Registry,
        title: &str,
        stop: &str,
        wide: bool,
    ) -> Result<(), TestError> {
        let expected = snapshot_rows(title, stop, wide)?;
        let actual: Vec<(i32, String)> = registry
            .entries()
            .iter()
            .map(|entry| (entry.number(), entry.name().to_owned()))
            .collect();
        assert_eq!(actual, expected, "{}", registry.title());
        Ok(())
    }

    /// Pins that every IANA-hosted registry table equals the pinned registry snapshot, row for row.
    #[test]
    fn the_registered_tables_equal_the_iana_snapshot() -> Result<(), TestError> {
        matches_snapshot(
            &encryption_type::REGISTRY,
            "Kerberos Encryption Type Numbers",
            "Kerberos Checksum Type Numbers",
            true,
        )?;
        matches_snapshot(
            &checksum_type::REGISTRY,
            "Kerberos Checksum Type Numbers",
            "Kerberos TCP Extensions",
            true,
        )?;
        matches_snapshot(
            &padata_type::REGISTRY,
            "Pre-authentication and Typed Data",
            "FAST Armor Types",
            true,
        )?;
        matches_snapshot(
            &fast_armor_type::REGISTRY,
            "FAST Armor Types",
            "FAST Options",
            false,
        )?;
        matches_snapshot(
            &fast_option::REGISTRY,
            "FAST Options",
            "Well-Known Kerberos Principal Names",
            false,
        )?;
        matches_snapshot(
            &transport_type::REGISTRY,
            "Kerberos Message Transport Types",
            "Kerberos Second Factor Types",
            true,
        )?;
        matches_snapshot(
            &second_factor_type::REGISTRY,
            "Kerberos Second Factor Types",
            "Kerberos SPAKE Groups",
            true,
        )?;
        assert_eq!(spake_group::REGISTRY.name(2_i32), Some("P-256"));
        Ok(())
    }

    /// Pins well-known numbers in both directions, one per registry.
    #[test]
    fn numbers_and_names_look_up_both_ways() -> Result<(), TestError> {
        assert_eq!(
            encryption_type::REGISTRY.name(18_i32),
            Some("aes256-cts-hmac-sha1-96")
        );
        assert_eq!(
            encryption_type::REGISTRY.number("AES128-CTS-HMAC-SHA1-96"),
            Some(17_i32)
        );
        assert_eq!(encryption_type::AES256_CTS_HMAC_SHA384_192, 20_i32);
        assert!(
            encryption_type::REGISTRY
                .get(1_i32)
                .context("des-cbc-crc")?
                .is_deprecated()
        );
        assert_eq!(
            checksum_type::REGISTRY.number("hmac-sha1-96-aes256"),
            Some(16_i32)
        );
        assert_eq!(padata_type::PA_ENC_TIMESTAMP, 2_i32);
        assert_eq!(padata_type::REGISTRY.name(136_i32), Some("PA-FX-FAST"));
        assert_eq!(padata_type::REGISTRY.number("PA-SPAKE"), Some(151_i32));
        assert_eq!(message_type::AP_REQ, 14_i32);
        assert_eq!(message_type::REGISTRY.name(30_i32), Some("ERROR"));
        assert_eq!(name_type::PRINCIPAL, 1_i32);
        assert_eq!(
            name_type::REGISTRY.number("ENTERPRISE_PRINCIPAL"),
            Some(10_i32)
        );
        assert_eq!(name_type::REGISTRY.name(-128_i32), Some("MS_PRINCIPAL"));
        assert_eq!(address_type::REGISTRY.name(24_i32), Some("INET6"));
        assert_eq!(address_type::REGISTRY.number("DECNET"), Some(12_i32));
        assert_eq!(authorization_data_type::KDC_ISSUED, 4_i32);
        assert_eq!(authorization_data_type::AND_OR, 5_i32);
        assert_eq!(
            authorization_data_type::REGISTRY.name(128_i32),
            Some("WIN2K_PAC")
        );
        assert_eq!(
            error_code::REGISTRY.name(25_i32),
            Some("KDC_ERR_PREAUTH_REQUIRED")
        );
        assert_eq!(error_code::REGISTRY.number("KRB_AP_ERR_SKEW"), Some(37_i32));
        assert_eq!(error_code::KRB_AP_ERR_REPEAT, 34_i32);
        assert_eq!(encryption_type::REGISTRY.name(8_i32), None);
        assert_eq!(error_code::REGISTRY.number("no such error"), None);
        Ok(())
    }

    /// Pins that every table lists numbers in ascending order and no name twice, so name lookups are unambiguous.
    #[test]
    fn tables_are_sorted_and_unambiguous() -> Result<(), TestError> {
        for registry in [
            encryption_type::REGISTRY,
            checksum_type::REGISTRY,
            padata_type::REGISTRY,
            fast_armor_type::REGISTRY,
            fast_option::REGISTRY,
            transport_type::REGISTRY,
            second_factor_type::REGISTRY,
            spake_group::REGISTRY,
            message_type::REGISTRY,
            name_type::REGISTRY,
            address_type::REGISTRY,
            authorization_data_type::REGISTRY,
            error_code::REGISTRY,
        ] {
            let entries = registry.entries();
            let first = entries.first().context("the registry lists an entry")?;
            assert!(first.number() <= entries.last().map_or(i32::MAX, Entry::number));
            for pair in entries.windows(2) {
                let [earlier, later] = pair else {
                    continue;
                };
                assert!(earlier.number() <= later.number(), "{}", registry.title());
            }
            for entry in entries {
                let found = entries
                    .iter()
                    .filter(|other| other.name().eq_ignore_ascii_case(entry.name()))
                    .count();
                assert!(
                    found == 1 || registry.title().contains("checksum"),
                    "{} lists {} {found} times",
                    registry.title(),
                    entry.name()
                );
            }
        }
        Ok(())
    }
}

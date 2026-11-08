//! Exhaustive deferred-consumer boundary review against all three catalogues.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error::Error;

    use super::super::{
        Config, ConfigDiagnostic, ParseMode, libdefaults::relations::RELATIONS,
        realm_relations::REALM_RELATIONS, section_decode::SECTION_RELATIONS,
    };

    /// Libdefaults: safe assignment and optional genuinely stronger assignment.
    /// None means no valid value tightens current behavior; table rationale explains why.
    const LIB: [(&str, &str, Option<&str>); 24] = [
        ("canonicalize", "false", None),
        ("ccache_type", "4", None),
        ("default_rcache_name", "none:", Some("dfl:")),
        ("dns_canonicalize_hostname", "fallback", None),
        ("dns_lookup_realm", "false", None),
        ("dns_uri_lookup", "false", None),
        ("enforce_ok_as_delegate", "true", None),
        ("err_fmt", "%C: %M", None),
        (
            "extra_addresses",
            "127.0.0.1",
            Some("127.0.0.1\n noaddresses = false"),
        ),
        ("ignore_acceptor_hostname", "false", None),
        ("k5login_authoritative", "true", None),
        ("k5login_directory", "/unread", None),
        ("kcm_mach_service", "-", None),
        ("kcm_socket", "-", None),
        ("kdc_timesync", "0", None),
        ("noaddresses", "true", Some("false")),
        ("plugin_base_dir", "%{LIBDIR}/unloaded", None),
        ("preferred_preauth_types", "17,16", None),
        ("qualify_shortname", "", None),
        ("rdns", "false", None),
        ("realm_try_domains", "-1", None),
        ("request_timeout", "0", Some("1s")),
        ("spake_preauth_groups", "P-521", None),
        ("verify_ap_req_nofail", "false", Some("true")),
    ];

    /// Realm values are restrictions on absent mechanisms, except encrypted timestamp.
    const REALM: [(&str, &str, Option<&str>); 21] = [
        ("auth_to_local", "DEFAULT", None),
        ("auth_to_local_names", "{\n Alice = alice\n }", None),
        ("default_domain", "example.test", None),
        ("disable_encrypted_timestamp", "false", Some("true")),
        ("http_anchors", "FILE:/ca", None),
        ("master_kdc", "master.example", None),
        ("primary_kdc", "primary.example", None),
        ("sitename", "Site", None),
        ("pkinit_anchors", "FILE:/ca", None),
        ("pkinit_cert_match", "<SUBJECT>restricted", None),
        ("pkinit_eku_checking", "kpKDC", None),
        ("pkinit_dh_min_bits", "P-521", None),
        ("pkinit_identities", "FILE:/identity", None),
        ("pkinit_kdc_hostname", "kdc.example", None),
        ("pkinit_pool", "FILE:/pool", None),
        ("pkinit_require_crl_checking", "true", None),
        ("pkinit_revoke", "FILE:/crl", None),
        ("pkinit_identity", "FILE:/identity", None),
        ("pkinit_allow_upn", "false", None),
        ("pkinit_indicator", "strong", None),
        ("pkinit_require_freshness", "true", None),
    ];

    /// Render actual profile inputs, not direct calls to classification predicates.
    fn profile(section: &str, name: &str, value: &str) -> String {
        if section == "realms" {
            format!("[realms]\n R = {{\n {name} = {value}\n }}\n")
        } else {
            format!("[libdefaults]\n {name} = {value}\n")
        }
    }

    /// Both parse modes are tested for each side; Compatible must preserve the diagnostic.
    fn boundary(name: &str, safe: &str, tighter: Option<&str>) -> Result<(), Box<dyn Error>> {
        let config = Config::parse(safe)?;
        assert!(config.diagnostics().iter().any(|item| matches!(item, ConfigDiagnostic::NotYetEffective { relation, package: _ } if *relation == name)), "safe {name}");
        drop(
            Config::parse_with_mode(safe, ParseMode::Strict)
                .err()
                .ok_or_else(|| format!("strict accepted {name}"))?,
        );
        if let Some(input) = tighter {
            for mode in [ParseMode::Compatible, ParseMode::Strict] {
                let failure = Config::parse_with_mode(input, mode)
                    .err()
                    .ok_or_else(|| format!("tightening ignored: {name}"))?;
                assert!(
                    matches!(failure, super::super::Error::NotYetEffective { relation, package: _ } if relation == name)
                );
            }
        }
        Ok(())
    }

    /// Classification refuses a tightened deferred libdefaults relation before any later
    /// section decoding, which would otherwise name a different restriction first.
    #[test]
    fn tightened_libdefaults_relation_refused_before_sections() -> Result<(), Box<dyn Error>> {
        for (relation, assignment, package) in [
            ("client_aware_channel_bindings", "true", "plan 2 WP-12"),
            ("default_rcache_name", "dfl:", "plan 2 WP-20"),
            ("noaddresses", "false", "plan 2 WP-04"),
            ("request_timeout", "1s", "plan 2 WP-10"),
            ("verify_ap_req_nofail", "true", "plan 2 WP-11"),
        ] {
            // Given the tightened relation and a refused preauthentication plugin restriction.
            let input = format!(
                "[libdefaults]\n {relation} = {assignment}\n[plugins]\n clpreauth = {{\n disable = encrypted_timestamp\n }}\n"
            );
            // When the profile is parsed in Compatible mode.
            let failure = Config::parse_with_mode(&input, ParseMode::Compatible)
                .err()
                .ok_or("tightening ignored")?;
            // Then the libdefaults relation is refused with its owning package.
            assert!(
                matches!(
                    failure,
                    super::super::Error::NotYetEffective { relation: named, package: owner }
                        if named == relation && owner == package
                ),
                "{relation}: {failure:?}"
            );
        }
        Ok(())
    }

    /// Every deferred libdefaults row has an explicit safe/tightening decision.
    #[test]
    fn every_libdefaults_boundary_is_reviewed() -> Result<(), Box<dyn Error>> {
        for row in RELATIONS.iter().filter(|row| row.3.starts_with("plan 2 ")) {
            let (name, safe, tight) = if row.0 == "client_aware_channel_bindings" {
                (row.0, "false", Some("true"))
            } else {
                LIB.iter()
                    .copied()
                    .find(|case| case.0 == row.0)
                    .ok_or("unreviewed libdefaults row")?
            };
            let tighter = tight.map(|value| profile("libdefaults", name, value));
            boundary(
                name,
                &profile("libdefaults", name, safe),
                tighter.as_deref(),
            )?;
        }
        assert_eq!(
            RELATIONS
                .iter()
                .filter(|row| row.3.starts_with("plan 2 "))
                .count(),
            LIB.len().saturating_add(1)
        );
        Ok(())
    }

    /// Every deferred realm row has an explicit safe/tightening decision.
    #[test]
    fn every_realm_boundary_is_reviewed() -> Result<(), Box<dyn Error>> {
        for row in REALM_RELATIONS
            .iter()
            .filter(|row| row.3.starts_with("plan 2 "))
        {
            let (name, safe, tight) = REALM
                .iter()
                .copied()
                .find(|case| case.0 == row.0)
                .ok_or("unreviewed realm row")?;
            let tighter = tight.map(|value| profile("realms", name, value));
            boundary(name, &profile("realms", name, safe), tighter.as_deref())?;
        }
        assert_eq!(
            REALM_RELATIONS
                .iter()
                .filter(|row| row.3.starts_with("plan 2 "))
                .count(),
            REALM.len()
        );
        Ok(())
    }

    /// Section restrictions are compared with actual built-in behavior, not plugin names alone.
    #[test]
    fn every_section_boundary_is_reviewed() -> Result<(), Box<dyn Error>> {
        for row in SECTION_RELATIONS
            .iter()
            .filter(|row| row.3.starts_with("plan 2 "))
        {
            match row.0 {
                "capaths" => boundary("capaths", "[capaths]\n A = {\n B = .\n }\n", None)?,
                "disable" => boundary(
                    "disable",
                    "[plugins]\n clpreauth = {\n disable = pkinit\n }\n",
                    Some("[plugins]\n clpreauth = {\n disable = encrypted_timestamp\n }\n"),
                )?,
                "enable_only" => boundary(
                    "enable_only",
                    "[plugins]\n clpreauth = {\n enable_only = encrypted_timestamp\n }\n",
                    Some("[plugins]\n clpreauth = {\n enable_only = pkinit\n }\n"),
                )?,
                _ => return Err("unreviewed section row".into()),
            }
        }
        Ok(())
    }
}

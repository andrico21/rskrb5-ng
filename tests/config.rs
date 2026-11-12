//! Configuration parsing, loading and realm resolution tests.

#[path = "support/env.rs"]
mod env;

#[path = "config/profile.rs"]
mod profile;
#[path = "config/restrictive.rs"]
mod restrictive;

#[path = "config/profile_limits.rs"]
mod profile_limits;

#[path = "config/expansion.rs"]
mod expansion;

#[path = "config/readers.rs"]
mod readers;

#[path = "config/consumers.rs"]
mod consumers;

#[path = "config/libdefaults_c1.rs"]
mod libdefaults_c1;

#[path = "config/relations_c1.rs"]
mod relations_c1;

#[path = "config/c1_boundaries.rs"]
mod c1_boundaries;

#[path = "config/libdefaults_c2.rs"]
mod libdefaults_c2;

#[path = "config/relations_c2.rs"]
mod relations_c2;

#[path = "config/sections_d.rs"]
mod sections_d;

#[path = "config/realm_relations_d.rs"]
mod realm_relations_d;
#[path = "config/section_composition_d.rs"]
mod section_composition_d;

#[path = "config/diagnostics_e.rs"]
mod diagnostics_e;

#[path = "config/compatibility_e.rs"]
mod compatibility_e;

#[path = "config/unavailable_e.rs"]
mod unavailable_e;

#[path = "config/mutation_profile.rs"]
mod mutation_profile;

#[path = "config/mutation_values.rs"]
mod mutation_values;

#[path = "config/mutation_core.rs"]
mod mutation_core;

#[path = "config/value_whitespace.rs"]
mod value_whitespace;
#[path = "config/value_whitespace_sites.rs"]
mod value_whitespace_sites;
#[path = "config/whitespace.rs"]
mod whitespace;

/// Configuration parsing, loading and realm resolution tests.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::{error, fmt::Display, time::Duration};
    use std::{
        env::{join_paths, split_paths, temp_dir, var_os},
        fs, io,
        path::PathBuf,
        process,
        time::{SystemTime, UNIX_EPOCH},
    };

    use pretty_assertions::assert_eq;
    use proptest::{collection, prelude::any, prop_assert_eq, proptest, sample};
    #[cfg(feature = "serde")]
    use proptest::{prelude::Strategy, prop_assert};
    #[cfg(feature = "messages")]
    use rasn::der;
    #[cfg(feature = "serde")]
    use rskrb5_ng::config::ConfigDiagnostic;
    #[cfg(any(feature = "serde", feature = "messages"))]
    use rskrb5_ng::config::LibDefaults;
    #[cfg(feature = "messages")]
    use rskrb5_ng::{
        Principal,
        client::{build_tgt_as_req, options::AsReq},
    };
    use rskrb5_ng::{
        config::{Config, Realm, parse_duration},
        error::Config as Error,
    };
    #[cfg(feature = "serde")]
    use serde_json::{Value, json};

    use super::env;

    /// Error type of the `Result`-returning tests.
    type TestError = Box<dyn error::Error>;

    /// A realm has a public validating construction path without text or serde.
    #[test]
    fn constructs_validated_realm() -> Result<(), TestError> {
        // Given an explicit realm name.
        let name = "EXAMPLE.COM";
        // When constructing without parsing a profile.
        let realm = Realm::new(name.to_owned())?;
        // Then its name is preserved and an empty name is rejected.
        assert_eq!(realm.name, name);
        assert!(Realm::new(String::new()).err().is_some());
        Ok(())
    }

    /// Attaches a description to a failure, as `expect` would, but as an error
    /// that `?` propagates.
    trait Context<T> {
        /// Returns the value, or an error that names `what`.
        fn context(self, what: &str) -> Result<T, TestError>;
    }

    impl<T, E: Display> Context<T> for Result<T, E> {
        fn context(self, what: &str) -> Result<T, TestError> {
            self.map_err(|cause| format!("{what}: {cause}").into())
        }
    }

    impl<T> Context<T> for Option<T> {
        fn context(self, what: &str) -> Result<T, TestError> {
            self.ok_or_else(|| what.into())
        }
    }

    /// The gokrb5 integration-test `krb5.conf`.
    const KRB5_CONF: &str = "[libdefaults]
  default_realm = TEST.GOKRB5
  dns_lookup_realm = false
  dns_lookup_kdc = false
  ticket_lifetime = 24h
  forwardable = yes
  default_tkt_enctypes = aes256-cts-hmac-sha1-96
  default_tgs_enctypes = aes256-cts-hmac-sha1-96
  noaddresses = false

[realms]
 TEST.GOKRB5 = {
  kdc = 127.0.0.1:88
  kdc = 127.0.0.2:88
  admin_server = 127.0.0.1:749
  default_domain = test.gokrb5
 }
 RESDOM.GOKRB5 = {
  kdc = 10.80.88.88:188
  admin_server = 127.0.0.1:749
  default_domain = resdom.gokrb5
 }

[domain_realm]
 .test.gokrb5 = TEST.GOKRB5
 test.gokrb5 = TEST.GOKRB5
 .resdom.gokrb5 = RESDOM.GOKRB5
 resdom.gokrb5 = RESDOM.GOKRB5
 ";

    /// The gokrb5 config with comments, port-less KDCs, extra sections and a lowercase realm.
    const COMPLEX_KRB5_CONF: &str = "
[logging]
 default = FILE:/var/log/kerberos/krb5libs.log

[libdefaults]
 default_realm = TEST.GOKRB5 ; comment to be ignored
 dns_lookup_realm = false
 dns_lookup_kdc = false
 #dns_lookup_kdc = true
 ;dns_lookup_kdc = true
 ticket_lifetime = 10h ;comment to be ignored
 forwardable = yes #comment to be ignored
 default_ccache_name = DIR:/tmp/krb5cc_dir
 default_keytab_name = FILE:/etc/krb5.keytab
 default_client_keytab_name = FILE:/home/gokrb5/client.keytab
 default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 # comment

[realms]
 TEST.GOKRB5 = {
  kdc = 10.80.88.88:88 #comment to be ignored
  kdc = assume.port.num ;comment to be ignored
  kdc = some.other.port:1234 # comment to be ignored
  kdc = 10.80.88.88*
  kdc = 10.1.2.3.4:88
  admin_server = 10.80.88.88:749 ; comment to be ignored
  default_domain = test.gokrb5
 }
 EXAMPLE.COM = {
        kdc = kerberos.example.com
        kdc = kerberos-1.example.com
        admin_server = kerberos.example.com
        auth_to_local = RULE:[1:$1@$0](.*@EXAMPLE.COM)s/.*//
 }
	lowercase.org = {
		kdc = kerberos.lowercase.org
		admin_server = kerberos.lowercase.org
	}

[domain_realm]
 .test.gokrb5 = TEST.GOKRB5 #comment to be ignored
 test.gokrb5 = TEST.GOKRB5 ;comment to be ignored
 .example.com = EXAMPLE.COM # comment to be ignored
 hostname1.example.com = EXAMPLE.COM ; comment to be ignored
 hostname2.example.com = TEST.GOKRB5
 .testlowercase.org = lowercase.org

[appdefaults]
 pam = {
   debug = false
 }
";

    /// Every supported enctype name, aliases included, with its enctype ID.
    #[cfg(feature = "serde")]
    const SUPPORTED_ENCTYPES: [(&str, i32); 14] = [
        ("aes128-cts-hmac-sha1-96", 17),
        ("aes128-cts", 17),
        ("aes128-sha1", 17),
        ("aes256-cts-hmac-sha1-96", 18),
        ("aes256-cts", 18),
        ("aes256-sha1", 18),
        ("aes128-cts-hmac-sha256-128", 19),
        ("aes128-sha2", 19),
        ("aes256-cts-hmac-sha384-192", 20),
        ("aes256-sha2", 20),
        ("des3-cbc-sha1-kd", 16),
        ("arcfour-hmac", 23),
        ("rc4-hmac", 23),
        ("arcfour-hmac-md5", 23),
    ];

    /// A `[domain_realm]` section with a leading-dot tag and a bare tag.
    const DOMAIN_REALM_CONF: &str = "[libdefaults]
 default_realm = CLIENT.REALM

[domain_realm]
 .example.com = SUFFIX.REALM
 example.org = BARE.REALM
";

    /// The configured suffixes, each with the realm its subdomains resolve to.
    const CONFIGURED_SUFFIXES: [(&str, &str); 2] = [
        (".example.com", "SUFFIX.REALM"),
        (".example.org", "BARE.REALM"),
    ];

    /// Length of the generated case mask; longer than any generated host.
    const CASE_MASK_LEN: usize = 64;

    /// A non-empty subset of [`SUPPORTED_ENCTYPES`], in arbitrary order.
    #[cfg(feature = "serde")]
    fn enctype_subset() -> impl Strategy<Value = Vec<(&'static str, i32)>> {
        sample::subsequence(SUPPORTED_ENCTYPES.to_vec(), 1..=SUPPORTED_ENCTYPES.len())
            .prop_shuffle()
    }

    proptest! {
        /// Any non-empty explicit `permitted_enctypes` list keeps
        /// `permitted_enctypes_explicit == true` and the same derived IDs
        /// through a serde round trip.
        #[cfg(feature = "serde")]
        #[test]
        fn permitted_enctypes_survive_a_serde_round_trip(enctypes in enctype_subset()) {
            let names: Vec<&str> = enctypes.iter().map(|entry| entry.0).collect();
            let mut expected_ids: Vec<i32> = Vec::new();
            for entry in &enctypes {
                if !expected_ids.contains(&entry.1) { expected_ids.push(entry.1); }
            }
            let config = Config::parse(&format!(
                "[libdefaults]\n allow_rc4 = true\n allow_des3 = true\n permitted_enctypes = {}\n",
                names.join(" ")
            ))?;
            prop_assert!(config.libdefaults.permitted_enctypes_explicit.is_enabled(), "parsed list is explicit");
            prop_assert_eq!(&config.libdefaults.permitted_enctype_ids(), &expected_ids);

            let json = serde_json::to_string(&config.libdefaults)?;
            let decoded: LibDefaults = serde_json::from_str(&json)?;

            prop_assert!(decoded.permitted_enctypes_explicit.is_enabled(), "explicit flag survives serde");
            prop_assert_eq!(&decoded.permitted_enctype_ids(), &expected_ids);
            prop_assert_eq!(decoded, config.libdefaults);
        }

        /// Any ASCII case permutation of a host under a configured
        /// `[domain_realm]` suffix, with or without a trailing root dot,
        /// resolves to that suffix's realm.
        #[test]
        fn resolve_realm_ignores_host_case(
            labels in "[a-z0-9]{1,10}(\\.[a-z0-9]{1,10}){0,3}",
            suffix in sample::select(CONFIGURED_SUFFIXES.to_vec()),
            case_mask in collection::vec(any::<bool>(), CASE_MASK_LEN),
            trailing_dot in any::<bool>(),
        ) {
            let config = Config::parse(DOMAIN_REALM_CONF)?;
            let (domain, realm) = suffix;
            let host = format!("{labels}{domain}");
            let mut permuted: String = host
                .chars()
                .enumerate()
                .map(|(index, character)| {
                    if case_mask.get(index) == Some(&true) {
                        character.to_ascii_uppercase()
                    } else {
                        character
                    }
                })
                .collect();
            if trailing_dot {
                permuted.push('.');
            }

            prop_assert_eq!(config.resolve_realm(&host), Some(realm));
            prop_assert_eq!(config.resolve_realm(&permuted), Some(realm), "{}", permuted);
        }
    }

    /// Assigned names, rather than a construction-time cache, control the wire.
    #[cfg(feature = "messages")]
    #[test]
    fn assigned_enctype_names_control_encoded_request() -> Result<(), TestError> {
        // Given a configuration whose names change after construction.
        let mut defaults = LibDefaults::new();
        defaults.default_tkt_enctypes = vec!["aes256-cts".to_owned()];
        // When the real AS-REQ builder encodes that configuration.
        let etypes = encoded_as_req_etypes(&defaults)?;
        // Then only the assigned algorithm is advertised.
        assert_eq!(etypes, vec![18_i32]);
        Ok(())
    }

    /// Unknown positive names are rejected even alongside a usable entry.
    #[test]
    fn unsupported_explicit_enctype_names_are_rejected() -> Result<(), TestError> {
        for key in [
            "default_tkt_enctypes",
            "default_tgs_enctypes",
            "permitted_enctypes",
        ] {
            let input = format!("[libdefaults]\n {key} = aes256-cts typo-enctype\n");
            // When parsing a mixed implemented/unknown list.
            let error = Config::parse(&input)
                .err()
                .ok_or("unknown term was dropped")?;
            // Then the original unknown token is named.
            assert!(matches!(error, Error::UnknownEnctype { token } if token == "typo-enctype"));
        }
        Ok(())
    }

    /// Stock Fedora/RHEL crypto policy retains implemented AES entries in order.
    #[test]
    fn crypto_policies_default_skips_camellia() -> Result<(), TestError> {
        // Given the crypto-policies DEFAULT krb5 back-end output.
        let input = "[libdefaults]\n permitted_enctypes = aes256-cts-hmac-sha384-192 aes128-cts-hmac-sha256-128 aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 camellia256-cts-cmac camellia128-cts-cmac\n";
        // When parsing the distro configuration.
        let config = Config::parse(input)?;
        // Then only implemented enctypes remain, in the configured order.
        assert_eq!(
            config.libdefaults.permitted_enctype_ids(),
            [20_i32, 19_i32, 18_i32, 17_i32]
        );
        assert_eq!(config.libdefaults.permitted_enctypes.len(), 4);
        Ok(())
    }

    /// Camellia cannot prevent use of a neighboring supported algorithm.
    #[test]
    fn usable_enctype_with_camellia_parses() -> Result<(), TestError> {
        // Given an unsupported entry before and after the implemented entry.
        let input = "[libdefaults]\n default_tgs_enctypes = camellia128-cts-cmac aes128-cts camellia256-cts-cmac\n";
        // When parsing the explicit request list.
        let config = Config::parse(input)?;
        // Then the name list and derived wire IDs agree.
        assert_eq!(
            config.libdefaults.default_tgs_enctypes,
            ["aes128-cts-hmac-sha1-96"]
        );
        assert_eq!(config.libdefaults.default_tgs_enctype_ids(), [17_i32]);
        Ok(())
    }

    /// An entirely disabled RC4 request never falls back to default algorithms.
    #[test]
    fn rc4_only_without_opt_in_has_no_usable_enctypes() -> Result<(), TestError> {
        // Given an explicit list with no policy-enabled entry.
        let input = "[libdefaults]\n default_tgs_enctypes = rc4-hmac\n";
        // When parsing without allow_rc4.
        let error = Config::parse(input)
            .err()
            .ok_or("disabled list was accepted")?;
        // Then the disabled token is rejected before list filtering.
        assert!(matches!(error, Error::DisabledEnctype { token } if token == "rc4-hmac"));
        Ok(())
    }

    /// MIT families expand, while invented family names fail by name.
    #[test]
    fn family_and_default_tokens_do_not_invent_enctypes() -> Result<(), TestError> {
        // Given unsupported family/selector tokens alongside a concrete name.
        for tokens in [
            "aes",
            "aes-sha1",
            "aes-sha2",
            "DEFAULT -rc4",
            "camellia",
            "des",
        ] {
            let input = format!("[libdefaults]\n default_tgs_enctypes = {tokens} aes256-cts\n");
            // When parsing the same inputs with MIT selector semantics.
            let result = Config::parse(&input);
            // Then known selectors expand and unknown names cannot disappear.
            match tokens {
                "aes" => assert_eq!(
                    result?.libdefaults.default_tgs_enctype_ids(),
                    [18_i32, 17_i32, 20_i32, 19_i32]
                ),
                "DEFAULT -rc4" => assert_eq!(
                    result?.libdefaults.default_tgs_enctype_ids(),
                    [20_i32, 19_i32, 18_i32, 17_i32]
                ),
                "camellia" => assert_eq!(result?.libdefaults.default_tgs_enctype_ids(), [18_i32]),
                _ => {
                    let error = result.err().ok_or("invented family accepted")?;
                    assert!(matches!(error, Error::UnknownEnctype { token } if token == tokens));
                }
            }
        }
        Ok(())
    }

    /// Valid family-only and DEFAULT-only lists expand to secure enctypes.
    #[test]
    fn family_and_default_only_lists_fail_closed() -> Result<(), TestError> {
        // Given the F2 family/DEFAULT probe inputs that 0.2.2 mapped to no IDs.
        for (key, names) in [
            ("permitted_enctypes", "aes"),
            ("default_tgs_enctypes", "DEFAULT -rc4"),
        ] {
            let input = format!("[libdefaults]\n {key} = {names}\n");
            // When expanding recognized selectors.
            let config = Config::parse(&input)?;
            // Then the exact family/default order reaches the request list.
            let expected: Vec<i32> = if names == "aes" {
                vec![18, 17, 20, 19]
            } else {
                vec![20, 19, 18, 17]
            };
            assert_eq!(config.libdefaults.default_tgs_enctype_ids(), expected);
        }
        Ok(())
    }

    /// Disabled positives cannot be silently removed from mixed lists.
    #[test]
    fn disabled_enctypes_are_rejected_in_mixed_lists() -> Result<(), TestError> {
        // Given each list with independent family/weak policy disabled.
        for key in [
            "default_tkt_enctypes",
            "default_tgs_enctypes",
            "permitted_enctypes",
        ] {
            let input = format!(
                "[libdefaults]\n {key} = rc4-hmac aes128-cts des3-cbc-sha1 aes256-cts rc4-hmac-exp\n"
            );
            // When parsing with default policy.
            let error = Config::parse(&input)
                .err()
                .ok_or("disabled term was dropped")?;
            // Then the first disabled token fails before any narrowing.
            assert!(matches!(error, Error::DisabledEnctype { token } if token == "rc4-hmac"));
        }
        Ok(())
    }

    /// Deprecated families require their own flag, not just weak-crypto opt-in.
    #[test]
    fn deprecated_enctypes_require_explicit_family_opt_in() -> Result<(), TestError> {
        use rskrb5_ng::error::{Policy, RejectedFeature};
        for name in [
            "rc4-hmac",
            "arcfour-hmac-md5",
            "rc4-hmac-exp",
            "des3-cbc-sha1-kd",
        ] {
            for key in [
                "default_tkt_enctypes",
                "default_tgs_enctypes",
                "permitted_enctypes",
            ] {
                let input = format!("[libdefaults]\n allow_weak_crypto = true\n {key} = {name}\n");
                let error = Config::parse(&input)
                    .err()
                    .ok_or("deprecated enctype was accepted")?;
                assert!(matches!(
                    error,
                    Error::Policy(Policy::RejectedFeature {
                        feature: RejectedFeature::WeakCrypto,
                        reason: _
                    })
                ));
            }
        }
        Ok(())
    }

    /// Config-derived wire defaults must not advertise deprecated families.
    #[cfg(feature = "messages")]
    #[test]
    fn default_wire_enctypes_are_aes_only() -> Result<(), TestError> {
        assert_eq!(
            encoded_as_req_etypes(&LibDefaults::new())?,
            vec![20_i32, 19_i32, 18_i32, 17_i32]
        );
        Ok(())
    }

    /// Later sections enable only the explicitly opted-in deprecated family.
    #[test]
    fn deprecated_family_flags_apply_after_all_sections() -> Result<(), TestError> {
        for (name, flag, id) in [
            ("rc4-hmac", "allow_rc4", 23_i32),
            ("des3-cbc-sha1-kd", "allow_des3", 16_i32),
        ] {
            let config = Config::parse(&format!(
                "[libdefaults]\n default_tkt_enctypes = {name}\n[libdefaults]\n {flag} = true\n"
            ))?;
            assert_eq!(config.libdefaults.default_tkt_enctype_ids(), vec![id]);
        }
        Ok(())
    }

    /// Ordinary defaults and parsing ignore hostile UID/HOME process inputs.
    #[test]
    fn ordinary_defaults_ignore_ambient_environment() -> Result<(), TestError> {
        let test = "tests::ordinary_defaults_ignore_ambient_environment";
        if !env::in_child(test) {
            env::run_in_child(
                test,
                &[
                    ("UID", Some("4242".as_ref())),
                    ("HOME", Some("/attacker/home".as_ref())),
                ],
            );
            return Ok(());
        }
        let config = Config::parse("[libdefaults]\n")?;
        assert_eq!(config.libdefaults.k5login_directory, "");
        assert_eq!(
            config.libdefaults.default_client_keytab_name,
            "/usr/local/var/krb5/user/%{euid}/client.keytab"
        );
        assert_eq!(Config::new(), config);
        Ok(())
    }

    /// Pins the gokrb5 defaults of the DNS lookup, canonicalization and address flags.
    #[test]
    fn libdefaults_defaults_match_gokrb5() {
        let config = Config::new();

        assert!(!config.libdefaults.dns_lookup_kdc.is_enabled());
        assert!(!config.libdefaults.dns_lookup_realm.is_enabled());
        assert!(config.libdefaults.dns_canonicalize_hostname.is_enabled());
        assert!(config.libdefaults.no_addresses.is_enabled());
    }

    /// Pins the libdefaults, KDCs, kpasswd servers and realm mapping of the gokrb5 integration config.
    #[test]
    fn parses_gokrb5_integration_config_fixture() -> Result<(), TestError> {
        assert!(matches!(
            Config::parse(KRB5_CONF),
            Err(Error::NotYetEffective {
                relation: "noaddresses",
                package: "plan 2 WP-04"
            })
        ));
        let config = Config::parse(&KRB5_CONF.replace("noaddresses = false", "noaddresses = true"))
            .context("addressless fixture parses")?;

        assert_eq!(config.libdefaults.default_realm, "TEST.GOKRB5");
        assert!(!config.libdefaults.dns_lookup_realm.is_enabled());
        assert!(!config.libdefaults.dns_lookup_kdc.is_enabled());
        assert!(config.libdefaults.no_addresses.is_enabled());
        assert!(config.libdefaults.forwardable.is_enabled());
        assert_eq!(config.libdefaults.ticket_lifetime, Duration::from_hours(24));
        assert_eq!(config.libdefaults.default_tkt_enctype_ids(), [18_i32]);
        assert_eq!(config.libdefaults.default_tgs_enctype_ids(), [18_i32]);

        assert_eq!(config.realms.len(), 2);
        assert_eq!(
            config
                .configured_kdcs("TEST.GOKRB5")
                .context("KDCs exist")?,
            ["127.0.0.1:88", "127.0.0.2:88"]
        );
        assert_eq!(
            config
                .configured_kpasswd_servers("TEST.GOKRB5")
                .context("kpasswd servers default from admin_server")?,
            ["127.0.0.1:464"]
        );
        assert_eq!(
            config.resolve_realm("host.test.gokrb5"),
            Some("TEST.GOKRB5")
        );
        assert_eq!(
            config.resolve_realm("resdom.gokrb5."),
            Some("RESDOM.GOKRB5")
        );
        Ok(())
    }

    /// Pins that a config file loads from a path.
    #[test]
    fn loads_config_file() -> Result<(), TestError> {
        let path = temp_file("load")?;
        fs::write(&path, KRB5_CONF).context("config fixture writes")?;
        assert!(matches!(
            Config::load(&path),
            Err(Error::NotYetEffective {
                relation: "noaddresses",
                package: "plan 2 WP-04"
            })
        ));
        fs::write(
            &path,
            KRB5_CONF.replace("noaddresses = false", "noaddresses = true"),
        )?;
        let config = Config::load(&path).context("config loads")?;
        fs::remove_file(&path).context("the test config is removed")?;

        assert_eq!(config.libdefaults.default_realm, "TEST.GOKRB5");
        assert_eq!(
            config
                .configured_kdcs("TEST.GOKRB5")
                .context("KDCs exist")?,
            ["127.0.0.1:88", "127.0.0.2:88"]
        );
        Ok(())
    }

    /// Pins first-value precedence across an ordered path list, skipping empty paths.
    #[test]
    fn loads_config_path_list_in_order() -> Result<(), TestError> {
        let first = temp_file("load-list-first")?;
        let second = temp_file("load-list-second")?;
        fs::write(
            &first,
            "
[libdefaults]
 default_realm = FIRST.GOKRB5

[domain_realm]
 .first.gokrb5 = FIRST.GOKRB5
",
        )
        .context("first config writes")?;
        fs::write(
            &second,
            "
[libdefaults]
 default_realm = SECOND.GOKRB5

[domain_realm]
 .second.gokrb5 = SECOND.GOKRB5
",
        )
        .context("second config writes")?;

        let config = Config::load_paths([first.clone(), PathBuf::new(), second.clone()])
            .context("config path list loads")?;
        fs::remove_file(&first).context("the test config is removed")?;
        fs::remove_file(&second).context("the test config is removed")?;

        assert_eq!(config.libdefaults.default_realm, "FIRST.GOKRB5");
        assert_eq!(
            config.resolve_realm("host.first.gokrb5"),
            Some("FIRST.GOKRB5")
        );
        assert_eq!(
            config.resolve_realm("host.second.gokrb5"),
            Some("SECOND.GOKRB5")
        );
        Ok(())
    }

    /// Pins first-value precedence across `KRB5_CONFIG` entries.
    #[test]
    fn loads_config_path_list_from_env() -> Result<(), TestError> {
        const TEST_PATH: &str = "tests::loads_config_path_list_from_env";
        if !env::in_child(TEST_PATH) {
            let paths = join_paths([temp_file("load-env-first")?, temp_file("load-env-second")?])
                .map_err(|cause| format!("config paths join: {cause}"))?;
            env::run_in_child(TEST_PATH, &[("KRB5_CONFIG", Some(&paths))]);
            return Ok(());
        }
        let paths = var_os("KRB5_CONFIG").ok_or("the parent test sets KRB5_CONFIG")?;
        let [first, second]: [PathBuf; 2] =
            split_paths(&paths).collect::<Vec<_>>().try_into().map_err(
                |listed: Vec<PathBuf>| format!("KRB5_CONFIG lists two paths: {}", listed.len()),
            )?;
        fs::write(
            &first,
            "
[libdefaults]
 default_realm = FIRST.GOKRB5
",
        )
        .map_err(|cause| format!("first config writes: {cause}"))?;
        fs::write(
            &second,
            "
[libdefaults]
 default_realm = SECOND.GOKRB5
",
        )
        .map_err(|cause| format!("second config writes: {cause}"))?;

        let config = Config::load_from_env()
            .map_err(|cause| format!("config loads from KRB5_CONFIG: {cause}"))?;
        fs::remove_file(&first).context("the test config is removed")?;
        fs::remove_file(&second).context("the test config is removed")?;

        assert_eq!(config.libdefaults.default_realm, "FIRST.GOKRB5");
        Ok(())
    }

    /// Pins that `load_default` and `load_default_or_parse` prefer `KRB5_CONFIG`.
    #[test]
    fn load_default_prefers_krb5_config_env() -> Result<(), TestError> {
        const TEST_PATH: &str = "tests::load_default_prefers_krb5_config_env";
        if !env::in_child(TEST_PATH) {
            let path = temp_file("load-default-env")?;
            env::run_in_child(TEST_PATH, &[("KRB5_CONFIG", Some(path.as_os_str()))]);
            return Ok(());
        }
        let path = PathBuf::from(var_os("KRB5_CONFIG").ok_or("the parent test sets KRB5_CONFIG")?);
        fs::write(
            &path,
            "
[libdefaults]
 default_realm = ENV.GOKRB5
",
        )
        .map_err(|cause| format!("env config writes: {cause}"))?;

        let config = Config::load_default()
            .map_err(|cause| format!("default config loads from env: {cause}"))?;
        let fallback = Config::load_default_or_parse(
            "
[libdefaults]
 default_realm = EMBEDDED.GOKRB5
",
        )
        .map_err(|cause| format!("default-or-embedded config loads from env: {cause}"))?;
        fs::remove_file(&path).context("the test config is removed")?;

        assert_eq!(config.libdefaults.default_realm, "ENV.GOKRB5");
        assert_eq!(fallback.libdefaults.default_realm, "ENV.GOKRB5");
        Ok(())
    }

    /// Pins that a path list with no non-empty path is rejected.
    #[test]
    fn rejects_empty_config_path_list() -> Result<(), TestError> {
        assert!(matches!(
            Config::load_paths(Vec::<PathBuf>::new())
                .err()
                .context("empty path list rejected")?,
            Error::EmptyConfigPathList
        ));
        assert!(matches!(
            Config::load_paths([PathBuf::new()])
                .err()
                .context("empty path rejected")?,
            Error::EmptyConfigPathList
        ));
        Ok(())
    }

    /// Pins that loading without `KRB5_CONFIG` reports the missing variable.
    #[test]
    fn rejects_missing_config_env() -> Result<(), TestError> {
        const TEST_PATH: &str = "tests::rejects_missing_config_env";
        if !env::in_child(TEST_PATH) {
            env::try_run_in_child(TEST_PATH, &[("KRB5_CONFIG", None)])?;
            return Ok(());
        }
        assert!(matches!(
            Config::load_from_env()
                .err()
                .context("missing KRB5_CONFIG rejected")?,
            Error::DefaultConfigName
        ));
        Ok(())
    }

    /// Pins comments, default ports, kpasswd defaults and realm sections of the complex gokrb5 config.
    #[test]
    fn parses_complex_gokrb5_config_semantics() -> Result<(), TestError> {
        let config = Config::parse(COMPLEX_KRB5_CONF).context("config parses")?;

        assert_eq!(config.libdefaults.default_realm, "TEST.GOKRB5");
        assert_eq!(config.libdefaults.ticket_lifetime, Duration::from_hours(10));
        assert_eq!(
            config.libdefaults.default_keytab_name,
            "FILE:/etc/krb5.keytab"
        );
        assert_eq!(
            config.libdefaults.default_ccache_name,
            "DIR:/tmp/krb5cc_dir"
        );
        assert_eq!(
            config.libdefaults.default_client_keytab_name,
            "FILE:/home/gokrb5/client.keytab"
        );
        assert_eq!(
            config.libdefaults.default_tkt_enctypes,
            ["aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96"]
        );
        assert_eq!(
            config.libdefaults.default_tkt_enctype_ids(),
            [18_i32, 17_i32]
        );
        assert_eq!(
            config.libdefaults.default_tgs_enctype_ids(),
            [20_i32, 19_i32, 18_i32, 17_i32]
        );

        assert_eq!(config.realms.len(), 3);
        let test_realm = config.realm("TEST.GOKRB5").context("TEST realm exists")?;
        assert_eq!(test_realm.name, "TEST.GOKRB5");
        assert_eq!(test_realm.admin_server, ["10.80.88.88:749"]);
        assert_eq!(test_realm.kpasswd_server, ["10.80.88.88:464"]);
        assert_eq!(test_realm.default_domain, "test.gokrb5");
        assert_eq!(
            test_realm.kdc,
            [
                "10.80.88.88:88",
                "assume.port.num:88",
                "some.other.port:1234",
                "10.80.88.88:88"
            ]
        );

        let example = config
            .realm("EXAMPLE.COM")
            .context("example realm exists")?;
        assert_eq!(
            example.kdc,
            ["kerberos.example.com:88", "kerberos-1.example.com:88"]
        );
        assert_eq!(example.admin_server, ["kerberos.example.com"]);
        assert_eq!(example.kpasswd_server, ["kerberos.example.com:464"]);

        assert_eq!(
            config.domain_realm.get(".test.gokrb5").map(String::as_str),
            Some("TEST.GOKRB5")
        );
        assert_eq!(
            config.domain_realm.get("test.gokrb5").map(String::as_str),
            Some("TEST.GOKRB5")
        );
        Ok(())
    }

    /// Pins that the gokrb5 config without blank lines between sections parses.
    #[test]
    fn parses_gokrb5_config_without_blank_lines() -> Result<(), TestError> {
        let config = Config::parse(
            "[logging]
 default = FILE:/var/log/kerberos/krb5libs.log
[libdefaults]
 default_realm = TEST.GOKRB5
 dns_lookup_realm = false
 dns_lookup_kdc = false
 ticket_lifetime = 10h
 forwardable = yes
 default_keytab_name = FILE:/etc/krb5.keytab
 default_client_keytab_name = FILE:/home/gokrb5/client.keytab
 default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
[realms]
 TEST.GOKRB5 = {
  kdc = 10.80.88.88:88
  kdc = assume.port.num
  admin_server = 10.80.88.88:749
  default_domain = test.gokrb5
 }
 EXAMPLE.COM = {
  kdc = kerberos.example.com
  admin_server = kerberos.example.com
 }
[domain_realm]
 .test.gokrb5 = TEST.GOKRB5
 test.gokrb5 = TEST.GOKRB5
",
        )
        .context("config parses")?;

        assert_eq!(config.libdefaults.default_realm, "TEST.GOKRB5");
        assert_eq!(config.libdefaults.ticket_lifetime, Duration::from_hours(10));
        assert_eq!(
            config.libdefaults.default_tkt_enctype_ids(),
            [18_i32, 17_i32]
        );
        assert_eq!(config.realms.len(), 2);
        assert_eq!(
            config
                .realm("TEST.GOKRB5")
                .context("TEST realm exists")?
                .kdc,
            ["10.80.88.88:88", "assume.port.num:88"]
        );
        assert_eq!(
            config.resolve_realm("host.test.gokrb5"),
            Some("TEST.GOKRB5")
        );
        Ok(())
    }

    /// Pins that the gokrb5 config with tab indentation and reordered sections parses.
    #[test]
    fn parses_gokrb5_config_with_tabs_and_reordered_sections() -> Result<(), TestError> {
        let config = Config::parse(
            "[logging]
	default = FILE:/var/log/kerberos/krb5libs.log

[libdefaults]
	default_realm = TEST.GOKRB5
	dns_lookup_realm = false
	dns_lookup_kdc = false
	ticket_lifetime = 10h
	forwardable = yes
	default_keytab_name = FILE:/etc/krb5.keytab
	default_client_keytab_name = FILE:/home/gokrb5/client.keytab
	default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96

[domain_realm]
	.test.gokrb5 = TEST.GOKRB5
	test.gokrb5 = TEST.GOKRB5
	.example.com = EXAMPLE.COM
	hostname1.example.com = EXAMPLE.COM

[appdefaults]
	pam = {
	 debug = false
	}

[realms]
	TEST.GOKRB5 = {
		kdc = 10.80.88.88:88
		kdc = assume.port.num
		admin_server = 10.80.88.88:749
		default_domain = test.gokrb5
	}
	EXAMPLE.COM = {
		kdc = kerberos.example.com
		kdc = kerberos-1.example.com
		admin_server = kerberos.example.com
	}
",
        )
        .context("config parses")?;

        assert_eq!(config.libdefaults.default_realm, "TEST.GOKRB5");
        assert_eq!(config.realms.len(), 2);
        assert_eq!(
            config
                .realm("EXAMPLE.COM")
                .context("example realm exists")?
                .kdc,
            ["kerberos.example.com:88", "kerberos-1.example.com:88"]
        );
        assert_eq!(
            config.resolve_realm("hostname1.example.com"),
            Some("EXAMPLE.COM")
        );
        Ok(())
    }

    /// Top-level path-list failures identify the requested file and retain their cause.
    #[test]
    fn load_paths_reports_failing_path_and_io_source() -> Result<(), TestError> {
        // Given a readable first path and a missing second path.
        let first = temp_file("path-error-first")?;
        let missing = temp_file("path-error-missing")?;
        fs::write(&first, "[libdefaults]\n default_realm = EXAMPLE.COM\n")?;
        // When loading the explicit path list.
        let failure = Config::load_paths([&first, &missing])
            .err()
            .context("missing path fails")?;
        fs::remove_file(first)?;
        // Then the requested path and original I/O error are available.
        assert!(failure.to_string().contains(&missing.display().to_string()));
        let cause = error::Error::source(&failure).context("I/O source retained")?;
        assert_eq!(
            cause
                .downcast_ref::<io::Error>()
                .context("I/O cause")?
                .kind(),
            io::ErrorKind::NotFound
        );
        Ok(())
    }

    /// Pins the gokrb5 duration formats: seconds, `h:m`, `h:m:s` and `d`/`h`/`m`/`s` units.
    #[test]
    fn duration_formats_match_gokrb5() -> Result<(), TestError> {
        let cases = [
            ("0", Duration::ZERO),
            ("0s", Duration::ZERO),
            ("100", Duration::from_secs(100)),
            ("12:30", Duration::from_mins(750)),
            ("12:30:15", Duration::from_secs(45_015)),
            ("1d12h30m15s", Duration::from_secs(131_415)),
            ("1d12h30m", Duration::from_mins(2_190)),
            ("1d12h", Duration::from_hours(36)),
            ("1d", Duration::from_hours(24)),
        ];

        for (input, expected) in cases {
            assert_eq!(parse_duration(input).context("duration parses")?, expected);
        }
        Ok(())
    }

    /// Plain zero and unit zero configure the same supported duration values.
    #[test]
    fn zero_seconds_configure_renew_lifetime_and_clockskew() -> Result<(), TestError> {
        // Given the two representations of zero seconds.
        for value in ["0", "0s"] {
            // When parsing explicit renewable lifetime and clock skew.
            let config = Config::parse(&format!(
                "[libdefaults]\n renew_lifetime = {value}\n clockskew = {value}\n"
            ))?;
            // Then both typed settings retain zero.
            assert_eq!(config.libdefaults.renew_lifetime, Duration::ZERO);
            assert_eq!(config.libdefaults.clockskew, Duration::ZERO);
        }
        Ok(())
    }

    /// Pins gokrb5's most-specific `[domain_realm]` match.
    #[test]
    fn resolve_realm_matches_gokrb5_specificity() -> Result<(), TestError> {
        let config = Config::parse(COMPLEX_KRB5_CONF).context("config parses")?;
        assert_eq!(config.resolve_realm("unknown.com"), None);
        assert_eq!(
            config.resolve_realm("hostname1.example.com"),
            Some("EXAMPLE.COM")
        );
        assert_eq!(
            config.resolve_realm("hostname2.example.com"),
            Some("TEST.GOKRB5")
        );
        assert_eq!(
            config.resolve_realm("one.two.three.example.com"),
            Some("EXAMPLE.COM")
        );
        assert_eq!(config.resolve_realm(".test.gokrb5"), Some("TEST.GOKRB5"));
        assert_eq!(
            config.resolve_realm("foo.testlowercase.org"),
            Some("lowercase.org")
        );
        Ok(())
    }

    /// Pins that configured KDCs are returned even when `dns_lookup_kdc` is on.
    #[test]
    fn repeated_realms_preserve_configured_endpoints() -> Result<(), TestError> {
        // Given distinct sections, plus later relations for the first realm.
        let input = "[libdefaults]\n dns_lookup_kdc = true\n\
            [realms]\n A = {\n kdc = first.example*\n admin_server = admin.example\n default_domain = old.example\n }\n\
            [realms]\n B = {\n kdc = other.example\n }\n\
            A = {\n kdc = ignored.example\n kpasswd_server = password.example\n default_domain = new.example\n }\n";

        // When the sections compose.
        let config = Config::parse(input)?;

        // Then unrelated realms, final relations and first scalar values survive.
        assert_eq!(config.configured_kdcs("A")?, ["first.example:88"]);
        assert_eq!(config.configured_kdcs("B")?, ["other.example:88"]);
        assert_eq!(
            config.configured_kpasswd_servers("A")?,
            ["password.example"]
        );
        assert_eq!(
            config.realm("A").context("realm A exists")?.default_domain,
            "old.example"
        );
        Ok(())
    }

    /// Path lists and includes have the same realm composition as inline sections.
    #[test]
    fn repeated_realms_compose_across_files() -> Result<(), TestError> {
        // Given two files with separate realms and an appended relation.
        let dir = include_fixture_dir(
            "realm-compose",
            &[
                ("a.conf", "[realms]\n A = {\n kdc = first.example\n }\n"),
                (
                    "b.conf",
                    "[realms]\n B = {\n kdc = other.example\n }\n A = {\n kdc = second.example\n }\n",
                ),
            ],
        )?;
        let first = dir.join("a.conf");
        let second = dir.join("b.conf");

        // When loading a path list or expanding includes.
        let results = [
            Config::load_paths([&first, &second]),
            Config::parse(&format!(
                "include {}\ninclude {}\n",
                first.display(),
                second.display()
            )),
        ];
        fs::remove_dir_all(dir)?;

        // Then configured routes retain their complete ordered relations.
        for result in results {
            let config = result?;
            assert_eq!(
                config.configured_kdcs("A")?,
                ["first.example:88", "second.example:88"]
            );
            assert_eq!(config.configured_kdcs("B")?, ["other.example:88"]);
            assert_eq!(config.realms.len(), 2);
        }
        Ok(())
    }

    /// Pins that configured KDCs are returned even when `dns_lookup_kdc` is on.
    #[test]
    fn configured_kdcs_are_used_even_when_dns_lookup_is_enabled() -> Result<(), TestError> {
        let config = Config::parse(
            "
[libdefaults]
 dns_lookup_kdc = true

[realms]
 TEST.GOKRB5 = {
  kdc = kdc2b.test.gokrb5:88
 }
",
        )
        .context("config parses")?;

        assert!(config.libdefaults.dns_lookup_kdc.is_enabled());
        assert_eq!(
            config
                .configured_kdcs("TEST.GOKRB5")
                .context("KDCs exist")?,
            ["kdc2b.test.gokrb5:88"]
        );
        Ok(())
    }

    /// Malformed address input fails rather than silently narrowing the list.
    #[test]
    fn libdefaults_keys_are_case_insensitive_and_extra_addresses_are_comma_separated()
    -> Result<(), TestError> {
        let result = Config::parse(
            "
[libdefaults]
 DEFAULT_REALM = TEST.GOKRB5
 EXTRA_ADDRESSES = 127.0.0.1, 127.0.0.2, not-an-ip
 FORWARDABLE = TRUE
",
        );
        assert!(matches!(result, Err(Error::InvalidAddress(value)) if value == "not-an-ip"));
        let valid = Config::parse(
            "[libdefaults]\n DEFAULT_REALM = TEST.GOKRB5\n EXTRA_ADDRESSES = 127.0.0.1, 127.0.0.2\n FORWARDABLE = TRUE\n",
        )?;
        assert_eq!(valid.libdefaults.default_realm, "TEST.GOKRB5");
        assert!(valid.libdefaults.forwardable.is_enabled());
        assert_eq!(
            valid
                .libdefaults
                .extra_addresses
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["127.0.0.1", "127.0.0.2"]
        );
        Ok(())
    }

    /// Pins that the RC4-HMAC enctype aliases map to enctype 23.
    #[test]
    fn maps_rc4_hmac_enctype_aliases() -> Result<(), TestError> {
        let config = Config::parse(
            "
[libdefaults]
 default_tkt_enctypes = arcfour-hmac rc4-hmac arcfour-hmac-md5
 default_tgs_enctypes = rc4-hmac
 allow_rc4 = true
",
        )
        .context("config parses")?;

        assert_eq!(config.libdefaults.default_tkt_enctype_ids(), [23_i32]);
        assert_eq!(config.libdefaults.default_tgs_enctype_ids(), [23_i32]);
        Ok(())
    }

    /// Pins the gokrb5 JSON shape of a config.
    #[cfg(feature = "serde")]
    #[test]
    fn config_json_matches_gokrb5_shape() -> Result<(), TestError> {
        let mut config = Config::parse(COMPLEX_KRB5_CONF).context("config parses")?;
        config.libdefaults.k5login_directory = "/home/test".to_owned();

        let json = config.json().context("config JSON renders")?;
        let value: Value = serde_json::from_str(&json).context("config JSON parses")?;

        assert!(json.contains(r#""LibDefaults""#), "{json}");
        assert!(json.contains(r#""DefaultTGSEnctypes""#), "{json}");
        assert!(json.contains(r#""DefaultTktEnctypeIDs""#), "{json}");
        assert_eq!(
            *json_at(&value, "/LibDefaults/Clockskew"),
            json!(300_000_000_000_u64)
        );
        assert_eq!(
            *json_at(&value, "/LibDefaults/TicketLifetime"),
            json!(36_000_000_000_000_u64)
        );
        assert_eq!(
            *json_at(&value, "/LibDefaults/KDCDefaultOptions/Bytes"),
            json!("AAAAEA==")
        );
        assert_eq!(
            *json_at(&value, "/LibDefaults/KDCDefaultOptions/BitLength"),
            json!(32_i32)
        );
        assert_eq!(
            *json_at(&value, "/LibDefaults/K5LoginDirectory"),
            json!("/home/test")
        );
        assert_eq!(
            *json_at(&value, "/Realms/0/KPasswdServer/0"),
            json!("10.80.88.88:464")
        );
        assert_eq!(*json_at(&value, "/Realms/0/MasterKDC"), Value::Null);
        assert_eq!(
            *json_at(&value, "/DomainRealm/hostname1.example.com"),
            json!("EXAMPLE.COM")
        );
        Ok(())
    }

    /// Pins that Kerberos v4 realm directives are rejected.
    #[test]
    fn rejects_v4_realm_directives() -> Result<(), TestError> {
        use rskrb5_ng::error::{Policy, RejectedFeature};
        let err = Config::parse(
            "
[realms]
 TEST.GOKRB5 = {
  kdc = 10.80.88.88:88
  v4_name_convert = {
   host = {
    rcmd = host
   }
  }
 }
",
        )
        .err()
        .context("v4 directives are rejected")?;

        assert!(matches!(
            err,
            Error::Policy(Policy::RejectedFeature {
                feature: RejectedFeature::V4Conversion,
                reason: _,
            })
        ));
        Ok(())
    }

    /// Returns the JSON value at `pointer`, or `null` when there is none, as
    /// indexing a [`Value`] would.
    #[cfg(feature = "serde")]
    fn json_at<'value>(value: &'value Value, pointer: &str) -> &'value Value {
        value.pointer(pointer).unwrap_or(&Value::Null)
    }

    /// Returns a unique path in the temporary directory for the test `name`.
    fn temp_file(name: &str) -> Result<PathBuf, TestError> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("current time is after unix epoch")?
            .as_nanos();
        Ok(temp_dir().join(format!("rskrb5-config-{name}-{}-{nanos}", process::id())))
    }

    /// Pins that `[domain_realm]` lookups fold the DNS case of the host name.
    #[test]
    fn resolve_realm_folds_dns_case() -> Result<(), TestError> {
        let config = Config::parse(
            "
[libdefaults]
 default_realm = CLIENT.REALM

[domain_realm]
 foo.example.com = PARTNER.REALM
 .example.com = SUFFIX.REALM
",
        )
        .map_err(|cause| format!("config parses: {cause}"))?;

        for spelling in [
            "foo.example.com",
            "FOO.EXAMPLE.COM",
            "Foo.Example.com",
            "FOO.EXAMPLE.COM.",
        ] {
            assert_eq!(
                config.resolve_realm(spelling),
                Some("PARTNER.REALM"),
                "{spelling}"
            );
        }
        for spelling in ["bar.example.com", "BAR.EXAMPLE.COM", "Bar.Example.com"] {
            assert_eq!(
                config.resolve_realm(spelling),
                Some("SUFFIX.REALM"),
                "{spelling}"
            );
        }
        Ok(())
    }
    /// Pins MIT's bare-tag precedence: a bare domain tag also covers its subdomains.
    #[test]
    fn resolve_realm_applies_bare_domain_tags_to_subdomains() -> Result<(), TestError> {
        // MIT's own three-tag example; expected values match the MIT 1.22.1
        // reference (`krb5_get_host_realm`, dns_lookup_realm=false).
        let config = Config::parse(
            "
[libdefaults]
 default_realm = CLIENT.REALM

[domain_realm]
 crash.mit.edu = TEST.ATHENA.MIT.EDU
 .dev.mit.edu = TEST.ATHENA.MIT.EDU
 mit.edu = ATHENA.MIT.EDU
",
        )
        .map_err(|cause| format!("config parses: {cause}"))?;

        assert_eq!(config.resolve_realm("mit.edu"), Some("ATHENA.MIT.EDU"));
        assert_eq!(
            config.resolve_realm("crash.mit.edu"),
            Some("TEST.ATHENA.MIT.EDU")
        );
        assert_eq!(
            config.resolve_realm("sub.crash.mit.edu"),
            Some("TEST.ATHENA.MIT.EDU")
        );
        assert_eq!(config.resolve_realm("dev.mit.edu"), Some("ATHENA.MIT.EDU"));
        assert_eq!(
            config.resolve_realm("foo.dev.mit.edu"),
            Some("TEST.ATHENA.MIT.EDU")
        );
        assert_eq!(
            config.resolve_realm("a.b.dev.mit.edu"),
            Some("TEST.ATHENA.MIT.EDU")
        );
        assert_eq!(config.resolve_realm("notmit.edu"), None);
        Ok(())
    }
    /// Pins that a leading-dot tag matches subdomains but not the domain itself.
    #[test]
    fn resolve_realm_dot_tag_does_not_match_the_domain_itself() -> Result<(), TestError> {
        let config = Config::parse(
            "
[libdefaults]
 default_realm = CLIENT.REALM

[domain_realm]
 .mit.edu = ATHENA.MIT.EDU
",
        )
        .map_err(|cause| format!("config parses: {cause}"))?;

        assert_eq!(config.resolve_realm("mit.edu"), None);
        assert_eq!(
            config.resolve_realm("crash.mit.edu"),
            Some("ATHENA.MIT.EDU")
        );
        Ok(())
    }
    /// Pins that a leading-dot tag wins over a bare tag for subdomains at the same level.
    #[test]
    fn resolve_realm_prefers_dot_tag_over_bare_at_the_same_level() -> Result<(), TestError> {
        // Reference precedence: MIT resolves dev.mit.edu from the bare tag and
        // x.dev.mit.edu from the leading-dot tag when both are declared.
        let config = Config::parse(
            "
[libdefaults]
 default_realm = CLIENT.REALM

[domain_realm]
 .dev.mit.edu = DOT.REALM
 dev.mit.edu = BARE.REALM
",
        )
        .map_err(|cause| format!("config parses: {cause}"))?;

        assert_eq!(config.resolve_realm("dev.mit.edu"), Some("BARE.REALM"));
        assert_eq!(config.resolve_realm("x.dev.mit.edu"), Some("DOT.REALM"));
        assert_eq!(config.resolve_realm("a.b.dev.mit.edu"), Some("DOT.REALM"));
        Ok(())
    }
    /// Pins that the explicit `permitted_enctypes` flag survives a serde round trip.
    #[cfg(feature = "serde")]
    #[test]
    fn permitted_enctypes_explicit_survives_a_serde_round_trip() -> Result<(), TestError> {
        let config = Config::parse(
            "
[libdefaults]
 permitted_enctypes = aes256-cts-hmac-sha1-96
",
        )
        .map_err(|cause| format!("config parses: {cause}"))?;
        assert!(config.libdefaults.permitted_enctypes_explicit.is_enabled());

        let json = serde_json::to_string(&config.libdefaults)
            .map_err(|cause| format!("libdefaults serialize: {cause}"))?;
        let decoded: LibDefaults = serde_json::from_str(&json)
            .map_err(|cause| format!("libdefaults deserialize: {cause}"))?;

        assert!(decoded.permitted_enctypes_explicit.is_enabled());
        assert_eq!(decoded, config.libdefaults);
        #[cfg(feature = "messages")]
        assert_eq!(encoded_as_req_etypes(&decoded)?, vec![18_i32]);
        Ok(())
    }
    /// Pins that an implicit permitted list stays implicit across a serde round trip.
    #[cfg(feature = "serde")]
    #[test]
    fn implicit_permitted_enctypes_round_trip_stays_implicit() -> Result<(), TestError> {
        assert!(matches!(
            Config::parse(KRB5_CONF),
            Err(Error::NotYetEffective {
                relation: "noaddresses",
                package: "plan 2 WP-04"
            })
        ));
        let config =
            Config::parse(&KRB5_CONF.replace("noaddresses = false", "noaddresses = true"))?;
        assert!(!config.libdefaults.permitted_enctypes_explicit.is_enabled());

        let json = serde_json::to_string(&config.libdefaults)
            .map_err(|cause| format!("libdefaults serialize: {cause}"))?;
        let decoded: LibDefaults = serde_json::from_str(&json)
            .map_err(|cause| format!("libdefaults deserialize: {cause}"))?;

        assert!(!decoded.permitted_enctypes_explicit.is_enabled());
        assert_eq!(serde_json::to_string(&decoded)?, json);
        assert!(
            decoded.enctype_diagnostics.is_empty(),
            "parse diagnostics are not serialized"
        );
        assert!(config.diagnostics().iter().any(|item| matches!(
            item,
            ConfigDiagnostic::NotYetEffective {
                relation: "dns_lookup_realm",
                package: "plan 2 WP-10"
            }
        )));
        Ok(())
    }
    /// Pins that JSON without the explicit flag deserializes as an implicit permitted list.
    #[cfg(feature = "serde")]
    #[test]
    fn libdefaults_json_without_the_explicit_field_deserializes_as_implicit()
    -> Result<(), TestError> {
        let config = Config::parse(
            "
[libdefaults]
 permitted_enctypes = aes256-cts-hmac-sha1-96
",
        )
        .map_err(|cause| format!("config parses: {cause}"))?;
        let mut value = serde_json::to_value(&config.libdefaults)
            .map_err(|cause| format!("libdefaults serialize: {cause}"))?;
        let removed = value
            .as_object_mut()
            .ok_or("libdefaults serialize as an object")?
            .remove("permitted_enctypes_explicit");
        assert_eq!(removed, Some(Value::Bool(true)));

        let decoded: LibDefaults = serde_json::from_value(value)
            .map_err(|cause| format!("libdefaults deserialize: {cause}"))?;

        assert!(!decoded.permitted_enctypes_explicit.is_enabled());
        assert_eq!(decoded.permitted_enctype_ids(), vec![18_i32]);
        Ok(())
    }
    /// Pins that an explicit `default_tkt_enctypes` entry outside the permitted list fails parsing.
    #[test]
    fn explicit_tkt_enctypes_outside_permitted_fail_parsing_naming_the_enctype()
    -> Result<(), TestError> {
        let error = Config::parse(
            "
[libdefaults]
 default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
 permitted_enctypes = aes256-cts-hmac-sha1-96
",
        )
        .err()
        .ok_or("an explicit request list outside the allowlist is rejected")?;

        assert!(
            matches!(
                &error,
                Error::EnctypeNotPermitted { key: "default_tkt_enctypes", enctype }
                    if enctype == "aes128-cts-hmac-sha1-96"
            ),
            "unexpected error: {error:?}"
        );
        let message = error.to_string();
        assert!(message.contains("default_tkt_enctypes"), "{message}");
        assert!(message.contains("aes128-cts-hmac-sha1-96"), "{message}");
        Ok(())
    }
    /// Pins that an explicit `default_tgs_enctypes` entry outside the permitted list fails parsing.
    #[test]
    fn explicit_tgs_enctypes_outside_permitted_fail_parsing_naming_the_enctype()
    -> Result<(), TestError> {
        let error = Config::parse(
            "
[libdefaults]
 default_tgs_enctypes = aes128-cts-hmac-sha1-96
 permitted_enctypes = aes256-cts-hmac-sha1-96
",
        )
        .err()
        .ok_or("an explicit request list outside the allowlist is rejected")?;

        assert!(
            matches!(
                &error,
                Error::EnctypeNotPermitted { key: "default_tgs_enctypes", enctype }
                    if enctype == "aes128-cts-hmac-sha1-96"
            ),
            "unexpected error: {error:?}"
        );
        let message = error.to_string();
        assert!(message.contains("default_tgs_enctypes"), "{message}");
        assert!(message.contains("aes128-cts-hmac-sha1-96"), "{message}");
        Ok(())
    }
    /// Pins that the implicit default request list is filtered to the permitted list.
    #[test]
    fn implicit_default_enctypes_are_filtered_to_permitted() -> Result<(), TestError> {
        let config = Config::parse(
            "
[libdefaults]
 permitted_enctypes = aes256-cts-hmac-sha1-96
",
        )
        .map_err(|cause| {
            format!("an implicit request list is not validated at parse time: {cause}")
        })?;

        assert!(config.libdefaults.permitted_enctypes_explicit.is_enabled());
        assert_eq!(config.libdefaults.default_tkt_enctype_ids(), vec![18_i32]);
        #[cfg(feature = "messages")]
        assert_eq!(encoded_as_req_etypes(&config.libdefaults)?, vec![18_i32]);
        Ok(())
    }
    /// Pins that an explicit request list in an earlier `[libdefaults]` section is validated.
    #[test]
    fn explicit_tkt_list_in_an_earlier_libdefaults_section_is_still_validated()
    -> Result<(), TestError> {
        let error = Config::parse(
            "
[libdefaults]
 default_tkt_enctypes = aes128-cts-hmac-sha1-96

[domain_realm]
 .test.gokrb5 = TEST.GOKRB5

[libdefaults]
 permitted_enctypes = aes256-cts-hmac-sha1-96
",
        )
        .err()
        .ok_or("the earlier explicit request list is validated")?;

        assert!(
            matches!(
                &error,
                Error::EnctypeNotPermitted { key: "default_tkt_enctypes", enctype }
                    if enctype == "aes128-cts-hmac-sha1-96"
            ),
            "unexpected error: {error:?}"
        );
        Ok(())
    }
    /// Pins that later sections cannot replace a conflicting first request list.
    #[test]
    fn a_later_section_cannot_repair_an_earlier_conflict() -> Result<(), TestError> {
        let result = Config::parse(
            "
[libdefaults]
 default_tkt_enctypes = aes128-cts-hmac-sha1-96
 permitted_enctypes = aes256-cts-hmac-sha1-96

[libdefaults]
 default_tkt_enctypes = aes256-cts-hmac-sha1-96
",
        );
        let failure = result.err().ok_or("first conflicting list was replaced")?;
        assert!(
            matches!(failure, Error::EnctypeNotPermitted { key: "default_tkt_enctypes", enctype } if enctype == "aes128-cts-hmac-sha1-96")
        );
        Ok(())
    }
    /// Pins that an explicit request list from an included file is validated.
    #[test]
    fn explicit_tkt_list_in_an_included_file_is_validated_against_permitted()
    -> Result<(), TestError> {
        let dir = include_fixture_dir(
            "include-enctype-reject",
            &[(
                "extra.conf",
                "[libdefaults]\n default_tkt_enctypes = aes128-cts-hmac-sha1-96\n",
            )],
        )?;
        let extra = dir.join("extra.conf");
        let main = format!(
            "[libdefaults]\n permitted_enctypes = aes256-cts-hmac-sha1-96\n\ninclude {}\n",
            extra.display()
        );
        let main_path = dir.join("krb5.conf");
        fs::write(&main_path, main).map_err(|cause| format!("main config is written: {cause}"))?;

        let error = Config::load(&main_path)
            .err()
            .ok_or("an included explicit request list outside the allowlist is rejected")?;
        fs::remove_dir_all(&dir)?;

        assert!(
            matches!(
                &error,
                Error::EnctypeNotPermitted { key: "default_tkt_enctypes", enctype }
                    if enctype == "aes128-cts-hmac-sha1-96"
            ),
            "unexpected error: {error:?}"
        );
        Ok(())
    }
    /// Pins that a later included file cannot replace the first request list.
    #[test]
    fn a_later_included_file_cannot_repair_an_earlier_conflict() -> Result<(), TestError> {
        let dir = include_fixture_dir(
            "include-enctype-repair",
            &[
                (
                    "a.conf",
                    "[libdefaults]\n default_tkt_enctypes = aes128-cts-hmac-sha1-96\n",
                ),
                (
                    "b.conf",
                    "[libdefaults]\n default_tkt_enctypes = aes256-cts-hmac-sha1-96\n",
                ),
            ],
        )?;
        let main = format!(
            "[libdefaults]\n permitted_enctypes = aes256-cts-hmac-sha1-96\n\ninclude {}\ninclude {}\n",
            dir.join("a.conf").display(),
            dir.join("b.conf").display()
        );
        let main_path = dir.join("krb5.conf");
        fs::write(&main_path, main).map_err(|cause| format!("main config is written: {cause}"))?;

        let loaded = Config::load(&main_path);
        fs::remove_dir_all(&dir)?;
        let failure = loaded
            .err()
            .ok_or("first included request list was replaced")?;
        assert!(
            matches!(failure, Error::EnctypeNotPermitted { key: "default_tkt_enctypes", enctype } if enctype == "aes128-cts-hmac-sha1-96")
        );
        Ok(())
    }
    /// Pins that a bare tag does not match a host that merely ends with its text.
    #[test]
    fn resolve_realm_rejects_bare_prefix_extension() -> Result<(), TestError> {
        let config = Config::parse(
            "
[libdefaults]
 default_realm = CLIENT.REALM

[domain_realm]
 mit.edu = ATHENA.MIT.EDU
",
        )
        .map_err(|cause| format!("config parses: {cause}"))?;

        assert_eq!(config.resolve_realm("notmit.edu"), None);
        assert_eq!(config.resolve_realm("sub.notmit.edu"), None);
        assert_eq!(config.resolve_realm("mit.edu"), Some("ATHENA.MIT.EDU"));
        assert_eq!(config.resolve_realm("sub.mit.edu"), Some("ATHENA.MIT.EDU"));
        Ok(())
    }
    /// Write `files` (name, body) into a fresh directory and return its path.
    fn include_fixture_dir(name: &str, files: &[(&str, &str)]) -> Result<PathBuf, TestError> {
        let dir = temp_file(name)?;
        fs::create_dir_all(&dir)
            .map_err(|cause| format!("fixture directory is created: {cause}"))?;
        for (file, body) in files {
            fs::write(dir.join(file), body)
                .map_err(|cause| format!("fixture file is written: {cause}"))?;
        }
        Ok(dir)
    }
    /// Encodes an AS-REQ built from `defaults` and returns its decoded etype list.
    #[cfg(feature = "messages")]
    fn encoded_as_req_etypes(defaults: &LibDefaults) -> Result<Vec<i32>, TestError> {
        let now = UNIX_EPOCH
            .checked_add(Duration::from_secs(1_893_553_447))
            .ok_or("the fixed request time fits in SystemTime")?;
        let options = AsReq::from_libdefaults(now, 0x1122_3344, defaults)?;
        let request = build_tgt_as_req(Principal::user("TEST.GOKRB5", "testuser1"), options)
            .map_err(|cause| format!("AS-REQ builds: {cause}"))?;
        let decoded: rasn_kerberos::AsReq =
            der::decode(request.der()).map_err(|cause| format!("AS-REQ decodes: {cause}"))?;
        Ok(decoded.0.req_body.etype)
    }

    /// Pins that an explicit `permitted_enctypes` naming no supported enctype fails parsing.
    #[test]
    fn explicit_permitted_enctypes_with_no_supported_ids_fail_parsing() -> Result<(), TestError> {
        for names in [
            "des-cbc-crc",
            "camellia256-cts-cmac",
            "des3-cbc-raw",
            "des-cbc-md5 camellia128-cts-cmac",
        ] {
            let error = Config::parse(&format!(
                "
[libdefaults]
 permitted_enctypes = {names}
"
            ))
            .err()
            .ok_or("an allowlist without a supported enctype is rejected")?;

            if names == "camellia256-cts-cmac" {
                assert!(matches!(error, Error::EmptyEnctypeExpression));
            } else {
                assert!(
                    matches!(error, Error::RejectedEnctype { token, source: _ } if names.starts_with(&token))
                );
            }
        }
        Ok(())
    }

    /// Pins that MIT's DES3 enctype names resolve to enctype 16.
    #[test]
    fn des3_mit_names_resolve_to_enctype_16() -> Result<(), TestError> {
        for name in [
            "des3-cbc-sha1",
            "des3-hmac-sha1",
            "des3-cbc-sha1-kd",
            "DES3-CBC-SHA1",
        ] {
            for allow_weak_crypto in [false, true] {
                let result = Config::parse(&format!(
                    "
[libdefaults]
  allow_weak_crypto = {allow_weak_crypto}
  allow_des3 = true
 default_tkt_enctypes = {name}
 permitted_enctypes = {name}
"
                ));
                if allow_weak_crypto {
                    let error = result.err().ok_or("weak crypto accepted")?;
                    assert!(matches!(error, Error::Policy(_)));
                    continue;
                }
                let config = result.map_err(|cause| format!("config parses: {cause}"))?;

                assert_eq!(
                    config.libdefaults.permitted_enctype_ids(),
                    vec![16_i32],
                    "{name}"
                );
                assert_eq!(
                    config.libdefaults.default_tkt_enctype_ids(),
                    vec![16_i32],
                    "{name}"
                );
            }
        }
        Ok(())
    }

    /// Pins that the seeded default request lists do not request DES3.
    #[test]
    fn seeded_default_enctypes_do_not_request_des3() {
        let defaults = Config::new().libdefaults;

        assert_eq!(
            defaults.default_tkt_enctype_ids(),
            vec![20_i32, 19_i32, 18_i32, 17_i32]
        );
        assert_eq!(
            defaults.default_tgs_enctype_ids(),
            vec![20_i32, 19_i32, 18_i32, 17_i32]
        );
        assert_eq!(
            defaults.permitted_enctype_ids(),
            vec![20_i32, 19_i32, 18_i32, 17_i32]
        );
    }
}

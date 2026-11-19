use core::error::Error;

use rskrb5_ng::{
    Config,
    config::{ConfigDiagnostic, EnctypeExpr, LibDefaults, ParseMode, Toggle},
    crypto::{CryptoPolicy, KerberosEtype, Use, camellia},
    error::{self, Policy, RejectedFeature},
};

/// The same permitted set governs all eight use categories.
#[test]
fn policy_checks_every_use() -> Result<(), Box<dyn Error>> {
    // Given an AES128-only config and every consumer category.
    let config = Config::parse("[libdefaults]\npermitted_enctypes = aes128-cts")?;
    let policy = CryptoPolicy::from_libdefaults(&config.libdefaults)?;
    for usage in [
        Use::RequestList,
        Use::ReplyKey,
        Use::SessionKey,
        Use::TicketKey,
        Use::AcceptorTicket,
        Use::AcceptorSubkey,
        Use::ImportedCredential,
        Use::CheckedLowLevel,
    ] {
        // When checking included and excluded wire IDs.
        policy.check_use(17, usage)?;
        let failure = policy
            .check_use(18, usage)
            .err()
            .ok_or("AES256 escaped policy")?;
        // Then the failure retains both the wire ID and intended use.
        assert!(
            matches!(failure, Policy::EnctypeNotPermitted { etype: 18_i32, usage: actual } if actual == usage)
        );
    }
    let excluded = policy
        .resolve(&EnctypeExpr::parse("aes256-cts")?)
        .err()
        .ok_or("resolve escaped allowlist")?;
    assert!(matches!(
        excluded,
        error::Config::Policy(Policy::EnctypeNotPermitted {
            etype: 18_i32,
            usage: Use::RequestList
        })
    ));
    Ok(())
}

/// Secure defaults never admit legacy, unknown or permanently forbidden IDs.
#[test]
fn policy_defaults_and_numeric_rejection() -> Result<(), Box<dyn Error>> {
    // Given default runtime policy.
    let policy = CryptoPolicy::default();
    // When resolving DEFAULT.
    let actual: Vec<i32> = policy
        .resolve(&EnctypeExpr::parse("DEFAULT")?)?
        .into_iter()
        .map(KerberosEtype::etype_id)
        .collect();
    // Then only implemented secure defaults remain.
    assert_eq!(actual, [20_i32, 19_i32, 18_i32, 17_i32]);
    for etype in [16_i32, 23_i32, 25_i32, 99_i32] {
        let failure = policy
            .check_use(etype, Use::CheckedLowLevel)
            .err()
            .ok_or("forbidden use accepted")?;
        assert!(
            matches!(failure, Policy::EnctypeNotPermitted { etype: rejected, usage: Use::CheckedLowLevel } if rejected == etype)
        );
    }
    for (etype, expected) in [
        (1_i32, RejectedFeature::SingleDes),
        (2_i32, RejectedFeature::SingleDes),
        (3_i32, RejectedFeature::SingleDes),
        (24_i32, RejectedFeature::Rc4Export),
    ] {
        let failure = policy
            .check_use(etype, Use::ReplyKey)
            .err()
            .ok_or("D2 use accepted")?;
        assert!(
            matches!(failure, Policy::RejectedFeature { feature, reason: _ } if feature == expected)
        );
    }
    Ok(())
}

/// Runtime family opt-ins and explicit membership are both required.
#[test]
fn policy_legacy_flags_and_mutated_defaults() -> Result<(), Box<dyn Error>> {
    // Given opt-ins plus explicit legacy membership.
    let config = Config::parse(
        "[libdefaults]\nallow_rc4 = true\nallow_des3 = true\npermitted_enctypes = DEFAULT rc4 des3",
    )?;
    let policy = CryptoPolicy::from_libdefaults(&config.libdefaults)?;
    // When using both legacy families under trusted runtime policy.
    policy.check_use(23, Use::TicketKey)?;
    policy.check_use(16, Use::TicketKey)?;
    // Then disabling the flag on the same public config cannot bypass validation.
    let mut defaults = config.libdefaults;
    defaults.allow_rc4 = Toggle::Disabled;
    let failure = CryptoPolicy::from_libdefaults(&defaults)
        .err()
        .ok_or("disabled RC4 accepted")?;
    assert!(matches!(failure, error::Config::DisabledEnctype { token } if token == "arcfour-hmac"));
    let mut empty = LibDefaults::new();
    empty.permitted_enctypes.clear();
    let empty_failure = CryptoPolicy::from_libdefaults(&empty)
        .err()
        .ok_or("empty policy accepted")?;
    assert!(matches!(
        empty_failure,
        error::Config::EmptyEnctypeExpression
    ));
    Ok(())
}

/// Subtractions work in all three relations, including aliases and comma separators.
#[test]
fn profile_subtractions_resolve_to_exact_ids() -> Result<(), Box<dyn Error>> {
    // Given each enctype-list relation and both modes.
    for key in [
        "default_tkt_enctypes",
        "default_tgs_enctypes",
        "permitted_enctypes",
    ] {
        for mode in [ParseMode::Compatible, ParseMode::Strict] {
            let text = format!("[libdefaults]\r\n{key} = AES256-CTS,aes128-sha1,-aes128-cts\r\n");
            // When parsing the full profile.
            let config = Config::parse_with_mode(&text, mode)?;
            let actual = match key {
                "default_tkt_enctypes" => config.libdefaults.default_tkt_enctype_ids(),
                "default_tgs_enctypes" => config.libdefaults.default_tgs_enctype_ids(),
                _ => config.libdefaults.permitted_enctype_ids(),
            };
            // Then subtraction is honored rather than ignored.
            assert_eq!(actual, [18_i32]);
        }
    }
    Ok(())
}

/// Explicit forbidden or unknown positive requests fail before allowlist narrowing.
#[test]
fn profile_rejects_disabled_unknown_and_d2_terms() -> Result<(), Box<dyn Error>> {
    // Given AS/TGS requests under an AES256-only allowlist, and direct permitted lists.
    for key in [
        "default_tkt_enctypes",
        "default_tgs_enctypes",
        "permitted_enctypes",
    ] {
        for token in ["rc4-hmac", "des3", "typo", "des-cbc-crc", "rc4-hmac-exp"] {
            for mode in [ParseMode::Compatible, ParseMode::Strict] {
                let text = format!(
                    "[libdefaults]\npermitted_enctypes = aes256-cts\n{key} = aes256-cts {token}"
                );
                if key == "permitted_enctypes" {
                    assert_eq!(
                        Config::parse_with_mode(&text, mode)?
                            .libdefaults
                            .permitted_enctype_ids(),
                        [18_i32]
                    );
                }
                let selected = if key == "permitted_enctypes" {
                    format!("[libdefaults]\n{key} = aes256-cts {token}")
                } else {
                    text
                };
                // When parsing the original positive token.
                let failure = Config::parse_with_mode(&selected, mode)
                    .err()
                    .ok_or("positive term silently dropped")?;
                // Then the exact token and typed failure class survive.
                assert!(failure.to_string().contains(token));
                match token {
                    "rc4-hmac" | "des3" => assert!(
                        matches!(failure, error::Config::DisabledEnctype { token: actual } if actual == token)
                    ),
                    "typo" => assert!(
                        matches!(failure, error::Config::UnknownEnctype { token: actual } if actual == token)
                    ),
                    _ => assert!(
                        matches!(failure, error::Config::RejectedEnctype { token: actual, source: Policy::RejectedFeature { feature: _, reason: _ } } if actual == token)
                    ),
                }
            }
        }
    }
    Ok(())
}

/// Compatible parsing exposes secure-unsupported diagnostics; strict parsing refuses.
#[test]
fn profile_camellia_diagnostics_are_visible() -> Result<(), Box<dyn Error>> {
    if camellia::AVAILABLE {
        // The leaf supports the name, so there is nothing to skip (tests/crypto_camellia.rs).
        return Ok(());
    }
    // Given a stock-policy-shaped list with implemented AES and Camellia.
    let text = "[libdefaults]\npermitted_enctypes = aes256-cts camellia";
    // When parsing through the default compatible entry point.
    let config = Config::parse(text)?;
    // Then skipped secure selections are observable and strict mode errors.
    assert!(
        matches!(config.libdefaults.diagnostics().as_ref(), [ConfigDiagnostic::UnsupportedSecureEnctype { token, until: "the `camellia` Cargo feature is enabled" }] if token == "camellia")
    );
    assert_eq!(config.libdefaults.default_tkt_enctype_ids(), [18_i32]);
    let policy = CryptoPolicy::from_libdefaults(&config.libdefaults)?;
    let resolved = policy.resolve_with_diagnostics(&EnctypeExpr::parse("aes256-cts camellia")?)?;
    assert_eq!(resolved.diagnostics().len(), 1);
    let failure = Config::parse_with_mode(text, ParseMode::Strict)
        .err()
        .ok_or("strict Camellia accepted")?;
    assert!(
        matches!(failure, error::Config::UnsupportedSecureEnctype { token, until: "the `camellia` Cargo feature is enabled" } if token == "camellia")
    );
    Ok(())
}

/// Weak crypto cannot be selected by text or by a programmatic defaults value.
#[test]
fn weak_crypto_is_permanently_rejected() -> Result<(), Box<dyn Error>> {
    // Given a positive weak-crypto relation, including one later reset to false.
    for value in ["true", "true\nallow_weak_crypto = false"] {
        // When parsing the relation.
        let failure = Config::parse(&format!("[libdefaults]\nallow_weak_crypto = {value}"))
            .err()
            .ok_or("weak crypto accepted")?;
        // Then the permanent prohibition is typed.
        assert!(matches!(
            failure,
            error::Config::Policy(Policy::RejectedFeature {
                feature: RejectedFeature::WeakCrypto,
                reason: _
            })
        ));
    }
    let config = Config::parse("[libdefaults]\nallow_weak_crypto = false")?;
    let defaults = config.libdefaults.with_allow_weak_crypto(Toggle::Enabled);
    let failure = CryptoPolicy::from_libdefaults(&defaults)
        .err()
        .ok_or("programmatic weak crypto accepted")?;
    assert!(matches!(
        failure,
        error::Config::Policy(Policy::RejectedFeature {
            feature: RejectedFeature::WeakCrypto,
            reason: _
        })
    ));
    Ok(())
}

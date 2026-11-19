use core::error::Error;

use rskrb5_ng::{
    config::{ConfigDiagnostic, EnctypeExpr, ParseMode, Toggle},
    crypto::{KerberosEtype, camellia},
    error::{self, Policy, RejectedFeature},
};

/// What the unavailable-Camellia diagnostics name as the way to make the enctypes available.
const UNTIL: &str = "the `camellia` Cargo feature is enabled";

/// Convert the resolved public values into wire IDs for exact comparisons.
fn ids(text: &str) -> Result<Vec<i32>, error::Config> {
    Ok(EnctypeExpr::parse(text)?
        .resolve(Toggle::Disabled, Toggle::Disabled, ParseMode::Compatible)?
        .enctypes()
        .iter()
        .copied()
        .map(KerberosEtype::etype_id)
        .collect())
}

/// Left-to-right selection preserves existing positions and appends removed entries.
#[test]
fn selector_order_removal_and_readdition() -> Result<(), Box<dyn Error>> {
    // Given expressions that distinguish append, duplicate and removal semantics.
    let cases: [(&str, Vec<i32>); 8] = [
        ("aes128-cts +aes256-cts aes128-cts", vec![17, 18]),
        ("aes256-cts aes128-cts -aes128-cts", vec![18]),
        (
            "aes128-cts aes256-cts -aes128-cts +aes128-cts",
            vec![18, 17],
        ),
        ("aes", vec![18, 17, 20, 19]),
        ("DEFAULT", vec![20, 19, 18, 17]),
        ("aes128-cts DEFAULT", vec![17, 20, 19, 18]),
        ("DEFAULT -aes +aes256-sha2", vec![20]),
        ("aes -DEFAULT aes128-sha1", vec![17]),
    ];
    for (text, expected) in cases {
        // When resolving the value of an enctype relation, including permitted_enctypes.
        let actual = ids(text)?;
        // Then the wire list is exact, not just a set.
        assert_eq!(actual, expected, "{text}");
    }
    Ok(())
}

/// MIT aliases, case folding and all five delimiters are accepted.
#[test]
fn aliases_case_and_delimiters() -> Result<(), Box<dyn Error>> {
    // Given every implemented MIT canonical name and alias.
    let cases: [(i32, &str); 4] = [
        (17, "aes128-cts-hmac-sha1-96 aes128-cts aes128-sha1"),
        (18, "aes256-cts-hmac-sha1-96 aes256-cts aes256-sha1"),
        (19, "aes128-cts-hmac-sha256-128 aes128-sha2"),
        (20, "aes256-cts-hmac-sha384-192 aes256-sha2"),
    ];
    for (id, aliases) in cases {
        for name in aliases.split(' ') {
            // When resolving upper-case aliases with repeated MIT separators.
            let actual = ids(&format!(" ,\t\r\n{} ,,\r\n", name.to_ascii_uppercase()))?;
            // Then aliases preserve their exact wire ID.
            assert_eq!(actual, [id]);
        }
    }
    assert_eq!(
        ids("AeS256-CtS,\r\nAeS128-CtS\tAES256-SHA2 AES128-SHA2")?,
        [18_i32, 17_i32, 20_i32, 19_i32]
    );
    Ok(())
}

/// Legacy opt-ins permit only explicitly added names and never modify DEFAULT.
#[test]
fn legacy_aliases_require_explicit_permission() -> Result<(), Box<dyn Error>> {
    // Given each legacy family/name and both possible parse modes.
    let cases: [(i32, &str); 2] = [
        (16, "des3 des3-cbc-sha1 des3-hmac-sha1 des3-cbc-sha1-kd"),
        (23, "rc4 arcfour-hmac rc4-hmac arcfour-hmac-md5"),
    ];
    for (id, names) in cases {
        for name in names.split(' ') {
            for mode in [ParseMode::Compatible, ParseMode::Strict] {
                let text = format!("aes256-cts {name}");
                let expression = EnctypeExpr::parse(&text)?;
                // When attempting a positive legacy term with no permission.
                let failure = expression
                    .resolve(Toggle::Disabled, Toggle::Disabled, mode)
                    .err()
                    .ok_or("disabled term accepted")?;
                // Then the original token is retained, including rc4-hmac in the QA case.
                assert!(
                    matches!(&failure, error::Config::DisabledEnctype { token } if token == name)
                );
                assert!(failure.to_string().contains(name));
                let allowed = expression.resolve(
                    Toggle::from_bool(id == 23_i32),
                    Toggle::from_bool(id == 16_i32),
                    mode,
                )?;
                assert_eq!(
                    allowed
                        .enctypes()
                        .iter()
                        .copied()
                        .map(KerberosEtype::etype_id)
                        .collect::<Vec<_>>(),
                    [18_i32, id]
                );
            }
        }
    }
    let defaults = EnctypeExpr::parse("DEFAULT")?.resolve(
        Toggle::Enabled,
        Toggle::Enabled,
        ParseMode::Strict,
    )?;
    assert_eq!(
        defaults
            .enctypes()
            .iter()
            .copied()
            .map(KerberosEtype::etype_id)
            .collect::<Vec<_>>(),
        [20_i32, 19_i32, 18_i32, 17_i32]
    );
    Ok(())
}

/// Known forbidden and unsupported names can be removed without enabling them.
#[test]
fn removals_accept_all_known_names() -> Result<(), Box<dyn Error>> {
    // Given removals of all unavailable classes, under strict mode and no opt-ins.
    let expression = EnctypeExpr::parse(
        "aes256-cts -rc4 -des3 -des3-cbc-raw -camellia -camellia128-cts -camellia256-cts-cmac -des-cbc-crc -des-cbc-md4 -des-cbc-md5 -des-cbc-raw -des -des3-cbc-sha1 -rc4-hmac-exp",
    );
    // When parsing an unknown family, even as a removal.
    let failure = expression.err().ok_or("des is not a MIT family")?;
    // Then unknown removal fails rather than being ignored.
    assert!(matches!(failure, error::Config::UnknownEnctype { token } if token == "-des"));
    let accepted = EnctypeExpr::parse("aes256-cts -rc4 -des3 -des3-cbc-raw -camellia -camellia128-cts -camellia256-cts-cmac -des-cbc-crc -des-cbc-md4 -des-cbc-md5 -des-cbc-raw -des3-cbc-sha1 -rc4-hmac-exp")?
        .resolve(Toggle::Disabled, Toggle::Disabled, ParseMode::Strict)?;
    assert_eq!(
        accepted
            .enctypes()
            .iter()
            .copied()
            .map(KerberosEtype::etype_id)
            .collect::<Vec<_>>(),
        [18_i32]
    );
    assert!(
        accepted.diagnostics().is_empty(),
        "removal emits no compatibility warning"
    );
    Ok(())
}

/// D2 names fail in both modes even with both legacy permissions enabled.
#[test]
fn insecure_names_are_typed_rejections() -> Result<(), Box<dyn Error>> {
    // Given removed DES aliases and all MIT export-RC4 aliases.
    for (names, feature) in [
        (
            "des-cbc-crc des-cbc-md4 des-cbc-md5 des-cbc-raw des-hmac-sha1",
            RejectedFeature::SingleDes,
        ),
        (
            "arcfour-hmac-exp rc4-hmac-exp arcfour-hmac-md5-exp",
            RejectedFeature::Rc4Export,
        ),
        ("des3-cbc-raw", RejectedFeature::WeakCrypto),
    ] {
        for name in names.split(' ') {
            for mode in [ParseMode::Compatible, ParseMode::Strict] {
                let text = format!("aes +{} -{name}", name.to_ascii_uppercase());
                // When adding a forbidden name, even if a later term removes it.
                let failure = EnctypeExpr::parse(&text)?
                    .resolve(Toggle::Enabled, Toggle::Enabled, mode)
                    .err()
                    .ok_or("D2 term accepted")?;
                // Then policy identifies the forbidden feature rather than generic unsupported crypto.
                assert!(
                    matches!(failure, error::Config::RejectedEnctype { token, source: Policy::RejectedFeature { feature: actual, reason: _ } } if actual == feature && token == format!("+{}", name.to_ascii_uppercase()))
                );
            }
        }
    }
    Ok(())
}

/// Only secure unimplemented Camellia names receive compatible-mode diagnostics.
#[test]
fn camellia_modes() -> Result<(), Box<dyn Error>> {
    if camellia::AVAILABLE {
        // The leaf resolves these names (tests/crypto_camellia.rs); nothing is skipped.
        return Ok(());
    }
    // Given each Camellia family/name/alias as originally spelled by an operator.
    for token in [
        "camellia",
        "camellia128-cts",
        "camellia128-cts-cmac",
        "camellia256-cts",
        "+CAMELLIA256-CTS-CMAC",
    ] {
        let text = format!("aes256-cts {token}");
        let expression = EnctypeExpr::parse(&text)?;
        // When resolving in compatibility mode.
        let resolved =
            expression.resolve(Toggle::Disabled, Toggle::Disabled, ParseMode::Compatible)?;
        // Then Camellia is skipped with its exact token and named future package.
        assert_eq!(
            resolved
                .enctypes()
                .iter()
                .copied()
                .map(KerberosEtype::etype_id)
                .collect::<Vec<_>>(),
            [18_i32]
        );
        assert!(
            matches!(resolved.diagnostics(), [ConfigDiagnostic::UnsupportedSecureEnctype { token: actual, until: UNTIL }] if actual == token)
        );
        let failure = expression
            .resolve(Toggle::Disabled, Toggle::Disabled, ParseMode::Strict)
            .err()
            .ok_or("strict Camellia accepted")?;
        assert!(
            matches!(failure, error::Config::UnsupportedSecureEnctype { token: actual, until: UNTIL } if actual == token)
        );
    }
    Ok(())
}

/// Unknown terms, extra operators and non-MIT delimiters must not disappear.
#[test]
fn unknown_tokens_are_named() -> Result<(), Box<dyn Error>> {
    // Given invalid selectors, including removal and Unicode whitespace.
    for token in [
        "typo",
        "ALL",
        "aes-sha1",
        "aes-sha2",
        "des",
        "-typo",
        "+",
        "-",
        "++aes",
        "--rc4",
        "aes\u{000b}rc4",
        "aes\u{00a0}rc4",
    ] {
        let text = format!("aes256-cts {token}");
        // When parsing the expression.
        let failure = EnctypeExpr::parse(&text)
            .err()
            .ok_or("unknown token accepted")?;
        // Then the entire original token is named.
        assert!(
            matches!(&failure, error::Config::UnknownEnctype { token: actual } if actual == token)
        );
        assert!(failure.to_string().contains(token));
    }
    Ok(())
}

/// Empty resolved lists always fail, including compatible-only Camellia input.
#[test]
fn empty_results_fail_closed() -> Result<(), Box<dyn Error>> {
    // Given empty or completely subtracted expression values.
    for text in [
        "",
        " ,\r\n\t",
        "DEFAULT -aes",
        "aes -DEFAULT",
        "-rc4",
        "camellia",
    ] {
        if camellia::AVAILABLE && text == "camellia" {
            // The leaf resolves the name, so the list is not empty (tests/crypto_camellia.rs).
            continue;
        }
        // When resolving with secure defaults.
        let failure = ids(text).err().ok_or("empty policy accepted")?;
        // Then no empty success can reach a caller.
        assert!(matches!(failure, error::Config::EmptyEnctypeExpression));
    }
    Ok(())
}

/// Parser allocations and diagnostic counts are bounded before token collection.
#[test]
fn oversized_expressions_are_rejected() -> Result<(), Box<dyn Error>> {
    // Given input above the documented 64 KiB limit.
    let text = " ".repeat(0x0001_0001);
    // When parsing before allocation of terms.
    let failure = EnctypeExpr::parse(&text)
        .err()
        .ok_or("oversized expression accepted")?;
    // Then the size budget is explicit and typed.
    assert!(matches!(
        failure,
        error::Config::EnctypeExpressionTooLarge {
            maximum: 0x0001_0000
        }
    ));
    Ok(())
}

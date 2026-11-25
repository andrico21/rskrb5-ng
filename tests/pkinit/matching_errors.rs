//! `pkinit_cert_match` rejections: a malformed or unbounded rule is a typed
//! error naming the rule, never skipped (MIT skips some, `pkinit_matching.c:650-656`).

use rskrb5_ng::{
    Config,
    client::principal::Principal,
    error::Pkinit,
    preauth::pkinit::{ConfiguredIdentities, IdentityProvider as _},
};

use crate::matching::{REALM, TestError, config, dir, select};

/// The rule of a `CertificateRule` error, or the unexpected outcome.
fn refused_rule(rules: &[&str]) -> Result<String, TestError> {
    match ConfiguredIdentities::from_config(&config(&["bob"], rules)?, REALM) {
        Err(Pkinit::CertificateRule { rule, reason: _ }) => Ok(rule),
        other => Err(format!("{rules:?}: {other:?}").into()),
    }
}

/// Every rule the bounded engine cannot honour identically is refused, with the
/// rule text in the error.
#[test]
fn malformed_certificate_rules_are_typed_errors_naming_the_rule() -> Result<(), TestError> {
    for rule in [
        // The component values MIT rejects.
        "<EKU>",
        "<EKU>bogus",
        "<EKU>pkinit,,clientAuth",
        "<EKU>pk",
        "<KU>sign",
        "<SUBJECT>",
        "&&<SAN>",
        "<SUBJECT>CN=bob<EKU>",
        // Patterns POSIX regcomp rejects.
        "<SUBJECT>(",
        "<SUBJECT>[a",
        "<SUBJECT>a{2",
        "<SUBJECT>*x",
        // Constructs the Rust engine would read differently from POSIX.
        "<SUBJECT>(a)\\1",
        "<SUBJECT>\\d",
        "<SUBJECT>\\w+",
        "<SUBJECT>\\<bob",
        "<SUBJECT>bob\\",
        "<SUBJECT>(?i)bob",
        "<SUBJECT>[\\d]",
        "<SUBJECT>[a\\]]",
        "<SUBJECT>[[:word:]]",
        "<SUBJECT>[a&&b]",
        "<SUBJECT>[a--b]",
        "<SUBJECT>[[.a.]]",
        "<SUBJECT>[[=a=]]",
        "<SUBJECT>[a[b]]",
    ] {
        assert_eq!(refused_rule(&[rule])?, rule, "{rule}");
    }
    Ok(())
}

/// A malformed rule is refused even when an earlier rule would select an identity.
#[test]
fn a_malformed_rule_is_not_skipped_behind_a_matching_one() -> Result<(), TestError> {
    assert_eq!(select(&["bob"], &["<SUBJECT>CN=bob$"])?, "bob");
    assert_eq!(
        refused_rule(&["<SUBJECT>CN=bob$", "<EKU>bogus"])?,
        "<EKU>bogus"
    );
    let result = select(&["bob"], &["<SUBJECT>CN=bob$", "<EKU>bogus"]);
    assert!(
        matches!(result, Err(Pkinit::CertificateRule { rule: _, reason: _ })),
        "{result:?}"
    );
    Ok(())
}

/// The bounds on rules, patterns, components and identities.
#[test]
fn certificate_rule_bounds_are_enforced() -> Result<(), TestError> {
    let long_pattern = format!("<SUBJECT>{}", "a".repeat(513));
    assert_eq!(refused_rule(&[&long_pattern])?, long_pattern);
    let many_components = "<KU>digitalSignature".repeat(9);
    assert_eq!(refused_rule(&[&many_components])?, many_components);
    let long_rule = format!("<SUBJECT>{}", "a|".repeat(1100));
    assert_eq!(refused_rule(&[&long_rule])?, long_rule);
    let deep = format!("<SUBJECT>{}a{}", "(".repeat(17), ")".repeat(17));
    assert_eq!(refused_rule(&[&deep])?, deep);
    let rules = vec!["<SUBJECT>CN=bob$"; 33];
    let too_many = ConfiguredIdentities::from_config(&config(&["bob"], &rules)?, REALM);
    assert!(
        matches!(
            too_many,
            Err(Pkinit::TooLarge {
                structure: "pkinit_cert_match",
                limit: 32
            })
        ),
        "{too_many:?}"
    );
    let identities = vec!["bob"; 21];
    let crowded = ConfiguredIdentities::from_config(&config(&identities, &[])?, REALM);
    assert!(
        matches!(
            crowded,
            Err(Pkinit::TooLarge {
                structure: "pkinit_identities",
                limit: 20
            })
        ),
        "{crowded:?}"
    );
    Ok(())
}

/// An identity that cannot be read fails the selection: the other identity that
/// matches is not chosen in its place.
#[test]
fn an_unreadable_candidate_fails_the_selection() -> Result<(), TestError> {
    let base = dir().join("bob").display().to_string();
    let profile = Config::parse(&format!(
        "[libdefaults]\n default_realm = {REALM}\n[realms]\n {REALM} = {{\n kdc = 127.0.0.1:1\n \
         pkinit_identities = FILE:{base}.pem,{base}.key\n \
         pkinit_identities = FILE:{}/missing.pem\n pkinit_cert_match = <SUBJECT>CN=bob$\n }}\n",
        dir().display()
    ))?;
    let provider = ConfiguredIdentities::from_config(&profile, REALM)?;
    let result = provider.identity(&Principal::user(REALM, "bob"));
    let error = result.err().ok_or("an unreadable candidate was skipped")?;
    assert!(
        matches!(
            error.downcast_ref::<Pkinit>(),
            Some(Pkinit::Io { path: _, source: _ })
        ),
        "{error:?}"
    );
    Ok(())
}

/// Only the selected identity's key is loaded.
///
/// An RSA key (which the software signer does not take) on a candidate that is
/// not selected is not an error; on the selected one it is a typed error.
#[test]
fn only_the_selected_identitys_key_is_loaded() -> Result<(), TestError> {
    assert_eq!(select(&["bob", "henry"], &["<SUBJECT>CN=bob$"])?, "bob");
    let selected = select(&["bob", "henry"], &["<SUBJECT>CN=henry$"]);
    assert!(
        matches!(selected, Err(Pkinit::Identity { reason: _ })),
        "{selected:?}"
    );
    Ok(())
}

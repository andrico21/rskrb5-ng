//! MIT 1.22.2 `t_localauth.py`: its `krb5_aname_to_localname` cases.
//!
//! The expected values are MIT's own (`src/tests/t_localauth.py`), driven
//! through `krb5.conf` text, plus the one case where this crate is stricter.

#![cfg(feature = "localauth")]

use rskrb5_ng::{
    config::Config,
    error::LocalAuth,
    localauth::{AuthToLocalRule, LocalNameMapper, principal_to_local_name},
};

use crate::support::{TestError, mapper, principal};

/// What `principal_to_local_name` answers for `text` under `realm_lines`.
fn translate(realm_lines: &str, text: &str) -> Result<Result<String, LocalAuth>, TestError> {
    Ok(principal_to_local_name(&mapper(realm_lines)?, &principal(text)))
}

/// `translate` expecting a translation.
fn local(realm_lines: &str, text: &str) -> Result<String, TestError> {
    Ok(translate(realm_lines, text)??)
}

/// `translate` expecting MIT's "No translation".
fn none(realm_lines: &str, text: &str) -> Result<bool, TestError> {
    Ok(matches!(
        translate(realm_lines, text)?,
        Err(LocalAuth::NoTranslation)
    ))
}

/// `t_localauth.py` "default": single component, or a second component equal
/// to the default realm, in the default realm only.
#[test]
fn default_rule_works_in_the_default_realm_only() -> Result<(), TestError> {
    assert_eq!(local("", "user@KRBTEST.COM")?, "user");
    assert_eq!(local("", "user/KRBTEST.COM@KRBTEST.COM")?, "user");
    assert!(none("", "user/KRBTEST.COM/x@KRBTEST.COM")?, "three components");
    assert!(none("", "user/X@KRBTEST.COM")?, "second component mismatch");
    assert!(none("", "user@X")?, "realm mismatch");
    Ok(())
}

/// `t_localauth.py` `auth_to_local_names`: the name without realm is the key.
///
/// The match is case-sensitive.
#[test]
fn names_map_by_case_sensitive_name() -> Result<(), TestError> {
    let names = " auth_to_local_names = {\n  user = abcd\n }";
    assert_eq!(local(names, "user@KRBTEST.COM")?, "abcd");
    assert_eq!(local(names, "x@KRBTEST.COM")?, "x");
    assert_eq!(local(names, "User@KRBTEST.COM")?, "User");
    Ok(())
}

/// Stricter than MIT (`t_localauth.py` maps `user@X` to `abcd`): an explicit
/// name of the default realm never translates a principal of another realm,
/// and the `DEFAULT` fallback does not apply to it either.
#[test]
fn names_do_not_translate_foreign_realms() -> Result<(), TestError> {
    let names = " auth_to_local_names = {\n  user = abcd\n }";
    assert!(none(names, "user@X")?, "foreign realm");
    Ok(())
}

/// `t_localauth.py`: names live in the default realm's section only.
#[test]
fn names_of_another_realms_section_are_ignored() -> Result<(), TestError> {
    let text = "[libdefaults]\n default_realm = KRBTEST.COM\n[realms]\n X = {\n auth_to_local_names = {\n  user = abcd\n }\n }\n";
    let config = Config::parse(text)?;
    let mapper = LocalNameMapper::from_config(&config)?;
    assert!(matches!(
        principal_to_local_name(&mapper, &principal("user@X")),
        Err(LocalAuth::NoTranslation)
    ));
    Ok(())
}

/// `t_localauth.py` "explicit default" and `auth_to_local` "invalid".
#[test]
fn explicit_default_and_invalid_types() -> Result<(), TestError> {
    assert_eq!(local(" auth_to_local = DEFAULT", "user@KRBTEST.COM")?, "user");
    assert!(matches!(
        AuthToLocalRule::parse("RULE"),
        Err(LocalAuth::MalformedRule { reason: _ })
    ));
    assert!(matches!(
        AuthToLocalRule::parse("UNRECOGNIZED:stuff"),
        Err(LocalAuth::UnsupportedRuleType { kind: _ })
    ));
    Ok(())
}

/// `t_localauth.py` "rule (empty)": the selection string is the principal
/// name without realm, and a foreign realm still translates.
#[test]
fn empty_rule_selects_the_name_without_realm() -> Result<(), TestError> {
    let rule = " auth_to_local = RULE:";
    assert_eq!(local(rule, "user@KRBTEST.COM")?, "user");
    assert_eq!(local(rule, "user@X")?, "user");
    assert_eq!(local(rule, "a/b/c@X")?, "a/b/c");
    Ok(())
}

/// `t_localauth.py` "rule (selection string)": `$0` is the realm, and a
/// configured rule suppresses `DEFAULT`.
#[test]
fn selection_string_and_suppressed_default() -> Result<(), TestError> {
    let rule = " auth_to_local = RULE:[2:$0.$2.$1]";
    assert_eq!(local(rule, "aaron/burr@REALM")?, "REALM.burr.aaron");
    assert!(none(rule, "user@KRBTEST.COM")?, "DEFAULT is suppressed");
    Ok(())
}

/// `t_localauth.py` "rule (match string)": the regex must match the whole
/// selection string.
#[test]
fn match_string_is_anchored_at_both_ends() -> Result<(), TestError> {
    let rule = " auth_to_local = RULE:(.*tail)";
    assert_eq!(local(rule, "withtail@X")?, "withtail");
    assert_eq!(local(rule, "x/withtail@X")?, "x/withtail");
    assert!(none(rule, "tails@X")?, "anchor mismatch");
    Ok(())
}

/// `t_localauth.py` "rule (substitutions)": once, globally, and in sequence.
#[test]
fn substitutions_once_globally_and_in_sequence() -> Result<(), TestError> {
    assert_eq!(
        local(" auth_to_local = RULE:s/birds/bees/", "thebirdsbirdsbirds@X")?,
        "thebeesbirdsbirds"
    );
    assert_eq!(
        local(
            " auth_to_local = RULE:s/birds/bees/g  s/bees/birds/",
            "the/birdsbirdsbirds@x"
        )?,
        "the/birdsbeesbees"
    );
    Ok(())
}

/// `t_localauth.py` "rule (combo)": values are tried in order, the first that
/// translates wins and `DEFAULT` can sit between rules.
#[test]
fn combination_of_rules_in_order() -> Result<(), TestError> {
    let combo = " auth_to_local = RULE:[1:$1-$0](fred.*)s/-/ /g\n auth_to_local = DEFAULT\n auth_to_local = RULE:[3:$1](z.*z)";
    assert_eq!(local(combo, "fred@X")?, "fred X");
    assert_eq!(local(combo, "fred-too@X")?, "fred too X");
    assert_eq!(local(combo, "fred@KRBTEST.COM")?, "fred KRBTEST.COM");
    assert_eq!(local(combo, "user@KRBTEST.COM")?, "user");
    assert_eq!(local(combo, "zazz/b/c@X")?, "zazz");
    assert!(none(combo, "a/b@KRBTEST.COM")?, "no rule applies");
    Ok(())
}

/// Without a default realm nothing translates, whatever the realm of the
/// principal (an empty realm must not equal an empty default).
#[test]
fn no_default_realm_means_no_translation() -> Result<(), TestError> {
    let config = Config::parse("[realms]\n KRBTEST.COM = {\n }\n")?;
    let mapper = LocalNameMapper::from_config(&config)?;
    assert!(matches!(
        principal_to_local_name(&mapper, &principal("user@KRBTEST.COM")),
        Err(LocalAuth::NoTranslation)
    ));
    assert!(matches!(
        principal_to_local_name(&mapper, &principal("user@")),
        Err(LocalAuth::NoTranslation)
    ));
    Ok(())
}

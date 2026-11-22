//! Malformed, hostile and over-bound rules and inputs: each is refused, none
//! takes unbounded time or space.

use rskrb5_ng::{
    ccache::Principal,
    error::LocalAuth,
    localauth::{
        AuthToLocalRule, LocalNameMapper, MAX_LOCAL_NAME_BYTES, MAX_MATCHES, MAX_PATTERN_BYTES, MAX_REPLACEMENT_BYTES,
        MAX_RULE_BYTES, MAX_RULES, MAX_SELECTION_BYTES, MAX_SUBSTITUTIONS, principal_to_local_name,
    },
};

use crate::support::{TestError, principal};

/// A mapper whose only rule is `rule`.
fn only(rule: &str) -> Result<LocalNameMapper, TestError> {
    Ok(LocalNameMapper::new(Some("R".to_owned())).with_rules(vec![AuthToLocalRule::parse(rule)?])?)
}

/// The translation of `text` by the single rule `rule`.
fn apply(rule: &str, text: &str) -> Result<Result<String, LocalAuth>, TestError> {
    Ok(principal_to_local_name(&only(rule)?, &principal(text)))
}

/// Syntax errors are refused when the rule is parsed (MIT finds them when the
/// rule is first evaluated, `KRB5_CONFIG_BADFORMAT`).
#[test]
fn malformed_rules_are_refused_at_parse_time() {
    for rule in [
        "RULE:[x:$1]",
        "RULE:[1:$1",
        "RULE:[1$1]",
        "RULE:[2:$3]",
        "RULE:[1:$]",
        "RULE:[1:$x]",
        "RULE:[1:$-1]",
        "RULE:[-1:$1]",
        "RULE:(abc",
        "RULE:s/a/b",
        "RULE:s/a",
        "RULE:s/a/b/ x",
        "RULE:s/a/b/ ",
        "RULE:x/a/b/",
        "DEFAULT:x",
        "default",
        "",
    ] {
        assert!(
            matches!(
                AuthToLocalRule::parse(rule),
                Err(LocalAuth::MalformedRule { reason: _ } | LocalAuth::UnsupportedRuleType { kind: _ })
            ),
            "{rule:?} must be refused"
        );
    }
}

/// A pattern the regex compiler refuses is refused when the rule is parsed.
///
/// MIT treats it as "rule does not apply". Back-references and look-around do
/// not exist in the linear-time engine, groups cannot nest deeply and a
/// pattern that expands past the compiled-size limit does not compile.
#[test]
fn patterns_the_engine_cannot_run_are_refused() {
    let deep = format!("RULE:s/{}a{}/x/", "(".repeat(40), ")".repeat(40));
    for rule in [
        "RULE:(a(b)",
        r"RULE:s/(a)\1/x/",
        "RULE:s/(?=a)b/x/",
        "RULE:s/(?<=a)b/x/",
        "RULE:s/[/x/",
        "RULE:s/a{1000}{1000}{1000}/x/",
        "RULE:s/((a{100}){100}){100}/x/",
        deep.as_str(),
    ] {
        assert!(
            matches!(
                AuthToLocalRule::parse(rule),
                Err(LocalAuth::InvalidRegex { message: _ })
            ),
            "{rule:?} must be refused"
        );
    }
}

/// Every size bound refuses at parse time, and the bound itself still parses.
#[test]
fn size_bounds_refuse_and_the_bound_itself_parses() {
    let parses = |text: String| AuthToLocalRule::parse(&text).is_ok();
    let limit = |text: String| {
        matches!(
            AuthToLocalRule::parse(&text),
            Err(LocalAuth::LimitExceeded { what: _, limit: _ })
        )
    };
    let over = |bound: usize| bound.saturating_add(1);
    assert!(parses(format!("RULE:({})", "a".repeat(MAX_PATTERN_BYTES))));
    assert!(limit(format!("RULE:({})", "a".repeat(over(MAX_PATTERN_BYTES)))));
    assert!(limit(format!("RULE:s/{}/x/", "a".repeat(over(MAX_PATTERN_BYTES)))));
    assert!(parses(format!("RULE:s/a/{}/", "b".repeat(MAX_REPLACEMENT_BYTES))));
    assert!(limit(format!("RULE:s/a/{}/", "b".repeat(over(MAX_REPLACEMENT_BYTES)))));
    assert!(parses(format!("RULE:{}", "s/a/b/".repeat(MAX_SUBSTITUTIONS))));
    assert!(limit(format!("RULE:{}", "s/a/b/".repeat(over(MAX_SUBSTITUTIONS)))));
    assert!(limit(format!("RULE:{}", " ".repeat(MAX_RULE_BYTES))));
}

/// More than `MAX_RULES` rules do not make a mapper.
#[test]
fn rule_count_is_bounded() {
    let rules = |count: usize| vec![AuthToLocalRule::default_rule(); count];
    let accepted = LocalNameMapper::new(None)
        .with_rules(rules(MAX_RULES))
        .is_ok();
    assert!(accepted, "the bound itself");
    assert!(matches!(
        LocalNameMapper::new(None).with_rules(rules(MAX_RULES.saturating_add(1))),
        Err(LocalAuth::LimitExceeded { what: _, limit: _ })
    ));
}

/// A pattern that backtracks exponentially in other engines finishes: the
/// match is linear in the selection string.
#[test]
fn catastrophic_patterns_run_in_linear_time() -> Result<(), TestError> {
    let subject = format!("{}b@R", "a".repeat(900));
    assert!(matches!(
        apply("RULE:(a*a*a*a*a*a*a*c)", &subject)?,
        Err(LocalAuth::NoTranslation)
    ));
    assert_eq!(apply("RULE:s/(a+)+b/x/", &subject)??, "x");
    Ok(())
}

/// A substitution that matches the empty string neither loops (MIT's
/// `do_replacement` does) nor grows past the bound: the replacement count is
/// capped and the result is refused.
#[test]
fn empty_matches_terminate() -> Result<(), TestError> {
    assert_eq!(apply("RULE:s/x*/-/g", "abc@R")??, "-a-b-c-");
    let long = principal(&format!("{}@R", "a".repeat(MAX_MATCHES)));
    assert!(matches!(
        principal_to_local_name(&only("RULE:s/x*/-/g")?, &long),
        Err(LocalAuth::LimitExceeded { what: _, limit: _ })
    ));
    Ok(())
}

/// The selection string is bounded; a longer one is refused, not truncated.
#[test]
fn selection_string_is_bounded() -> Result<(), TestError> {
    let at_limit = principal(&format!("{}@R", "a".repeat(MAX_SELECTION_BYTES)));
    let over = principal(&format!("{}@R", "a".repeat(MAX_SELECTION_BYTES.saturating_add(1))));
    let mapper = only("RULE:[1:$1]s/a+/u/")?;
    assert_eq!(principal_to_local_name(&mapper, &at_limit)?, "u");
    assert!(matches!(
        principal_to_local_name(&mapper, &over),
        Err(LocalAuth::LimitExceeded { what: _, limit: _ })
    ));
    Ok(())
}

/// A translation that is not a usable account name is refused, never returned.
#[test]
fn unusable_translations_are_refused() -> Result<(), TestError> {
    let invalid = |result: Result<String, LocalAuth>| {
        matches!(result, Err(LocalAuth::InvalidLocalName { reason: _ }))
    };
    assert!(invalid(principal_to_local_name(&only("RULE:s/.*//")?, &principal("a@R"))));
    let long = format!("RULE:s/^/{}/", "x".repeat(MAX_LOCAL_NAME_BYTES));
    assert!(invalid(principal_to_local_name(&only(&long)?, &principal("a@R"))));
    let nul = Principal::new("R", 1, vec!["a\0b".to_owned()]);
    let default = LocalNameMapper::new(Some("R".to_owned()));
    assert!(invalid(principal_to_local_name(&default, &nul)));
    Ok(())
}

/// A component that holds `@` makes the name without realm ambiguous: the
/// explicit mapping never matches it and the unselected rule refuses it.
#[test]
fn at_sign_in_a_component_is_ambiguous() -> Result<(), TestError> {
    let tricky = Principal::new("R", 1, vec!["alice@EVIL".to_owned()]);
    let named = LocalNameMapper::new(Some("R".to_owned())).with_name("alice@EVIL", "root");
    assert_ne!(
        principal_to_local_name(&named, &tricky).ok().as_deref(),
        Some("root")
    );
    assert!(matches!(
        principal_to_local_name(&only("RULE:")?, &tricky),
        Err(LocalAuth::NoTranslation)
    ));
    Ok(())
}

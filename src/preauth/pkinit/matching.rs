//! `pkinit_cert_match`: the rules that choose the client certificate.
//!
//! This is the client half of MIT 1.22.2 `pkinit_matching.c`.
//!
//! A rule is `[&&|||]` then one or more components written back to back:
//! `<SUBJECT>`, `<ISSUER>` and `<SAN>` followed by a POSIX extended regular
//! expression, `<EKU>` and `<KU>` followed by a comma-separated keyword list.
//! `&&` (the default) needs every component, `||` any one. The rules are tried
//! in order over every candidate certificate and the first rule that selects
//! exactly one certificate wins; a rule that selects none or several leaves
//! the decision to the next (`pkinit_matching.c:643-696`).
//!
//! # Security
//!
//! - More than one match is never resolved by taking the first: when no rule
//!   selects exactly one certificate the selection fails with
//!   [`Error::AmbiguousCertificates`] (some rule matched several) or
//!   [`Error::NoMatchingCertificate`].
//! - A malformed rule is [`Error::CertificateRule`], naming the rule; MIT
//!   skips the rules that are `EINVAL` (`pkinit_matching.c:650-656`), this
//!   client never does.
//! - The engine is the linear-time `regex` crate. A pattern is accepted only
//!   when POSIX and the engine read it alike (see `matching_pattern.rs`);
//!   back-references, Perl escapes and the other non-POSIX forms are refused.
//!   Rule count, rule and pattern length, components, candidates and the text
//!   one selection may scan are bounded ([`MAX_RULES`], [`MAX_RULE_BYTES`],
//!   [`MAX_PATTERN_BYTES`], [`MAX_COMPONENTS`], [`MAX_CANDIDATES`],
//!   [`MAX_MATCH_BYTES`]).
//! - Differences from MIT: no `<KU>`/`<EKU>` keyword prefix is accepted
//!   (MIT's `strncasecmp(value, keyword, len)` takes `pk` for `pkinit` and then
//!   reads past the value), names are matched per Unicode scalar and not per
//!   byte, and a name that OpenSSL cannot print fails the selection as in MIT.

use regex::Regex;

use super::{
    matching_facts::{EKU_KEYWORDS, Facts, KU_KEYWORDS},
    matching_pattern,
};
use crate::error::Pkinit as Error;

/// The most rules one `pkinit_cert_match` list holds.
pub const MAX_RULES: usize = 32;
/// The longest rule, in bytes.
pub const MAX_RULE_BYTES: usize = 2048;
/// The longest regular expression of one component, in bytes.
pub const MAX_PATTERN_BYTES: usize = 512;
/// The most components of one rule.
pub const MAX_COMPONENTS: usize = 8;
/// The most candidate certificates (MIT `MAX_CREDS_ALLOWED`,
/// `pkinit_crypto_openssl.c:60`).
pub const MAX_CANDIDATES: usize = 20;
/// The most bytes of certificate text one selection matches against.
pub const MAX_MATCH_BYTES: usize = 1024 * 1024;

/// The component keywords, as MIT's `matching_keywords` (case-sensitive).
const KEYWORDS: [&str; 5] = ["<KU>", "<EKU>", "<SAN>", "<ISSUER>", "<SUBJECT>"];

/// What one component tests.
#[derive(Clone, Debug)]
enum Component {
    /// `<SUBJECT>`.
    Subject(Regex),
    /// `<ISSUER>`.
    Issuer(Regex),
    /// `<SAN>`: any PKINIT principal or UPN.
    San(Regex),
    /// `<EKU>`: all these bits.
    Eku(u8),
    /// `<KU>`: all these bits.
    Ku(u8),
}

/// How the components of a rule combine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Relation {
    /// `&&` or the default: every component.
    All,
    /// `||`: any component.
    Any,
}

/// One compiled rule.
#[derive(Clone, Debug)]
struct Rule {
    /// How the components combine.
    relation: Relation,
    /// The components, in order.
    components: Vec<Component>,
}

/// The compiled `pkinit_cert_match` rules of a realm.
///
/// Equality compares the rule texts.
#[derive(Clone, Debug)]
pub struct CertificateRules {
    /// The rule texts, as configured.
    sources: Vec<String>,
    /// The compiled rules, in the same order.
    rules: Vec<Rule>,
}

impl PartialEq for CertificateRules {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.sources == other.sources
    }
}

impl Eq for CertificateRules {}

/// The keyword that starts `text`, if any.
fn keyword_at(text: &str) -> Option<&'static str> {
    KEYWORDS.iter().find(|keyword| text.starts_with(**keyword)).copied()
}

/// The bits of a comma-separated keyword list (MIT `parse_list_value`, with
/// exact keywords and one optional trailing comma).
///
/// # Errors
/// Returns the reason for an unknown, empty or truncated keyword.
fn list_bits(value: &str, table: &[(&str, u8)]) -> Result<u8, &'static str> {
    let body = value.strip_suffix(',').unwrap_or(value);
    let mut bits = 0;
    for item in body.split(',') {
        let (_, bit) = table
            .iter()
            .find(|(keyword, _)| keyword.eq_ignore_ascii_case(item))
            .ok_or("an unknown or empty key usage keyword")?;
        bits |= bit;
    }
    Ok(bits)
}

/// The component of `keyword` over `value`.
///
/// # Errors
/// Returns the reason the pattern or the list is refused.
fn component(keyword: &str, value: &str) -> Result<Component, &'static str> {
    Ok(match keyword {
        "<SUBJECT>" => Component::Subject(matching_pattern::compile(value)?),
        "<ISSUER>" => Component::Issuer(matching_pattern::compile(value)?),
        "<SAN>" => Component::San(matching_pattern::compile(value)?),
        "<EKU>" => Component::Eku(list_bits(value, &EKU_KEYWORDS)?),
        _ => Component::Ku(list_bits(value, &KU_KEYWORDS)?),
    })
}

/// Parse one rule (MIT `parse_rule_set`).
///
/// # Errors
/// Returns the reason the rule is refused.
fn parse_rule(text: &str) -> Result<Rule, &'static str> {
    if text.len() > MAX_RULE_BYTES {
        return Err("the rule is over the length bound");
    }
    let (relation, mut rest) = match (text.strip_prefix("&&"), text.strip_prefix("||")) {
        (Some(rest), _) => (Relation::All, rest),
        (None, Some(rest)) => (Relation::Any, rest),
        (None, None) => (Relation::All, text),
    };
    let mut components = Vec::new();
    while !rest.is_empty() {
        let keyword = keyword_at(rest).ok_or("a missing or unknown component keyword")?;
        let after = rest.get(keyword.len()..).unwrap_or_default();
        let end = after
            .char_indices()
            .find(|(index, _)| keyword_at(after.get(*index..).unwrap_or_default()).is_some())
            .map_or(after.len(), |(index, _)| index);
        let (value, next) = after.split_at(end);
        if value.is_empty() {
            return Err("a component without a value");
        }
        if components.len() == MAX_COMPONENTS {
            return Err("the rule has too many components");
        }
        components.push(component(keyword, value)?);
        rest = next;
    }
    if components.is_empty() {
        return Err("a rule without a component");
    }
    Ok(Rule {
        relation,
        components,
    })
}

/// Match `regex` against `text`, spending its length from `budget`.
///
/// # Errors
/// Returns [`Error::TooLarge`] when the work budget is spent.
fn is_match(regex: &Regex, text: &str, budget: &mut usize) -> Result<bool, Error> {
    *budget = budget.checked_sub(text.len()).ok_or(Error::TooLarge {
        structure: "pkinit_cert_match matching work",
        limit: MAX_MATCH_BYTES,
    })?;
    Ok(regex.is_match(text))
}

impl Component {
    /// Whether the certificate described by `facts` satisfies this component.
    ///
    /// # Errors
    /// Returns [`Error::TooLarge`] when the work budget is spent.
    fn matches(&self, facts: &Facts, budget: &mut usize) -> Result<bool, Error> {
        Ok(match self {
            Self::Subject(regex) => is_match(regex, &facts.subject, budget)?,
            Self::Issuer(regex) => is_match(regex, &facts.issuer, budget)?,
            Self::San(regex) => {
                for name in &facts.sans {
                    if is_match(regex, name, budget)? {
                        return Ok(true);
                    }
                }
                false
            }
            Self::Eku(bits) => facts.eku & bits == *bits,
            Self::Ku(bits) => facts.ku & bits == *bits,
        })
    }
}

impl Rule {
    /// Whether the certificate satisfies the rule, short-circuiting in order.
    ///
    /// # Errors
    /// Returns [`Error::TooLarge`] when the work budget is spent.
    fn matches(&self, facts: &Facts, budget: &mut usize) -> Result<bool, Error> {
        for component in &self.components {
            let matched = component.matches(facts, budget)?;
            match (self.relation, matched) {
                (Relation::Any, true) => return Ok(true),
                (Relation::All, false) => return Ok(false),
                (Relation::Any, false) | (Relation::All, true) => {}
            }
        }
        Ok(self.relation == Relation::All)
    }
}

impl CertificateRules {
    /// Compile the rules of a `pkinit_cert_match` list, in order.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TooLarge`] for more than [`MAX_RULES`] rules and
    /// [`Error::CertificateRule`] for a rule that is malformed, over a bound
    /// or uses a pattern construct the bounded engine does not honour.
    #[inline]
    pub fn parse<S>(rules: &[S]) -> Result<Self, Error>
    where
        S: AsRef<str>,
    {
        if rules.len() > MAX_RULES {
            return Err(Error::TooLarge {
                structure: "pkinit_cert_match",
                limit: MAX_RULES,
            });
        }
        let mut sources = Vec::new();
        let mut compiled = Vec::new();
        for source in rules {
            let text = source.as_ref();
            compiled.push(parse_rule(text).map_err(|reason| Error::CertificateRule {
                rule: text.to_owned(),
                reason,
            })?);
            sources.push(text.to_owned());
        }
        Ok(Self {
            sources,
            rules: compiled,
        })
    }

    /// The rule texts, as configured.
    #[inline]
    #[must_use]
    pub fn sources(&self) -> &[String] {
        &self.sources
    }

    /// The index in `certificates` (DER) of the one certificate the rules
    /// select.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TooLarge`] for more than [`MAX_CANDIDATES`]
    /// certificates or past [`MAX_MATCH_BYTES`] of matched text,
    /// [`Error::Malformed`] for a certificate that cannot be read,
    /// [`Error::AmbiguousCertificates`] when no rule selects exactly one and
    /// some rule matched several, and [`Error::NoMatchingCertificate`] when
    /// no rule matched anything.
    #[inline]
    pub fn select(&self, certificates: &[&[u8]]) -> Result<usize, Error> {
        if certificates.len() > MAX_CANDIDATES {
            return Err(Error::TooLarge {
                structure: "pkinit_identities",
                limit: MAX_CANDIDATES,
            });
        }
        let facts = certificates
            .iter()
            .map(|der| Facts::from_der(der))
            .collect::<Result<Vec<_>, _>>()?;
        let mut budget = MAX_MATCH_BYTES;
        let mut ambiguous = false;
        for rule in &self.rules {
            let mut chosen = None;
            let mut count = 0_usize;
            for (index, candidate) in facts.iter().enumerate() {
                if rule.matches(candidate, &mut budget)? {
                    chosen = Some(index);
                    count = count.saturating_add(1);
                }
            }
            match (count, chosen) {
                (1, Some(index)) => return Ok(index),
                (0, _) => {}
                _ => ambiguous = true,
            }
        }
        let candidates = facts.len();
        Err(if ambiguous {
            Error::AmbiguousCertificates { candidates }
        } else {
            Error::NoMatchingCertificate { candidates }
        })
    }
}

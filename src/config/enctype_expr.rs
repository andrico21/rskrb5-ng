//! Ordered MIT enctype-list expressions.

use core::str::FromStr;

use super::{
    ConfigDiagnostic, EnctypeExpr, EnctypeOperation, EnctypeTerm, ParseMode, ResolvedEnctypes,
    Toggle, enctype_names,
};
use crate::{
    crypto::{KerberosEtype, camellia},
    error::{Config as Error, Policy, RejectionReason},
};

/// Ordered, nonempty implemented encryption types.
pub(super) fn enctypes(this: &ResolvedEnctypes) -> &[KerberosEtype] {
    &this.enctypes
}

/// Diagnostics for every skipped positive secure unsupported term.
pub(super) fn diagnostics(this: &ResolvedEnctypes) -> &[ConfigDiagnostic] {
    &this.diagnostics
}

/// Parse at most 64 KiB into known selectors, retaining their order and spelling.
///
/// # Errors
/// Returns [`Error::EnctypeExpressionTooLarge`] before allocating tokens for
/// oversized input, or [`Error::UnknownEnctype`] naming an unknown token.
/// Recognition of a forbidden name is not permission; call [`Self::resolve`].
pub(super) fn parse(text: &str) -> Result<EnctypeExpr, Error> {
    (text.len() <= 0x0001_0000).ok_or(Error::EnctypeExpressionTooLarge {
        maximum: 0x0001_0000,
    })?;
    let terms = text
        .split([' ', '\t', '\r', '\n', ','])
        .filter(|token| !token.is_empty())
        .map(|token| {
            let (name, operation) = token.strip_prefix('-').map_or_else(
                || {
                    (
                        token.strip_prefix('+').unwrap_or(token),
                        EnctypeOperation::Add,
                    )
                },
                |name| (name, EnctypeOperation::Remove),
            );
            let selector =
                enctype_names::Selector::parse(name).ok_or_else(|| Error::UnknownEnctype {
                    token: token.to_owned(),
                })?;
            Ok(EnctypeTerm {
                token: token.to_owned(),
                selector,
                operation,
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;
    Ok(EnctypeExpr { terms })
}

/// Resolve using explicit RC4 and DES3 runtime permissions and parsing mode.
///
/// # Errors
/// Returns [`Error::RejectedEnctype`] with a typed policy cause for D2 terms,
/// [`Error::DisabledEnctype`] for disabled legacy terms,
/// [`Error::UnsupportedSecureEnctype`] for Camellia in strict mode, and
/// [`Error::EmptyEnctypeExpression`] when nothing remains.
pub(super) fn resolve(
    this: &EnctypeExpr,
    allow_rc4: Toggle,
    allow_des3: Toggle,
    mode: ParseMode,
) -> Result<ResolvedEnctypes, Error> {
    let mut result = ResolvedEnctypes {
        enctypes: Vec::new(),
        diagnostics: Vec::new(),
    };
    for term in &this.terms {
        let selected = term.selector.enctypes();
        match term.operation {
            EnctypeOperation::Remove => {
                result.enctypes.retain(|etype| !selected.contains(etype));
            }
            EnctypeOperation::Add => {
                term.check_permission(allow_rc4, allow_des3)?;
                match term.selector {
                    enctype_names::Selector::Camellia(&[]) => {
                        match mode {
                            ParseMode::Compatible => result.diagnostics.push(
                                ConfigDiagnostic::UnsupportedSecureEnctype {
                                    token: term.token.clone(),
                                    until: camellia::UNAVAILABLE_UNTIL,
                                },
                            ),
                            ParseMode::Strict => {
                                return Err(Error::UnsupportedSecureEnctype {
                                    token: term.token.clone(),
                                    until: camellia::UNAVAILABLE_UNTIL,
                                });
                            }
                        }
                    }
                    enctype_names::Selector::Camellia(_)
                    | enctype_names::Selector::Secure(_)
                    | enctype_names::Selector::Des3
                    | enctype_names::Selector::Rc4
                    | enctype_names::Selector::Rejected(_) => {
                        for &etype in selected {
                            if !result.enctypes.contains(&etype) {
                                result.enctypes.push(etype);
                            }
                        }
                    }
                }
            }
        }
    }
    (!result.enctypes.is_empty()).ok_or(Error::EmptyEnctypeExpression)?;
    Ok(result)
}

impl FromStr for EnctypeExpr {
    type Err = Error;
    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// Reject positive insecure or disabled selections before expanding them.
///
/// # Errors
/// Returns a named disabled error or a named error with a typed policy cause.
pub(super) fn check_permission(
    this: &EnctypeTerm,
    allow_rc4: Toggle,
    allow_des3: Toggle,
) -> Result<(), Error> {
    let enabled = match this.selector {
        enctype_names::Selector::Des3 => allow_des3.is_enabled(),
        enctype_names::Selector::Rc4 => allow_rc4.is_enabled(),
        enctype_names::Selector::Rejected(feature) => {
            return Err(Error::RejectedEnctype {
                token: this.token.clone(),
                source: Policy::RejectedFeature {
                    feature,
                    reason: RejectionReason::InsecureByDesign,
                },
            });
        }
        enctype_names::Selector::Secure(_) | enctype_names::Selector::Camellia(_) => true,
    };
    enabled.ok_or_else(|| Error::DisabledEnctype {
        token: this.token.clone(),
    })
}

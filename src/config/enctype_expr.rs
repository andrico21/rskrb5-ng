use core::str::FromStr;

use crate::{
    crypto::{KerberosEtype, camellia},
    error::{Policy, RejectionReason},
};

/// Selector vocabulary separated from ordered expression evaluation.
mod enctype_names;

/// Configuration parsing diagnostic, including skipped secure enctypes.
pub type ConfigDiagnostic = diagnostic::Diagnostic;
/// Compatible or strict treatment of secure unsupported configuration.
pub type ParseMode = diagnostic::ParseMode;

/// A parsed, ordered MIT enctype-list expression, not yet runtime-authorized.
///
/// Names and aliases are case-insensitive. Only space, tab, CR, LF and comma
/// delimit terms. `+` or no prefix adds; `-` removes. Adding an existing entry
/// keeps its position; adding a removed entry appends it. `aes` expands in MIT
/// order `[18, 17, 20, 19]`; `DEFAULT` uses this crate's secure SHA2-first list
/// `[20, 19, 18, 17]`, never DES3/RC4, even when those families are enabled.
///
/// See [krb5.conf](https://web.mit.edu/kerberos/krb5-1.22/doc/admin/conf_files/krb5_conf.html)
/// and its linked [Encryption types section](https://web.mit.edu/kerberos/krb5-1.22/doc/admin/conf_files/kdc_conf.html#encryption-types).
/// Ordering and tokenization follow
/// [MIT `init_ctx.c:411-492`](https://github.com/krb5/krb5/blob/krb5-1.22.2-final/src/lib/krb5/krb/init_ctx.c#L411-L492).
/// Unlike MIT's unknown-token filtering, positive forbidden/disabled terms and
/// unknown terms fail closed. Known removal terms never need permission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnctypeExpr {
    /// Parsed terms retain original spelling for operator diagnostics.
    terms: Vec<EnctypeTerm>,
}

/// One bounded expression token and its validated selector.
#[derive(Clone, Debug, Eq, PartialEq)]
struct EnctypeTerm {
    /// Original token, including any operator.
    token: String,
    /// Validated vocabulary entry.
    selector: enctype_names::Selector,
    /// Whether to insert or remove the selector's entries.
    operation: EnctypeOperation,
}

/// Ordered-list operations are separate from algorithm permission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EnctypeOperation {
    /// Append an entry only when not already present.
    Add,
    /// Remove any present matching entries.
    Remove,
}

/// Successfully resolved nonempty enctypes and compatible-mode diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedEnctypes {
    /// Authorized implemented entries in preference order.
    enctypes: Vec<KerberosEtype>,
    /// Explicitly skipped secure unsupported selections.
    diagnostics: Vec<ConfigDiagnostic>,
}

impl ResolvedEnctypes {
    /// Ordered, nonempty implemented encryption types.
    #[must_use]
    #[inline]
    pub fn enctypes(&self) -> &[KerberosEtype] {
        &self.enctypes
    }

    /// Diagnostics for every skipped positive secure unsupported term.
    #[must_use]
    #[inline]
    pub fn diagnostics(&self) -> &[ConfigDiagnostic] {
        &self.diagnostics
    }
}

impl EnctypeExpr {
    /// Parse at most 64 KiB into known selectors, retaining their order and spelling.
    ///
    /// # Errors
    /// Returns [`Error::EnctypeExpressionTooLarge`] before allocating tokens for
    /// oversized input, or [`Error::UnknownEnctype`] naming an unknown token.
    /// Recognition of a forbidden name is not permission; call [`Self::resolve`].
    #[inline]
    pub fn parse(text: &str) -> Result<Self, Error> {
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
        Ok(Self { terms })
    }

    /// Resolve using explicit RC4 and DES3 runtime permissions and parsing mode.
    ///
    /// `allow_rc4` and `allow_des3` are enforced client-side too, deliberately
    /// stricter than MIT's KDC-side relations. No Cargo feature grants permission.
    /// Compatible mode skips only secure Camellia names whose `camellia` leaf is not
    /// compiled in, with diagnostics; strict mode rejects them. With the leaf compiled
    /// in, a Camellia name resolves like any secure name, and `DEFAULT` never includes it.
    /// A later removal cannot erase an earlier refusal.
    ///
    /// # Errors
    /// Returns [`Error::RejectedEnctype`] with a typed policy cause for D2 terms,
    /// [`Error::DisabledEnctype`] for disabled legacy terms,
    /// [`Error::UnsupportedSecureEnctype`] for Camellia in strict mode, and
    /// [`Error::EmptyEnctypeExpression`] when nothing remains.
    #[inline]
    pub fn resolve(
        &self,
        allow_rc4: Toggle,
        allow_des3: Toggle,
        mode: ParseMode,
    ) -> Result<ResolvedEnctypes, Error> {
        let mut result = ResolvedEnctypes {
            enctypes: Vec::new(),
            diagnostics: Vec::new(),
        };
        for term in &self.terms {
            let selected = term.selector.enctypes();
            match term.operation {
                EnctypeOperation::Remove => {
                    result.enctypes.retain(|etype| !selected.contains(etype));
                }
                EnctypeOperation::Add => {
                    term.check_permission(allow_rc4, allow_des3)?;
                    match term.selector {
                        enctype_names::Selector::Camellia(&[]) => match mode {
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
                        },
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
}

impl FromStr for EnctypeExpr {
    type Err = Error;
    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl EnctypeTerm {
    /// Reject positive insecure or disabled selections before expanding them.
    ///
    /// # Errors
    /// Returns a named disabled error or a named error with a typed policy cause.
    fn check_permission(&self, allow_rc4: Toggle, allow_des3: Toggle) -> Result<(), Error> {
        let enabled = match self.selector {
            enctype_names::Selector::Des3 => allow_des3.is_enabled(),
            enctype_names::Selector::Rc4 => allow_rc4.is_enabled(),
            enctype_names::Selector::Rejected(feature) => {
                return Err(Error::RejectedEnctype {
                    token: self.token.clone(),
                    source: Policy::RejectedFeature {
                        feature,
                        reason: RejectionReason::InsecureByDesign,
                    },
                });
            }
            enctype_names::Selector::Secure(_) | enctype_names::Selector::Camellia(_) => true,
        };
        enabled.ok_or_else(|| Error::DisabledEnctype {
            token: self.token.clone(),
        })
    }
}

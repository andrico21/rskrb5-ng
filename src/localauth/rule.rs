//! `auth_to_local` rule parsing and application (`localauth_rule.c`).

use crate::{ccache::Principal, error::LocalAuth as Error};

use super::AuthToLocalRule;

/// A compiled rule.
#[derive(Clone, Debug)]
pub(super) enum Kind {
    /// `DEFAULT`.
    Default,
}

impl AuthToLocalRule {
    /// Parse one `auth_to_local` value.
    ///
    /// # Errors
    ///
    /// Every malformed or over-bound rule is an error at parse time.
    #[inline]
    pub fn parse(text: &str) -> Result<Self, Error> {
        let _unused = text;
        Err(Error::MalformedRule {
            reason: "not parsed",
        })
    }

    /// The `DEFAULT` rule.
    #[must_use]
    #[inline]
    pub const fn default_rule() -> Self {
        Self { kind: Kind::Default }
    }

    /// Apply the rule to `principal`.
    ///
    /// # Errors
    ///
    /// [`Error::NoTranslation`] when the rule does not apply.
    #[inline]
    pub fn apply(&self, principal: &Principal, default_realm: &str) -> Result<String, Error> {
        let _unused = (&self.kind, principal, default_realm);
        Err(Error::NoTranslation)
    }
}

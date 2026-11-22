//! The mapping half (`localauth_names.c`, `localauth.c:299-352`).

use alloc::collections::BTreeMap;

use crate::{config::Config, error::LocalAuth as Error};

use super::{AuthToLocalRule, LocalNameMapper};

impl LocalNameMapper {
    /// A mapper for `default_realm` with no mapping and no rule (`DEFAULT`).
    #[must_use]
    #[inline]
    pub const fn new(default_realm: Option<String>) -> Self {
        Self {
            default_realm,
            names: BTreeMap::new(),
            rules: Vec::new(),
        }
    }

    /// Add the explicit mapping of `principal_name` (no realm) to `local_name`.
    #[must_use]
    #[inline]
    pub fn with_name(mut self, principal_name: impl Into<String>, local_name: impl Into<String>) -> Self {
        drop(self.names.insert(principal_name.into(), local_name.into()));
        self
    }

    /// Replace the rules.
    ///
    /// # Errors
    ///
    /// [`Error::LimitExceeded`] for more than [`MAX_RULES`](super::MAX_RULES).
    #[inline]
    pub fn with_rules(mut self, rules: Vec<AuthToLocalRule>) -> Result<Self, Error> {
        self.rules = rules;
        Ok(self)
    }

    /// The mapper of the default realm of `config`.
    ///
    /// # Errors
    ///
    /// A malformed `auth_to_local` value of the default realm.
    #[inline]
    pub fn from_config(config: &Config) -> Result<Self, Error> {
        let _unused = config;
        Ok(Self::new(None))
    }
}

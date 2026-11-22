//! The mapping half (`localauth_names.c`, `localauth.c:299-352,408-436`).

use alloc::collections::BTreeMap;

use crate::{
    ccache::Principal,
    config::{Config, section_values::Value},
    error::LocalAuth as Error,
};

use super::{AuthToLocalRule, LocalNameMapper, MAX_LOCAL_NAME_BYTES, MAX_RULES, unparse};

/// A translation that may be used as an account name.
///
/// # Errors
///
/// [`Error::InvalidLocalName`] for an empty, NUL-holding or too long name.
fn usable(name: String) -> Result<String, Error> {
    if name.is_empty() {
        Err(Error::InvalidLocalName { reason: "empty" })
    } else if name.contains('\0') {
        Err(Error::InvalidLocalName {
            reason: "contains a NUL byte",
        })
    } else if name.len() > MAX_LOCAL_NAME_BYTES {
        Err(Error::InvalidLocalName {
            reason: "longer than the account name limit",
        })
    } else {
        Ok(name)
    }
}

impl LocalNameMapper {
    /// A mapper for `default_realm` with no mapping and no rule, which is
    /// the `DEFAULT` rule. With no default realm nothing translates.
    #[must_use]
    #[inline]
    pub const fn new(default_realm: Option<String>) -> Self {
        Self {
            default_realm,
            names: BTreeMap::new(),
            rules: Vec::new(),
        }
    }

    /// Add the explicit mapping of `principal_name` (the unparsed name without
    /// realm) to `local_name`, replacing an earlier one.
    #[must_use]
    #[inline]
    pub fn with_name<P, L>(mut self, principal_name: P, local_name: L) -> Self
    where
        P: Into<String>,
        L: Into<String>,
    {
        drop(self.names.insert(principal_name.into(), local_name.into()));
        self
    }

    /// Replace the rules: they are tried in order and an empty list is the
    /// `DEFAULT` rule.
    ///
    /// # Errors
    ///
    /// [`Error::LimitExceeded`] for more than [`MAX_RULES`] rules.
    #[inline]
    pub fn with_rules(mut self, rules: Vec<AuthToLocalRule>) -> Result<Self, Error> {
        if rules.len() > MAX_RULES {
            return Err(Error::LimitExceeded {
                what: "rules",
                limit: MAX_RULES,
            });
        }
        self.rules = rules;
        Ok(self)
    }

    /// The mapper of the default realm of `config`: its
    /// `auth_to_local_names` and `auth_to_local` (MIT reads them from the
    /// default realm's section only).
    ///
    /// # Errors
    ///
    /// A malformed or over-bound `auth_to_local` value, or more than
    /// [`MAX_RULES`] of them.
    #[inline]
    pub fn from_config(config: &Config) -> Result<Self, Error> {
        let default_realm = Some(config.libdefaults.default_realm.clone()).filter(|realm| !realm.is_empty());
        let mut mapper = Self::new(default_realm.clone());
        let Some(realm) = default_realm.as_deref().and_then(|name| config.realm(name)) else {
            return Ok(mapper);
        };
        mapper.names.clone_from(&realm.auth_to_local_names);
        if let Some(Value::List(values)) = realm.relations.get("auth_to_local") {
            let rules = values
                .iter()
                .map(|text| AuthToLocalRule::parse(text))
                .collect::<Result<Vec<_>, _>>()?;
            return mapper.with_rules(rules);
        }
        Ok(mapper)
    }

    /// `krb5_aname_to_localname`: the explicit mapping, then the rules.
    ///
    /// # Errors
    ///
    /// [`Error::NoTranslation`], [`Error::InvalidLocalName`] and the errors of
    /// the rules.
    pub(super) fn translate(&self, principal: &Principal) -> Result<String, Error> {
        let realm = self
            .default_realm
            .as_deref()
            .ok_or(Error::NoTranslation)?;
        let explicit = (principal.realm == realm)
            .then(|| unparse::without_realm(principal))
            .flatten()
            .and_then(|key| self.names.get(&key));
        if let Some(local) = explicit {
            return usable(local.clone());
        }
        let default = [AuthToLocalRule::default_rule()];
        let rules = if self.rules.is_empty() {
            default.as_slice()
        } else {
            self.rules.as_slice()
        };
        for rule in rules {
            match rule.apply(principal, realm) {
                Ok(name) => return usable(name),
                Err(Error::NoTranslation) => {}
                Err(other) => return Err(other),
            }
        }
        Err(Error::NoTranslation)
    }
}

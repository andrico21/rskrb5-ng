//! The mapping half (`localauth_names.c`, `localauth.c:299-352,408-436`).

use alloc::collections::BTreeMap;

use super::{AuthToLocalRule, BUILTINS, LocalNameMapper, MAX_LOCAL_NAME_BYTES, MAX_RULES, unparse};
use crate::{
    ccache::Principal,
    config::{Config, section_values::Value},
    error::LocalAuth as Error,
    extensions::{Interface, order},
};

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
            modules: None,
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
        let default_realm =
            Some(config.libdefaults.default_realm.clone()).filter(|realm| !realm.is_empty());
        let mut mapper = Self::new(default_realm.clone());
        mapper.modules = Some(order::arrange(Interface::LocalAuth, config, BUILTINS));
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

    /// The `names` module (`localauth_names.c:38-84`): the explicit mapping of
    /// a principal of the default realm, `None` when there is none.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLocalName`] when the configured name is not usable.
    pub(super) fn explicit(&self, principal: &Principal) -> Option<Result<String, Error>> {
        let realm = self.default_realm.as_deref()?;
        (principal.realm == realm)
            .then(|| unparse::without_realm(principal))
            .flatten()
            .and_then(|key| self.names.get(&key))
            .map(|local| usable(local.clone()))
    }

    /// The `auth_to_local` module (`localauth.c:300-352`): the rules in order,
    /// `DEFAULT` when there are none.
    ///
    /// # Errors
    ///
    /// [`Error::NoTranslation`], [`Error::InvalidLocalName`] and the errors of
    /// the rules.
    pub(super) fn by_rules(&self, principal: &Principal) -> Result<String, Error> {
        let realm = self.default_realm.as_deref().ok_or(Error::NoTranslation)?;
        let default = [AuthToLocalRule::default_rule()];
        let rules = if self.rules.is_empty() {
            default.as_slice()
        } else {
            self.rules.as_slice()
        };
        for rule in rules {
            // A configured rule whose type module `[plugins] localauth` removed
            // is a configuration error, as MIT's `find_typed_module` failure
            // (`localauth.c:328-340`); the implicit `DEFAULT` needs no module.
            if !self.rules.is_empty() && !self.consults(rule.module()) {
                return Err(Error::UnsupportedRuleType {
                    kind: rule.module().to_ascii_uppercase(),
                });
            }
            match rule.apply(principal, realm) {
                Ok(name) => return usable(name),
                Err(Error::NoTranslation) => {}
                Err(other) => return Err(other),
            }
        }
        Err(Error::NoTranslation)
    }

    /// `krb5_aname_to_localname`: the explicit mapping, then the rules.
    ///
    /// # Errors
    ///
    /// [`Error::NoTranslation`], [`Error::InvalidLocalName`] and the errors of
    /// the rules.
    pub(super) fn translate(&self, principal: &Principal) -> Result<String, Error> {
        for &module in self.consulted() {
            let answer = match module {
                "names" => self.explicit(principal),
                "auth_to_local" => Some(self.by_rules(principal)),
                _ => None,
            };
            match answer {
                Some(Err(Error::NoTranslation)) | None => {}
                Some(found) => return found,
            }
        }
        Err(Error::NoTranslation)
    }

    /// Whether `[plugins] localauth` leaves the built-in module `name`.
    pub(super) fn consults(&self, name: &str) -> bool {
        self.modules
            .as_ref()
            .is_none_or(|modules| modules.contains(&name))
    }

    /// The built-in modules in consultation order.
    fn consulted(&self) -> &[&'static str] {
        self.modules.as_deref().unwrap_or(&BUILTINS)
    }
}

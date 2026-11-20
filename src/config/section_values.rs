//! Typed non-libdefaults profile data; values never execute code or discover files.

use alloc::collections::BTreeMap;

use super::{Error, Toggle, parse_boolean};

/// Parsed realm relation value, including inert mechanism-specific selections.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[non_exhaustive]
pub enum Value {
    /// Boolean policy.
    Boolean(Toggle),
    /// Scalar text, including opaque rule-language expressions.
    Text(String),
    /// Repeated profile values in source order.
    List(Vec<String>),
    /// An admitted finite choice; its vocabulary is checked at parse time.
    Choice(String),
    /// Named certificate, identity or environment references; never resolved here.
    Locations(Vec<Location>),
}

/// An inert MIT certificate/identity location.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[non_exhaustive]
pub enum Location {
    /// FILE path, optionally with an identity key path after a comma.
    File(String),
    /// Directory reference.
    Directory(String),
    /// Environment variable reference, not an environment read.
    Environment(String),
    /// PKCS12 identity file reference.
    Pkcs12(String),
    /// PKCS11 identity descriptor, never dynamically loaded.
    Pkcs11(String),
}

/// Explicit cross-realm route; validation remains the caller's WP-11 policy.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[non_exhaustive]
pub enum Route {
    /// The profile contains only `.` for this pair.
    Direct,
    /// Ordered intermediate realm names, preserving repetitions.
    Via(Vec<String>),
}

/// Client realm -> server realm -> declared route.
pub type Capaths = BTreeMap<String, BTreeMap<String, Route>>;

/// Per-interface plugin restrictions, not a registry of executable modules.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[non_exhaustive]
pub struct Plugins {
    /// Repeated disabled module names, in profile order.
    pub disable: Vec<String>,
    /// Repeated allowlisted module names, in profile order.
    pub enable_only: Vec<String>,
}

/// Application values retain hierarchy and case; type is chosen by the caller.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct Applications {
    /// Path below appdefaults -> first scalar value.
    values: Vec<(Vec<String>, String)>,
}

impl Applications {
    /// Store a selected scalar without discarding application-specific syntax.
    pub(super) fn insert(&mut self, path: Vec<String>, value: String) {
        self.values.push((path, value));
    }

    /// MIT app+realm, app, realm, global precedence with exact-case keys.
    #[inline]
    #[must_use]
    pub fn get(&self, app: &str, realm: &str, relation: &str) -> Option<&str> {
        [
            vec![app.to_owned(), realm.to_owned(), relation.to_owned()],
            vec![app.to_owned(), relation.to_owned()],
            vec![realm.to_owned(), relation.to_owned()],
            vec![relation.to_owned()],
        ]
        .iter()
        .find_map(|path| {
            self.values
                .iter()
                .find(|(key, _)| key == path)
                .map(|(_, value)| value.as_str())
        })
    }

    /// Read a boolean at the same precedence, preserving missing versus malformed.
    /// # Errors
    /// Returns `InvalidBoolean` rather than MIT's silent malformed-to-false coercion.
    #[inline]
    pub fn boolean(&self, app: &str, realm: &str, relation: &str) -> Result<Option<bool>, Error> {
        self.get(app, realm, relation)
            .map(parse_boolean)
            .transpose()
    }
}

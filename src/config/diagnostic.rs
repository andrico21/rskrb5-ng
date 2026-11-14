/// Treatment of secure configuration features that are not implemented yet.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[non_exhaustive]
pub enum ParseMode {
    /// Skip only explicitly classified secure unsupported features with diagnostics.
    #[default]
    Compatible,
    /// Reject unsupported secure features as well as forbidden or unknown input.
    Strict,
}

/// A configuration selection that could not take effect in compatible mode.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Diagnostic {
    /// An unrecognized top-level profile section; names match case-sensitively.
    UnknownSection {
        /// Section name as written in the profile.
        section: String,
    },
    /// An unrecognized relation or subsection under a supported section,
    /// including a wrongly cased known name.
    UnknownRelation {
        /// Full selected profile path, as written in the profile.
        path: Vec<String>,
    },
    /// A server-only section is recognized but not applied by this client library.
    ServerOnly {
        /// Canonical section name.
        section: &'static str,
    },
    /// A known relation has no complete runtime consumer yet.
    NotYetEffective {
        /// Selected scalar relation name.
        relation: &'static str,
        /// Work package implementing the missing behavior.
        package: &'static str,
    },
    /// A removed draft-9 mechanism was ignored in a preference list.
    IgnoredPreauthType {
        /// Ignored PA type, never selected for an outgoing exchange.
        id: i32,
    },
    /// A secure encryption type is known but not implemented in this release.
    UnsupportedSecureEnctype {
        /// Original expression token, including its prefix and case.
        token: String,
        /// Work package required before this selection can take effect.
        until: &'static str,
    },
}

impl Diagnostic {
    /// Convert every diagnostic kind to its strict-mode error without exceptions.
    pub(super) fn into_error(self) -> super::Error {
        use super::Error;
        match self {
            Self::UnknownSection { section } => Error::UnknownSection { section },
            Self::UnknownRelation { path } => Error::UnknownRelation { path },
            Self::NotYetEffective { relation, package } => {
                Error::NotYetEffective { relation, package }
            }
            Self::ServerOnly { section } => Error::ServerOnly { section },
            Self::IgnoredPreauthType { id } => Error::IgnoredPreauthType { id },
            Self::UnsupportedSecureEnctype { token, until } => {
                Error::UnsupportedSecureEnctype { token, until }
            }
        }
    }
}

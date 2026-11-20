/// Whether a configuration option is enabled; serialized as its original boolean.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(from = "bool", into = "bool"))]
pub enum Toggle {
    /// The option is disabled.
    #[default]
    Disabled,
    /// The option is enabled.
    Enabled,
}

impl Toggle {
    /// Converts a configuration boolean into its option state.
    #[must_use]
    #[inline]
    pub const fn from_bool(value: bool) -> Self {
        if value { Self::Enabled } else { Self::Disabled }
    }

    /// Returns whether the option is enabled.
    #[must_use]
    #[inline]
    pub const fn is_enabled(self) -> bool {
        match self {
            Self::Disabled => false,
            Self::Enabled => true,
        }
    }
}

impl From<bool> for Toggle {
    #[inline]
    fn from(value: bool) -> Self {
        Self::from_bool(value)
    }
}

impl From<Toggle> for bool {
    #[inline]
    fn from(value: Toggle) -> Self {
        value.is_enabled()
    }
}

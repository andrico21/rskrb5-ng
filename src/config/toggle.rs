//! The configuration option state.

use super::Toggle;

/// Converts a configuration boolean into its option state.
pub(super) const fn from_bool(value: bool) -> Toggle {
    if value {
        Toggle::Enabled
    } else {
        Toggle::Disabled
    }
}

/// Returns whether the option is enabled.
pub(super) const fn is_enabled(this: Toggle) -> bool {
    match this {
        Toggle::Disabled => false,
        Toggle::Enabled => true,
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

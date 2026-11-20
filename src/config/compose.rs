//! Profile composition entry points, including registered profile modules.

use alloc::sync::Arc;

use super::{Config, IncludeExpansion, MAX_INCLUDE_BYTES, ParseMode, profile_syntax};
use crate::error::Config as Error;

/// Expand caller text under the include budget and apply `mode`.
///
/// # Errors
/// Returns include, profile and expression-policy errors without fallback.
pub(super) fn compose(
    mut loader: IncludeExpansion,
    text: &str,
    mode: ParseMode,
) -> Result<Config, Error> {
    if text.len() > MAX_INCLUDE_BYTES {
        return Err(Error::IncludeTooLarge {
            bytes: text.len(),
            limit: MAX_INCLUDE_BYTES,
        });
    }
    loader.bytes = text.len();
    loader.expand(text, 0)?;
    loader.profile.finish(mode)
}

/// Compose `text` with the `[plugins]` module names a registry resolves; the
/// resolution point of `extensions::Registry::parse_config`.
///
/// # Errors
/// Returns the [`Config::parse_with_mode`] errors; a `module` outside `modules`
/// is still [`Error::UnsupportedDynamicModule`].
pub(super) fn compose_with_modules(
    text: &str,
    mode: ParseMode,
    modules: Arc<[(&'static str, String)]>,
) -> Result<Config, Error> {
    compose(
        IncludeExpansion {
            modules,
            ..IncludeExpansion::default()
        },
        text,
        mode,
    )
}

/// The `module <id>:<residual>` profile directive, when it is the only content of `text`.
pub(super) fn profile_module_directive(text: &str) -> Option<(&str, &str)> {
    let mut lines = text
        .lines()
        .map(|line| profile_syntax::comments(line).trim_matches(profile_syntax::tag_whitespace))
        .filter(|line| !line.is_empty());
    let spec = lines
        .next()?
        .strip_prefix("module")
        .filter(|rest| rest.starts_with(profile_syntax::tag_whitespace))?
        .trim_start_matches(profile_syntax::tag_whitespace);
    lines
        .next()
        .is_none()
        .then(|| spec.split_once(':'))
        .flatten()
}

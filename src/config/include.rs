//! Include expansion: directive recognition and in-place source splicing.

use alloc::sync::Arc;
use std::path::{Path, PathBuf};

use super::{IncludeDirective, IncludeExpansion, Line, profile_syntax};
use crate::error::Config as Error;

/// The directive a line carries, or `None` when it carries neither.
pub(super) fn directive(line: &str) -> Option<IncludeDirective<'_>> {
    // `includedir` first: `include` is a prefix of it.
    if let Some(rest) = line.strip_prefix("includedir")
        && starts_with_whitespace(rest)
    {
        return Some(IncludeDirective::Directory(
            rest.trim_matches(profile_syntax::tag_whitespace),
        ));
    }
    let rest = line.strip_prefix("include")?;
    if starts_with_whitespace(rest) {
        return Some(IncludeDirective::File(
            rest.trim_matches(profile_syntax::tag_whitespace),
        ));
    }
    None
}

/// Whether `text` begins with whitespace (and so the keyword before it was a
/// whole token).
pub(super) fn starts_with_whitespace(text: &str) -> bool {
    text.chars()
        .next()
        .is_some_and(profile_syntax::tag_whitespace)
}

/// The same expansion, with the canonical paths the configuration's own
/// text came from already on the open chain.
pub(super) fn with_roots<I>(mut this: IncludeExpansion, roots: I) -> IncludeExpansion
where
    I: IntoIterator<Item = PathBuf>,
{
    this.open.extend(roots);
    this
}

/// Replace every directive in `input` with what it names, recursively.
///
/// # Errors
/// Returns the [`Self::include_file`] or [`Self::include_dir`] error of the
/// first directive whose target cannot be read or breaks a limit.
pub(super) fn expand(this: &mut IncludeExpansion, input: &str, depth: usize) -> Result<(), Error> {
    let mut state = profile_syntax::State::with_modules(Arc::clone(&this.modules));
    let mut lines = input.lines().enumerate();
    while let Some((index, line)) = lines.next() {
        let cleaned = profile_syntax::comments(line)
            .trim_start_matches(profile_syntax::tag_whitespace)
            .trim_end_matches(profile_syntax::tag_whitespace);
        if cleaned.is_empty() {
            continue;
        }
        if cleaned
            .split(profile_syntax::tag_whitespace)
            .next()
            .is_some_and(|word| state.dynamic_module(word))
            && !state.local_mapping_assignment(cleaned)
            && !state.registered_module(cleaned)
        {
            return Err(Error::UnsupportedDynamicModule);
        }
        if !state.local_mapping_assignment(cleaned)
            && let Some(directive) = IncludeDirective::parse(cleaned)
        {
            let opens_subsection = state.needs_include_lookahead()
                && lines
                    .clone()
                    .map(|(_, text)| {
                        #[cfg(test)]
                        super::fork_tests::LOOKAHEAD_SCANS
                            .with(|count| count.set(count.get().saturating_add(1)));
                        profile_syntax::comments(text).trim_matches(profile_syntax::tag_whitespace)
                    })
                    .find(|text| !text.is_empty() && IncludeDirective::parse(text).is_none())
                    == Some("{");
            state.before_include(opens_subsection, &mut this.profile)?;
            this.splice(directive, depth)?;
            continue;
        }
        state.line(
            &Line {
                number: index.saturating_add(1),
                text: cleaned.to_owned(),
                value: None,
            },
            &mut this.profile,
        )?;
    }
    state.finish(&mut this.profile)
}

/// What one directive contributes to the expanded text.
///
/// # Errors
/// Returns the [`Self::include_file`] or [`Self::include_dir`] error for
/// the directive's target.
pub(super) fn splice(
    this: &mut IncludeExpansion,
    directive: IncludeDirective<'_>,
    depth: usize,
) -> Result<(), Error> {
    let next_depth = depth.saturating_add(1);
    match directive {
        IncludeDirective::File(value) => this.include_file(Path::new(value), next_depth),
        IncludeDirective::Directory(value) => this.include_dir(Path::new(value), next_depth),
    }
}

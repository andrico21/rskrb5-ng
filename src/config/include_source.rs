//! Bounded reading of included files and `includedir` directories.

use std::{fs, io, io::Read as _, path::Path};

use super::{
    IncludeExpansion, MAX_INCLUDE_BYTES, MAX_INCLUDE_DEPTH, MAX_INCLUDE_FILES,
    sections::profile_file_error,
};
use crate::error::Config as Error;

/// Whether `name` is one an `includedir` accepts, per MIT's `valid_name`.
///
/// MIT's rule (`krb5-1.21-final`, `src/util/profile/prof_parse.c:224-243`):
/// dotfiles - "editor or filesystem artifacts" - are skipped, a name ending in
/// `.conf` is included, and so is a name made only of alphanumeric characters,
/// dashes and underscores. Like MIT's, it works on the name's bytes.
pub(super) fn includedir_name_is_valid(name: &[u8]) -> bool {
    if name.starts_with(b".") {
        return false;
    }
    if name.len() >= 5 && name.ends_with(b".conf") {
        return true;
    }
    !name.is_empty()
        && name
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-' || *byte == b'_')
}

/// One `include`: read the file and expand its own directives in turn.
///
/// # Errors
/// Returns [`Error::IncludeTooDeep`] past [`MAX_INCLUDE_DEPTH`],
/// [`Error::IncludeFile`] for an included file that cannot be resolved or
/// read, [`Error::File`] for a top-level file that cannot,
/// [`Error::IncludeCycle`] for a file already being expanded, the
/// [`Self::read_include`] limit errors, and the errors of its own
/// directives.
pub(super) fn include_file(
    this: &mut IncludeExpansion,
    path: &Path,
    depth: usize,
) -> Result<(), Error> {
    // Saturating: `MAX_INCLUDE_DEPTH` refuses the chain long before
    // `usize::MAX`.
    let file_depth = depth;
    if file_depth > MAX_INCLUDE_DEPTH {
        return Err(Error::IncludeTooDeep {
            depth: file_depth,
            limit: MAX_INCLUDE_DEPTH,
        });
    }
    // Resolving the path is how a file that does not exist is named rather
    // than skipped; it also gives the cycle check its canonical key.
    let canonical =
        fs::canonicalize(path).map_err(|source| profile_file_error(path, depth, source))?;
    if this.open.contains(&canonical) {
        return Err(Error::IncludeCycle {
            path: path.to_path_buf(),
        });
    }
    let content = this.read_include(path, depth)?;
    this.open.push(canonical);
    let expanded = this.expand(&content, file_depth);
    drop(this.open.pop());
    expanded
}

/// One included file's text, counted against the file and byte caps.
///
/// # Errors
/// Returns [`Error::IncludeTooMany`] past [`MAX_INCLUDE_FILES`],
/// [`Error::IncludeTooLarge`] past [`MAX_INCLUDE_BYTES`], and
/// [`Error::IncludeFile`] for an included file that cannot be opened or
/// read, or that is not UTF-8 text ([`Error::File`] for a top-level file).
pub(super) fn read_include(
    this: &mut IncludeExpansion,
    path: &Path,
    depth: usize,
) -> Result<String, Error> {
    use std::fs::File;

    // Saturating: `MAX_INCLUDE_FILES` refuses long before `usize::MAX`.
    let count = this.files.saturating_add(1);
    if count > MAX_INCLUDE_FILES {
        return Err(Error::IncludeTooMany {
            count,
            limit: MAX_INCLUDE_FILES,
        });
    }
    // Read at most one byte past what is left of the budget, so an oversize
    // file is refused without reading it into memory first.
    let remaining = MAX_INCLUDE_BYTES.saturating_sub(this.bytes);
    let file = File::open(path).map_err(|source| profile_file_error(path, depth, source))?;
    // Saturating: the limit plus one is what is read, and a `usize` budget
    // past `u64` is clamped rather than wrapped.
    let limit = u64::try_from(remaining)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut bytes = Vec::new();
    let _: usize = file
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(|source| profile_file_error(path, depth, source))?;
    if bytes.len() > remaining {
        return Err(Error::IncludeTooLarge {
            bytes: this.bytes.saturating_add(bytes.len()),
            limit: MAX_INCLUDE_BYTES,
        });
    }
    let content = String::from_utf8(bytes).map_err(|error| {
        profile_file_error(
            path,
            depth,
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("not UTF-8 text: {error}"),
            ),
        )
    })?;
    this.files = count;
    // Saturating: the byte check above keeps the total within
    // `MAX_INCLUDE_BYTES`.
    this.bytes = this.bytes.saturating_add(content.len());
    Ok(content)
}

/// One `includedir`: every accepted name, in alphanumeric order.
///
/// # Errors
/// Returns [`Error::IncludeTooDeep`] past [`MAX_INCLUDE_DEPTH`],
/// [`Error::IncludeDir`] for a directory that cannot be resolved or
/// listed, [`Error::IncludeCycle`] for a directory already being expanded,
/// [`Error::IncludeTooMany`] once its accepted names pass
/// [`MAX_INCLUDE_FILES`], and the [`Self::include_file`] error of any
/// accepted file.
pub(super) fn include_dir(
    this: &mut IncludeExpansion,
    dir: &Path,
    depth: usize,
) -> Result<(), Error> {
    (depth <= MAX_INCLUDE_DEPTH).ok_or(Error::IncludeTooDeep {
        depth,
        limit: MAX_INCLUDE_DEPTH,
    })?;
    let canonical = fs::canonicalize(dir).map_err(|source| Error::IncludeDir {
        path: dir.to_path_buf(),
        source,
    })?;
    if this.open.contains(&canonical) {
        return Err(Error::IncludeCycle {
            path: dir.to_path_buf(),
        });
    }
    let entries = fs::read_dir(dir).map_err(|source| Error::IncludeDir {
        path: dir.to_path_buf(),
        source,
    })?;
    let mut names = Vec::new();
    for listed in entries {
        let entry = listed.map_err(|source| Error::IncludeDir {
            path: dir.to_path_buf(),
            source,
        })?;
        // Matched as bytes, like MIT's `valid_name`, so a `.conf` name that is
        // not UTF-8 is included too; the path used to open a file is always
        // the one the directory entry carries.
        let name = entry.file_name();
        // A name that cannot be inspected is kept, so that reading it names
        // the failure instead of skipping it.
        if includedir_name_is_valid(name.as_encoded_bytes())
            && !fs::metadata(dir.join(&name)).is_ok_and(|metadata| metadata.is_dir())
        {
            // Saturating: `MAX_INCLUDE_FILES` refuses long before
            // `usize::MAX`.
            let count = this.files.saturating_add(names.len()).saturating_add(1);
            if count > MAX_INCLUDE_FILES {
                return Err(Error::IncludeTooMany {
                    count,
                    limit: MAX_INCLUDE_FILES,
                });
            }
            names.push(name);
        }
    }
    // Byte order, which is `strcmp` order: MIT reads the directory's accepted
    // files in alphanumeric order.
    names.sort_by(|left, right| left.as_encoded_bytes().cmp(right.as_encoded_bytes()));
    this.open.push(canonical);
    for name in names {
        this.include_file(&dir.join(name), depth)?;
    }
    drop(this.open.pop());
    Ok(())
}

/// Split a normalized assignment at its first equals sign.
///
/// # Errors
/// Returns a line-numbered error if the assignment separator is missing.
fn parse_assignment<'line>(
    line: &'line Line,
    section: &'static str,
) -> Result<(&'line str, &'line str), Error> {
    let Some((key, value)) = line.text.split_once('=') else {
        return Err(Error::InvalidLine {
            section,
            line: line.number,
            text: line.text.clone(),
        });
    };
    Ok((
        key.trim(),
        line.value.as_deref().unwrap_or_else(|| value.trim()),
    ))
}

/// Distinguish root-source I/O from failures in included files at the read boundary.
fn profile_file_error(path: &Path, depth: usize, source: io::Error) -> Error {
    if depth == 0 {
        Error::File {
            path: path.to_path_buf(),
            source,
        }
    } else {
        Error::IncludeFile {
            path: path.to_path_buf(),
            source,
        }
    }
}

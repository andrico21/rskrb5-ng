//! Rust syntax parsing with original source locations for inventory failures.

use std::io;

use proc_macro2::Span;
use syn::File;

/// Report a source shape the inventory cannot safely classify.
pub(super) fn unsupported(file: &str, span: Span, cause: &str) -> io::Error {
    io::Error::other(format!(
        "unsupported source {file}:{}: {cause}",
        span.start().line
    ))
}

/// Parse complete source without treating comments or literal text as items.
pub(super) fn parse(file: &str, source: &str) -> Result<File, io::Error> {
    syn::parse_file(source).map_err(|error| unsupported(file, error.span(), &error.to_string()))
}

//! Prove test-only exclusion without evaluating library features or target selection.

use std::io;

use syn::{Attribute, Expr, Lit, Meta, Token, parse::Parser as _, punctuated::Punctuated};

use super::source::unsupported;

/// Possible truth values with test disabled and other predicates unconstrained.
#[derive(Clone, Copy)]
struct Possibility {
    /// Predicate can hold in a library configuration.
    yes: bool,
    /// Predicate can fail in a library configuration.
    no: bool,
}

/// Exclude only predicates proven false without test; reject ambiguous syntax.
pub(super) fn included(file: &str, attributes: &[Attribute]) -> Result<bool, io::Error> {
    let mut included = true;
    for attribute in attributes {
        if attribute.path().is_ident("cfg") {
            let predicate = attribute
                .parse_args::<Meta>()
                .map_err(|error| unsupported(file, error.span(), "unparsable cfg"))?;
            included &= possible(file, &predicate)?.yes;
        }
        if attribute.path().is_ident("cfg_attr") {
            let nested = attribute
                .parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
                .map_err(|error| unsupported(file, error.span(), "unparsable cfg_attr"))?;
            let Some(predicate) = nested.first() else {
                return Err(unsupported(
                    file,
                    attribute.bracket_token.span.open(),
                    "empty cfg_attr",
                ));
            };
            let _: Possibility = possible(file, predicate)?;
            for meta in nested.iter().skip(1) {
                if meta.path().is_ident("cfg")
                    || meta.path().is_ident("cfg_attr")
                    || meta.path().is_ident("path")
                {
                    return Err(unsupported(
                        file,
                        attribute.bracket_token.span.open(),
                        "ambiguous conditional source selection",
                    ));
                }
            }
        }
    }
    Ok(included)
}

/// Boolean cfg operators preserve all possible feature and target branches.
fn possible(file: &str, meta: &Meta) -> Result<Possibility, io::Error> {
    let unknown = Possibility {
        yes: true,
        no: true,
    };
    match meta {
        Meta::Path(path) => {
            if path.is_ident("test") {
                return Ok(Possibility {
                    yes: false,
                    no: true,
                });
            }
            if path.is_ident("unix")
                || path.is_ident("windows")
                || path.is_ident("doctest")
                || path.is_ident("debug_assertions")
            {
                return Ok(unknown);
            }
        }
        Meta::NameValue(value) => {
            if (value.path.is_ident("feature")
                || value
                    .path
                    .get_ident()
                    .is_some_and(|name| name.to_string().starts_with("target_")))
                && matches!(&value.value, Expr::Lit(literal) if matches!(literal.lit, Lit::Str(_)))
            {
                return Ok(unknown);
            }
        }
        Meta::List(list) => {
            let arguments = Punctuated::<Meta, Token![,]>::parse_terminated
                .parse2(list.tokens.clone())
                .map_err(|error| unsupported(file, error.span(), "unparsable cfg predicate"))?;
            let values = arguments
                .iter()
                .map(|argument| possible(file, argument))
                .collect::<Result<Vec<_>, _>>()?;
            if list.path.is_ident("all") {
                return Ok(Possibility {
                    yes: values.iter().all(|value| value.yes),
                    no: values.iter().any(|value| value.no),
                });
            }
            if list.path.is_ident("any") {
                return Ok(Possibility {
                    yes: values.iter().any(|value| value.yes),
                    no: values.iter().all(|value| value.no),
                });
            }
            if list.path.is_ident("not")
                && let [value] = values.as_slice()
            {
                return Ok(Possibility {
                    yes: value.no,
                    no: value.yes,
                });
            }
        }
    }
    Err(unsupported(
        file,
        meta.path()
            .segments
            .first()
            .map_or_else(proc_macro2::Span::call_site, |segment| segment.ident.span()),
        "ambiguous cfg predicate",
    ))
}

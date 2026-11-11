//! Parse supported standard macro inputs so nested mutations remain visible.

use syn::{
    Expr, Macro, Token,
    parse::{ParseStream, Parser as _},
    punctuated::Punctuated,
};

/// Unsupported invocations have no proven expression expansion.
pub(super) fn expressions(invocation: &Macro) -> Option<Vec<Expr>> {
    if invocation.path.is_ident("vec") {
        let repeated = syn::parse2::<syn::ExprRepeat>(
            proc_macro2::TokenTree::Group(proc_macro2::Group::new(
                proc_macro2::Delimiter::Bracket,
                invocation.tokens.clone(),
            ))
            .into(),
        );
        if let Ok(value) = repeated {
            return Some(vec![*value.expr, *value.len]);
        }
    }
    if invocation.path.is_ident("matches") {
        let parser = |input: ParseStream<'_>| {
            let mut expressions = vec![input.parse::<Expr>()?];
            let _: Token![,] = input.parse()?;
            drop(syn::Pat::parse_multi_with_leading_vert(input)?);
            if input.peek(Token![if]) {
                let _: Token![if] = input.parse()?;
                expressions.push(input.parse::<Expr>()?);
            }
            if input.peek(Token![,]) {
                let _: Token![,] = input.parse()?;
            }
            Ok(expressions)
        };
        return parser.parse2(invocation.tokens.clone()).ok();
    }
    if [
        "format",
        "format_args",
        "write",
        "writeln",
        "assert",
        "assert_eq",
        "assert_ne",
        "debug_assert",
        "debug_assert_eq",
        "debug_assert_ne",
        "vec",
    ]
    .iter()
    .any(|name| invocation.path.is_ident(name))
    {
        return Punctuated::<Expr, Token![,]>::parse_terminated
            .parse2(invocation.tokens.clone())
            .ok()
            .map(|arguments| arguments.into_iter().collect());
    }
    None
}

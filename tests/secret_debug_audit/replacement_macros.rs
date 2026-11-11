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

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use std::io;

    #[test]
    fn whole_receiver_mutations_require_proof() {
        for body in [
            "*self = Self { secret: value };",
            "core::mem::replace(self, Self { secret: value });",
            "core::mem::take(self);",
            "let receiver = &mut *self; consume(receiver);",
        ] {
            let source = format!(
                "pub struct Owner {{ secret: Vec<u8> }}\nimpl Owner {{ pub fn set(&mut self, value: Vec<u8>) {{ {body} }} }}"
            );
            match super::super::methods("src/probe.rs", &source) {
                Ok(methods) => assert!(
                    methods
                        .iter()
                        .any(|method| method.fields.contains(&"secret".to_owned())),
                    "whole receiver mutation omitted: {body}: {methods:?}"
                ),
                Err(error) => assert!(error.to_string().contains("src/probe.rs:2:")),
            }
        }
    }

    #[test]
    fn receiver_identity_and_moves_are_distinct() -> Result<(), io::Error> {
        let source = "pub struct Owner { secret: Vec<u8> }
        impl Owner { pub fn moved(mut self) -> Self { consume(self) } }
        mod transport {
            pub struct Owner { count: usize }
            impl Owner { pub fn set(&mut self) { consume(self); } }
        }";
        let methods = super::super::methods("src/probe.rs", source)?;
        let [moved, transport] = methods.as_slice() else {
            return Err(io::Error::other("two receiver methods required"));
        };
        assert!(
            moved.fields.is_empty(),
            "moving a receiver is not replacement"
        );
        assert_eq!(transport.owner, "src/probe.rs::transport::Owner");
        assert_eq!(transport.fields, ["count"]);
        Ok(())
    }
}

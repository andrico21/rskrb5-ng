//! Bounded structural proof of declaration-free local macro transcribers.

use std::io;

use proc_macro2::{Delimiter, Group, TokenStream, TokenTree};
use syn::{
    Expr, File, Item, Macro,
    parse::{Parse, ParseStream, Parser as _},
    punctuated::Punctuated,
    visit::{self, Visit},
};

use super::source::unsupported;

/// A macro rule retains its matcher and transcriber without expanding user input.
struct Rule {
    /// Captures whose fragment kinds constrain substitution.
    matcher: Group,
    /// Output whose syntax must be proven declaration-free.
    output: Group,
}

/// The alternatives of a local declarative macro.
struct Rules(Vec<Rule>);

impl Parse for Rules {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let mut rules = Vec::new();
        while !input.is_empty() {
            let matcher: Group = input.parse()?;
            let _: syn::Token![=>] = input.parse()?;
            let output: Group = input.parse()?;
            rules.push(Rule { matcher, output });
            if !input.is_empty() {
                let _: syn::Token![;] = input.parse()?;
            }
        }
        Ok(Self(rules))
    }
}

/// Collect only fragment kinds whose substitution cannot introduce an item.
fn captures(stream: TokenStream, depth: usize) -> Option<Vec<String>> {
    if depth > 32 {
        return None;
    }
    let mut names = Vec::new();
    let mut tokens = stream.into_iter().peekable();
    while let Some(token) = tokens.next() {
        match token {
            TokenTree::Group(group) => {
                names.extend(captures(group.stream(), depth.saturating_add(1))?);
            }
            TokenTree::Punct(punct) if punct.as_char() == '$' => {
                if matches!(tokens.peek(), Some(TokenTree::Group(_))) {
                    continue;
                }
                let Some(TokenTree::Ident(name)) = tokens.next() else {
                    return None;
                };
                let Some(TokenTree::Punct(colon)) = tokens.next() else {
                    return None;
                };
                let Some(TokenTree::Ident(kind)) = tokens.next() else {
                    return None;
                };
                if colon.as_char() != ':' || !matches!(kind.to_string().as_str(), "ident" | "expr")
                {
                    return None;
                }
                names.push(name.to_string());
            }
            TokenTree::Ident(_) | TokenTree::Punct(_) | TokenTree::Literal(_) => {}
        }
    }
    Some(names)
}

/// Parse one representative repetition; captures remain atomic Rust identifiers.
fn representative(stream: TokenStream, names: &[String], depth: usize) -> Option<TokenStream> {
    if depth > 32 {
        return None;
    }
    let mut output = TokenStream::new();
    let mut tokens = stream.into_iter();
    while let Some(token) = tokens.next() {
        match token {
            TokenTree::Punct(punct) if punct.as_char() == '$' => match tokens.next()? {
                TokenTree::Ident(name) if names.contains(&name.to_string()) => {
                    output.extend([TokenTree::Ident(name)]);
                }
                TokenTree::Group(group) if group.delimiter() == Delimiter::Parenthesis => {
                    let mut operator = tokens.next()?;
                    if !matches!(&operator, TokenTree::Punct(repeat) if matches!(repeat.as_char(), '*' | '+' | '?'))
                    {
                        operator = tokens.next()?;
                    }
                    if !matches!(&operator, TokenTree::Punct(repeat) if matches!(repeat.as_char(), '*' | '+' | '?'))
                    {
                        return None;
                    }
                    output.extend(representative(
                        group.stream(),
                        names,
                        depth.saturating_add(1),
                    )?);
                }
                TokenTree::Group(_)
                | TokenTree::Ident(_)
                | TokenTree::Punct(_)
                | TokenTree::Literal(_) => return None,
            },
            TokenTree::Group(group) => {
                let mut rebuilt = Group::new(
                    group.delimiter(),
                    representative(group.stream(), names, depth.saturating_add(1))?,
                );
                rebuilt.set_span(group.span());
                output.extend([TokenTree::Group(rebuilt)]);
            }
            TokenTree::Ident(_) | TokenTree::Punct(_) | TokenTree::Literal(_) => {
                output.extend([token]);
            }
        }
    }
    Some(output)
}

/// Reject nested declarations and invocations even inside an impl or expression.
#[derive(Default)]
struct Opaque(bool);

impl<'ast> Visit<'ast> for Opaque {
    fn visit_item(&mut self, i: &'ast Item) {
        match i {
            Item::Impl(item) => visit::visit_item_impl(self, item),
            Item::Const(_)
            | Item::Enum(_)
            | Item::ExternCrate(_)
            | Item::Fn(_)
            | Item::ForeignMod(_)
            | Item::Macro(_)
            | Item::Mod(_)
            | Item::Static(_)
            | Item::Struct(_)
            | Item::Trait(_)
            | Item::TraitAlias(_)
            | Item::Type(_)
            | Item::Union(_)
            | Item::Use(_)
            | Item::Verbatim(_)
            | _ => self.0 = true,
        }
    }

    fn visit_macro(&mut self, _: &'ast Macro) {
        self.0 = true;
    }
}

/// Every alternative must parse as only impl items or a declaration-free expression.
pub(super) fn classify(file: &str, definition: &Macro) -> Result<(), io::Error> {
    let reject = || {
        unsupported(
            file,
            definition.bang_token.span,
            "unclassified local macro transcriber",
        )
    };
    let Rules(rules) = syn::parse2(definition.tokens.clone()).map_err(|_syntax| reject())?;
    if rules.is_empty() {
        return Err(reject());
    }
    for rule in rules {
        let names = captures(rule.matcher.stream(), 0).ok_or_else(reject)?;
        let output = representative(rule.output.stream(), &names, 0).ok_or_else(reject)?;
        let mut opaque = Opaque::default();
        if let Ok(tree) = syn::parse2::<File>(output.clone()) {
            opaque.visit_file(&tree);
        } else {
            let expression = syn::parse2::<Expr>(output).map_err(|_syntax| reject())?;
            opaque.visit_expr(&expression);
        }
        if opaque.0 {
            return Err(reject());
        }
    }
    Ok(())
}

/// Invocation expressions cannot inject declarations through an otherwise safe capture.
pub(super) fn arguments(file: &str, invocation: &Macro) -> Result<(), io::Error> {
    let expressions = Punctuated::<Expr, syn::Token![,]>::parse_terminated
        .parse2(invocation.tokens.clone())
        .map_err(|error| unsupported(file, error.span(), "unclassified macro arguments"))?;
    let mut opaque = Opaque::default();
    for expression in expressions {
        opaque.visit_expr(&expression);
    }
    if opaque.0 {
        return Err(unsupported(
            file,
            invocation.bang_token.span,
            "macro arguments contain opaque declarations",
        ));
    }
    Ok(())
}

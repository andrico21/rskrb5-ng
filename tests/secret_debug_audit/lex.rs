//! Lexical tokens for the secret-owner inventory; malformed input is an error.

use core::{iter::Peekable, str::Chars};
use std::io;

/// Consume the closing delimiter of a raw string, or reject truncated input.
fn raw_literal(chars: &mut Peekable<Chars<'_>>, hashes: usize) -> Result<(), io::Error> {
    while let Some(next) = chars.next() {
        if next == '"' {
            let mut probe = chars.clone();
            let mut matched = 0_usize;
            while matched < hashes && probe.peek() == Some(&'#') {
                let _: Option<char> = probe.next();
                matched = matched.saturating_add(1);
            }
            if matched == hashes {
                *chars = probe;
                return Ok(());
            }
        }
    }
    Err(io::Error::other("unterminated raw literal"))
}

/// Consume a line comment through its newline.
fn line_comment(chars: &mut Peekable<Chars<'_>>) {
    for next in chars.by_ref() {
        if next == '\n' {
            break;
        }
    }
}

fn raw_identifier(chars: &mut Peekable<Chars<'_>>) -> Result<String, io::Error> {
    let _: Option<char> = chars.next();
    let mut identifier = String::new();
    while chars
        .peek()
        .is_some_and(|next| next.is_alphanumeric() || *next == '_')
    {
        if let Some(next) = chars.next() {
            identifier.push(next);
        }
    }
    if identifier.is_empty() {
        return Err(io::Error::other("empty raw identifier"));
    }
    Ok(identifier)
}

/// Tokenize Rust without interpreting comment or literal contents as declarations.
pub(super) fn tokens(source: &str) -> Result<Vec<String>, io::Error> {
    let mut chars = source.chars().peekable();
    let mut words = Vec::new();
    while let Some(character) = chars.next() {
        match character {
            ch if ch.is_whitespace() => {}
            '/' if chars.peek() == Some(&'/') => {
                line_comment(&mut chars);
            }
            '/' if chars.peek() == Some(&'*') => {
                let _: Option<char> = chars.next();
                let mut depth = 1_usize;
                while let Some(next) = chars.next() {
                    match (next, chars.peek()) {
                        ('/', Some('*')) => {
                            let _: Option<char> = chars.next();
                            depth = depth.saturating_add(1);
                        }
                        ('*', Some('/')) => {
                            let _: Option<char> = chars.next();
                            depth = depth.saturating_sub(1);
                        }
                        _ => {}
                    }
                    if depth == 0 {
                        break;
                    }
                }
                if depth != 0 {
                    return Err(io::Error::other("unterminated comment"));
                }
            }
            '"' => {
                let mut closed = false;
                while let Some(next) = chars.next() {
                    match next {
                        '\\' => {
                            let _: Option<char> = chars.next();
                        }
                        '"' => {
                            closed = true;
                            break;
                        }
                        _ => {}
                    }
                }
                if !closed {
                    return Err(io::Error::other("unterminated literal"));
                }
                words.push("literal".to_owned());
            }
            '\'' => {
                let mut probe = chars.clone();
                if probe.next() == Some('\\') {
                    let _: Option<char> = probe.next();
                }
                if probe.next() == Some('\'') {
                    chars = probe;
                    words.push("literal".to_owned());
                } else {
                    words.push("'".to_owned());
                }
            }
            ch if ch.is_alphabetic() || ch == '_' => {
                let mut word = ch.to_string();
                while chars
                    .peek()
                    .is_some_and(|next| next.is_alphanumeric() || *next == '_')
                {
                    if let Some(next) = chars.next() {
                        word.push(next);
                    }
                }
                if matches!(word.as_str(), "r" | "br" | "cr")
                    && matches!(chars.peek(), Some('#' | '"'))
                {
                    let mut probe = chars.clone();
                    let mut hashes = 0_usize;
                    while probe.peek() == Some(&'#') {
                        let _: Option<char> = probe.next();
                        hashes = hashes.saturating_add(1);
                    }
                    if probe.next() == Some('"') {
                        chars = probe;
                        raw_literal(&mut chars, hashes)?;
                        words.push("literal".to_owned());
                    } else if word == "r" && hashes == 1 {
                        words.push(raw_identifier(&mut chars)?);
                    } else {
                        return Err(io::Error::other("unclassified literal prefix"));
                    }
                } else {
                    words.push(word);
                }
            }
            other => words.push(other.to_string()),
        }
    }
    Ok(words)
}

/// Return a balanced delimiter end, rejecting truncation and mismatched nesting.
pub(super) fn closing(words: &[String], start: usize) -> Result<usize, io::Error> {
    let mut stack = Vec::new();
    for (index, word) in words.iter().enumerate().skip(start) {
        match word.as_str() {
            "(" => stack.push(")"),
            "[" => stack.push("]"),
            "{" => stack.push("}"),
            ")" | "]" | "}" => {
                if stack.pop() != Some(word.as_str()) {
                    return Err(io::Error::other("unbalanced delimiter"));
                }
                if stack.is_empty() {
                    return Ok(index);
                }
            }
            _ => {}
        }
    }
    Err(io::Error::other("unterminated delimiter"))
}

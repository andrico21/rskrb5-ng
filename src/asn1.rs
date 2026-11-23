//! Checked DER length and application-tag utilities.
//!
//! The functions read untrusted bytes under explicit budgets and accept only
//! canonical DER: definite lengths in their shortest form, tag numbers in their
//! shortest form, no trailing data after a complete element. They are the
//! public counterpart of gokrb5's `asn1tools` (`AddASNAppTag`,
//! `GetLengthFromASN1`) and check what those helpers assume.
//!
//! [`read_element`] reads a prefix and returns the rest; [`read_complete`] and
//! [`validate`] require the whole input to be one element. Structural
//! canonicality only is checked: the content of primitive types (INTEGER,
//! BIT STRING, ...) is opaque here.
//!
//! # Security
//!
//! Every length is compared with [`Limits::max_length`] before it is used to
//! slice or allocate, and nesting is bounded by [`Limits::max_depth`]; no
//! input makes these functions allocate more than they return.

mod identifier;

use identifier::read_identifier;

use crate::error::Der as Error;

/// The size and nesting budget of one read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Limits {
    /// The largest length one element may declare.
    max_length: usize,
    /// The deepest nesting of constructed elements.
    max_depth: usize,
}

/// The class of a tag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Class {
    /// Universal (`00`).
    Universal,
    /// Application (`01`).
    Application,
    /// Context-specific (`10`).
    ContextSpecific,
    /// Private (`11`).
    Private,
}

/// The identifier octets of an element: class, form and tag number.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Identifier {
    /// The class.
    class: Class,
    /// Whether the content is itself a sequence of elements.
    constructed: bool,
    /// The tag number.
    number: u32,
}

/// One tag-length-value element borrowed from its input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Element<'input> {
    /// The identifier.
    identifier: Identifier,
    /// The content octets.
    content: &'input [u8],
}

impl Limits {
    /// The default budget: 16 MiB per element, 32 levels of nesting.
    #[must_use]
    #[inline]
    pub const fn new() -> Self {
        Self {
            max_length: 0x0100_0000,
            max_depth: 32,
        }
    }

    /// The largest length one element may declare.
    #[must_use]
    #[inline]
    pub const fn with_max_length(mut self, max_length: usize) -> Self {
        self.max_length = max_length;
        self
    }

    /// The deepest nesting of constructed elements.
    #[must_use]
    #[inline]
    pub const fn with_max_depth(mut self, max_depth: usize) -> Self {
        self.max_depth = max_depth;
        self
    }

    /// The largest length one element may declare.
    #[must_use]
    #[inline]
    pub const fn max_length(&self) -> usize {
        self.max_length
    }

    /// The deepest nesting of constructed elements.
    #[must_use]
    #[inline]
    pub const fn max_depth(&self) -> usize {
        self.max_depth
    }
}

impl Default for Limits {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl Identifier {
    /// The class.
    #[must_use]
    #[inline]
    pub const fn class(self) -> Class {
        self.class
    }

    /// Whether the content is a sequence of elements.
    #[must_use]
    #[inline]
    pub const fn is_constructed(self) -> bool {
        self.constructed
    }

    /// The tag number.
    #[must_use]
    #[inline]
    pub const fn number(self) -> u32 {
        self.number
    }
}

impl<'input> Element<'input> {
    /// The identifier.
    #[must_use]
    #[inline]
    pub const fn identifier(&self) -> Identifier {
        self.identifier
    }

    /// The content octets.
    #[must_use]
    #[inline]
    pub const fn content(&self) -> &'input [u8] {
        self.content
    }
}

/// The shortest definite DER encoding of `length`.
#[must_use]
#[inline]
pub fn encode_length(length: usize) -> Vec<u8> {
    if let Ok(short) = u8::try_from(length)
        && short < 0x80
    {
        return vec![short];
    }
    let bytes = length.to_be_bytes();
    let significant: Vec<u8> = bytes
        .iter()
        .copied()
        .skip_while(|byte| *byte == 0)
        .collect();
    let count = u8::try_from(significant.len()).unwrap_or(u8::MAX);
    let mut out = Vec::with_capacity(significant.len().saturating_add(1));
    out.push(0x80 | count);
    out.extend(significant);
    out
}

/// Read a canonical definite length from the start of `input`: the length and
/// the number of octets it took.
///
/// # Errors
///
/// Returns [`Error::Truncated`], [`Error::IndefiniteLength`],
/// [`Error::ReservedLength`], [`Error::NonMinimalLength`] or
/// [`Error::LengthTooLarge`] when the length exceeds `limits`.
#[inline]
pub fn decode_length(input: &[u8], limits: &Limits) -> Result<(usize, usize), Error> {
    let (&first, rest) = input.split_first().ok_or(Error::Truncated)?;
    if first < 0x80 {
        let length = usize::from(first);
        return if length > limits.max_length {
            Err(Error::LengthTooLarge {
                limit: limits.max_length,
            })
        } else {
            Ok((length, 1))
        };
    }
    let count = usize::from(first & 0x7f);
    if first == 0x80 {
        return Err(Error::IndefiniteLength);
    }
    if first == 0xff {
        return Err(Error::ReservedLength);
    }
    let octets = rest.get(..count).ok_or(Error::Truncated)?;
    let leading = octets.first().copied().ok_or(Error::Truncated)?;
    if leading == 0 {
        return Err(Error::NonMinimalLength);
    }
    let mut length = 0_usize;
    for octet in octets {
        length = length
            .checked_mul(256)
            .and_then(|shifted| shifted.checked_add(usize::from(*octet)))
            .filter(|value| *value <= limits.max_length)
            .ok_or(Error::LengthTooLarge {
                limit: limits.max_length,
            })?;
    }
    if length < 0x80 {
        return Err(Error::NonMinimalLength);
    }
    Ok((length, count.saturating_add(1)))
}

/// Read one element from the start of `input` and return it with the rest.
///
/// # Errors
///
/// Returns the errors of [`decode_length`], [`Error::NonMinimalTag`],
/// [`Error::TagTooLarge`] and [`Error::Truncated`] when the content is cut off.
#[inline]
pub fn read_element<'input>(
    input: &'input [u8],
    limits: &Limits,
) -> Result<(Element<'input>, &'input [u8]), Error> {
    let (identifier, tag_len) = read_identifier(input)?;
    let after_tag = input.get(tag_len..).ok_or(Error::Truncated)?;
    let (length, length_len) = decode_length(after_tag, limits)?;
    let body = after_tag.get(length_len..).ok_or(Error::Truncated)?;
    let content = body.get(..length).ok_or(Error::Truncated)?;
    let rest = body.get(length..).ok_or(Error::Truncated)?;
    Ok((
        Element {
            identifier,
            content,
        },
        rest,
    ))
}

/// Read `input` as exactly one element.
///
/// # Errors
///
/// Returns the errors of [`read_element`] and [`Error::TrailingData`].
#[inline]
pub fn read_complete<'input>(
    input: &'input [u8],
    limits: &Limits,
) -> Result<Element<'input>, Error> {
    let (element, rest) = read_element(input, limits)?;
    if rest.is_empty() {
        Ok(element)
    } else {
        Err(Error::TrailingData)
    }
}

/// The tag number and content of the `[APPLICATION n]` element that is all of `input`.
///
/// # Errors
///
/// Returns the errors of [`read_complete`] and [`Error::NotApplication`].
#[inline]
pub fn application_tag<'input>(
    input: &'input [u8],
    limits: &Limits,
) -> Result<(u32, &'input [u8]), Error> {
    let element = read_complete(input, limits)?;
    if element.identifier.class == Class::Application {
        Ok((element.identifier.number, element.content))
    } else {
        Err(Error::NotApplication)
    }
}

/// Wrap `content` in a constructed `[APPLICATION number]` element (gokrb5
/// `AddASNAppTag`), with the shortest tag and length encodings.
#[must_use]
#[inline]
pub fn add_application_tag(number: u32, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len().saturating_add(8));
    if let Ok(low) = u8::try_from(number)
        && low < 0x1f
    {
        out.push(0x60 | low);
    } else {
        out.push(0x7f);
        let mut groups = Vec::new();
        let mut rest = number;
        loop {
            groups.push(u8::try_from(rest & 0x7f).unwrap_or(0));
            rest >>= 7_u32;
            if rest == 0 {
                break;
            }
        }
        groups.reverse();
        let last = groups.len().saturating_sub(1);
        for (index, group) in groups.iter().enumerate() {
            out.push(if index == last { *group } else { *group | 0x80 });
        }
    }
    out.extend(encode_length(content.len()));
    out.extend_from_slice(content);
    out
}

/// Check that `input` is one canonical element, walking every constructed
/// element inside it within the depth budget.
///
/// # Errors
///
/// Returns the errors of [`read_element`], [`Error::TrailingData`] and
/// [`Error::TooDeep`].
#[inline]
pub fn validate(input: &[u8], limits: &Limits) -> Result<(), Error> {
    let element = read_complete(input, limits)?;
    walk(&element, 1, limits)
}

/// Walk the children of a constructed `element` at nesting `depth`.
///
/// # Errors
///
/// Returns [`Error::TooDeep`] and the errors of [`read_element`].
fn walk(element: &Element<'_>, depth: usize, limits: &Limits) -> Result<(), Error> {
    if depth > limits.max_depth {
        return Err(Error::TooDeep {
            limit: limits.max_depth,
        });
    }
    if !element.identifier.constructed {
        return Ok(());
    }
    let mut rest = element.content;
    while !rest.is_empty() {
        let (child, remainder) = read_element(rest, limits)?;
        walk(&child, depth.saturating_add(1), limits)?;
        rest = remainder;
    }
    Ok(())
}

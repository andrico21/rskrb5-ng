use super::{Error, ObjectIdentifier, oid};

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests;

/// DER universal tag of a SEQUENCE (constructed).
pub(super) const TAG_SEQUENCE: u8 = 0x30;
/// DER universal tag of an OBJECT IDENTIFIER.
pub(super) const TAG_OBJECT_IDENTIFIER: u8 = 0x06;
/// DER universal tag of an OCTET STRING.
pub(super) const TAG_OCTET_STRING: u8 = 0x04;
/// DER universal tag of a BIT STRING.
pub(super) const TAG_BIT_STRING: u8 = 0x03;
/// DER universal tag of an ENUMERATED value.
pub(super) const TAG_ENUMERATED: u8 = 0x0a;
/// DER constructed application tag 0, the GSS-API `InitialContextToken` wrapper.
pub(super) const TAG_APPLICATION_0: u8 = 0x60;
/// DER constructed context-specific tag `[0]`.
pub(super) const TAG_CONTEXT_0: u8 = 0xa0;
/// DER constructed context-specific tag `[1]`.
pub(super) const TAG_CONTEXT_1: u8 = 0xa1;
/// DER constructed context-specific tag `[2]`.
pub(super) const TAG_CONTEXT_2: u8 = 0xa2;
/// DER constructed context-specific tag `[3]`.
pub(super) const TAG_CONTEXT_3: u8 = 0xa3;

/// One DER tag-length-value element borrowed from its input buffer.
#[derive(Clone, Copy)]
pub(super) struct Tlv<'buffer> {
    /// One-byte identifier octet.
    tag: u8,
    /// Content octets.
    value: &'buffer [u8],
}

impl<'buffer> Tlv<'buffer> {
    /// One-byte identifier octet of this element.
    pub(super) const fn tag(&self) -> u8 {
        self.tag
    }

    /// Content octets of this element.
    pub(super) const fn value(&self) -> &'buffer [u8] {
        self.value
    }
}

/// Cursor that reads DER elements one at a time from a borrowed buffer.
pub(super) struct DerReader<'buffer> {
    /// Bytes not consumed yet.
    rest: &'buffer [u8],
}

impl<'buffer> DerReader<'buffer> {
    /// Start reading at the beginning of `bytes`.
    pub(super) const fn new(bytes: &'buffer [u8]) -> Self {
        Self { rest: bytes }
    }

    /// Read the next tag-length-value element.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TruncatedDer`] when no input is left or the length
    /// octets are missing, [`Error::HighTagNumber`] for a high-tag-number
    /// identifier, [`Error::IndefiniteLength`] for an indefinite length, and
    /// [`Error::LengthExceedsInput`] when the length does not fit in `usize`
    /// or exceeds the remaining input.
    pub(super) fn read_tlv(&mut self) -> Result<Tlv<'buffer>, Error> {
        let (&tag, rest) = self.rest.split_first().ok_or(Error::TruncatedDer)?;
        self.rest = rest;
        if tag & 0x1f == 0x1f {
            return Err(Error::HighTagNumber);
        }
        let length = self.read_len()?;
        let (value, after) = self
            .rest
            .split_at_checked(length)
            .ok_or(Error::LengthExceedsInput)?;
        self.rest = after;
        Ok(Tlv { tag, value })
    }

    /// Read exactly `N` raw bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TruncatedDer`] when fewer than `N` bytes remain.
    pub(super) fn read_array<const N: usize>(&mut self) -> Result<&'buffer [u8; N], Error> {
        let (bytes, rest) = self
            .rest
            .split_first_chunk::<N>()
            .ok_or(Error::TruncatedDer)?;
        self.rest = rest;
        Ok(bytes)
    }

    /// Bytes not consumed yet.
    pub(super) const fn remaining(&self) -> &'buffer [u8] {
        self.rest
    }

    /// Check that the whole input was consumed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TrailingData`] when unread bytes remain.
    pub(super) const fn finish(&self) -> Result<(), Error> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(Error::TrailingData)
        }
    }

    /// Read definite-form DER length octets.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TruncatedDer`] when no length octet is left,
    /// [`Error::IndefiniteLength`] for the indefinite form, and
    /// [`Error::LengthExceedsInput`] when the long form needs more octets than
    /// `usize` holds or than the input has.
    fn read_len(&mut self) -> Result<usize, Error> {
        let (&first, rest) = self.rest.split_first().ok_or(Error::TruncatedDer)?;
        self.rest = rest;
        if first & 0x80 == 0 {
            return Ok(first.into());
        }

        let count = usize::from(first & 0x7f);
        if count == 0 {
            return Err(Error::IndefiniteLength);
        }
        if count > size_of::<usize>() {
            return Err(Error::LengthExceedsInput);
        }
        let (length_bytes, after) = self
            .rest
            .split_at_checked(count)
            .ok_or(Error::LengthExceedsInput)?;

        if length_bytes.first() == Some(&0) || (count == 1 && length_bytes < [128].as_slice()) {
            return Err(Error::NonminimalLength);
        }

        let mut length = 0_usize;
        for byte in length_bytes {
            length = (length << 8_u32) | usize::from(*byte);
        }
        self.rest = after;
        Ok(length)
    }
}

/// Read exactly one element with `expected_tag` that spans all of `bytes`.
///
/// # Errors
///
/// Returns the [`DerReader::read_tlv`] errors, [`Error::TrailingData`] when
/// bytes follow the element, and [`Error::UnexpectedTag`] when the element has
/// another tag.
pub(super) fn read_single_tlv(bytes: &[u8], expected_tag: u8) -> Result<Tlv<'_>, Error> {
    let mut reader = DerReader::new(bytes);
    let tlv = reader.read_tlv()?;
    reader.finish()?;
    if tlv.tag != expected_tag {
        return Err(Error::UnexpectedTag {
            expected: expected_tag,
            actual: tlv.tag,
        });
    }
    Ok(tlv)
}

/// Decode an OBJECT IDENTIFIER element.
///
/// # Errors
///
/// Returns [`Error::UnexpectedTag`] when the element is not an OBJECT
/// IDENTIFIER, [`Error::InvalidOidEncoding`] for malformed base-128 content,
/// and [`Error::InvalidOid`] when the arcs are invalid.
pub(super) fn decode_oid_tlv(tlv: Tlv<'_>) -> Result<ObjectIdentifier, Error> {
    if tlv.tag != TAG_OBJECT_IDENTIFIER {
        return Err(Error::UnexpectedTag {
            expected: TAG_OBJECT_IDENTIFIER,
            actual: tlv.tag,
        });
    }
    decode_oid_value(tlv.value)
}

/// Decode the content octets of an OBJECT IDENTIFIER.
///
/// # Errors
///
/// Returns [`Error::InvalidOidEncoding`] for empty content, a truncated or
/// nonminimal subidentifier, or an arc wider than 32 bits, and
/// [`Error::InvalidOid`] when the arcs are invalid.
pub(super) fn decode_oid_value(value: &[u8]) -> Result<ObjectIdentifier, Error> {
    let mut rest = value;
    let first = decode_base128(&mut rest)?;
    let (root, second) = match first {
        0..40 => (0, first),
        40..80 => (1, first.saturating_sub(40)),
        _ => (2, first.saturating_sub(80)),
    };
    let mut arcs = vec![
        root,
        u32::try_from(second).map_err(|_overflow| Error::InvalidOidEncoding)?,
    ];
    while !rest.is_empty() {
        arcs.push(
            u32::try_from(decode_base128(&mut rest)?)
                .map_err(|_overflow| Error::InvalidOidEncoding)?,
        );
    }

    ObjectIdentifier::from_arcs(arcs)
}

/// Consume one minimal base-128 subidentifier, allowing the first two arcs to combine.
///
/// # Errors
///
/// Returns [`Error::InvalidOidEncoding`] for truncated, nonminimal or overflowing content.
fn decode_base128(rest: &mut &[u8]) -> Result<u64, Error> {
    if rest.first() == Some(&0x80) {
        return Err(Error::InvalidOidEncoding);
    }
    let mut value = 0_u64;
    loop {
        let (&byte, tail) = rest.split_first().ok_or(Error::InvalidOidEncoding)?;
        *rest = tail;
        value = value
            .checked_mul(128)
            .and_then(|base| base.checked_add(u64::from(byte & 0x7f)))
            .ok_or(Error::InvalidOidEncoding)?;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
}

/// Encode an object identifier as a complete OBJECT IDENTIFIER element.
///
/// # Errors
///
/// Returns [`Error::InvalidOid`] when the arcs are invalid.
pub(super) fn encode_oid(oid: &ObjectIdentifier) -> Result<Vec<u8>, Error> {
    oid::validate_arcs(oid.arcs())?;
    let [first_arc, second_arc, later_arcs @ ..] = oid.arcs() else {
        return Err(Error::InvalidOid);
    };
    let first = u64::from(*first_arc)
        .checked_mul(40)
        .and_then(|base| base.checked_add(u64::from(*second_arc)))
        .ok_or(Error::InvalidOid)?;
    let mut value = Vec::new();
    encode_base128(first, &mut value);
    for arc in later_arcs {
        encode_base128(u64::from(*arc), &mut value);
    }
    Ok(encode_tlv(TAG_OBJECT_IDENTIFIER, &value))
}

/// Append `value` in minimal base-128 form, high groups first, with the
/// continuation bit set on every group but the last.
fn encode_base128(value: u64, out: &mut Vec<u8>) {
    let mut emitting = false;
    for shift in [63_u32, 56, 49, 42, 35, 28, 21, 14, 7] {
        let [low_byte, ..] = value.wrapping_shr(shift).to_le_bytes();
        let group = low_byte & 0x7f;
        emitting |= group != 0;
        if emitting {
            out.push(group | 0x80);
        }
    }
    let [last_byte, ..] = value.to_le_bytes();
    out.push(last_byte & 0x7f);
}

/// Decode the content octets of a non-negative INTEGER or ENUMERATED value.
///
/// # Errors
///
/// Returns [`Error::InvalidInteger`] for empty content, more than five
/// octets, a redundant sign octet, a negative value or a value above `u32::MAX`.
pub(super) fn decode_u32(bytes: &[u8]) -> Result<u32, Error> {
    let Some((first, _)) = bytes.split_first() else {
        return Err(Error::InvalidInteger);
    };
    if bytes.len() > 5 || first & 0x80 != 0 {
        return Err(Error::InvalidInteger);
    }
    if let [0, second, ..] = bytes
        && second & 0x80 == 0
    {
        return Err(Error::InvalidInteger);
    }
    let mut value = 0_u32;
    for byte in bytes {
        value = value
            .checked_mul(256)
            .and_then(|base| base.checked_add(u32::from(*byte)))
            .ok_or(Error::InvalidInteger)?;
    }
    Ok(value)
}

/// Encode `value` as the minimal content octets of a non-negative INTEGER.
pub(super) fn encode_u32(value: u32) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let mut significant: &[u8] = &bytes;
    while let [0, rest @ ..] = significant
        && !rest.is_empty()
    {
        significant = rest;
    }
    let mut encoded = Vec::with_capacity(5);
    if let [first, ..] = significant
        && first & 0x80 != 0
    {
        encoded.push(0);
    }
    encoded.extend_from_slice(significant);
    encoded
}

/// Encode `inner_der` under an explicit constructed tag.
pub(super) fn encode_explicit(tag: u8, inner_der: &[u8]) -> Vec<u8> {
    encode_tlv(tag, inner_der)
}

/// Encode one tag-length-value element.
pub(super) fn encode_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len().saturating_add(5));
    out.push(tag);
    encode_len(value.len(), &mut out);
    out.extend_from_slice(value);
    out
}

/// Append the definite-form DER length octets for `len`.
fn encode_len(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        let [short, ..] = len.to_le_bytes();
        out.push(short);
        return;
    }

    let bytes = len.to_be_bytes();
    let mut length_bytes: &[u8] = &bytes;
    while let [0, rest @ ..] = length_bytes {
        length_bytes = rest;
    }
    let [count, ..] = length_bytes.len().to_le_bytes();
    out.push(0x80 | count);
    out.extend_from_slice(length_bytes);
}

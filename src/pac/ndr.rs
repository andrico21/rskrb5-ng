//! NDR (Network Data Representation) decoding helpers for PAC buffers.

use super::{
    CLAIM_TYPE_ID_BOOLEAN, CLAIM_TYPE_ID_INT64, CLAIM_TYPE_ID_STRING, CLAIM_TYPE_ID_UINT64,
    ClaimEntry, ClaimValues, ClaimsArray, DomainGroupMembership, Error, GroupMembership,
    RpcUnicodeString, SecpkgSupplementalCredential, Sid, SidAndAttributes, reader::Reader,
};

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "ndr_tests.rs"]
mod tests;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "ndr_mutation_tests.rs"]
mod mutation_tests;

/// Upper bound on any NDR conformant count, to stop hostile buffers from
/// requesting huge allocations.
const MAX_REASONABLE_NDR_COUNT: u32 = 1_000_000;

/// Fixed part of an NDR `RPC_UNICODE_STRING`; the characters are deferred.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RpcUnicodeStringDescriptor {
    /// Byte length of the string, without a terminator.
    length: u16,
    /// Byte capacity of the buffer.
    maximum_length: u16,
    /// Referent ID of the deferred character array; 0 means null.
    referent_id: u32,
}

impl RpcUnicodeStringDescriptor {
    /// Reads the fixed descriptor fields.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`] when the buffer ends early.
    pub(super) fn read(reader: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Self {
            length: reader.read_u16()?,
            maximum_length: reader.read_u16()?,
            referent_id: reader.read_u32()?,
        })
    }
}

/// Fixed part of an NDR `CLAIMS_ARRAY`; the entries are deferred.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ClaimsArrayDescriptor {
    /// Claims source type (`CLAIMS_SOURCE_TYPE`).
    claims_source_type: u16,
    /// Number of claim entries.
    claims_count: u32,
    /// Referent ID of the deferred entries; 0 means null.
    claim_entries_ref: u32,
}

/// Fixed part of an NDR `CLAIM_ENTRY`; the ID and values are deferred.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ClaimEntryDescriptor {
    /// Referent ID of the deferred claim ID string.
    id_ref: u32,
    /// Claim value type (`CLAIM_TYPE`).
    claim_type: u16,
    /// Number of values.
    value_count: u32,
    /// Referent ID of the deferred values; 0 means null.
    values_ref: u32,
}

/// Converts an NDR count into a `usize` length.
///
/// # Errors
///
/// Returns [`Error::LengthOverflow`] when the count does not fit in `usize`.
fn ndr_len(count: u32) -> Result<usize, Error> {
    usize::try_from(count).map_err(|_out_of_range| Error::LengthOverflow)
}

/// Validates the NDR type-serialization header and the top-level referent.
///
/// # Errors
///
/// Returns [`Error::TooShort`] for a buffer under 20 bytes,
/// [`Error::InvalidNdrHeader`] for an unsupported common header,
/// [`Error::InvalidNdrObjectLength`] when the object length exceeds the buffer,
/// [`Error::MissingNdrPointer`] for a null top-level referent, and
/// [`Error::Truncated`] when the buffer ends early.
pub(super) fn read_ndr_wrapper(reader: &mut Reader<'_>, target: &'static str) -> Result<(), Error> {
    let minimum = 20;
    if reader.len() < minimum {
        return Err(Error::TooShort {
            target,
            minimum,
            actual: reader.len(),
        });
    }

    let version = reader.read_u8()?;
    let endianness = reader.read_u8()?;
    let common_header_length = reader.read_u16()?;
    if version != 1 || endianness != 0x10 || common_header_length != 8 {
        return Err(Error::InvalidNdrHeader);
    }

    let _fill = reader.read_u32()?;
    let raw_object_len = reader.read_u32()?;
    let _reserved = reader.read_u32()?;
    let object_len = ndr_len(raw_object_len)?;
    if object_len != reader.len().saturating_sub(16) || !object_len.is_multiple_of(8) {
        return Err(Error::InvalidNdrObjectLength {
            object_len,
            remaining: reader.len().saturating_sub(16),
        });
    }

    let top_level_referent = reader.read_u32()?;
    if top_level_referent == 0 {
        return Err(Error::MissingNdrPointer(target));
    }
    Ok(())
}

/// Reads a 2-byte-aligned little-endian `u16`.
///
/// # Errors
///
/// Returns [`Error::Truncated`] when the alignment padding or the value is
/// missing.
pub(super) fn read_ndr_u16(reader: &mut Reader<'_>) -> Result<u16, Error> {
    reader.align(2)?;
    reader.read_u16()
}

/// Reads a 4-byte-aligned little-endian `u32`.
///
/// # Errors
///
/// Returns [`Error::Truncated`] when the alignment padding or the value is
/// missing.
pub(super) fn read_ndr_u32(reader: &mut Reader<'_>) -> Result<u32, Error> {
    reader.align(4)?;
    reader.read_u32()
}

/// Reads an 8-byte-aligned little-endian `u64`.
///
/// # Errors
///
/// Returns [`Error::Truncated`] when the alignment padding or the value is
/// missing.
fn read_ndr_u64(reader: &mut Reader<'_>) -> Result<u64, Error> {
    reader.align(8)?;
    reader.read_u64()
}

/// Reads an aligned conformant count and rejects counts above [`MAX_REASONABLE_NDR_COUNT`].
///
/// # Errors
///
/// Returns [`Error::UnreasonableNdrCount`] for an oversized count and
/// [`Error::Truncated`] when the buffer ends early.
fn read_ndr_reasonable_count(reader: &mut Reader<'_>, target: &'static str) -> Result<u32, Error> {
    let count = read_ndr_u32(reader)?;
    if count > MAX_REASONABLE_NDR_COUNT {
        return Err(Error::UnreasonableNdrCount { target, count });
    }
    Ok(count)
}

/// Reads a deferred conformant byte array of `count` elements.
///
/// # Errors
///
/// Returns [`Error::MissingNdrPointer`] for a null pointer with a non-zero
/// count, [`Error::UnreasonableNdrCount`] or [`Error::CountMismatch`] for a bad
/// conformant count, and [`Error::Truncated`] when the buffer ends early.
pub(super) fn read_deferred_u8_array(
    reader: &mut Reader<'_>,
    referent_id: u32,
    count: u32,
    target: &'static str,
) -> Result<Vec<u8>, Error> {
    if referent_id == 0 {
        if count == 0 {
            return Ok(Vec::new());
        }
        return Err(Error::MissingNdrPointer(target));
    }

    let max_count = read_ndr_reasonable_count(reader, target)?;
    if max_count != count {
        return Err(Error::CountMismatch {
            target,
            expected: count,
            actual: max_count,
        });
    }

    let len = ndr_len(count)?;
    let bytes = reader.read_bytes(len)?.to_vec();
    reader.align(4)?;
    Ok(bytes)
}

/// Reads `count` `SECPKG_SUPPLEMENTAL_CRED` entries and their deferred data.
///
/// # Errors
///
/// Returns the errors of [`read_deferred_unicode_string`] and
/// [`read_deferred_u8_array`], [`Error::LengthOverflow`] when `count` does not
/// fit in `usize`, and [`Error::Truncated`] when the buffer ends early.
pub(super) fn read_counted_supplemental_credentials(
    reader: &mut Reader<'_>,
    count: u32,
) -> Result<Vec<SecpkgSupplementalCredential>, Error> {
    if count == 0 {
        return Ok(Vec::new());
    }

    let len = ndr_len(count)?;
    let descriptor_bytes = len.checked_mul(16).ok_or(Error::LengthOverflow)?;
    (count <= MAX_REASONABLE_NDR_COUNT && descriptor_bytes <= reader.remaining()).ok_or(
        Error::UnreasonableNdrCount {
            target: "SECPKGSupplementalCred",
            count,
        },
    )?;
    let mut descriptors = Vec::new();
    descriptors
        .try_reserve_exact(len)
        .map_err(|_allocation| Error::CredentialAllocation)?;
    for _ in 0..count {
        descriptors.push((
            RpcUnicodeStringDescriptor::read(reader)?,
            read_ndr_u32(reader)?,
            read_ndr_u32(reader)?,
        ));
    }

    let mut supplemental_credentials = Vec::new();
    supplemental_credentials
        .try_reserve_exact(len)
        .map_err(|_allocation| Error::CredentialAllocation)?;
    for (package_name_descriptor, credential_size, credentials_ref) in descriptors {
        let package_name = read_deferred_unicode_string(
            reader,
            package_name_descriptor,
            "SECPKGSupplementalCred.PackageName",
        )?;
        let credential_bytes = read_deferred_u8_array(
            reader,
            credentials_ref,
            credential_size,
            "SECPKGSupplementalCred.Credentials",
        )?;
        supplemental_credentials.push(SecpkgSupplementalCredential {
            package_name,
            credential_size,
            credentials: credential_bytes.into(),
        });
    }
    Ok(supplemental_credentials)
}

/// Reads a deferred conformant array of `RPC_UNICODE_STRING` values.
///
/// # Errors
///
/// Returns [`Error::MissingNdrPointer`] for a null pointer with a non-zero
/// count, [`Error::UnreasonableNdrCount`] or [`Error::CountMismatch`] for a bad
/// conformant count, and [`Error::Truncated`] when the buffer ends early, plus
/// the errors of [`read_deferred_unicode_string`].
pub(super) fn read_deferred_rpc_unicode_strings(
    reader: &mut Reader<'_>,
    referent_id: u32,
    count: u32,
    target: &'static str,
) -> Result<Vec<RpcUnicodeString>, Error> {
    if referent_id == 0 {
        if count == 0 {
            return Ok(Vec::new());
        }
        return Err(Error::MissingNdrPointer(target));
    }

    let max_count = read_ndr_reasonable_count(reader, target)?;
    if max_count != count {
        return Err(Error::CountMismatch {
            target,
            expected: count,
            actual: max_count,
        });
    }

    let len = ndr_len(count)?;
    let mut descriptors = Vec::with_capacity(len);
    for _ in 0..count {
        descriptors.push(RpcUnicodeStringDescriptor::read(reader)?);
    }

    let mut strings = Vec::with_capacity(len);
    for descriptor in descriptors {
        strings.push(read_deferred_unicode_string(reader, descriptor, target)?);
    }
    Ok(strings)
}

/// Reads a deferred conformant array of `CLAIMS_ARRAY` values.
///
/// # Errors
///
/// Returns [`Error::MissingNdrPointer`] for a null pointer with a non-zero
/// count, [`Error::UnreasonableNdrCount`] or [`Error::CountMismatch`] for a bad
/// conformant count, and [`Error::Truncated`] when the buffer ends early, plus
/// the errors of [`read_deferred_claim_entries`].
pub(super) fn read_deferred_claims_arrays(
    reader: &mut Reader<'_>,
    referent_id: u32,
    count: u32,
    target: &'static str,
) -> Result<Vec<ClaimsArray>, Error> {
    if referent_id == 0 {
        if count == 0 {
            return Ok(Vec::new());
        }
        return Err(Error::MissingNdrPointer(target));
    }

    let max_count = read_ndr_reasonable_count(reader, target)?;
    if max_count != count {
        return Err(Error::CountMismatch {
            target,
            expected: count,
            actual: max_count,
        });
    }

    let len = ndr_len(count)?;
    let mut descriptors = Vec::with_capacity(len);
    for _ in 0..count {
        descriptors.push(ClaimsArrayDescriptor {
            claims_source_type: read_ndr_u16(reader)?,
            claims_count: read_ndr_u32(reader)?,
            claim_entries_ref: read_ndr_u32(reader)?,
        });
    }

    let mut arrays = Vec::with_capacity(len);
    for descriptor in descriptors {
        let claim_entries = read_deferred_claim_entries(
            reader,
            descriptor.claim_entries_ref,
            descriptor.claims_count,
            "ClaimsArray.ClaimEntries",
        )?;
        arrays.push(ClaimsArray {
            claims_source_type: descriptor.claims_source_type,
            claims_count: descriptor.claims_count,
            claim_entries,
        });
    }
    Ok(arrays)
}

/// Reads a deferred conformant array of `CLAIM_ENTRY` values.
///
/// # Errors
///
/// Returns [`Error::MissingNdrPointer`] for a null pointer with a non-zero
/// count, [`Error::UnreasonableNdrCount`] or [`Error::CountMismatch`] for a bad
/// conformant count, and [`Error::Truncated`] when the buffer ends early,
/// [`Error::UnsupportedClaimType`] for an unknown claim type, plus the errors
/// of the per-type value readers.
fn read_deferred_claim_entries(
    reader: &mut Reader<'_>,
    referent_id: u32,
    count: u32,
    target: &'static str,
) -> Result<Vec<ClaimEntry>, Error> {
    if referent_id == 0 {
        if count == 0 {
            return Ok(Vec::new());
        }
        return Err(Error::MissingNdrPointer(target));
    }

    let max_count = read_ndr_reasonable_count(reader, target)?;
    if max_count != count {
        return Err(Error::CountMismatch {
            target,
            expected: count,
            actual: max_count,
        });
    }

    let len = ndr_len(count)?;
    let mut descriptors = Vec::with_capacity(len);
    for _ in 0..count {
        descriptors.push(read_claim_entry_descriptor(reader)?);
    }

    let mut entries = Vec::with_capacity(len);
    for descriptor in descriptors {
        let id = read_deferred_claim_string(reader, descriptor.id_ref, "ClaimEntry.ID")?;
        let values = match descriptor.claim_type {
            CLAIM_TYPE_ID_INT64 => ClaimValues::Int64(read_deferred_i64_array(
                reader,
                descriptor.values_ref,
                descriptor.value_count,
                "ClaimEntry.Int64Values",
            )?),
            CLAIM_TYPE_ID_UINT64 => ClaimValues::UInt64(read_deferred_u64_array(
                reader,
                descriptor.values_ref,
                descriptor.value_count,
                "ClaimEntry.UInt64Values",
            )?),
            CLAIM_TYPE_ID_STRING => ClaimValues::String(read_deferred_lpwstr_array(
                reader,
                descriptor.values_ref,
                descriptor.value_count,
                "ClaimEntry.StringValues",
            )?),
            CLAIM_TYPE_ID_BOOLEAN => ClaimValues::Boolean(read_deferred_bool_array(
                reader,
                descriptor.values_ref,
                descriptor.value_count,
                "ClaimEntry.BooleanValues",
            )?),
            claim_type => return Err(Error::UnsupportedClaimType(claim_type)),
        };
        entries.push(ClaimEntry {
            id,
            claim_type: descriptor.claim_type,
            values,
        });
    }
    Ok(entries)
}

/// Reads the fixed part of a `CLAIM_ENTRY`.
///
/// # Errors
///
/// Returns [`Error::InvalidClaimUnionTag`] when the union tag differs from the
/// claim type, and [`Error::Truncated`] when the buffer ends early.
fn read_claim_entry_descriptor(reader: &mut Reader<'_>) -> Result<ClaimEntryDescriptor, Error> {
    let id_ref = read_ndr_u32(reader)?;
    let claim_type = read_ndr_u16(reader)?;
    let union_tag = read_ndr_u16(reader)?;
    if union_tag != claim_type {
        return Err(Error::InvalidClaimUnionTag {
            claim_type,
            union_tag,
        });
    }
    Ok(ClaimEntryDescriptor {
        id_ref,
        claim_type,
        value_count: read_ndr_u32(reader)?,
        values_ref: read_ndr_u32(reader)?,
    })
}

/// Reads a deferred conformant array of signed 64-bit claim values.
///
/// # Errors
///
/// Returns [`Error::MissingNdrPointer`] for a null pointer with a non-zero
/// count, [`Error::UnreasonableNdrCount`] or [`Error::CountMismatch`] for a bad
/// conformant count, and [`Error::Truncated`] when the buffer ends early.
fn read_deferred_i64_array(
    reader: &mut Reader<'_>,
    referent_id: u32,
    count: u32,
    target: &'static str,
) -> Result<Vec<i64>, Error> {
    if referent_id == 0 {
        if count == 0 {
            return Ok(Vec::new());
        }
        return Err(Error::MissingNdrPointer(target));
    }

    let max_count = read_ndr_reasonable_count(reader, target)?;
    if max_count != count {
        return Err(Error::CountMismatch {
            target,
            expected: count,
            actual: max_count,
        });
    }

    let len = ndr_len(count)?;
    let mut values = Vec::with_capacity(len);
    for _ in 0..count {
        values.push(read_ndr_u64(reader)?.cast_signed());
    }
    Ok(values)
}

/// Reads a deferred conformant array of unsigned 64-bit claim values.
///
/// # Errors
///
/// Returns [`Error::MissingNdrPointer`] for a null pointer with a non-zero
/// count, [`Error::UnreasonableNdrCount`] or [`Error::CountMismatch`] for a bad
/// conformant count, and [`Error::Truncated`] when the buffer ends early.
fn read_deferred_u64_array(
    reader: &mut Reader<'_>,
    referent_id: u32,
    count: u32,
    target: &'static str,
) -> Result<Vec<u64>, Error> {
    if referent_id == 0 {
        if count == 0 {
            return Ok(Vec::new());
        }
        return Err(Error::MissingNdrPointer(target));
    }

    let max_count = read_ndr_reasonable_count(reader, target)?;
    if max_count != count {
        return Err(Error::CountMismatch {
            target,
            expected: count,
            actual: max_count,
        });
    }

    let len = ndr_len(count)?;
    let mut values = Vec::with_capacity(len);
    for _ in 0..count {
        values.push(read_ndr_u64(reader)?);
    }
    Ok(values)
}

/// Reads Boolean claim values as aligned ULONG64 zero/one values (MS-ADTS).
///
/// # Errors
///
/// Returns [`Error::MissingNdrPointer`] for a null pointer with a non-zero
/// count, [`Error::UnreasonableNdrCount`] or [`Error::CountMismatch`] for a bad
/// conformant count, and [`Error::Truncated`] when the buffer ends early.
fn read_deferred_bool_array(
    reader: &mut Reader<'_>,
    referent_id: u32,
    count: u32,
    target: &'static str,
) -> Result<Vec<bool>, Error> {
    if referent_id == 0 {
        if count == 0 {
            return Ok(Vec::new());
        }
        return Err(Error::MissingNdrPointer(target));
    }

    let max_count = read_ndr_reasonable_count(reader, target)?;
    if max_count != count {
        return Err(Error::CountMismatch {
            target,
            expected: count,
            actual: max_count,
        });
    }

    let len = ndr_len(count)?;
    let mut values = Vec::with_capacity(len);
    for _ in 0..count {
        let value = read_ndr_u64(reader)?;
        let boolean = match value {
            0 => false,
            1 => true,
            _ => return Err(Error::InvalidBooleanClaim(value)),
        };
        values.push(boolean);
    }
    Ok(values)
}

/// Reads a deferred conformant array of `LPWSTR` claim values.
///
/// # Errors
///
/// Returns [`Error::MissingNdrPointer`] for a null pointer with a non-zero
/// count, [`Error::UnreasonableNdrCount`] or [`Error::CountMismatch`] for a bad
/// conformant count, and [`Error::Truncated`] when the buffer ends early, plus
/// the errors of [`read_deferred_claim_string`].
fn read_deferred_lpwstr_array(
    reader: &mut Reader<'_>,
    referent_id: u32,
    count: u32,
    target: &'static str,
) -> Result<Vec<String>, Error> {
    if referent_id == 0 {
        if count == 0 {
            return Ok(Vec::new());
        }
        return Err(Error::MissingNdrPointer(target));
    }

    let max_count = read_ndr_reasonable_count(reader, target)?;
    if max_count != count {
        return Err(Error::CountMismatch {
            target,
            expected: count,
            actual: max_count,
        });
    }

    let len = ndr_len(count)?;
    let mut string_refs = Vec::with_capacity(len);
    for _ in 0..count {
        string_refs.push(read_ndr_u32(reader)?);
    }

    let mut values = Vec::with_capacity(len);
    for string_ref in string_refs {
        values.push(read_deferred_claim_string(reader, string_ref, target)?);
    }
    Ok(values)
}

/// Reads a deferred varying `LPWSTR`, dropping one trailing NUL.
///
/// # Errors
///
/// Returns [`Error::MissingNdrPointer`] for a null pointer,
/// [`Error::UnreasonableNdrCount`] or [`Error::InvalidNdrArrayBounds`] for bad
/// array bounds, [`Error::InvalidUtf16`] for invalid UTF-16, and
/// [`Error::Truncated`] when the buffer ends early.
fn read_deferred_claim_string(
    reader: &mut Reader<'_>,
    referent_id: u32,
    target: &'static str,
) -> Result<String, Error> {
    if referent_id == 0 {
        return Err(Error::MissingNdrPointer(target));
    }

    let max_count = read_ndr_reasonable_count(reader, target)?;
    let offset = read_ndr_u32(reader)?;
    let actual_count = read_ndr_reasonable_count(reader, target)?;
    if offset > max_count || actual_count > max_count.saturating_sub(offset) {
        return Err(Error::InvalidNdrArrayBounds {
            target,
            max_count,
            offset,
            actual_count,
        });
    }

    let unit_count = ndr_len(actual_count)?;
    let mut units = Vec::with_capacity(unit_count);
    for _ in 0..actual_count {
        units.push(reader.read_u16()?);
    }
    reader.align(4)?;

    if units.last().copied() == Some(0) {
        let _: Option<u16> = units.pop();
    }
    String::from_utf16(&units).map_err(|error| Error::InvalidUtf16 {
        target,
        message: error.to_string(),
    })
}

/// Checks that only zero padding follows the decoded structure.
///
/// # Errors
///
/// Returns [`Error::TrailingNdrBytesAfter`] when a non-zero byte remains, and
/// [`Error::Truncated`] when the final alignment padding is missing.
pub(super) fn ensure_zero_trailing(
    reader: &mut Reader<'_>,
    target: &'static str,
) -> Result<(), Error> {
    reader.align(4)?;
    if reader.remaining_bytes().iter().any(|byte| *byte != 0) {
        return Err(Error::TrailingNdrBytesAfter {
            target,
            remaining: reader.remaining(),
        });
    }
    Ok(())
}

/// Reads the deferred characters of an `RPC_UNICODE_STRING`.
///
/// # Errors
///
/// Returns [`Error::InvalidRpcUnicodeString`] or [`Error::InvalidUtf16Length`]
/// for an inconsistent descriptor, [`Error::UnreasonableNdrCount`] or
/// [`Error::InvalidNdrArrayBounds`] for bad array bounds,
/// [`Error::InvalidRpcUnicodeStringData`] when fewer units than `length`
/// arrive, [`Error::InvalidUtf16`] for invalid UTF-16, and [`Error::Truncated`]
/// when the buffer ends early.
pub(super) fn read_deferred_unicode_string(
    reader: &mut Reader<'_>,
    descriptor: RpcUnicodeStringDescriptor,
    target: &'static str,
) -> Result<RpcUnicodeString, Error> {
    if descriptor.maximum_length < descriptor.length {
        return Err(Error::InvalidRpcUnicodeString {
            target,
            length: descriptor.length,
            maximum_length: descriptor.maximum_length,
        });
    }
    if !descriptor.length.is_multiple_of(2) {
        return Err(Error::InvalidUtf16Length {
            target,
            bytes: descriptor.length.into(),
        });
    }
    if descriptor.referent_id == 0 {
        return Ok(RpcUnicodeString {
            length: descriptor.length,
            maximum_length: descriptor.maximum_length,
            value: String::new(),
        });
    }

    let max_count = read_reasonable_count(reader, target)?;
    let offset = reader.read_u32()?;
    let actual_count = read_reasonable_count(reader, target)?;
    if offset > max_count || actual_count > max_count.saturating_sub(offset) {
        return Err(Error::InvalidNdrArrayBounds {
            target,
            max_count,
            offset,
            actual_count,
        });
    }

    let unit_count = ndr_len(actual_count)?;
    let mut units = Vec::with_capacity(unit_count);
    for _ in 0..actual_count {
        units.push(reader.read_u16()?);
    }
    reader.align(4)?;

    // `length` is even (checked above), so halving counts UTF-16 units exactly.
    let logical_len = usize::from(descriptor.length.div_euclid(2));
    let Some(logical_units) = units.get(..logical_len) else {
        return Err(Error::InvalidRpcUnicodeStringData {
            target,
            expected_units: logical_len,
            actual_units: units.len(),
        });
    };

    let value = String::from_utf16(logical_units).map_err(|error| Error::InvalidUtf16 {
        target,
        message: error.to_string(),
    })?;
    Ok(RpcUnicodeString {
        length: descriptor.length,
        maximum_length: descriptor.maximum_length,
        value,
    })
}

/// Reads a deferred conformant array of `GROUP_MEMBERSHIP` values.
///
/// # Errors
///
/// Returns [`Error::MissingNdrPointer`] for a null pointer with a non-zero
/// count, [`Error::UnreasonableNdrCount`] or [`Error::CountMismatch`] for a bad
/// conformant count, and [`Error::Truncated`] when the buffer ends early.
pub(super) fn read_deferred_group_memberships(
    reader: &mut Reader<'_>,
    referent_id: u32,
    count: u32,
    target: &'static str,
) -> Result<Vec<GroupMembership>, Error> {
    if referent_id == 0 {
        if count == 0 {
            return Ok(Vec::new());
        }
        return Err(Error::MissingNdrPointer(target));
    }

    let max_count = read_reasonable_count(reader, target)?;
    if max_count != count {
        return Err(Error::CountMismatch {
            target,
            expected: count,
            actual: max_count,
        });
    }

    let len = ndr_len(count)?;
    let mut groups = Vec::with_capacity(len);
    for _ in 0..count {
        groups.push(GroupMembership {
            relative_id: reader.read_u32()?,
            attributes: reader.read_u32()?,
        });
    }
    Ok(groups)
}

/// Reads a deferred `SID`; a null referent yields `None`.
///
/// # Errors
///
/// Returns [`Error::UnreasonableNdrCount`] for an oversized count,
/// [`Error::InvalidSidRevision`] or [`Error::InvalidSidSubAuthorityCount`] for
/// a malformed SID, and [`Error::Truncated`] when the buffer ends early.
pub(super) fn read_deferred_sid(
    reader: &mut Reader<'_>,
    referent_id: u32,
    target: &'static str,
) -> Result<Option<Sid>, Error> {
    if referent_id == 0 {
        return Ok(None);
    }

    let max_sub_authority_count = read_reasonable_count(reader, target)?;
    let revision = reader.read_u8()?;
    let sub_authority_count = reader.read_u8()?;
    if revision != 1 {
        return Err(Error::InvalidSidRevision(revision));
    }
    if u32::from(sub_authority_count) > max_sub_authority_count || sub_authority_count > 15 {
        return Err(Error::InvalidSidSubAuthorityCount {
            target,
            max_count: max_sub_authority_count,
            actual_count: sub_authority_count,
        });
    }

    let identifier_authority: [u8; 6] = reader.read_array()?;
    let mut sub_authorities = Vec::with_capacity(sub_authority_count.into());
    for _ in 0..sub_authority_count {
        sub_authorities.push(reader.read_u32()?);
    }
    reader.align(4)?;

    Ok(Some(Sid {
        revision,
        identifier_authority,
        sub_authorities,
    }))
}

/// Reads a deferred conformant array of `KERB_SID_AND_ATTRIBUTES` values.
///
/// # Errors
///
/// Returns [`Error::MissingNdrPointer`] for a null pointer with a non-zero
/// count, [`Error::UnreasonableNdrCount`] or [`Error::CountMismatch`] for a bad
/// conformant count, and [`Error::Truncated`] when the buffer ends early, plus
/// the errors of [`read_deferred_sid`].
pub(super) fn read_deferred_sid_and_attributes(
    reader: &mut Reader<'_>,
    referent_id: u32,
    count: u32,
    target: &'static str,
) -> Result<Vec<SidAndAttributes>, Error> {
    if referent_id == 0 {
        if count == 0 {
            return Ok(Vec::new());
        }
        return Err(Error::MissingNdrPointer(target));
    }

    let max_count = read_reasonable_count(reader, target)?;
    if max_count != count {
        return Err(Error::CountMismatch {
            target,
            expected: count,
            actual: max_count,
        });
    }

    let len = ndr_len(count)?;
    let mut refs_and_attributes = Vec::with_capacity(len);
    for _ in 0..count {
        refs_and_attributes.push((reader.read_u32()?, reader.read_u32()?));
    }

    let mut out = Vec::with_capacity(len);
    for (sid_ref, attributes) in refs_and_attributes {
        let sid =
            read_deferred_sid(reader, sid_ref, target)?.ok_or(Error::MissingNdrPointer(target))?;
        out.push(SidAndAttributes { sid, attributes });
    }
    Ok(out)
}

/// Reads a deferred conformant array of `DOMAIN_GROUP_MEMBERSHIP` values.
///
/// # Errors
///
/// Returns [`Error::MissingNdrPointer`] for a null pointer with a non-zero
/// count, [`Error::UnreasonableNdrCount`] or [`Error::CountMismatch`] for a bad
/// conformant count, and [`Error::Truncated`] when the buffer ends early, plus
/// the errors of [`read_deferred_sid`] and [`read_deferred_group_memberships`].
pub(super) fn read_deferred_domain_group_memberships(
    reader: &mut Reader<'_>,
    referent_id: u32,
    count: u32,
    target: &'static str,
) -> Result<Vec<DomainGroupMembership>, Error> {
    if referent_id == 0 {
        if count == 0 {
            return Ok(Vec::new());
        }
        return Err(Error::MissingNdrPointer(target));
    }

    let max_count = read_reasonable_count(reader, target)?;
    if max_count != count {
        return Err(Error::CountMismatch {
            target,
            expected: count,
            actual: max_count,
        });
    }

    let len = ndr_len(count)?;
    let mut descriptors = Vec::with_capacity(len);
    for _ in 0..count {
        descriptors.push((reader.read_u32()?, reader.read_u32()?, reader.read_u32()?));
    }

    let mut groups = Vec::with_capacity(len);
    for (domain_id_ref, group_count, group_ids_ref) in descriptors {
        let domain_id = read_deferred_sid(reader, domain_id_ref, target)?
            .ok_or(Error::MissingNdrPointer(target))?;
        let group_ids =
            read_deferred_group_memberships(reader, group_ids_ref, group_count, target)?;
        groups.push(DomainGroupMembership {
            domain_id,
            group_count,
            group_ids,
        });
    }
    Ok(groups)
}

/// Reads an unaligned conformant count and rejects counts above [`MAX_REASONABLE_NDR_COUNT`].
///
/// # Errors
///
/// Returns [`Error::UnreasonableNdrCount`] for an oversized count and
/// [`Error::Truncated`] when the buffer ends early.
fn read_reasonable_count(reader: &mut Reader<'_>, target: &'static str) -> Result<u32, Error> {
    let count = reader.read_u32()?;
    if count > MAX_REASONABLE_NDR_COUNT {
        return Err(Error::UnreasonableNdrCount { target, count });
    }
    Ok(count)
}

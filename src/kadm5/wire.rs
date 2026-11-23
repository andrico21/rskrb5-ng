//! The kadm5 XDR layouts of MIT 1.22.2's `kadm_rpc_xdr.c`: the argument
//! encoders and the bounded result decoder.

use core::iter;

use zeroize::Zeroizing;

use super::{
    ApiVersion, KeyData, KeyInfo, KeySaltTuple, PolicyRecord, PrincipalMask, PrincipalRecord,
    Privileges, Procedure, Response, StringAttribute, TlData, name,
};
use crate::{
    client::principal::Principal,
    error::{Kadm5 as Error, Rpc},
    keytab::EncryptionKey,
    rpcsec_gss::xdr::{Decoder, Encoder},
};

/// The longest string: principal names, policy names, passwords, attributes.
const MAX_STRING: usize = 0x1_0000;

/// The most names a list may hold.
const MAX_NAMES: usize = 0x10_0000;

/// The most keys, key data or key/salt tuples in one call or result.
const MAX_KEYS: usize = 4096;

/// The longest key or salt.
const MAX_KEY_BYTES: usize = 1024;

/// The most tagged data entries of a record.
const MAX_TL: usize = 4096;

/// `xdr_nulltype`'s "null" boolean: `TRUE` means no value follows.
const NULL: bool = true;

/// A bound failure as the kadm5 error; any other RPC error as itself.
fn too_large(error: Rpc) -> Error {
    if let Rpc::TooLarge {
        field,
        maximum,
        actual,
    } = error
    {
        Error::TooLarge {
            field,
            maximum,
            actual,
        }
    } else {
        Error::Rpc(error)
    }
}

/// An encoding failure: an argument XDR cannot carry.
fn argument(error: Rpc) -> Error {
    if let Rpc::Malformed(reason) = error {
        Error::InvalidArgument(reason)
    } else {
        too_large(error)
    }
}

/// A decoding failure: a result that does not follow the layout.
fn result(error: Rpc) -> Error {
    if let Rpc::Malformed(reason) = error {
        Error::Malformed(reason)
    } else {
        too_large(error)
    }
}

/// The start of every argument: the API version.
pub(super) fn begin(version: ApiVersion) -> Encoder {
    Encoder::new().u32(version.wire())
}

/// A string or none (`xdr_nullstring`).
///
/// # Errors
///
/// Returns the bound, layout or argument error of the first field that fails.
pub(super) fn text(
    encoder: Encoder,
    field: &'static str,
    value: Option<&[u8]>,
) -> Result<Encoder, Error> {
    encoder
        .nullstring(field, value, MAX_STRING)
        .map_err(argument)
}

/// A principal (`xdr_krb5_principal`): its MIT string form.
///
/// # Errors
///
/// Returns the bound, layout or argument error of the first field that fails.
pub(super) fn principal(encoder: Encoder, value: &Principal) -> Result<Encoder, Error> {
    text(encoder, "principal", Some(name::unparse(value).as_bytes()))
}

/// Tagged data under `xdr_nulltype`: none as "null", else each entry after
/// a "more" boolean.
///
/// # Errors
///
/// Returns the bound, layout or argument error of the first field that fails.
fn tl_data(mut encoder: Encoder, entries: &[TlData]) -> Result<Encoder, Error> {
    if entries.is_empty() {
        return Ok(encoder.bool(NULL));
    }
    encoder = encoder.bool(!NULL);
    for entry in entries {
        encoder = encoder
            .bool(true)
            .i32(i32::from(entry.kind))
            .opaque("tagged data", &entry.contents, MAX_STRING)
            .map_err(argument)?;
    }
    Ok(encoder.bool(false))
}

/// A count of `entries` as the record's `krb5_int16`.
///
/// # Errors
///
/// Returns the bound, layout or argument error of the first field that fails.
fn short_count(field: &'static str, count: usize) -> Result<i32, Error> {
    i16::try_from(count)
        .map(i32::from)
        .map_err(|_overflow| Error::TooLarge {
            field,
            maximum: usize::try_from(i16::MAX).unwrap_or(usize::MAX),
            actual: count,
        })
}

/// A principal record as MIT's client sends it (`client_principal.c`).
///
/// It has no modifier, the policy only under `KADM5_POLICY`, the tagged data
/// only under `KADM5_TL_DATA`, and no key data.
///
/// # Errors
///
/// Returns the bound, layout or argument error of the first field that fails.
pub(super) fn principal_record(
    encoder: Encoder,
    record: &PrincipalRecord,
    mask: PrincipalMask,
) -> Result<Encoder, Error> {
    let policy = if mask.contains(PrincipalMask::POLICY) {
        record.policy.as_deref().map(str::as_bytes)
    } else {
        None
    };
    let entries: &[TlData] = if mask.contains(PrincipalMask::TL_DATA) {
        &record.tl_data
    } else {
        &[]
    };
    let head = principal(encoder, &record.principal)?
        .i32(record.princ_expire_time)
        .i32(record.last_pwd_change)
        .i32(record.pw_expiration)
        .i32(record.max_life)
        .bool(NULL)
        .i32(record.mod_date)
        .i32(record.attributes)
        .u32(record.kvno)
        .u32(record.mkvno);
    let tail = text(head, "policy", policy)?
        .i32(record.aux_attributes)
        .i32(record.max_renewable_life)
        .i32(record.last_success)
        .i32(record.last_failed)
        .u32(record.fail_auth_count)
        .i32(0)
        .i32(short_count("tagged data", entries.len())?);
    Ok(tl_data(tail, entries)?.u32(0).i32(mask_bits(mask)))
}

/// A mask as MIT's `long` on the wire.
const fn mask_bits(mask: PrincipalMask) -> i32 {
    i32::from_be_bytes(mask.bits().to_be_bytes())
}

/// A policy record under `version` (`_xdr_kadm5_policy_ent_rec`), then `mask`.
///
/// # Errors
///
/// Returns the bound, layout or argument error of the first field that fails.
pub(super) fn policy_record(
    encoder: Encoder,
    record: &PolicyRecord,
    version: ApiVersion,
    mask: u32,
) -> Result<Encoder, Error> {
    let mut out = text(encoder, "policy", Some(record.name.as_bytes()))?
        .i32(record.pw_min_life)
        .i32(record.pw_max_life)
        .i32(record.pw_min_length)
        .i32(record.pw_min_classes)
        .i32(record.pw_history_num)
        .i32(record.policy_refcnt);
    if version >= ApiVersion::V3 {
        out = out
            .u32(record.pw_max_fail)
            .i32(record.pw_failcnt_interval)
            .i32(record.pw_lockout_duration);
    }
    if version >= ApiVersion::V4 {
        out = out
            .i32(record.attributes)
            .i32(record.max_life)
            .i32(record.max_renewable_life);
        out = text(
            out,
            "allowed key/salt tuples",
            record.allowed_keysalts.as_deref().map(str::as_bytes),
        )?
        .i32(short_count("tagged data", record.tl_data.len())?);
        out = tl_data(out, &record.tl_data)?;
    }
    Ok(out.i32(i32::from_be_bytes(mask.to_be_bytes())))
}

/// An array count.
///
/// # Errors
///
/// Returns the bound, layout or argument error of the first field that fails.
fn count(field: &'static str, length: usize) -> Result<u32, Error> {
    u32::try_from(length)
        .ok()
        .filter(|_| length <= MAX_KEYS)
        .ok_or(Error::TooLarge {
            field,
            maximum: MAX_KEYS,
            actual: length,
        })
}

/// Key/salt tuples (`xdr_array` of `xdr_krb5_key_salt_tuple`).
///
/// # Errors
///
/// Returns the bound, layout or argument error of the first field that fails.
pub(super) fn keysalts(encoder: Encoder, tuples: &[KeySaltTuple]) -> Result<Encoder, Error> {
    let mut out = encoder.u32(count("key/salt tuples", tuples.len())?);
    for tuple in tuples {
        out = out.i32(tuple.enctype).i32(tuple.salt.wire());
    }
    Ok(out)
}

/// One keyblock (`xdr_krb5_keyblock`).
///
/// # Errors
///
/// Returns the bound, layout or argument error of the first field that fails.
fn keyblock(encoder: Encoder, key: &EncryptionKey) -> Result<Encoder, Error> {
    encoder
        .i32(key.etype())
        .opaque("key", key.value(), MAX_KEY_BYTES)
        .map_err(argument)
}

/// Keyblocks (`xdr_array` of `xdr_krb5_keyblock`).
///
/// # Errors
///
/// Returns the bound, layout or argument error of the first field that fails.
pub(super) fn keyblocks(encoder: Encoder, keys: &[EncryptionKey]) -> Result<Encoder, Error> {
    let mut out = encoder.u32(count("keys", keys.len())?);
    for key in keys {
        out = keyblock(out, key)?;
    }
    Ok(out)
}

/// Key data (`xdr_array` of `xdr_kadm5_key_data`).
///
/// # Errors
///
/// Returns the bound, layout or argument error of the first field that fails.
pub(super) fn key_data(encoder: Encoder, keys: &[KeyData]) -> Result<Encoder, Error> {
    let mut out = encoder.u32(count("key data", keys.len())?);
    for entry in keys {
        out = keyblock(out.u32(entry.kvno), &entry.key)?
            .i32(i32::from(entry.salt_type))
            .opaque("salt", &entry.salt, MAX_KEY_BYTES)
            .map_err(argument)?;
    }
    Ok(out)
}

/// A `krb5_int16` carried as `xdr_int`.
///
/// # Errors
///
/// Returns the bound, layout or argument error of the first field that fails.
fn short(decoder: &mut Decoder<'_>) -> Result<i16, Error> {
    i16::try_from(decoder.i32().map_err(result)?)
        .map_err(|_overflow| Error::Malformed("a 16-bit field out of range"))
}

/// A string that must be present and UTF-8.
///
/// # Errors
///
/// Returns the bound, layout or argument error of the first field that fails.
fn string(decoder: &mut Decoder<'_>, field: &'static str) -> Result<String, Error> {
    let bytes = decoder
        .nullstring(field, MAX_STRING)
        .map_err(result)?
        .ok_or(Error::Malformed("a required string is null"))?;
    String::from_utf8(bytes.to_vec()).map_err(|_invalid| Error::Malformed("a string is not UTF-8"))
}

/// An optional UTF-8 string.
///
/// # Errors
///
/// Returns the bound, layout or argument error of the first field that fails.
fn optional_string(
    decoder: &mut Decoder<'_>,
    field: &'static str,
) -> Result<Option<String>, Error> {
    decoder
        .nullstring(field, MAX_STRING)
        .map_err(result)?
        .map(|bytes| {
            String::from_utf8(bytes.to_vec())
                .map_err(|_invalid| Error::Malformed("a string is not UTF-8"))
        })
        .transpose()
}

/// A principal (`xdr_krb5_principal`) that must be present.
///
/// # Errors
///
/// Returns the bound, layout or argument error of the first field that fails.
fn decode_principal(decoder: &mut Decoder<'_>) -> Result<Principal, Error> {
    name::parse(&string(decoder, "principal")?)
}

/// Tagged data under `xdr_nulltype`, in wire order, `expected` entries.
///
/// # Errors
///
/// Returns the bound, layout or argument error of the first field that fails.
fn decode_tl_data(decoder: &mut Decoder<'_>, expected: i16) -> Result<Vec<TlData>, Error> {
    let mut entries = Vec::new();
    if !decoder.bool().map_err(result)? {
        while decoder.bool().map_err(result)? {
            if entries.len() >= MAX_TL {
                return Err(Error::TooLarge {
                    field: "tagged data",
                    maximum: MAX_TL,
                    actual: entries.len().saturating_add(1),
                });
            }
            let kind = short(decoder)?;
            let contents = decoder
                .opaque("tagged data", MAX_STRING)
                .map_err(result)?
                .to_vec();
            entries.push(TlData { kind, contents });
        }
    }
    if usize::try_from(expected).ok() == Some(entries.len()) {
        Ok(entries)
    } else {
        Err(Error::Malformed(
            "the tagged data count disagrees with its list",
        ))
    }
}

/// A principal record (`_xdr_kadm5_principal_ent_rec`).
///
/// # Errors
///
/// Returns the bound, layout or argument error of the first field that fails.
fn decode_principal_record(decoder: &mut Decoder<'_>) -> Result<PrincipalRecord, Error> {
    let mut record = PrincipalRecord::new(decode_principal(decoder)?);
    record.princ_expire_time = decoder.i32().map_err(result)?;
    record.last_pwd_change = decoder.i32().map_err(result)?;
    record.pw_expiration = decoder.i32().map_err(result)?;
    record.max_life = decoder.i32().map_err(result)?;
    record.mod_name = if decoder.bool().map_err(result)? {
        None
    } else {
        optional_string(decoder, "modifier")?
            .map(|text| name::parse(&text))
            .transpose()?
    };
    record.mod_date = decoder.i32().map_err(result)?;
    record.attributes = decoder.i32().map_err(result)?;
    record.kvno = decoder.u32().map_err(result)?;
    record.mkvno = decoder.u32().map_err(result)?;
    record.policy = optional_string(decoder, "policy")?;
    record.aux_attributes = decoder.i32().map_err(result)?;
    record.max_renewable_life = decoder.i32().map_err(result)?;
    record.last_success = decoder.i32().map_err(result)?;
    record.last_failed = decoder.i32().map_err(result)?;
    record.fail_auth_count = decoder.u32().map_err(result)?;
    let key_count = short(decoder)?;
    let tl_count = short(decoder)?;
    record.tl_data = decode_tl_data(decoder, tl_count)?;
    let keys = decoder.count("key data", MAX_KEYS, 12).map_err(result)?;
    if usize::try_from(key_count).ok() != Some(keys) {
        return Err(Error::Malformed(
            "the key data count disagrees with its array",
        ));
    }
    for _ in 0..keys {
        let version = short(decoder)?;
        let kvno = u16::try_from(decoder.u32().map_err(result)?)
            .map_err(|_overflow| Error::Malformed("a key version out of range"))?;
        let enctype = short(decoder)?;
        let salt_type = if version > 1 { short(decoder)? } else { 0 };
        record.key_data.push(KeyInfo {
            version,
            kvno,
            enctype,
            salt_type,
        });
    }
    Ok(record)
}

/// A policy record under `version`.
///
/// # Errors
///
/// Returns the bound, layout or argument error of the first field that fails.
fn decode_policy_record(
    decoder: &mut Decoder<'_>,
    version: ApiVersion,
) -> Result<PolicyRecord, Error> {
    let mut record = PolicyRecord::new(&string(decoder, "policy")?);
    record.pw_min_life = decoder.i32().map_err(result)?;
    record.pw_max_life = decoder.i32().map_err(result)?;
    record.pw_min_length = decoder.i32().map_err(result)?;
    record.pw_min_classes = decoder.i32().map_err(result)?;
    record.pw_history_num = decoder.i32().map_err(result)?;
    record.policy_refcnt = decoder.i32().map_err(result)?;
    if version >= ApiVersion::V3 {
        record.pw_max_fail = decoder.u32().map_err(result)?;
        record.pw_failcnt_interval = decoder.i32().map_err(result)?;
        record.pw_lockout_duration = decoder.i32().map_err(result)?;
    }
    if version >= ApiVersion::V4 {
        record.attributes = decoder.i32().map_err(result)?;
        record.max_life = decoder.i32().map_err(result)?;
        record.max_renewable_life = decoder.i32().map_err(result)?;
        record.allowed_keysalts = optional_string(decoder, "allowed key/salt tuples")?;
        let tl_count = short(decoder)?;
        record.tl_data = decode_tl_data(decoder, tl_count)?;
    }
    Ok(record)
}

/// The `int` count and the array count of a list: equal.
///
/// # Errors
///
/// Returns the bound, layout or argument error of the first field that fails.
fn list_count(
    decoder: &mut Decoder<'_>,
    field: &'static str,
    maximum: usize,
    minimum: usize,
) -> Result<usize, Error> {
    let declared = decoder.i32().map_err(result)?;
    let count = decoder.count(field, maximum, minimum).map_err(result)?;
    if usize::try_from(declared).ok() == Some(count) {
        Ok(count)
    } else {
        Err(Error::Malformed("a list count disagrees with its array"))
    }
}

/// A list of names (`gprincs_ret`, `gpols_ret`).
///
/// # Errors
///
/// Returns the bound, layout or argument error of the first field that fails.
fn decode_names(decoder: &mut Decoder<'_>) -> Result<Vec<String>, Error> {
    let count = list_count(decoder, "names", MAX_NAMES, 8)?;
    let mut names = Vec::with_capacity(count);
    for _ in 0..count {
        names.push(string(decoder, "name")?);
    }
    Ok(names)
}

/// Keyblocks (`chrand_ret`).
///
/// # Errors
///
/// Returns the bound, layout or argument error of the first field that fails.
fn decode_keys(decoder: &mut Decoder<'_>) -> Result<Vec<EncryptionKey>, Error> {
    let count = decoder.count("keys", MAX_KEYS, 8).map_err(result)?;
    iter::repeat_with(|| {
        let etype = decoder.i32().map_err(result)?;
        let value = Zeroizing::new(
            decoder
                .opaque("key", MAX_KEY_BYTES)
                .map_err(result)?
                .to_vec(),
        );
        Ok(EncryptionKey::new(etype, value))
    })
    .take(count)
    .collect()
}

/// Key data (`getpkeys_ret`).
///
/// # Errors
///
/// Returns the bound, layout or argument error of the first field that fails.
fn decode_key_data(decoder: &mut Decoder<'_>) -> Result<Vec<KeyData>, Error> {
    let count = decoder.count("key data", MAX_KEYS, 16).map_err(result)?;
    iter::repeat_with(|| {
        let kvno = decoder.u32().map_err(result)?;
        let etype = decoder.i32().map_err(result)?;
        let key = Zeroizing::new(
            decoder
                .opaque("key", MAX_KEY_BYTES)
                .map_err(result)?
                .to_vec(),
        );
        let salt_type = short(decoder)?;
        let salt = Zeroizing::new(
            decoder
                .opaque("salt", MAX_KEY_BYTES)
                .map_err(result)?
                .to_vec(),
        );
        Ok(KeyData {
            kvno,
            key: EncryptionKey::new(etype, key),
            salt_type,
            salt,
        })
    })
    .take(count)
    .collect()
}

/// String attributes (`gstrings_ret`).
///
/// # Errors
///
/// Returns the bound, layout or argument error of the first field that fails.
fn decode_strings(decoder: &mut Decoder<'_>) -> Result<Vec<StringAttribute>, Error> {
    let count = list_count(decoder, "string attributes", MAX_TL, 16)?;
    iter::repeat_with(|| {
        Ok(StringAttribute {
            key: string(decoder, "attribute key")?,
            value: string(decoder, "attribute value")?,
        })
    })
    .take(count)
    .collect()
}

/// See [`Response::decode`].
///
/// # Errors
///
/// Returns the bound, layout or argument error of the first field that fails.
pub(super) fn decode_response(
    procedure: Procedure,
    version: ApiVersion,
    bytes: &[u8],
) -> Result<Response, Error> {
    let mut decoder = Decoder::new(bytes);
    let _api_version = decoder.u32().map_err(result)?;
    let code = decoder.u32().map_err(result)?;
    if code != 0 {
        return Err(Error::Server {
            procedure: procedure.name(),
            code,
        });
    }
    let response = match procedure {
        Procedure::GetPrincipal => {
            Response::Principal(Box::new(decode_principal_record(&mut decoder)?))
        }
        Procedure::GetPolicy => {
            Response::Policy(Box::new(decode_policy_record(&mut decoder, version)?))
        }
        Procedure::GetPrincipals | Procedure::GetPolicies => {
            Response::Names(decode_names(&mut decoder)?)
        }
        Procedure::RandomizeKeys | Procedure::RandomizeKeys3 => {
            Response::Keys(decode_keys(&mut decoder)?)
        }
        Procedure::GetPrivileges => {
            Response::Privileges(Privileges(decoder.u32().map_err(result)?))
        }
        Procedure::GetStrings => Response::Strings(decode_strings(&mut decoder)?),
        Procedure::ExtractKeys => Response::KeyData(decode_key_data(&mut decoder)?),
        Procedure::CreatePrincipal
        | Procedure::DeletePrincipal
        | Procedure::ModifyPrincipal
        | Procedure::RenamePrincipal
        | Procedure::ChangePassword
        | Procedure::CreatePolicy
        | Procedure::DeletePolicy
        | Procedure::ModifyPolicy
        | Procedure::Init
        | Procedure::SetKeys
        | Procedure::CreatePrincipal3
        | Procedure::ChangePassword3
        | Procedure::SetKeys3
        | Procedure::PurgeKeys
        | Procedure::SetString
        | Procedure::SetKeys4
        | Procedure::CreateAlias => Response::Done,
    };
    decoder.end().map_err(result)?;
    Ok(response)
}

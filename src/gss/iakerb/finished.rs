//! The `IAKERB-FINISHED` checksum of the transcript.
//!
//! MIT 1.22.2 `iakerb_make_finished` and `iakerb_verify_finished`
//! (`iakerb.c:125-181`): the checksum of the default type of the key over the
//! transcript, key usage `KRB5_KEYUSAGE_FINISHED` (41, `iakerb.c:141,173`; not
//! the unused `KRB5_KEYUSAGE_IAKERB_FINISHED` 42 of `krb5.hin:990`), carried as
//! extension type 2 (`GSS_EXTS_FINISHED`, `gssapiP_krb5.h:1296`) after the
//! flags and the optional delegation of the authenticator checksum
//! (`init_sec_context.c:341-345`).

use rasn::{AsnType, Decode, Decoder as _, Encode, Encoder as _, der};

use super::Error;
use crate::{
    crypto::KerberosEtype, der::decode_complete, gss::ContextFlags, keytab::EncryptionKey,
};

/// `KRB5_KEYUSAGE_FINISHED`.
const USAGE: u32 = 41;
/// `GSS_EXTS_FINISHED`.
const EXTENSION_TYPE: u32 = 2;
/// The delegation option of the authenticator checksum.
const DELEGATION_OPTION: u16 = 1;
/// The most extensions a checksum may carry.
const MAX_EXTENSIONS: usize = 16;

/// `IAKERB-FINISHED ::= SEQUENCE { checksum [1] Checksum }`
/// (MIT `asn1_k_encode.c:1102-1107`).
#[derive(AsnType, Clone, Debug, Decode, Encode, Eq, PartialEq)]
struct Finished {
    /// The checksum of the transcript.
    #[rasn(tag(explicit(1)))]
    checksum: rasn_kerberos::Checksum,
}

/// The cipher of `key`.
///
/// # Errors
///
/// Returns [`Error::BadFinished`] for an enctype this crate does not implement.
fn cipher(key: &EncryptionKey) -> Result<KerberosEtype, Error> {
    KerberosEtype::from_etype_id(key.etype()).ok_or(Error::BadFinished)
}

/// The `IAKERB-FINISHED` of `transcript` under `key`.
///
/// # Errors
///
/// Returns [`Error::BadFinished`] for a key that cannot checksum.
pub(super) fn make(key: &EncryptionKey, transcript: &[u8]) -> Result<Vec<u8>, Error> {
    let kind = cipher(key)?;
    let checksum = kind
        .checksum(key.value(), transcript, USAGE)
        .map_err(|_failure| Error::BadFinished)?;
    der::encode(&Finished {
        checksum: rasn_kerberos::Checksum {
            r#type: kind.checksum_type_id(),
            checksum: checksum.into(),
        },
    })
    .map_err(|_failure| Error::BadFinished)
}

/// The extension that carries `finished` in the authenticator checksum: a
/// big-endian type and length, then the value.
///
/// # Errors
///
/// Returns [`Error::BadFinished`] for a value above 4 GiB.
pub(super) fn extension(finished: &[u8]) -> Result<Vec<u8>, Error> {
    let length = u32::try_from(finished.len()).map_err(|_range| Error::BadFinished)?;
    let mut out = EXTENSION_TYPE.to_be_bytes().to_vec();
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(finished);
    Ok(out)
}

/// Verify `finished` against `transcript` under `key`.
///
/// # Errors
///
/// Returns [`Error::BadFinished`] unless `finished` is exactly one
/// `IAKERB-FINISHED` whose checksum is of the key's type and covers the
/// transcript.
pub(super) fn verify(key: &EncryptionKey, transcript: &[u8], finished: &[u8]) -> Result<(), Error> {
    let kind = cipher(key)?;
    let value: Finished = decode_complete(finished).map_err(|_failure| Error::BadFinished)?;
    if value.checksum.r#type != kind.checksum_type_id()
        || !kind.verify_checksum(key.value(), transcript, &value.checksum.checksum, USAGE)
    {
        return Err(Error::BadFinished);
    }
    Ok(())
}

/// Take `N` bytes off the front of `rest`.
fn take<const N: usize>(rest: &mut &[u8]) -> Option<[u8; N]> {
    let (head, tail) = rest.split_first_chunk::<N>()?;
    *rest = tail;
    Some(*head)
}

/// The `IAKERB-FINISHED` extension of an authenticator checksum, if any
/// (MIT `kg_process_extension`, `accept_sec_context.c:371-401`).
///
/// # Errors
///
/// Returns [`Error::BadFinished`] for a checksum whose layout is malformed or
/// that carries two finished extensions.
pub(super) fn find(checksum: &[u8]) -> Result<Option<Vec<u8>>, Error> {
    let malformed = || Error::BadFinished;
    let mut rest = checksum;
    let _bindings_length: [u8; 4] = take(&mut rest).ok_or_else(malformed)?;
    let _bindings: [u8; 16] = take(&mut rest).ok_or_else(malformed)?;
    let flags = u32::from_le_bytes(take(&mut rest).ok_or_else(malformed)?);
    if rest.len() >= 4 && flags & ContextFlags::DELEG.bits() != 0 {
        let option = u16::from_le_bytes(take(&mut rest).ok_or_else(malformed)?);
        let length = usize::from(u16::from_le_bytes(take(&mut rest).ok_or_else(malformed)?));
        let (_credential, tail) = rest.split_at_checked(length).ok_or_else(malformed)?;
        if option != DELEGATION_OPTION {
            return Err(malformed());
        }
        rest = tail;
    }
    let mut found = None;
    for _extension in 0..MAX_EXTENSIONS {
        if rest.is_empty() {
            return Ok(found);
        }
        let kind = u32::from_be_bytes(take(&mut rest).ok_or_else(malformed)?);
        let length = usize::try_from(u32::from_be_bytes(take(&mut rest).ok_or_else(malformed)?))
            .map_err(|_range| malformed())?;
        let (value, tail) = rest.split_at_checked(length).ok_or_else(malformed)?;
        rest = tail;
        if kind == EXTENSION_TYPE && found.replace(value.to_vec()).is_some() {
            return Err(malformed());
        }
    }
    if rest.is_empty() {
        Ok(found)
    } else {
        Err(malformed())
    }
}

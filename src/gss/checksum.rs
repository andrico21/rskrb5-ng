//! The authenticator checksum and the CBT authorization data.
//!
//! The RFC 4121 section 4.1.1 authenticator checksum (type `0x8003`) and the
//! MS-KILE `KERB_AP_OPTIONS_CBT` authorization data.
//!
//! Decoding follows MIT 1.22.2 `process_checksum` (`accept_sec_context.c:464-597`):
//! a 24-byte fixed part, an optional delegation option when the delegation
//! flag is set and at least four bytes follow, then big-endian extensions, of
//! which only the `IAKERB-FINISHED` is kept (`kg_process_extension`,
//! `accept_sec_context.c:369-401`). The AP-OPTIONS search follows `check_cbt`
//! (`accept_sec_context.c:422-448`), the encoding `make_ap_authdata`
//! (`mk_req_ext.c:360-400`).

use rasn::der;
use zeroize::Zeroizing;

use super::{ContextFlags, Error, context::Mechanism};
use crate::der::decode_complete;

/// The authenticator checksum type of the krb5 GSS mechanism.
pub(super) const CHECKSUM_TYPE: i32 = 0x8003;
/// The extension type of an `IAKERB-FINISHED` (`GSS_EXTS_FINISHED`,
/// `gssapiP_krb5.h:1296`).
pub(super) const FINISHED_EXTENSION: u32 = 2;
/// The length of the fixed part: bindings length, bindings, flags.
const FIXED_LEN: usize = 24;
/// The delegation option (`KRB5_GSS_FOR_CREDS_OPTION`).
const DELEGATION_OPTION: u16 = 1;
/// The most extensions a checksum may carry.
const MAX_EXTENSIONS: usize = 16;
/// MS-KILE `KERB_AP_OPTIONS_CBT`.
const KERB_AP_OPTIONS_CBT: u32 = 0x4000;
/// `KRB5_AUTHDATA_AP_OPTIONS`.
const AD_AP_OPTIONS: i32 = 143;
/// `KRB5_AUTHDATA_IF_RELEVANT`.
const AD_IF_RELEVANT: i32 = 1;
/// The deepest `AD-IF-RELEVANT` nesting searched.
const MAX_DEPTH: usize = 8;

/// The extension record of an AP exchange (MIT `krb5_gss_ctx_ext_rec`,
/// `gssapiP_krb5.h:199-205`): what a mechanism layered on krb5 adds to the
/// shared initiator and acceptor.
#[derive(Clone, Copy, Debug)]
pub(super) struct Extensions<'conv> {
    /// The mechanism of the context and its tokens.
    mechanism: Mechanism,
    /// The IAKERB transcript the `IAKERB-FINISHED` covers (`iakerb.conv`),
    /// set only when IAKERB tokens were exchanged (`iakerb_make_exts`,
    /// `iakerb.c:838-844`).
    conversation: Option<&'conv [u8]>,
}

impl<'conv> Extensions<'conv> {
    /// The krb5 mechanism: no extension.
    pub(super) const KRB5: Self = Self {
        mechanism: Mechanism::Krb5,
        conversation: None,
    };

    /// An IAKERB context whose exchange produced `transcript`.
    pub(super) const fn iakerb(transcript: &'conv [u8]) -> Self {
        Self {
            mechanism: Mechanism::Iakerb,
            conversation: if transcript.is_empty() {
                None
            } else {
                Some(transcript)
            },
        }
    }

    /// The mechanism of the context.
    pub(super) const fn mechanism(self) -> Mechanism {
        self.mechanism
    }

    /// The transcript an `IAKERB-FINISHED` must cover.
    pub(super) const fn conversation(self) -> Option<&'conv [u8]> {
        self.conversation
    }
}

/// A decoded authenticator checksum.
pub(super) struct Decoded {
    /// The channel-binding digest; all zero when the initiator sent none.
    bindings: [u8; 16],
    /// The initiator's context flags.
    flags: u32,
    /// The delegated KRB-CRED, when the initiator sent one.
    delegation: Option<Zeroizing<Vec<u8>>>,
    /// The `IAKERB-FINISHED` extension, when the initiator sent one.
    finished: Option<Vec<u8>>,
}

impl Decoded {
    /// The channel-binding digest.
    pub(super) const fn bindings(&self) -> &[u8; 16] {
        &self.bindings
    }

    /// The initiator's context flags.
    pub(super) const fn flags(&self) -> ContextFlags {
        ContextFlags::from_bits(self.flags)
    }

    /// Take the delegated KRB-CRED.
    pub(super) const fn take_delegation(&mut self) -> Option<Zeroizing<Vec<u8>>> {
        self.delegation.take()
    }

    /// The `IAKERB-FINISHED` extension.
    pub(super) fn finished(&self) -> Option<&[u8]> {
        self.finished.as_deref()
    }
}

/// An authenticator-checksum extension: a big-endian type and length, then
/// the value (MIT `init_sec_context.c:341-345`).
///
/// # Errors
///
/// Returns [`Error::DefectiveChecksum`] for a value above 4 GiB.
pub(super) fn extension(kind: u32, value: &[u8]) -> Result<Vec<u8>, Error> {
    let length = u32::try_from(value.len())
        .map_err(|_range| Error::DefectiveChecksum("an extension above 4 GiB"))?;
    let mut out = kind.to_be_bytes().to_vec();
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(value);
    Ok(out)
}

/// The checksum bytes of `bindings`, `flags` and an optional KRB-CRED.
///
/// # Errors
///
/// Returns [`Error::DefectiveChecksum`] for a KRB-CRED longer than MIT sends
/// (`init_sec_context.c:291-295`).
pub(super) fn encode(
    bindings: &[u8; 16],
    flags: ContextFlags,
    delegation: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(FIXED_LEN);
    out.extend_from_slice(&16_u32.to_le_bytes());
    out.extend_from_slice(bindings);
    out.extend_from_slice(&flags.bits().to_le_bytes());
    if let Some(credential) = delegation {
        let fits = credential.len().saturating_add(28) <= 0x7fff;
        let length = u16::try_from(credential.len())
            .ok()
            .filter(|_| fits)
            .ok_or(Error::DefectiveChecksum(
                "the delegated credential is too long",
            ))?;
        out.extend_from_slice(&DELEGATION_OPTION.to_le_bytes());
        out.extend_from_slice(&length.to_le_bytes());
        out.extend_from_slice(credential);
    }
    Ok(out)
}

/// Take `N` bytes off the front of `rest`.
///
/// # Errors
///
/// Returns [`Error::DefectiveChecksum`] naming `what` when fewer remain.
fn take<const N: usize>(rest: &mut &[u8], what: &'static str) -> Result<[u8; N], Error> {
    let (head, tail) = rest
        .split_first_chunk::<N>()
        .ok_or(Error::DefectiveChecksum(what))?;
    *rest = tail;
    Ok(*head)
}

/// Take `length` bytes off the front of `rest`.
///
/// # Errors
///
/// Returns [`Error::DefectiveChecksum`] naming `what` when fewer remain.
fn take_slice<'bytes>(
    rest: &mut &'bytes [u8],
    length: usize,
    what: &'static str,
) -> Result<&'bytes [u8], Error> {
    let (head, tail) = rest
        .split_at_checked(length)
        .ok_or(Error::DefectiveChecksum(what))?;
    *rest = tail;
    Ok(head)
}

/// Decode a checksum value.
///
/// # Errors
///
/// Returns [`Error::DefectiveChecksum`] for a short value, a bindings length
/// other than 16, an unknown or truncated option, a truncated extension, more
/// than 16 extensions or two `IAKERB-FINISHED` extensions.
pub(super) fn decode(bytes: &[u8]) -> Result<Decoded, Error> {
    let fixed = "shorter than its 24-byte fixed part";
    let mut rest = bytes;
    if u32::from_le_bytes(take::<4>(&mut rest, fixed)?) != 16 {
        return Err(Error::DefectiveChecksum("the bindings length is not 16"));
    }
    let bindings = take::<16>(&mut rest, fixed)?;
    let flags = u32::from_le_bytes(take::<4>(&mut rest, fixed)?);
    let delegation = if rest.len() >= 4 && flags & ContextFlags::DELEG.bits() != 0 {
        let option = "a truncated delegation option";
        if u16::from_le_bytes(take::<2>(&mut rest, option)?) != DELEGATION_OPTION {
            return Err(Error::DefectiveChecksum("an unknown option"));
        }
        let length = usize::from(u16::from_le_bytes(take::<2>(&mut rest, option)?));
        Some(Zeroizing::new(
            take_slice(&mut rest, length, option)?.to_vec(),
        ))
    } else {
        None
    };
    let mut extensions = 0_usize;
    let mut finished = None;
    while !rest.is_empty() {
        extensions = extensions.saturating_add(1);
        if extensions > MAX_EXTENSIONS {
            return Err(Error::DefectiveChecksum("more than 16 extensions"));
        }
        let extension = "a truncated extension";
        let kind = u32::from_be_bytes(take::<4>(&mut rest, extension)?);
        let length = usize::try_from(u32::from_be_bytes(take::<4>(&mut rest, extension)?))
            .map_err(|_range| Error::DefectiveChecksum(extension))?;
        let value = take_slice(&mut rest, length, extension)?;
        if kind == FINISHED_EXTENSION && finished.replace(value.to_vec()).is_some() {
            return Err(Error::DefectiveChecksum("two IAKERB-FINISHED extensions"));
        }
    }
    Ok(Decoded {
        bindings,
        flags,
        delegation,
        finished,
    })
}

/// The authorization data of a channel-binding-aware initiator: an
/// `AD-IF-RELEVANT` holding one `AD-AP-OPTIONS` of `KERB_AP_OPTIONS_CBT`.
///
/// # Errors
///
/// Returns [`Error::DefectiveToken`] when the data does not encode.
pub(super) fn cbt_authorization_data() -> Result<rasn_kerberos::AuthorizationData, Error> {
    let inner: rasn_kerberos::AuthorizationData = vec![rasn_kerberos::AuthorizationDataValue {
        r#type: AD_AP_OPTIONS,
        data: KERB_AP_OPTIONS_CBT.to_le_bytes().to_vec().into(),
    }];
    let wrapped = der::encode(&inner)
        .map_err(|_encode| Error::DefectiveToken("authorization data does not encode"))?;
    Ok(vec![rasn_kerberos::AuthorizationDataValue {
        r#type: AD_IF_RELEVANT,
        data: wrapped.into(),
    }])
}

/// Collect the `AD-AP-OPTIONS` elements of `data`, searching `AD-IF-RELEVANT`.
///
/// # Errors
///
/// Returns [`Error::DefectiveToken`] for an undecodable container or nesting
/// deeper than eight.
fn ap_options(
    data: &rasn_kerberos::AuthorizationData,
    depth: usize,
    found: &mut Vec<Vec<u8>>,
) -> Result<(), Error> {
    if depth > MAX_DEPTH {
        return Err(Error::DefectiveToken("authorization data nests too deeply"));
    }
    for entry in data {
        match entry.r#type {
            AD_AP_OPTIONS => found.push(entry.data.to_vec()),
            AD_IF_RELEVANT => {
                let nested = decode_complete::<rasn_kerberos::AuthorizationData>(&entry.data)
                    .map_err(|_decode| Error::DefectiveToken("malformed AD-IF-RELEVANT"))?;
                ap_options(&nested, depth.saturating_add(1), found)?;
            }
            _ => {}
        }
    }
    Ok(())
}

/// Whether the authenticator asserts `KERB_AP_OPTIONS_CBT`.
///
/// # Errors
///
/// Returns [`Error::DefectiveToken`] for more than one `AD-AP-OPTIONS`, one
/// that is not four bytes (MIT `KRB5KRB_AP_ERR_MSG_TYPE`), or malformed
/// containers.
pub(super) fn asserts_cbt(data: Option<&rasn_kerberos::AuthorizationData>) -> Result<bool, Error> {
    let Some(elements) = data else {
        return Ok(false);
    };
    let mut found = Vec::new();
    ap_options(elements, 0, &mut found)?;
    match found.as_slice() {
        [] => Ok(false),
        [only] => {
            let options: [u8; 4] = only
                .as_slice()
                .try_into()
                .map_err(|_length| Error::DefectiveToken("AD-AP-OPTIONS is not four bytes"))?;
            Ok(u32::from_le_bytes(options) & KERB_AP_OPTIONS_CBT != 0)
        }
        _ => Err(Error::DefectiveToken("more than one AD-AP-OPTIONS")),
    }
}

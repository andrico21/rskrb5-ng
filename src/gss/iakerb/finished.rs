//! The `IAKERB-FINISHED` checksum of the transcript.
//!
//! MIT 1.22.2 `iakerb_make_finished` and `iakerb_verify_finished`
//! (`iakerb.c:125-181`): the checksum of the default type of the key over the
//! transcript, key usage `KRB5_KEYUSAGE_FINISHED` (41, `iakerb.c:141,173`; not
//! the unused `KRB5_KEYUSAGE_IAKERB_FINISHED` 42 of `krb5.hin:990`), carried as
//! extension type 2 (`GSS_EXTS_FINISHED`, `gssapiP_krb5.h:1296`) of the
//! authenticator checksum (`init_sec_context.c:341-345`). The shared krb5 AP
//! exchange calls [`make`] and [`check`] through its extension record.

use rasn::{AsnType, Decode, Decoder as _, Encode, Encoder as _, der};

use crate::{crypto::KerberosEtype, der::decode_complete, error::Gss, keytab::EncryptionKey};

/// `KRB5_KEYUSAGE_FINISHED`.
const USAGE: u32 = 41;

/// `IAKERB-FINISHED ::= SEQUENCE { checksum [1] Checksum }`
/// (MIT `asn1_k_encode.c:1102-1107`).
#[derive(AsnType, Clone, Debug, Decode, Encode, Eq, PartialEq)]
struct Finished {
    /// The checksum of the transcript.
    #[rasn(tag(explicit(1)))]
    checksum: rasn_kerberos::Checksum,
}

/// Why the acceptor refuses the `IAKERB-FINISHED` of an AP-REQ.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::gss) enum Fault {
    /// One arrived although no IAKERB token was exchanged
    /// (`KRB5KRB_AP_ERR_MSG_TYPE`, `accept_sec_context.c:381-383`).
    Unexpected,
    /// None arrived after an IAKERB exchange (`GSS_S_BAD_SIG`,
    /// `accept_sec_context.c:850-853`).
    Missing,
    /// It does not cover the transcript under the initiator's subkey
    /// (`GSS_S_BAD_SIG`).
    Bad,
}

/// The krb5 mechanism's error for a [`Fault`]: only [`Fault::Unexpected`] can
/// reach a krb5 context, which has no transcript.
const fn gss(fault: Fault) -> Gss {
    match fault {
        Fault::Unexpected => {
            Gss::DefectiveChecksum("an IAKERB-FINISHED without an IAKERB exchange")
        }
        Fault::Missing | Fault::Bad => Gss::BadSignature,
    }
}

impl From<Fault> for Gss {
    #[inline]
    fn from(fault: Fault) -> Self {
        gss(fault)
    }
}

/// The `IAKERB-FINISHED` of `transcript` under `key`.
///
/// # Errors
///
/// Returns [`Gss::DefectiveChecksum`] for a key that cannot checksum.
pub(in crate::gss) fn make(key: &EncryptionKey, transcript: &[u8]) -> Result<Vec<u8>, Gss> {
    let failed = || Gss::DefectiveChecksum("the IAKERB-FINISHED cannot be computed");
    let kind = KerberosEtype::from_etype_id(key.etype()).ok_or_else(failed)?;
    let checksum = kind
        .checksum(key.value(), transcript, USAGE)
        .map_err(|_failure| failed())?;
    der::encode(&Finished {
        checksum: rasn_kerberos::Checksum {
            r#type: kind.checksum_type_id(),
            checksum: checksum.into(),
        },
    })
    .map_err(|_failure| failed())
}

/// Verify `finished` against `transcript` under `key`.
///
/// # Errors
///
/// Returns [`Fault::Bad`] unless `finished` is exactly one `IAKERB-FINISHED`
/// whose checksum is of the key's type and covers the transcript.
fn verify(key: &EncryptionKey, transcript: &[u8], finished: &[u8]) -> Result<(), Fault> {
    let kind = KerberosEtype::from_etype_id(key.etype()).ok_or(Fault::Bad)?;
    let value: Finished = decode_complete(finished).map_err(|_failure| Fault::Bad)?;
    if value.checksum.r#type != kind.checksum_type_id()
        || !kind.verify_checksum(key.value(), transcript, &value.checksum.checksum, USAGE)
    {
        return Err(Fault::Bad);
    }
    Ok(())
}

/// Check the `IAKERB-FINISHED` of an authenticator against a transcript.
///
/// The transcript comes from the extension record, the key is the
/// authenticator's `subkey` (MIT `kg_process_extension`,
/// `accept_sec_context.c:369-401`, and the verification requirement of
/// `:850-853`).
///
/// # Errors
///
/// Returns [`Fault::Unexpected`] for a finished without a transcript,
/// [`Fault::Missing`] for a transcript without a finished, and [`Fault::Bad`]
/// for one that does not verify or an authenticator without a subkey.
pub(in crate::gss) fn check(
    transcript: Option<&[u8]>,
    finished: Option<&[u8]>,
    subkey: Option<&rasn_kerberos::EncryptionKey>,
) -> Result<(), Fault> {
    match (transcript, finished) {
        (None, None) => Ok(()),
        (None, Some(_)) => Err(Fault::Unexpected),
        (Some(_), None) => Err(Fault::Missing),
        (Some(conversation), Some(proof)) => {
            let wire = subkey.ok_or(Fault::Bad)?;
            let key = EncryptionKey::new(wire.r#type, wire.value.to_vec());
            verify(&key, conversation, proof)
        }
    }
}

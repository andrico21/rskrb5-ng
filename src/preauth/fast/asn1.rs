//! RFC 6113 section 5.4 FAST messages, DER-encoded with explicit tags.
//!
//! A KDC reply is untrusted input: decoding refuses unknown CHOICE
//! alternatives and trailing bytes, and every field is bounded by the reply
//! the transport already bounded. The types stay inside the crate: they hold
//! keys and ciphertext and are never handed to callers.

use core::fmt;

use rasn::{
    AsnType, Decode, Decoder as _, Encode, Encoder as _,
    types::{OctetString, SequenceOf},
};
use rasn_kerberos::{
    Checksum, EncryptedData, EncryptionKey, KdcReqBody, KerberosFlags, KerberosTime, Microseconds,
    PaData, PrincipalName, Realm,
};

/// `KrbFastArmor` (RFC 6113 section 5.4.1).
#[derive(AsnType, Clone, Decode, Encode, Eq, PartialEq)]
pub(crate) struct KrbFastArmor {
    /// The armor type; 1 is `FX_FAST_ARMOR_AP_REQUEST`.
    #[rasn(tag(explicit(0)))]
    pub armor_type: i32,
    /// The armor: the DER AP-REQ of an AP-REQ armor.
    #[rasn(tag(explicit(1)))]
    pub armor_value: OctetString,
}

impl fmt::Debug for KrbFastArmor {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KrbFastArmor")
            .field("armor_type", &self.armor_type)
            .field("armor_value_bytes", &self.armor_value.len())
            .finish()
    }
}

/// `KrbFastArmoredReq` (RFC 6113 section 5.4.2).
#[derive(AsnType, Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub(crate) struct KrbFastArmoredReq {
    /// The armor; present in an AS-REQ.
    #[rasn(tag(explicit(0)))]
    pub armor: Option<KrbFastArmor>,
    /// The armor key's checksum over the outer KDC-REQ-BODY (usage 50).
    #[rasn(tag(explicit(1)))]
    pub req_checksum: Checksum,
    /// The `KrbFastReq`, encrypted in the armor key (usage 51).
    #[rasn(tag(explicit(2)))]
    pub enc_fast_req: EncryptedData,
}

/// `PA-FX-FAST-REQUEST` (RFC 6113 section 5.4.2), an extensible CHOICE.
#[derive(AsnType, Clone, Debug, Decode, Encode, Eq, PartialEq)]
#[rasn(choice)]
pub(crate) enum PaFxFastRequest {
    /// The armored request.
    #[rasn(tag(explicit(0)))]
    ArmoredData(KrbFastArmoredReq),
}

/// `KrbFastReq` (RFC 6113 section 5.4.2): the protected inner request.
#[derive(AsnType, Clone, Decode, Encode, Eq, PartialEq)]
pub(crate) struct KrbFastReq {
    /// `FastOptions` (bits 1-15 are critical).
    #[rasn(tag(explicit(0)))]
    pub fast_options: KerberosFlags,
    /// The inner padata.
    #[rasn(tag(explicit(1)))]
    pub padata: SequenceOf<PaData>,
    /// The inner request body, used in preference to the outer one.
    #[rasn(tag(explicit(2)))]
    pub req_body: KdcReqBody,
}

impl fmt::Debug for KrbFastReq {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let types: Vec<i32> = self.padata.iter().map(|entry| entry.r#type).collect();
        f.debug_struct("KrbFastReq")
            .field("padata_types", &types)
            .field("nonce", &self.req_body.nonce)
            .finish_non_exhaustive()
    }
}

/// `KrbFastArmoredRep` (RFC 6113 section 5.4.3).
#[derive(AsnType, Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub(crate) struct KrbFastArmoredRep {
    /// The `KrbFastResponse`, encrypted in the armor key (usage 52).
    #[rasn(tag(explicit(0)))]
    pub enc_fast_rep: EncryptedData,
}

/// `PA-FX-FAST-REPLY` (RFC 6113 section 5.4.3), an extensible CHOICE.
#[derive(AsnType, Clone, Debug, Decode, Encode, Eq, PartialEq)]
#[rasn(choice)]
pub(crate) enum PaFxFastReply {
    /// The armored reply.
    #[rasn(tag(explicit(0)))]
    ArmoredData(KrbFastArmoredRep),
}

/// `KrbFastResponse` (RFC 6113 section 5.4.3). Its `Debug` output redacts the
/// strengthen key; the dependency-owned key bytes are not erased on drop.
#[derive(AsnType, Clone, Decode, Encode, Eq, PartialEq)]
pub(crate) struct KrbFastResponse {
    /// The reply padata.
    #[rasn(tag(explicit(0)))]
    pub padata: SequenceOf<PaData>,
    /// The key that strengthens the reply key; absent in an error.
    #[rasn(tag(explicit(1)))]
    pub strengthen_key: Option<EncryptionKey>,
    /// The finished message of a reply that carries a ticket.
    #[rasn(tag(explicit(2)))]
    pub finished: Option<KrbFastFinished>,
    /// The nonce of the request this answers.
    #[rasn(tag(explicit(3)))]
    pub nonce: u32,
}

impl fmt::Debug for KrbFastResponse {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let types: Vec<i32> = self.padata.iter().map(|entry| entry.r#type).collect();
        f.debug_struct("KrbFastResponse")
            .field("padata_types", &types)
            .field("strengthen_key", &self.strengthen_key.is_some())
            .field("finished", &self.finished)
            .field("nonce", &self.nonce)
            .finish()
    }
}

/// `KrbFastFinished` (RFC 6113 section 5.4.3).
#[derive(AsnType, Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub(crate) struct KrbFastFinished {
    /// The KDC time the ticket was issued.
    #[rasn(tag(explicit(0)))]
    pub timestamp: KerberosTime,
    /// The microseconds of `timestamp`.
    #[rasn(tag(explicit(1)))]
    pub usec: Microseconds,
    /// The authenticated client realm.
    #[rasn(tag(explicit(2)))]
    pub crealm: Realm,
    /// The authenticated client name.
    #[rasn(tag(explicit(3)))]
    pub cname: PrincipalName,
    /// The armor key's checksum over the ticket (usage 53).
    #[rasn(tag(explicit(4)))]
    pub ticket_checksum: Checksum,
}

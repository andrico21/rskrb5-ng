//! The RFC 6113 section 5.4 messages, written from the RFC's ASN.1 module
//! independently of the library's own definitions.

use rasn::{
    AsnType, Decode, Decoder as _, Encode, Encoder as _,
    types::{OctetString, SequenceOf},
};
use rasn_kerberos::{
    Checksum, EncryptedData, EncryptionKey, KdcReqBody, KerberosFlags, KerberosTime, Microseconds,
    PaData, PrincipalName, Realm,
};

/// `KrbFastArmor`.
#[derive(AsnType, Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub(crate) struct KrbFastArmor {
    /// `armor-type [0] Int32`.
    #[rasn(tag(explicit(0)))]
    pub armor_type: i32,
    /// `armor-value [1] OCTET STRING`.
    #[rasn(tag(explicit(1)))]
    pub armor_value: OctetString,
}

/// `KrbFastArmoredReq`.
#[derive(AsnType, Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub(crate) struct KrbFastArmoredReq {
    /// `armor [0] KrbFastArmor OPTIONAL`.
    #[rasn(tag(explicit(0)))]
    pub armor: Option<KrbFastArmor>,
    /// `req-checksum [1] Checksum`.
    #[rasn(tag(explicit(1)))]
    pub req_checksum: Checksum,
    /// `enc-fast-req [2] EncryptedData`.
    #[rasn(tag(explicit(2)))]
    pub enc_fast_req: EncryptedData,
}

/// `PA-FX-FAST-REQUEST`.
#[derive(AsnType, Clone, Debug, Decode, Encode, Eq, PartialEq)]
#[rasn(choice)]
pub(crate) enum PaFxFastRequest {
    /// `armored-data [0] KrbFastArmoredReq`.
    #[rasn(tag(explicit(0)))]
    ArmoredData(KrbFastArmoredReq),
}

/// `KrbFastReq`.
#[derive(AsnType, Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub(crate) struct KrbFastReq {
    /// `fast-options [0] FastOptions`.
    #[rasn(tag(explicit(0)))]
    pub fast_options: KerberosFlags,
    /// `padata [1] SEQUENCE OF PA-DATA`.
    #[rasn(tag(explicit(1)))]
    pub padata: SequenceOf<PaData>,
    /// `req-body [2] KDC-REQ-BODY`.
    #[rasn(tag(explicit(2)))]
    pub req_body: KdcReqBody,
}

/// `KrbFastArmoredRep`.
#[derive(AsnType, Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub(crate) struct KrbFastArmoredRep {
    /// `enc-fast-rep [0] EncryptedData`.
    #[rasn(tag(explicit(0)))]
    pub enc_fast_rep: EncryptedData,
}

/// `PA-FX-FAST-REPLY`.
#[derive(AsnType, Clone, Debug, Decode, Encode, Eq, PartialEq)]
#[rasn(choice)]
pub(crate) enum PaFxFastReply {
    /// `armored-data [0] KrbFastArmoredRep`.
    #[rasn(tag(explicit(0)))]
    ArmoredData(KrbFastArmoredRep),
}

/// `KrbFastResponse`.
#[derive(AsnType, Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub(crate) struct KrbFastResponse {
    /// `padata [0] SEQUENCE OF PA-DATA`.
    #[rasn(tag(explicit(0)))]
    pub padata: SequenceOf<PaData>,
    /// `strengthen-key [1] EncryptionKey OPTIONAL`.
    #[rasn(tag(explicit(1)))]
    pub strengthen_key: Option<EncryptionKey>,
    /// `finished [2] KrbFastFinished OPTIONAL`.
    #[rasn(tag(explicit(2)))]
    pub finished: Option<KrbFastFinished>,
    /// `nonce [3] UInt32`.
    #[rasn(tag(explicit(3)))]
    pub nonce: u32,
}

/// `KrbFastFinished`.
#[derive(AsnType, Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub(crate) struct KrbFastFinished {
    /// `timestamp [0] KerberosTime`.
    #[rasn(tag(explicit(0)))]
    pub timestamp: KerberosTime,
    /// `usec [1] Microseconds`.
    #[rasn(tag(explicit(1)))]
    pub usec: Microseconds,
    /// `crealm [2] Realm`.
    #[rasn(tag(explicit(2)))]
    pub crealm: Realm,
    /// `cname [3] PrincipalName`.
    #[rasn(tag(explicit(3)))]
    pub cname: PrincipalName,
    /// `ticket-checksum [4] Checksum`.
    #[rasn(tag(explicit(4)))]
    pub ticket_checksum: Checksum,
}

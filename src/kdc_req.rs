//! AS-REQ/TGS-REQ decoding and request-body helpers.

use rasn::{der, types::Integer};

use crate::{
    crypto::selection, der::decode_complete, error::Ticket as TicketError,
    ticket::validate as validate_ticket,
};

/// Kerberos protocol version number carried in every message (RFC 4120).
const KRB5_PVNO: i32 = 5;

/// AS-REQ message type.
pub const KRB_AS_REQ_MSG_TYPE: i32 = 10;

/// TGS-REQ message type.
pub const KRB_TGS_REQ_MSG_TYPE: i32 = 12;

/// Decode and validate a DER-encoded KDC request body.
///
/// # Errors
///
/// Returns [`Error::Decode`] when `bytes` is not a DER KDC request body, and
/// [`Error::InvalidMessage`] when an additional ticket has the wrong version.
#[inline]
pub fn decode_kdc_req_body(bytes: &[u8]) -> Result<rasn_kerberos::KdcReqBody, Error> {
    let req_body = decode::<rasn_kerberos::KdcReqBody>("KDC-REQ-BODY", bytes)?;
    validate_kdc_req_body(&req_body)?;
    Ok(req_body)
}

/// Validate nested tickets on an already decoded KDC request body.
///
/// # Errors
///
/// Returns [`Error::InvalidMessage`] when an additional ticket has the wrong
/// version.
#[inline]
pub fn validate_kdc_req_body(req_body: &rasn_kerberos::KdcReqBody) -> Result<(), Error> {
    if let Some(tickets) = &req_body.additional_tickets {
        for ticket in tickets {
            validate_ticket(ticket).map_err(ticket_error)?;
        }
    }
    Ok(())
}

/// Encode a KDC request body as DER.
///
/// # Errors
///
/// Returns [`Error::Encode`] when DER encoding fails, or a policy cause when a
/// requested enctype is permanently prohibited.
#[inline]
pub fn encode_kdc_req_body(req_body: &rasn_kerberos::KdcReqBody) -> Result<Vec<u8>, Error> {
    reject_requested_enctypes(req_body)?;
    encode("KDC-REQ-BODY", req_body)
}

/// Decode and validate a DER-encoded AS-REQ message.
///
/// # Errors
///
/// Returns [`Error::Decode`] when `bytes` is not a DER AS-REQ, and
/// [`Error::InvalidMessage`] when its protocol version, message type or the
/// version of an additional ticket is wrong.
#[inline]
pub fn decode_as_req(bytes: &[u8]) -> Result<rasn_kerberos::AsReq, Error> {
    let as_req = decode::<rasn_kerberos::AsReq>("AS-REQ", bytes)?;
    validate_as_req(&as_req)?;
    Ok(as_req)
}

/// Validate AS-REQ protocol version, message type, and nested request body.
///
/// # Errors
///
/// Returns [`Error::InvalidMessage`] when the protocol version, message type
/// or the version of an additional ticket is wrong.
#[inline]
pub fn validate_as_req(as_req: &rasn_kerberos::AsReq) -> Result<(), Error> {
    validate_kdc_req(&as_req.0, KRB_AS_REQ_MSG_TYPE)
}

/// Encode an AS-REQ message as DER.
///
/// # Errors
///
/// Returns [`Error::Encode`] when DER encoding fails, or a policy cause for a
/// permanently prohibited requested enctype or preauthentication mechanism.
#[inline]
pub fn encode_as_req(as_req: &rasn_kerberos::AsReq) -> Result<Vec<u8>, Error> {
    reject_requested_enctypes(&as_req.0.req_body)?;
    for data in as_req.0.padata.as_deref().unwrap_or_default() {
        selection::preauth(data.r#type)?;
    }
    encode("AS-REQ", as_req)
}

/// Build an AS-REQ message from an already prepared request body and padata.
#[inline]
pub fn build_as_req(
    req_body: rasn_kerberos::KdcReqBody,
    padata: Option<Vec<rasn_kerberos::PaData>>,
) -> rasn_kerberos::AsReq {
    rasn_kerberos::AsReq(rasn_kerberos::KdcReq {
        pvno: Integer::from(KRB5_PVNO),
        msg_type: Integer::from(KRB_AS_REQ_MSG_TYPE),
        padata,
        req_body,
    })
}

/// Encode an AS-REQ message built from an already prepared request body and padata.
///
/// # Errors
///
/// Returns the encoding and permanent-selection errors of [`encode_as_req`].
#[inline]
pub fn encode_build_as_req(
    req_body: rasn_kerberos::KdcReqBody,
    padata: Option<Vec<rasn_kerberos::PaData>>,
) -> Result<Vec<u8>, Error> {
    encode_as_req(&build_as_req(req_body, padata))
}

/// Decode and validate a DER-encoded TGS-REQ message.
///
/// # Errors
///
/// Returns [`Error::Decode`] when `bytes` is not a DER TGS-REQ, and
/// [`Error::InvalidMessage`] when its protocol version, message type or the
/// version of an additional ticket is wrong.
#[inline]
pub fn decode_tgs_req(bytes: &[u8]) -> Result<rasn_kerberos::TgsReq, Error> {
    let tgs_req = decode::<rasn_kerberos::TgsReq>("TGS-REQ", bytes)?;
    validate_tgs_req(&tgs_req)?;
    Ok(tgs_req)
}

/// Validate TGS-REQ protocol version, message type, and nested request body.
///
/// # Errors
///
/// Returns [`Error::InvalidMessage`] when the protocol version, message type
/// or the version of an additional ticket is wrong.
#[inline]
pub fn validate_tgs_req(tgs_req: &rasn_kerberos::TgsReq) -> Result<(), Error> {
    validate_kdc_req(&tgs_req.0, KRB_TGS_REQ_MSG_TYPE)
}

/// Encode a TGS-REQ message as DER.
///
/// # Errors
///
/// Returns [`Error::Encode`] when DER encoding fails, or a policy cause for a
/// permanently prohibited requested enctype or preauthentication mechanism.
#[inline]
pub fn encode_tgs_req(tgs_req: &rasn_kerberos::TgsReq) -> Result<Vec<u8>, Error> {
    reject_requested_enctypes(&tgs_req.0.req_body)?;
    for data in tgs_req.0.padata.as_deref().unwrap_or_default() {
        selection::preauth(data.r#type)?;
    }
    encode("TGS-REQ", tgs_req)
}

/// Build a TGS-REQ message from an already prepared request body and padata.
#[inline]
pub fn build_tgs_req(
    req_body: rasn_kerberos::KdcReqBody,
    padata: Option<Vec<rasn_kerberos::PaData>>,
) -> rasn_kerberos::TgsReq {
    rasn_kerberos::TgsReq(rasn_kerberos::KdcReq {
        pvno: Integer::from(KRB5_PVNO),
        msg_type: Integer::from(KRB_TGS_REQ_MSG_TYPE),
        padata,
        req_body,
    })
}

/// Encode a TGS-REQ message built from an already prepared request body and padata.
///
/// # Errors
///
/// Returns the encoding and permanent-selection errors of [`encode_tgs_req`].
#[inline]
pub fn encode_build_tgs_req(
    req_body: rasn_kerberos::KdcReqBody,
    padata: Option<Vec<rasn_kerberos::PaData>>,
) -> Result<Vec<u8>, Error> {
    encode_tgs_req(&build_tgs_req(req_body, padata))
}

/// Reject permanent numeric selections without imposing runtime legacy permission.
/// # Errors
/// Returns the permanent policy cause for a prohibited requested encryption type.
fn reject_requested_enctypes(body: &rasn_kerberos::KdcReqBody) -> Result<(), Error> {
    for &etype in &body.etype {
        selection::reject_enctype(etype)?;
    }
    Ok(())
}

/// Check a KDC request's protocol version, message type and request body.
///
/// # Errors
///
/// Returns [`Error::InvalidMessage`] when the protocol version, message type
/// or the version of an additional ticket is wrong.
fn validate_kdc_req(kdc_req: &rasn_kerberos::KdcReq, msg_type: i32) -> Result<(), Error> {
    validate_integer("pvno", &kdc_req.pvno, KRB5_PVNO)?;
    validate_integer("msg-type", &kdc_req.msg_type, msg_type)?;
    validate_kdc_req_body(&kdc_req.req_body)
}

/// Decode a DER value with a typed error.
///
/// # Errors
///
/// Returns [`Error::Decode`] naming `target` when `bytes` is not valid DER for
/// `T`.
fn decode<T>(target: &'static str, bytes: &[u8]) -> Result<T, Error>
where
    T: rasn::Decode,
{
    decode_complete(bytes).map_err(|source| Error::Decode {
        target,
        message: source,
    })
}

/// Encode a value to DER with a typed error.
///
/// # Errors
///
/// Returns [`Error::Encode`] naming `target` when the DER encoder fails.
fn encode<T>(target: &'static str, value: &T) -> Result<Vec<u8>, Error>
where
    T: rasn::Encode,
{
    der::encode(value).map_err(|source| Error::Encode {
        target,
        message: source.to_string(),
    })
}

/// Check that a decoded protocol integer such as `pvno` equals `expected`.
///
/// # Errors
///
/// Returns [`Error::InvalidMessage`] naming `field` when the value differs.
fn validate_integer(field: &'static str, actual: &Integer, expected: i32) -> Result<(), Error> {
    if actual != &Integer::from(expected) {
        return Err(Error::InvalidMessage {
            field,
            expected,
            actual: actual.to_string(),
        });
    }
    Ok(())
}

/// Map a Ticket module error to the KDC request error; a key mismatch becomes
/// [`Error::TicketKeyEtypeMismatch`].
fn ticket_error(error: TicketError) -> Error {
    match error {
        TicketError::Decode { target, message } => Error::Decode { target, message },
        TicketError::Encode { target, message } => Error::Encode { target, message },
        TicketError::InvalidMessage {
            field,
            expected,
            actual,
        } => Error::InvalidMessage {
            field,
            expected,
            actual,
        },
        TicketError::UnsupportedEtype(etype) => Error::UnsupportedEtype(etype),
        TicketError::KeyEtypeMismatch {
            key_etype,
            encrypted_data_etype,
        } => Error::TicketKeyEtypeMismatch {
            key_etype,
            encrypted_data_etype,
        },
        TicketError::Random(source) => Error::Random(source),
        TicketError::Crypto(source) => Error::Crypto(source),
    }
}

use crate::error::KdcReq as Error;

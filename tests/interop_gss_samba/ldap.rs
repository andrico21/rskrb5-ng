//! The LDAPv3 messages of a SASL bind and of the Who Am I? operation
//! (RFC 4511, RFC 4532), in the BER subset Samba answers with.

use core::error::Error;
use std::io::Read;

/// The largest LDAP message read, in bytes.
const MAX_MESSAGE: usize = 1 << 20;
/// A universal SEQUENCE, the `LDAPMessage`.
const SEQUENCE: u8 = 0x30;
/// INTEGER.
const INTEGER: u8 = 0x02;
/// ENUMERATED.
const ENUMERATED: u8 = 0x0a;
/// OCTET STRING.
const OCTET_STRING: u8 = 0x04;
/// `BindRequest`, `[APPLICATION 0]` constructed.
const BIND_REQUEST: u8 = 0x60;
/// `BindResponse`, `[APPLICATION 1]` constructed.
const BIND_RESPONSE: u8 = 0x61;
/// `SaslCredentials`, `[3]` constructed.
const SASL: u8 = 0xa3;
/// `serverSaslCreds`, `[7]` primitive.
const SERVER_SASL_CREDS: u8 = 0x87;
/// `ExtendedRequest`, `[APPLICATION 23]` constructed.
const EXTENDED_REQUEST: u8 = 0x77;
/// `ExtendedResponse`, `[APPLICATION 24]` constructed.
const EXTENDED_RESPONSE: u8 = 0x78;
/// `requestName`, `[0]` primitive.
const REQUEST_NAME: u8 = 0x80;
/// `responseValue`, `[11]` primitive.
const RESPONSE_VALUE: u8 = 0x8b;
/// The Who Am I? operation (RFC 4532).
const WHO_AM_I: &[u8] = b"1.3.6.1.4.1.4203.1.11.3";

/// An LDAP result: its code, its diagnostic message and its SASL or extended
/// payload.
#[derive(Debug)]
pub(super) struct Response {
    /// `resultCode`.
    code: u32,
    /// `diagnosticMessage`.
    diagnostic: String,
    /// `serverSaslCreds` or `responseValue`.
    payload: Option<Vec<u8>>,
}

impl Response {
    /// `resultCode`.
    pub(super) const fn code(&self) -> u32 {
        self.code
    }

    /// `diagnosticMessage`.
    pub(super) fn diagnostic(&self) -> &str {
        &self.diagnostic
    }

    /// `serverSaslCreds` of a bind or `responseValue` of an extended operation.
    pub(super) fn payload(&self) -> Option<&[u8]> {
        self.payload.as_deref()
    }
}

/// The BER element `tag` holding `contents`.
fn element(tag: u8, contents: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut encoded = vec![tag];
    match u8::try_from(contents.len()) {
        Ok(short) if short < 0x80 => encoded.push(short),
        _ => {
            let bytes = u32::try_from(contents.len())?.to_be_bytes();
            let zeros = bytes.iter().take_while(|byte| **byte == 0).count();
            let significant = bytes.get(zeros..).ok_or("length bytes")?;
            encoded.push(0x80 | u8::try_from(significant.len())?);
            encoded.extend_from_slice(significant);
        }
    }
    encoded.extend_from_slice(contents);
    Ok(encoded)
}

/// A BER element: its tag, its contents and the bytes that follow it.
type Element<'input> = (u8, &'input [u8], &'input [u8]);

/// The first BER element of `input`.
fn split(input: &[u8]) -> Result<Element<'_>, Box<dyn Error>> {
    let (&tag, after_tag) = input.split_first().ok_or("truncated element")?;
    let (&first, after_first) = after_tag.split_first().ok_or("truncated length")?;
    let (length, after_length) = if first < 0x80 {
        (usize::from(first), after_first)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 {
            return Err("unsupported BER length".into());
        }
        let (bytes, rest) = after_first
            .split_at_checked(count)
            .ok_or("truncated long length")?;
        (big_endian(bytes)?, rest)
    };
    let (contents, rest) = after_length
        .split_at_checked(length)
        .ok_or("truncated contents")?;
    Ok((tag, contents, rest))
}

/// The unsigned big-endian number `bytes`.
fn big_endian(bytes: &[u8]) -> Result<usize, Box<dyn Error>> {
    Ok(bytes
        .iter()
        .try_fold(0_usize, |sum, byte| {
            sum.checked_mul(256)?.checked_add(usize::from(*byte))
        })
        .ok_or("number overflow")?)
}

/// An `LDAPMessage` numbered `id` (below 128) carrying `operation`.
fn message(id: u8, operation: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    element(
        SEQUENCE,
        &[element(INTEGER, &[id])?, operation.to_vec()].concat(),
    )
}

/// A GSSAPI SASL `BindRequest` numbered `id` carrying `credentials`.
pub(super) fn bind_request(id: u8, credentials: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let sasl = element(
        SASL,
        &[
            element(OCTET_STRING, b"GSSAPI")?,
            element(OCTET_STRING, credentials)?,
        ]
        .concat(),
    )?;
    let bind = element(
        BIND_REQUEST,
        &[element(INTEGER, &[3])?, element(OCTET_STRING, b"")?, sasl].concat(),
    )?;
    message(id, &bind)
}

/// A Who Am I? `ExtendedRequest` numbered `id`.
pub(super) fn whoami_request(id: u8) -> Result<Vec<u8>, Box<dyn Error>> {
    message(
        id,
        &element(EXTENDED_REQUEST, &element(REQUEST_NAME, WHO_AM_I)?)?,
    )
}

/// The next `LDAPMessage` of `stream`, which must answer `id` with `operation`.
fn read_response<Stream>(
    stream: &mut Stream,
    id: u8,
    operation: u8,
) -> Result<Response, Box<dyn Error>>
where
    Stream: Read,
{
    let mut header = [0; 2];
    stream.read_exact(&mut header)?;
    let [tag, first] = header;
    if tag != SEQUENCE {
        return Err(format!("an LDAPMessage starts with {tag:#04x}").into());
    }
    let length = if first < 0x80 {
        usize::from(first)
    } else {
        let mut bytes = vec![0; usize::from(first & 0x7f)];
        if bytes.is_empty() || bytes.len() > 4 {
            return Err("unsupported LDAPMessage length".into());
        }
        stream.read_exact(&mut bytes)?;
        big_endian(&bytes)?
    };
    if length > MAX_MESSAGE {
        return Err(format!("an LDAPMessage of {length} bytes").into());
    }
    let mut contents = vec![0; length];
    stream.read_exact(&mut contents)?;
    let (id_tag, id_bytes, after_id) = split(&contents)?;
    if id_tag != INTEGER || id_bytes != [id] {
        return Err(format!("the answer to message {id} has the id {id_bytes:02x?}").into());
    }
    let (operation_tag, body, _controls) = split(after_id)?;
    if operation_tag != operation {
        return Err(format!("message {id} answered by operation {operation_tag:#04x}").into());
    }
    let (code_tag, code_bytes, after_code) = split(body)?;
    if code_tag != ENUMERATED {
        return Err("a result without its resultCode".into());
    }
    let (_, _matched, after_matched) = split(after_code)?;
    let (_, diagnostic, mut rest) = split(after_matched)?;
    let mut payload = None;
    while !rest.is_empty() {
        let (field, value, next) = split(rest)?;
        if field == SERVER_SASL_CREDS || field == RESPONSE_VALUE {
            payload = Some(value.to_vec());
        }
        rest = next;
    }
    Ok(Response {
        code: u32::try_from(big_endian(code_bytes)?)?,
        diagnostic: String::from_utf8_lossy(diagnostic).into_owned(),
        payload,
    })
}

/// The `BindResponse` to message `id`.
pub(super) fn read_bind_response<Stream>(
    stream: &mut Stream,
    id: u8,
) -> Result<Response, Box<dyn Error>>
where
    Stream: Read,
{
    read_response(stream, id, BIND_RESPONSE)
}

/// The `ExtendedResponse` to message `id`.
pub(super) fn read_extended_response<Stream>(
    stream: &mut Stream,
    id: u8,
) -> Result<Response, Box<dyn Error>>
where
    Stream: Read,
{
    read_response(stream, id, EXTENDED_RESPONSE)
}

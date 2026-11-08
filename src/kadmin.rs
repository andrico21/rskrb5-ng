//! RFC 3244 password-change protocol helpers.

use rasn::{AsnType, Decode, Decoder as _, Encode, Encoder as _, types::Integer};

use crate::{
    ap_req, crypto::selection, keytab::EncryptionKey, krb_priv, krb_priv::EncKrbPrivPartOptions,
    messages,
};

/// Wire codecs and protocol error conversion.
mod codec;
pub mod password;
/// Password payload ownership and encoding.
mod payload;
/// Reply parsing and result handling.
mod reply;
/// Request frame and option implementations.
mod request;
/// Result code interpretation.
mod result;
/// Password-specific zeroizing DER writer.
mod secret_der;

use codec::{
    ap_req_error, encryption_key_to_rasn, kerberos_string, krb_priv_error, random_key_material,
};

/// Password-change request protocol version (`0xff80`).
pub const CHANGE_PASSWORD_REQUEST_VERSION: u16 = 0xff80;
/// Password-change reply protocol version.
pub const CHANGE_PASSWORD_REPLY_VERSION: u16 = 1;
/// Password change succeeded.
pub const KPASSWD_SUCCESS: u16 = 0;
/// Request was malformed.
pub const KPASSWD_MALFORMED: u16 = 1;
/// Server hard error.
pub const KPASSWD_HARDERROR: u16 = 2;
/// Authentication error.
pub const KPASSWD_AUTHERROR: u16 = 3;
/// Server soft error.
pub const KPASSWD_SOFTERROR: u16 = 4;
/// Access denied.
pub const KPASSWD_ACCESSDENIED: u16 = 5;
/// Bad protocol version.
pub const KPASSWD_BAD_VERSION: u16 = 6;
/// Initial ticket flag is required.
pub const KPASSWD_INITIAL_FLAG_NEEDED: u16 = 7;
/// The length of the kpasswd frame header: message length, protocol version
/// and AP-REQ/AP-REP length, two big-endian bytes each.
const HEADER_LEN: usize = 6;

/// Payload encrypted inside a Kerberos password-change request.
#[derive(AsnType, Clone, Decode, Encode, Eq, PartialEq)]
#[non_exhaustive]
pub struct ChangePasswdData {
    /// New password bytes.
    #[rasn(tag(explicit(0)))]
    pub new_passwd: password::Bytes,
    /// Optional target principal name.
    #[rasn(tag(explicit(1)))]
    pub targ_name: Option<rasn_kerberos::PrincipalName>,
    /// Optional target realm.
    #[rasn(tag(explicit(2)))]
    pub targ_realm: Option<rasn_kerberos::Realm>,
}

/// Build an unencrypted KRB-PRIV part around application data.
#[inline]
pub fn build_enc_krb_priv_part<P>(
    user_data: P,
    options: EncKrbPrivPartOptions,
) -> rasn_kerberos::EncKrbPrivPart
where
    P: AsRef<[u8]>,
{
    krb_priv::build_enc_krb_priv_part(user_data, options)
}

/// Build a KRB-PRIV message using a caller-supplied confounder.
///
/// # Errors
///
/// Returns [`Error::UnsupportedEtype`] for a key whose enctype is not
/// implemented, and [`Error::Encode`] or [`Error::Crypto`] when encoding or
/// encrypting the part fails.
#[inline]
pub fn build_krb_priv_with_confounder<P>(
    user_data: P,
    options: EncKrbPrivPartOptions,
    key: &EncryptionKey,
    confounder: &[u8],
) -> Result<rasn_kerberos::KrbPriv, Error>
where
    P: AsRef<[u8]>,
{
    krb_priv::build_krb_priv_with_confounder(user_data, options, key, None, confounder)
        .map_err(krb_priv_error)
}

/// Build a KRB-PRIV message using a random confounder.
///
/// # Errors
///
/// Returns [`Error::UnsupportedEtype`] for a key whose enctype is not
/// implemented, and [`Error::Encode`] or [`Error::Crypto`] when generating the
/// confounder, encoding or encrypting the part fails.
#[inline]
pub fn build_krb_priv<P>(
    user_data: P,
    options: EncKrbPrivPartOptions,
    key: &EncryptionKey,
) -> Result<rasn_kerberos::KrbPriv, Error>
where
    P: AsRef<[u8]>,
{
    krb_priv::build(user_data, options, key, None).map_err(krb_priv_error)
}

/// Decode and validate a DER-encoded KRB-PRIV message.
///
/// # Errors
///
/// Returns [`Error::Decode`] when `bytes` is not a DER KRB-PRIV, and
/// [`Error::InvalidKerberosMessage`] when its protocol version or message type
/// is wrong.
#[inline]
pub fn decode_krb_priv(bytes: &[u8]) -> Result<rasn_kerberos::KrbPriv, Error> {
    krb_priv::decode(bytes).map_err(krb_priv_error)
}

/// Encode a KRB-PRIV message as DER.
///
/// # Errors
///
/// Returns [`Error::Encode`] when the DER encoder fails.
#[inline]
pub fn encode_krb_priv(krb_priv: &rasn_kerberos::KrbPriv) -> Result<Vec<u8>, Error> {
    krb_priv::encode(krb_priv).map_err(krb_priv_error)
}

/// Decode a DER-encoded `EncKrbPrivPart`.
///
/// # Errors
///
/// Returns [`Error::Decode`] when `bytes` is not a DER `EncKrbPrivPart`.
#[inline]
pub fn decode_enc_krb_priv_part(bytes: &[u8]) -> Result<rasn_kerberos::EncKrbPrivPart, Error> {
    krb_priv::decode_enc_krb_priv_part(bytes).map_err(krb_priv_error)
}

/// Decrypt and decode a KRB-PRIV encrypted part.
///
/// # Errors
///
/// Returns [`Error::KeyEtypeMismatch`] when the key's enctype differs from
/// the encrypted part's, [`Error::UnsupportedEtype`] for an enctype that is not
/// implemented, [`Error::Crypto`] when decryption fails, and [`Error::Decode`]
/// when the plaintext is not a DER `EncKrbPrivPart`.
#[inline]
pub fn decrypt_krb_priv_enc_part(
    krb_priv: &rasn_kerberos::KrbPriv,
    key: &EncryptionKey,
) -> Result<rasn_kerberos::EncKrbPrivPart, Error> {
    krb_priv::decrypt_krb_priv_enc_part(krb_priv, key).map_err(krb_priv_error)
}

/// Complete password-change request assembled for transport.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct BuiltChangePasswordRequest {
    /// Framed request message.
    pub request: Request,
    /// DER-encoded kpasswd request frame.
    pub der: Vec<u8>,
    /// Reply key used for the request subkey and KRB-PRIV encryption.
    pub reply_key: EncryptionKey,
}

/// Options for constructing a full kpasswd request message.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ChangePasswdMessageOptions {
    /// Authenticator and KRB-PRIV timestamp.
    pub timestamp: rasn_kerberos::KerberosTime,
    /// Authenticator and KRB-PRIV microseconds.
    pub cusec: u32,
    /// Authenticator and KRB-PRIV sequence number.
    pub sequence_number: u32,
    /// Sender address used in KRB-PRIV encrypted part.
    pub sender_address: rasn_kerberos::HostAddress,
    /// Optional recipient address used in KRB-PRIV encrypted part.
    pub recipient_address: Option<rasn_kerberos::HostAddress>,
}

/// Password-change request frame containing AP-REQ and KRB-PRIV messages.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Request {
    /// AP-REQ authenticating the password-change request.
    pub ap_req: rasn_kerberos::ApReq,
    /// KRB-PRIV carrying encrypted `ChangePasswdData`.
    pub krb_priv: rasn_kerberos::KrbPriv,
}

/// Build a complete kpasswd request frame using a caller-supplied AP-REQ,
/// reply key, request payload, and KRB-PRIV confounder.
///
/// # Errors
///
/// Returns the [`ChangePasswdData::encode_der`] and
/// [`build_krb_priv_with_confounder`] errors, and the [`Request::encode`]
/// errors for the frame.
#[inline]
pub fn build_change_password_request_with_confounder(
    ap_req: rasn_kerberos::ApReq,
    change_data: &ChangePasswdData,
    reply_key: EncryptionKey,
    options: EncKrbPrivPartOptions,
    confounder: &[u8],
) -> Result<BuiltChangePasswordRequest, Error> {
    if let Some(time) = &options.timestamp {
        messages::whole_seconds(time).map_err(|source| Error::Encode {
            target: "kpasswd KRB-PRIV time",
            message: source.to_string(),
        })?;
    }
    if let Some(usec) = &options.usec {
        let _micros =
            messages::microseconds("krb-priv.usec", usec).map_err(|source| Error::Encode {
                target: "kpasswd KRB-PRIV time",
                message: source.to_string(),
            })?;
    }
    let plaintext = secret_der::private_part(&secret_der::change_data(change_data)?, options)?;
    let krb_priv = payload::encrypt(&plaintext, &reply_key, confounder)?;
    build_change_password_request_from_parts(ap_req, krb_priv, reply_key)
}

/// Build a full kpasswd request message using a service ticket, explicit context,
/// and explicit confounders for AP-REQ and KRB-PRIV encryption.
///
/// # Errors
///
/// Returns [`Error::InvalidKerberosString`] for a client realm that is not a
/// valid Kerberos string, the AP-REQ build errors mapped onto [`Error`], and
/// the [`build_change_password_request_with_confounder`] errors.
#[inline]
pub fn build_change_password_message_with_confounders(
    client_principal: rasn_kerberos::PrincipalName,
    client_realm: &str,
    change_data: &ChangePasswdData,
    service_ticket: rasn_kerberos::Ticket,
    session_key: &EncryptionKey,
    options: ChangePasswdMessageOptions,
    encryption: PasswordEncryption<'_>,
) -> Result<BuiltChangePasswordRequest, Error> {
    messages::microseconds("cusec", &Integer::from(options.cusec))
        .and_then(|_value| messages::whole_seconds(&options.timestamp))
        .map_err(|source| Error::Encode {
            target: "kpasswd request time",
            message: source.to_string(),
        })?;
    let PasswordEncryption {
        reply_key,
        ap_req_confounder,
        krb_priv_confounder,
    } = encryption;
    let mut krb_priv_options = EncKrbPrivPartOptions::new(options.sender_address.clone())
        .with_timestamp(options.timestamp.clone(), options.cusec)
        .with_sequence_number(options.sequence_number);
    if let Some(recipient_address) = options.recipient_address {
        krb_priv_options = krb_priv_options.with_recipient_address(recipient_address);
    }

    let authenticator = rasn_kerberos::Authenticator {
        authenticator_vno: Integer::from(5_i32),
        crealm: kerberos_string(client_realm)?,
        cname: client_principal,
        cksum: None,
        cusec: Integer::from(options.cusec),
        ctime: options.timestamp,
        subkey: Some(encryption_key_to_rasn(&reply_key)),
        seq_number: Some(options.sequence_number),
        authorization_data: None,
    };
    let authenticator_usage = ap_req::authenticator_usage_for_ticket(&service_ticket);
    let ap_req_kvno = service_ticket.enc_part.kvno;
    let ap_req = ap_req::build_ap_req_with_confounder(
        service_ticket,
        ap_req::ap_options_from_bits(0),
        &authenticator,
        session_key,
        authenticator_usage,
        ap_req_kvno,
        ap_req_confounder,
    )
    .map_err(ap_req_error)?;

    build_change_password_request_with_confounder(
        ap_req,
        change_data,
        reply_key,
        krb_priv_options,
        krb_priv_confounder,
    )
}

/// Reply key and independent encryption confounders for a password-change message.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct PasswordEncryption<'request> {
    /// The key used to protect the password-change reply.
    pub reply_key: EncryptionKey,
    /// The AP-REQ authenticator confounder.
    pub ap_req_confounder: &'request [u8],
    /// The KRB-PRIV payload confounder.
    pub krb_priv_confounder: &'request [u8],
}

/// Build a full kpasswd request message using generated subkey and confounders.
///
/// # Errors
///
/// Returns [`Error::UnsupportedEtype`] for a session key whose enctype is not
/// implemented, [`Error::Crypto`] when the random subkey or confounders cannot
/// be generated, and the
/// [`build_change_password_message_with_confounders`] errors.
#[inline]
pub fn build_change_password_message(
    client_principal: rasn_kerberos::PrincipalName,
    client_realm: &str,
    change_data: &ChangePasswdData,
    service_ticket: rasn_kerberos::Ticket,
    session_key: &EncryptionKey,
    options: ChangePasswdMessageOptions,
) -> Result<BuiltChangePasswordRequest, Error> {
    let etype =
        selection::enctype(session_key.etype)?.ok_or(Error::UnsupportedEtype(session_key.etype))?;
    let reply_key = EncryptionKey {
        etype: session_key.etype,
        value: random_key_material(etype.key_len())?.into_vec().into(),
    };
    let ap_req_confounder = random_key_material(etype.confounder_len())?;
    let krb_priv_confounder = random_key_material(etype.confounder_len())?;

    build_change_password_message_with_confounders(
        client_principal,
        client_realm,
        change_data,
        service_ticket,
        session_key,
        options,
        PasswordEncryption::new(reply_key, &ap_req_confounder, &krb_priv_confounder),
    )
}

/// Frame an AP-REQ and a KRB-PRIV into a request, keeping the reply key.
///
/// # Errors
///
/// Returns the [`Request::encode`] errors.
fn build_change_password_request_from_parts(
    ap_req: rasn_kerberos::ApReq,
    krb_priv: rasn_kerberos::KrbPriv,
    reply_key: EncryptionKey,
) -> Result<BuiltChangePasswordRequest, Error> {
    let request = Request { ap_req, krb_priv };
    let der = request.encode()?;

    Ok(BuiltChangePasswordRequest {
        request,
        der,
        reply_key,
    })
}

/// Build a complete kpasswd request frame using a caller-supplied AP-REQ,
/// reply key, request payload, and random KRB-PRIV confounder.
///
/// # Errors
///
/// Returns the [`ChangePasswdData::encode_der`] and [`build_krb_priv`]
/// errors, and the [`Request::encode`] errors for the frame.
#[inline]
pub fn build_change_password_request(
    ap_req: rasn_kerberos::ApReq,
    change_data: &ChangePasswdData,
    reply_key: EncryptionKey,
    options: EncKrbPrivPartOptions,
) -> Result<BuiltChangePasswordRequest, Error> {
    let etype =
        selection::enctype(reply_key.etype)?.ok_or(Error::UnsupportedEtype(reply_key.etype))?;
    let confounder = random_key_material(etype.confounder_len())?;
    build_change_password_request_with_confounder(
        ap_req,
        change_data,
        reply_key,
        options,
        &confounder,
    )
}

/// Parsed RFC 3244-style password-change reply frame.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Reply {
    /// Total wire length; bare RFC 3244 errors have no length prefix.
    pub message_length: u16,
    /// Framed version, or [`CHANGE_PASSWORD_REQUEST_VERSION`] for a bare RFC 3244 error.
    pub version: u16,
    /// DER byte length of the AP-REP section, or zero for a KRB-ERROR reply.
    pub ap_rep_length: u16,
    /// Parsed AP-REP section for successful protocol replies.
    pub ap_rep: Option<rasn_kerberos::ApRep>,
    /// Parsed KRB-PRIV section for successful protocol replies.
    pub krb_priv: Option<rasn_kerberos::KrbPriv>,
    /// Parsed KRB-ERROR section for error replies.
    pub krb_error: Option<rasn_kerberos::KrbError>,
    /// Parsed password-change result from KRB-ERROR `e-data`.
    pub result: Option<ChangePasswordResult>,
}

/// Cleartext password-change response code and text.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ChangePasswordResult {
    /// Result code from the first two bytes.
    pub code: u16,
    /// Result text from the remaining bytes.
    pub text: String,
    /// Result text as received, before lossy UTF-8 conversion.
    pub text_raw: Vec<u8>,
}

use crate::error::Kadmin as Error;

/// A kpasswd frame split into its header fields and body.
struct Frame<'bytes> {
    /// The total frame length the header declares.
    message_length: u16,
    /// The protocol version.
    version: u16,
    /// The AP-REQ or AP-REP length; zero for a KRB-ERROR reply.
    payload_length: u16,
    /// The bytes after the header, up to the declared frame length.
    body: &'bytes [u8],
}

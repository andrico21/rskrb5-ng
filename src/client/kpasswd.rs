//! Client-side kpasswd request building and AP-REP verification helpers.

use core::time::Duration;
use std::time::SystemTime;

use super::{
    BuiltApReq, Error, TgsRepSession, ap_rep_error, encryption_key_from_rasn, integer_to_u32,
    system_time_from_kerberos_time,
};
use crate::{
    ap_rep::{decrypt_ap_rep_enc_part, validate as validate_ap_rep},
    crypto::{CryptoPolicy, Use, selection},
    kadmin,
    keytab::EncryptionKey,
    messages,
};

/// Request authenticator construction and KRB-PRIV options.
mod request;
use request::{build_kpasswd_ap_req_with_confounder, kpasswd_krb_priv_options};

#[cfg(feature = "tokio")]
use crate::error::Kadmin;

/// Reflected password ciphertext regressions.
#[cfg(test)]
#[cfg(feature = "tokio")]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod reflection_tests;

/// Unsigned rejection classification regressions.
#[cfg(test)]
#[cfg(feature = "tokio")]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod rejection_tests;

/// Options for constructing a kpasswd request from a service ticket.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct RequestOptions {
    /// Explicit runtime permission; absent means secure defaults.
    pub crypto_policy: Option<CryptoPolicy>,
    /// Authenticator and KRB-PRIV timestamp.
    pub timestamp: SystemTime,
    /// Authenticator and KRB-PRIV microseconds.
    pub cusec: u32,
    /// Authenticator and KRB-PRIV sequence number.
    pub sequence_number: u32,
    /// Sender address used in the KRB-PRIV encrypted part.
    pub sender_address: rasn_kerberos::HostAddress,
    /// Optional recipient address used in the KRB-PRIV encrypted part.
    pub recipient_address: Option<rasn_kerberos::HostAddress>,
}

impl RequestOptions {
    /// Construct options with the required timestamp, sequence number, and sender address.
    #[inline]
    pub const fn new(
        timestamp: SystemTime,
        cusec: u32,
        sequence_number: u32,
        sender_address: rasn_kerberos::HostAddress,
    ) -> Self {
        Self {
            crypto_policy: None,
            timestamp,
            cusec,
            sequence_number,
            sender_address,
            recipient_address: None,
        }
    }

    #[must_use]
    /// Set the optional recipient address.
    #[inline]
    pub fn with_recipient_address(mut self, recipient_address: rasn_kerberos::HostAddress) -> Self {
        self.recipient_address = Some(recipient_address);
        self
    }
}

/// Built kpasswd request plus the key needed to decrypt the reply.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct BuiltKpasswdRequest {
    /// Policy bound to this request for checked exchanges without configuration.
    pub crypto_policy: CryptoPolicy,
    /// Parsed kpasswd request.
    pub request: kadmin::Request,
    /// Encoded kpasswd request frame.
    pub der: Vec<u8>,
    /// Authenticator subkey used to encrypt request KRB-PRIV payloads and reply KRB-PRIV payloads
    /// when the AP-REP does not select a server subkey.
    pub reply_key: EncryptionKey,
    /// Built AP-REQ metadata.
    pub ap_req: BuiltApReq,
}

/// Verified kpasswd AP-REP reply metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct VerifiedKpasswdApRep {
    /// Reply `ctime` without `cusec`.
    pub ctime: SystemTime,
    /// Reply microsecond field.
    pub cusec: u32,
    /// Reply timestamp including `cusec`.
    pub authenticator_time: SystemTime,
    /// Optional server-selected subkey.
    pub subkey: Option<EncryptionKey>,
    /// Optional server sequence number.
    pub sequence_number: Option<u32>,
}

/// Build a complete kpasswd request with explicit confounders.
///
/// # Errors
///
/// Returns an error when the AP-REQ cannot be built from the service ticket
/// (for example an unsupported session-key encryption type or a confounder of
/// the wrong length), when the request timestamp is outside the Kerberos time
/// range, or when the KRB-PRIV change-password payload cannot be encrypted or
/// encoded.
#[inline]
pub fn build_kpasswd_request_with_confounders(
    service_ticket: &TgsRepSession,
    change_data: &kadmin::ChangePasswdData,
    reply_key: EncryptionKey,
    options: &RequestOptions,
    ap_req_confounder: &[u8],
    krb_priv_confounder: &[u8],
) -> Result<BuiltKpasswdRequest, Error> {
    let ap_req = build_kpasswd_ap_req_with_confounder(
        service_ticket,
        &reply_key,
        options,
        ap_req_confounder,
    )?;
    let krb_priv_options = kpasswd_krb_priv_options(options)?;
    let built_request = kadmin::build_change_password_request_with_confounder(
        ap_req.message.clone(),
        change_data,
        reply_key,
        krb_priv_options,
        krb_priv_confounder,
    )?;

    Ok(BuiltKpasswdRequest {
        crypto_policy: options.crypto_policy.clone().unwrap_or_default(),
        request: built_request.request,
        der: built_request.der,
        reply_key: built_request.reply_key,
        ap_req,
    })
}

/// Build a complete kpasswd request with generated reply key and confounders.
///
/// # Errors
///
/// Returns [`Error::UnsupportedEtype`] when the service-ticket session key uses
/// an unsupported encryption type, an error when the operating system random
/// source fails, and the errors of [`build_kpasswd_request_with_confounders`]
/// for building, encrypting or encoding the request.
#[inline]
pub fn build_kpasswd_request(
    service_ticket: &TgsRepSession,
    change_data: &kadmin::ChangePasswdData,
    options: &RequestOptions,
) -> Result<BuiltKpasswdRequest, Error> {
    let etype = selection::enctype(service_ticket.session_key.etype)?
        .ok_or(Error::UnsupportedEtype(service_ticket.session_key.etype))?;
    let mut reply_key = EncryptionKey {
        etype: service_ticket.session_key.etype,
        value: vec![0; etype.key_len()],
    };
    getrandom::fill(&mut reply_key.value)?;
    let mut ap_req_confounder = vec![0; etype.confounder_len()];
    getrandom::fill(&mut ap_req_confounder)?;

    let ap_req = build_kpasswd_ap_req_with_confounder(
        service_ticket,
        &reply_key,
        options,
        &ap_req_confounder,
    )?;
    let krb_priv_options = kpasswd_krb_priv_options(options)?;
    let built_request = kadmin::build_change_password_request(
        ap_req.message.clone(),
        change_data,
        reply_key,
        krb_priv_options,
    )?;

    Ok(BuiltKpasswdRequest {
        crypto_policy: options.crypto_policy.clone().unwrap_or_default(),
        request: built_request.request,
        der: built_request.der,
        reply_key: built_request.reply_key,
        ap_req,
    })
}

/// Verify the AP-REP section of a successful kpasswd reply.
///
/// KRB-ERROR replies do not carry AP-REP and return `Ok(None)`. Successful
/// replies must echo the AP-REQ authenticator timestamp and are encrypted with
/// the kpasswd service-ticket session key.
///
/// # Errors
///
/// Returns [`Error::MissingKpasswdApRep`] when a non-error reply carries no
/// AP-REP, an AP-REP validation or decryption error, a time conversion error
/// (including [`Error::TimeOverflow`]) when the reply timestamp is out of
/// range, and [`Error::KpasswdApRepTimestampMismatch`] when the reply does not
/// echo the request authenticator timestamp.
#[inline]
pub fn verify_kpasswd_ap_rep(
    reply: &kadmin::Reply,
    request: &BuiltKpasswdRequest,
) -> Result<Option<VerifiedKpasswdApRep>, Error> {
    if reply.is_krb_error() {
        return Ok(None);
    }

    let ap_rep = reply.ap_rep.as_ref().ok_or(Error::MissingKpasswdApRep)?;
    validate_ap_rep(ap_rep).map_err(ap_rep_error)?;
    let enc_part =
        decrypt_ap_rep_enc_part(ap_rep, &request.ap_req.session_key).map_err(ap_rep_error)?;
    messages::whole_seconds(&enc_part.ctime)
        .and_then(|()| messages::microseconds("ap-rep.cusec", &enc_part.cusec).map(|_value| ()))
        .map_err(|_invalid| Error::KpasswdReplyControl("AP-REP time range"))?;
    let ctime = system_time_from_kerberos_time(&enc_part.ctime)?;
    let cusec = integer_to_u32("ap-rep.cusec", &enc_part.cusec)?;
    let authenticator_time = ctime
        .checked_add(Duration::from_micros(cusec.into()))
        .ok_or(Error::TimeOverflow)?;

    if ctime != request.ap_req.authenticator_ctime || cusec != request.ap_req.authenticator_cusec {
        return Err(Error::KpasswdApRepTimestampMismatch {
            expected: request.ap_req.authenticator_time,
            actual: authenticator_time,
        });
    }

    Ok(Some(VerifiedKpasswdApRep {
        ctime,
        cusec,
        authenticator_time,
        subkey: enc_part.subkey.as_ref().map(encryption_key_from_rasn),
        sequence_number: enc_part.seq_number,
    }))
}

/// Consume the result only after validating the authenticated response controls.
///
/// # Errors
///
/// Returns protocol/decryption errors or [`Error::KpasswdReplyControl`] for an
/// invalid sequence, time pair or address. A configured request recipient pins
/// the response sender; otherwise only IPv4/IPv6 address shape is enforced.
#[cfg(feature = "tokio")]
pub(super) fn validated_result(
    reply: &kadmin::Reply,
    request: &BuiltKpasswdRequest,
    options: &RequestOptions,
    policy: &CryptoPolicy,
) -> Result<kadmin::ChangePasswordResult, Error> {
    policy.check_use(request.ap_req.session_key.etype, Use::SessionKey)?;
    if let Some(ap_rep) = &reply.ap_rep {
        policy.check_use(ap_rep.enc_part.etype, Use::SessionKey)?;
    }
    if reply
        .krb_priv
        .as_ref()
        .is_some_and(|part| part.enc_part.cipher == request.request.krb_priv.enc_part.cipher)
    {
        return Err(Error::KpasswdReplyControl("reflected ciphertext"));
    }
    let Some(verified) = verify_kpasswd_ap_rep(reply, request)? else {
        let result = reply.decrypt_result(&request.reply_key)?;
        return Err(Kadmin::UnauthenticatedRejection {
            code: result.code,
            text_raw: result.text_raw,
        }
        .into());
    };
    let key = verified.subkey.as_ref().unwrap_or(&request.reply_key);
    policy.check_use(key.etype, Use::SessionKey)?;
    if let Some(private) = &reply.krb_priv {
        policy.check_use(private.enc_part.etype, Use::SessionKey)?;
    }
    let part = kadmin::decrypt_krb_priv_enc_part(
        reply
            .krb_priv
            .as_ref()
            .ok_or(Error::KpasswdReplyControl("missing KRB-PRIV"))?,
        key,
    )?;
    if let Some(expected) = verified.sequence_number
        && part.seq_number != Some(expected)
    {
        return Err(Error::KpasswdReplyControl("sequence"));
    }
    match (&part.timestamp, &part.usec) {
        (Some(time), Some(usec)) => {
            let micros = integer_to_u32("krb-priv.usec", usec)?;
            if micros > 999_999 || time.0.timestamp_subsec_nanos() != 0 {
                return Err(Error::KpasswdReplyControl("time range"));
            }
            let actual = system_time_from_kerberos_time(time)?
                .checked_add(Duration::from_micros(u64::from(micros)))
                .ok_or(Error::TimeOverflow)?;
            let expected = options
                .timestamp
                .checked_add(Duration::from_micros(u64::from(options.cusec)))
                .ok_or(Error::TimeOverflow)?;
            let skew = actual
                .duration_since(expected)
                .unwrap_or_else(|error| error.duration());
            if skew > Duration::from_secs(300) {
                return Err(Error::KpasswdReplyControl("stale timestamp"));
            }
        }
        (None, None) if verified.sequence_number.is_some() => {}
        (Some(_) | None, None) | (None, Some(_)) => {
            return Err(Error::KpasswdReplyControl("missing freshness"));
        }
    }
    let address = &part.sender_address;
    if !matches!(
        (address.addr_type, address.address.len()),
        (2_i32, 4) | (24_i32, 16)
    ) || options
        .recipient_address
        .as_ref()
        .is_some_and(|expected| expected != address)
        || part
            .recipient_address
            .as_ref()
            .is_some_and(|actual| actual != &options.sender_address)
    {
        return Err(Error::KpasswdReplyControl("address"));
    }
    kadmin::ChangePasswordResult::parse(part.user_data.as_ref()).map_err(Error::from)
}

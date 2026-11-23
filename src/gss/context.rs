//! Per-message tokens of an established context.
//!
//! Per-message tokens of an established context (RFC 4121 section 4.2; MIT
//! `k5sealv3.c`, `k5unsealiov.c`).

use std::time::SystemTime;

use zeroize::Zeroizing;

use super::{
    ContextInquiry, EncryptionKey, Error, EstablishedContext, ObjectIdentifier, Unwrapped,
};
use crate::{
    crypto::{KerberosEtype, Use},
    spnego::{
        GSS_TOKEN_FLAG_ACCEPTOR_SUBKEY, GSS_TOKEN_FLAG_SEALED, GSS_TOKEN_FLAG_SENT_BY_ACCEPTOR,
        GSSAPI_ACCEPTOR_SEAL_USAGE, GSSAPI_ACCEPTOR_SIGN_USAGE, GSSAPI_INITIATOR_SEAL_USAGE,
        GSSAPI_INITIATOR_SIGN_USAGE, MicToken, WrapToken,
    },
};

/// The longest per-message token, in bytes.
pub(super) const MAX_TOKEN_LEN: usize = 0x100_0000;

/// The context key: the acceptor subkey, else the initiator subkey, else the
/// session key (RFC 4121 section 2).
pub(super) fn key(context: &EstablishedContext) -> &EncryptionKey {
    context
        .acceptor_subkey
        .as_ref()
        .or(context.initiator_subkey.as_ref())
        .unwrap_or(&context.session_key)
}

/// `gss_inquire_context`.
pub(super) fn inquire(context: &EstablishedContext) -> ContextInquiry {
    ContextInquiry {
        source: context.source.clone(),
        target: context.target.clone(),
        expires: context.expires,
        mechanism: ObjectIdentifier::krb5(),
        flags: context.flags,
        locally_initiated: context.initiated,
        open: context.open,
        key_etype: key(context).etype(),
        ssf: match key(context).etype() {
            18 | 20 | 26 => 256,
            17 | 19 | 25 => 128,
            16 => 112,
            23 | 24 => 64,
            _ => 0,
        },
    }
}

/// The token flags this end sends.
pub(super) const fn sent_flags(context: &EstablishedContext) -> u8 {
    let mut flags = 0;
    if !context.initiated {
        flags |= GSS_TOKEN_FLAG_SENT_BY_ACCEPTOR;
    }
    if context.acceptor_subkey.is_some() {
        flags |= GSS_TOKEN_FLAG_ACCEPTOR_SUBKEY;
    }
    flags
}

/// The key usages of this end's tokens: (sign, seal).
pub(super) const fn usages(sending_initiator: bool) -> (u32, u32) {
    if sending_initiator {
        (GSSAPI_INITIATOR_SIGN_USAGE, GSSAPI_INITIATOR_SEAL_USAGE)
    } else {
        (GSSAPI_ACCEPTOR_SIGN_USAGE, GSSAPI_ACCEPTOR_SEAL_USAGE)
    }
}

/// Refuse a context that is not established yet: a DCE-style acceptor before
/// the initiator's AP-REP.
///
/// # Errors
///
/// Returns [`Error::UnexpectedStep`].
pub(super) const fn established(context: &EstablishedContext) -> Result<(), Error> {
    if context.open {
        Ok(())
    } else {
        Err(Error::UnexpectedStep("the context is not established"))
    }
}

/// Refuse an unestablished or expired context or one whose key needs the
/// legacy formats.
///
/// # Errors
///
/// Returns [`Error::UnexpectedStep`], [`Error::ContextExpired`],
/// [`Error::LegacyTokenFormat`] or the policy error of the key.
pub(super) fn usable(context: &EstablishedContext) -> Result<&EncryptionKey, Error> {
    established(context)?;
    if SystemTime::now() > context.expires {
        return Err(Error::ContextExpired);
    }
    let current = key(context);
    context
        .crypto_policy
        .check_use(current.etype(), Use::SessionKey)?;
    match KerberosEtype::from_etype_id(current.etype()) {
        Some(KerberosEtype::Sha1(_) | KerberosEtype::Sha2(_) | KerberosEtype::Camellia(_)) => {
            Ok(current)
        }
        Some(KerberosEtype::Des3CbcSha1Kd(_) | KerberosEtype::Rc4Hmac(_)) | None => {
            Err(Error::LegacyTokenFormat(current.etype()))
        }
    }
}

/// The key of a received token.
///
/// It is the acceptor subkey when the token's flag says so, else the initiator
/// subkey or the session key (RFC 4121 section 4.2.2; MIT `k5unsealiov.c`).
///
/// # Errors
///
/// Returns [`Error::DefectiveToken`] for the acceptor-subkey flag on a context
/// without an acceptor subkey.
pub(super) fn received_key(context: &EstablishedContext, flags: u8) -> Result<EncryptionKey, Error> {
    if flags & GSS_TOKEN_FLAG_ACCEPTOR_SUBKEY == 0 {
        return Ok(context
            .initiator_subkey
            .as_ref()
            .unwrap_or(&context.session_key)
            .clone());
    }
    context.acceptor_subkey.clone().ok_or(Error::DefectiveToken(
        "the acceptor-subkey flag on a context without one",
    ))
}

/// Take the next sequence number to send.
const fn next_sequence(context: &mut EstablishedContext) -> u64 {
    let number = context.send_sequence;
    context.send_sequence = number.wrapping_add(1);
    number
}

/// Refuse an oversized token.
///
/// # Errors
///
/// Returns [`Error::TokenTooLarge`].
const fn bounded(token: &[u8]) -> Result<(), Error> {
    if token.len() > MAX_TOKEN_LEN {
        return Err(Error::TokenTooLarge {
            maximum: MAX_TOKEN_LEN,
            actual: token.len(),
        });
    }
    Ok(())
}

/// `gss_get_mic`.
///
/// # Errors
///
/// Returns the errors of [`super::EstablishedContext::get_mic`].
pub(super) fn get_mic(context: &mut EstablishedContext, message: &[u8]) -> Result<Vec<u8>, Error> {
    let current = usable(context)?.clone();
    let (sign, _) = usages(context.initiated);
    let flags = sent_flags(context);
    let mut token = MicToken::new(flags, next_sequence(context)).with_payload(message.to_vec());
    token.set_checksum(&current, sign)?;
    Ok(token.encode()?)
}

/// `gss_verify_mic`.
///
/// # Errors
///
/// Returns the errors of [`super::EstablishedContext::verify_mic`].
pub(super) fn verify_mic(
    context: &mut EstablishedContext,
    message: &[u8],
    token: &[u8],
) -> Result<(), Error> {
    bounded(token)?;
    let _usable: &EncryptionKey = usable(context)?;
    let (sign, _) = usages(!context.initiated);
    let decoded = MicToken::decode(token, context.initiated)?;
    if decoded.flags() & GSS_TOKEN_FLAG_SEALED != 0 {
        return Err(Error::DefectiveToken("a MIC token cannot be sealed"));
    }
    let current = received_key(context, decoded.flags())?;
    let number = decoded.snd_seq_num();
    decoded
        .with_payload(message.to_vec())
        .verify(&current, sign)?;
    context.window.admit(number)
}

/// `gss_wrap`.
///
/// # Errors
///
/// Returns the errors of [`super::EstablishedContext::wrap`].
pub(super) fn wrap(
    context: &mut EstablishedContext,
    message: &[u8],
    confidential: bool,
) -> Result<Vec<u8>, Error> {
    let current = usable(context)?.clone();
    let (_, seal) = usages(context.initiated);
    let flags = sent_flags(context);
    let mut token = WrapToken::new(flags, next_sequence(context)).with_payload(message.to_vec());
    if confidential {
        let etype = KerberosEtype::from_etype_id(current.etype())
            .ok_or(Error::LegacyTokenFormat(current.etype()))?;
        let mut confounder = Zeroizing::new(vec![0; etype.confounder_len()]);
        getrandom::fill(&mut confounder).map_err(Error::Random)?;
        token.encrypt_payload_with_confounder(&current, seal, &confounder)?;
    } else {
        token.set_checksum(&current, seal)?;
    }
    Ok(token.encode()?)
}

/// `gss_unwrap`.
///
/// # Errors
///
/// Returns the errors of [`super::EstablishedContext::unwrap`].
pub(super) fn unwrap(context: &mut EstablishedContext, token: &[u8]) -> Result<Unwrapped, Error> {
    bounded(token)?;
    let _usable: &EncryptionKey = usable(context)?;
    let (_, seal) = usages(!context.initiated);
    let decoded = WrapToken::decode(token, context.initiated)?;
    let current = received_key(context, decoded.flags())?;
    let number = decoded.snd_seq_num();
    let confidential = decoded.is_sealed();
    let message = if confidential {
        Zeroizing::new(decoded.decrypt_payload(&current, seal)?)
    } else {
        decoded.verify(&current, seal)?;
        Zeroizing::new(decoded.payload().unwrap_or_default().to_vec())
    };
    context.window.admit(number)?;
    Ok(Unwrapped {
        message,
        confidential,
    })
}

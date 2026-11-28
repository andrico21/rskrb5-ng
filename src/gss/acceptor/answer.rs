//! The AP-REP of the krb5 acceptor.
//!
//! The acceptor subkey and sequence number, framed with the context's
//! mechanism (MIT `accept_sec_context.c:1020-1076`).

use zeroize::Zeroizing;

use super::{EncryptionKey, Error, ObjectIdentifier, initiator};
use crate::{
    crypto::KerberosEtype,
    service::{ApRepOptions, ValidatedApReq},
    spnego::Krb5MechToken,
};

/// A random acceptor subkey of `etype`, none for the legacy enctypes.
///
/// # Errors
///
/// Returns the random source and key errors.
fn acceptor_subkey(etype: i32) -> Result<Option<EncryptionKey>, Error> {
    match KerberosEtype::from_etype_id(etype) {
        Some(KerberosEtype::Sha1(_) | KerberosEtype::Sha2(_) | KerberosEtype::Camellia(_)) => {
            Ok(Some(initiator::random_key(etype)?))
        }
        Some(KerberosEtype::Des3CbcSha1Kd(_) | KerberosEtype::Rc4Hmac(_)) | None => Ok(None),
    }
}

/// The AP-REP of a mutually authenticated context: the acceptor's sequence
/// number and subkey, and the token, framed with the mechanism `frame` names
/// or raw without one.
///
/// # Errors
///
/// Returns the key, random-source and AP-REP errors.
pub(super) fn reply(
    validated: &ValidatedApReq,
    frame: Option<&ObjectIdentifier>,
    dce_style: bool,
) -> Result<(u32, Option<EncryptionKey>, Vec<u8>), Error> {
    let current = validated
        .subkey()
        .unwrap_or_else(|| validated.session_key());
    // DCE style implies an acceptor subkey (`accept_sec_context.c:933-934,1020`).
    let subkey = if dce_style {
        Some(initiator::random_key(current.etype())?)
    } else {
        acceptor_subkey(current.etype())?
    };
    let send = initiator::random_sequence()?;
    let reply_options = ApRepOptions::default()
        .with_subkey(subkey.clone())
        .with_sequence_number(Some(send));
    let etype = KerberosEtype::from_etype_id(validated.session_key().etype())
        .ok_or(Error::LegacyTokenFormat(validated.session_key().etype()))?;
    let mut confounder = Zeroizing::new(vec![0; etype.confounder_len()]);
    getrandom::fill(&mut confounder).map_err(Error::Random)?;
    let reply = validated.build_ap_rep_with_confounder(&confounder, &reply_options)?;
    let answer = match frame {
        Some(mechanism) => {
            let mut answer = Krb5MechToken::ap_rep(reply);
            answer.set_oid(mechanism.clone());
            answer.encode()?
        }
        // A raw AP-REP (`accept_sec_context.c:1067-1076`).
        None => reply,
    };
    Ok((send, subkey, answer))
}

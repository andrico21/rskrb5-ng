//! Password result consumption after a transport exchange.

use super::Error;
use crate::{
    client::kpasswd::{BuiltKpasswdRequest, RequestOptions, validated_result},
    crypto::{CryptoPolicy, Use},
    kadmin,
};

/// Consume the password result after the transport has delivered the request.
///
/// # Errors
/// Wraps contextual validation and decryption failures exactly once as unknown;
/// only authenticated and contextually valid server rejection is definite.
pub(super) fn checked(
    reply: &kadmin::Reply,
    request: &BuiltKpasswdRequest,
    options: &RequestOptions,
    policy: &CryptoPolicy,
) -> Result<kadmin::ChangePasswordResult, Error> {
    let result = validated_result(reply, request, options, policy)
        .map_err(|source| Error::KpasswdOutcomeUnknown(Box::new(source)))?;
    result.ensure_success()?;
    Ok(result)
}

/// Reject disallowed outgoing keys before any password mutation can be delivered.
///
/// # Errors
/// Returns the typed encryption-policy failure.
pub(super) fn outgoing(request: &BuiltKpasswdRequest, policy: &CryptoPolicy) -> Result<(), Error> {
    for id in [
        request.ap_req.session_key.etype,
        request.reply_key.etype,
        request.request.ap_req.ticket.enc_part.etype,
        request.request.ap_req.authenticator.etype,
        request.request.krb_priv.enc_part.etype,
    ] {
        policy.check_use(id, Use::SessionKey)?;
    }
    Ok(())
}

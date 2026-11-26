//! The AP exchange of the IAKERB acceptor.
//!
//! It is the krb5 mechanism's, with the transcript in its extension record,
//! so the `IAKERB-FINISHED` is verified before the replay cache commits the
//! authenticator (MIT
//! `iakerb_gss_accept_sec_context` over `krb5_gss_accept_sec_context_ext`,
//! `iakerb.c:895-912`, `accept_sec_context.c:369-401, 850-853`).

use super::super::{AP_REQ_TOKEN_ID, Context, Error, unframe};
use crate::gss::{
    Accepted, Acceptor,
    acceptor::{self, Request},
    checksum::Extensions,
};

/// The AP-REQ after the exchange: validate it with the finished checksum of
/// `transcript`, and answer with the AP-REP.
///
/// # Errors
///
/// Returns [`Error::UnexpectedStep`] for a token that is not an AP-REQ of the
/// IAKERB mechanism, [`Error::MissingFinished`], [`Error::BadFinished`] and
/// [`Error::UnexpectedFinished`] for the transcript checksum, and the AP-REQ
/// validation, checksum, bindings and delegation errors.
pub(super) fn ap_accept(
    transcript: &[u8],
    acceptor: &mut Acceptor<'_>,
    token: &[u8],
) -> Result<Accepted, Error> {
    let (id, der) = unframe(token)?;
    if id != AP_REQ_TOKEN_ID {
        return Err(Error::UnexpectedStep(
            "the token is neither a proxy token nor an AP-REQ",
        ));
    }
    let request = Request::new(der, Some(Context::mechanism()));
    acceptor::establish(acceptor, &request, Extensions::iakerb(transcript))
}

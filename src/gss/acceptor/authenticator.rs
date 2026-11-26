//! The authenticator checks of the krb5 acceptor.
//!
//! The checksum, the channel bindings, the sequence number and the extensions
//! of the record (MIT `process_checksum`, `accept_sec_context.c:464-597`).

use super::{
    AcceptorOptions, ChannelBindings, Checked, Error, Fault, bindings, checksum, finished,
};
use crate::gss::checksum::Extensions;

/// Interpret the authenticator checksum and the CBT assertion against the
/// acceptor's bindings policy, and its extensions against the extension
/// record.
///
/// # Errors
///
/// Returns [`Error::DefectiveChecksum`] for a missing or malformed checksum,
/// [`Error::BadBindings`] and [`Error::MissingBindings`] by the policy,
/// [`Error::DefectiveToken`] without a sequence number, and the [`Fault`] of
/// an `IAKERB-FINISHED` the record does not expect or that does not verify.
pub(super) fn check<E>(
    authenticator: &rasn_kerberos::Authenticator,
    options: &AcceptorOptions,
    extensions: Extensions<'_>,
) -> Result<Checked, E>
where
    E: From<Error> + From<Fault>,
{
    let value = authenticator
        .cksum
        .as_ref()
        .ok_or(Error::DefectiveChecksum(
            "the authenticator has no checksum",
        ))?;
    if value.r#type != checksum::CHECKSUM_TYPE {
        return Err(Error::DefectiveChecksum("not a GSS checksum").into());
    }
    let mut decoded = checksum::decode(&value.checksum)?;
    let ours = options.bindings.as_ref().map(ChannelBindings::digest);
    let present = *decoded.bindings() != [0; 16];
    let bound = present && ours.is_some_and(|digest| bindings::same(decoded.bindings(), &digest));
    if present && ours.is_some() && !bound {
        return Err(Error::BadBindings.into());
    }
    if checksum::asserts_cbt(authenticator.authorization_data.as_ref())? && ours.is_some() && !bound
    {
        return Err(Error::BadBindings.into());
    }
    if options.require_bindings && !bound {
        return Err(Error::MissingBindings.into());
    }
    if authenticator.seq_number.is_none() {
        return Err(Error::DefectiveToken("the authenticator has no sequence number").into());
    }
    finished::check(
        extensions.conversation(),
        decoded.finished(),
        authenticator.subkey.as_ref(),
    )?;
    Ok(Checked {
        flags: decoded.flags(),
        bound,
        delegation: decoded.take_delegation(),
    })
}

//! Mutual authentication of the krb5 initiator: the acceptor's AP-REP (MIT
//! `mutual_auth`, `init_sec_context.c:691-870`).

use super::{EncryptionKey, Error, EstablishedContext, InitStep, Pending, dce, seq};
use crate::{
    ap_rep,
    client::time::from_kerberos,
    crypto::Use,
    gss::ContextFlags,
    spnego::{Krb5MechToken, Krb5TokenId},
};

/// The second step: verify the acceptor's AP-REP.
///
/// # Errors
///
/// Returns [`Error::DefectiveToken`] for a token that is not an AP-REP, and the
/// errors of [`complete`].
pub(super) fn reply(
    pending: Pending,
    token: &[u8],
) -> Result<(EstablishedContext, InitStep), Error> {
    let wire = if pending.context.flags.contains(ContextFlags::DCE_STYLE) {
        // A raw AP-REP (`init_sec_context.c:757-759`).
        ap_rep::decode(token).map_err(Error::ApRep)?
    } else {
        let mech = Krb5MechToken::decode(token)?;
        if mech.token_id() != Krb5TokenId::ApRep {
            return Err(Error::DefectiveToken(
                "the acceptor did not answer with an AP-REP",
            ));
        }
        ap_rep::decode(mech.message()).map_err(Error::ApRep)?
    };
    complete(pending, &wire)
}

/// Verify the acceptor's AP-REP `wire` and complete the context (MIT
/// `mutual_auth`, `init_sec_context.c:691-870`); a DCE-style context answers
/// with its own AP-REP.
///
/// # Errors
///
/// Returns [`Error::DefectiveToken`] for an AP-REP that does not echo the
/// authenticator, and the AP-REP decryption, policy and timestamp errors.
pub(in crate::gss) fn complete(
    pending: Pending,
    wire: &rasn_kerberos::ApRep,
) -> Result<(EstablishedContext, InitStep), Error> {
    let Pending {
        mut context,
        ctime,
        cusec: sent_cusec,
    } = pending;
    let dce = context.flags.contains(ContextFlags::DCE_STYLE);
    let policy = &context.crypto_policy;
    policy.check_use(wire.enc_part.etype, Use::SessionKey)?;
    let part = ap_rep::decrypt_ap_rep_enc_part(wire, &context.session_key)?;
    let echoed = from_kerberos(&part.ctime);
    let cusec = part.cusec.to_string().parse::<u32>().ok();
    if echoed != Some(ctime) || cusec != Some(sent_cusec) {
        return Err(Error::DefectiveToken(
            "the AP-REP does not echo the authenticator",
        ));
    }
    let acceptor_subkey = match &part.subkey {
        Some(key) => {
            policy.check_use(key.r#type, Use::AcceptorSubkey)?;
            Some(EncryptionKey::new(key.r#type, key.value.to_vec()))
        }
        None => None,
    };
    context.acceptor_subkey = acceptor_subkey;
    let received = part.seq_number.unwrap_or(0);
    context.window = seq::Window::new(
        u64::from(received),
        context.flags.contains(ContextFlags::REPLAY),
        context.flags.contains(ContextFlags::SEQUENCE),
    );
    if dce {
        let third = dce::initiator_reply(&context.session_key, received)?;
        return Ok((context, InitStep::Complete(Some(third))));
    }
    Ok((context, InitStep::Complete(None)))
}

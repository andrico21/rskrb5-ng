//! DCE-style establishment.
//!
//! `GSS_C_DCE_STYLE` (MS-KILE section 3.4.5.1; MIT 1.22.2
//! `init_sec_context.c:420-430,554-555,757-835`,
//! `accept_sec_context.c:283-360,770-776,855-860,980-1080`): raw AP-REQ and
//! AP-REP tokens without the RFC 2743 framing, an acceptor subkey always, and
//! a third leg in which the initiator answers with its own AP-REP. That AP-REP
//! carries no subkey and echoes the acceptor's sequence number
//! (`mk_rep.c:69-120`, `rd_rep.c:148-200`); the acceptor opens its context
//! only when it verifies.

use std::time::{SystemTime, UNIX_EPOCH};

use rasn::types::Integer;
use rasn_kerberos::KerberosTime;
use zeroize::Zeroizing;

use super::{Accepted, EncryptionKey, Error};
use crate::{
    ap_rep,
    crypto::{KerberosEtype, Use},
};

/// The first byte of a DER AP-REQ (`[APPLICATION 14]`), which a framed GSS
/// token (`[APPLICATION 0]`, 0x60) never starts with.
const AP_REQ_TAG: u8 = 0x6e;

/// Whether `token` is a raw AP-REQ, as only a DCE-style initiator sends.
pub(super) fn is_raw_ap_req(token: &[u8]) -> bool {
    token.first() == Some(&AP_REQ_TAG)
}

/// The initiator's AP-REP of the third leg: the current time, no subkey, and
/// the acceptor's sequence number, sealed in the ticket session key
/// (`mk_rep.c:87-112` with `dce_style`).
///
/// # Errors
///
/// Returns [`Error::ContextExpired`] for a clock outside the Kerberos range,
/// and the AP-REP and random-source errors.
pub(super) fn initiator_reply(
    session_key: &EncryptionKey,
    acceptor_sequence: u32,
) -> Result<Vec<u8>, Error> {
    let since = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_before| Error::ContextExpired)?;
    let seconds = i64::try_from(since.as_secs()).map_err(|_range| Error::ContextExpired)?;
    let ctime = chrono::DateTime::from_timestamp(seconds, 0)
        .map(|utc| KerberosTime(utc.fixed_offset()))
        .ok_or(Error::ContextExpired)?;
    let part = rasn_kerberos::EncApRepPart {
        ctime,
        cusec: Integer::from(since.subsec_micros()),
        subkey: None,
        seq_number: Some(acceptor_sequence),
    };
    let etype = KerberosEtype::from_etype_id(session_key.etype())
        .ok_or(Error::LegacyTokenFormat(session_key.etype()))?;
    let mut confounder = Zeroizing::new(vec![0; etype.confounder_len()]);
    getrandom::fill(&mut confounder).map_err(Error::Random)?;
    let reply = ap_rep::build_ap_rep_with_confounder(&part, session_key, None, &confounder)?;
    Ok(ap_rep::encode(&reply)?)
}

/// The acceptor's third leg: verify the initiator's AP-REP and open the
/// context (`rd_rep.c:148-200`).
///
/// # Errors
///
/// Returns [`Error::UnexpectedStep`] for a context that is not waiting for it,
/// [`Error::DefectiveToken`] for an AP-REP with a subkey or another sequence
/// number, and the AP-REP decoding, decryption and policy errors.
pub(super) fn complete(accepted: &mut Accepted, token: &[u8]) -> Result<(), Error> {
    let context = &mut accepted.context;
    if context.open {
        return Err(Error::UnexpectedStep("the context is already established"));
    }
    let wire = ap_rep::decode(token)?;
    context
        .crypto_policy
        .check_use(wire.enc_part.etype, Use::SessionKey)?;
    let part = ap_rep::decrypt_ap_rep_enc_part(&wire, &context.session_key)?;
    if part.subkey.is_some() {
        return Err(Error::DefectiveToken(
            "the initiator's DCE AP-REP carries a subkey",
        ));
    }
    if part.seq_number.map(u64::from) != Some(context.send_sequence) {
        return Err(Error::DefectiveToken(
            "the initiator's DCE AP-REP does not echo the acceptor's sequence number",
        ));
    }
    context.open = true;
    accepted.output_token = None;
    Ok(())
}

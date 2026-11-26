//! The mechanism an IAKERB context reports.
//!
//! MIT 1.22.2 answers `gss_inquire_context` of an IAKERB context with
//! `gss_mech_iakerb` (`iakerb.c:1183-1226`; the krb5 context under it keeps the
//! IAKERB OID as its `mech_used`, `init_sec_context.c:925-926`,
//! `inq_context.c:164`), and the mechanism survives a context transfer.

use rskrb5_ng::gss::{EstablishedContext, MemoryTransferLedger, TransferKey, iakerb::Context};

use super::{
    context::TestError,
    kdc::Kdc,
    support::{establish, password_credential},
};

/// Both ends of an IAKERB context report IAKERB, before and after a transfer.
#[test]
fn iakerb_inquiry_reports_iakerb() -> Result<(), TestError> {
    // Given an IAKERB context established through the relay,
    let pair = establish(&password_credential(true)?, &Kdc::new())?;
    // then each end reports the IAKERB mechanism,
    for context in [&pair.initiator, &pair.acceptor] {
        assert_eq!(context.inquire().mechanism(), &Context::mechanism());
    }
    // and keeps it across export and import.
    let key = TransferKey::generate()?;
    let mut ledger = MemoryTransferLedger::new();
    for context in [pair.initiator, pair.acceptor] {
        let blob = context.export(&key)?;
        let imported = EstablishedContext::import(&blob, &key, &mut ledger)?;
        assert_eq!(imported.inquire().mechanism(), &Context::mechanism());
    }
    Ok(())
}

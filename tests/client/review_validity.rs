use super::*;

/// INVALID credential usability regressions.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use super::*;

    /// INVALID tickets remain unusable inside their time window.
    #[test]
    fn cached_service_rejects_invalid_flag() -> Result<(), TestError> {
        let tgt = current_tgt_session(1, 60)?;
        let mut ticket = tgt.clone();
        ticket.service = sample_service_principal();
        align_ticket_service(&mut ticket)?;
        ticket.ticket_flags =
            (u32::from_be_bytes(ticket.ticket_flags) | 0x0100_0000_u32).to_be_bytes();
        let mut client = Tokio::from_tgt_session(config_without_kdcs()?, KdcProtocol::Tcp, tgt);
        client.cache_service_ticket(ticket.clone())?;
        assert!(client.cached_service_ticket(ticket.service).is_none());
        Ok(())
    }

    /// Pruning removes all INVALID copies despite renewable metadata.
    #[test]
    fn pruning_removes_invalid_sessions_despite_renewable_metadata() -> Result<(), TestError> {
        // Given: live renewable sessions differing only in the INVALID flag.
        let valid = current_tgt_session(1, 60)?;
        let mut removed = Vec::new();
        for invalid_flag in [0_u32, 0x0100_0000] {
            let mut tgt = valid.clone();
            tgt.ticket_flags =
                (u32::from_be_bytes(tgt.ticket_flags) | KDC_OPTION_RENEWABLE | invalid_flag)
                    .to_be_bytes();
            tgt.renew_till = Some(
                tgt.end_time
                    .checked_add(Duration::from_hours(1))
                    .context("renewal horizon")?,
            );
            let mut ticket = tgt.clone();
            ticket.service = sample_service_principal();
            align_ticket_service(&mut ticket)?;
            let mut client = Tokio::from_tgt_session(config_without_kdcs()?, KdcProtocol::Tcp, tgt);
            client.cache_service_ticket(ticket)?;

            // When: pruning evaluates current usability independently of renewal metadata.
            let pruned = client.prune_unusable_sessions();

            // Then: all INVALID copies disappear while the valid control survives.
            removed.push((
                pruned.primary_tgt,
                pruned.tgt_sessions,
                pruned.service_tickets,
            ));
        }
        assert_eq!(removed, [(false, 0_usize, 0_usize), (true, 1, 1)]);
        Ok(())
    }
}

use super::*;

/// Ineligible cached credentials never trigger renewal traffic.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use rskrb5_ng::client::AsRepSession;

    use super::*;

    /// Invalid flag and time combinations with a future renewal horizon.
    fn ineligible_sessions() -> Result<Vec<AsRepSession>, TestError> {
        let current = current_tgt_session(1, 60)?;
        let mut missing_flag = current.clone();
        missing_flag.set_ticket_flags(
            (u32::from_be_bytes(current.ticket_flags()) & !KDC_OPTION_RENEWABLE).to_be_bytes(),
        );
        let mut future = current.clone();
        future.set_start_time(
            current
                .end_time()
                .checked_sub(Duration::from_mins(30))
                .context("future start")?,
        );
        let expired = current_tgt_session(120, 0)?;
        let mut horizon_before_end = current.clone();
        horizon_before_end.set_renew_till(Some(
            current
                .end_time()
                .checked_sub(Duration::from_mins(30))
                .context("short horizon")?,
        ));
        let mut invalid = current;
        invalid.set_ticket_flags(
            (u32::from_be_bytes(invalid.ticket_flags()) | 0x0100_0000).to_be_bytes(),
        );
        Ok(vec![
            missing_flag,
            future,
            expired,
            horizon_before_end,
            invalid,
        ])
    }

    /// Explicit renewal must reject metadata locally, not merely fail at an absent KDC.
    #[test]
    fn explicit_renewal_rejects_ineligible_sessions_before_transport() -> Result<(), TestError> {
        let mut transport_attempted = Vec::new();
        for session in ineligible_sessions()? {
            // Given: a cached session and DNS disabled with no KDC endpoints.
            let mut client =
                Tokio::from_tgt_session(config_without_kdcs()?, KdcProtocol::Tcp, session);
            // When: explicit renewal is requested.
            let error = runtime()?
                .block_on(client.renew_tgt())
                .err()
                .context("renewal rejected")?;
            // Then: no transport-discovery error may be reached.
            transport_attempted.push(!matches!(error, Error::TicketNotRenewable));
        }
        assert_eq!(transport_attempted, [false; 5]);
        Ok(())
    }

    /// Pruning removes expired and future tickets even if `renew_till` is in the future.
    #[test]
    fn pruning_drops_expired_and_future_renewable_sessions() -> Result<(), TestError> {
        let mut removed = Vec::new();
        for mut session in [current_tgt_session(120, 0)?, current_tgt_session(1, 60)?] {
            if session.end_time() > SystemTime::now() {
                session.set_start_time(
                    session
                        .end_time()
                        .checked_sub(Duration::from_mins(30))
                        .context("future start")?,
                );
            }
            let mut client = Tokio::from_tgt_session(Config::new(), KdcProtocol::Tcp, session);
            let pruned = client.prune_unusable_sessions();
            removed.push((pruned.primary_tgt, pruned.tgt_sessions));
        }
        assert_eq!(removed, [(true, 1_usize), (true, 1_usize)]);
        Ok(())
    }

    /// A due but unflagged primary is reused by cache-only callers without renewal.
    #[test]
    fn due_unflagged_primary_does_not_attempt_renewal() -> Result<(), TestError> {
        let mut session = current_tgt_session(55, 5)?;
        session.set_ticket_flags(
            (u32::from_be_bytes(session.ticket_flags()) & !KDC_OPTION_RENEWABLE).to_be_bytes(),
        );
        let mut client =
            Tokio::from_tgt_session(config_without_kdcs()?, KdcProtocol::Tcp, session.clone());
        let refreshed = runtime()?.block_on(client.refresh_tgt_if_needed())?;
        assert_eq!(refreshed, &session);
        Ok(())
    }
}

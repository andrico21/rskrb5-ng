use super::*;

/// Documented keep-better insertion and explicit replacement examples.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use super::*;

    /// A shorter valid service ticket replaces a longer one only after explicit removal.
    #[test]
    fn service_cache_keep_better_and_force_replacement() -> Result<(), TestError> {
        // Given a currently valid cached ticket and a shorter valid candidate.
        let mut longer = sample_tgt_session()?;
        let now = SystemTime::now();
        longer.start_time = now.checked_sub(Duration::from_secs(60)).context("start")?;
        longer.end_time = now.checked_add(Duration::from_hours(2)).context("end")?;
        let mut client = Tokio::from_tgt_session(Config::new(), KdcProtocol::Tcp, longer.clone());
        longer.service = Principal::user("TEST.GOKRB5", "service");
        align_ticket_service(&mut longer)?;
        let mut shorter = longer.clone();
        shorter.end_time = now
            .checked_add(Duration::from_hours(1))
            .context("short end")?;
        client.cache_service_ticket(longer.clone())?;
        // When inserting a worse candidate, then the existing ticket is retained.
        client.cache_service_ticket(shorter.clone())?;
        assert_eq!(
            client.cached_service_ticket(longer.service.clone()),
            Some(longer.clone())
        );
        // When explicitly removing before insertion, then replacement is unconditional.
        assert_eq!(
            client.remove_cached_service_ticket(longer.service.clone()),
            Some(longer)
        );
        client.cache_service_ticket(shorter.clone())?;
        assert_eq!(
            client.cached_service_ticket(shorter.service.clone()),
            Some(shorter)
        );
        Ok(())
    }

    /// Removing the home-realm TGT clears both indexes before forced replacement.
    #[test]
    fn tgt_cache_keep_better_and_force_replacement() -> Result<(), TestError> {
        // Given a longer valid primary TGT and a shorter valid candidate for the same realm.
        let mut longer = sample_tgt_session()?;
        let now = SystemTime::now();
        longer.start_time = now.checked_sub(Duration::from_secs(60)).context("start")?;
        longer.end_time = now.checked_add(Duration::from_hours(2)).context("end")?;
        let mut shorter = longer.clone();
        shorter.end_time = now
            .checked_add(Duration::from_hours(1))
            .context("short end")?;
        let mut client = Tokio::from_tgt_session(Config::new(), KdcProtocol::Tcp, longer.clone());
        // When inserting a shorter TGT, then both indexes retain the better cached TGT.
        client.cache_tgt_session(shorter.clone())?;
        assert_eq!(client.tgt_session(), Some(&longer));
        assert_eq!(client.tgt_session_for_realm("TEST.GOKRB5"), Some(&longer));
        // When explicitly removing before insertion, then both indexes accept the replacement.
        assert_eq!(
            client.remove_tgt_session_for_realm("TEST.GOKRB5"),
            Some(longer)
        );
        client.cache_tgt_session(shorter.clone())?;
        assert_eq!(client.tgt_session(), Some(&shorter));
        assert_eq!(client.tgt_session_for_realm("TEST.GOKRB5"), Some(&shorter));
        Ok(())
    }
}

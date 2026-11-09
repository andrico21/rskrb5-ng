use super::*;

/// Scheduling regressions for unusable primary TGTs.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use alloc::sync::Arc;
    use std::time::Instant as WallInstant;

    use rasn::{der, types::Integer};
    use rskrb5_ng::client::AsRepSession;
    use tokio::{runtime::Builder, sync::Mutex, task::yield_now, time::Instant};

    use super::*;

    /// An INVALID TGT with hours remaining still needs immediate acquisition.
    fn invalid_tgt() -> Result<AsRepSession, TestError> {
        let mut tgt = current_tgt_session(1, 180)?;
        tgt.set_ticket_flags((u32::from_be_bytes(tgt.ticket_flags()) | 0x0100_0000).to_be_bytes());
        Ok(tgt)
    }

    /// A future TGT cannot be used even though expiry is hours away.
    fn future_tgt() -> Result<AsRepSession, TestError> {
        let mut tgt = current_tgt_session(1, 180)?;
        tgt.set_start_time(
            tgt.end_time()
                .checked_sub(Duration::from_hours(1))
                .context("future start")?,
        );
        tgt.set_renew_till(None);
        Ok(tgt)
    }

    /// INVALID is a refresh trigger, not permission to clear the flag.
    #[test]
    fn invalid_primary_is_due_immediately() -> Result<(), TestError> {
        let tgt = invalid_tgt()?;
        let client = Tokio::from_tgt_session(Config::new(), KdcProtocol::Tcp, tgt.clone());
        let due = client.tgt_refresh_due();
        assert!(due);
        assert_eq!(
            client
                .tgt_session()
                .context("primary retained")?
                .ticket_flags(),
            tgt.ticket_flags()
        );
        Ok(())
    }

    /// Future start times trigger refresh before the expiry band.
    #[test]
    fn future_primary_is_due_immediately() -> Result<(), TestError> {
        let client = Tokio::from_tgt_session(Config::new(), KdcProtocol::Tcp, future_tgt()?);
        let due = client.tgt_refresh_due();
        assert!(due);
        Ok(())
    }

    /// Observe the actual AS request without letting virtual time reach the expiry band.
    fn assert_immediate_acquisition(tgt: &AsRepSession) -> Result<(), TestError> {
        Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()?
            .block_on(async {
                // Given: an unusable primary and explicit credentials with a loopback KDC.
                let listener = TcpListener::bind("127.0.0.1:0").await?;
                let client = Arc::new(Mutex::new(
                    Tokio::from_tgt_session(
                        config_with_kdc_server(&listener.local_addr()?.to_string())?,
                        KdcProtocol::Tcp,
                        tgt.clone(),
                    )
                    .with_password_credential(TESTUSER_PASSWORD),
                ));
                let virtual_start = Instant::now();
                let wall_start = WallInstant::now();
                let request = tokio::spawn(async move { read_tcp_kdc_request(&listener).await });

                // When: auto-refresh starts, keep paused time fixed while loopback I/O progresses.
                let renewal = Tokio::spawn_auto_renewal(Arc::clone(&client));
                while !request.is_finished() {
                    if wall_start.elapsed() >= Duration::from_secs(2) {
                        request.abort();
                        return Err(
                            "auto-refresh did not begin acquisition with time paused".into()
                        );
                    }
                    yield_now().await;
                }
                let (encoded, stream) = request.await??;
                drop(renewal);
                drop(stream);

                // Then: acquisition began now, without converting the old ticket into a valid one.
                let as_req: rasn_kerberos::AsReq = der::decode(&encoded)?;
                assert_eq!(as_req.0.msg_type, Integer::from(10_i32));
                assert_eq!(virtual_start.elapsed(), Duration::ZERO);
                let guard = client.lock().await;
                let retained = guard
                    .tgt_session()
                    .context("old primary retained until success")?;
                assert_eq!(retained.ticket_flags(), tgt.ticket_flags());
                assert_eq!(retained.start_time(), tgt.start_time());
                drop(guard);
                Ok(())
            })
    }

    /// The background scheduler immediately starts AS acquisition for INVALID TGTs.
    #[test]
    fn invalid_primary_starts_acquisition_with_time_paused() -> Result<(), TestError> {
        assert_immediate_acquisition(&invalid_tgt()?)
    }

    /// The background scheduler immediately starts AS acquisition for future TGTs.
    #[test]
    fn future_primary_starts_acquisition_with_time_paused() -> Result<(), TestError> {
        assert_immediate_acquisition(&future_tgt()?)
    }
}

#[cfg(all(feature = "tokio", feature = "spnego"))]
use rskrb5_ng::error::Ccache as CcacheError;

use super::*;

/// Session-cache tests: cached tickets, ccache and keytab loading (including the
/// child-process environment tests), renewal and realm case folding.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    #[cfg(feature = "tokio")]
    use alloc::sync::Arc;
    #[cfg(feature = "tokio")]
    use core::sync::atomic::{AtomicUsize, Ordering};
    #[cfg(feature = "tokio")]
    use std::{fs, sync::mpsc, thread};

    #[cfg(feature = "tokio")]
    use rasn::{der, types::Integer};
    #[cfg(feature = "tokio")]
    use rskrb5_ng::client::AsRepSession;
    #[cfg(all(feature = "tokio", feature = "spnego"))]
    use rskrb5_ng::spnego::parse_negotiate_header;
    #[cfg(feature = "tokio")]
    use tokio::{
        runtime::Builder as RuntimeBuilder,
        sync::Mutex,
        task::{JoinHandle, yield_now},
        time::sleep,
    };

    use super::*;

    /// Pins that a service ticket loaded from a ccache is served from the cache.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_returns_cached_service_ticket_from_ccache() -> Result<(), TestError> {
        let tgt = sample_tgt_session()?;
        let service_ticket = sample_service_ticket_session(&tgt)?;
        let mut cache = ccache::CCache::new(ccache::Principal::new(
            "TEST.GOKRB5",
            1,
            vec!["testuser1".to_owned()],
        ));
        let now = u32::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .context("current time is after unix epoch")?
                .as_secs(),
        )?;
        let mut tgt_credential = tgt.to_ccache_credential().context("TGT converts")?;
        make_credential_current(&mut tgt_credential, now)?;
        let mut service_credential = service_ticket
            .to_ccache_credential()
            .context("service ticket converts")?;
        // MIT kvno can store host-based service tickets as NT-PRINCIPAL in ccache.
        service_credential.server.name_type = 1_i32;
        make_credential_current(&mut service_credential, now)?;
        cache.credentials_mut().push(tgt_credential);
        cache.credentials_mut().push(service_credential);

        let mut client = Tokio::from_ccache(Config::new(), KdcProtocol::Tcp, &cache);
        let returned = runtime()?
            .block_on(client.get_service_ticket(sample_service_principal()))
            .context("cached service ticket is returned")?;

        assert_eq!(
            client.tgt_session().context("TGT loaded")?.service,
            tgt.service
        );
        assert_eq!(client.cached_service_ticket_count(), 1);
        assert_eq!(returned.client, service_ticket.client);
        assert_eq!(returned.service, service_ticket.service);
        assert_eq!(returned.session_key, service_ticket.session_key);
        assert_eq!(returned.ticket, service_ticket.ticket);
        Ok(())
    }

    /// Pins that the Tokio client exposes a cached service ticket and removes it on request.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_exposes_and_removes_cached_service_ticket() -> Result<(), TestError> {
        let tgt = sample_tgt_session()?;
        let mut service_ticket = sample_service_ticket_session(&tgt)?;
        let now = timestamp(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .context("current time is after unix epoch")?
                .as_secs(),
        )?;
        service_ticket.start_time = now
            .checked_sub(Duration::from_mins(1))
            .context("start time")?;
        service_ticket.end_time = now
            .checked_add(Duration::from_hours(1))
            .context("end time")?;
        let mut client = Tokio::from_tgt_session(Config::new(), KdcProtocol::Tcp, tgt);
        client.cache_service_ticket(service_ticket.clone())?;

        let cached = client
            .cached_service_ticket(sample_service_principal())
            .context("valid cached service ticket is returned")?;
        assert_eq!(cached.service, service_ticket.service);
        assert_eq!(cached.session_key, service_ticket.session_key);

        let removed = client
            .remove_cached_service_ticket(sample_service_principal())
            .context("cached service ticket is removed")?;
        assert_eq!(removed.ticket, service_ticket.ticket);
        assert_eq!(client.cached_service_ticket_count(), 0);
        assert!(
            client
                .cached_service_ticket(sample_service_principal())
                .is_none()
        );
        Ok(())
    }

    /// Pins that the service-ticket cache keeps the ticket with the latest end time.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_prefers_freshest_cached_service_ticket() -> Result<(), TestError> {
        let tgt = current_tgt_session(5, 180)?;
        let service_session = |remaining_minutes: u64, ticket: &[u8]| -> Result<_, TestError> {
            let now = SystemTime::now();
            let mut service_ticket = sample_service_ticket_session(&tgt)?;
            service_ticket.ticket = marked_ticket(ticket)?.into();
            align_ticket_service(&mut service_ticket)?;
            service_ticket.auth_time = now
                .checked_sub(Duration::from_mins(5))
                .context("auth time")?;
            service_ticket.start_time = service_ticket.auth_time;
            service_ticket.end_time = now
                .checked_add(Duration::from_mins(remaining_minutes))
                .context("end time")?;
            service_ticket.renew_till = Some(
                now.checked_add(Duration::from_hours(24))
                    .context("renew time")?,
            );
            Ok(service_ticket)
        };
        let mut client = Tokio::from_tgt_session(Config::new(), KdcProtocol::Tcp, tgt.clone());

        client.cache_service_ticket(service_session(120, b"service-long")?)?;
        client.cache_service_ticket(service_session(30, b"service-short")?)?;
        assert_eq!(
            client
                .cached_service_ticket(sample_service_principal())
                .context("longer service ticket remains")?
                .ticket
                .as_slice(),
            service_session(120, b"service-long")?.ticket.as_slice()
        );

        client.cache_service_ticket(service_session(180, b"service-longer")?)?;
        assert_eq!(
            client
                .cached_service_ticket(sample_service_principal())
                .context("longer service ticket is selected")?
                .ticket
                .as_slice(),
            service_session(180, b"service-longer")?.ticket.as_slice()
        );
        assert_eq!(client.cached_service_ticket_count(), 1);
        Ok(())
    }

    /// Pins that clearing the service-ticket cache keeps the TGT.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_clears_service_ticket_cache_without_dropping_tgt() -> Result<(), TestError> {
        let tgt = sample_tgt_session()?;
        let service_ticket = sample_service_ticket_session(&tgt)?;
        let mut client = Tokio::from_tgt_session(Config::new(), KdcProtocol::Tcp, tgt.clone());
        client.cache_service_ticket(service_ticket)?;

        assert_eq!(client.cached_service_ticket_count(), 1);
        client.clear_service_ticket_cache();

        assert_eq!(client.cached_service_ticket_count(), 0);
        assert_eq!(client.tgt_session().context("TGT remains cached")?, &tgt);
        Ok(())
    }

    /// Pins that cached-ticket lookup resolves an empty realm and skips expired tickets.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_cached_service_ticket_resolves_empty_realm_and_ignores_expired_entries()
    -> Result<(), TestError> {
        let tgt = sample_tgt_session()?;
        let mut service_ticket = sample_service_ticket_session(&tgt)?;
        let now = timestamp(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .context("current time is after unix epoch")?
                .as_secs(),
        )?;
        service_ticket.start_time = now
            .checked_sub(Duration::from_mins(10))
            .context("start time")?;
        service_ticket.end_time = now
            .checked_sub(Duration::from_mins(1))
            .context("end time")?;

        let mut config = Config::new();
        drop(
            config
                .domain_realm
                .insert("host.test.gokrb5".to_owned(), "TEST.GOKRB5".to_owned()),
        );
        let mut client = Tokio::from_tgt_session(config, KdcProtocol::Tcp, tgt);
        client.cache_service_ticket(service_ticket)?;

        assert!(
            client
                .cached_service_ticket(Principal::new("", 2, ["HTTP", "host.test.gokrb5"]))
                .is_none()
        );
        assert_eq!(client.cached_service_ticket_count(), 1);
        assert!(
            client
                .remove_cached_service_ticket(Principal::new("", 2, ["HTTP", "host.test.gokrb5"]))
                .is_some()
        );
        assert_eq!(client.cached_service_ticket_count(), 0);
        Ok(())
    }

    /// Pins that pruning drops expired sessions even with a future renewal horizon.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_prunes_expired_sessions_despite_renewable_metadata() -> Result<(), TestError> {
        let tgt = current_tgt_session(10, 50)?;
        let now = SystemTime::now();
        let expired_start = now
            .checked_sub(Duration::from_hours(2))
            .context("expired start time")?;
        let expired_end = now
            .checked_sub(Duration::from_hours(1))
            .context("expired end time")?;
        let future_renew_till = now
            .checked_add(Duration::from_hours(1))
            .context("renew-till time")?;
        let mut client = Tokio::from_tgt_session(Config::new(), KdcProtocol::Tcp, tgt.clone());

        let mut expired_referral_tgt = sample_referral_tgt_session("EXPIRED.GOKRB5")?;
        expired_referral_tgt.auth_time = expired_start;
        expired_referral_tgt.start_time = expired_start;
        expired_referral_tgt.end_time = expired_end;
        expired_referral_tgt.renew_till = None;
        client
            .cache_tgt_session(expired_referral_tgt)
            .context("expired referral TGT caches")?;

        let mut expired_service_ticket = sample_service_ticket_session(&tgt)?;
        expired_service_ticket.service =
            Principal::new("TEST.GOKRB5", 2, ["HTTP", "expired.test.gokrb5"]);
        align_ticket_service(&mut expired_service_ticket)?;
        expired_service_ticket.start_time = expired_start;
        expired_service_ticket.end_time = expired_end;
        expired_service_ticket.renew_till = None;
        client.cache_service_ticket(expired_service_ticket)?;

        let mut renewable_service_ticket = sample_service_ticket_session(&tgt)?;
        renewable_service_ticket.service =
            Principal::new("TEST.GOKRB5", 2, ["HTTP", "renewable.test.gokrb5"]);
        align_ticket_service(&mut renewable_service_ticket)?;
        renewable_service_ticket.start_time = expired_start;
        renewable_service_ticket.end_time = expired_end;
        renewable_service_ticket.renew_till = Some(future_renew_till);
        client.cache_service_ticket(renewable_service_ticket.clone())?;

        let pruned = client.prune_unusable_sessions();

        assert_eq!(
            pruned,
            PrunedSessions::default()
                .with_primary_tgt(false)
                .with_tgt_sessions(1)
                .with_service_tickets(2)
        );
        assert!(!pruned.is_empty(), "pruning reports the removed sessions");
        assert_eq!(client.tgt_session_count(), 1);
        assert!(client.tgt_session().is_some());
        assert!(client.tgt_session_for_realm("EXPIRED.GOKRB5").is_none());
        assert_eq!(client.cached_service_ticket_count(), 0);
        assert!(
            client
                .cached_service_ticket(renewable_service_ticket.service.clone())
                .is_none()
        );
        assert!(
            client
                .remove_cached_service_ticket(renewable_service_ticket.service)
                .is_none()
        );
        Ok(())
    }

    /// Pins that pruning drops an expired, non-renewable primary TGT.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_prunes_expired_nonrenewable_primary_tgt() -> Result<(), TestError> {
        let mut tgt = current_tgt_session(70, 0)?;
        tgt.renew_till = None;
        let mut client = Tokio::from_tgt_session(Config::new(), KdcProtocol::Tcp, tgt);

        let pruned = client.prune_unusable_sessions();

        assert_eq!(
            pruned,
            PrunedSessions::default()
                .with_primary_tgt(true)
                .with_tgt_sessions(1)
                .with_service_tickets(0)
        );
        assert!(client.tgt_session().is_none());
        assert_eq!(client.tgt_session_count(), 0);
        assert!(
            client.prune_unusable_sessions().is_empty(),
            "a second prune removes nothing"
        );
        assert!(
            PrunedSessions::default().is_empty(),
            "the default prune report is empty"
        );
        Ok(())
    }

    /// Pins that destroying the client clears its credentials, sessions and ticket cache.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_destroy_clears_credentials_sessions_and_cache() -> Result<(), TestError> {
        let tgt = sample_tgt_session()?;
        let service_ticket = sample_service_ticket_session(&tgt)?;
        let mut client = Tokio::from_tgt_session(Config::new(), KdcProtocol::Tcp, tgt)
            .with_password_credential(TESTUSER_PASSWORD);
        client.cache_service_ticket(service_ticket)?;

        client.destroy();

        assert!(client.tgt_session().is_none());
        assert_eq!(client.tgt_session_count(), 0);
        assert_eq!(client.cached_service_ticket_count(), 0);
        assert!(
            client
                .cached_service_ticket(sample_service_principal())
                .is_none()
        );
        let error = runtime()?
            .block_on(client.login())
            .err()
            .context("destroyed client has no credentials or TGT")?;
        assert!(matches!(error, Error::NoClientCredentials));
        Ok(())
    }

    /// Pins that loading a ccache ignores credentials of other clients.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_from_ccache_ignores_other_client_credentials() -> Result<(), TestError> {
        let tgt = sample_tgt_session()?;
        let service_ticket = sample_service_ticket_session(&tgt)?;
        let default_client = ccache::Principal::new("TEST.GOKRB5", 1, vec!["testuser1".to_owned()]);
        let other_client = ccache::Principal::new("OTHER.REALM", 1, vec!["other".to_owned()]);
        let now = u32::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .context("current time is after unix epoch")?
                .as_secs(),
        )?;
        let mut cache = ccache::CCache::new(default_client.clone());

        let mut tgt_credential = tgt.to_ccache_credential().context("TGT converts")?;
        make_credential_current(&mut tgt_credential, now)?;
        let mut service_credential = service_ticket
            .to_ccache_credential()
            .context("service ticket converts")?;
        make_credential_current(&mut service_credential, now)?;

        let mut other_tgt = tgt_credential.clone();
        other_tgt.client = other_client.clone();
        other_tgt.server = ccache::Principal::new(
            "OTHER.REALM",
            2,
            vec!["krbtgt".to_owned(), "OTHER.REALM".to_owned()],
        );
        other_tgt.key.value = vec![0xee];
        other_tgt.times.end_time = now + 2 * 60 * 60;
        other_tgt.times.renew_till = now + 3 * 60 * 60;

        let mut other_service = service_credential.clone();
        other_service.client = other_client;
        other_service.server = ccache::Principal::new(
            "OTHER.REALM",
            2,
            vec!["HTTP".to_owned(), "other.test.gokrb5".to_owned()],
        );
        other_service.key.value = vec![0xdd];

        cache.credentials_mut().push(other_tgt);
        cache
            .credentials_mut()
            .push(x_cacheconf_credential(&default_client));
        cache.credentials_mut().push(tgt_credential);
        cache.credentials_mut().push(other_service);
        cache.credentials_mut().push(service_credential);

        let mut client = Tokio::from_ccache(Config::new(), KdcProtocol::Tcp, &cache);
        let returned = runtime()?
            .block_on(client.get_service_ticket(sample_service_principal()))
            .context("default client's cached service ticket is returned")?;
        let loaded_tgt = client.tgt_session().context("TGT loaded")?;

        assert_eq!(client.client_principal(), &tgt.client);
        assert_eq!(loaded_tgt.client, tgt.client);
        assert_eq!(loaded_tgt.service, tgt.service);
        assert_eq!(loaded_tgt.session_key, tgt.session_key);
        assert_eq!(client.cached_service_ticket_count(), 1);
        assert_eq!(returned.session_key, service_ticket.session_key);
        Ok(())
    }

    /// Pins that loading a ccache keeps the freshest of duplicate service tickets.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_from_ccache_keeps_freshest_duplicate_service_ticket() -> Result<(), TestError> {
        let tgt = sample_tgt_session()?;
        let mut fresh_service_ticket = sample_service_ticket_session(&tgt)?;
        let mut older_service_ticket = fresh_service_ticket.clone();
        fresh_service_ticket.session_key.value = vec![0xf1];
        fresh_service_ticket.ticket = marked_ticket(b"fresh-service-ticket")?.into();
        align_ticket_service(&mut fresh_service_ticket)?;
        older_service_ticket.session_key.value = vec![0x0d];
        older_service_ticket.ticket = marked_ticket(b"older-service-ticket")?.into();
        align_ticket_service(&mut older_service_ticket)?;
        let now = u32::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .context("current time is after unix epoch")?
                .as_secs(),
        )?;

        let mut cache = ccache::CCache::new(ccache::Principal::new(
            "TEST.GOKRB5",
            1,
            vec!["testuser1".to_owned()],
        ));
        let mut tgt_credential = tgt.to_ccache_credential().context("TGT converts")?;
        make_credential_current(&mut tgt_credential, now)?;
        let mut fresh_credential = fresh_service_ticket
            .to_ccache_credential()
            .context("fresh service ticket converts")?;
        make_credential_current(&mut fresh_credential, now)?;
        fresh_credential.times.end_time = now + 2 * 60 * 60;
        let mut older_credential = older_service_ticket
            .to_ccache_credential()
            .context("older service ticket converts")?;
        make_credential_current(&mut older_credential, now)?;
        older_credential.times.end_time = now + 60;

        cache.credentials_mut().push(tgt_credential);
        cache.credentials_mut().push(fresh_credential);
        cache.credentials_mut().push(older_credential);

        let mut client = Tokio::from_ccache(Config::new(), KdcProtocol::Tcp, &cache);
        let returned = runtime()?
            .block_on(client.get_service_ticket(sample_service_principal()))
            .context("freshest cached service ticket is returned")?;

        assert_eq!(client.cached_service_ticket_count(), 1);
        assert_eq!(returned.session_key, fresh_service_ticket.session_key);
        assert_eq!(returned.ticket, fresh_service_ticket.ticket);
        Ok(())
    }

    /// Pins that loading a ccache prefers a current TGT over a not-yet-valid duplicate.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_from_ccache_prefers_current_tgt_over_future_duplicate() -> Result<(), TestError>
    {
        let mut current_tgt = sample_tgt_session()?;
        let mut future_tgt = current_tgt.clone();
        current_tgt.session_key.value = vec![0xc1];
        future_tgt.session_key.value = vec![0xf1];
        let now = u32::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .context("current time is after unix epoch")?
                .as_secs(),
        )?;

        let mut cache = ccache::CCache::new(ccache::Principal::new(
            "TEST.GOKRB5",
            1,
            vec!["testuser1".to_owned()],
        ));
        let mut current_credential = current_tgt
            .to_ccache_credential()
            .context("current TGT converts")?;
        make_credential_current(&mut current_credential, now)?;
        current_credential.times.end_time = now + 60 * 60;
        let mut future_credential = future_tgt
            .to_ccache_credential()
            .context("future TGT converts")?;
        future_credential.times.auth_time = now;
        future_credential.times.start_time = now + 60;
        future_credential.times.end_time = now + 2 * 60 * 60;
        future_credential.times.renew_till = now + 3 * 60 * 60;

        cache.credentials_mut().push(current_credential);
        cache.credentials_mut().push(future_credential);

        let client = Tokio::from_ccache(Config::new(), KdcProtocol::Tcp, &cache);
        let loaded_tgt = client.tgt_session().context("TGT loaded")?;

        assert_eq!(loaded_tgt.session_key, current_tgt.session_key);
        Ok(())
    }

    /// Pins that login returns a current TGT of a cache-only client without a KDC.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_login_returns_current_cache_only_tgt() -> Result<(), TestError> {
        let tgt = sample_tgt_session()?;
        let now = u32::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .context("current time is after unix epoch")?
                .as_secs(),
        )?;

        let mut cache = ccache::CCache::new(ccache::Principal::new(
            "TEST.GOKRB5",
            1,
            vec!["testuser1".to_owned()],
        ));
        let mut tgt_credential = tgt.to_ccache_credential().context("TGT converts")?;
        make_credential_current(&mut tgt_credential, now)?;
        cache.credentials_mut().push(tgt_credential);

        let mut client = Tokio::from_ccache(Config::new(), KdcProtocol::Tcp, &cache);
        let session = runtime()?
            .block_on(client.login())
            .context("current cache-only TGT is returned")?;

        assert_eq!(session.client, tgt.client);
        assert_eq!(session.service, tgt.service);
        assert_eq!(session.session_key, tgt.session_key);
        Ok(())
    }

    /// Pins that `affirm_login` returns a current TGT of a cache-only client without a KDC.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_affirm_login_returns_current_cache_only_tgt() -> Result<(), TestError> {
        let tgt = sample_tgt_session()?;
        let now = u32::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .context("current time is after unix epoch")?
                .as_secs(),
        )?;

        let mut cache = ccache::CCache::new(ccache::Principal::new(
            "TEST.GOKRB5",
            1,
            vec!["testuser1".to_owned()],
        ));
        let mut tgt_credential = tgt.to_ccache_credential().context("TGT converts")?;
        make_credential_current(&mut tgt_credential, now)?;
        cache.credentials_mut().push(tgt_credential);

        let mut client = Tokio::from_ccache(Config::new(), KdcProtocol::Tcp, &cache);
        let session = runtime()?
            .block_on(client.affirm_login())
            .context("current cache-only TGT is returned")?;

        assert_eq!(session.client, tgt.client);
        assert_eq!(session.service, tgt.service);
        assert_eq!(session.session_key, tgt.session_key);
        Ok(())
    }

    /// Pins that `affirm_login` reuses a valid TGT even when credentials are attached.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_affirm_login_reuses_valid_tgt_with_attached_credentials()
    -> Result<(), TestError> {
        let mut tgt = sample_tgt_session()?;
        let now = SystemTime::now();
        tgt.auth_time = now
            .checked_sub(Duration::from_mins(2))
            .context("auth time")?;
        tgt.start_time = now
            .checked_sub(Duration::from_mins(1))
            .context("start time")?;
        tgt.end_time = now
            .checked_add(Duration::from_hours(1))
            .context("end time")?;
        tgt.renew_till = Some(
            now.checked_add(Duration::from_hours(2))
                .context("renew time")?,
        );
        let mut client = Tokio::from_tgt_session(config_without_kdcs()?, KdcProtocol::Tcp, tgt)
            .with_password_credential(TESTUSER_PASSWORD);

        let session = runtime()?
            .block_on(client.affirm_login())
            .context("valid TGT is reused without KDC endpoints")?;

        assert_eq!(session.service, Principal::tgt_service("TEST.GOKRB5"));
        assert_eq!(session.session_key.value, decode_hex(SESSION_KEY)?);
        Ok(())
    }

    /// Pins that the Tokio client reports the assume-pre-authentication setting.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_exposes_assume_preauthentication_setting() {
        assert!(
            password_client()
                .with_assume_preauthentication(true)
                .assume_preauthentication()
        );
    }

    /// Pins that the Tokio client reports the FAST negotiation setting.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_exposes_fast_negotiation_setting() {
        assert!(
            !password_client()
                .with_fast_negotiation(false)
                .fast_negotiation()
        );
    }

    /// A Tokio client of `testuser1` with the test password and no KDC.
    #[cfg(feature = "tokio")]
    fn password_client() -> Tokio {
        Tokio::with_password(
            Config::new(),
            KdcProtocol::Tcp,
            Principal::user("TEST.GOKRB5", "testuser1"),
            TESTUSER_PASSWORD,
        )
    }

    /// Pins the window in which the Tokio client reports its TGT refresh as due.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_reports_tgt_refresh_due_window() -> Result<(), TestError> {
        let missing = Tokio::with_password(
            Config::new(),
            KdcProtocol::Tcp,
            Principal::user("TEST.GOKRB5", "testuser1"),
            TESTUSER_PASSWORD,
        );
        assert!(missing.tgt_refresh_due());

        let fresh = Tokio::from_tgt_session(
            Config::new(),
            KdcProtocol::Tcp,
            current_tgt_session(10, 50)?,
        );
        assert!(!fresh.tgt_refresh_due());

        let due =
            Tokio::from_tgt_session(Config::new(), KdcProtocol::Tcp, current_tgt_session(55, 5)?);
        assert!(due.tgt_refresh_due());

        let expired =
            Tokio::from_tgt_session(Config::new(), KdcProtocol::Tcp, current_tgt_session(70, 0)?);
        assert!(expired.tgt_refresh_due());
        Ok(())
    }

    /// Pins that a refresh reuses a fresh TGT of a cache-only client.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_refresh_tgt_if_needed_reuses_fresh_cache_only_tgt() -> Result<(), TestError> {
        let tgt = current_tgt_session(10, 50)?;
        let mut client = Tokio::from_tgt_session(Config::new(), KdcProtocol::Tcp, tgt.clone());

        let refreshed = runtime()?
            .block_on(client.refresh_tgt_if_needed())
            .context("fresh cache-only TGT is reused")?;

        assert_eq!(refreshed.session_key, tgt.session_key);
        assert_eq!(refreshed.ticket, tgt.ticket);
        Ok(())
    }

    /// Pins that configuration validation reports a realm without a configured KDC.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_validates_configuration() -> Result<(), TestError> {
        let mut dns_config = Config::new();
        dns_config.libdefaults.dns_lookup_kdc = true.into();
        let configured = Tokio::with_password(
            dns_config,
            KdcProtocol::Tcp,
            Principal::user("TEST.GOKRB5", "testuser1"),
            TESTUSER_PASSWORD,
        );
        assert!(configured.is_configured());
        configured
            .validate_configuration()
            .context("password-backed client with DNS KDC lookup is configured")?;

        let missing_name = Tokio::with_password(
            Config::new(),
            KdcProtocol::Tcp,
            Principal::user("TEST.GOKRB5", ""),
            TESTUSER_PASSWORD,
        );
        assert!(!missing_name.is_configured());
        assert!(matches!(
            missing_name.validate_configuration(),
            Err(Error::MissingClientName)
        ));

        let missing_realm = Tokio::with_password(
            Config::new(),
            KdcProtocol::Tcp,
            Principal::user("", "testuser1"),
            TESTUSER_PASSWORD,
        );
        assert!(!missing_realm.is_configured());
        assert!(matches!(
            missing_realm.validate_configuration(),
            Err(Error::MissingClientRealm)
        ));

        let mut missing_credentials =
            Tokio::from_tgt_session(Config::new(), KdcProtocol::Tcp, sample_tgt_session()?);
        missing_credentials.destroy();
        assert!(!missing_credentials.is_configured());
        assert!(matches!(
            missing_credentials.validate_configuration(),
            Err(Error::NoClientCredentials)
        ));

        let missing_kdc = Tokio::with_password(
            config_without_kdcs()?,
            KdcProtocol::Tcp,
            Principal::user("TEST.GOKRB5", "testuser1"),
            TESTUSER_PASSWORD,
        );
        assert!(!missing_kdc.is_configured());
        assert!(matches!(
            missing_kdc.validate_configuration(),
            Err(Error::NoConfiguredKdc { realm }) if realm == "TEST.GOKRB5"
        ));
        Ok(())
    }

    /// Pins that login rejects an expired TGT of a cache-only client.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_login_rejects_expired_cache_only_tgt() -> Result<(), TestError> {
        let tgt = sample_tgt_session()?;
        let now = u32::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .context("current time is after unix epoch")?
                .as_secs(),
        )?;

        let mut cache = ccache::CCache::new(ccache::Principal::new(
            "TEST.GOKRB5",
            1,
            vec!["testuser1".to_owned()],
        ));
        let mut tgt_credential = tgt.to_ccache_credential().context("TGT converts")?;
        make_credential_expired(&mut tgt_credential, now)?;
        cache.credentials_mut().push(tgt_credential);

        let mut client = Tokio::from_ccache(Config::new(), KdcProtocol::Tcp, &cache);
        let error = runtime()?
            .block_on(client.login())
            .err()
            .context("expired cache-only TGT is not returned")?;

        assert!(matches!(error, Error::NoClientCredentials));
        Ok(())
    }

    /// Pins that loading a ccache prefers a current service ticket over a not-yet-valid duplicate.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_from_ccache_prefers_current_service_ticket_over_future_duplicate()
    -> Result<(), TestError> {
        let tgt = sample_tgt_session()?;
        let mut current_service_ticket = sample_service_ticket_session(&tgt)?;
        let mut future_service_ticket = current_service_ticket.clone();
        current_service_ticket.session_key.value = vec![0xc2];
        current_service_ticket.ticket = marked_ticket(b"current-service-ticket")?.into();
        align_ticket_service(&mut current_service_ticket)?;
        future_service_ticket.session_key.value = vec![0xf2];
        future_service_ticket.ticket = marked_ticket(b"future-service-ticket")?.into();
        align_ticket_service(&mut future_service_ticket)?;
        let now = u32::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .context("current time is after unix epoch")?
                .as_secs(),
        )?;

        let mut cache = ccache::CCache::new(ccache::Principal::new(
            "TEST.GOKRB5",
            1,
            vec!["testuser1".to_owned()],
        ));
        let mut tgt_credential = tgt.to_ccache_credential().context("TGT converts")?;
        make_credential_current(&mut tgt_credential, now)?;
        let mut current_credential = current_service_ticket
            .to_ccache_credential()
            .context("current service ticket converts")?;
        make_credential_current(&mut current_credential, now)?;
        current_credential.times.end_time = now + 60 * 60;
        let mut future_credential = future_service_ticket
            .to_ccache_credential()
            .context("future service ticket converts")?;
        future_credential.times.auth_time = now;
        future_credential.times.start_time = now + 60;
        future_credential.times.end_time = now + 2 * 60 * 60;
        future_credential.times.renew_till = now + 3 * 60 * 60;

        cache.credentials_mut().push(tgt_credential);
        cache.credentials_mut().push(current_credential);
        cache.credentials_mut().push(future_credential);

        let mut client = Tokio::from_ccache(Config::new(), KdcProtocol::Tcp, &cache);
        let returned = runtime()?
            .block_on(client.get_service_ticket(sample_service_principal()))
            .context("current cached service ticket is returned")?;

        assert_eq!(client.cached_service_ticket_count(), 1);
        assert_eq!(returned.session_key, current_service_ticket.session_key);
        assert_eq!(returned.ticket, current_service_ticket.ticket);
        Ok(())
    }

    /// Pins that loading a ccache with only an expired TGT and no credentials is rejected.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_from_ccache_rejects_expired_tgt_without_live_credentials()
    -> Result<(), TestError> {
        let tgt = sample_tgt_session()?;
        let now = u32::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .context("current time is after unix epoch")?
                .as_secs(),
        )?;

        let mut cache = ccache::CCache::new(ccache::Principal::new(
            "TEST.GOKRB5",
            1,
            vec!["testuser1".to_owned()],
        ));
        let mut tgt_credential = tgt.to_ccache_credential().context("TGT converts")?;
        make_credential_expired(&mut tgt_credential, now)?;
        cache.credentials_mut().push(tgt_credential);

        let mut client = Tokio::from_ccache(Config::new(), KdcProtocol::Tcp, &cache);
        let error = runtime()?
            .block_on(client.get_service_ticket(sample_service_principal()))
            .err()
            .context("expired cache-only TGT cannot acquire a service ticket")?;

        assert!(matches!(error, Error::NoClientCredentials));
        Ok(())
    }

    /// Pins that loading a ccache skips an expired service ticket.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_from_ccache_rejects_expired_service_ticket() -> Result<(), TestError> {
        let tgt = sample_tgt_session()?;
        let service_ticket = sample_service_ticket_session(&tgt)?;
        let now = u32::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .context("current time is after unix epoch")?
                .as_secs(),
        )?;

        let mut cache = ccache::CCache::new(ccache::Principal::new(
            "TEST.GOKRB5",
            1,
            vec!["testuser1".to_owned()],
        ));
        let mut tgt_credential = tgt.to_ccache_credential().context("TGT converts")?;
        make_credential_current(&mut tgt_credential, now)?;
        let mut service_credential = service_ticket
            .to_ccache_credential()
            .context("service ticket converts")?;
        make_credential_expired(&mut service_credential, now)?;
        cache.credentials_mut().push(tgt_credential);
        cache.credentials_mut().push(service_credential);

        let mut client = Tokio::from_ccache(config_without_kdcs()?, KdcProtocol::Tcp, &cache);
        let error = runtime()?
            .block_on(client.get_service_ticket(sample_service_principal()))
            .err()
            .context("expired service ticket is not returned from cache")?;

        assert!(matches!(
            error,
            Error::NoKdcEndpoints {
                realm,
                protocol: KdcProtocol::Tcp,
            } if realm == "TEST.GOKRB5"
        ));
        Ok(())
    }

    /// Pins that an expired renewable service ticket is reacquired using the current TGT.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_reacquires_expired_renewable_cached_service_ticket() -> Result<(), TestError> {
        runtime()?.block_on(async {
            let tgt = current_tgt_session(10, 50)?;
            let mut service_ticket = sample_service_ticket_session(&tgt)?;
            service_ticket.session_key.value = vec![0x44; 32];
            let cached_session_key = service_ticket.session_key.clone();
            let renewal_reply_key = tgt.session_key.clone();
            let now = SystemTime::now();
            service_ticket.start_time = now
                .checked_sub(Duration::from_hours(2))
                .context("expired start time")?;
            service_ticket.end_time = now
                .checked_sub(Duration::from_hours(1))
                .context("expired end time")?;
            service_ticket.renew_till = Some(
                now.checked_add(Duration::from_hours(1))
                    .context("renew-till time")?,
            );

            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .context("bind local KDC listener")?;
            let addr = listener.local_addr().context("local listener address")?;
            let mut client = Tokio::from_tgt_session(
                config_with_kdc_server(&addr.to_string())?,
                KdcProtocol::Tcp,
                tgt,
            );
            client.cache_service_ticket(service_ticket.clone())?;
            assert_eq!(client.cached_service_ticket_count(), 1);

            let task = tokio::spawn(async move {
                let (request, mut socket) = read_tcp_kdc_request(&listener).await?;
                let decoded: rasn_kerberos::TgsReq =
                    der::decode(&request).context("TGS-REQ decodes")?;
                let body = &decoded.0.req_body;
                let expected_options = 0x0000_0010_u32;
                assert_eq!(
                    body.kdc_options.0.as_raw_slice(),
                    expected_options.to_be_bytes().as_slice()
                );
                assert_eq!(
                    principal_from_parts(&body.realm, body.sname.as_ref().context("sname")?)?,
                    sample_service_principal()
                );

                let built = built_tgs_request_from_der(decoded, &request)?;
                let response = synthetic_tgs_rep(&built, built.nonce, &renewal_reply_key)?;
                write_tcp_kdc_response(&mut socket, &response).await?;
                Ok::<(), TestError>(())
            });

            let renewed = client
                .get_service_ticket(sample_service_principal())
                .await
                .context("expired service ticket is reacquired")?;
            task.await.context("KDC task succeeds")??;

            assert_eq!(renewed.service, sample_service_principal());
            assert_eq!(hex_encode(&renewed.session_key.value)?, SERVICE_SESSION_KEY);
            assert_eq!(client.cached_service_ticket_count(), 1);
            let cached = client
                .remove_cached_service_ticket(sample_service_principal())
                .context("renewed service ticket is cached")?;
            assert_eq!(cached.session_key, renewed.session_key);
            assert_ne!(cached.session_key, cached_session_key);
            Ok::<(), TestError>(())
        })?;
        Ok(())
    }

    /// Pins that an expired ccache service ticket is reacquired with the current TGT.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_reacquires_ccache_loaded_expired_service_ticket() -> Result<(), TestError> {
        runtime()?.block_on(async {
            let tgt = sample_tgt_session()?;
            let mut service_ticket = sample_service_ticket_session(&tgt)?;
            service_ticket.session_key.value = vec![0x46; 32];
            let cached_session_key = service_ticket.session_key.clone();
            let renewal_reply_key = tgt.session_key.clone();
            let now = u32::try_from(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .context("current time is after unix epoch")?
                    .as_secs(),
            )?;

            let mut cache = ccache::CCache::new(ccache::Principal::new(
                "TEST.GOKRB5",
                1,
                vec!["testuser1".to_owned()],
            ));
            let mut tgt_credential = tgt.to_ccache_credential().context("TGT converts")?;
            make_credential_current(&mut tgt_credential, now)?;
            let mut service_credential = service_ticket
                .to_ccache_credential()
                .context("service ticket converts")?;
            service_credential.times.auth_time = now - 2 * 60 * 60;
            service_credential.times.start_time = now - 2 * 60 * 60;
            service_credential.times.end_time = now - 60 * 60;
            service_credential.times.renew_till = now + 60 * 60;
            cache.credentials_mut().push(tgt_credential);
            cache.credentials_mut().push(service_credential);

            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .context("bind local KDC listener")?;
            let addr = listener.local_addr().context("local listener address")?;
            let mut client = Tokio::from_ccache(
                config_with_kdc_server(&addr.to_string())?,
                KdcProtocol::Tcp,
                &cache,
            );
            assert_eq!(client.cached_service_ticket_count(), 1);

            let task = tokio::spawn(async move {
                let (request, mut socket) = read_tcp_kdc_request(&listener).await?;
                let decoded: rasn_kerberos::TgsReq =
                    der::decode(&request).context("TGS-REQ decodes")?;
                let body = &decoded.0.req_body;
                let expected_options = 0x0000_0010_u32;
                assert_eq!(
                    body.kdc_options.0.as_raw_slice(),
                    expected_options.to_be_bytes().as_slice()
                );
                assert_eq!(
                    principal_from_parts(&body.realm, body.sname.as_ref().context("sname")?)?,
                    sample_service_principal()
                );

                let built = built_tgs_request_from_der(decoded, &request)?;
                let response = synthetic_tgs_rep(&built, built.nonce, &renewal_reply_key)?;
                write_tcp_kdc_response(&mut socket, &response).await?;
                Ok::<(), TestError>(())
            });

            let renewed = client
                .get_service_ticket(sample_service_principal())
                .await
                .context("expired ccache service ticket is reacquired")?;
            task.await.context("KDC task succeeds")??;

            assert_eq!(renewed.service, sample_service_principal());
            assert_eq!(hex_encode(&renewed.session_key.value)?, SERVICE_SESSION_KEY);
            let cached = client
                .remove_cached_service_ticket(sample_service_principal())
                .context("renewed service ticket is cached")?;
            assert_eq!(cached.session_key, renewed.session_key);
            assert_ne!(cached.session_key, cached_session_key);
            Ok::<(), TestError>(())
        })?;
        Ok(())
    }

    /// Pins that an expired referral is reacquired with the current primary TGT.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_reacquires_expired_cached_referral_tgt() -> Result<(), TestError> {
        runtime()?.block_on(async {
            let primary_tgt = current_tgt_session(10, 50)?;
            let mut referral_tgt = valid_referral_tgt_session(&primary_tgt, "RESDOM.GOKRB5")?;
            referral_tgt.session_key.value = vec![0x45; 32];
            let cached_referral_key = referral_tgt.session_key.clone();
            let referral_renewal_reply_key = primary_tgt.session_key.clone();
            let now = SystemTime::now();
            referral_tgt.start_time = now
                .checked_sub(Duration::from_hours(2))
                .context("expired start time")?;
            referral_tgt.end_time = now
                .checked_sub(Duration::from_hours(1))
                .context("expired end time")?;
            referral_tgt.renew_till = Some(
                now.checked_add(Duration::from_hours(1))
                    .context("renew-till time")?,
            );

            let resource_service =
                Principal::new("RESDOM.GOKRB5", 2, ["HTTP", "app.resdom.gokrb5"]);
            let expected_client = primary_tgt.client.clone();
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .context("bind local KDC listener")?;
            let addr = listener.local_addr().context("local listener address")?;
            let mut client = Tokio::from_tgt_session(
                config_with_kdc_server(&addr.to_string())?,
                KdcProtocol::Tcp,
                primary_tgt,
            );
            client
                .cache_tgt_session(referral_tgt)
                .context("expired referral TGT caches")?;

            let expected_resource_service = resource_service.clone();
            let task = tokio::spawn(async move {
                let (renewal_request, mut renewal_socket) = read_tcp_kdc_request(&listener).await?;
                let renewal_decoded: rasn_kerberos::TgsReq =
                    der::decode(&renewal_request).context("renewal TGS-REQ decodes")?;
                let renewal_body = &renewal_decoded.0.req_body;
                let expected_options = 0x0000_0010_u32;
                assert_eq!(
                    renewal_body.kdc_options.0.as_raw_slice(),
                    expected_options.to_be_bytes().as_slice()
                );
                assert_eq!(
                    principal_from_parts(
                        &renewal_body.realm,
                        renewal_body.sname.as_ref().context("renewal sname")?
                    )?,
                    Principal::new("TEST.GOKRB5", 2, ["krbtgt", "RESDOM.GOKRB5"])
                );
                let mut renewal_built =
                    built_tgs_request_from_der(renewal_decoded, &renewal_request)?;
                renewal_built.client = expected_client.clone();
                let renewal_response = synthetic_tgs_rep_with_service(
                    &renewal_built,
                    renewal_built.nonce,
                    &referral_renewal_reply_key,
                    &Principal::new("TEST.GOKRB5", 2, ["krbtgt", "RESDOM.GOKRB5"]),
                )?;
                write_tcp_kdc_response(&mut renewal_socket, &renewal_response).await?;

                let (service_request, mut service_socket) = read_tcp_kdc_request(&listener).await?;
                let service_decoded: rasn_kerberos::TgsReq =
                    der::decode(&service_request).context("service TGS-REQ decodes")?;
                let service_body = &service_decoded.0.req_body;
                assert_eq!(
                    principal_from_parts(
                        &service_body.realm,
                        service_body.sname.as_ref().context("service sname")?
                    )?,
                    expected_resource_service
                );
                let mut service_built =
                    built_tgs_request_from_der(service_decoded, &service_request)?;
                service_built.client = expected_client;
                let renewed_referral_key = EncryptionKey::new(18, decode_hex(SERVICE_SESSION_KEY)?);
                let service_response =
                    synthetic_tgs_rep(&service_built, service_built.nonce, &renewed_referral_key)?;
                write_tcp_kdc_response(&mut service_socket, &service_response).await?;
                Ok::<(), TestError>(())
            });

            let ticket = client
                .get_service_ticket(resource_service.clone())
                .await
                .context("service ticket is acquired through renewed referral TGT")?;
            task.await.context("KDC task succeeds")??;

            assert_eq!(ticket.service, resource_service);
            assert_eq!(client.cached_service_ticket_count(), 1);
            let renewed_referral = client
                .tgt_session_for_realm("RESDOM.GOKRB5")
                .context("renewed referral TGT is cached")?;
            assert_ne!(renewed_referral.session_key, cached_referral_key);
            assert_eq!(
                hex_encode(&renewed_referral.session_key.value)?,
                SERVICE_SESSION_KEY
            );
            Ok::<(), TestError>(())
        })?;
        Ok(())
    }

    /// Pins that a destination's cached TGT is renewed with its original issuing-realm server.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_renews_tgt_session_for_realm() -> Result<(), TestError> {
        runtime()?.block_on(async {
            let primary_tgt = current_tgt_session(10, 50)?;
            let mut referral_tgt = valid_referral_tgt_session(&primary_tgt, "RESDOM.GOKRB5")?;
            referral_tgt.session_key.value = vec![0x47; 32];
            referral_tgt.auth_time = primary_tgt.auth_time;
            referral_tgt.start_time = primary_tgt.start_time;
            referral_tgt.end_time = primary_tgt.end_time;
            referral_tgt.renew_till = primary_tgt.renew_till;
            referral_tgt.ticket_flags = primary_tgt.ticket_flags;
            let cached_referral_key = referral_tgt.session_key.clone();
            let referral_renewal_reply_key = referral_tgt.session_key.clone();
            let expected_client = primary_tgt.client.clone();

            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .context("bind local KDC listener")?;
            let addr = listener.local_addr().context("local listener address")?;
            let mut client = Tokio::from_tgt_session(
                config_with_kdc_server(&addr.to_string())?,
                KdcProtocol::Tcp,
                primary_tgt,
            );
            client
                .cache_tgt_session(referral_tgt)
                .context("referral TGT caches")?;

            let task = tokio::spawn(async move {
                let (request, mut socket) = read_tcp_kdc_request(&listener).await?;
                let decoded: rasn_kerberos::TgsReq =
                    der::decode(&request).context("TGS-REQ decodes")?;
                let body = &decoded.0.req_body;
                let expected_options = 0x0000_0010 | KDC_OPTION_RENEWABLE | KDC_OPTION_RENEW;
                assert_eq!(
                    body.kdc_options.0.as_raw_slice(),
                    expected_options.to_be_bytes().as_slice()
                );
                assert_eq!(
                    principal_from_parts(&body.realm, body.sname.as_ref().context("sname")?)?,
                    Principal::new("TEST.GOKRB5", 2, ["krbtgt", "RESDOM.GOKRB5"])
                );

                let mut built = built_tgs_request_from_der(decoded, &request)?;
                built.client = expected_client;
                let response = synthetic_tgs_rep(&built, built.nonce, &referral_renewal_reply_key)?;
                write_tcp_kdc_response(&mut socket, &response).await?;
                Ok::<(), TestError>(())
            });

            let renewed = client
                .renew_tgt_session_for_realm("RESDOM.GOKRB5")
                .await
                .context("referral TGT renews explicitly")?;
            task.await.context("KDC task succeeds")??;

            assert_eq!(
                renewed.service,
                Principal::new("TEST.GOKRB5", 2, ["krbtgt", "RESDOM.GOKRB5"])
            );
            assert_ne!(renewed.session_key, cached_referral_key);
            assert_eq!(hex_encode(&renewed.session_key.value)?, SERVICE_SESSION_KEY);
            assert_eq!(
                client
                    .tgt_session_for_realm("RESDOM.GOKRB5")
                    .context("renewed referral is cached")?
                    .session_key,
                renewed.session_key
            );
            assert!(matches!(
                client
                    .renew_tgt_session_for_realm("MISSING.GOKRB5")
                    .await
                    .err()
                    .context("missing realm has no TGT")?,
                Error::NoTgtSession
            ));
            Ok::<(), TestError>(())
        })?;
        Ok(())
    }

    /// Pins that the Tokio client exports, saves and reloads its ccache, by path and by name.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_exports_and_saves_ccache() -> Result<(), TestError> {
        let tgt = sample_tgt_session()?;
        let service_ticket = sample_service_ticket_session(&tgt)?;
        let mut client = Tokio::from_tgt_session(Config::new(), KdcProtocol::Tcp, tgt.clone());
        client.cache_service_ticket(service_ticket)?;

        let cache = client.to_ccache().context("client exports ccache")?;
        assert_eq!(cache.default_principal().realm, "TEST.GOKRB5");
        assert_eq!(cache.default_principal().components, ["testuser1"]);
        assert_eq!(cache.entries().len(), 2);
        assert!(cache.contains_server(&["krbtgt", "TEST.GOKRB5"]));
        assert!(cache.contains_server(&["HTTP", "host.test.gokrb5"]));

        let reloaded = Tokio::from_ccache(Config::new(), KdcProtocol::Tcp, &cache);
        assert_eq!(reloaded.tgt_session().context("TGT reloads")?, &tgt);
        assert_eq!(reloaded.cached_service_ticket_count(), 1);

        let path = temp_client_ccache_file("export-save")?;
        client.save_ccache(&path).context("client saves ccache")?;
        let loaded = ccache::CCache::load(&path).context("saved ccache loads")?;
        fs::remove_file(&path).context("remove the test file")?;
        assert_eq!(loaded, cache);

        let name_path = temp_client_ccache_file("export-save-name")?;
        let name = format!("FILE:{}", name_path.display());
        client
            .save_ccache_name(&name)
            .context("client saves ccache by name")?;
        let loaded_by_name = ccache::CCache::load_name(&name).context("named ccache loads")?;
        fs::remove_file(&name_path).context("remove the test file")?;
        assert_eq!(loaded_by_name, cache);
        Ok(())
    }

    /// Pins that the Tokio client loads its sessions from a `FILE:` ccache name.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_loads_from_ccache_name() -> Result<(), TestError> {
        let tgt = sample_tgt_session()?;
        let service_ticket = sample_service_ticket_session(&tgt)?;
        let mut client = Tokio::from_tgt_session(Config::new(), KdcProtocol::Tcp, tgt.clone());
        client.cache_service_ticket(service_ticket)?;
        let cache = client.to_ccache().context("client exports ccache")?;
        let path = temp_client_ccache_file("load-name")?;
        let name = format!("FILE:{}", path.display());
        cache.save_name(&name).context("ccache saves by name")?;

        let loaded = Tokio::from_ccache_name(Config::new(), KdcProtocol::Tcp, &name)
            .context("client loads ccache by name")?;
        fs::remove_file(&path).context("remove the test file")?;

        assert_eq!(loaded.tgt_session().context("TGT reloads")?, &tgt);
        assert_eq!(loaded.cached_service_ticket_count(), 1);
        Ok(())
    }

    /// Pins that a `NegotiateClient` loaded from a ccache name builds a SPNEGO header for a host.
    #[cfg(all(feature = "tokio", feature = "spnego"))]
    #[test]
    fn negotiate_client_builds_authorization_header_for_host_from_ccache_name()
    -> Result<(), TestError> {
        let (path, name) = save_sample_negotiate_ccache("negotiate-load-name")?;

        let mut client = NegotiateClient::from_ccache_name(Config::new(), &name)
            .context("negotiate client loads")?;
        assert_eq!(client.inner().protocol(), KdcProtocol::Auto);
        let header = runtime()?
            .block_on(client.authorization_header_for_host("HTTP", "host.test.gokrb5"))
            .context("authorization header builds")?;
        fs::remove_file(&path).context("remove the test file")?;

        assert!(header.starts_with("Negotiate "));
        drop(parse_negotiate_header(&header).context("SPNEGO header parses")?);
        Ok(())
    }

    /// Pins that a `BlockingNegotiateClient` loaded from a ccache name builds a SPNEGO header for a host.
    #[cfg(all(feature = "tokio", feature = "spnego"))]
    #[test]
    fn blocking_negotiate_client_builds_authorization_header_for_host_from_ccache_name()
    -> Result<(), TestError> {
        let (path, name) = save_sample_negotiate_ccache("blocking-negotiate-load-name")?;

        let mut client = BlockingNegotiateClient::from_ccache_name(Config::new(), &name)
            .context("blocking negotiate client loads")?;
        let header = client
            .authorization_header_for_host("HTTP", "host.test.gokrb5")
            .context("blocking authorization header builds")?;
        fs::remove_file(&path).context("remove the test file")?;

        assert!(header.starts_with("Negotiate "));
        drop(parse_negotiate_header(&header).context("SPNEGO header parses")?);
        Ok(())
    }

    /// Pins that a `NegotiateClient` reports an unsupported ccache type as such.
    #[cfg(all(feature = "tokio", feature = "spnego"))]
    #[test]
    fn negotiate_client_preserves_unsupported_cache_type_error() -> Result<(), TestError> {
        let error = NegotiateClient::from_ccache_name(Config::new(), "API:")
            .err()
            .context("unsupported cache type rejected")?;

        assert!(matches!(
            error,
            Error::CCache(CcacheError::UnsupportedCacheType { cache_type })
                if cache_type == "API"
        ));
        Ok(())
    }

    /// Pins that the client loads its ccache from `KRB5CCNAME`.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_loads_from_ccache_env() -> Result<(), TestError> {
        const TEST_PATH: &str = "session_cache::tests::tokio_client_loads_from_ccache_env";
        if !env::in_child(TEST_PATH) {
            let path = temp_client_ccache_file("load-env")?;
            let name = format!("FILE:{}", path.display());
            env::run_in_child(TEST_PATH, &[("KRB5CCNAME", Some(name.as_ref()))]);
            return Ok(());
        }
        let tgt = sample_tgt_session()?;
        let service_ticket = sample_service_ticket_session(&tgt)?;
        let mut client = Tokio::from_tgt_session(Config::new(), KdcProtocol::Tcp, tgt.clone());
        client.cache_service_ticket(service_ticket)?;
        let cache = client
            .to_ccache()
            .map_err(|cause| format!("client exports ccache: {cause}"))?;
        let (name, path) = file_name_from_parent("KRB5CCNAME");
        cache
            .save_name(&name)
            .map_err(|cause| format!("ccache saves by name: {cause}"))?;

        let loaded = Tokio::from_ccache_env(Config::new(), KdcProtocol::Tcp)
            .map_err(|cause| format!("client loads ccache from env: {cause}"))?;
        fs::remove_file(&path).context("remove the test file")?;

        assert_eq!(loaded.tgt_session().context("TGT reloads")?, &tgt);
        assert_eq!(loaded.cached_service_ticket_count(), 1);
        Ok(())
    }

    /// Pins that the Tokio client saves to and loads from a `DIR:` ccache collection.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_saves_and_loads_dir_collection_ccache_name() -> Result<(), TestError> {
        let tgt = sample_tgt_session()?;
        let service_ticket = sample_service_ticket_session(&tgt)?;
        let mut client = Tokio::from_tgt_session(Config::new(), KdcProtocol::Tcp, tgt.clone());
        client.cache_service_ticket(service_ticket)?;
        let directory = temp_client_ccache_dir("dir-collection-name")?;
        fs::create_dir_all(&directory).context("temp DIR collection is created")?;
        let name = format!("DIR:{}", directory.display());

        client
            .save_ccache_name(&name)
            .context("client saves ccache to DIR collection")?;
        let loaded = Tokio::from_ccache_name(Config::new(), KdcProtocol::Tcp, &name)
            .context("client loads ccache from DIR collection")?;

        fs::remove_file(directory.join("tkt")).context("remove the test file")?;
        fs::remove_file(directory.join("primary")).context("remove the test file")?;
        fs::remove_dir(&directory).context("remove the test directory")?;

        assert_eq!(loaded.tgt_session().context("TGT reloads")?, &tgt);
        assert_eq!(loaded.cached_service_ticket_count(), 1);
        Ok(())
    }

    /// Pins that the Tokio client loads the default ccache named by the configuration.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_loads_from_config_default_ccache_name() -> Result<(), TestError> {
        let tgt = sample_tgt_session()?;
        let service_ticket = sample_service_ticket_session(&tgt)?;
        let directory = temp_client_ccache_dir("default-ccache-name")?;
        fs::create_dir_all(&directory).context("temp DIR collection is created")?;
        let name = format!("DIR:{}", directory.display());
        let mut client = Tokio::from_tgt_session(
            config_with_default_ccache_name(&name)?,
            KdcProtocol::Tcp,
            tgt.clone(),
        );
        client.cache_service_ticket(service_ticket)?;
        client
            .save_default_ccache_name()
            .context("client saves configured ccache")?;

        let loaded = Tokio::from_default_ccache_name(
            config_with_default_ccache_name(&name)?,
            KdcProtocol::Tcp,
        )
        .context("client loads configured default ccache")?;

        fs::remove_file(directory.join("tkt")).context("remove the test file")?;
        fs::remove_file(directory.join("primary")).context("remove the test file")?;
        fs::remove_dir(&directory).context("remove the test directory")?;

        assert_eq!(loaded.tgt_session().context("TGT reloads")?, &tgt);
        assert_eq!(loaded.cached_service_ticket_count(), 1);
        Ok(())
    }

    /// Pins the configured default ccache when `KRB5CCNAME` is unset.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_uses_config_default_ccache_when_env_is_absent() -> Result<(), TestError> {
        const TEST_PATH: &str =
            "session_cache::tests::tokio_client_uses_config_default_ccache_when_env_is_absent";
        if !env::in_child(TEST_PATH) {
            env::run_in_child(TEST_PATH, &[("KRB5CCNAME", None)]);
            return Ok(());
        }
        let tgt = sample_tgt_session()?;
        let service_ticket = sample_service_ticket_session(&tgt)?;
        let directory = temp_client_ccache_dir("default-ccache-env-fallback")?;
        fs::create_dir_all(&directory)
            .map_err(|cause| format!("temp DIR collection is created: {cause}"))?;
        let name = format!("DIR:{}", directory.display());
        let mut client = Tokio::from_tgt_session(
            config_with_default_ccache_name(&name)?,
            KdcProtocol::Tcp,
            tgt.clone(),
        );
        client.cache_service_ticket(service_ticket)?;
        client
            .save_default_ccache()
            .map_err(|cause| format!("client saves default ccache: {cause}"))?;

        let loaded =
            Tokio::from_default_ccache(config_with_default_ccache_name(&name)?, KdcProtocol::Tcp)
                .map_err(|cause| format!("client loads default ccache: {cause}"))?;
        loaded
            .update_default_ccache()
            .map_err(|cause| format!("client updates default ccache: {cause}"))?;

        fs::remove_file(directory.join("tkt")).context("remove the test file")?;
        fs::remove_file(directory.join("primary")).context("remove the test file")?;
        fs::remove_dir(&directory).context("remove the test directory")?;

        assert_eq!(loaded.tgt_session().context("TGT reloads")?, &tgt);
        assert_eq!(loaded.cached_service_ticket_count(), 1);
        Ok(())
    }

    /// Pins that `KRB5CCNAME` overrides the configured default ccache name.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_prefers_env_default_ccache_over_config_name() -> Result<(), TestError> {
        const TEST_PATH: &str =
            "session_cache::tests::tokio_client_prefers_env_default_ccache_over_config_name";
        if !env::in_child(TEST_PATH) {
            let path = temp_client_ccache_file("default-ccache-env-precedence")?;
            let env_name = format!("FILE:{}", path.display());
            env::run_in_child(TEST_PATH, &[("KRB5CCNAME", Some(env_name.as_ref()))]);
            return Ok(());
        }
        let tgt = sample_tgt_session()?;
        let service_ticket = sample_service_ticket_session(&tgt)?;
        let (_, path) = file_name_from_parent("KRB5CCNAME");
        let config_default = "MEMORY:config-default".to_owned();
        let mut client = Tokio::from_tgt_session(
            config_with_default_ccache_name(&config_default)?,
            KdcProtocol::Tcp,
            tgt.clone(),
        );
        client.cache_service_ticket(service_ticket)?;
        client
            .save_default_ccache()
            .map_err(|cause| format!("client saves default ccache from env: {cause}"))?;

        let loaded = Tokio::from_default_ccache(
            config_with_default_ccache_name(&config_default)?,
            KdcProtocol::Tcp,
        )
        .map_err(|cause| format!("client loads default ccache from env: {cause}"))?;
        loaded
            .update_default_ccache()
            .map_err(|cause| format!("client updates default ccache from env: {cause}"))?;
        fs::remove_file(&path).context("remove the test file")?;

        assert_eq!(loaded.tgt_session().context("TGT reloads")?, &tgt);
        assert_eq!(loaded.cached_service_ticket_count(), 1);
        Ok(())
    }

    /// Pins `NoDefaultCCacheName` when neither `KRB5CCNAME` nor the config names a ccache.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_rejects_missing_config_default_ccache_name() -> Result<(), TestError> {
        const TEST_PATH: &str =
            "session_cache::tests::tokio_client_rejects_missing_config_default_ccache_name";
        if !env::in_child(TEST_PATH) {
            env::run_in_child(TEST_PATH, &[("KRB5CCNAME", None)]);
            return Ok(());
        }
        let error = Tokio::from_default_ccache_name(Config::new(), KdcProtocol::Tcp)
            .err()
            .context("missing default ccache name is rejected")?;

        assert!(matches!(error, Error::NoDefaultCCacheName));

        let client =
            Tokio::from_tgt_session(Config::new(), KdcProtocol::Tcp, sample_tgt_session()?);
        let save_error = client
            .save_default_ccache_name()
            .err()
            .context("missing default ccache name is rejected")?;
        assert!(matches!(save_error, Error::NoDefaultCCacheName));

        let update_error = client
            .update_default_ccache_name()
            .err()
            .context("missing default ccache name is rejected")?;
        assert!(matches!(update_error, Error::NoDefaultCCacheName));

        let load_default_error = Tokio::from_default_ccache(Config::new(), KdcProtocol::Tcp)
            .err()
            .context("missing default ccache name is rejected")?;
        assert!(matches!(load_default_error, Error::NoDefaultCCacheName));

        let save_default_error = client
            .save_default_ccache()
            .err()
            .context("missing default ccache name is rejected")?;
        assert!(matches!(save_default_error, Error::NoDefaultCCacheName));

        let update_default_error = client
            .update_default_ccache()
            .err()
            .context("missing default ccache name is rejected")?;
        assert!(matches!(update_default_error, Error::NoDefaultCCacheName));
        Ok(())
    }

    /// Pins that the Tokio client loads the client keytab named by the configuration.
    #[cfg(all(feature = "tokio", feature = "serde"))]
    #[test]
    fn tokio_client_loads_client_keytab_from_config_name() -> Result<(), TestError> {
        let keytab = keytab_with_reply_key(1)?;
        let path = temp_client_keytab_file("load-config-name")?;
        let name = format!("FILE:{}", path.display());
        keytab.save_name(&name).context("keytab saves by name")?;

        let client = Tokio::with_client_keytab_from_config(
            config_with_client_keytab_name(&name)?,
            KdcProtocol::Tcp,
            Principal::user("TEST.GOKRB5", "testuser1"),
        )
        .context("client loads keytab by config name")?;
        fs::remove_file(&path).context("remove the test file")?;

        let diagnostics = runtime()?.block_on(client.diagnostics());
        assert_eq!(diagnostics.credential_source, "keytab");
        assert_eq!(diagnostics.keytab_enctypes, [18_i32]);
        Ok(())
    }

    #[cfg(all(feature = "tokio", feature = "serde"))]
    /// Pins that the client loads its keytab from `KRB5_KTNAME`.
    #[test]
    fn tokio_client_loads_keytab_from_env() -> Result<(), TestError> {
        const TEST_PATH: &str = "session_cache::tests::tokio_client_loads_keytab_from_env";
        if !env::in_child(TEST_PATH) {
            let path = temp_client_keytab_file("load-keytab-env")?;
            let name = format!("FILE:{}", path.display());
            env::run_in_child(TEST_PATH, &[("KRB5_KTNAME", Some(name.as_ref()))]);
            return Ok(());
        }
        let keytab = keytab_with_reply_key(1)?;
        let (name, path) = file_name_from_parent("KRB5_KTNAME");
        keytab
            .save_name(&name)
            .map_err(|cause| format!("keytab saves by name: {cause}"))?;

        let client = Tokio::with_keytab_from_env(
            Config::new(),
            KdcProtocol::Tcp,
            Principal::user("TEST.GOKRB5", "testuser1"),
        )
        .map_err(|cause| format!("client loads keytab from env: {cause}"))?;
        fs::remove_file(&path).context("remove the test file")?;

        let diagnostics = runtime()?.block_on(client.diagnostics());
        assert_eq!(diagnostics.credential_source, "keytab");
        assert_eq!(diagnostics.keytab_enctypes, [18_i32]);
        Ok(())
    }

    #[cfg(all(feature = "tokio", feature = "serde"))]
    /// Pins that the client loads its client keytab from `KRB5_CLIENT_KTNAME`.
    #[test]
    fn tokio_client_loads_client_keytab_from_env() -> Result<(), TestError> {
        const TEST_PATH: &str = "session_cache::tests::tokio_client_loads_client_keytab_from_env";
        if !env::in_child(TEST_PATH) {
            let path = temp_client_keytab_file("load-client-keytab-env")?;
            let name = format!("FILE:{}", path.display());
            env::run_in_child(TEST_PATH, &[("KRB5_CLIENT_KTNAME", Some(name.as_ref()))]);
            return Ok(());
        }
        let keytab = keytab_with_reply_key(1)?;
        let (name, path) = file_name_from_parent("KRB5_CLIENT_KTNAME");
        keytab
            .save_name(&name)
            .map_err(|cause| format!("keytab saves by name: {cause}"))?;

        let client = Tokio::with_client_keytab_from_env(
            Config::new(),
            KdcProtocol::Tcp,
            Principal::user("TEST.GOKRB5", "testuser1"),
        )
        .map_err(|cause| format!("client loads client keytab from env: {cause}"))?;
        fs::remove_file(&path).context("remove the test file")?;

        let diagnostics = runtime()?.block_on(client.diagnostics());
        assert_eq!(diagnostics.credential_source, "keytab");
        assert_eq!(diagnostics.keytab_enctypes, [18_i32]);
        Ok(())
    }

    #[cfg(all(feature = "tokio", feature = "serde"))]
    /// Pins the configured default client keytab when `KRB5_CLIENT_KTNAME` is unset.
    #[test]
    fn tokio_client_loads_default_client_keytab_when_env_is_absent() -> Result<(), TestError> {
        const TEST_PATH: &str =
            "session_cache::tests::tokio_client_loads_default_client_keytab_when_env_is_absent";
        if !env::in_child(TEST_PATH) {
            env::run_in_child(TEST_PATH, &[("KRB5_CLIENT_KTNAME", None)]);
            return Ok(());
        }
        let keytab = keytab_with_reply_key(1)?;
        let path = temp_client_keytab_file("load-default-client-keytab")?;
        let name = format!("FILE:{}", path.display());
        keytab
            .save_name(&name)
            .map_err(|cause| format!("keytab saves by name: {cause}"))?;

        let client = Tokio::with_client_keytab_from_default(
            config_with_client_keytab_name(&name)?,
            KdcProtocol::Tcp,
            Principal::user("TEST.GOKRB5", "testuser1"),
        )
        .map_err(|cause| format!("client loads default client keytab: {cause}"))?;
        fs::remove_file(&path).context("remove the test file")?;

        let diagnostics = runtime()?.block_on(client.diagnostics());
        assert_eq!(diagnostics.credential_source, "keytab");
        assert_eq!(diagnostics.keytab_enctypes, [18_i32]);
        Ok(())
    }

    #[cfg(all(feature = "tokio", feature = "serde"))]
    /// Pins that `KRB5_CLIENT_KTNAME` overrides the configured client keytab name.
    #[test]
    fn tokio_client_prefers_env_client_keytab_over_config_name() -> Result<(), TestError> {
        const TEST_PATH: &str =
            "session_cache::tests::tokio_client_prefers_env_client_keytab_over_config_name";
        if !env::in_child(TEST_PATH) {
            let path = temp_client_keytab_file("load-env-client-keytab")?;
            let env_name = format!("FILE:{}", path.display());
            env::run_in_child(
                TEST_PATH,
                &[("KRB5_CLIENT_KTNAME", Some(env_name.as_ref()))],
            );
            return Ok(());
        }
        let keytab = keytab_with_reply_key(1)?;
        let (env_name, path) = file_name_from_parent("KRB5_CLIENT_KTNAME");
        keytab
            .save_name(&env_name)
            .map_err(|cause| format!("keytab saves by name: {cause}"))?;
        let missing_config_name = format!(
            "FILE:{}",
            temp_client_keytab_file("missing-config-client-keytab")?.display()
        );

        let client = Tokio::with_client_keytab_from_default(
            config_with_client_keytab_name(&missing_config_name)?,
            KdcProtocol::Tcp,
            Principal::user("TEST.GOKRB5", "testuser1"),
        )
        .map_err(|cause| {
            format!("client loads env client keytab before config default: {cause}")
        })?;
        fs::remove_file(&path).context("remove the test file")?;

        let diagnostics = runtime()?.block_on(client.diagnostics());
        assert_eq!(diagnostics.credential_source, "keytab");
        assert_eq!(diagnostics.keytab_enctypes, [18_i32]);
        Ok(())
    }

    /// Pins the error for a client keytab named by neither the environment nor the config.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_reports_missing_client_keytab_env() -> Result<(), TestError> {
        const TEST_PATH: &str =
            "session_cache::tests::tokio_client_reports_missing_client_keytab_env";
        if !env::in_child(TEST_PATH) {
            env::run_in_child(TEST_PATH, &[("KRB5_CLIENT_KTNAME", None)]);
            return Ok(());
        }
        let error = Tokio::with_client_keytab_from_env(
            Config::new(),
            KdcProtocol::Tcp,
            Principal::user("TEST.GOKRB5", "testuser1"),
        )
        .err()
        .context("missing client keytab env is rejected")?;

        assert!(matches!(error, Error::DefaultClientKeytabName(_)));
        Ok(())
    }

    /// Pins that the Tokio client keeps TGT sessions of several realms.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_tracks_multiple_tgt_sessions() -> Result<(), TestError> {
        let primary_tgt = sample_tgt_session()?;
        let referral_tgt = sample_referral_tgt_session("RESDOM.GOKRB5")?;
        let mut client =
            Tokio::from_tgt_session(Config::new(), KdcProtocol::Tcp, primary_tgt.clone());

        client
            .cache_tgt_session(referral_tgt.clone())
            .context("referral TGT caches")?;

        assert_eq!(client.tgt_session_count(), 2);
        assert_eq!(
            client
                .tgt_session_for_realm("TEST.GOKRB5")
                .context("primary TGT is cached")?
                .service,
            primary_tgt.service
        );
        assert_eq!(
            client
                .tgt_session_for_realm("RESDOM.GOKRB5")
                .context("referral TGT is cached")?
                .service,
            referral_tgt.service
        );

        let cache = client.to_ccache().context("client exports ccache")?;
        assert_eq!(cache.entries().len(), 2);
        assert!(cache.contains_server(&["krbtgt", "TEST.GOKRB5"]));
        assert!(cache.contains_server(&["krbtgt", "RESDOM.GOKRB5"]));

        let reloaded = Tokio::from_ccache(Config::new(), KdcProtocol::Tcp, &cache);
        assert_eq!(reloaded.tgt_session_count(), 2);
        assert!(reloaded.tgt_session_for_realm("RESDOM.GOKRB5").is_some());

        let removed_referral = client
            .remove_tgt_session_for_realm("RESDOM.GOKRB5")
            .context("referral TGT is removed")?;
        assert_eq!(removed_referral.service, referral_tgt.service);
        assert_eq!(client.tgt_session_count(), 1);
        assert!(client.tgt_session_for_realm("RESDOM.GOKRB5").is_none());
        assert_eq!(
            client.tgt_session().context("primary TGT remains")?.service,
            primary_tgt.service
        );

        let removed_primary = client
            .remove_tgt_session_for_realm("TEST.GOKRB5")
            .context("primary TGT is removed")?;
        assert_eq!(removed_primary.service, primary_tgt.service);
        assert!(client.tgt_session().is_none());
        assert_eq!(client.tgt_session_count(), 0);
        assert!(
            client
                .remove_tgt_session_for_realm("MISSING.GOKRB5")
                .is_none()
        );
        Ok(())
    }

    /// Pins that caching a non-TGT session as a TGT session is rejected.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_rejects_non_tgt_session_cache_insert() -> Result<(), TestError> {
        let tgt = current_tgt_session(5, 180)?;
        let service_ticket = sample_service_ticket_session(&tgt)?;
        let mut client = Tokio::from_tgt_session(Config::new(), KdcProtocol::Tcp, tgt);

        let error = client
            .cache_tgt_session(service_ticket)
            .err()
            .context("service ticket is rejected as a TGT session")?;

        assert!(matches!(
            error,
            Error::InvalidTgtSession { service } if service == "HTTP/host.test.gokrb5"
        ));
        Ok(())
    }

    /// Pins that the TGT-session cache keeps the session with the latest end time.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_prefers_freshest_cached_tgt_session() -> Result<(), TestError> {
        let primary_session = |remaining_minutes: u64, ticket: &[u8]| -> Result<_, TestError> {
            let mut tgt = current_tgt_session(5, remaining_minutes)?;
            tgt.ticket = marked_ticket(ticket)?.into();
            Ok(tgt)
        };
        let referral_session = |remaining_minutes: u64, ticket: &[u8]| -> Result<_, TestError> {
            let mut tgt = primary_session(remaining_minutes, ticket)?;
            tgt.service = Principal::new(
                "TEST.GOKRB5",
                2,
                ["krbtgt".to_owned(), "RESDOM.GOKRB5".to_owned()],
            );
            align_ticket_service(&mut tgt)?;
            Ok(tgt)
        };

        let primary_tgt = primary_session(120, b"primary-long")?;
        let mut client = Tokio::from_tgt_session(Config::new(), KdcProtocol::Tcp, primary_tgt);

        client
            .cache_tgt_session(primary_session(30, b"primary-short")?)
            .context("shorter primary TGT caches")?;
        assert_eq!(
            client
                .tgt_session()
                .context("primary TGT remains")?
                .ticket
                .as_slice(),
            marked_ticket(b"primary-long")?.as_slice()
        );
        assert_eq!(
            client
                .tgt_session_for_realm("TEST.GOKRB5")
                .context("realm-keyed primary remains")?
                .ticket
                .as_slice(),
            marked_ticket(b"primary-long")?.as_slice()
        );

        client
            .cache_tgt_session(primary_session(180, b"primary-longer")?)
            .context("longer primary TGT caches")?;
        assert_eq!(
            client
                .tgt_session()
                .context("primary TGT is replaced")?
                .ticket
                .as_slice(),
            marked_ticket(b"primary-longer")?.as_slice()
        );

        client
            .cache_tgt_session(referral_session(90, b"referral-long")?)
            .context("referral TGT caches")?;

        client
            .cache_tgt_session(referral_session(15, b"referral-short")?)
            .context("shorter referral TGT caches")?;
        assert_eq!(
            client
                .tgt_session_for_realm("RESDOM.GOKRB5")
                .context("longer referral TGT remains")?
                .ticket
                .as_slice(),
            referral_session(90, b"referral-long")?.ticket.as_slice()
        );

        client
            .cache_tgt_session(referral_session(180, b"referral-longer")?)
            .context("longer referral TGT caches")?;
        assert_eq!(
            client
                .tgt_session_for_realm("RESDOM.GOKRB5")
                .context("longer referral TGT is selected")?
                .ticket
                .as_slice(),
            referral_session(180, b"referral-longer")?.ticket.as_slice()
        );
        Ok(())
    }

    /// Pins that the JSON snapshots of the Tokio client match the gokrb5 shapes.
    #[cfg(all(feature = "tokio", feature = "serde"))]
    #[test]
    fn tokio_client_json_snapshots_match_gokrb5_shapes() -> Result<(), TestError> {
        let tgt = sample_tgt_session()?;
        let service_ticket = sample_service_ticket_session(&tgt)?;
        let mut client = Tokio::from_tgt_session(Config::new(), KdcProtocol::Tcp, tgt);
        client.cache_service_ticket(service_ticket)?;

        let sessions = client.sessions_json().context("sessions JSON renders")?;
        assert_eq!(
            sessions,
            r#"[
  {
    "Realm": "TEST.GOKRB5",
    "AuthTime": "2030-01-02T03:04:05Z",
    "EndTime": "2030-01-03T03:04:05Z",
    "RenewTill": "2030-01-08T03:04:05Z",
    "SessionKeyExpiration": "2030-01-03T03:04:05Z"
  }
]"#
        );

        let service_tickets = client
            .service_ticket_cache_json()
            .context("service-ticket cache JSON renders")?;
        assert_eq!(
            service_tickets,
            r#"[
  {
    "SPN": "HTTP/host.test.gokrb5",
    "AuthTime": "2030-01-02T03:04:05Z",
    "StartTime": "2030-01-02T03:04:06Z",
    "EndTime": "2030-01-02T05:04:06Z",
    "RenewTill": "2030-01-08T03:04:06Z"
  }
]"#
        );
        Ok(())
    }

    /// Pins that updating a ccache file replaces tickets instead of duplicating them.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_updates_ccache_file_without_duplicate_tickets() -> Result<(), TestError> {
        let tgt = sample_tgt_session()?;
        let service_ticket = sample_service_ticket_session(&tgt)?;
        let mut client = Tokio::from_tgt_session(Config::new(), KdcProtocol::Tcp, tgt.clone());
        client.cache_service_ticket(service_ticket.clone())?;

        let mut old_tgt = tgt.to_ccache_credential().context("TGT converts")?;
        old_tgt.client.name_type = 0_i32;
        old_tgt.key.value = vec![0xaa];
        let mut old_service = service_ticket
            .to_ccache_credential()
            .context("service ticket converts")?;
        old_service.client.name_type = 0_i32;
        old_service.key.value = vec![0xbb];
        let config_entry = x_cacheconf_credential(&old_service.client);
        let mut other_client = old_service.clone();
        other_client.client = ccache::Principal::new("OTHER.REALM", 1, vec!["other".to_owned()]);
        other_client.server = ccache::Principal::new(
            "OTHER.REALM",
            2,
            vec!["HTTP".to_owned(), "other".to_owned()],
        );

        let mut existing = ccache::CCache::new(old_tgt.client.clone());
        existing.credentials_mut().push(old_tgt);
        existing.credentials_mut().push(config_entry.clone());
        existing.credentials_mut().push(old_service);
        existing.credentials_mut().push(other_client.clone());

        let path = temp_client_ccache_file("update-file")?;
        existing.save(&path).context("existing ccache saves")?;
        let name = format!("FILE:{}", path.display());
        client
            .update_ccache_name(&name)
            .context("client updates ccache name")?;
        let updated = ccache::CCache::load(&path).context("updated ccache loads")?;
        fs::remove_file(&path).context("remove the test file")?;

        assert_eq!(updated.default_principal().components, ["testuser1"]);
        assert_eq!(
            updated
                .credentials()
                .iter()
                .filter(|credential| credential.client == config_entry.client
                    && credential.server.components == ["krb5_ccache_conf_data", "fast_avail"])
                .count(),
            1
        );
        assert!(updated.credentials().contains(&other_client));
        assert_eq!(
            matching_credentials(
                &updated,
                &ccache::Principal::new(
                    "TEST.GOKRB5",
                    2,
                    vec!["krbtgt".to_owned(), "TEST.GOKRB5".to_owned()]
                )
            )
            .len(),
            1
        );
        assert_eq!(
            matching_credentials(
                &updated,
                &ccache::Principal::new(
                    "TEST.GOKRB5",
                    2,
                    vec!["HTTP".to_owned(), "host.test.gokrb5".to_owned()]
                )
            )
            .len(),
            1
        );
        assert_eq!(
            updated
                .get_entry(&["krbtgt", "TEST.GOKRB5"])
                .context("updated TGT exists")?
                .key
                .value,
            tgt.session_key.value
        );
        assert_eq!(
            updated
                .get_entry(&["HTTP", "host.test.gokrb5"])
                .context("updated service ticket exists")?
                .key
                .value,
            service_ticket.session_key.value
        );
        Ok(())
    }

    /// A counting KDC: its serving task, then the AS-REQ and TGS-REQ counts.
    #[cfg(feature = "tokio")]
    type CountingKdc = (
        JoinHandle<Result<(), TestError>>,
        Arc<AtomicUsize>,
        Arc<AtomicUsize>,
    );

    /// Pins that cached service tickets are found and replaced regardless of host case.
    #[cfg(feature = "tokio")]
    #[test]
    fn cached_service_ticket_identity_is_case_folded() -> Result<(), TestError> {
        let tgt = sample_tgt_session()?;
        let now = timestamp(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
        let session_for = |host: &str| -> Result<_, TestError> {
            let mut ticket = sample_service_ticket_session(&tgt)?;
            ticket.service = Principal::host_based_service_in_realm("HTTP", host, "CERN.CH")?;
            align_ticket_service(&mut ticket)?;
            ticket.start_time = now
                .checked_sub(Duration::from_mins(1))
                .ok_or("start time")?;
            ticket.end_time = now.checked_add(Duration::from_hours(1)).ok_or("end time")?;
            Ok(ticket)
        };
        let mut client = Tokio::from_tgt_session(Config::new(), KdcProtocol::Tcp, tgt.clone());
        client.cache_service_ticket(session_for("auth.cern.ch")?)?;

        assert!(
            client
                .cached_service_ticket(Principal::host_based_service_in_realm(
                    "HTTP",
                    "AUTH.CERN.CH",
                    "CERN.CH"
                )?)
                .is_some()
        );
        client.cache_service_ticket(session_for("Auth.Cern.CH")?)?;
        assert_eq!(client.cached_service_ticket_count(), 1);
        Ok(())
    }

    /// Pins that auto-renewal paces a due, non-renewable TGT on a cache-only client.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_auto_renewal_paces_cache_only_nonrenewable_tgt() -> Result<(), TestError> {
        let (done, finished) = mpsc::channel();
        drop(thread::spawn(move || -> Result<(), TestError> {
            let runtime = RuntimeBuilder::new_current_thread()
                .enable_all()
                .start_paused(true)
                .build()?;
            runtime.block_on(async move {
                // Due (55 min old, 5 min left) but not renewable, and cache-only:
                // the refresh is a successful no-op that must be paced.
                let mut tgt = current_tgt_session(55, 5)?;
                tgt.renew_till = None;
                let client = Arc::new(Mutex::new(Tokio::from_tgt_session(
                    Config::new(),
                    KdcProtocol::Tcp,
                    tgt,
                )));
                let renewal =
                    Tokio::spawn_auto_renewal_with_retry(client, Duration::from_millis(50));

                // With auto-advanced paused time, a paced loop lets this sleep
                // complete; a spinning loop keeps the runtime busy instead.
                sleep(Duration::from_mins(10)).await;
                renewal.abort();
                done.send(())?;
                Ok::<(), TestError>(())
            })?;
            Ok(())
        }));

        finished
            .recv_timeout(Duration::from_secs(10))
            .map_err(|error| format!("the auto-renewal loop paces instead of spinning: {error}"))?;
        Ok(())
    }

    /// Pins that the refresh band follows the current ticket life, not `auth_time`.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_refresh_due_uses_current_ticket_life() -> Result<(), TestError> {
        let now = SystemTime::now();
        let mut renewed = current_tgt_session(60 * 60, 10 * 60)?;
        renewed.start_time = now
            .checked_sub(Duration::from_mins(1))
            .ok_or("recent start time")?;

        let renewed_client =
            Tokio::from_tgt_session(Config::new(), KdcProtocol::Tcp, renewed.clone());
        assert!(
            !renewed_client.tgt_refresh_due(),
            "a ticket renewed 60 s ago with 10 h left is not due from a 60 h old auth_time"
        );

        let mut near_end = renewed;
        near_end.end_time = now
            .checked_add(Duration::from_secs(10))
            .ok_or("near end time")?;
        near_end.key_expiration = Some(near_end.end_time);
        let near_end_client = Tokio::from_tgt_session(Config::new(), KdcProtocol::Tcp, near_end);
        assert!(
            near_end_client.tgt_refresh_due(),
            "the current life, not auth_time, drives the refresh band"
        );
        Ok(())
    }

    /// Counting KDC that refuses every TGS-REQ with `KDC_ERR_TKT_EXPIRED`.
    #[cfg(feature = "tokio")]
    fn spawn_counting_kdc(
        listener: TcpListener,
        client_principal: Principal,
        password: Vec<u8>,
    ) -> CountingKdc {
        spawn_counting_kdc_with_tgs_reply(listener, client_principal, password, |_, _, _| {
            krb_error_bytes(32)
        })
    }

    /// Counting KDC that answers each TGS-REQ through `tgs_reply`, which receives
    /// the decoded request, its DER and the number of AS-REQs served before it.
    #[cfg(feature = "tokio")]
    fn spawn_counting_kdc_with_tgs_reply<F>(
        listener: TcpListener,
        client_principal: Principal,
        password: Vec<u8>,
        tgs_reply: F,
    ) -> CountingKdc
    where
        F: Fn(rasn_kerberos::TgsReq, &[u8], usize) -> Result<Vec<u8>, TestError> + Send + 'static,
    {
        let as_requests = Arc::new(AtomicUsize::new(0));
        let tgs_requests = Arc::new(AtomicUsize::new(0));
        let as_count = Arc::clone(&as_requests);
        let tgs_count = Arc::clone(&tgs_requests);
        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return Ok::<(), TestError>(());
                };
                let mut header = [0_u8; 4];
                if socket.read_exact(&mut header).await.is_err() {
                    continue;
                }
                let mut body = vec![0_u8; usize::try_from(u32::from_be_bytes(header))?];
                if socket.read_exact(&mut body).await.is_err() {
                    continue;
                }
                let reply = match body.first().copied() {
                    // AS-REQ and TGS-REQ application tags.
                    Some(0x6a) => {
                        let _: usize = as_count.fetch_add(1, Ordering::SeqCst);
                        let decoded: rasn_kerberos::AsReq = der::decode(&body)?;
                        let built = built_request_from_der(decoded, &body)?;
                        let reply_key = derive_password_reply_key(
                            &client_principal,
                            &password,
                            &password_key_info(),
                        )?;
                        synthetic_as_rep_with_reply_key(
                            &built,
                            built.nonce,
                            &built.service,
                            &reply_key,
                        )?
                    }
                    Some(0x6c) => {
                        let _: usize = tgs_count.fetch_add(1, Ordering::SeqCst);
                        let decoded: rasn_kerberos::TgsReq = der::decode(&body)?;
                        tgs_reply(decoded, &body, as_count.load(Ordering::SeqCst))?
                    }
                    _ => continue,
                };
                let mut response = Vec::with_capacity(reply.len().saturating_add(4));
                response.extend_from_slice(&u32::try_from(reply.len())?.to_be_bytes());
                response.extend_from_slice(&reply);
                // A client that hung up gets no reply; keep serving the next one.
                socket.write_all(&response).await.unwrap_or_default();
            }
        });
        (handle, as_requests, tgs_requests)
    }

    /// DER of a KRB-ERROR from the test realm's TGS with `error_code`.
    #[cfg(feature = "tokio")]
    fn krb_error_bytes(error_code: i32) -> Result<Vec<u8>, TestError> {
        let error = rasn_kerberos::KrbError {
            pvno: Integer::from(5_i32),
            msg_type: Integer::from(30_i32),
            ctime: None,
            cusec: None,
            stime: kerberos_time(1_893_553_440)?,
            susec: Integer::from(0_i32),
            error_code,
            crealm: Some(realm("TEST.GOKRB5")?),
            cname: Some(rasn_principal(&Principal::user(
                "TEST.GOKRB5",
                "testuser1",
            ))?),
            realm: realm("TEST.GOKRB5")?,
            sname: rasn_principal(&Principal::tgt_service("TEST.GOKRB5"))?,
            e_text: None,
            e_data: None,
        };
        Ok(der::encode(&error)?)
    }

    /// A TGT that expired a minute ago but stays renewable for another hour.
    #[cfg(feature = "tokio")]
    fn expired_renewable_tgt() -> Result<AsRepSession, TestError> {
        let now = SystemTime::now();
        let mut tgt = current_tgt_session(120, 0)?;
        tgt.renew_till = Some(
            now.checked_add(Duration::from_hours(1))
                .ok_or("renew till")?,
        );
        Ok(tgt)
    }

    /// Pins that `affirm_login` with an expired renewable TGT and a password uses AS only.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_affirm_login_falls_back_to_as_for_expired_renewable_tgt()
    -> Result<(), TestError> {
        runtime()?.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            let client_principal = Principal::user("TEST.GOKRB5", "testuser1");
            let (kdc, as_requests, tgs_requests) = spawn_counting_kdc(
                listener,
                client_principal.clone(),
                TESTUSER_PASSWORD.to_vec(),
            );

            let mut client = Tokio::from_tgt_session(
                config_with_kdc_server(&addr.to_string())?,
                KdcProtocol::Tcp,
                expired_renewable_tgt()?,
            )
            .with_password_credential(TESTUSER_PASSWORD);

            let _: &AsRepSession = client.affirm_login().await?;
            assert!(as_requests.load(Ordering::SeqCst) >= 1);
            assert_eq!(
                tgs_requests.load(Ordering::SeqCst),
                0,
                "an expired TGT with a credential goes straight to the AS exchange"
            );
            kdc.abort();
            Ok::<(), TestError>(())
        })
    }

    /// Pins that `refresh_tgt_if_needed` with an expired renewable TGT skips the renewal.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_refresh_tgt_if_needed_falls_back_to_as_for_expired_renewable_tgt()
    -> Result<(), TestError> {
        runtime()?.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            let client_principal = Principal::user("TEST.GOKRB5", "testuser1");
            let (kdc, as_requests, tgs_requests) = spawn_counting_kdc(
                listener,
                client_principal.clone(),
                TESTUSER_PASSWORD.to_vec(),
            );

            let mut client = Tokio::from_tgt_session(
                config_with_kdc_server(&addr.to_string())?,
                KdcProtocol::Tcp,
                expired_renewable_tgt()?,
            )
            .with_password_credential(TESTUSER_PASSWORD);

            let _: &AsRepSession = client.refresh_tgt_if_needed().await?;
            assert!(as_requests.load(Ordering::SeqCst) >= 1);
            assert_eq!(
                tgs_requests.load(Ordering::SeqCst),
                0,
                "expired renewable TGTs do not spend a doomed TGS renewal first"
            );
            kdc.abort();
            Ok::<(), TestError>(())
        })
    }

    /// Pins that a cache-only expired TGT is unavailable without any network renewal.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_cache_only_expired_tgt_is_unavailable_without_network() -> Result<(), TestError>
    {
        runtime()?.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            let client_principal = Principal::user("TEST.GOKRB5", "testuser1");
            let (kdc, as_requests, tgs_requests) = spawn_counting_kdc(
                listener,
                client_principal.clone(),
                TESTUSER_PASSWORD.to_vec(),
            );

            let mut client = Tokio::from_tgt_session(
                config_with_kdc_server(&addr.to_string())?,
                KdcProtocol::Tcp,
                expired_renewable_tgt()?,
            );

            assert!(matches!(
                client.affirm_login().await,
                Err(Error::NoClientCredentials)
            ));
            assert_eq!(as_requests.load(Ordering::SeqCst), 0);
            assert_eq!(
                tgs_requests.load(Ordering::SeqCst),
                0,
                "expired cache-only credentials never attempt renewal"
            );
            kdc.abort();
            Ok::<(), TestError>(())
        })
    }

    /// Run `test` on a paused current-thread runtime in its own thread and return
    /// its report, failing after 10 s of real time so a spinning loop cannot hang.
    #[cfg(feature = "tokio")]
    fn run_on_paused_runtime<T, F, Fut>(test: F) -> Result<T, TestError>
    where
        T: Send + 'static,
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = T>,
    {
        let (done, finished) = mpsc::channel();
        drop(thread::spawn(move || {
            let report = RuntimeBuilder::new_current_thread()
                .enable_all()
                .start_paused(true)
                .build()
                .map(|runtime| runtime.block_on(test()));
            done.send(report)
        }));
        let report = finished
            .recv_timeout(Duration::from_secs(10))
            .map_err(|error| {
                format!("the paused-clock test reports within 10 s of real time: {error}")
            })?;
        Ok(report?)
    }

    /// Whether `request` asks for a renewal (the `renew` KDC option is set).
    #[cfg(feature = "tokio")]
    fn is_renewal_request(request: &rasn_kerberos::TgsReq) -> bool {
        <[u8; 4]>::try_from(request.0.req_body.kdc_options.0.as_raw_slice())
            .is_ok_and(|options| u32::from_be_bytes(options) & KDC_OPTION_RENEW != 0)
    }

    /// Seconds from the Unix epoch to `time`.
    #[cfg(feature = "tokio")]
    fn unix_seconds(time: SystemTime) -> Result<u64, TestError> {
        Ok(time.duration_since(UNIX_EPOCH)?.as_secs())
    }

    /// TGS-REP DER renewing the primary TGT the way RFC 4120 renewal does.
    ///
    /// `auth_time` stays 60 h old while `start_time` restarts a 10 h ticket life now.
    /// The session key is unchanged, so every later renewal decrypts with it too.
    #[cfg(feature = "tokio")]
    fn renewed_tgt_reply_keeping_auth_time(
        request: rasn_kerberos::TgsReq,
        der: &[u8],
    ) -> Result<Vec<u8>, TestError> {
        let built = built_tgs_request_from_der(request, der)?;
        let now = unix_seconds(SystemTime::now())?;
        let session_key = EncryptionKey::new(18, decode_hex(SESSION_KEY)?);
        let enc_part = rasn_kerberos::EncTgsRepPart(rasn_kerberos::EncKdcRepPart {
            key: rasn_encryption_key(&session_key),
            last_req: vec![rasn_kerberos::LastReqValue {
                r#type: 0,
                value: kerberos_time(now)?,
            }],
            nonce: built.nonce,
            key_expiration: None,
            flags: rasn_kerberos::TicketFlags(rasn_kerberos::KerberosFlags::from_slice(
                TICKET_FLAGS,
            )),
            auth_time: kerberos_time(now.checked_sub(60 * 60 * 60).ok_or("auth time")?)?,
            start_time: Some(kerberos_time(now)?),
            end_time: kerberos_time(now.checked_add(10 * 60 * 60).ok_or("end time")?)?,
            renew_till: Some(kerberos_time(
                now.checked_add(7 * 24 * 60 * 60).ok_or("renew till")?,
            )?),
            srealm: realm(&built.service.realm)?,
            sname: rasn_principal(&built.service)?,
            caddr: None,
            encrypted_pa_data: None,
        });
        let encrypted = encrypt_message(
            &session_key,
            &der::encode(&enc_part)?,
            TGS_REP_ENCPART_SESSION_KEY_USAGE,
            TGS_REP_CONFOUNDER,
        )?;
        let tgs_rep = rasn_kerberos::TgsRep(rasn_kerberos::KdcRep {
            pvno: Integer::from(5_i32),
            msg_type: Integer::from(13_i32),
            padata: None,
            crealm: realm(&built.client.realm)?,
            cname: rasn_principal(&built.client)?,
            ticket: rasn_kerberos::Ticket {
                tkt_vno: Integer::from(5_i32),
                realm: realm(&built.service.realm)?,
                sname: rasn_principal(&built.service)?,
                enc_part: rasn_kerberos::EncryptedData {
                    etype: 18,
                    kvno: Some(2),
                    cipher: [0xde, 0xad, 0xbe, 0xef].as_slice().into(),
                },
            },
            enc_part: rasn_kerberos::EncryptedData {
                etype: session_key.etype,
                kvno: None,
                cipher: encrypted.into(),
            },
        });
        Ok(der::encode(&tgs_rep)?)
    }

    /// After a renewal that keeps an old `auth_time`, auto-renewal measures the
    /// refresh band from the renewed ticket's own life and sleeps instead of
    /// renewing again.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_auto_renewal_paces_after_renewal() -> Result<(), TestError> {
        let (as_requests, renewal_requests) = run_on_paused_runtime(async || {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            let (kdc, as_requests, tgs_requests) = spawn_counting_kdc_with_tgs_reply(
                listener,
                Principal::user("TEST.GOKRB5", "testuser1"),
                TESTUSER_PASSWORD.to_vec(),
                |request, der, _| renewed_tgt_reply_keeping_auth_time(request, der),
            );

            // Due (55 min old, 5 min left) and renewable; cache-only, so only a
            // renewal can refresh it.
            let client = Arc::new(Mutex::new(Tokio::from_tgt_session(
                config_with_kdc_server(&addr.to_string())?,
                KdcProtocol::Tcp,
                current_tgt_session(55, 5)?,
            )));
            let renewal = Tokio::spawn_auto_renewal(Arc::clone(&client));

            // Spin without timers until the first renewal is installed: an idle
            // paused runtime auto-advances the clock while loopback I/O is still
            // in flight, which would fire the transport timeout.
            let renewed_life_floor = Duration::from_hours(1);
            loop {
                let renewed = tgs_requests.load(Ordering::SeqCst) >= 1
                    && client.try_lock().is_ok_and(|guard| {
                        guard.tgt_session().is_some_and(|tgt| {
                            tgt.end_time
                                .duration_since(SystemTime::now())
                                .is_ok_and(|left| left > renewed_life_floor)
                        })
                    });
                if renewed {
                    break;
                }
                yield_now().await;
            }

            // 600 s of virtual time in 1 s steps; a loop that still treats the
            // renewed ticket as due renews again on every step.
            for _ in 0_u16..600 {
                sleep(Duration::from_secs(1)).await;
            }
            renewal.abort();
            kdc.abort();
            Ok::<_, TestError>((
                as_requests.load(Ordering::SeqCst),
                tgs_requests.load(Ordering::SeqCst),
            ))
        })??;

        assert_eq!(as_requests, 0, "a cache-only client never logs in");
        assert_eq!(
            renewal_requests, 1,
            "a renewal with a fresh 10 h life is not due again within 600 s"
        );
        Ok(())
    }

    /// When the KDC refuses to renew a due TGT, auto-renewal with a configured
    /// password falls back to a fresh AS exchange instead of retrying the renewal.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_auto_renewal_uses_as_when_renewal_refused() -> Result<(), TestError> {
        let (as_requests, renewal_requests) = run_on_paused_runtime(async || {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            let (kdc, as_requests, tgs_requests) = spawn_counting_kdc(
                listener,
                Principal::user("TEST.GOKRB5", "testuser1"),
                TESTUSER_PASSWORD.to_vec(),
            );

            // The paused clock auto-advances while loopback I/O is in flight, so
            // keep the transport timeout beyond the 600 s window: the renewal must
            // fail on the KDC's refusal, not on a virtual timeout.
            let client = Arc::new(Mutex::new(
                Tokio::from_tgt_session(
                    config_with_kdc_server(&addr.to_string())?,
                    KdcProtocol::Tcp,
                    current_tgt_session(55, 5)?,
                )
                .with_password_credential(TESTUSER_PASSWORD)
                .with_transport(TokioKdcTransport::new().with_timeout(Duration::from_hours(24))),
            ));
            let renewal = Tokio::spawn_auto_renewal(client);

            for _ in 0_u16..600 {
                if as_requests.load(Ordering::SeqCst) >= 1 {
                    break;
                }
                sleep(Duration::from_secs(1)).await;
            }
            renewal.abort();
            kdc.abort();
            Ok::<_, TestError>((
                as_requests.load(Ordering::SeqCst),
                tgs_requests.load(Ordering::SeqCst),
            ))
        })??;

        assert!(
            renewal_requests >= 1,
            "the due TGT is offered for renewal first"
        );
        assert!(
            as_requests >= 1,
            "a refused renewal falls back to the AS exchange within 600 s"
        );
        Ok(())
    }

    /// `get_service_ticket` with an expired renewable TGT and a password skips the
    /// renewal a conforming KDC refuses, logs in through AS, then requests the
    /// service ticket with the fresh TGT.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_get_service_ticket_falls_back_to_as_for_expired_renewable_tgt()
    -> Result<(), TestError> {
        runtime()?.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            let tgt_session_key = EncryptionKey::new(18, decode_hex(SESSION_KEY)?);
            let (kdc, as_requests, tgs_requests) = spawn_counting_kdc_with_tgs_reply(
                listener,
                Principal::user("TEST.GOKRB5", "testuser1"),
                TESTUSER_PASSWORD.to_vec(),
                move |request, der, as_requests_before| {
                    // KDC_ERR_TKT_EXPIRED for a renewal of the expired TGT, and for
                    // a service request that did not follow the AS exchange.
                    if is_renewal_request(&request) || as_requests_before == 0 {
                        return krb_error_bytes(32);
                    }
                    let built = built_tgs_request_from_der(request, der)?;
                    synthetic_tgs_rep(&built, built.nonce, &tgt_session_key)
                },
            );

            let mut client = Tokio::from_tgt_session(
                config_with_kdc_server(&addr.to_string())?,
                KdcProtocol::Tcp,
                expired_renewable_tgt()?,
            )
            .with_password_credential(TESTUSER_PASSWORD);

            let ticket = client
                .get_service_ticket(sample_service_principal())
                .await?;
            assert_eq!(ticket.service, sample_service_principal());
            assert_eq!(as_requests.load(Ordering::SeqCst), 1);
            assert_eq!(
                tgs_requests.load(Ordering::SeqCst),
                1,
                "only the service TGS-REQ follows the AS exchange; no doomed renewal"
            );
            kdc.abort();
            Ok::<(), TestError>(())
        })
    }

    /// Pins that service realm resolution folds the DNS case of `domain_realm` hosts.
    #[cfg(feature = "tokio")]
    #[test]
    fn service_realm_resolution_folds_dns_case() -> Result<(), TestError> {
        let config = Config::parse(
            "
[libdefaults]
 default_realm = CLIENT.REALM

[domain_realm]
 .example.com = PARTNER.REALM
",
        )?;
        let tgt = sample_tgt_session()?;
        let mut service_ticket = sample_service_ticket_session(&tgt)?;
        let now = timestamp(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
        service_ticket.start_time = now
            .checked_sub(Duration::from_mins(1))
            .ok_or("start time")?;
        service_ticket.end_time = now.checked_add(Duration::from_hours(1)).ok_or("end time")?;
        service_ticket.service = Principal::new("PARTNER.REALM", 2, ["HTTP", "Host.Example.COM"]);
        align_ticket_service(&mut service_ticket)?;

        let mut client = Tokio::from_tgt_session(config, KdcProtocol::Tcp, tgt);
        client.cache_service_ticket(service_ticket.clone())?;

        let lookup = Principal::new("", 2, ["HTTP", "Host.Example.COM"]);
        let cached = client
            .cached_service_ticket(lookup)
            .ok_or("mixed-case host resolves to the partner realm")?;
        assert_eq!(cached.service.realm, "PARTNER.REALM");
        assert_eq!(cached.ticket, service_ticket.ticket);
        Ok(())
    }
}

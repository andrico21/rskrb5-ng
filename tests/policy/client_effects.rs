use core::error::Error;
use std::time::SystemTime;

use rskrb5_ng::{
    Config,
    ccache::{CCache, Principal as CachePrincipal},
    client::{
        self, Tokio,
        options::{ApReq, AsReq},
        principal::Principal,
        transport::KdcProtocol,
    },
    crypto::{CryptoPolicy, Use},
    error::{Client as ClientError, Config as ConfigError, Policy},
    keytab::Keytab,
};
use tokio::runtime::Builder;

use super::client::{policy_cause, session};

/// AES128-only config never uses an AES256 ccache ticket, including for SPNEGO.
#[test]
fn excluded_ccache_never_reaches_ap_or_network() -> Result<(), Box<dyn Error>> {
    // Given a usable-time AES256 credential for the correct identity.
    let mut cache = CCache::new(CachePrincipal::new(
        "EXAMPLE.COM",
        1,
        vec!["alice".to_owned()],
    ));
    drop(cache.upsert_credential(session(18, 18)?.to_ccache_credential()?));
    let config = Config::parse("[libdefaults]\npermitted_enctypes = aes128-cts")?;
    // When importing through checked and legacy constructors.
    let error = Tokio::try_from_ccache(config.clone(), KdcProtocol::Tcp, &cache)
        .err()
        .ok_or("excluded import accepted")?;
    assert!(matches!(
        policy_cause(&error),
        Some(Policy::EnctypeNotPermitted {
            etype: 18_i32,
            usage: Use::ImportedCredential
        })
    ));
    let mut client = Tokio::from_ccache(config, KdcProtocol::Tcp, &cache);
    let runtime = Builder::new_current_thread().enable_all().build()?;
    let use_error = runtime
        .block_on(client.get_service_ticket(Principal::new("EXAMPLE.COM", 2, ["HTTP", "host"])))
        .err()
        .ok_or("excluded cache used")?;
    // Then failure remains policy, not endpoint discovery or credential absence.
    assert!(matches!(
        policy_cause(&use_error),
        Some(Policy::EnctypeNotPermitted {
            etype: 18_i32,
            usage: Use::ImportedCredential
        })
    ));
    assert_eq!(client.cached_service_ticket_count(), 0);
    Ok(())
}

/// Explicit AP policy rejects excluded sessions before confounder validation.
#[test]
fn ap_request_checks_session_and_ticket() -> Result<(), Box<dyn Error>> {
    // Given independent excluded session-key and ticket-key cases.
    for (session_id, ticket_id, usage) in [
        (18_i32, 17_i32, Use::SessionKey),
        (17_i32, 18_i32, Use::TicketKey),
    ] {
        let config = Config::parse("[libdefaults]\npermitted_enctypes = aes128-cts")?;
        let mut options = ApReq::new();
        options.set_crypto_policy(Some(CryptoPolicy::from_libdefaults(&config.libdefaults)?));
        // When building with deliberately invalid crypto inputs.
        let error = client::build_ap_req_with_confounder(
            &session(session_id, ticket_id)?,
            options,
            SystemTime::UNIX_EPOCH,
            0,
            &[],
        )
        .err()
        .ok_or("excluded AP built")?;
        // Then the exact policy use fails first.
        assert!(
            matches!(policy_cause(&error), Some(Policy::EnctypeNotPermitted { etype: 18_i32, usage: actual }) if *actual == usage)
        );
    }
    Ok(())
}

/// Invalid configured policy blocks cache admission even when the explicit flag is false.
#[test]
fn empty_allowlist_cannot_admit_credentials() -> Result<(), Box<dyn Error>> {
    // Given a programmatically emptied permitted list.
    let mut config = Config::new();
    config.libdefaults.permitted_enctypes.clear();
    let mut client = Tokio::with_keytab(
        config,
        KdcProtocol::Tcp,
        Principal::user("EXAMPLE.COM", "alice"),
        Keytab::new(),
    );
    // When admitting an otherwise supported session.
    let error = client
        .cache_service_ticket(session(18, 18)?)
        .err()
        .ok_or("empty allowlist admitted cache")?;
    // Then invalid configuration is a typed permanent operational failure.
    assert!(matches!(
        error,
        ClientError::Config(ConfigError::EmptyEnctypeExpression)
    ));
    Ok(())
}

/// Both password and keytab optimistic preauth stop before calling transport.
#[test]
fn preauth_cannot_use_overridden_excluded_request() -> Result<(), Box<dyn Error>> {
    // Given a configured AES128 policy overridden to request AES256.
    let config = Config::parse("[libdefaults]\npermitted_enctypes = aes128-cts")?;
    let options = AsReq::from_libdefaults(SystemTime::now(), 1, &config.libdefaults)?
        .with_etypes(vec![18_i32])
        .with_assume_preauthentication(true);
    let principal = Principal::user("EXAMPLE.COM", "alice");
    // When attempting either credential source with a counting transport.
    let mut transport = CountingTransport(0);
    let password_error = client::login_tgt_with_password(
        &mut transport,
        principal.clone(),
        b"password",
        options.clone(),
    )
    .err()
    .ok_or("excluded preauth accepted")?;
    let keytab_error =
        client::login_tgt_with_keytab(&mut transport, principal, &Keytab::new(), options)
            .err()
            .ok_or("excluded keytab preauth accepted")?;
    // Then both fail by policy with zero sends.
    assert!(matches!(
        policy_cause(&password_error),
        Some(Policy::EnctypeNotPermitted {
            usage: Use::RequestList,
            etype: 18_i32
        })
    ));
    assert!(matches!(
        policy_cause(&keytab_error),
        Some(Policy::EnctypeNotPermitted {
            usage: Use::RequestList,
            etype: 18_i32
        })
    ));
    assert_eq!(transport.0, 0);
    Ok(())
}

/// Count attempted sends without providing any network capability.
struct CountingTransport(usize);
impl client::KdcTransport for CountingTransport {
    fn send(&mut self, _realm: &str, _request: &[u8]) -> Result<Vec<u8>, ClientError> {
        self.0 = self.0.saturating_add(1);
        Err(ClientError::Transport("unexpected send".to_owned()))
    }
}

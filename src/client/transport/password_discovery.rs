//! Configured password endpoint selection.

use super::{Config, Error, KdcEndpoint, KdcProtocol, Tokio};
use crate::{config::restrictions, error::Config as ConfigError};

/// Prefer configured password servers, using DNS only when enabled.
///
/// # Errors
/// Returns configuration, endpoint parsing or DNS discovery errors.
///
/// # Cancel safety
/// cancel-safe: discovery reads configuration and DNS without mutating credentials.
pub(super) async fn discover(
    transport: &Tokio,
    config: &Config,
    realm: &str,
    protocol: KdcProtocol,
) -> Result<Vec<KdcEndpoint>, Error> {
    restrictions::config(config)?;
    if let Some(realm_entry) = config.realm(realm)
        && !realm_entry.kpasswd_server.is_empty()
    {
        return realm_entry
            .kpasswd_server
            .iter()
            .map(|value| KdcEndpoint::configured_with_default_port(protocol, value, 464))
            .collect();
    }

    if config.libdefaults.dns_lookup_kdc.is_enabled() {
        return transport
            .discover_kpasswd_servers_with_dns(realm, protocol)
            .await;
    }

    match config.realm(realm) {
        Some(_) => Err(ConfigError::NoKpasswdServer(realm.to_owned()).into()),
        None => Err(ConfigError::NoRealm(realm.to_owned()).into()),
    }
}

/// Configuration-only discovery boundaries.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error::Error as StdError;

    use super::{Config, Error, KdcProtocol, Tokio};
    use crate::error::Config as ConfigError;

    /// Missing realms and emptied lists preserve exact configuration errors.
    #[tokio::test]
    async fn configured_password_errors_are_precise() -> Result<(), Box<dyn StdError>> {
        // Given DNS-disabled configuration with no realm.
        let mut config = Config::parse("[libdefaults]\ndns_lookup_kdc = false\n")?;
        let transport = Tokio::new();
        // When discovery runs, then absence is not silently replaced by a fallback.
        assert!(
            matches!(transport.discover_kpasswd_servers(&config, "TEST.GOKRB5", KdcProtocol::Tcp).await,
            Err(Error::Config(ConfigError::NoRealm(realm))) if realm == "TEST.GOKRB5")
        );
        config = Config::parse(
            "[libdefaults]\ndns_lookup_kdc = false\n[realms]\nTEST.GOKRB5 = {\nkpasswd_server = 127.0.0.1:1464\n}\n",
        )?;
        config
            .realms
            .first_mut()
            .ok_or("fixture realm")?
            .kpasswd_server
            .clear();
        assert!(
            matches!(transport.discover_kpasswd_servers(&config, "TEST.GOKRB5", KdcProtocol::Tcp).await,
            Err(Error::Config(ConfigError::NoKpasswdServer(realm))) if realm == "TEST.GOKRB5")
        );
        Ok(())
    }
}

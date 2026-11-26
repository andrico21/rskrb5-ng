//! Password changes to located servers keep the A8 delivery rules (MIT-plugin-6).
//!
//! TCP goes first, and a request that may have been delivered is never repeated
//! over UDP.

extern crate alloc;

use alloc::sync::Arc;

use rskrb5_ng::extensions::{
    Extension, LocateRequest, LocateService, ProviderError, Registry, ServerAddress, ServerLocator,
};

use super::{
    kpasswd_order::{REQUEST, assert_no_datagram, closed_port, describe},
    *,
};

/// A locator that names one loopback port for every password-change request.
struct Kpasswd(u16);

impl ServerLocator for Kpasswd {
    fn id(&self) -> &'static str {
        "kpasswd"
    }

    fn locate(
        &self,
        request: &LocateRequest<'_>,
    ) -> Result<Option<Vec<ServerAddress>>, ProviderError> {
        Ok((request.service == LocateService::Kpasswd)
            .then(|| vec![ServerAddress::new("127.0.0.1", self.0)]))
    }
}

/// A transport whose registry holds a [`Kpasswd`] locator for `port`.
fn located(port: u16) -> Result<Tokio, TestError> {
    let mut registry = Registry::new();
    registry.register(Extension::ServerLocator(Arc::new(Kpasswd(port))))?;
    Ok(Tokio::new()
        .with_timeout(Duration::from_millis(300))
        .with_registry(Arc::new(registry)))
}

/// A located password server that may have received the request leaves the
/// outcome unknown, and the UDP side of the same server receives nothing.
#[test]
fn kpasswd_locator_preserves_delivery_rules() -> Result<(), TestError> {
    runtime()?.block_on(async {
        // Given a realm the profile does not know, and a locator that names a TCP
        // server which reads the request and drops the connection.
        let (listener, udp) = bind_tcp_and_udp_pair().await?;
        let transport = located(udp.local_addr()?.port())?;
        let config = Config::parse("[libdefaults]\ndns_lookup_kdc = false\n")?;
        let server = tokio::spawn(async move {
            let (request, socket) = read_tcp_request(&listener).await?;
            drop(socket);
            Ok::<_, io::Error>(request)
        });
        // When the Auto password change runs.
        let result = transport
            .send_to_kpasswd_realm(&config, KdcProtocol::Auto, "LOCATED.TEST", REQUEST)
            .await;
        // Then the located server got the request, the outcome is unknown, and
        // UDP is never tried.
        assert!(
            matches!(result, Err(ClientError::KpasswdOutcomeUnknown(_))),
            "expected KpasswdOutcomeUnknown, got {}",
            describe(&result)
        );
        assert_no_datagram(&udp, "located unknown TCP outcome").await;
        assert_eq!(
            bounded(Duration::from_secs(10), "TCP peer", server).await???,
            REQUEST
        );
        Ok(())
    })
}

/// An explicit TCP password change goes to the located server before the
/// profile's servers.
#[test]
fn kpasswd_locator_answers_before_the_profile() -> Result<(), TestError> {
    runtime()?.block_on(async {
        // Given a profile server that refuses and a located server that reads the request.
        let (listener, udp) = bind_tcp_and_udp_pair().await?;
        let transport = located(udp.local_addr()?.port())?;
        let config = Config::parse(&format!(
            "[libdefaults]\ndns_lookup_kdc = false\n[realms]\nTEST.GOKRB5 = {{\nkpasswd_server = {}\n}}\n",
            closed_port().await?
        ))?;
        let server = tokio::spawn(async move {
            let (request, socket) = read_tcp_request(&listener).await?;
            drop(socket);
            Ok::<_, io::Error>(request)
        });
        // When the TCP password change runs.
        let result = transport
            .send_to_kpasswd_realm(&config, KdcProtocol::Tcp, "TEST.GOKRB5", REQUEST)
            .await;
        // Then the located server, not the profile's, received it.
        assert!(
            matches!(result, Err(ClientError::KpasswdOutcomeUnknown(_))),
            "expected KpasswdOutcomeUnknown, got {}",
            describe(&result)
        );
        assert_eq!(
            bounded(Duration::from_secs(10), "TCP peer", server).await???,
            REQUEST
        );
        drop(udp);
        Ok(())
    })
}

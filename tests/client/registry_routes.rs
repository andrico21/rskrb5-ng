use super::*;

/// Registered host-realm mappers on the service-ticket routes (MIT-authz-6,
/// MIT-plugin-3): the realm of a service host comes from the transport's
/// registry before `[domain_realm]` and `default_realm`.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use alloc::sync::Arc;
    use std::sync::{Mutex, PoisonError};

    use rskrb5_ng::{
        error::KdcProxy,
        extensions::{Extension, HostRealm, ProviderError, RealmQuery, Registry},
        transport::{
            kkdcp::ProxyMessage,
            proxy::{KdcProxyTransport, PostFuture, Request},
        },
    };

    use super::*;

    /// The realm a mapper names for every host.
    const MAPPED: &str = "MAPPED.TEST";

    /// A KDC proxy that records each Kerberos message and refuses delivery.
    #[derive(Debug)]
    struct Recorder(Mutex<Vec<Vec<u8>>>);

    impl Recorder {
        /// A recorder that has seen nothing.
        const fn new() -> Self {
            Self(Mutex::new(Vec::new()))
        }

        /// The messages seen so far.
        fn seen(&self) -> Vec<Vec<u8>> {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }
    }

    impl KdcProxyTransport for Recorder {
        fn post<'request>(&'request self, request: Request<'request>) -> PostFuture<'request> {
            let message = ProxyMessage::decode(request.body).map_or_else(
                |_error| Vec::new(),
                |decoded| decoded.kerb_message().to_vec(),
            );
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(message);
            Box::pin(async { Err(KdcProxy::NotDelivered("recorded".into())) })
        }
    }

    /// A mapper that names [`MAPPED`] for every host, or fails.
    struct Mapper(Result<(), &'static str>);

    impl HostRealm for Mapper {
        fn id(&self) -> &'static str {
            "mapper"
        }

        fn realms(&self, _query: &RealmQuery<'_>) -> Result<Option<Vec<String>>, ProviderError> {
            match self.0 {
                Ok(()) => Ok(Some(vec![MAPPED.to_owned()])),
                Err(reason) => Err(reason.into()),
            }
        }
    }

    /// A transport through `proxy`, with a registry holding `mapper` when given.
    fn transport(
        proxy: &'static Recorder,
        mapper: Option<Mapper>,
    ) -> Result<TokioKdcTransport, TestError> {
        let plain = TokioKdcTransport::new().with_kdc_proxy(proxy);
        let Some(provider) = mapper else {
            return Ok(plain);
        };
        let mut registry = Registry::new();
        registry.register(Extension::HostRealm(Arc::new(provider)))?;
        Ok(plain.with_registry(Arc::new(registry)))
    }

    /// The client realm's KDC behind the recording proxy, a direct path to
    /// [`MAPPED`], and the client realm as `default_realm`.
    fn config() -> Result<Config, TestError> {
        Ok(Config::parse(&format!(
            "[libdefaults]\ndefault_realm = TEST.GOKRB5\ndns_lookup_kdc = false\n\
             [realms]\nTEST.GOKRB5 = {{\nkdc = https://kdc.test.gokrb5/\n\
             http_anchors = FILE:/etc/proxy-ca.pem\n}}\n\
             [capaths]\nTEST.GOKRB5 = {{\n{MAPPED} = .\n}}\n"
        ))?)
    }

    /// Whether `message` names the [`MAPPED`] realm anywhere.
    fn names_mapped(message: &[u8]) -> bool {
        message
            .windows(MAPPED.len())
            .any(|window| window == MAPPED.as_bytes())
    }

    /// A host service without a realm, as `Principal::host_based_service` makes it.
    fn web() -> Result<Principal, TestError> {
        Ok(Principal::host_based_service("host", "web.example")?)
    }

    /// The high-level client asks the registered mapper for the realm of a
    /// service host: the TGS request goes towards the mapped realm.
    #[test]
    fn service_ticket_route_uses_registered_hostrealm() -> Result<(), TestError> {
        static MAPPED_PROXY: Recorder = Recorder::new();
        static PLAIN_PROXY: Recorder = Recorder::new();
        runtime()?.block_on(async {
            for (proxy, mapper, expected) in [
                (&MAPPED_PROXY, Some(Mapper(Ok(()))), true),
                (&PLAIN_PROXY, None, false),
            ] {
                // Given a client with a current TGT for TEST.GOKRB5.
                let mut client = Tokio::from_tgt_session(
                    config()?,
                    KdcProtocol::Tcp,
                    current_tgt_session(1, 180)?,
                )
                .with_transport(transport(proxy, mapper)?);
                // When a ticket for a host service without a realm is requested.
                let result = client.get_service_ticket(web()?).await;
                // Then the request reached the client realm's KDC and names the
                // mapped realm exactly when the mapper is registered.
                assert!(result.is_err(), "the recording proxy delivers nothing");
                let seen = proxy.seen();
                assert_eq!(seen.len(), 1, "one TGS request");
                assert_eq!(
                    seen.iter().any(|message| names_mapped(message)),
                    expected,
                    "mapper registered: {expected}"
                );
            }
            Ok(())
        })
    }

    /// The transport's own service-ticket route maps an empty service realm
    /// through the registry too.
    #[test]
    fn transport_service_route_uses_registered_hostrealm() -> Result<(), TestError> {
        static PROXY: Recorder = Recorder::new();
        runtime()?.block_on(async {
            // Given a transport with a mapper and a current TGT.
            let tgt = current_tgt_session(1, 180)?;
            let config = config()?;
            let mapped = transport(&PROXY, Some(Mapper(Ok(()))))?;
            // When a ticket for a host service without a realm is requested.
            let result = mapped
                .get_service_ticket_with_referrals(
                    &config,
                    KdcProtocol::Tcp,
                    &tgt,
                    web()?,
                    TgsReq::new(SystemTime::now(), 9),
                )
                .await;
            // Then the TGS request names the mapped realm.
            assert!(result.is_err(), "the recording proxy delivers nothing");
            assert!(PROXY.seen().iter().any(|message| names_mapped(message)));
            Ok(())
        })
    }

    /// A failing mapper stops the acquisition before any request is sent.
    #[test]
    fn failing_hostrealm_stops_ticket_acquisition() -> Result<(), TestError> {
        static PROXY: Recorder = Recorder::new();
        runtime()?.block_on(async {
            // Given a client whose registered mapper fails.
            let mut client =
                Tokio::from_tgt_session(config()?, KdcProtocol::Tcp, current_tgt_session(1, 180)?)
                    .with_transport(transport(&PROXY, Some(Mapper(Err("mapper down"))))?);
            // When a ticket is requested.
            let result = client.get_service_ticket(web()?).await;
            // Then the mapper's failure is the error and nothing was sent.
            assert!(matches!(result, Err(Error::Locate(_))), "{result:?}");
            assert_eq!(PROXY.seen(), Vec::<Vec<u8>>::new());
            Ok(())
        })
    }

    /// An explicit service realm is authoritative: the mapper is not asked.
    #[test]
    fn explicit_service_realm_is_not_remapped() -> Result<(), TestError> {
        static PROXY: Recorder = Recorder::new();
        runtime()?.block_on(async {
            // Given a client with a mapper that would fail if asked.
            let mut client =
                Tokio::from_tgt_session(config()?, KdcProtocol::Tcp, current_tgt_session(1, 180)?)
                    .with_transport(transport(&PROXY, Some(Mapper(Err("never asked"))))?);
            // When a ticket for a service with an explicit realm is requested.
            let explicit =
                Principal::host_based_service_in_realm("host", "web.example", "TEST.GOKRB5")?;
            let result = client.get_service_ticket(explicit).await;
            // Then the request was sent unmapped (the proxy refused it).
            assert!(!matches!(result, Err(Error::Locate(_))), "{result:?}");
            assert_eq!(PROXY.seen().len(), 1);
            assert!(!PROXY.seen().iter().any(|message| names_mapped(message)));
            Ok(())
        })
    }
}

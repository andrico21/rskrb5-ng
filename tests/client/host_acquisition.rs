use super::*;

/// Host acquisition through the high-level client (MIT-config-14, -34, the
/// client share of MIT-dns-4): only the explicit operation canonicalizes, and
/// only with the caller's approval.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use super::*;
    use crate::kdc_recorder::Recorder;

    /// The client realm's KDC behind `proxy`, with `qualify_shortname` set and
    /// DNS canonicalization off, so no lookup is needed to qualify.
    fn client(proxy: &'static Recorder) -> Result<Tokio, TestError> {
        let config = Config::parse(
            "[libdefaults]\ndefault_realm = TEST.GOKRB5\ndns_lookup_kdc = false\n\
             dns_canonicalize_hostname = false\nqualify_shortname = example.org\n\
             [realms]\nTEST.GOKRB5 = {\nkdc = https://kdc.test.gokrb5/\n\
             http_anchors = FILE:/etc/proxy-ca.pem\n}\n",
        )?;
        Ok(
            Tokio::from_tgt_session(config, KdcProtocol::Tcp, current_tgt_session(1, 180)?)
                .with_transport(TokioKdcTransport::new().with_kdc_proxy(proxy)),
        )
    }

    /// An explicit host-based principal keeps its host: no suffix is added.
    #[test]
    fn explicit_principal_is_not_qualified() -> Result<(), TestError> {
        static PROXY: Recorder = Recorder::new();
        runtime()?.block_on(async {
            let mut client = client(&PROXY)?;
            let result = client
                .get_service_ticket(Principal::host_based_service("host", "short")?)
                .await;
            assert!(result.is_err(), "the recording proxy delivers nothing");
            let seen = PROXY.seen();
            assert_eq!(seen.len(), 1);
            assert!(seen.iter().all(|message| Recorder::names(message, "short")));
            assert!(
                !seen
                    .iter()
                    .any(|message| Recorder::names(message, "short.example.org"))
            );
            Ok(())
        })
    }

    /// The explicit operation names the qualified host when the policy approves
    /// it, and sends nothing when it does not.
    #[test]
    fn host_acquisition_route_asks_for_the_approved_name() -> Result<(), TestError> {
        static APPROVED: Recorder = Recorder::new();
        static REFUSED: Recorder = Recorder::new();
        runtime()?.block_on(async {
            let approve = |_requested: &str, candidate: &str| candidate == "short.example.org";
            let result = client(&APPROVED)?
                .get_host_service_ticket("host", "short", &approve)
                .await;
            assert!(result.is_err(), "the recording proxy delivers nothing");
            assert!(
                APPROVED
                    .seen()
                    .iter()
                    .any(|message| Recorder::names(message, "short.example.org"))
            );
            let refuse = |_requested: &str, _candidate: &str| false;
            let refused = client(&REFUSED)?
                .get_host_service_ticket("host", "short", &refuse)
                .await;
            assert!(
                matches!(&refused, Err(Error::HostNameNotApproved { host }) if host == "short"),
                "{refused:?}"
            );
            assert_eq!(REFUSED.seen(), Vec::<Vec<u8>>::new());
            Ok(())
        })
    }
}

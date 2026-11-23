//! Downstream API tests for crate-wide domain error propagation (no external services).

/// Causal-chain coverage for every retained error payload.
#[cfg(test)]
#[path = "error_api/sources.rs"]
#[expect(
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
#[cfg_attr(
    feature = "tokio",
    expect(
        clippy::missing_panics_doc,
        reason = "test code is not rendered API documentation"
    )
)]
#[cfg_attr(
    feature = "tokio",
    expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")
)]
mod sources;

/// Domain failures retain their concrete cause through the crate-wide result alias.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use core::error::Error as _;

    #[cfg(feature = "http")]
    use http_types::Request;
    #[cfg(feature = "http")]
    use rskrb5_ng::http;
    use rskrb5_ng::{
        Result, ccache::CCache, config, crypto::AesSha1Etype, error, keytab::Keytab, pac::Pac,
        routing::RealmPath, trace::Options,
    };
    #[cfg(feature = "messages")]
    use rskrb5_ng::{ap_rep, ap_req, client::principal::Principal, kadmin, kdc_rep, kdc_req};
    #[cfg(feature = "spnego")]
    use rskrb5_ng::{gss, spnego};
    #[cfg(feature = "messages")]
    use rskrb5_ng::{krb_cred, krb_error, krb_priv, krb_safe, messages::PaForUser, ticket};

    /// Exercise `?` in a downstream crate and require the original domain as its source.
    macro_rules! propagates_domain {
        ($name:ident, $domain:ty, $operation:expr) => {
            /// A public domain operation propagates without erasing its cause.
            #[test]
            fn $name() -> core::result::Result<(), Box<dyn core::error::Error>> {
                // Given a real domain operation that rejects its input.
                let operation = || -> Result<()> {
                    // When a downstream caller propagates through the crate alias.
                    let _value = $operation?;
                    Ok(())
                };
                let failure = operation().err().ok_or("expected domain failure")?;
                // Then the concrete domain cause remains inspectable.
                assert!(failure.source().is_some_and(|cause| cause.is::<$domain>()));
                Ok(())
            }
        };
    }

    propagates_domain!(keytab_when_truncated, error::Keytab, Keytab::parse(&[]));
    propagates_domain!(ccache_when_truncated, error::Ccache, CCache::parse(&[]));
    propagates_domain!(
        config_when_boolean_invalid,
        error::Config,
        config::parse_boolean("invalid")
    );
    propagates_domain!(
        crypto_when_key_invalid,
        error::Crypto,
        AesSha1Etype::Aes128.derive_key(&[], &[])
    );
    propagates_domain!(pac_when_truncated, error::Pac, Pac::parse(&[]));
    propagates_domain!(
        trace_when_destination_empty,
        error::Trace,
        Options::new().with_file("")
    );
    propagates_domain!(
        routing_when_same_realm,
        error::Routing,
        RealmPath::hierarchical("A.TEST", "A.TEST")
    );

    propagates_domain!(
        local_auth_when_no_translation,
        error::LocalAuth,
        None::<()>.ok_or(error::LocalAuth::NoTranslation)
    );
    #[cfg(feature = "messages")]
    propagates_domain!(
        client_when_principal_invalid,
        error::Client,
        Principal::parse_user("")
    );
    #[cfg(feature = "messages")]
    propagates_domain!(ap_req_when_truncated, error::ApReq, ap_req::decode(&[]));
    #[cfg(feature = "messages")]
    propagates_domain!(ap_rep_when_truncated, error::ApRep, ap_rep::decode(&[]));
    #[cfg(feature = "messages")]
    propagates_domain!(
        kadmin_when_truncated,
        error::Kadmin,
        kadmin::decode_krb_priv(&[])
    );
    #[cfg(feature = "messages")]
    propagates_domain!(
        kdc_req_when_truncated,
        error::KdcReq,
        kdc_req::decode_as_req(&[])
    );
    #[cfg(feature = "messages")]
    propagates_domain!(
        kdc_rep_when_truncated,
        error::KdcRep,
        kdc_rep::decode_as_rep(&[])
    );
    #[cfg(feature = "messages")]
    propagates_domain!(
        krb_error_when_truncated,
        error::KrbErrorCodec,
        krb_error::decode(&[])
    );
    #[cfg(feature = "messages")]
    propagates_domain!(
        krb_priv_when_truncated,
        error::KrbPriv,
        krb_priv::decode(&[])
    );
    #[cfg(feature = "messages")]
    propagates_domain!(
        krb_cred_when_truncated,
        error::KrbCred,
        krb_cred::decode(&[])
    );
    #[cfg(feature = "messages")]
    propagates_domain!(
        krb_safe_when_truncated,
        error::KrbSafe,
        krb_safe::decode(&[])
    );
    #[cfg(feature = "messages")]
    propagates_domain!(ticket_when_truncated, error::Ticket, ticket::decode(&[]));
    #[cfg(feature = "messages")]
    propagates_domain!(
        messages_when_truncated,
        error::Messages,
        PaForUser::decode_der(&[])
    );
    #[cfg(feature = "messages")]
    propagates_domain!(
        service_when_ap_req_truncated,
        error::Service,
        rskrb5_ng::service::Validator::new(&Keytab::new()).validate_ap_req(&[])
    );
    #[cfg(feature = "spnego")]
    propagates_domain!(
        spnego_when_header_invalid,
        error::Spnego,
        spnego::parse_negotiate_header("invalid")
    );
    #[cfg(feature = "spnego")]
    propagates_domain!(
        gss_when_exported_name_truncated,
        error::Gss,
        gss::Name::import(&[], gss::NameType::Export)
    );
    #[cfg(feature = "spnego")]
    propagates_domain!(
        negoex_when_token_empty,
        error::Negoex,
        gss::negoex::Conversation::accepting().parse(&[])
    );
    #[cfg(feature = "http")]
    propagates_domain!(
        http_when_authorization_missing,
        error::Http,
        http::authorization_header(&Request::new(()))
    );
}

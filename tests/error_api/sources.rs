//! Autonomous source-chain tests for typed causal wrappers.

use core::{error::Error, str, time::Duration};
use std::{
    env::VarError,
    io,
    time::{SystemTimeError, UNIX_EPOCH},
};

#[cfg(feature = "http")]
use http_types::header::{HeaderValue, InvalidHeaderValue, ToStrError};
use rskrb5_ng::error;

/// Construct the actual decoder error without constant-invalid UTF-8 literals.
fn utf8_cause() -> Result<str::Utf8Error, Box<dyn Error>> {
    Ok(String::from_utf8(vec![255_u8])
        .err()
        .ok_or("UTF-8 fixture")?
        .utf8_error())
}

/// Require a wrapper's source to retain the concrete payload type.
macro_rules! retains_source {
    ($name:ident, $cause:ty, $wrapper:expr) => {
        /// A retained causal payload remains downcastable through `source()`.
        #[test]
        fn $name() -> Result<(), Box<dyn core::error::Error>> {
            // Given a wrapper retaining a concrete error.
            let wrapper = $wrapper;
            // When generic diagnostics traverse its source.
            let source = wrapper.source().ok_or("retained cause missing")?;
            // Then the payload type, rather than a string, is available.
            assert!(source.is::<$cause>());
            Ok(())
        }
    };
}

retains_source!(
    ccache_environment_source,
    VarError,
    error::Ccache::DefaultCacheName(VarError::NotPresent)
);
retains_source!(
    keytab_environment_source,
    VarError,
    error::Keytab::DefaultKeytabName(VarError::NotPresent)
);
retains_source!(
    ccache_io_source,
    io::Error,
    error::Ccache::Io(io::Error::from(io::ErrorKind::PermissionDenied))
);
retains_source!(
    keytab_io_source,
    io::Error,
    error::Keytab::Io(io::Error::from(io::ErrorKind::PermissionDenied))
);
retains_source!(
    config_io_source,
    io::Error,
    error::Config::Io(io::Error::from(io::ErrorKind::PermissionDenied))
);
retains_source!(
    config_file_source,
    io::Error,
    error::Config::File {
        path: "explicit.conf".into(),
        source: io::Error::from(io::ErrorKind::PermissionDenied)
    }
);
retains_source!(
    config_include_file_source,
    io::Error,
    error::Config::IncludeFile {
        path: "include.conf".into(),
        source: io::Error::from(io::ErrorKind::PermissionDenied)
    }
);
retains_source!(
    config_include_dir_source,
    io::Error,
    error::Config::IncludeDir {
        path: "include.d".into(),
        source: io::Error::from(io::ErrorKind::PermissionDenied)
    }
);
retains_source!(
    ccache_utf8_source,
    str::Utf8Error,
    error::Ccache::InvalidString(utf8_cause()?)
);
retains_source!(
    keytab_utf8_source,
    str::Utf8Error,
    error::Keytab::InvalidString(utf8_cause()?)
);
retains_source!(
    keytab_timestamp_source,
    SystemTimeError,
    error::Keytab::TimestampBeforeUnixEpoch(
        UNIX_EPOCH
            .duration_since(
                UNIX_EPOCH
                    .checked_add(Duration::from_secs(1))
                    .ok_or("time fixture")?
            )
            .err()
            .ok_or("time error")?
    )
);
retains_source!(
    keytab_crypto_source,
    error::Crypto,
    error::Keytab::Crypto(error::Crypto::EmptyPlaintext)
);
retains_source!(
    pac_crypto_source,
    error::Crypto,
    error::Pac::Crypto(error::Crypto::EmptyPlaintext)
);

#[cfg(feature = "tokio")]
retains_source!(
    client_environment_source,
    VarError,
    error::Client::DefaultClientKeytabName(VarError::NotPresent)
);
#[cfg(feature = "tokio")]
retains_source!(
    client_io_source,
    io::Error,
    error::Client::Io(io::Error::from(io::ErrorKind::PermissionDenied))
);
#[cfg(feature = "messages")]
retains_source!(
    client_utf8_source,
    str::Utf8Error,
    error::Client::InvalidString(utf8_cause()?)
);
#[cfg(feature = "messages")]
retains_source!(
    krb_cred_utf8_source,
    str::Utf8Error,
    error::KrbCred::InvalidString(utf8_cause()?)
);
#[cfg(feature = "messages")]
retains_source!(
    messages_utf8_source,
    str::Utf8Error,
    error::Messages::InvalidString(utf8_cause()?)
);
#[cfg(feature = "messages")]
retains_source!(
    service_utf8_source,
    str::Utf8Error,
    error::Service::InvalidString(utf8_cause()?)
);

/// Instantiate the shared crypto and randomness wrapper contract per domain.
macro_rules! crypto_random_sources {
    ($domain:ident, $crypto:ident, $random:ident) => {
        #[cfg(feature = "messages")]
        retains_source!(
            $crypto,
            error::Crypto,
            error::$domain::Crypto(error::Crypto::EmptyPlaintext)
        );
        #[cfg(feature = "messages")]
        retains_source!(
            $random,
            getrandom::Error,
            error::$domain::Random(getrandom::Error::UNSUPPORTED)
        );
    };
}

crypto_random_sources!(ApRep, ap_rep_crypto_source, ap_rep_random_source);
#[cfg(feature = "messages")]
retains_source!(
    krb_error_utf8_source,
    str::Utf8Error,
    error::KrbErrorCodec::InvalidString(utf8_cause()?)
);
crypto_random_sources!(ApReq, ap_req_crypto_source, ap_req_random_source);
crypto_random_sources!(Client, client_crypto_source, client_random_source);
crypto_random_sources!(KdcRep, kdc_rep_crypto_source, kdc_rep_random_source);
crypto_random_sources!(KdcReq, kdc_req_crypto_source, kdc_req_random_source);
crypto_random_sources!(KrbCred, krb_cred_crypto_source, krb_cred_random_source);
crypto_random_sources!(KrbPriv, krb_priv_crypto_source, krb_priv_random_source);
crypto_random_sources!(Service, service_crypto_source, service_random_source);
crypto_random_sources!(Ticket, ticket_crypto_source, ticket_random_source);
#[cfg(feature = "messages")]
retains_source!(
    krb_safe_crypto_source,
    error::Crypto,
    error::KrbSafe::Crypto(error::Crypto::EmptyPlaintext)
);
#[cfg(feature = "messages")]
retains_source!(
    client_keytab_source,
    error::Keytab,
    error::Client::Keytab(error::Keytab::InvalidKeytabName)
);
#[cfg(feature = "messages")]
retains_source!(
    client_config_source,
    error::Config,
    error::Client::Config(error::Config::NoDefault)
);
#[cfg(feature = "messages")]
retains_source!(
    client_ccache_source,
    error::Ccache,
    error::Client::CCache(error::Ccache::InvalidCacheName)
);
#[cfg(feature = "messages")]
retains_source!(
    client_kadmin_source,
    error::Kadmin,
    error::Client::Kadmin(error::Kadmin::MissingApRep)
);
#[cfg(feature = "messages")]
retains_source!(
    client_message_source,
    error::Messages,
    error::Client::Message(error::Messages::TimeOverflow)
);
#[cfg(feature = "messages")]
retains_source!(
    service_keytab_source,
    error::Keytab,
    error::Service::Keytab(error::Keytab::InvalidKeytabName)
);
#[cfg(feature = "messages")]
retains_source!(
    service_pac_source,
    error::Pac,
    error::Service::Pac(error::Pac::LengthOverflow)
);
#[cfg(feature = "messages")]
retains_source!(
    unknown_outcome_source,
    Box<error::Client>,
    error::Client::KpasswdOutcomeUnknown(Box::new(error::Client::TimeOverflow))
);

#[cfg(feature = "spnego")]
retains_source!(
    base64_source,
    base64::DecodeError,
    error::Spnego::Base64(base64::DecodeError::InvalidLength(1))
);
#[cfg(feature = "spnego")]
retains_source!(
    client_spnego_source,
    error::Spnego,
    error::Client::Spnego(error::Spnego::EmptyInput)
);
#[cfg(feature = "spnego")]
retains_source!(
    spnego_crypto_source,
    error::Crypto,
    error::Spnego::Crypto(error::Crypto::EmptyPlaintext)
);
#[cfg(feature = "spnego")]
retains_source!(
    spnego_random_source,
    getrandom::Error,
    error::Spnego::Random(getrandom::Error::UNSUPPORTED)
);
#[cfg(feature = "spnego")]
retains_source!(
    spnego_service_source,
    error::Service,
    error::Spnego::Service(error::Service::TimeOverflow)
);
#[cfg(feature = "spnego")]
retains_source!(
    spnego_client_source,
    Box<error::Client>,
    error::Spnego::Client(Box::new(error::Client::TimeOverflow))
);
include!("feature_sources.rs");

/// The unknown outcome does not hide the underlying transport failure.
#[cfg(feature = "tokio")]
#[test]
fn unknown_outcome_io_chain() -> Result<(), Box<dyn Error>> {
    // Given a deliberately classified post-delivery I/O failure.
    let wrapper = error::Client::KpasswdOutcomeUnknown(Box::new(error::Client::Io(
        io::Error::from(io::ErrorKind::ConnectionReset),
    )));
    // When traversing both retained source edges.
    let domain = wrapper.source().ok_or("outcome cause missing")?;
    let cause = domain.source().ok_or("I/O cause missing")?;
    // Then diagnostics recover the original typed transport failure.
    assert!(domain.is::<Box<error::Client>>());
    assert_eq!(
        cause.downcast_ref::<io::Error>().ok_or("I/O type")?.kind(),
        io::ErrorKind::ConnectionReset
    );
    Ok(())
}

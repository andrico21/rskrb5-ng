//! An `https://` `admin_server` as the kpasswd fallback (FU-KDP-P04).

use core::error::Error as StdError;

use super::{
    Error, KdcProtocol, Tokio,
    proxy_tests::{Answer, Fake, profile},
};
use crate::{config::Config, error::KdcProxy};

/// A realm that names only an HTTPS admin server sends its password changes to
/// that complete proxy URL, port and path included.
#[tokio::test]
async fn https_admin_server_remains_a_kpasswd_proxy_url() -> Result<(), Box<dyn StdError>> {
    static PROXY: Fake = Fake::new(&[Answer::Reply]);
    let config = profile("admin_server", &["https://adm.r.test:8443/kpx"])?;
    let entry = config.realm("R.TEST").ok_or("realm")?;
    assert_eq!(entry.kpasswd_server, ["https://adm.r.test:8443/kpx"]);
    for protocol in [KdcProtocol::Auto, KdcProtocol::Tcp] {
        let reply = Tokio::new()
            .with_kdc_proxy(&PROXY)
            .send_to_kpasswd_realm(&config, protocol, "R.TEST", &[0, 1])
            .await?;
        assert_eq!(reply, [0x6b, 1, 2], "{protocol:?}");
    }
    let urls: Vec<String> = PROXY.seen().into_iter().map(|seen| seen.0).collect();
    assert_eq!(urls, ["https://adm.r.test:8443/kpx"; 2]);
    Ok(())
}

/// An explicit `kpasswd_server` replaces the admin-server fallback.
#[tokio::test]
async fn explicit_kpasswd_overrides_https_admin() -> Result<(), Box<dyn StdError>> {
    static PROXY: Fake = Fake::new(&[Answer::Reply]);
    let config = Config::parse(
        "[libdefaults]\ndns_lookup_kdc = false\n[realms]\nR.TEST = {\n\
         admin_server = https://adm.r.test:8443/kpx\n\
         kpasswd_server = https://kp.r.test/p\n\
         http_anchors = FILE:/etc/proxy-ca.pem\n}\n",
    )?;
    let reply = Tokio::new()
        .with_kdc_proxy(&PROXY)
        .send_to_kpasswd_realm(&config, KdcProtocol::Auto, "R.TEST", &[0, 1])
        .await?;
    assert_eq!(reply, [0x6b, 1, 2]);
    let urls: Vec<String> = PROXY.seen().into_iter().map(|seen| seen.0).collect();
    assert_eq!(urls, ["https://kp.r.test:443/p"]);
    Ok(())
}

/// A password change that may have reached the admin-server proxy is never
/// resent: the outcome is unknown.
#[tokio::test]
async fn https_admin_kpasswd_preserves_unknown_outcome() -> Result<(), Box<dyn StdError>> {
    static UNSURE: Fake = Fake::new(&[Answer::MaybeDelivered]);
    let config = profile(
        "admin_server",
        &["https://a.r.test/p", "https://b.r.test/p"],
    )?;
    let outcome = Tokio::new()
        .with_kdc_proxy(&UNSURE)
        .send_to_kpasswd_realm(&config, KdcProtocol::Auto, "R.TEST", &[0, 1])
        .await;
    assert!(
        matches!(outcome, Err(Error::KpasswdOutcomeUnknown(_))),
        "{outcome:?}"
    );
    assert_eq!(
        UNSURE.seen().len(),
        1,
        "an uncertain change is never resent"
    );
    Ok(())
}

/// A malformed HTTPS admin server is refused by the proxy URL parser before
/// anything is sent, instead of becoming a host named `https`.
#[tokio::test]
async fn malformed_https_admin_is_refused_by_the_proxy_parser() -> Result<(), Box<dyn StdError>> {
    static PROXY: Fake = Fake::new(&[Answer::Reply]);
    let config = profile("admin_server", &["https://user@adm.r.test/p"])?;
    let outcome = Tokio::new()
        .with_kdc_proxy(&PROXY)
        .send_to_kpasswd_realm(&config, KdcProtocol::Auto, "R.TEST", &[0, 1])
        .await;
    assert!(
        matches!(
            outcome,
            Err(Error::KdcProxy(KdcProxy::InvalidUrl { reason: _ }))
        ),
        "{outcome:?}"
    );
    assert!(PROXY.seen().is_empty(), "nothing is sent");
    Ok(())
}

//! Live integration tests against the gokrb5 Docker MIT KDC fixtures.
//!
//! The tests drive AS, TGS, renewal, referral, kpasswd and SPNEGO exchanges
//! over UDP and TCP against the Docker KDCs, and cross-check credential caches
//! with the MIT `kinit` and `kvno` tools. They run only with `INTEGRATION=1`
//! and reachable fixtures; further variables enable the kpasswd, DNS and
//! privileged groups.
#![cfg(feature = "tokio")]

/// Service endpoint selection for live fixtures.
#[path = "client_integration/endpoints.rs"]
mod endpoints;

/// Availability gates for explicitly requested live fixtures.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
#[path = "client_integration/preflight.rs"]
mod preflight;

use core::{error::Error, iter, net::Ipv4Addr, time::Duration};
use std::{
    fs,
    io::Write as _,
    net::{TcpStream, ToSocketAddrs as _},
    path::PathBuf,
    process::{Command, Stdio},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use rskrb5_ng::{
    ccache::CCache,
    client::{
        AsRepSession, BuiltAsReq, Password, PreauthKeyInfo, Tokio, build_tgs_req, build_tgt_as_req,
        derive_password_reply_key,
        options::{AsReq, TgsReq},
        pa_enc_timestamp_with_confounder,
        principal::Principal,
        transport::{KdcEndpoint, KdcEndpointSource, KdcProtocol, Tokio as TokioKdcTransport},
    },
    config::Config,
    crypto::{AesSha1Etype, Des3CbcSha1KdEtype},
    error::Client as ClientError,
    kadmin::{ChangePasswordResult, KPASSWD_SUCCESS},
    keytab::{EncryptionKey, Entry as KeytabEntry, Keytab, Principal as KeytabPrincipal},
};

/// Realm of the Docker MIT KDC fixtures.
const REALM: &str = "TEST.GOKRB5";

/// Test user principal name.
const USER: &str = "testuser1";

/// Password of the test user.
const PASSWORD: &[u8] = b"passwordvalue";

/// Default salt of the test user.
const TESTUSER1_SALT: &[u8] = b"TEST.GOKRB5testuser1";

/// Enctype id of aes128-cts-hmac-sha1-96.
const AES128_ETYPE: i32 = 17;

/// Enctype id of aes256-cts-hmac-sha1-96.
const AES256_ETYPE: i32 = 18;

/// Enctype id of aes128-cts-hmac-sha256-128.
const AES128_SHA2_ETYPE: i32 = 19;

/// Enctype id of aes256-cts-hmac-sha384-192.
const AES256_SHA2_ETYPE: i32 = 20;

/// Enctype id of des3-cbc-sha1-kd.
const DES3_ETYPE: i32 = 16;

/// Enctype id of rc4-hmac.
const RC4_HMAC_ETYPE: i32 = 23;

/// Key version number of the test user keys.
const TESTUSER1_KVNO: u32 = 2;

/// Host of the HTTP service in the test realm.
const SERVICE_HOST: &str = "host.test.gokrb5";

/// Realm of the resource domain reached through a referral.
const RESDOM_REALM: &str = "RESDOM.GOKRB5";

/// Host of the HTTP service in the resource realm.
const RESDOM_SERVICE_HOST: &str = "host.resdom.gokrb5";

/// Temporary password the kpasswd test changes to and back from.
const TEMP_PASSWORD: &[u8] = b"passwordvalue-rskrb5-temp";

/// Keytab of testuser2@TEST.GOKRB5, a user that requires preauthentication.
const KEYTAB_TESTUSER2_TEST_GOKRB5: &str = "05020000003b0001000b544553542e474f4b52423500097465737475736572320000000159beb240010011001086824c55ff5de30386dd83dc62b44bb7000000010000004b0001000b544553542e474f4b52423500097465737475736572320000000159beb2400100120020d8ed27f96be76fd5b281ee9f8029db93cc5fb06c7eb3be9ee753106d3488fa92000000010000003b0001000b544553542e474f4b52423500097465737475736572320000000159beb240020011001086824c55ff5de30386dd83dc62b44bb7000000020000004b0001000b544553542e474f4b52423500097465737475736572320000000159beb2400200120020d8ed27f96be76fd5b281ee9f8029db93cc5fb06c7eb3be9ee753106d3488fa92000000020000003b0001000b544553542e474f4b52423500097465737475736572320000000159beb24001001300106ccff358aaa8a4a41c444e173b1463c2000000010000003b0001000b544553542e474f4b52423500097465737475736572320000000159beb24002001300106ccff358aaa8a4a41c444e173b1463c2000000020000004b0001000b544553542e474f4b52423500097465737475736572320000000159beb24001001400205cf3773dd920be800229ac1c6f9bf59c6706c583f82c2dea66c9a29152118cd7000000010000004b0001000b544553542e474f4b52423500097465737475736572320000000159beb24002001400205cf3773dd920be800229ac1c6f9bf59c6706c583f82c2dea66c9a29152118cd700000002000000430001000b544553542e474f4b52423500097465737475736572320000000159beb2400100100018bc025746e9e66bd6b62a918f6413d529803192a28aabf79200000001000000430001000b544553542e474f4b52423500097465737475736572320000000159beb2400200100018bc025746e9e66bd6b62a918f6413d529803192a28aabf792000000020000003b0001000b544553542e474f4b52423500097465737475736572320000000159beb2400100170010084768c373663b3bef1f6385883cf7ff000000010000003b0001000b544553542e474f4b52423500097465737475736572320000000159beb2400200170010084768c373663b3bef1f6385883cf7ff00000002";

/// Keytab of testuser1@TEST.GOKRB5 with keys of a wrong password.
const KEYTAB_TESTUSER1_TEST_GOKRB5_WRONGPASSWD: &str = "0502000000370001000b544553542e474f4b52423500097465737475736572310000000158ef4bc5010011001039a9a382153105f8708e80f93382654e000000470001000b544553542e474f4b52423500097465737475736572310000000158ef4bc60100120020fc5bb940d6075214e0c6fc0456ce68c33306094198a927b4187d7cf3f4aea50d";

/// Serialises the Docker tests, which share the KDC state and the test password.
static INTEGRATION_LOCK: Mutex<()> = Mutex::new(());

/// Keytab of the `HTTP/host.test.gokrb5` service.
#[cfg(feature = "spnego")]
const HTTP_KEYTAB: &str = concat!(
    "0502000000440002000b544553542e474f4b5242350004485454500010686f73742e746573742e676f6b",
    "72623500000001590dc4dc010011001057a7754c70c4d85c155c718c2f1292b0000000540002000b",
    "544553542e474f4b5242350004485454500010686f73742e746573742e676f6b72623500000001590d",
    "c4dc01001200209cad00bbc72d703258e911dc18e6d5487cf737bf67fd111f0c2463ad6033bf51",
    "000000440002000b544553542e474f4b5242350004485454500010686f73742e746573742e676f6b",
    "72623500000001590dc4dc020011001057a7754c70c4d85c155c718c2f1292b0000000540002000b",
    "544553542e474f4b5242350004485454500010686f73742e746573742e676f6b72623500000001590d",
    "c4dc02001200209cad00bbc72d703258e911dc18e6d5487cf737bf67fd111f0c2463ad6033bf51",
);

/// Builds a preauthenticated AS-REQ for the test user with an AES256 timestamp.
///
/// The cusec, nonce and confounder vary by `protocol`, so the UDP and TCP
/// requests of one test never collide in the KDC replay cache.
///
/// # Errors
///
/// Returns an error if the clock is before the Unix epoch or the request cannot be built.
fn build_login_request(
    protocol: KdcProtocol,
    key: &EncryptionKey,
) -> Result<BuiltAsReq, Box<dyn Error>> {
    let now = SystemTime::now();
    let elapsed = now.duration_since(UNIX_EPOCH)?;
    let timestamp = UNIX_EPOCH
        .checked_add(Duration::from_secs(elapsed.as_secs()))
        .ok_or("the current time fits a SystemTime")?;
    // `subsec_micros` is below one million, so the offsets cannot overflow.
    let cusec = match protocol {
        KdcProtocol::Udp => elapsed.subsec_micros(),
        KdcProtocol::Tcp => elapsed
            .subsec_micros()
            .wrapping_add(1)
            .wrapping_rem(1_000_000),
        KdcProtocol::Auto => elapsed
            .subsec_micros()
            .wrapping_add(2)
            .wrapping_rem(1_000_000),

        _ => return Err("unexpected non-exhaustive protocol variant".into()),
    };
    let nonce = u32::try_from(elapsed.as_nanos() & 0x0fff_ffff)?
        | match protocol {
            KdcProtocol::Udp => 0x1000_0000,
            KdcProtocol::Tcp => 0x2000_0000,
            KdcProtocol::Auto => 0x3000_0000,

            _ => return Err("unexpected non-exhaustive protocol variant".into()),
        };
    let padata = pa_enc_timestamp_with_confounder(
        key,
        timestamp,
        cusec,
        &confounder(protocol, elapsed),
        Some(TESTUSER1_KVNO),
    )?;
    let options = AsReq::new(timestamp, nonce)
        .with_ticket_lifetime(Duration::from_hours(24))
        .with_etypes(vec![AES256_ETYPE])
        .with_padata(vec![padata]);

    Ok(build_tgt_as_req(Principal::user(REALM, USER), options)?)
}

/// Asserts that `session` is a fresh AES256 TGT of the test user in the test realm.
///
/// # Panics
///
/// Panics if any of those properties does not hold.
fn assert_login_session(session: &AsRepSession) {
    assert_eq!(
        session.client,
        Principal::user(REALM, USER),
        "the TGT is issued to the test user"
    );
    assert_eq!(
        session.service,
        Principal::tgt_service(REALM),
        "the session is a TGT of the test realm"
    );
    assert_eq!(
        session.session_key.etype, AES256_ETYPE,
        "the TGT session key is AES256"
    );
    assert!(
        !session.session_key.value.is_empty(),
        "session.session_key.value must not be empty"
    );
    assert!(
        !session.ticket.is_empty(),
        "session.ticket must not be empty"
    );
    assert!(
        session.end_time > session.start_time,
        "the TGT ends after it starts"
    );
}

/// Builds a per-protocol, per-time AES confounder so replayed requests differ.
///
/// Byte 0 tags the protocol, bytes 1..9 hold the seconds and bytes 9..13 the
/// nanoseconds of `elapsed`; the rest stay zero.
/// # Panics
/// Panics when a future protocol variant has no fixture tag.
fn confounder(protocol: KdcProtocol, elapsed: Duration) -> [u8; 16] {
    let tag: u8 = match protocol {
        KdcProtocol::Udp => 1,
        KdcProtocol::Tcp => 2,
        KdcProtocol::Auto => 3,

        _ => {
            assert!(
                matches!(protocol, KdcProtocol::Udp),
                "unexpected non-exhaustive protocol variant"
            );
            0
        }
    };
    let bytes = iter::once(tag)
        .chain(elapsed.as_secs().to_be_bytes())
        .chain(elapsed.subsec_nanos().to_be_bytes());
    let mut confounder = [0_u8; 16];
    for (slot, byte) in confounder.iter_mut().zip(bytes) {
        *slot = byte;
    }
    confounder
}

/// Live Docker MIT KDC integration tests (gated on `INTEGRATION=1`) and
/// their preflight checks.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    #[cfg(feature = "spnego")]
    use std::io::Read as _;
    use std::{env, io, net::TcpListener, process};

    use rskrb5_ng::{crypto::CryptoPolicy, krb_priv::ipv4_host_address};
    #[cfg(feature = "spnego")]
    use rskrb5_ng::{
        error::{Service as ServiceError, Spnego as SpnegoError},
        service::{ApRepOptions, Principal as ServicePrincipal, Validator},
        spnego,
    };
    use tokio::runtime::{Builder, Runtime};

    use super::{
        endpoints::{
            kdc_addr, kpasswd_addr, latest_kdc_addr, old_kdc_addr, resdom_kdc_addr, short_kdc_addr,
        },
        preflight::{
            integration_enabled, integration_enabled_for, privileged_integration_enabled,
            privileged_kvno_integration_enabled,
        },
        *,
    };

    /// Names a KDC transport protocol in progress messages.
    const fn protocol_label(protocol: KdcProtocol) -> &'static str {
        match protocol {
            KdcProtocol::Udp => "Udp",
            KdcProtocol::Tcp => "Tcp",
            KdcProtocol::Auto => "Auto",

            _ => {
                assert!(
                    matches!(protocol, KdcProtocol::Udp),
                    "unexpected non-exhaustive protocol variant"
                );
                "unknown"
            }
        }
    }

    /// Joins the authorities of discovered KDC endpoints for progress messages.
    fn endpoint_list(endpoints: &[KdcEndpoint]) -> String {
        endpoints
            .iter()
            .map(KdcEndpoint::authority)
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Pins that a hand-built preauthenticated AS-REQ yields an AES256 TGT over UDP and TCP.
    #[test]
    fn docker_mit_kdc_as_login_through_tcp_and_udp() -> Result<(), Box<dyn Error>> {
        if !integration_enabled()? {
            return Ok(());
        }
        let _guard = INTEGRATION_LOCK
            .lock()
            .map_err(|cause| format!("integration test lock: {cause}"))?;

        runtime()?.block_on(async {
            let addr = kdc_addr();
            let transport = TokioKdcTransport::new().with_timeout(Duration::from_secs(10));

            for protocol in [KdcProtocol::Udp, KdcProtocol::Tcp] {
                writeln!(
                    io::stderr(),
                    "running Docker KDC AS login over {} to {addr}",
                    protocol_label(protocol)
                )?;
                let key = testuser_reply_key()?;
                let request = build_login_request(protocol, &key)?;
                let session = transport
                    .exchange_as_req(protocol, addr.as_str(), &request, &key)
                    .await?;

                assert_eq!(session.client, Principal::user(REALM, USER));
                assert_eq!(session.service, Principal::tgt_service(REALM));
                assert_eq!(session.session_key.etype, AES256_ETYPE);
                assert!(
                    !session.session_key.value.is_empty(),
                    "session.session_key.value must not be empty"
                );
                assert!(
                    !session.ticket.is_empty(),
                    "session.ticket must not be empty"
                );
                assert!(session.end_time > session.start_time);
            }

            Ok::<_, Box<dyn Error>>(())
        })
    }

    /// Pins that the negotiated password and keytab logins both yield a TGT over UDP and TCP.
    #[test]
    fn docker_mit_kdc_negotiated_as_login_with_password_and_keytab() -> Result<(), Box<dyn Error>> {
        if !integration_enabled()? {
            return Ok(());
        }
        let _guard = INTEGRATION_LOCK
            .lock()
            .map_err(|cause| format!("integration test lock: {cause}"))?;

        runtime()?.block_on(async {
            let addr = kdc_addr();
            let transport = TokioKdcTransport::new().with_timeout(Duration::from_secs(10));
            let keytab = testuser_keytab()?;

            for protocol in [KdcProtocol::Udp, KdcProtocol::Tcp] {
                writeln!(
                    io::stderr(),
                    "running negotiated Docker KDC password AS login over {} to {addr}",
                    protocol_label(protocol)
                )?;
                let password_session = transport
                    .login_tgt_with_password(
                        protocol,
                        addr.as_str(),
                        Principal::user(REALM, USER),
                        PASSWORD,
                        login_options(protocol, 1)?,
                    )
                    .await?;
                assert_login_session(&password_session);

                writeln!(
                    io::stderr(),
                    "running negotiated Docker KDC keytab AS login over {} to {addr}",
                    protocol_label(protocol)
                )?;
                let keytab_session = transport
                    .login_tgt_with_keytab(
                        protocol,
                        addr.as_str(),
                        Principal::user(REALM, USER),
                        &keytab,
                        login_options(protocol, 2)?,
                    )
                    .await?;
                assert_login_session(&keytab_session);
            }

            Ok::<_, Box<dyn Error>>(())
        })
    }

    /// Pins that a password login restricted to RC4-HMAC yields an RC4 TGT over UDP and TCP.
    #[test]
    fn docker_mit_kdc_rc4_hmac_as_login_through_tcp_and_udp() -> Result<(), Box<dyn Error>> {
        if !integration_enabled()? {
            return Ok(());
        }
        let _guard = INTEGRATION_LOCK
            .lock()
            .map_err(|cause| format!("integration test lock: {cause}"))?;

        runtime()?.block_on(async {
            let addr = kdc_addr();
            let transport = TokioKdcTransport::new().with_timeout(Duration::from_secs(10));

            for protocol in [KdcProtocol::Udp, KdcProtocol::Tcp] {
                writeln!(
                    io::stderr(),
                    "running Docker KDC RC4-HMAC AS login over {} to {addr}",
                    protocol_label(protocol)
                )?;
                let session = transport
                    .login_tgt_with_password(
                        protocol,
                        addr.as_str(),
                        Principal::user(REALM, USER),
                        PASSWORD,
                        login_options_with_etypes(protocol, 14, vec![RC4_HMAC_ETYPE])?,
                    )
                    .await?;

                assert_eq!(session.client, Principal::user(REALM, USER));
                assert_eq!(session.service, Principal::tgt_service(REALM));
                assert_eq!(session.session_key.etype, RC4_HMAC_ETYPE);
                assert!(
                    !session.session_key.value.is_empty(),
                    "session.session_key.value must not be empty"
                );
                assert!(
                    !session.ticket.is_empty(),
                    "session.ticket must not be empty"
                );
                assert!(session.end_time > session.start_time);
            }

            Ok::<_, Box<dyn Error>>(())
        })
    }

    /// Pins that a password login restricted to DES3 yields a DES3 TGT over UDP and TCP.
    #[test]
    fn docker_mit_kdc_des3_as_login_through_tcp_and_udp() -> Result<(), Box<dyn Error>> {
        if !integration_enabled()? {
            return Ok(());
        }
        let _guard = INTEGRATION_LOCK
            .lock()
            .map_err(|cause| format!("integration test lock: {cause}"))?;

        runtime()?.block_on(async {
            let addr = kdc_addr();
            let transport = TokioKdcTransport::new().with_timeout(Duration::from_secs(10));

            for protocol in [KdcProtocol::Udp, KdcProtocol::Tcp] {
                writeln!(
                    io::stderr(),
                    "running Docker KDC DES3 AS login over {} to {addr}",
                    protocol_label(protocol)
                )?;
                let session = transport
                    .login_tgt_with_password(
                        protocol,
                        addr.as_str(),
                        Principal::user(REALM, USER),
                        PASSWORD,
                        login_options_with_etypes(protocol, 19, vec![DES3_ETYPE])?,
                    )
                    .await?;

                assert_eq!(session.client, Principal::user(REALM, USER));
                assert_eq!(session.service, Principal::tgt_service(REALM));
                assert_eq!(session.session_key.etype, DES3_ETYPE);
                assert_eq!(
                    session.session_key.value.len(),
                    Des3CbcSha1KdEtype::key_len()
                );
                assert!(
                    !session.ticket.is_empty(),
                    "session.ticket must not be empty"
                );
                assert!(session.end_time > session.start_time);
            }

            Ok::<_, Box<dyn Error>>(())
        })
    }

    /// Pins that KDC discovery from the configuration finds one KDC and both login kinds use it.
    #[test]
    fn docker_mit_kdc_configured_kdc_as_login() -> Result<(), Box<dyn Error>> {
        if !integration_enabled()? {
            return Ok(());
        }
        let _guard = INTEGRATION_LOCK
            .lock()
            .map_err(|cause| format!("integration test lock: {cause}"))?;

        runtime()?.block_on(async {
            let config = configured_kdc_config()?;
            let transport = TokioKdcTransport::new().with_timeout(Duration::from_secs(10));
            let keytab = testuser_keytab()?;

            for protocol in [KdcProtocol::Udp, KdcProtocol::Tcp] {
                let endpoints = transport.discover_kdcs(&config, REALM, protocol).await?;
                writeln!(
                    io::stderr(),
                    "running config-discovered Docker KDC AS login over {}: {}",
                    protocol_label(protocol),
                    endpoint_list(&endpoints)
                )?;
                assert_eq!(endpoints.len(), 1);

                let password_session = transport
                    .login_tgt_with_password_config(
                        &config,
                        protocol,
                        Principal::user(REALM, USER),
                        PASSWORD,
                        login_options(protocol, 7)?,
                    )
                    .await?;
                assert_login_session(&password_session);

                let keytab_session = transport
                    .login_tgt_with_keytab_config(
                        &config,
                        protocol,
                        Principal::user(REALM, USER),
                        &keytab,
                        login_options(protocol, 8)?,
                    )
                    .await?;
                assert_login_session(&keytab_session);
            }

            Ok::<_, Box<dyn Error>>(())
        })
    }

    /// Pins that a login with a keytab holding the wrong keys fails.
    #[test]
    fn docker_mit_kdc_rejects_wrong_keytab_login() -> Result<(), Box<dyn Error>> {
        if !integration_enabled()? {
            return Ok(());
        }
        let _guard = INTEGRATION_LOCK
            .lock()
            .map_err(|cause| format!("integration test lock: {cause}"))?;

        runtime()?.block_on(async {
            let mut client = Tokio::with_keytab(
                configured_kdc_config()?,
                KdcProtocol::Auto,
                Principal::user(REALM, USER),
                keytab_from_hex(KEYTAB_TESTUSER1_TEST_GOKRB5_WRONGPASSWD)?,
            )
            .with_transport(TokioKdcTransport::new().with_timeout(Duration::from_secs(10)));

            assert!(
                client.login().await.is_err(),
                "login with an incorrect keytab must fail"
            );

            Ok::<_, Box<dyn Error>>(())
        })
    }

    /// Pins that testuser2, which requires preauthentication, logs in with its keytab.
    #[test]
    fn docker_mit_kdc_keytab_login_for_preauth_user() -> Result<(), Box<dyn Error>> {
        if !integration_enabled()? {
            return Ok(());
        }
        let _guard = INTEGRATION_LOCK
            .lock()
            .map_err(|cause| format!("integration test lock: {cause}"))?;

        runtime()?.block_on(async {
            let keytab = keytab_from_hex(KEYTAB_TESTUSER2_TEST_GOKRB5)?;
            for protocol in [KdcProtocol::Auto, KdcProtocol::Tcp] {
                let mut client = Tokio::with_keytab(
                    configured_kdc_config()?,
                    protocol,
                    Principal::user(REALM, "testuser2"),
                    keytab.clone(),
                )
                .with_transport(TokioKdcTransport::new().with_timeout(Duration::from_secs(10)));
                let session = client.login().await?;

                assert_eq!(session.client, Principal::user(REALM, "testuser2"));
                assert_eq!(session.service, Principal::tgt_service(REALM));
                assert_eq!(session.session_key.etype, AES256_ETYPE);
            }

            Ok::<_, Box<dyn Error>>(())
        })
    }

    /// Pins that a TGS request for an unknown service principal returns KDC error 7.
    #[test]
    fn docker_mit_kdc_invalid_service_principal_returns_kdc_error() -> Result<(), Box<dyn Error>> {
        if !integration_enabled()? {
            return Ok(());
        }
        let _guard = INTEGRATION_LOCK
            .lock()
            .map_err(|cause| format!("integration test lock: {cause}"))?;

        runtime()?.block_on(async {
            let mut client = Tokio::with_keytab(
                configured_kdc_config()?,
                KdcProtocol::Auto,
                Principal::user(REALM, USER),
                testuser_keytab()?,
            )
            .with_transport(TokioKdcTransport::new().with_timeout(Duration::from_secs(10)));
            let _: &AsRepSession = client.login().await?;
            let error = client
                .get_service_ticket(Principal::new(REALM, 2, ["host.test.gokrb5"]))
                .await
                .err()
                .ok_or("invalid service principal must be rejected")?;

            assert!(
                matches!(&error, ClientError::Kdc(kdc_error) if kdc_error.error_code == 7_i32),
                "expected KDC service-principal error, got {error}"
            );

            Ok::<_, Box<dyn Error>>(())
        })
    }

    /// Pins that a TCP login fails when the only configured KDC is unreachable.
    #[test]
    fn docker_mit_kdc_tcp_login_fails_for_unreachable_kdc() -> Result<(), Box<dyn Error>> {
        if !integration_enabled_for(&[])? {
            return Ok(());
        }
        let _guard = INTEGRATION_LOCK
            .lock()
            .map_err(|cause| format!("integration test lock: {cause}"))?;

        runtime()?.block_on(async {
            let mut client = Tokio::with_keytab(
                configured_kdc_config_with_primary_realm_kdcs(&[closed_tcp_kdc_addr()])?,
                KdcProtocol::Tcp,
                Principal::user(REALM, USER),
                testuser_keytab()?,
            )
            .with_transport(TokioKdcTransport::new().with_timeout(Duration::from_secs(10)));

            assert!(
                client.login().await.is_err(),
                "login through an unreachable KDC must fail"
            );

            Ok::<_, Box<dyn Error>>(())
        })
    }

    /// Pins that a TCP login moves on to the next configured KDC after an unreachable one.
    #[test]
    fn docker_mit_kdc_tcp_login_tries_next_configured_kdc() -> Result<(), Box<dyn Error>> {
        if !integration_enabled()? {
            return Ok(());
        }
        let _guard = INTEGRATION_LOCK
            .lock()
            .map_err(|cause| format!("integration test lock: {cause}"))?;

        runtime()?.block_on(async {
            let mut client = Tokio::with_keytab(
                configured_kdc_config_with_primary_realm_kdcs(&[
                    closed_tcp_kdc_addr(),
                    kdc_addr(),
                ])?,
                KdcProtocol::Tcp,
                Principal::user(REALM, USER),
                testuser_keytab()?,
            )
            .with_transport(TokioKdcTransport::new().with_timeout(Duration::from_secs(10)));
            let session = client.login().await?;

            assert_login_session(&session.clone());

            Ok::<_, Box<dyn Error>>(())
        })
    }

    /// Pins that the Tokio client caches one service ticket and returns it on the second request.
    #[test]
    fn docker_mit_kdc_tokio_client_password_cache() -> Result<(), Box<dyn Error>> {
        if !integration_enabled()? {
            return Ok(());
        }
        let _guard = INTEGRATION_LOCK
            .lock()
            .map_err(|cause| format!("integration test lock: {cause}"))?;

        runtime()?.block_on(async {
            let config = configured_kdc_config()?;

            for protocol in [KdcProtocol::Udp, KdcProtocol::Tcp] {
                writeln!(
                    io::stderr(),
                    "running high-level Tokio client cached TGS flow over {}",
                    protocol_label(protocol)
                )?;
                let mut client = Tokio::with_password(
                    config.clone(),
                    protocol,
                    Principal::user(REALM, USER),
                    PASSWORD,
                )
                .with_transport(TokioKdcTransport::new().with_timeout(Duration::from_secs(10)));

                let service = service_principal();
                let first = client.get_service_ticket(service.clone()).await?;
                let second = client.get_service_ticket(service.clone()).await?;

                assert_eq!(client.client_principal(), &Principal::user(REALM, USER));
                assert!(client.tgt_session().is_some());
                assert_eq!(client.cached_service_ticket_count(), 1);
                assert_eq!(first, second);
                assert_eq!(first.client, Principal::user(REALM, USER));
                assert_eq!(first.service, service);
                assert_eq!(first.session_key.etype, AES256_ETYPE);
                assert!(!first.ticket.is_empty(), "first.ticket must not be empty");
            }

            Ok::<_, Box<dyn Error>>(())
        })
    }

    /// Pins that `destroy` drops the TGT, the cached tickets and the credentials.
    #[test]
    fn docker_mit_kdc_tokio_client_destroy_clears_live_state() -> Result<(), Box<dyn Error>> {
        if !integration_enabled()? {
            return Ok(());
        }
        let _guard = INTEGRATION_LOCK
            .lock()
            .map_err(|cause| format!("integration test lock: {cause}"))?;

        runtime()?.block_on(async {
            let service = service_principal();
            let mut client = Tokio::with_keytab(
                configured_kdc_config()?,
                KdcProtocol::Auto,
                Principal::user(REALM, USER),
                testuser_keytab()?,
            )
            .with_transport(TokioKdcTransport::new().with_timeout(Duration::from_secs(10)));
            let _: &AsRepSession = client.login().await?;
            let ticket = client.get_service_ticket(service.clone()).await?;

            assert_login_session(&client.tgt_session().ok_or("TGT is cached")?.clone());
            assert_eq!(ticket.service, service);
            assert_eq!(client.cached_service_ticket_count(), 1);
            assert!(client.cached_service_ticket(service.clone()).is_some());

            client.destroy();

            assert!(client.tgt_session().is_none());
            assert_eq!(client.tgt_session_count(), 0);
            assert_eq!(client.cached_service_ticket_count(), 0);
            assert!(client.cached_service_ticket(service).is_none());
            let error = client
                .login()
                .await
                .err()
                .ok_or("destroyed client must not log in without credentials")?;
            assert!(matches!(error, ClientError::NoClientCredentials));

            Ok::<_, Box<dyn Error>>(())
        })
    }

    /// Pins that the Tokio client changes the password through kpasswd and back (`TEST_KPASSWD=1`).
    #[test]
    fn docker_mit_kdc_tokio_client_change_password() -> Result<(), Box<dyn Error>> {
        if env::var("TEST_KPASSWD").as_deref() != Ok("1") {
            writeln!(
                io::stderr(),
                "skipping Docker KDC kpasswd test; set TEST_KPASSWD=1 to enable"
            )?;
            return Ok(());
        }
        if !integration_enabled_for(&[(kdc_addr(), "primary KDC"), (kpasswd_addr(), "kpasswd")])? {
            return Ok(());
        }
        let _guard = INTEGRATION_LOCK
            .lock()
            .map_err(|cause| format!("integration test lock: {cause}"))?;

        runtime()?.block_on(async {
            let config = configured_kpasswd_config()?;
            let protocol = KdcProtocol::Tcp;

            if password_login(&config, protocol, PASSWORD).await.is_err() {
                writeln!(
                    io::stderr(),
                    "original Docker KDC password did not authenticate; \
                     attempting temp-password restore"
                )?;
                drop(change_password_once(&config, protocol, TEMP_PASSWORD, PASSWORD).await?);
                drop(password_login(&config, protocol, PASSWORD).await?);
            }

            writeln!(
                io::stderr(),
                "running high-level Tokio client kpasswd change over {}",
                protocol_label(protocol)
            )?;
            let mut client = Tokio::with_password(
                config.clone(),
                protocol,
                Principal::user(REALM, USER),
                PASSWORD.to_vec(),
            )
            .with_transport(TokioKdcTransport::new().with_timeout(Duration::from_secs(10)));

            let changed = client
                .change_password(
                    Password::from_vec(TEMP_PASSWORD.to_vec()),
                    kpasswd_sender_address()?,
                )
                .await?;
            assert_eq!(changed.code, KPASSWD_SUCCESS);

            let restored = client
                .change_password(
                    Password::from_vec(PASSWORD.to_vec()),
                    kpasswd_sender_address()?,
                )
                .await?;
            assert_eq!(restored.code, KPASSWD_SUCCESS);

            let session = password_login(&config, protocol, PASSWORD).await?;
            assert_login_session(&session);

            Ok::<_, Box<dyn Error>>(())
        })
    }

    /// Pins that DNS SRV discovery finds the KDCs and a login through them succeeds (`TEST_DNS_KDC=1`).
    #[test]
    fn docker_mit_kdc_dns_srv_as_login() -> Result<(), Box<dyn Error>> {
        if !integration_enabled()? {
            return Ok(());
        }
        if env::var("TEST_DNS_KDC").as_deref() != Ok("1") {
            writeln!(
                io::stderr(),
                "skipping Docker KDC DNS integration test; set TEST_DNS_KDC=1 to enable"
            )?;
            return Ok(());
        }
        let _guard = INTEGRATION_LOCK
            .lock()
            .map_err(|cause| format!("integration test lock: {cause}"))?;

        runtime()?.block_on(async {
            let config = dns_kdc_config()?;
            let mut transport = TokioKdcTransport::new().with_timeout(Duration::from_secs(10));
            match env::var("RSKRB5_DNS_SERVER") {
                Ok(server) => transport = transport.with_dns_server(&server)?,
                Err(env::VarError::NotPresent) => {}
                Err(error) => return Err(error.into()),
            }

            for protocol in [KdcProtocol::Udp, KdcProtocol::Tcp] {
                let endpoints = transport.discover_kdcs(&config, REALM, protocol).await?;
                writeln!(
                    io::stderr(),
                    "running DNS SRV Docker KDC AS login over {}: {}",
                    protocol_label(protocol),
                    endpoint_list(&endpoints)
                )?;
                assert!(
                    endpoints
                        .iter()
                        .all(|endpoint| endpoint.source == KdcEndpointSource::DnsSrv)
                );

                let session = transport
                    .login_tgt_with_password_config(
                        &config,
                        protocol,
                        Principal::user(REALM, USER),
                        PASSWORD,
                        login_options(protocol, 9)?,
                    )
                    .await?;
                assert_login_session(&session);
            }

            Ok::<_, Box<dyn Error>>(())
        })
    }

    /// Pins that a TGS exchange yields an AES256 HTTP service ticket over UDP and TCP.
    #[test]
    fn docker_mit_kdc_tgs_service_ticket_through_tcp_and_udp() -> Result<(), Box<dyn Error>> {
        if !integration_enabled()? {
            return Ok(());
        }
        let _guard = INTEGRATION_LOCK
            .lock()
            .map_err(|cause| format!("integration test lock: {cause}"))?;

        runtime()?.block_on(async {
            let addr = kdc_addr();
            let transport = TokioKdcTransport::new().with_timeout(Duration::from_secs(10));

            for protocol in [KdcProtocol::Udp, KdcProtocol::Tcp] {
                writeln!(
                    io::stderr(),
                    "running Docker KDC TGS service-ticket exchange over {} to {addr}",
                    protocol_label(protocol)
                )?;
                let tgt = transport
                    .login_tgt_with_password(
                        protocol,
                        addr.as_str(),
                        Principal::user(REALM, USER),
                        PASSWORD,
                        login_options(protocol, 3)?,
                    )
                    .await?;
                assert_login_session(&tgt.clone());

                let service = service_principal();
                let request = build_tgs_req(&tgt, service.clone(), tgs_options(protocol, 4)?)?;
                let ticket = transport
                    .exchange_tgs_req(protocol, addr.as_str(), &request, &tgt.session_key)
                    .await?;

                assert_eq!(ticket.client, Principal::user(REALM, USER));
                assert_eq!(ticket.service, service);
                assert_eq!(ticket.session_key.etype, AES256_ETYPE);
                assert!(
                    !ticket.session_key.value.is_empty(),
                    "ticket.session_key.value must not be empty"
                );
                assert!(!ticket.ticket.is_empty(), "ticket.ticket must not be empty");
                assert!(ticket.end_time > ticket.start_time);
            }

            Ok::<_, Box<dyn Error>>(())
        })
    }

    /// Pins that the Auto protocol completes an AS and a TGS exchange.
    #[test]
    fn docker_mit_kdc_auto_as_tgs_service_ticket() -> Result<(), Box<dyn Error>> {
        if !integration_enabled()? {
            return Ok(());
        }
        let _guard = INTEGRATION_LOCK
            .lock()
            .map_err(|cause| format!("integration test lock: {cause}"))?;

        runtime()?.block_on(async {
            let addr = kdc_addr();
            let transport = TokioKdcTransport::new().with_timeout(Duration::from_secs(10));
            let protocol = KdcProtocol::Auto;

            writeln!(
                io::stderr(),
                "running Docker KDC auto AS/TGS exchange to {addr}"
            )?;
            let tgt = transport
                .login_tgt_with_password(
                    protocol,
                    addr.as_str(),
                    Principal::user(REALM, USER),
                    PASSWORD,
                    login_options(protocol, 47)?,
                )
                .await?;
            assert_login_session(&tgt.clone());

            let service = service_principal();
            let request = build_tgs_req(&tgt, service.clone(), tgs_options(protocol, 48)?)?;
            let ticket = transport
                .exchange_tgs_req(protocol, addr.as_str(), &request, &tgt.session_key)
                .await?;

            assert_eq!(ticket.client, Principal::user(REALM, USER));
            assert_eq!(ticket.service, service);
            assert_eq!(ticket.session_key.etype, AES256_ETYPE);
            assert!(
                !ticket.session_key.value.is_empty(),
                "ticket.session_key.value must not be empty"
            );
            assert!(!ticket.ticket.is_empty(), "ticket.ticket must not be empty");
            assert!(ticket.end_time > ticket.start_time);

            Ok::<_, Box<dyn Error>>(())
        })
    }

    /// Pins that AS and TGS exchanges restricted to AES128 yield AES128 keys over UDP and TCP.
    #[test]
    fn docker_mit_kdc_aes128_as_tgs_through_tcp_and_udp() -> Result<(), Box<dyn Error>> {
        if !integration_enabled()? {
            return Ok(());
        }
        let _guard = INTEGRATION_LOCK
            .lock()
            .map_err(|cause| format!("integration test lock: {cause}"))?;

        runtime()?.block_on(async {
            let addr = kdc_addr();
            let transport = TokioKdcTransport::new().with_timeout(Duration::from_secs(10));

            for protocol in [KdcProtocol::Udp, KdcProtocol::Tcp] {
                writeln!(
                    io::stderr(),
                    "running Docker KDC AES128 AS/TGS exchange over {} to {addr}",
                    protocol_label(protocol)
                )?;
                let tgt = transport
                    .login_tgt_with_password(
                        protocol,
                        addr.as_str(),
                        Principal::user(REALM, USER),
                        PASSWORD,
                        login_options_with_etypes(protocol, 27, vec![AES128_ETYPE])?,
                    )
                    .await?;
                assert_eq!(tgt.session_key.etype, AES128_ETYPE);
                assert!(
                    !tgt.session_key.value.is_empty(),
                    "tgt.session_key.value must not be empty"
                );

                let service = service_principal();
                let request = build_tgs_req(
                    &tgt,
                    service.clone(),
                    tgs_options_with_etypes(protocol, 28, vec![AES128_ETYPE])?,
                )?;
                let ticket = transport
                    .exchange_tgs_req(protocol, addr.as_str(), &request, &tgt.session_key)
                    .await?;

                assert_eq!(ticket.client, Principal::user(REALM, USER));
                assert_eq!(ticket.service, service);
                assert_eq!(ticket.session_key.etype, AES128_ETYPE);
                assert!(
                    !ticket.session_key.value.is_empty(),
                    "ticket.session_key.value must not be empty"
                );
                assert!(!ticket.ticket.is_empty(), "ticket.ticket must not be empty");
                assert!(ticket.end_time > ticket.start_time);
            }

            Ok::<_, Box<dyn Error>>(())
        })
    }

    /// Pins that AS and TGS exchanges restricted to RC4-HMAC yield RC4 keys over UDP and TCP.
    #[test]
    fn docker_mit_kdc_rc4_hmac_tgs_service_ticket_through_tcp_and_udp() -> Result<(), Box<dyn Error>>
    {
        if !integration_enabled()? {
            return Ok(());
        }
        let _guard = INTEGRATION_LOCK
            .lock()
            .map_err(|cause| format!("integration test lock: {cause}"))?;

        runtime()?.block_on(async {
            let addr = kdc_addr();
            let transport = TokioKdcTransport::new().with_timeout(Duration::from_secs(10));

            for protocol in [KdcProtocol::Udp, KdcProtocol::Tcp] {
                writeln!(
                    io::stderr(),
                    "running Docker KDC RC4-HMAC TGS service-ticket exchange over {} to {addr}",
                    protocol_label(protocol)
                )?;
                let tgt = transport
                    .login_tgt_with_password(
                        protocol,
                        addr.as_str(),
                        Principal::user(REALM, USER),
                        PASSWORD,
                        login_options_with_etypes(protocol, 15, vec![RC4_HMAC_ETYPE])?,
                    )
                    .await?;
                assert_eq!(tgt.session_key.etype, RC4_HMAC_ETYPE);

                let service = service_principal();
                let request = build_tgs_req(
                    &tgt,
                    service.clone(),
                    tgs_options_with_etypes(protocol, 16, vec![RC4_HMAC_ETYPE])?,
                )?;
                let ticket = transport
                    .exchange_tgs_req(protocol, addr.as_str(), &request, &tgt.session_key)
                    .await?;

                assert_eq!(ticket.client, Principal::user(REALM, USER));
                assert_eq!(ticket.service, service);
                assert_eq!(ticket.session_key.etype, RC4_HMAC_ETYPE);
                assert!(
                    !ticket.session_key.value.is_empty(),
                    "ticket.session_key.value must not be empty"
                );
                assert!(!ticket.ticket.is_empty(), "ticket.ticket must not be empty");
                assert!(ticket.end_time > ticket.start_time);
            }

            Ok::<_, Box<dyn Error>>(())
        })
    }

    /// Pins that AS and TGS exchanges restricted to DES3 yield DES3 keys over UDP and TCP.
    #[test]
    fn docker_mit_kdc_des3_tgs_service_ticket_through_tcp_and_udp() -> Result<(), Box<dyn Error>> {
        if !integration_enabled()? {
            return Ok(());
        }
        let _guard = INTEGRATION_LOCK
            .lock()
            .map_err(|cause| format!("integration test lock: {cause}"))?;

        runtime()?.block_on(async {
            let addr = kdc_addr();
            let transport = TokioKdcTransport::new().with_timeout(Duration::from_secs(10));

            for protocol in [KdcProtocol::Udp, KdcProtocol::Tcp] {
                writeln!(
                    io::stderr(),
                    "running Docker KDC DES3 TGS service-ticket exchange over {} to {addr}",
                    protocol_label(protocol)
                )?;
                let tgt = transport
                    .login_tgt_with_password(
                        protocol,
                        addr.as_str(),
                        Principal::user(REALM, USER),
                        PASSWORD,
                        login_options_with_etypes(protocol, 20, vec![DES3_ETYPE])?,
                    )
                    .await?;
                assert_eq!(tgt.session_key.etype, DES3_ETYPE);

                let service = service_principal();
                let request = build_tgs_req(
                    &tgt,
                    service.clone(),
                    tgs_options_with_etypes(protocol, 21, vec![DES3_ETYPE])?,
                )?;
                let ticket = transport
                    .exchange_tgs_req(protocol, addr.as_str(), &request, &tgt.session_key)
                    .await?;

                assert_eq!(ticket.client, Principal::user(REALM, USER));
                assert_eq!(ticket.service, service);
                assert_eq!(ticket.session_key.etype, DES3_ETYPE);
                assert_eq!(
                    ticket.session_key.value.len(),
                    Des3CbcSha1KdEtype::key_len()
                );
                assert!(!ticket.ticket.is_empty(), "ticket.ticket must not be empty");
                assert!(ticket.end_time > ticket.start_time);
            }

            Ok::<_, Box<dyn Error>>(())
        })
    }

    /// Pins that the legacy KDC serves password and keytab AS/TGS exchanges with AES256.
    #[test]
    fn docker_mit_old_kdc_password_and_keytab_as_tgs_through_tcp_and_udp()
    -> Result<(), Box<dyn Error>> {
        if !integration_enabled_for(&[(old_kdc_addr(), "legacy KDC")])? {
            return Ok(());
        }
        let _guard = INTEGRATION_LOCK
            .lock()
            .map_err(|cause| format!("integration test lock: {cause}"))?;

        runtime()?.block_on(async {
            let addr = old_kdc_addr();
            assert_password_as_tgs_for_etypes(&addr, &[AES256_ETYPE], 49).await?;
            assert_keytab_as_tgs_for_etypes(&addr, &[AES256_ETYPE], 51).await?;
            Ok::<_, Box<dyn Error>>(())
        })
    }

    /// Pins that the latest KDC serves password AS/TGS exchanges with both AES-SHA2 enctypes.
    #[test]
    fn docker_mit_latest_kdc_aes_sha2_as_tgs_through_tcp_and_udp() -> Result<(), Box<dyn Error>> {
        if !integration_enabled_for(&[(latest_kdc_addr(), "AES-SHA2 KDC")])? {
            return Ok(());
        }
        let _guard = INTEGRATION_LOCK
            .lock()
            .map_err(|cause| format!("integration test lock: {cause}"))?;

        runtime()?.block_on(async {
            let addr = latest_kdc_addr();
            let transport = TokioKdcTransport::new().with_timeout(Duration::from_secs(10));

            for etype in [AES128_SHA2_ETYPE, AES256_SHA2_ETYPE] {
                for protocol in [KdcProtocol::Udp, KdcProtocol::Tcp] {
                    writeln!(
                        io::stderr(),
                        "running Docker latest-KDC AES-SHA2 etype {etype} AS/TGS exchange \
                     over {} to {addr}",
                        protocol_label(protocol)
                    )?;
                    let tgt = transport
                        .login_tgt_with_password(
                            protocol,
                            addr.as_str(),
                            Principal::user(REALM, USER),
                            PASSWORD,
                            login_options_with_etypes(
                                protocol,
                                u32::try_from(etype)?.saturating_add(4),
                                vec![etype],
                            )?,
                        )
                        .await?;
                    assert_eq!(tgt.session_key.etype, etype);
                    assert!(
                        !tgt.session_key.value.is_empty(),
                        "tgt.session_key.value must not be empty"
                    );

                    let service = service_principal();
                    let request = build_tgs_req(
                        &tgt,
                        service.clone(),
                        tgs_options_with_etypes(
                            protocol,
                            u32::try_from(etype)?.saturating_add(6),
                            vec![etype],
                        )?,
                    )?;
                    let ticket = transport
                        .exchange_tgs_req(protocol, addr.as_str(), &request, &tgt.session_key)
                        .await?;

                    assert_eq!(ticket.client, Principal::user(REALM, USER));
                    assert_eq!(ticket.service, service);
                    assert_eq!(ticket.session_key.etype, etype);
                    assert!(
                        !ticket.session_key.value.is_empty(),
                        "ticket.session_key.value must not be empty"
                    );
                    assert!(!ticket.ticket.is_empty(), "ticket.ticket must not be empty");
                    assert!(ticket.end_time > ticket.start_time);
                }
            }

            Ok::<_, Box<dyn Error>>(())
        })
    }

    /// Pins that keytab AS/TGS exchanges work with AES128, AES256, DES3 and RC4-HMAC keys.
    #[test]
    fn docker_mit_kdc_keytab_enctype_as_tgs_through_tcp_and_udp() -> Result<(), Box<dyn Error>> {
        if !integration_enabled()? {
            return Ok(());
        }
        let _guard = INTEGRATION_LOCK
            .lock()
            .map_err(|cause| format!("integration test lock: {cause}"))?;

        runtime()?.block_on(assert_keytab_as_tgs_for_etypes(
            &kdc_addr(),
            &[AES128_ETYPE, AES256_ETYPE, DES3_ETYPE, RC4_HMAC_ETYPE],
            29,
        ))
    }

    /// Pins that the latest KDC serves keytab AS/TGS exchanges with both AES-SHA2 enctypes.
    #[test]
    fn docker_mit_latest_kdc_keytab_aes_sha2_as_tgs_through_tcp_and_udp()
    -> Result<(), Box<dyn Error>> {
        if !integration_enabled_for(&[(latest_kdc_addr(), "AES-SHA2 KDC")])? {
            return Ok(());
        }
        let _guard = INTEGRATION_LOCK
            .lock()
            .map_err(|cause| format!("integration test lock: {cause}"))?;

        runtime()?.block_on(assert_keytab_as_tgs_for_etypes(
            &latest_kdc_addr(),
            &[AES128_SHA2_ETYPE, AES256_SHA2_ETYPE],
            45,
        ))
    }

    /// Pins that a credential cache written by MIT `kinit` loads with its TGT (`TESTPRIVILEGED=1`).
    #[test]
    fn docker_mit_kdc_loads_external_kinit_ccache() -> Result<(), Box<dyn Error>> {
        if !privileged_integration_enabled()? {
            return Ok(());
        }
        let _guard = INTEGRATION_LOCK
            .lock()
            .map_err(|cause| format!("integration test lock: {cause}"))?;

        let env = ExternalKrbEnv::new("load-kinit")?;
        env.kinit()?;
        let cache = CCache::load_name(&env.ccache_name)?;

        assert_eq!(cache.default_principal().name_string(), USER);
        assert_eq!(cache.default_principal().realm, REALM);
        assert!(cache.contains_server(&["krbtgt", REALM]));

        Ok(())
    }

    /// Pins that a service ticket fetched by MIT `kvno` is read from the cache (`TESTPRIVILEGED=1`).
    #[test]
    fn docker_mit_kdc_reads_external_kvno_service_ticket_ccache() -> Result<(), Box<dyn Error>> {
        if !privileged_integration_enabled()? {
            return Ok(());
        }
        if !privileged_kvno_integration_enabled()? {
            return Ok(());
        }
        let _guard = INTEGRATION_LOCK
            .lock()
            .map_err(|cause| format!("integration test lock: {cause}"))?;

        let env = ExternalKrbEnv::new("kvno-service")?;
        env.kinit()?;
        env.kvno(&format!("HTTP/{SERVICE_HOST}"))?;
        let cache = CCache::load_name(&env.ccache_name)?;

        assert!(cache.contains_server(&["HTTP", SERVICE_HOST]));
        let service = cache
            .get_entry(&["HTTP", SERVICE_HOST])
            .ok_or("HTTP service ticket is cached")?;
        assert_eq!(service.server.realm, REALM);
        assert_eq!(service.key.etype, AES256_ETYPE);

        Ok(())
    }

    /// Pins that a Tokio client built from a `kinit` cache gets and caches a service ticket.
    #[test]
    fn docker_mit_kdc_tokio_client_uses_external_ccache_tgt() -> Result<(), Box<dyn Error>> {
        if !privileged_integration_enabled()? {
            return Ok(());
        }
        let _guard = INTEGRATION_LOCK
            .lock()
            .map_err(|cause| format!("integration test lock: {cause}"))?;

        let env = ExternalKrbEnv::new("client-tgt")?;
        env.kinit()?;
        let cache = CCache::load_name(&env.ccache_name)?;

        runtime()?.block_on(async {
            let mut client =
                Tokio::from_ccache(configured_kdc_config()?, KdcProtocol::Auto, &cache)
                    .with_transport(TokioKdcTransport::new().with_timeout(Duration::from_secs(10)));
            let first = client.get_service_ticket(service_principal()).await?;
            let second = client.get_service_ticket(service_principal()).await?;

            assert_eq!(first, second);
            assert_eq!(first.client, Principal::user(REALM, USER));
            assert_eq!(first.service, service_principal());
            assert_eq!(first.session_key.etype, AES256_ETYPE);
            assert_eq!(client.cached_service_ticket_count(), 1);

            Ok::<_, Box<dyn Error>>(())
        })
    }

    /// Pins that a service ticket already in a `kvno` cache is used without any KDC configured.
    #[test]
    fn docker_mit_kdc_tokio_client_uses_cached_service_ticket_without_kdc()
    -> Result<(), Box<dyn Error>> {
        if !privileged_integration_enabled()? {
            return Ok(());
        }
        if !privileged_kvno_integration_enabled()? {
            return Ok(());
        }
        let _guard = INTEGRATION_LOCK
            .lock()
            .map_err(|cause| format!("integration test lock: {cause}"))?;

        let env = ExternalKrbEnv::new("client-cached-service")?;
        env.kinit()?;
        env.kvno(&format!("HTTP/{SERVICE_HOST}"))?;
        let cache = CCache::load_name(&env.ccache_name)?;

        runtime()?.block_on(async {
            let mut client = Tokio::from_ccache(Config::new(), KdcProtocol::Auto, &cache)
                .with_transport(TokioKdcTransport::new().with_timeout(Duration::from_secs(10)));
            let ticket = client.get_service_ticket(service_principal()).await?;

            assert_eq!(ticket.client, Principal::user(REALM, USER));
            assert_eq!(ticket.service, service_principal());
            assert_eq!(ticket.session_key.etype, AES256_ETYPE);

            Ok::<_, Box<dyn Error>>(())
        })
    }

    /// Pins that a renewable TGT renews over UDP and TCP and keeps its renew-till.
    #[test]
    fn docker_mit_kdc_tgt_renewal_through_tcp_and_udp() -> Result<(), Box<dyn Error>> {
        if !integration_enabled_for(&[(short_kdc_addr(), "short-ticket KDC")])? {
            return Ok(());
        }
        let _guard = INTEGRATION_LOCK
            .lock()
            .map_err(|cause| format!("integration test lock: {cause}"))?;

        runtime()?.block_on(async {
            let addr = short_kdc_addr();
            let transport = TokioKdcTransport::new().with_timeout(Duration::from_secs(10));

            for protocol in [KdcProtocol::Udp, KdcProtocol::Tcp] {
                writeln!(
                    io::stderr(),
                    "running Docker KDC TGT renewal over {} to {addr}",
                    protocol_label(protocol)
                )?;
                let tgt = transport
                    .login_tgt_with_password(
                        protocol,
                        addr.as_str(),
                        Principal::user(REALM, USER),
                        PASSWORD,
                        login_options(protocol, 12)?
                            .with_renew_lifetime(Some(Duration::from_mins(10))),
                    )
                    .await?;
                assert_login_session(&tgt.clone());
                let original_renew_till = tgt.renew_till.ok_or("renewable TGT has renew-till")?;

                let renewed = transport
                    .renew_tgt(protocol, addr.as_str(), &tgt, tgs_options(protocol, 13)?)
                    .await?;

                assert_login_session(&renewed.clone());
                assert_eq!(renewed.service, Principal::tgt_service(REALM));
                assert_eq!(renewed.renew_till, Some(original_renew_till));
                assert!(renewed.end_time <= original_renew_till);
            }

            Ok::<_, Box<dyn Error>>(())
        })
    }

    /// Pins that the Tokio client renews its TGT and keeps the renew-till.
    #[test]
    fn docker_mit_kdc_tokio_client_tgt_renewal() -> Result<(), Box<dyn Error>> {
        if !integration_enabled_for(&[(short_kdc_addr(), "short-ticket KDC")])? {
            return Ok(());
        }
        let _guard = INTEGRATION_LOCK
            .lock()
            .map_err(|cause| format!("integration test lock: {cause}"))?;

        runtime()?.block_on(async {
            let config = short_kdc_config()?;

            for protocol in [KdcProtocol::Udp, KdcProtocol::Tcp] {
                writeln!(
                    io::stderr(),
                    "running high-level Tokio client TGT renewal over {}",
                    protocol_label(protocol)
                )?;
                let mut client = Tokio::with_password(
                    config.clone(),
                    protocol,
                    Principal::user(REALM, USER),
                    PASSWORD,
                )
                .with_transport(TokioKdcTransport::new().with_timeout(Duration::from_secs(10)));

                let original = client.login().await?.clone();
                let original_renew_till =
                    original.renew_till.ok_or("renewable TGT has renew-till")?;
                let renewed = client.renew_tgt().await?.clone();

                assert_login_session(&renewed.clone());
                assert_eq!(renewed.service, Principal::tgt_service(REALM));
                assert_eq!(renewed.renew_till, Some(original_renew_till));
                assert!(renewed.end_time <= original_renew_till);
            }

            Ok::<_, Box<dyn Error>>(())
        })
    }

    /// Pins that a TGS request for a resource-domain service follows the cross-realm referral.
    #[test]
    fn docker_mit_kdc_tgs_referral_to_resource_domain() -> Result<(), Box<dyn Error>> {
        if !integration_enabled_for(&[
            (kdc_addr(), "primary KDC"),
            (resdom_kdc_addr(), "resource KDC"),
        ])? {
            return Ok(());
        }
        let _guard = INTEGRATION_LOCK
            .lock()
            .map_err(|cause| format!("integration test lock: {cause}"))?;

        runtime()?.block_on(async {
            let config = configured_kdc_config()?;
            let transport = TokioKdcTransport::new().with_timeout(Duration::from_secs(10));

            for protocol in [KdcProtocol::Udp, KdcProtocol::Tcp] {
                writeln!(
                    io::stderr(),
                    "running Docker KDC TGS referral exchange over {} \
                 from {REALM} to {RESDOM_REALM}",
                    protocol_label(protocol)
                )?;
                let tgt = transport
                    .login_tgt_with_password_config(
                        &config,
                        protocol,
                        Principal::user(REALM, USER),
                        PASSWORD,
                        login_options(protocol, 10)?,
                    )
                    .await?;
                assert_login_session(&tgt.clone());

                let service = resdom_service_principal();
                let ticket = transport
                    .get_service_ticket_with_referrals(
                        &config,
                        protocol,
                        &tgt,
                        service.clone(),
                        tgs_options(protocol, 11)?,
                    )
                    .await?;

                assert_eq!(ticket.client, Principal::user(REALM, USER));
                assert_eq!(ticket.service, service);
                assert_eq!(ticket.session_key.etype, AES256_ETYPE);
                assert!(
                    !ticket.session_key.value.is_empty(),
                    "ticket.session_key.value must not be empty"
                );
                assert!(!ticket.ticket.is_empty(), "ticket.ticket must not be empty");
                assert!(ticket.end_time > ticket.start_time);
            }

            Ok::<_, Box<dyn Error>>(())
        })
    }

    /// Pins that the Tokio client caches the referral TGT and the resource-domain service ticket.
    #[test]
    fn docker_mit_kdc_tokio_client_caches_referral_tgt() -> Result<(), Box<dyn Error>> {
        if !integration_enabled_for(&[
            (kdc_addr(), "primary KDC"),
            (resdom_kdc_addr(), "resource KDC"),
        ])? {
            return Ok(());
        }
        let _guard = INTEGRATION_LOCK
            .lock()
            .map_err(|cause| format!("integration test lock: {cause}"))?;

        runtime()?.block_on(async {
            let config = configured_kdc_config()?;

            for protocol in [KdcProtocol::Udp, KdcProtocol::Tcp] {
                writeln!(
                    io::stderr(),
                    "running high-level Tokio client TGS referral cache over {}",
                    protocol_label(protocol)
                )?;
                let mut client = Tokio::with_password(
                    config.clone(),
                    protocol,
                    Principal::user(REALM, USER),
                    PASSWORD,
                )
                .with_transport(TokioKdcTransport::new().with_timeout(Duration::from_secs(10)));

                let service = resdom_service_principal();
                let first = client.get_service_ticket(service.clone()).await?;
                let second = client.get_service_ticket(service.clone()).await?;

                assert_eq!(first, second);
                assert_eq!(first.client, Principal::user(REALM, USER));
                assert_eq!(first.service, service);
                assert_eq!(first.session_key.etype, AES256_ETYPE);
                assert!(client.tgt_session().is_some());
                assert!(client.tgt_session_for_realm(RESDOM_REALM).is_some());
                assert_eq!(client.tgt_session_count(), 2);
                assert_eq!(client.cached_service_ticket_count(), 1);
            }

            Ok::<_, Box<dyn Error>>(())
        })
    }

    /// Pins an AES SPNEGO header round trip: the validator accepts it and the AP-REP verifies.
    #[cfg(feature = "spnego")]
    #[test]
    fn docker_mit_kdc_spnego_header_round_trip_through_service_validator()
    -> Result<(), Box<dyn Error>> {
        if !integration_enabled()? {
            return Ok(());
        }
        let _guard = INTEGRATION_LOCK
            .lock()
            .map_err(|cause| format!("integration test lock: {cause}"))?;

        runtime()?.block_on(async {
            let addr = kdc_addr();
            let transport = TokioKdcTransport::new().with_timeout(Duration::from_secs(10));

            for protocol in [KdcProtocol::Udp, KdcProtocol::Tcp] {
                writeln!(
                    io::stderr(),
                    "running Docker KDC SPNEGO client header round-trip over {} to {addr}",
                    protocol_label(protocol)
                )?;
                let tgt = transport
                    .login_tgt_with_password(
                        protocol,
                        addr.as_str(),
                        Principal::user(REALM, USER),
                        PASSWORD,
                        login_options(protocol, 5)?,
                    )
                    .await?;
                let service = service_principal();
                let request = build_tgs_req(&tgt, service.clone(), tgs_options(protocol, 6)?)?;
                let service_ticket = transport
                    .exchange_tgs_req(protocol, addr.as_str(), &request, &tgt.session_key)
                    .await?;
                let context = spnego::init_sec_context(
                    &service_ticket,
                    spnego::InitiatorContextOptions::new(),
                )?;
                assert_eq!(context.service, service);
                assert!(context.sequence_number.is_some());

                let keytab = http_keytab()?;
                let mut validator = Validator::new(&keytab).with_now(SystemTime::now());
                validator = validator.with_crypto_policy(context.crypto_policy.clone());
                let accepted = spnego::accept_sec_context_header(&mut validator, &context.header)?;
                assert_eq!(
                    accepted.ap_req.client,
                    ServicePrincipal::new(REALM.to_owned(), 1, vec![USER.to_owned()])
                );
                assert_eq!(accepted.ap_req.service.name(), "HTTP/host.test.gokrb5");

                let elapsed = SystemTime::now().duration_since(UNIX_EPOCH)?;
                let response_header = accepted.ap_rep_response_header_with_confounder(
                    &confounder(protocol, elapsed),
                    &ApRepOptions::default(),
                )?;
                let verified = context.verify_ap_rep_response_header(&response_header)?;
                assert_eq!(verified.ctime, context.authenticator_ctime);
                assert_eq!(verified.cusec, context.authenticator_cusec);
            }

            Ok::<_, Box<dyn Error>>(())
        })
    }

    /// Pins that the SPNEGO acceptor rejects a replay of either of two accepted headers.
    #[cfg(feature = "spnego")]
    #[test]
    fn docker_mit_kdc_spnego_service_rejects_replayed_headers() -> Result<(), Box<dyn Error>> {
        if !integration_enabled()? {
            return Ok(());
        }
        let _guard = INTEGRATION_LOCK
            .lock()
            .map_err(|cause| format!("integration test lock: {cause}"))?;

        runtime()?.block_on(async {
            let mut client = Tokio::with_password(
                configured_kdc_config()?,
                KdcProtocol::Auto,
                Principal::user(REALM, USER),
                PASSWORD,
            )
            .with_transport(TokioKdcTransport::new().with_timeout(Duration::from_secs(10)));
            let service_ticket = client.get_service_ticket(service_principal()).await?;
            let now = SystemTime::now();
            let [first, second] = replay_contexts(&service_ticket, now)?;

            let keytab = http_keytab()?;
            let mut validator = Validator::new(&keytab).with_now(now);
            drop(spnego::accept_sec_context_header(
                &mut validator,
                &first.header,
            )?);
            drop(spnego::accept_sec_context_header(
                &mut validator,
                &second.header,
            )?);

            let first_replay = spnego::accept_sec_context_header(&mut validator, &first.header)
                .err()
                .ok_or("first header replay is rejected")?;
            let second_replay = spnego::accept_sec_context_header(&mut validator, &second.header)
                .err()
                .ok_or("second header replay is rejected")?;

            assert!(matches!(
                first_replay,
                SpnegoError::Service(ServiceError::Replay)
            ));
            assert!(matches!(
                second_replay,
                SpnegoError::Service(ServiceError::Replay)
            ));

            Ok::<_, Box<dyn Error>>(())
        })
    }

    /// Builds the two distinct authentications used by live and offline replay scenarios.
    #[cfg(feature = "spnego")]
    fn replay_contexts(
        session: &AsRepSession,
        now: SystemTime,
    ) -> Result<[spnego::InitiatorContext; 2], Box<dyn Error>> {
        let elapsed = now.duration_since(UNIX_EPOCH)?;
        let seconds = UNIX_EPOCH
            .checked_add(Duration::from_secs(elapsed.as_secs()))
            .ok_or("time")?;
        let cusec = elapsed.subsec_micros();
        let next_cusec = cusec
            .checked_add(1)
            .filter(|value| *value < 1_000_000)
            .unwrap_or(0);
        Ok([
            spnego::init_sec_context_with_confounder(
                session,
                spnego::InitiatorContextOptions::new().with_sequence_number(Some(1)),
                seconds,
                cusec,
                &[0x11; 16],
            )?,
            spnego::init_sec_context_with_confounder(
                session,
                spnego::InitiatorContextOptions::new().with_sequence_number(Some(2)),
                seconds,
                next_cusec,
                &[0x22; 16],
            )?,
        ])
    }

    /// A fractional clock still allows two fresh authentications and rejects both replays.
    #[cfg(feature = "spnego")]
    #[test]
    fn replay_scenario_accepts_fractional_clock() -> Result<(), Box<dyn Error>> {
        use core::str;

        use rskrb5_ng::{ap_req, ticket};
        let request = ap_req::decode(include_bytes!("fixtures/valid_ap_req.der"))?;
        let key = EncryptionKey::new(
            18,
            hex::decode("9cad00bbc72d703258e911dc18e6d5487cf737bf67fd111f0c2463ad6033bf51")?,
        );
        let part = ticket::decrypt_ticket_enc_part(&request.ticket, &key)?;
        let session_key = EncryptionKey::new(part.key.r#type, part.key.value.as_ref().to_vec());
        let auth = ap_req::decrypt_ap_req_authenticator(&request, &session_key, 11)?;
        let now = UNIX_EPOCH
            .checked_add(Duration::from_secs(u64::try_from(
                auth.ctime.0.timestamp(),
            )?))
            .ok_or("time")?
            .checked_add(Duration::from_millis(500))
            .ok_or("time")?;
        let realm = str::from_utf8(request.ticket.realm.as_bytes())?.to_owned();
        let names = request
            .ticket
            .sname
            .string
            .iter()
            .map(|name| str::from_utf8(name.as_bytes()).map(str::to_owned))
            .collect::<Result<Vec<_>, _>>()?;
        let client_names = auth
            .cname
            .string
            .iter()
            .map(|name| str::from_utf8(name.as_bytes()).map(str::to_owned))
            .collect::<Result<Vec<_>, _>>()?;
        let session = AsRepSession::new(
            Principal::new(
                str::from_utf8(auth.crealm.as_bytes())?,
                auth.cname.r#type,
                client_names,
            ),
            Principal::new(realm.clone(), request.ticket.sname.r#type, names.clone()),
            session_key,
            ticket::encode(&request.ticket)?.into(),
            [0; 4],
            now,
            now,
        );
        let contexts = replay_contexts(&session, now)?;
        let mut keys = Keytab::new();
        keys.entries_mut().push(KeytabEntry::new(
            KeytabPrincipal::new(realm, request.ticket.sname.r#type, names),
            0,
            1,
            key,
            1,
        ));
        let mut validator = Validator::new(&keys).with_now(now);
        for context in &contexts {
            drop(spnego::accept_sec_context_header(
                &mut validator,
                &context.header,
            )?);
        }
        for context in &contexts {
            assert!(matches!(
                spnego::accept_sec_context_header(&mut validator, &context.header),
                Err(SpnegoError::Service(ServiceError::Replay))
            ));
        }
        Ok(())
    }

    /// Pins that the client SPNEGO header authenticates to the Docker `mod_auth_gssapi` server.
    #[cfg(feature = "spnego")]
    #[test]
    fn docker_mit_kdc_spnego_header_authenticates_to_docker_http() -> Result<(), Box<dyn Error>> {
        if !integration_enabled()? {
            return Ok(());
        }
        if !http_service_reachable()? {
            return Ok(());
        }
        let _guard = INTEGRATION_LOCK
            .lock()
            .map_err(|cause| format!("integration test lock: {cause}"))?;

        runtime()?.block_on(async {
            let config = configured_kdc_config()?;
            let mut client = Tokio::with_password(
                config,
                KdcProtocol::Auto,
                Principal::user(REALM, USER),
                PASSWORD,
            )
            .with_transport(TokioKdcTransport::new().with_timeout(Duration::from_secs(10)));
            let header = client.spnego_header(service_principal()).await?;
            let response = http_get_with_authorization("/modgssapi/index.html", &header)?;
            let status = response.lines().next().unwrap_or_default();

            assert!(
                status.contains(" 200 "),
                "unexpected Docker HTTP response status: {status}"
            );

            Ok::<_, Box<dyn Error>>(())
        })
    }

    /// Pins that a raw Kerberos token in a Negotiate header authenticates to the Docker HTTP server.
    #[cfg(feature = "spnego")]
    #[test]
    fn docker_mit_kdc_raw_krb5_header_authenticates_to_docker_http() -> Result<(), Box<dyn Error>> {
        if !integration_enabled()? {
            return Ok(());
        }
        if !http_service_reachable()? {
            return Ok(());
        }
        let _guard = INTEGRATION_LOCK
            .lock()
            .map_err(|cause| format!("integration test lock: {cause}"))?;

        runtime()?.block_on(async {
            let mut client = Tokio::with_password(
                configured_kdc_config()?,
                KdcProtocol::Auto,
                Principal::user(REALM, USER),
                PASSWORD,
            )
            .with_transport(TokioKdcTransport::new().with_timeout(Duration::from_secs(10)));
            let service_ticket = client.get_service_ticket(service_principal()).await?;
            let context =
                spnego::init_sec_context(&service_ticket, spnego::InitiatorContextOptions::new())?;
            let header = format!("Negotiate {}", base64_encode(&context.krb5_token.encode()?));
            let response = http_get_with_authorization("/modgssapi/index.html", &header)?;
            let status = response.lines().next().unwrap_or_default();

            assert!(
                status.contains(" 200 "),
                "unexpected Docker HTTP response status: {status}"
            );

            Ok::<_, Box<dyn Error>>(())
        })
    }

    /// Pins an RC4-HMAC SPNEGO header round trip through the service validator.
    #[cfg(feature = "spnego")]
    #[test]
    fn docker_mit_kdc_rc4_hmac_spnego_header_round_trip_through_service_validator()
    -> Result<(), Box<dyn Error>> {
        if !integration_enabled()? {
            return Ok(());
        }
        let _guard = INTEGRATION_LOCK
            .lock()
            .map_err(|cause| format!("integration test lock: {cause}"))?;

        runtime()?.block_on(async {
            let addr = kdc_addr();
            let transport = TokioKdcTransport::new().with_timeout(Duration::from_secs(10));

            for protocol in [KdcProtocol::Udp, KdcProtocol::Tcp] {
                writeln!(
                    io::stderr(),
                    "running Docker KDC RC4-HMAC SPNEGO client header round-trip over {} to {addr}",
                    protocol_label(protocol)
                )?;
                let tgt = transport
                    .login_tgt_with_password(
                        protocol,
                        addr.as_str(),
                        Principal::user(REALM, USER),
                        PASSWORD,
                        login_options_with_etypes(protocol, 17, vec![RC4_HMAC_ETYPE])?,
                    )
                    .await?;
                assert_eq!(tgt.session_key.etype, RC4_HMAC_ETYPE);

                let service = service_principal();
                let request = build_tgs_req(
                    &tgt,
                    service.clone(),
                    tgs_options_with_etypes(protocol, 18, vec![RC4_HMAC_ETYPE])?,
                )?;
                let service_ticket = transport
                    .exchange_tgs_req(protocol, addr.as_str(), &request, &tgt.session_key)
                    .await?;
                assert_eq!(service_ticket.session_key.etype, RC4_HMAC_ETYPE);

                let context = spnego::init_sec_context(
                    &service_ticket,
                    spnego::InitiatorContextOptions::new()
                        .with_crypto_policy(fixture_crypto_policy(&[RC4_HMAC_ETYPE])?),
                )?;
                assert_eq!(context.service, service);
                assert!(context.sequence_number.is_some());

                let keytab = http_keytab()?;
                let mut validator = Validator::new(&keytab).with_now(SystemTime::now());
                validator = validator.with_crypto_policy(context.crypto_policy.clone());
                let accepted = spnego::accept_sec_context_header(&mut validator, &context.header)?;
                assert_eq!(
                    accepted.ap_req.client,
                    ServicePrincipal::new(REALM.to_owned(), 1, vec![USER.to_owned()])
                );
                assert_eq!(accepted.ap_req.service.name(), "HTTP/host.test.gokrb5");
                assert_eq!(accepted.ap_req.session_key.etype, RC4_HMAC_ETYPE);

                let elapsed = SystemTime::now().duration_since(UNIX_EPOCH)?;
                let response_header = accepted.ap_rep_response_header_with_confounder(
                    &rc4_confounder(protocol, elapsed),
                    &ApRepOptions::default(),
                )?;
                let verified = context.verify_ap_rep_response_header(&response_header)?;
                assert_eq!(verified.ctime, context.authenticator_ctime);
                assert_eq!(verified.cusec, context.authenticator_cusec);
            }

            Ok::<_, Box<dyn Error>>(())
        })
    }

    /// Pins a DES3 SPNEGO header round trip through the service validator.
    #[cfg(feature = "spnego")]
    #[test]
    fn docker_mit_kdc_des3_spnego_header_round_trip_through_service_validator()
    -> Result<(), Box<dyn Error>> {
        if !integration_enabled()? {
            return Ok(());
        }
        let _guard = INTEGRATION_LOCK
            .lock()
            .map_err(|cause| format!("integration test lock: {cause}"))?;

        runtime()?.block_on(async {
            let addr = kdc_addr();
            let transport = TokioKdcTransport::new().with_timeout(Duration::from_secs(10));

            for protocol in [KdcProtocol::Udp, KdcProtocol::Tcp] {
                writeln!(
                    io::stderr(),
                    "running Docker KDC DES3 SPNEGO client header round-trip over {} to {addr}",
                    protocol_label(protocol)
                )?;
                let tgt = transport
                    .login_tgt_with_password(
                        protocol,
                        addr.as_str(),
                        Principal::user(REALM, USER),
                        PASSWORD,
                        login_options_with_etypes(protocol, 22, vec![DES3_ETYPE])?,
                    )
                    .await?;
                assert_eq!(tgt.session_key.etype, DES3_ETYPE);

                let service = service_principal();
                let request = build_tgs_req(
                    &tgt,
                    service.clone(),
                    tgs_options_with_etypes(protocol, 23, vec![DES3_ETYPE])?,
                )?;
                let service_ticket = transport
                    .exchange_tgs_req(protocol, addr.as_str(), &request, &tgt.session_key)
                    .await?;
                assert_eq!(service_ticket.session_key.etype, DES3_ETYPE);

                let context = spnego::init_sec_context(
                    &service_ticket,
                    spnego::InitiatorContextOptions::new()
                        .with_crypto_policy(fixture_crypto_policy(&[DES3_ETYPE])?),
                )?;
                assert_eq!(context.service, service);
                assert!(context.sequence_number.is_some());

                let keytab = http_keytab()?;
                let mut validator = Validator::new(&keytab)
                    .with_now(SystemTime::now())
                    .with_crypto_policy(context.crypto_policy.clone());
                let accepted = spnego::accept_sec_context_header(&mut validator, &context.header)?;
                assert_eq!(
                    accepted.ap_req.client,
                    ServicePrincipal::new(REALM.to_owned(), 1, vec![USER.to_owned()])
                );
                assert_eq!(accepted.ap_req.service.name(), "HTTP/host.test.gokrb5");
                assert_eq!(accepted.ap_req.session_key.etype, DES3_ETYPE);

                let elapsed = SystemTime::now().duration_since(UNIX_EPOCH)?;
                let response_header = accepted.ap_rep_response_header_with_confounder(
                    &des3_confounder(protocol, elapsed),
                    &ApRepOptions::default(),
                )?;
                let verified = context.verify_ap_rep_response_header(&response_header)?;
                assert_eq!(verified.ctime, context.authenticator_ctime);
                assert_eq!(verified.cusec, context.authenticator_cusec);
            }

            Ok::<_, Box<dyn Error>>(())
        })
    }

    /// Live legacy options encode exactly their selected enctypes under explicit permission.
    #[test]
    fn legacy_live_options_have_explicit_permission() -> Result<(), Box<dyn Error>> {
        use rasn::der;
        use rskrb5_ng::{ap_req, crypto::Use, error::Policy, ticket};
        for id in [16_i32, 23_i32] {
            let as_options = login_options_with_etypes(KdcProtocol::Tcp, 1, vec![id])?;
            let tgs_options = tgs_options_with_etypes(KdcProtocol::Tcp, 2, vec![id])?;
            as_options
                .crypto_policy
                .as_ref()
                .map_err(Clone::clone)?
                .check_use(id, Use::RequestList)?;
            tgs_options
                .crypto_policy
                .as_ref()
                .map_err(Clone::clone)?
                .check_use(id, Use::RequestList)?;
            let built = build_tgt_as_req(Principal::user(REALM, USER), as_options)?;
            let decoded: rasn_kerberos::AsReq = der::decode(&built.der)?;
            assert_eq!(decoded.0.req_body.etype, vec![id]);
            let service = Principal::tgt_service(REALM);
            let mut ticket = ap_req::decode(include_bytes!("fixtures/valid_ap_req.der"))?.ticket;
            // The session's service must match the encoded ticket (FU-CLI-R06).
            ticket.realm = rasn_kerberos::KerberosString::from_bytes(REALM.as_bytes())?;
            ticket.sname = rasn_kerberos::PrincipalName {
                r#type: service.name_type,
                string: service
                    .components
                    .iter()
                    .map(|value| rasn_kerberos::KerberosString::from_bytes(value.as_bytes()))
                    .collect::<Result<_, _>>()?,
            };
            let now = SystemTime::UNIX_EPOCH
                .checked_add(Duration::from_secs(1_893_553_447))
                .ok_or("time")?;
            let session = AsRepSession::new(
                Principal::user(REALM, USER),
                service,
                EncryptionKey::new(18, vec![0x11; 32]),
                ticket::encode(&ticket)?.into(),
                [0; 4],
                now,
                now,
            );
            let tgs = build_tgs_req(&session, service_principal(), tgs_options)?;
            let decoded_tgs: rasn_kerberos::TgsReq = der::decode(&tgs.der)?;
            assert_eq!(decoded_tgs.0.req_body.etype, vec![id]);
            assert!(matches!(
                CryptoPolicy::default().check_use(id, Use::RequestList),
                Err(Policy::EnctypeNotPermitted { etype: _, usage: _ })
            ));
        }
        Ok(())
    }

    /// Builds AS-REQ options with AES256 and a nonce unique to `protocol` and `sequence`.
    fn login_options(protocol: KdcProtocol, sequence: u32) -> Result<AsReq, Box<dyn Error>> {
        login_options_with_etypes(protocol, sequence, vec![AES256_ETYPE])
    }

    /// Builds AS-REQ options for `etypes` with a nonce unique to `protocol` and `sequence`.
    fn login_options_with_etypes(
        protocol: KdcProtocol,
        sequence: u32,
        etypes: Vec<i32>,
    ) -> Result<AsReq, Box<dyn Error>> {
        let now = SystemTime::now();
        let elapsed = now.duration_since(UNIX_EPOCH)?;
        let nonce = (u32::try_from(elapsed.as_nanos() & 0x00ff_ffff)? | sequence.wrapping_shl(24))
            | match protocol {
                KdcProtocol::Udp => 0x1000_0000,
                KdcProtocol::Tcp => 0x2000_0000,
                KdcProtocol::Auto => 0x3000_0000,

                _ => return Err("unexpected non-exhaustive protocol variant".into()),
            };
        let policy = fixture_crypto_policy(&etypes)?;
        let mut options = AsReq::new(now, nonce)
            .with_ticket_lifetime(Duration::from_hours(24))
            .with_etypes(etypes);
        options.crypto_policy = Ok(policy);
        Ok(options)
    }

    /// Builds TGS-REQ options with AES256 and a nonce unique to `protocol` and `sequence`.
    fn tgs_options(protocol: KdcProtocol, sequence: u32) -> Result<TgsReq, Box<dyn Error>> {
        tgs_options_with_etypes(protocol, sequence, vec![AES256_ETYPE])
    }

    /// Builds TGS-REQ options for `etypes` with a nonce unique to `protocol` and `sequence`.
    fn tgs_options_with_etypes(
        protocol: KdcProtocol,
        sequence: u32,
        etypes: Vec<i32>,
    ) -> Result<TgsReq, Box<dyn Error>> {
        let now = SystemTime::now();
        let elapsed = now.duration_since(UNIX_EPOCH)?;
        let nonce = (u32::try_from(elapsed.as_nanos() & 0x00ff_ffff)? | sequence.wrapping_shl(24))
            | match protocol {
                KdcProtocol::Udp => 0x1000_0000,
                KdcProtocol::Tcp => 0x2000_0000,
                KdcProtocol::Auto => 0x3000_0000,

                _ => return Err("unexpected non-exhaustive protocol variant".into()),
            };
        let policy = fixture_crypto_policy(&etypes)?;
        let mut options = TgsReq::new(now, nonce)
            .with_ticket_lifetime(Duration::from_hours(24))
            .with_etypes(etypes);
        options.crypto_policy = Ok(policy);
        Ok(options)
    }

    /// Opt in only to legacy families explicitly requested by a live fixture.
    fn fixture_crypto_policy(etypes: &[i32]) -> Result<CryptoPolicy, Box<dyn Error>> {
        let mut config = Config::new();
        config.libdefaults.allow_rc4 = etypes.contains(&23_i32).into();
        config.libdefaults.allow_des3 = etypes.contains(&16_i32).into();
        if etypes.contains(&23_i32) {
            config.libdefaults.permitted_enctypes.push("rc4".to_owned());
        }
        if etypes.contains(&16_i32) {
            config
                .libdefaults
                .permitted_enctypes
                .push("des3".to_owned());
        }
        Ok(CryptoPolicy::from_libdefaults(&config.libdefaults)?)
    }

    /// Returns the `HTTP/host.test.gokrb5` service principal.
    fn service_principal() -> Principal {
        Principal::new(REALM, 2, ["HTTP", SERVICE_HOST])
    }

    /// Returns the `HTTP/host.resdom.gokrb5` service principal of the resource realm.
    fn resdom_service_principal() -> Principal {
        Principal::new(RESDOM_REALM, 2, ["HTTP", RESDOM_SERVICE_HOST])
    }

    /// Sends one `GET` with an `Authorization` header to the Docker HTTP fixture and returns the raw response.
    #[cfg(feature = "spnego")]
    fn http_get_with_authorization(
        path: &str,
        authorization: &str,
    ) -> Result<String, Box<dyn Error>> {
        let HttpTarget {
            authority,
            addr,
            path: target_path,
        } = http_target(path)?;
        let mut stream = TcpStream::connect(&addr)?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;
        write!(
            stream,
            "GET {target_path} HTTP/1.1\r\nHost: {authority}\r\nAuthorization: {authorization}\r\nConnection: close\r\n\r\n",
        )?;

        let mut response = String::new();
        let _: usize = stream.read_to_string(&mut response)?;
        Ok(response)
    }

    /// Where and how to reach the Docker HTTP fixture.
    #[cfg(feature = "spnego")]
    struct HttpTarget {
        /// `Host` header value.
        authority: String,
        /// Socket address to connect to.
        addr: String,
        /// Absolute request path.
        path: String,
    }

    /// Resolves the Docker HTTP fixture from `TEST_HTTP_URL` and `TEST_HTTP_ADDR`.
    #[cfg(feature = "spnego")]
    fn http_target(path: &str) -> Result<HttpTarget, Box<dyn Error>> {
        let base = env::var("TEST_HTTP_URL").unwrap_or_else(|_| "http://127.0.0.1".to_owned());
        let Some(without_scheme) = base.strip_prefix("http://") else {
            return Err(format!("TEST_HTTP_URL must be an http:// URL: {base}").into());
        };
        let (authority, base_path) = without_scheme
            .split_once('/')
            .map_or((without_scheme, ""), |(host, rest)| (host, rest));
        if authority.is_empty() {
            return Err("TEST_HTTP_URL must include a host".into());
        }

        let port = authority
            .rsplit_once(':')
            .map(|(_, port)| port)
            .filter(|port| port.parse::<u16>().is_ok())
            .unwrap_or("80")
            .to_owned();
        let connect_host = env::var("TEST_HTTP_ADDR")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| authority.to_owned());
        let addr = if connect_host
            .rsplit_once(':')
            .is_some_and(|(_, connect_port)| connect_port.parse::<u16>().is_ok())
        {
            connect_host
        } else {
            format!("{connect_host}:{port}")
        };
        let trimmed_base = base_path.trim_matches('/');
        let request_path = ensure_absolute_path(path);
        let target_path = if trimmed_base.is_empty() {
            request_path
        } else {
            format!("/{trimmed_base}{request_path}")
        };

        Ok(HttpTarget {
            authority: authority.to_owned(),
            addr,
            path: target_path,
        })
    }

    /// Prefixes `path` with `/` unless it already starts with one.
    #[cfg(feature = "spnego")]
    fn ensure_absolute_path(path: &str) -> String {
        if path.starts_with('/') {
            path.to_owned()
        } else {
            format!("/{path}")
        }
    }

    /// Runs a keytab AS and a TGS exchange per enctype over UDP and TCP against `addr`.
    async fn assert_keytab_as_tgs_for_etypes(
        addr: &str,
        etypes: &[i32],
        mut sequence: u32,
    ) -> Result<(), Box<dyn Error>> {
        let transport = TokioKdcTransport::new().with_timeout(Duration::from_secs(10));
        let keytab = testuser_keytab_for_etypes(etypes)?;

        for etype in etypes {
            for protocol in [KdcProtocol::Udp, KdcProtocol::Tcp] {
                writeln!(
                    io::stderr(),
                    "running Docker KDC keytab etype {etype} AS/TGS exchange over {} to {addr}",
                    protocol_label(protocol)
                )?;
                let options = login_options_with_etypes(protocol, sequence, vec![*etype])?;
                let tgt = transport
                    .login_tgt_with_keytab(
                        protocol,
                        addr,
                        Principal::user(REALM, USER),
                        &keytab,
                        options,
                    )
                    .await?;
                sequence = sequence.saturating_add(1);
                assert_eq!(tgt.session_key.etype, *etype);
                assert!(
                    !tgt.session_key.value.is_empty(),
                    "tgt.session_key.value must not be empty"
                );

                let service = service_principal();
                let request = build_tgs_req(
                    &tgt,
                    service.clone(),
                    tgs_options_with_etypes(protocol, sequence, vec![*etype])?,
                )?;
                sequence = sequence.saturating_add(1);
                let ticket = transport
                    .exchange_tgs_req(protocol, addr, &request, &tgt.session_key)
                    .await?;

                assert_eq!(ticket.client, Principal::user(REALM, USER));
                assert_eq!(ticket.service, service);
                assert_eq!(ticket.session_key.etype, *etype);
                assert!(
                    !ticket.session_key.value.is_empty(),
                    "ticket.session_key.value must not be empty"
                );
                assert!(!ticket.ticket.is_empty(), "ticket.ticket must not be empty");
                assert!(ticket.end_time > ticket.start_time);
            }
        }

        Ok(())
    }

    /// Runs a password AS and a TGS exchange per enctype over UDP and TCP against `addr`.
    async fn assert_password_as_tgs_for_etypes(
        addr: &str,
        etypes: &[i32],
        mut sequence: u32,
    ) -> Result<(), Box<dyn Error>> {
        let transport = TokioKdcTransport::new().with_timeout(Duration::from_secs(10));

        for etype in etypes {
            for protocol in [KdcProtocol::Udp, KdcProtocol::Tcp] {
                writeln!(
                    io::stderr(),
                    "running Docker KDC password etype {etype} AS/TGS exchange over {} to {addr}",
                    protocol_label(protocol)
                )?;
                let options = login_options_with_etypes(protocol, sequence, vec![*etype])?;
                let tgt = transport
                    .login_tgt_with_password(
                        protocol,
                        addr,
                        Principal::user(REALM, USER),
                        PASSWORD,
                        options,
                    )
                    .await?;
                sequence = sequence.saturating_add(1);
                assert_eq!(tgt.session_key.etype, *etype);
                assert!(
                    !tgt.session_key.value.is_empty(),
                    "tgt.session_key.value must not be empty"
                );

                let service = service_principal();
                let request = build_tgs_req(
                    &tgt,
                    service.clone(),
                    tgs_options_with_etypes(protocol, sequence, vec![*etype])?,
                )?;
                sequence = sequence.saturating_add(1);
                let ticket = transport
                    .exchange_tgs_req(protocol, addr, &request, &tgt.session_key)
                    .await?;

                assert_eq!(ticket.client, Principal::user(REALM, USER));
                assert_eq!(ticket.service, service);
                assert_eq!(ticket.session_key.etype, *etype);
                assert!(
                    !ticket.session_key.value.is_empty(),
                    "ticket.session_key.value must not be empty"
                );
                assert!(!ticket.ticket.is_empty(), "ticket.ticket must not be empty");
                assert!(ticket.end_time > ticket.start_time);
            }
        }

        Ok(())
    }

    /// Changes the test user's password from `current_password` to `new_password` once.
    ///
    /// # Cancel safety
    ///
    /// NOT cancel-safe: dropping the future after the kpasswd request is sent
    /// leaves it unknown whether the KDC changed the password.
    async fn change_password_once(
        config: &Config,
        protocol: KdcProtocol,
        current_password: &[u8],
        new_password: &[u8],
    ) -> Result<ChangePasswordResult, Box<dyn Error>> {
        let mut client = Tokio::with_password(
            config.clone(),
            protocol,
            Principal::user(REALM, USER),
            current_password.to_vec(),
        )
        .with_transport(TokioKdcTransport::new().with_timeout(Duration::from_secs(10)));

        let sender = kpasswd_sender_address()?;
        Ok(client
            .change_password(Password::from_vec(new_password.to_vec()), sender)
            .await?)
    }

    /// Logs the test user in with `password` and returns the TGT session.
    async fn password_login(
        config: &Config,
        protocol: KdcProtocol,
        password: &[u8],
    ) -> Result<AsRepSession, Box<dyn Error>> {
        let mut client = Tokio::with_password(
            config.clone(),
            protocol,
            Principal::user(REALM, USER),
            password.to_vec(),
        )
        .with_transport(TokioKdcTransport::new().with_timeout(Duration::from_secs(10)));

        Ok(client.login().await?.clone())
    }

    /// Returns the kpasswd sender address from `TEST_KPASSWD_SADDR`, else 127.0.0.1.
    fn kpasswd_sender_address() -> Result<rasn_kerberos::HostAddress, Box<dyn Error>> {
        let address = match env::var("TEST_KPASSWD_SADDR") {
            Ok(value) => value.parse::<Ipv4Addr>()?,
            Err(env::VarError::NotPresent) => Ipv4Addr::LOCALHOST,
            Err(error) => return Err(error.into()),
        };
        Ok(ipv4_host_address(address.octets()))
    }

    /// Derives the AES256 reply key of the test user from its password.
    fn testuser_reply_key() -> Result<EncryptionKey, Box<dyn Error>> {
        let etype = AesSha1Etype::Aes256;
        Ok(EncryptionKey::new(
            etype.etype_id(),
            etype.string_to_key(PASSWORD, TESTUSER1_SALT, AesSha1Etype::default_s2kparams())?,
        ))
    }

    /// Builds an AES256 keytab of the test user.
    fn testuser_keytab() -> Result<Keytab, Box<dyn Error>> {
        testuser_keytab_for_etypes(&[AES256_ETYPE])
    }

    /// Parses a keytab from its hex dump.
    fn keytab_from_hex(hex: &str) -> Result<Keytab, Box<dyn Error>> {
        Ok(Keytab::parse(&decode_hex(hex)?)?)
    }

    /// Builds a keytab of the test user with one password-derived key per enctype.
    fn testuser_keytab_for_etypes(etypes: &[i32]) -> Result<Keytab, Box<dyn Error>> {
        let mut keytab = Keytab::new();
        for etype in etypes {
            keytab.entries_mut().push(testuser_keytab_entry(*etype)?);
        }
        Ok(keytab)
    }

    /// Builds the password-derived keytab entry of the test user for `etype`.
    fn testuser_keytab_entry(etype: i32) -> Result<KeytabEntry, Box<dyn Error>> {
        Ok(KeytabEntry::new(
            KeytabPrincipal::new(REALM, 1, vec![USER.to_owned()]),
            1_893_553_440,
            u8::try_from(TESTUSER1_KVNO)?,
            derive_password_reply_key(
                &Principal::user(REALM, USER),
                PASSWORD,
                &PreauthKeyInfo::new(etype)
                    .with_salt(Some(String::from_utf8(TESTUSER1_SALT.to_vec())?))
                    .with_s2kparams(testuser_s2kparams(etype)),
            )?,
            TESTUSER1_KVNO,
        ))
    }

    /// Returns the string-to-key parameters the KDC uses for the test user and `etype`.
    fn testuser_s2kparams(etype: i32) -> Option<Vec<u8>> {
        match etype {
            AES128_ETYPE | AES256_ETYPE => Some(vec![0, 0, 16, 0]),
            AES128_SHA2_ETYPE | AES256_SHA2_ETYPE => Some(vec![0, 0, 128, 0]),
            _ => None,
        }
    }

    /// Builds the 8-byte RC4 confounder: tag 1-3 by protocol, then the time of `elapsed`.
    #[cfg(feature = "spnego")]
    fn rc4_confounder(protocol: KdcProtocol, elapsed: Duration) -> [u8; 8] {
        let tag: u8 = match protocol {
            KdcProtocol::Udp => 1,
            KdcProtocol::Tcp => 2,
            KdcProtocol::Auto => 3,

            _ => {
                assert!(
                    matches!(protocol, KdcProtocol::Udp),
                    "unexpected non-exhaustive protocol variant"
                );
                0
            }
        };
        short_confounder(tag, elapsed)
    }

    /// Builds the 8-byte DES3 confounder: tag 3-5 by protocol, then the time of `elapsed`.
    #[cfg(feature = "spnego")]
    fn des3_confounder(protocol: KdcProtocol, elapsed: Duration) -> [u8; 8] {
        let tag: u8 = match protocol {
            KdcProtocol::Udp => 3,
            KdcProtocol::Tcp => 4,
            KdcProtocol::Auto => 5,

            _ => {
                assert!(
                    matches!(protocol, KdcProtocol::Udp),
                    "unexpected non-exhaustive protocol variant"
                );
                0
            }
        };
        short_confounder(tag, elapsed)
    }

    /// Lays out an 8-byte confounder: `tag`, the four nanosecond bytes of
    /// `elapsed`, then bytes 5..8 of its big-endian seconds.
    #[cfg(feature = "spnego")]
    fn short_confounder(tag: u8, elapsed: Duration) -> [u8; 8] {
        let bytes = iter::once(tag)
            .chain(elapsed.subsec_nanos().to_be_bytes())
            .chain(elapsed.as_secs().to_be_bytes().into_iter().skip(5));
        let mut confounder = [0_u8; 8];
        for (slot, byte) in confounder.iter_mut().zip(bytes) {
            *slot = byte;
        }
        confounder
    }

    /// A private `krb5.conf` and credential cache for running the MIT tools.
    struct ExternalKrbEnv {
        /// Temporary `krb5.conf` handed to the tools via `KRB5_CONFIG`.
        config_path: PathBuf,
        /// Temporary credential cache file.
        ccache_path: PathBuf,
        /// `FILE:` name of the credential cache, handed via `KRB5CCNAME`.
        ccache_name: String,
    }

    impl ExternalKrbEnv {
        /// Writes a fresh `krb5.conf` and picks a cache path, both named after `label`.
        fn new(label: &str) -> Result<Self, Box<dyn Error>> {
            let config_path = temp_integration_file(&format!("{label}-krb5.conf"))?;
            let ccache_path = temp_integration_file(&format!("{label}-ccache"))?;
            let ccache_name = format!("FILE:{}", ccache_path.display());
            fs::write(&config_path, external_tool_krb5_conf())?;
            Ok(Self {
                config_path,
                ccache_path,
                ccache_name,
            })
        }

        /// Runs `kinit` for the test user, feeding the password on stdin.
        fn kinit(&self) -> Result<(), Box<dyn Error>> {
            let mut child = self
                .command("kinit")
                .arg(format!("{USER}@{REALM}"))
                .stdin(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?;
            let mut stdin = child.stdin.take().ok_or("kinit stdin is piped")?;
            stdin.write_all(PASSWORD)?;
            stdin.write_all(b"\n")?;
            drop(stdin);
            let output = child.wait_with_output()?;
            if !output.status.success() {
                return Err(format!(
                    "kinit failed with {}: {}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr)
                )
                .into());
            }
            Ok(())
        }

        /// Runs `kvno` for `service`, which stores its ticket in the cache.
        fn kvno(&self, service: &str) -> Result<(), Box<dyn Error>> {
            let output = self.command("kvno").arg(service).output()?;
            if !output.status.success() {
                return Err(format!(
                    "kvno failed with {}: {}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr)
                )
                .into());
            }
            Ok(())
        }

        /// Builds a command for `program` pointed at this configuration and cache.
        fn command(&self, program: &str) -> Command {
            let mut command = Command::new(program);
            let _: &mut Command = command
                .env("KRB5_CONFIG", &self.config_path)
                .env("KRB5CCNAME", &self.ccache_name);
            command
        }
    }

    // Drop audit: removes the two temporary files this value created. Removal
    // is best effort: a missing or undeletable file must not panic in drop.
    impl Drop for ExternalKrbEnv {
        fn drop(&mut self) {
            let _: Option<()> = fs::remove_file(&self.config_path).ok();
            let _: Option<()> = fs::remove_file(&self.ccache_path).ok();
        }
    }

    /// Returns whether any resolved address of `endpoint` accepts a TCP connection within a second.
    ///
    /// A resolution failure is reported on stderr and counts as unreachable.
    pub(super) fn tcp_reachable(endpoint: &str, label: &str) -> Result<bool, Box<dyn Error>> {
        let mut addrs = match endpoint.to_socket_addrs() {
            Ok(addrs) => addrs,
            Err(error) => {
                writeln!(
                    io::stderr(),
                    "failed to resolve {label} {endpoint}: {error}"
                )?;
                return Ok(false);
            }
        };
        let timeout = Duration::from_secs(1);
        Ok(addrs.any(|addr| TcpStream::connect_timeout(&addr, timeout).is_ok()))
    }

    /// Returns whether the Docker HTTP fixture accepts connections; reports a skip on stderr.
    #[cfg(feature = "spnego")]
    pub(super) fn http_service_reachable() -> Result<bool, Box<dyn Error>> {
        let target = match http_target("/modgssapi/index.html") {
            Ok(target) => target.addr,
            Err(error) => {
                writeln!(
                    io::stderr(),
                    "skipping Docker KDC integration test; invalid TEST_HTTP_URL/TEST_HTTP_ADDR: {error}"
                )?;
                return preflight::unavailable("invalid HTTP fixture endpoint");
            }
        };

        if tcp_reachable(&target, "Docker HTTP fixture")? {
            return Ok(true);
        }

        writeln!(
            io::stderr(),
            "skipping Docker KDC integration test; cannot reach Docker HTTP fixture at {target}"
        )?;
        preflight::unavailable("HTTP fixture unreachable")
    }

    /// Renders the `krb5.conf` handed to the MIT tools.
    fn external_tool_krb5_conf() -> String {
        format!(
            "
[libdefaults]
 default_realm = {REALM}
 dns_lookup_realm = false
 dns_lookup_kdc = false
 ticket_lifetime = 24h
 forwardable = yes
 default_tkt_enctypes = aes256-cts-hmac-sha1-96
 default_tgs_enctypes = aes256-cts-hmac-sha1-96
 noaddresses = false

[realms]
 {REALM} = {{
  kdc = {}
  default_domain = test.gokrb5
 }}

[domain_realm]
 .test.gokrb5 = {REALM}
 test.gokrb5 = {REALM}
",
            kdc_addr()
        )
    }

    /// Returns a unique temporary file path for `name`.
    fn temp_integration_file(name: &str) -> Result<PathBuf, Box<dyn Error>> {
        let elapsed = SystemTime::now().duration_since(UNIX_EPOCH)?;
        Ok(env::temp_dir().join(format!(
            "rskrb5-{name}-{}-{}",
            process::id(),
            elapsed.as_nanos()
        )))
    }

    /// Returns an endpoint no KDC listens on, from `TEST_BAD_KDC_ADDR`.
    fn closed_tcp_kdc_addr() -> String {
        env::var("TEST_BAD_KDC_ADDR").unwrap_or_else(|_| "127.0.0.1:9".to_owned())
    }

    /// Builds a configuration with the primary KDC and the resource-realm KDC.
    fn configured_kdc_config() -> Result<Config, Box<dyn Error>> {
        configured_kdc_config_with_primary_realm_kdcs(&[kdc_addr()])
    }

    /// Builds a configuration listing `kdcs` for the test realm plus the resource-realm KDC.
    fn configured_kdc_config_with_primary_realm_kdcs(
        kdcs: &[String],
    ) -> Result<Config, Box<dyn Error>> {
        let primary_kdcs = kdcs.iter().fold(String::new(), |mut lines, kdc| {
            lines.push_str("  kdc = ");
            lines.push_str(kdc);
            lines.push('\n');
            lines
        });

        Ok(Config::parse(&format!(
            "
[libdefaults]
 dns_lookup_kdc = false

[realms]
 {REALM} = {{
{primary_kdcs}
 }}
 {RESDOM_REALM} = {{
  kdc = {}
 }}

[domain_realm]
 .test.gokrb5 = {REALM}
 test.gokrb5 = {REALM}
 .resdom.gokrb5 = {RESDOM_REALM}
 resdom.gokrb5 = {RESDOM_REALM}
",
            resdom_kdc_addr()
        ))?)
    }

    /// Builds a configuration for the short-ticket KDC with a ten-minute renew lifetime.
    fn short_kdc_config() -> Result<Config, Box<dyn Error>> {
        Ok(Config::parse(&format!(
            "
[libdefaults]
 dns_lookup_kdc = false
 renew_lifetime = 600

[realms]
 {REALM} = {{
  kdc = {}
 }}
",
            short_kdc_addr()
        ))?)
    }

    /// Builds a TCP-only configuration with the primary KDC and the kpasswd server.
    fn configured_kpasswd_config() -> Result<Config, Box<dyn Error>> {
        Ok(Config::parse(&format!(
            "
[libdefaults]
 dns_lookup_kdc = false
 udp_preference_limit = 1

[realms]
 {REALM} = {{
  kdc = {}
  kpasswd_server = {}
 }}
",
            kdc_addr(),
            kpasswd_addr()
        ))?)
    }

    /// Builds a configuration that discovers the KDCs through DNS SRV records.
    fn dns_kdc_config() -> Result<Config, Box<dyn Error>> {
        Ok(Config::parse(&format!(
            "
[libdefaults]
 dns_lookup_kdc = true
 default_realm = {REALM}
"
        ))?)
    }

    /// Builds the current-thread Tokio runtime the tests run on.
    fn runtime() -> io::Result<Runtime> {
        Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
    }

    /// Parses the keytab of the `HTTP/host.test.gokrb5` service.
    #[cfg(feature = "spnego")]
    fn http_keytab() -> Result<Keytab, Box<dyn Error>> {
        Ok(Keytab::parse(&decode_hex(HTTP_KEYTAB)?)?)
    }

    /// Decodes a hex fixture.
    fn decode_hex(input: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        assert!(input.len().is_multiple_of(2), "hex input has even length");
        input
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&[high, low]| {
                let byte = hex_value(high)?
                    .saturating_mul(16)
                    .saturating_add(hex_value(low)?);
                Ok(u8::try_from(byte)?)
            })
            .collect()
    }

    /// Returns the value of one hex digit.
    fn hex_value(byte: u8) -> Result<u32, Box<dyn Error>> {
        Ok(char::from(byte)
            .to_digit(16)
            .ok_or_else(|| format!("invalid hex byte: {byte}"))?)
    }

    /// Encodes `bytes` as standard base64.
    #[cfg(feature = "spnego")]
    fn base64_encode(bytes: &[u8]) -> String {
        use base64::{Engine as _, engine::general_purpose::STANDARD};

        STANDARD.encode(bytes)
    }

    /// Pins that the preflight probe accepts an open local listener.
    #[test]
    fn tcp_reachable_accepts_open_local_listener() -> Result<(), Box<dyn Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        assert!(tcp_reachable(&addr.to_string(), "open listener")?);
        drop(listener);
        Ok(())
    }

    /// Pins that the preflight probe rejects an endpoint that does not resolve.
    #[test]
    fn tcp_reachable_rejects_invalid_endpoint() -> Result<(), Box<dyn Error>> {
        assert!(!tcp_reachable(":::not-valid", "invalid")?);
        Ok(())
    }

    /// Pins that the preflight probe rejects the closed discard port.
    #[test]
    fn tcp_reachable_rejects_closed_port_by_default() -> Result<(), Box<dyn Error>> {
        assert!(!tcp_reachable("127.0.0.1:9", "closed port")?);
        Ok(())
    }
}

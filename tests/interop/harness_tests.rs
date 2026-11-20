//! Harness regressions.
//!
//! A test that needs a changed environment re-runs itself in a child test
//! process (`support/env.rs`); the parent asserts the child's outcome and output.

use core::{error::Error, time::Duration};
use std::{ffi::OsStr, io, time::SystemTime};

use rskrb5_ng::{
    client::{
        build_preauthenticated_tgt_as_req, build_tgt_as_req, options::AsReq, principal::Principal,
        transport::KdcProtocol,
    },
    keytab::EncryptionKey,
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream, UdpSocket},
    runtime::Builder,
    time::timeout,
};

use super::{
    Fixture, assert_negotiated_enctype, assert_negotiated_mechanism, assert_negotiated_padata,
    assert_ticket_flag, kdc_tap::KdcTap, require,
};
use crate::{child_env, closed_port::reserve_closed_tcp_port};

/// Env-file key of the fixture endpoint the child processes check.
const ENDPOINT_KEY: &str = "INTEROP_HARNESS_TEST_KDC";

/// The fixture the child processes require.
const FIXTURE: Fixture = Fixture::new("mit-kdc", ENDPOINT_KEY);

/// Runs `test_path` in a child with `INTEROP`, the two required switches and
/// the fixture endpoint set exactly as given (`None` removes a variable).
fn child(
    test_path: &str,
    interop: Option<&str>,
    required: (Option<&str>, Option<&str>),
    endpoint: Option<&str>,
) -> Result<(), String> {
    child_env::try_run_in_child(
        test_path,
        &[
            ("INTEROP", interop.map(OsStr::new)),
            ("INTEROP_REQUIRED", required.0.map(OsStr::new)),
            ("INTEGRATION_REQUIRED", required.1.map(OsStr::new)),
            (ENDPOINT_KEY, endpoint.map(OsStr::new)),
            // A namespaced run exports its own prefix; these tests name the default container.
            ("INTEROP_CONTAINER_PREFIX", None),
        ],
    )
}

/// A closed loopback endpoint from the reserved range.
fn closed_endpoint() -> io::Result<String> {
    Ok(format!("127.0.0.1:{}", reserve_closed_tcp_port()?))
}

/// In a child: the scenario's `require` result is the test result.
fn require_in_child() -> Result<(), Box<dyn Error>> {
    if require("harness-selftest", &[FIXTURE])? {
        return Err("the child ran a scenario against an unreachable fixture".into());
    }
    Ok(())
}

/// With `INTEROP_REQUIRED=1` an unreachable fixture fails the scenario, naming
/// the fixture, the endpoint and the container.
#[test]
fn required_unreachable_fixture_fails_naming_it() -> Result<(), Box<dyn Error>> {
    const PATH: &str = "harness::tests::required_unreachable_fixture_fails_naming_it";
    if child_env::in_child(PATH) {
        return require_in_child();
    }
    let endpoint = closed_endpoint()?;
    let report = child(PATH, Some("1"), (Some("1"), None), Some(&endpoint))
        .err()
        .ok_or("required mode passed with an unreachable fixture")?;
    let named = format!(
        "required interop fixture unreachable: mit-kdc at {endpoint} (container rskrb5-interop-mit-kdc)"
    );
    assert!(
        report.contains(&named),
        "the failure does not name the fixture: {report}"
    );
    assert!(
        report.contains("1 failed"),
        "the child did not fail one test: {report}"
    );
    Ok(())
}

/// A run namespace (`INTEROP_CONTAINER_PREFIX` in the env file) puts its own
/// container name into the failure, so the report points at the right container.
#[test]
fn required_failure_names_the_namespaced_container() -> Result<(), Box<dyn Error>> {
    const PATH: &str = "harness::tests::required_failure_names_the_namespaced_container";
    if child_env::in_child(PATH) {
        return require_in_child();
    }
    let endpoint = closed_endpoint()?;
    let report = child_env::try_run_in_child(
        PATH,
        &[
            ("INTEROP", Some(OsStr::new("1"))),
            ("INTEROP_REQUIRED", Some(OsStr::new("1"))),
            ("INTEGRATION_REQUIRED", None),
            (
                "INTEROP_CONTAINER_PREFIX",
                Some(OsStr::new("rskrb5-interop--t34")),
            ),
            (ENDPOINT_KEY, Some(OsStr::new(&endpoint))),
        ],
    )
    .err()
    .ok_or("required mode passed with an unreachable fixture")?;
    assert!(
        report.contains("(container rskrb5-interop--t34-mit-kdc)"),
        "the failure does not name the namespaced container: {report}"
    );
    Ok(())
}

/// Plan 1's `INTEGRATION_REQUIRED=1` makes the interop suite required too.
#[test]
fn integration_required_implies_interop_required() -> Result<(), Box<dyn Error>> {
    const PATH: &str = "harness::tests::integration_required_implies_interop_required";
    if child_env::in_child(PATH) {
        return require_in_child();
    }
    let endpoint = closed_endpoint()?;
    let report = child(PATH, Some("1"), (None, Some("1")), Some(&endpoint))
        .err()
        .ok_or("INTEGRATION_REQUIRED=1 let an unreachable fixture pass")?;
    assert!(
        report.contains("required interop fixture unreachable: mit-kdc"),
        "the failure does not name the fixture: {report}"
    );
    Ok(())
}

/// In required mode an unset endpoint key fails, naming the key.
#[test]
fn required_unset_endpoint_key_fails_naming_it() -> Result<(), Box<dyn Error>> {
    const PATH: &str = "harness::tests::required_unset_endpoint_key_fails_naming_it";
    if child_env::in_child(PATH) {
        return require_in_child();
    }
    let report = child(PATH, Some("1"), (Some("1"), None), None)
        .err()
        .ok_or("required mode passed without the fixture endpoint")?;
    assert!(
        report.contains("required interop fixture unreachable: mit-kdc")
            && report.contains(ENDPOINT_KEY),
        "the failure does not name the fixture and its key: {report}"
    );
    Ok(())
}

/// Without required mode an unreachable fixture is a visible skip.
#[test]
fn optional_unreachable_fixture_skips_visibly() -> Result<(), Box<dyn Error>> {
    const PATH: &str = "harness::tests::optional_unreachable_fixture_skips_visibly";
    if child_env::in_child(PATH) {
        return require_in_child();
    }
    let endpoint = closed_endpoint()?;
    child_env::run_in_child(
        PATH,
        &[
            ("INTEROP", Some(OsStr::new("1"))),
            ("INTEROP_REQUIRED", None),
            ("INTEGRATION_REQUIRED", None),
            (ENDPOINT_KEY, Some(OsStr::new(&endpoint))),
        ],
    );
    Ok(())
}

/// Without `INTEROP=1` nothing runs and nothing fails, even in required mode.
#[test]
fn disabled_suite_skips() -> Result<(), Box<dyn Error>> {
    const PATH: &str = "harness::tests::disabled_suite_skips";
    if child_env::in_child(PATH) {
        return require_in_child();
    }
    child(PATH, None, (Some("1"), Some("1")), None).map_err(Into::into)
}

/// A different enctype than the required one is an error.
#[test]
fn enctype_fallback_is_not_negotiated() {
    assert!(
        assert_negotiated_enctype("TGT session key", 20, 18).is_err(),
        "an AES-SHA1 fallback passed for AES-SHA2"
    );
    assert!(
        assert_negotiated_enctype("TGT session key", 20, 20).is_ok(),
        "the required enctype was refused"
    );
}

/// A different GSS mechanism than the required one is an error.
#[test]
fn mechanism_fallback_is_not_negotiated() {
    let krb5 = [1, 2, 840, 113_554, 1, 2, 2];
    let ms_legacy = [1, 2, 840, 48_018, 1, 2, 2];
    assert!(
        assert_negotiated_mechanism(&krb5, &ms_legacy).is_err(),
        "the Microsoft legacy OID passed for krb5"
    );
    assert!(
        assert_negotiated_mechanism(&krb5, &krb5).is_ok(),
        "the required mechanism was refused"
    );
}

/// A missing pre-authentication type is an error.
#[test]
fn padata_fallback_is_not_negotiated() {
    assert!(
        assert_negotiated_padata("KDC_ERR_PREAUTH_REQUIRED", 2, &[19_i32, 136_i32]).is_err(),
        "a reply without PA-ENC-TIMESTAMP passed"
    );
    assert!(
        assert_negotiated_padata("KDC_ERR_PREAUTH_REQUIRED", 2, &[19_i32, 2_i32]).is_ok(),
        "an offered PA-ENC-TIMESTAMP was refused"
    );
}

/// A clear ticket flag is an error; bit numbers follow RFC 4120 (bit 0 first).
#[test]
fn clear_ticket_flag_is_not_negotiated() {
    let pre_authent = [0x00, 0x20, 0x00, 0x00];
    assert!(
        assert_ticket_flag("pre-authent", 10, [0x40, 0x00, 0x00, 0x00]).is_err(),
        "a ticket without PRE-AUTHENT passed"
    );
    assert!(
        assert_ticket_flag("pre-authent", 10, pre_authent).is_ok(),
        "a PRE-AUTHENT ticket was refused"
    );
    assert!(
        assert_ticket_flag("renewable", 8, pre_authent).is_err(),
        "a ticket without RENEWABLE passed"
    );
}

/// PA-DATA type of PA-ENC-TIMESTAMP (RFC 4120).
const PA_ENC_TIMESTAMP: i32 = 2;

/// The DER of two AS-REQs: one without PA-DATA and one with a PA-ENC-TIMESTAMP entry.
fn as_reqs() -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let client = Principal::user("TEST.RSKRB5", "preauthuser");
    let options = || {
        AsReq::new(SystemTime::now(), 7)
            .with_ticket_lifetime(Duration::from_hours(1))
            .with_etypes(vec![18_i32])
    };
    let key = EncryptionKey::new(18, vec![0x55_u8; 32]);
    let probe = build_tgt_as_req(client.clone(), options()).map_err(|error| error.to_string())?;
    let answered = build_preauthenticated_tgt_as_req(client, options(), &key, None)
        .map_err(|error| error.to_string())?;
    Ok((probe.der().to_vec(), answered.der().to_vec()))
}

/// The relay forwards a client's requests over TCP unchanged and records the PA-DATA types of
/// every AS-REQ in order, so a scenario can assert the mechanism the exchange carried.
#[test]
fn the_tap_records_the_padata_of_each_as_req_over_tcp() -> Result<(), Box<dyn Error>> {
    Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?
        .block_on(async {
            // Given a KDC that answers every framed request with a framed marker.
            let kdc = TcpListener::bind("127.0.0.1:0").await?;
            let upstream = kdc.local_addr()?.to_string();
            let server = tokio::spawn(async move {
                let (mut stream, _peer) = kdc.accept().await?;
                for _ in 0_u8..2_u8 {
                    let mut header = [0_u8; 4];
                    let _header = stream.read_exact(&mut header).await?;
                    let mut request = vec![0_u8; usize::try_from(u32::from_be_bytes(header))?];
                    let _body = stream.read_exact(&mut request).await?;
                    stream.write_all(&[0, 0, 0, 3, b'o', b'k', b'!']).await?;
                }
                Ok::<_, Box<dyn Error + Send + Sync>>(())
            });
            let tap = KdcTap::start(KdcProtocol::Tcp, &upstream).await?;
            let (probe, answered) = as_reqs()?;
            // When a client sends the probe and then the pre-authenticated request.
            let mut client = TcpStream::connect(tap.endpoint()).await?;
            for request in [&probe, &answered] {
                client
                    .write_all(&u32::try_from(request.len())?.to_be_bytes())
                    .await?;
                client.write_all(request).await?;
                let mut reply = [0_u8; 7];
                let _answer = client.read_exact(&mut reply).await?;
                assert_eq!(
                    &reply,
                    &[0, 0, 0, 3, b'o', b'k', b'!'],
                    "the reply was altered"
                );
            }
            server.await?.map_err(|error| error.to_string())?;
            // Then the relay saw an AS-REQ without PA-DATA, then one with PA-ENC-TIMESTAMP.
            let seen = tap.as_req_padata()?;
            assert_eq!(seen, vec![Vec::<i32>::new(), vec![PA_ENC_TIMESTAMP]]);
            let [probe_types, answered_types] = seen.as_slice() else {
                return Err("the relay did not record two AS-REQs".into());
            };
            assert_negotiated_padata("the answered AS-REQ", PA_ENC_TIMESTAMP, answered_types)?;
            assert!(
                assert_negotiated_padata("the probe", PA_ENC_TIMESTAMP, probe_types).is_err(),
                "a request without PA-DATA passed for PA-ENC-TIMESTAMP"
            );
            Ok(())
        })
}

/// The same over UDP: one datagram out, the KDC's answer back, the PA-DATA types recorded.
#[test]
fn the_tap_records_the_padata_of_each_as_req_over_udp() -> Result<(), Box<dyn Error>> {
    Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?
        .block_on(async {
            // Given a KDC that answers a datagram with a marker.
            let kdc = UdpSocket::bind("127.0.0.1:0").await?;
            let upstream = kdc.local_addr()?.to_string();
            let server = tokio::spawn(async move {
                let mut buffer = vec![0_u8; 0x1_0000];
                let (_length, peer) = kdc.recv_from(&mut buffer).await?;
                let _sent = kdc.send_to(b"ok!", peer).await?;
                Ok::<_, io::Error>(())
            });
            let tap = KdcTap::start(KdcProtocol::Udp, &upstream).await?;
            let (_probe, answered) = as_reqs()?;
            // When a client sends the pre-authenticated request.
            let client = UdpSocket::bind("127.0.0.1:0").await?;
            let _sent = client.send_to(&answered, tap.endpoint()).await?;
            let mut reply = [0_u8; 3];
            let (received, _peer) = timeout(Duration::from_secs(5), client.recv_from(&mut reply))
                .await
                .map_err(|_elapsed| "no answer through the relay")??;
            assert_eq!(received, 3);
            assert_eq!(&reply, b"ok!");
            server.await??;
            // Then the relay recorded PA-ENC-TIMESTAMP.
            assert_eq!(tap.as_req_padata()?, vec![vec![PA_ENC_TIMESTAMP]]);
            Ok(())
        })
}

/// A relay that cannot reach its KDC reports the failure instead of an empty record.
#[test]
fn a_relay_failure_is_reported_not_read_as_no_preauth() -> Result<(), Box<dyn Error>> {
    Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?
        .block_on(async {
            // Given a relay whose upstream refuses the connection.
            let closed = reserve_closed_tcp_port()?;
            let tap = KdcTap::start(KdcProtocol::Tcp, &format!("127.0.0.1:{closed}")).await?;
            let (_probe, answered) = as_reqs()?;
            // When a client sends a request.
            let mut client = TcpStream::connect(tap.endpoint()).await?;
            client
                .write_all(&u32::try_from(answered.len())?.to_be_bytes())
                .await?;
            client.write_all(&answered).await?;
            let mut reply = [0_u8; 1];
            let read = timeout(Duration::from_secs(5), client.read(&mut reply))
                .await
                .map_err(|_elapsed| "the relay neither answered nor closed")?;
            // Then the client sees the connection end, and the record says why.
            assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");
            assert!(
                tap.as_req_padata().is_err(),
                "a relay that could not reach its KDC reported an empty record"
            );
            Ok(())
        })
}

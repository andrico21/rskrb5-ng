//! The acceptor's redacted trace events (WP-18, GO-service-1).

use rskrb5_ng::{
    error::Service as ServiceError,
    trace::{Guard, Options, capture::Memory},
};

use super::{
    TestError, VALID_AP_REQ, VALID_SESSION_KEY, Validator, decode_hex, hex_encode, http_keytab,
    timestamp,
};

/// The service key of the fixture keytab (AES256, kvno 1).
const SERVICE_KEY: &str = "9cad00bbc72d703258e911dc18e6d5487cf737bf67fd111f0c2463ad6033bf51";

/// An accepted AP-REQ and a replayed one are traced, and no key reaches the sink.
#[test]
fn accept_and_reject_are_traced_without_secrets() -> Result<(), TestError> {
    let sink = Memory::new();
    let guard = Guard::new(sink.clone(), Options::new().with_identities(true));
    let keytab = http_keytab()?;
    let bytes = decode_hex(VALID_AP_REQ)?;
    let mut validator = Validator::new(&keytab)
        .with_now(timestamp(1_893_553_447)?)
        .with_trace(guard);
    drop(validator.validate_ap_req(&bytes)?);
    let replay = validator.validate_ap_req(&bytes).err();
    assert!(matches!(replay, Some(ServiceError::Replay)), "{replay:?}");
    let lines = sink.lines();
    assert_eq!(lines.len(), 2, "{lines:?}");
    let [accepted, rejected] = lines.as_slice() else {
        return Err("two events".into());
    };
    assert!(accepted.starts_with("ap-req-accepted "), "{accepted}");
    assert!(
        accepted.contains("service=HTTP/host.test.gokrb5@TEST.GOKRB5"),
        "{accepted}"
    );
    assert!(rejected.starts_with("ap-req-rejected "), "{rejected}");
    let text = lines.join("\n");
    for secret in [SERVICE_KEY, VALID_SESSION_KEY, &hex_encode(&bytes)] {
        assert!(!text.contains(secret), "{secret} reached the sink");
    }
    Ok(())
}

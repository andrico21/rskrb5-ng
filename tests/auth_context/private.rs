//! KRB-PRIV and KRB-SAFE through the context.

use rskrb5_ng::{
    error::{AuthMessage as Error, KrbPriv, KrbSafe},
    krb_priv::ipv4_host_address,
    messages::{AuthContext, MessagePolicy},
};

use super::support::{acceptor, acceptor_subkey, at, initiator, initiator_subkey, session_key};
use crate::context::{Context as _, TestError};

/// The time of every message of these tests.
const NOW: u64 = 1_893_553_447;

/// Pins that a KRB-PRIV round-trips and carries the sender's timestamp.
#[test]
fn priv_round_trips_and_reports_the_time() -> Result<(), TestError> {
    let mut sender = initiator(MessagePolicy::new(), NOW)?;
    let mut receiver = acceptor(MessagePolicy::new(), NOW)?;

    let wire = sender.mk_priv(b"secret user data")?;
    let delivered = receiver.rd_priv(&wire)?;

    assert_eq!(delivered.content().as_slice(), b"secret user data");
    assert_eq!(delivered.timestamp(), Some(at(NOW)?));
    assert_eq!(delivered.sequence(), None);
    assert!(
        !format!("{delivered:?}").contains("secret"),
        "the payload is not printed"
    );
    Ok(())
}

/// Pins that sub-keys are used per direction: each end sends under its own and reads under the peer's.
#[test]
fn priv_uses_the_subkey_of_each_direction() -> Result<(), TestError> {
    let mut sender = AuthContext::new(session_key(), MessagePolicy::new())
        .with_subkeys(Some(initiator_subkey()), Some(acceptor_subkey()))
        .with_local_address(ipv4_host_address([10, 0, 0, 1]))
        .with_now(at(NOW)?);
    let mut receiver = AuthContext::new(session_key(), MessagePolicy::new())
        .with_subkeys(Some(acceptor_subkey()), Some(initiator_subkey()))
        .with_local_address(ipv4_host_address([10, 0, 0, 2]))
        .with_now(at(NOW)?);
    let mut stranger = acceptor(MessagePolicy::new(), NOW)?;

    let wire = sender.mk_priv(b"data")?;

    assert_eq!(receiver.rd_priv(&wire)?.content().as_slice(), b"data");
    let refused = stranger.rd_priv(&wire);
    assert!(
        matches!(refused, Err(Error::Priv(KrbPriv::Crypto(_)))),
        "{refused:?}"
    );
    Ok(())
}

/// Pins that a KRB-PRIV and a KRB-SAFE are not interchangeable.
#[test]
fn priv_and_safe_do_not_cross() -> Result<(), TestError> {
    let mut sender = initiator(MessagePolicy::new(), NOW)?;
    let mut receiver = acceptor(MessagePolicy::new(), NOW)?;
    let private = sender.mk_priv(b"x")?;
    let safe = sender.mk_safe(b"x")?;

    assert!(matches!(receiver.rd_safe(&private), Err(Error::Safe(_))));
    assert!(matches!(receiver.rd_priv(&safe), Err(Error::Priv(_))));
    Ok(())
}

/// Pins that a KRB-SAFE round-trips, and that any change of its bytes is refused.
#[test]
fn safe_round_trips_and_detects_tampering() -> Result<(), TestError> {
    let mut sender = initiator(MessagePolicy::new(), NOW)?;
    let mut receiver = acceptor(MessagePolicy::new(), NOW)?;
    let wire = sender.mk_safe(b"integrity protected")?;

    let delivered = receiver.rd_safe(&wire)?;
    assert_eq!(delivered.content().as_slice(), b"integrity protected");

    let mut fresh = acceptor(MessagePolicy::new(), NOW)?;
    let mut tampered = wire.clone();
    let position = tampered
        .windows(b"integrity".len())
        .position(|window| window == b"integrity")
        .context("the user data is visible in a KRB-SAFE")?;
    *tampered.get_mut(position).context("byte")? ^= 0x01;
    let refused = fresh.rd_safe(&tampered);
    assert!(
        matches!(refused, Err(Error::Safe(KrbSafe::ChecksumMismatch))),
        "{refused:?}"
    );
    Ok(())
}

/// Pins that the sender must have a local address, as MIT's `KRB5_LOCAL_ADDR_REQUIRED`, and a key.
#[test]
fn a_local_address_and_a_key_are_required() -> Result<(), TestError> {
    let mut nameless = AuthContext::new(session_key(), MessagePolicy::new()).with_now(at(NOW)?);
    assert!(matches!(
        nameless.mk_priv(b"x"),
        Err(Error::LocalAddressRequired)
    ));
    assert!(matches!(
        nameless.mk_safe(b"x"),
        Err(Error::LocalAddressRequired)
    ));

    let mut keyless = AuthContext::without_key(MessagePolicy::new())
        .with_local_address(ipv4_host_address([10, 0, 0, 1]))
        .with_now(at(NOW)?);
    assert!(matches!(keyless.mk_priv(b"x"), Err(Error::NoKey)));
    assert!(matches!(keyless.mk_safe(b"x"), Err(Error::NoKey)));
    Ok(())
}

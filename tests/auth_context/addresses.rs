//! Sender and recipient address checks (MIT `k5_privsafe_check_addrs`).

use rskrb5_ng::{
    error::AuthMessage as Error,
    krb_priv::ipv4_host_address,
    messages::{AuthContext, MessagePolicy},
};

use super::support::{ACCEPTOR, INITIATOR, acceptor, at, initiator, session_key};
use crate::context::TestError;

/// The time of every message.
const NOW: u64 = 1_893_553_447;

/// Pins that a message from an address other than the configured peer is refused.
#[test]
fn a_foreign_sender_is_refused() -> Result<(), TestError> {
    let mut sender = initiator(MessagePolicy::new(), NOW)?;
    let wire = sender.mk_priv(b"x")?;
    let mut receiver = AuthContext::new(session_key(), MessagePolicy::new())
        .with_local_address(ipv4_host_address(ACCEPTOR))
        .with_remote_address(ipv4_host_address([192, 0, 2, 9]))
        .with_now(at(NOW)?);

    assert!(matches!(
        receiver.rd_priv(&wire),
        Err(Error::BadAddress { which: "sender" })
    ));
    assert!(matches!(
        receiver.rd_safe(&sender.mk_safe(b"x")?),
        Err(Error::BadAddress { which: "sender" })
    ));
    Ok(())
}

/// Pins that a message addressed to another recipient is refused, and one without a recipient is accepted.
#[test]
fn the_recipient_address_is_checked_when_present() -> Result<(), TestError> {
    let mut sender = initiator(MessagePolicy::new(), NOW)?;
    let wire = sender.mk_priv(b"x")?;
    let mut wrong = AuthContext::new(session_key(), MessagePolicy::new())
        .with_local_address(ipv4_host_address([10, 9, 9, 9]))
        .with_remote_address(ipv4_host_address(INITIATOR))
        .with_now(at(NOW)?);
    assert!(matches!(
        wrong.rd_priv(&wire),
        Err(Error::BadAddress { which: "recipient" })
    ));

    let mut anonymous = AuthContext::new(session_key(), MessagePolicy::new())
        .with_local_address(ipv4_host_address(INITIATOR))
        .with_now(at(NOW)?);
    let unaddressed = anonymous.mk_priv(b"no recipient")?;
    let mut receiver = acceptor(MessagePolicy::new(), NOW)?;
    assert_eq!(
        receiver.rd_priv(&unaddressed)?.content().as_slice(),
        b"no recipient"
    );
    Ok(())
}

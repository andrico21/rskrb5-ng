//! Clock-skew and replay checks.

use core::time::Duration;

use rskrb5_ng::{error::AuthContext as Error, messages::MessagePolicy};

use super::support::{acceptor, initiator};
use crate::context::TestError;

/// The time the sender stamps.
const NOW: u64 = 1_893_553_447;

/// Pins that a message exactly one skew old is accepted and one second older is refused.
#[test]
fn the_skew_boundary_is_inclusive() -> Result<(), TestError> {
    let policy = MessagePolicy::new().with_clock_skew(Duration::from_mins(5));
    let mut sender = initiator(policy.clone(), NOW)?;
    let wire = sender.mk_priv(b"x")?;

    let mut on_time = acceptor(policy.clone(), NOW + 300)?;
    assert_eq!(on_time.rd_priv(&wire)?.content.as_slice(), b"x");

    let mut late = acceptor(policy.clone(), NOW + 301)?;
    assert!(
        matches!(late.rd_priv(&wire), Err(Error::ClockSkew { max_clock_skew }) if max_clock_skew == Duration::from_mins(5))
    );
    let mut early = acceptor(policy, NOW - 301)?;
    assert!(matches!(
        early.rd_priv(&wire),
        Err(Error::ClockSkew { max_clock_skew: _ })
    ));
    Ok(())
}

/// Pins that the same message is refused the second time, for PRIV and SAFE alike.
#[test]
fn a_repeated_message_is_a_replay() -> Result<(), TestError> {
    let mut sender = initiator(MessagePolicy::new(), NOW)?;
    let mut receiver = acceptor(MessagePolicy::new(), NOW)?;
    let private = sender.mk_priv(b"once")?;
    let safe = sender.mk_safe(b"once")?;

    drop(receiver.rd_priv(&private)?);
    drop(receiver.rd_safe(&safe)?);

    assert!(matches!(receiver.rd_priv(&private), Err(Error::Replay)));
    assert!(matches!(receiver.rd_safe(&safe), Err(Error::Replay)));
    Ok(())
}

/// Pins that a message the context itself made is a replay when reflected back to it.
#[test]
fn a_reflected_message_is_refused() -> Result<(), TestError> {
    let mut sender = initiator(MessagePolicy::new(), NOW)?;
    let wire = sender.mk_priv(b"mine")?;

    assert!(matches!(
        sender.rd_priv(&wire),
        Err(Error::Replay | Error::BadAddress { which: _ })
    ));
    Ok(())
}

/// Pins that with time checking off a message with no timestamp is accepted, and with it on it is refused.
#[test]
fn time_checking_can_be_turned_off_deliberately() -> Result<(), TestError> {
    let off = MessagePolicy::new().checking_time(false);
    let mut sender = initiator(off.clone(), NOW)?;
    let wire = sender.mk_priv(b"untimed")?;

    let mut lax = acceptor(off, NOW)?;
    let received = lax.rd_priv(&wire)?;
    assert_eq!(received.timestamp, None);
    drop(lax.rd_priv(&wire)?);

    let mut strict = acceptor(MessagePolicy::new(), NOW)?;
    assert!(matches!(
        strict.rd_priv(&wire),
        Err(Error::MissingTimestamp)
    ));
    Ok(())
}

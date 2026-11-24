//! Sequence numbers, including MIT's tolerance for Heimdal's unsigned encodings.

use rskrb5_ng::{error::AuthMessage as Error, messages::MessagePolicy};

use super::support::{acceptor, initiator};
use crate::context::TestError;

/// The time of every message.
const NOW: u64 = 1_893_553_447;

/// The policy: sequence numbers on, time checking off so that only the numbers decide.
fn sequenced() -> MessagePolicy {
    MessagePolicy::new()
        .checking_time(false)
        .checking_sequence(true)
}

/// Pins that messages in order are accepted with their numbers and the counters advance.
#[test]
fn messages_in_order_are_accepted() -> Result<(), TestError> {
    let mut sender = initiator(sequenced(), NOW)?.with_sequence(7, 0);
    let mut receiver = acceptor(sequenced(), NOW)?.with_sequence(0, 7);

    for (expected, private) in [(7_u32, true), (8, false), (9, true)] {
        let wire = if private {
            sender.mk_priv(b"p")?
        } else {
            sender.mk_safe(b"s")?
        };
        let delivered = if private {
            receiver.rd_priv(&wire)?
        } else {
            receiver.rd_safe(&wire)?
        };
        assert_eq!(delivered.sequence(), Some(expected));
    }
    assert_eq!(sender.local_sequence(), 10);
    assert_eq!(receiver.remote_sequence(), 10);
    Ok(())
}

/// Pins that a repeated, skipped or out-of-order number is refused with both numbers named.
#[test]
fn a_wrong_number_is_refused() -> Result<(), TestError> {
    let mut sender = initiator(sequenced(), NOW)?.with_sequence(0, 0);
    let mut receiver = acceptor(sequenced(), NOW)?.with_sequence(0, 0);
    let first = sender.mk_priv(b"0")?;
    let second = sender.mk_priv(b"1")?;
    let third = sender.mk_priv(b"2")?;

    assert!(matches!(
        receiver.rd_priv(&second),
        Err(Error::BadSequence {
            expected: 0,
            received: 1
        })
    ));
    drop(receiver.rd_priv(&first)?);
    assert!(matches!(
        receiver.rd_priv(&first),
        Err(Error::BadSequence {
            expected: 1,
            received: 0
        })
    ));
    assert!(matches!(
        receiver.rd_priv(&third),
        Err(Error::BadSequence {
            expected: 1,
            received: 2
        })
    ));
    drop(receiver.rd_priv(&second)?);
    Ok(())
}

/// Pins that with sequence checking on a message without a number is refused.
#[test]
fn a_missing_number_is_refused() -> Result<(), TestError> {
    let mut sender = initiator(MessagePolicy::new().checking_time(false), NOW)?;
    let wire = sender.mk_priv(b"unnumbered")?;
    let mut receiver = acceptor(sequenced(), NOW)?;

    assert!(matches!(
        receiver.rd_priv(&wire),
        Err(Error::MissingSequence)
    ));
    Ok(())
}

/// Pins MIT's Heimdal tolerance (`privsafe.c:225-304`): a counter of 0x80 sent as 0xFFFFFF80 is accepted once.
#[test]
fn heimdal_unsigned_encodings_are_accepted_like_mit() -> Result<(), TestError> {
    let mut sender = initiator(sequenced(), NOW)?.with_sequence(0xFFFF_FF80, 0);
    let mut receiver = acceptor(sequenced(), NOW)?.with_sequence(0, 0x80);

    let wire = sender.mk_priv(b"heimdal")?;

    assert_eq!(receiver.rd_priv(&wire)?.sequence(), Some(0xFFFF_FF80));
    assert_eq!(receiver.remote_sequence(), 0x81);
    Ok(())
}

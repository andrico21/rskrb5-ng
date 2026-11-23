//! KRB-PRIV and KRB-SAFE through an [`AuthContext`] (MIT `mk_priv.c`, `rd_priv.c`,
//! `mk_safe.c`, `rd_safe.c` and `privsafe.c`).

use core::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use rasn::types::Integer;
use rasn_kerberos::{HostAddress, KerberosTime};
use zeroize::Zeroizing;

use super::{AuthContext, Received, sequence};
use crate::{
    crypto::Use,
    error::AuthContext as Error,
    keytab::EncryptionKey,
    krb_priv::{self, EncKrbPrivPartOptions},
    krb_safe,
    replay::Tag,
};

/// A Kerberos time and microseconds for `at`.
///
/// # Errors
///
/// Returns [`Error::TimeOutOfRange`] before the epoch or past the range of a
/// Kerberos time.
pub(super) fn kerberos_time(at: SystemTime) -> Result<(KerberosTime, Integer), Error> {
    let since = at
        .duration_since(UNIX_EPOCH)
        .map_err(|_before_epoch| Error::TimeOutOfRange)?;
    let seconds = i64::try_from(since.as_secs()).map_err(|_range| Error::TimeOutOfRange)?;
    let time = chrono::DateTime::from_timestamp(seconds, 0).ok_or(Error::TimeOutOfRange)?;
    Ok((
        KerberosTime(time.fixed_offset()),
        Integer::from(since.subsec_micros()),
    ))
}

/// The `SystemTime` of a received Kerberos time and microseconds.
///
/// # Errors
///
/// Returns [`Error::TimeOutOfRange`] for a time or microseconds Kerberos cannot carry.
pub(super) fn system_time(
    time: &KerberosTime,
    usec: Option<&Integer>,
) -> Result<SystemTime, Error> {
    let micros = match usec {
        None => 0,
        Some(value) => u32::try_from(value)
            .ok()
            .filter(|micros| *micros <= 999_999)
            .ok_or(Error::TimeOutOfRange)?,
    };
    let whole = UNIX_EPOCH
        .checked_add(Duration::from_secs(
            u64::try_from(time.0.timestamp()).map_err(|_negative| Error::TimeOutOfRange)?,
        ))
        .ok_or(Error::TimeOutOfRange)?;
    whole
        .checked_add(Duration::from_micros(u64::from(micros)))
        .ok_or(Error::TimeOutOfRange)
}

/// The key this end sends under: the send sub-key, else the session key.
///
/// # Errors
///
/// Returns [`Error::NoKey`] or [`Error::Policy`].
pub(super) fn sending_key(context: &AuthContext) -> Result<&EncryptionKey, Error> {
    let key = context
        .send_subkey
        .as_ref()
        .or(context.session_key.as_ref())
        .ok_or(Error::NoKey)?;
    context
        .policy
        .crypto
        .check_use(key.etype(), Use::CheckedLowLevel)?;
    Ok(key)
}

/// The keys this end may read under, in MIT's order: the receive sub-key, then the session key.
pub(super) fn receiving_keys(context: &AuthContext) -> impl Iterator<Item = &EncryptionKey> {
    context.recv_subkey.iter().chain(context.session_key.iter())
}

/// The key this end reads KRB-PRIV and KRB-SAFE under: the receive sub-key, else the session key.
///
/// # Errors
///
/// Returns [`Error::NoKey`] or [`Error::Policy`].
fn reading_key(context: &AuthContext) -> Result<&EncryptionKey, Error> {
    let key = context
        .recv_subkey
        .as_ref()
        .or(context.session_key.as_ref())
        .ok_or(Error::NoKey)?;
    context
        .policy
        .crypto
        .check_use(key.etype(), Use::CheckedLowLevel)?;
    Ok(key)
}

/// The timestamp with microseconds and the number a message carries.
type Outgoing = (Option<(KerberosTime, Integer)>, Option<u32>);

/// The timestamp and number a message made now carries, per the policy.
///
/// # Errors
///
/// Returns [`Error::TimeOutOfRange`] for an unrepresentable clock.
fn outgoing(context: &AuthContext) -> Result<Outgoing, Error> {
    let time = if context.policy.check_time {
        Some(kerberos_time(context.now())?)
    } else {
        None
    };
    let number = context
        .policy
        .check_sequence
        .then_some(context.local_sequence);
    Ok((time, number))
}

/// Count one sent message.
const fn sent(context: &mut AuthContext) {
    if context.policy.check_sequence {
        context.local_sequence = context.local_sequence.wrapping_add(1);
    }
}

/// Record a message tag and check its time (MIT `k5_privsafe_check_replay`).
///
/// # Errors
///
/// Returns [`Error::MissingTimestamp`], [`Error::ClockSkew`], [`Error::Replay`]
/// or [`Error::ReplayMemoryFull`].
pub(super) fn check_replay(
    context: &mut AuthContext,
    timestamp: Option<SystemTime>,
    tag: &[u8],
) -> Result<(), Error> {
    if !context.policy.check_time {
        return Ok(());
    }
    let now = context.now();
    if let Some(sent_at) = timestamp {
        let skew = context.policy.clock_skew;
        let difference = match now.duration_since(sent_at) {
            Ok(gap) => gap,
            Err(early) => early.duration(),
        };
        let whole = Duration::from_secs(difference.as_secs());
        if whole > skew {
            return Err(Error::ClockSkew {
                max_clock_skew: skew,
            });
        }
    } else {
        return Err(Error::MissingTimestamp);
    }
    let retention = context.policy.clock_skew.saturating_mul(3);
    context.seen.record(tag, now, retention)
}

/// Check the message number (MIT `rd_priv.c:128-134`).
///
/// # Errors
///
/// Returns [`Error::MissingSequence`] or [`Error::BadSequence`].
pub(super) fn check_sequence(context: &mut AuthContext, number: Option<u32>) -> Result<(), Error> {
    if !context.policy.check_sequence {
        return Ok(());
    }
    let received = number.ok_or(Error::MissingSequence)?;
    let expected = context.remote_sequence;
    if !sequence::accepts(context, received) {
        return Err(Error::BadSequence { expected, received });
    }
    context.remote_sequence = context.remote_sequence.wrapping_add(1);
    Ok(())
}

/// Check the sender and recipient addresses (MIT `k5_privsafe_check_addrs`).
///
/// A message that names a recipient needs a configured local address: MIT
/// would search the host's interfaces, this crate fails closed.
///
/// # Errors
///
/// Returns [`Error::BadAddress`].
fn check_addresses(
    context: &AuthContext,
    sender: &HostAddress,
    recipient: Option<&HostAddress>,
) -> Result<(), Error> {
    if context
        .remote_address
        .as_ref()
        .is_some_and(|remote| remote != sender)
    {
        return Err(Error::BadAddress { which: "sender" });
    }
    match (recipient, context.local_address.as_ref()) {
        (Some(named), Some(local)) if named == local => Ok(()),
        (Some(_named), _unmatched) => Err(Error::BadAddress { which: "recipient" }),
        (None, _any) => Ok(()),
    }
}

/// MIT `krb5_mk_priv`.
///
/// # Errors
///
/// Returns [`Error::LocalAddressRequired`], [`Error::NoKey`], the replay-memory
/// errors and the encoding errors of the codec.
pub(super) fn make_priv(context: &mut AuthContext, data: &[u8]) -> Result<Vec<u8>, Error> {
    let local = context
        .local_address
        .clone()
        .ok_or(Error::LocalAddressRequired)?;
    let key = sending_key(context)?;
    let (time, number) = outgoing(context)?;
    let mut options = EncKrbPrivPartOptions::new(local);
    if let Some((stamp, micros)) = time {
        options = options.with_timestamp(stamp, u32::try_from(&micros).unwrap_or(0));
    }
    if let Some(value) = number {
        options = options.with_sequence_number(value);
    }
    if let Some(remote) = context.remote_address.clone() {
        options = options.with_recipient_address(remote);
    }
    let message = krb_priv::build(data, options, key, None)?;
    let tag = Tag::from_authenticator(message.enc_part.etype, message.enc_part.cipher.as_ref());
    let wire = krb_priv::encode(&message)?;
    let stamped = context.policy.check_time.then(|| context.now());
    check_replay(context, stamped, tag.as_bytes())?;
    sent(context);
    Ok(wire)
}

/// MIT `krb5_rd_priv`.
///
/// # Errors
///
/// Returns [`Error::NoKey`], the codec errors, the address, time, replay and
/// sequence refusals.
pub(super) fn read_priv(
    context: &mut AuthContext,
    wire: &[u8],
) -> Result<Received<Zeroizing<Vec<u8>>>, Error> {
    let key = reading_key(context)?;
    let message = krb_priv::decode(wire)?;
    let part = krb_priv::decrypt_krb_priv_enc_part(&message, key)?;
    check_addresses(
        context,
        &part.sender_address,
        part.recipient_address.as_ref(),
    )?;
    let replay = match &part.timestamp {
        Some(stamp) => Some(system_time(stamp, part.usec.as_ref())?),
        None => None,
    };
    let tag = Tag::from_authenticator(message.enc_part.etype, message.enc_part.cipher.as_ref());
    check_replay(context, replay, tag.as_bytes())?;
    check_sequence(context, part.seq_number)?;
    Ok(Received {
        content: Zeroizing::new(part.user_data.to_vec()),
        timestamp: replay,
        sequence: part.seq_number,
    })
}

/// MIT `krb5_mk_safe`.
///
/// # Errors
///
/// Returns [`Error::LocalAddressRequired`], [`Error::NoKey`], the replay-memory
/// errors and the checksum errors of the codec.
pub(super) fn make_safe(context: &mut AuthContext, data: &[u8]) -> Result<Vec<u8>, Error> {
    let local = context
        .local_address
        .clone()
        .ok_or(Error::LocalAddressRequired)?;
    let key = sending_key(context)?;
    let (time, number) = outgoing(context)?;
    let (timestamp, usec) = match time {
        Some((stamp, micros)) => (Some(stamp), Some(micros)),
        None => (None, None),
    };
    let body = rasn_kerberos::KrbSafeBody {
        user_data: data.to_vec().into(),
        timestamp,
        usec,
        seq_number: number,
        s_address: local,
        r_address: context.remote_address.clone(),
    };
    let message = krb_safe::build(body, key)?;
    let wire = krb_safe::encode(&message)?;
    let stamped = context.policy.check_time.then(|| context.now());
    check_replay(context, stamped, message.cksum.checksum.as_ref())?;
    sent(context);
    Ok(wire)
}

/// MIT `krb5_rd_safe`.
///
/// # Errors
///
/// Returns [`Error::NoKey`], the codec and checksum errors, the address, time,
/// replay and sequence refusals.
pub(super) fn read_safe(
    context: &mut AuthContext,
    wire: &[u8],
) -> Result<Received<Zeroizing<Vec<u8>>>, Error> {
    let key = reading_key(context)?;
    let message = krb_safe::decode(wire)?;
    check_addresses(
        context,
        &message.body.s_address,
        message.body.r_address.as_ref(),
    )?;
    krb_safe::verify_krb_safe_checksum(&message, key)?;
    let replay = match &message.body.timestamp {
        Some(stamp) => Some(system_time(stamp, message.body.usec.as_ref())?),
        None => None,
    };
    check_replay(context, replay, message.cksum.checksum.as_ref())?;
    check_sequence(context, message.body.seq_number)?;
    Ok(Received {
        content: Zeroizing::new(message.body.user_data.to_vec()),
        timestamp: replay,
        sequence: message.body.seq_number,
    })
}

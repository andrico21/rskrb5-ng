//! The sequence and replay window.
//!
//! The 64-entry sequence and replay window of MIT 1.22.2's `g_seqstate`
//! (`generic/util_seqstate.c:36-114`), with 64-bit RFC 4121 sequence numbers.
//!
//! MIT returns a duplicate, old, out-of-sequence or gap token's message with a
//! supplementary status; this window refuses it instead and leaves its state
//! as it was, so a refused token never moves the window.

use super::Error;

/// The window of the sequence numbers a context has received.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Window {
    /// Whether replays are refused.
    replay: bool,
    /// Whether out-of-order tokens are refused.
    sequence: bool,
    /// The first expected sequence number; every number is taken relative to it.
    base: u64,
    /// One more than the highest relative number received.
    next: u64,
    /// Bit `i - 1` set: relative number `next - i` was received.
    received: u64,
}

impl Window {
    /// A window expecting `base` first.
    pub(super) const fn new(base: u64, replay: bool, sequence: bool) -> Self {
        Self {
            replay,
            sequence,
            base,
            next: 0,
            received: 0,
        }
    }

    /// Admit `number`, or refuse it without changing the window.
    ///
    /// # Errors
    ///
    /// Returns [`Error::GapToken`] for a token after a gap under sequencing,
    /// [`Error::OldToken`] or [`Error::UnsequencedToken`] for one more than 64
    /// behind, [`Error::DuplicateToken`] for a replay and
    /// [`Error::UnsequencedToken`] for a late token under sequencing.
    pub(super) fn admit(&mut self, number: u64) -> Result<(), Error> {
        if !self.replay && !self.sequence {
            return Ok(());
        }
        let relative = number.wrapping_sub(self.base);
        if let Some(offset) = relative.checked_sub(self.next) {
            if offset > 0 && self.sequence {
                return Err(Error::GapToken(number));
            }
            let shift = u32::try_from(offset.saturating_add(1)).unwrap_or(u32::MAX);
            self.received = self.received.checked_shl(shift).unwrap_or(0) | 1;
            self.next = relative.wrapping_add(1);
            return Ok(());
        }
        let behind = self.next.wrapping_sub(relative);
        if behind > 64 {
            return Err(if self.sequence {
                Error::UnsequencedToken(number)
            } else {
                Error::OldToken(number)
            });
        }
        let bit = 1_u64
            .checked_shl(u32::try_from(behind.saturating_sub(1)).unwrap_or(u32::MAX))
            .unwrap_or(0);
        if self.replay && self.received & bit != 0 {
            return Err(Error::DuplicateToken(number));
        }
        if self.sequence {
            return Err(Error::UnsequencedToken(number));
        }
        self.received |= bit;
        Ok(())
    }
}

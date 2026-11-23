//! The bounded record of an IAKERB exchange.
//!
//! Every IAKERB token an end sends or receives is appended to one transcript
//! (MIT `iakerb_save_token`, `iakerb.c:186-200`) and every token an end
//! produces counts as a round (`iakerb.c:394-397`, `:321-324`). The record also
//! enforces the byte and round bounds, which MIT leaves to its limits on the
//! number of hops.

use super::{Error, RelayPolicy};

/// The transcript, the round count and their bounds.
#[derive(Debug)]
pub(super) struct Conversation {
    /// Every token of the exchange, in order.
    transcript: Vec<u8>,
    /// The tokens this end produced.
    rounds: usize,
    /// The most rounds.
    max_rounds: usize,
    /// The longest token.
    max_message: usize,
    /// The longest transcript.
    max_transcript: usize,
}

impl Conversation {
    /// A record bounded by `policy`.
    pub(super) const fn for_policy(policy: &RelayPolicy) -> Self {
        Self::bounded(
            policy.max_rounds,
            policy.max_message_bytes,
            policy.max_transcript_bytes,
        )
    }

    /// A record with MIT's round bound and the default byte bounds, for the
    /// initiator.
    pub(super) const fn with_defaults() -> Self {
        Self::bounded(
            RelayPolicy::DEFAULT_MAX_ROUNDS,
            RelayPolicy::DEFAULT_MAX_MESSAGE_BYTES,
            RelayPolicy::DEFAULT_MAX_TRANSCRIPT_BYTES,
        )
    }

    /// A record bounded by the given rounds, token bytes and transcript bytes.
    const fn bounded(max_rounds: usize, max_message: usize, max_transcript: usize) -> Self {
        Self {
            transcript: Vec::new(),
            rounds: 0,
            max_rounds,
            max_message,
            max_transcript,
        }
    }

    /// The transcript.
    pub(super) fn transcript(&self) -> &[u8] {
        &self.transcript
    }

    /// Refuse another round after the bound.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RoundLimit`] when this end already produced the most
    /// tokens it may.
    pub(super) const fn check_round(&self) -> Result<(), Error> {
        if self.rounds >= self.max_rounds {
            return Err(Error::RoundLimit {
                maximum: self.max_rounds,
            });
        }
        Ok(())
    }

    /// Refuse a token above the message bound.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TokenTooLarge`] above the bound.
    pub(super) const fn check_size(&self, length: usize) -> Result<(), Error> {
        if length > self.max_message {
            return Err(Error::TokenTooLarge {
                maximum: self.max_message,
                actual: length,
            });
        }
        Ok(())
    }

    /// Append a token to the transcript.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TokenTooLarge`] and [`Error::TranscriptTooLarge`] above the bounds.
    pub(super) fn append(&mut self, token: &[u8]) -> Result<(), Error> {
        self.check_size(token.len())?;
        if self.transcript.len().saturating_add(token.len()) > self.max_transcript {
            return Err(Error::TranscriptTooLarge {
                maximum: self.max_transcript,
            });
        }
        self.transcript.extend_from_slice(token);
        Ok(())
    }

    /// Record a token this end produces and return it.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::check_round`] and [`Self::append`].
    pub(super) fn produce(&mut self, token: Vec<u8>) -> Result<Vec<u8>, Error> {
        self.check_round()?;
        self.append(&token)?;
        self.rounds = self.rounds.saturating_add(1);
        Ok(token)
    }
}

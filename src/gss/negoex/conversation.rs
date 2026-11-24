/// The most bytes of one `NegoEx` token (MIT has no bound).
pub const MAX_TOKEN_LEN: usize = 0x10_0000;
/// The most messages in one token.
const MAX_MESSAGES: usize = 32;
/// The most authentication schemes in one `NEGO_MESSAGE`.
const MAX_SCHEMES: usize = 64;
/// The most extensions in one `NEGO_MESSAGE`.
const MAX_EXTENSIONS: usize = 16;
/// The most alerts in one `ALERT_MESSAGE`.
const MAX_ALERTS: usize = 16;

/// The `MESSAGE_HEADER` signature, `0x535458454F47454E` little endian (`gssapiP_negoex.h:53`).
const SIGNATURE: [u8; 8] = *b"NEGOEXTS";
/// Bytes of the `MESSAGE_HEADER` every message starts with.
const HEADER_LEN: usize = 40;
/// Header bytes of a `NEGO_MESSAGE` (`gssapiP_negoex.h:68`).
const NEGO_HEADER_LEN: usize = 96;
/// Header bytes of an `EXCHANGE_MESSAGE`.
const EXCHANGE_HEADER_LEN: usize = 64;
/// Header bytes of a `VERIFY_MESSAGE`.
const VERIFY_HEADER_LEN: usize = 80;
/// Header bytes of an `ALERT_MESSAGE`.
const ALERT_HEADER_LEN: usize = 72;
/// Bytes of one `EXTENSION`.
const EXTENSION_LEN: usize = 12;
/// Bytes of one `ALERT`.
const ALERT_LEN: usize = 12;
/// Bytes of an `ALERT_PULSE`.
const ALERT_PULSE_LEN: usize = 8;
/// The `CHECKSUM` header length field.
const CHECKSUM_HEADER_LEN: u32 = 20;
/// The RFC 3961 checksum scheme.
const CHECKSUM_SCHEME_RFC3961: u32 = 1;
/// Set in an extension type when the receiver must understand it.
const EXTENSION_FLAG_CRITICAL: u32 = 0x8000_0000;
/// `ALERT_TYPE_PULSE`.
const ALERT_TYPE_PULSE: u32 = 1;
/// `ALERT_VERIFY_NO_KEY`.
const ALERT_VERIFY_NO_KEY: u32 = 1;

/// A forward reader over message bytes; every short read is an invalid size.
struct Cursor<'bytes> {
    /// The bytes not read yet.
    rest: &'bytes [u8],
}

impl<'bytes> Cursor<'bytes> {
    /// Take the next `count` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Negoex::InvalidMessageSize`] when fewer remain.
    fn take(&mut self, count: usize) -> Result<&'bytes [u8], Negoex> {
        let (head, tail) = self
            .rest
            .split_at_checked(count)
            .ok_or(Negoex::InvalidMessageSize)?;
        self.rest = tail;
        Ok(head)
    }

    /// Take the next `N` bytes as an array.
    ///
    /// # Errors
    ///
    /// Returns [`Negoex::InvalidMessageSize`] when fewer remain.
    fn array<const N: usize>(&mut self) -> Result<[u8; N], Negoex> {
        <[u8; N]>::try_from(self.take(N)?).map_err(|_short| Negoex::InvalidMessageSize)
    }

    /// A little-endian `u16`.
    ///
    /// # Errors
    ///
    /// Returns [`Negoex::InvalidMessageSize`] when too few bytes remain.
    fn u16(&mut self) -> Result<u16, Negoex> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    /// A little-endian `u32`.
    ///
    /// # Errors
    ///
    /// Returns [`Negoex::InvalidMessageSize`] when too few bytes remain.
    fn u32(&mut self) -> Result<u32, Negoex> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    /// A little-endian `i32`.
    ///
    /// # Errors
    ///
    /// Returns [`Negoex::InvalidMessageSize`] when too few bytes remain.
    fn i32(&mut self) -> Result<i32, Negoex> {
        Ok(i32::from_le_bytes(self.array()?))
    }

    /// A little-endian `u64`.
    ///
    /// # Errors
    ///
    /// Returns [`Negoex::InvalidMessageSize`] when too few bytes remain.
    fn u64(&mut self) -> Result<u64, Negoex> {
        Ok(u64::from_le_bytes(self.array()?))
    }
}

/// A wire length as a `usize`.
///
/// # Errors
///
/// Returns [`Negoex::InvalidMessageSize`] when it does not fit.
fn index(value: u32) -> Result<usize, Negoex> {
    usize::try_from(value).map_err(|_wide| Negoex::InvalidMessageSize)
}

/// The `count` elements of `width` bytes at `offset` in `message`, which must
/// lie inside it (MIT `vector_base`, `negoex_util.c:146-153`).
///
/// # Errors
///
/// Returns [`Negoex::InvalidMessageSize`] when the vector leaves the message.
fn vector(message: &[u8], offset: u32, count: usize, width: usize) -> Result<&[u8], Negoex> {
    let total = count
        .checked_mul(width)
        .ok_or(Negoex::InvalidMessageSize)?;
    message
        .get(index(offset)?..)
        .and_then(|from| from.get(..total))
        .ok_or(Negoex::InvalidMessageSize)
}

/// The sequence number and conversation id of one `NegoEx` exchange.
///
/// One counter covers the messages both sides send, as in MIT
/// (`negoex_seqnum`, `negoex_util.c:243,276`): an initiator starts at 0 with an
/// id it chose, an acceptor learns the id from the message with sequence number 0.
/// [`Conversation::parse`] changes nothing when a token is refused.
#[derive(Clone, Copy, Debug)]
pub struct Conversation {
    /// The conversation id, once known.
    id: Option<ConversationId>,
    /// The sequence number of the next message, sent or received.
    next_sequence: u32,
}

impl Conversation {
    /// The conversation of an initiator that chose `id`.
    #[inline]
    #[must_use]
    pub const fn initiating(id: ConversationId) -> Self {
        Self {
            id: Some(id),
            next_sequence: 0,
        }
    }

    /// The conversation of an acceptor, which learns its id from the first message.
    #[inline]
    #[must_use]
    pub const fn accepting() -> Self {
        Self {
            id: None,
            next_sequence: 0,
        }
    }

    /// The conversation id, once known.
    #[inline]
    #[must_use]
    pub const fn id(&self) -> Option<&ConversationId> {
        self.id.as_ref()
    }

    /// The sequence number of the next message.
    #[inline]
    #[must_use]
    pub const fn next_sequence(&self) -> u32 {
        self.next_sequence
    }

    /// Parse every message of `token`, checking signature, sizes, sequence
    /// numbers and the conversation id (MIT `negoex_parse_token`).
    ///
    /// # Errors
    ///
    /// Returns [`Negoex::TokenTooLarge`] and [`Negoex::TooManyMessages`] above
    /// the bounds, [`Negoex::InvalidMessageSize`] for an empty token or a length,
    /// offset or count that leaves its message, [`Negoex::InvalidMessageSignature`],
    /// [`Negoex::InvalidMessageType`], [`Negoex::MessageOutOfSequence`],
    /// [`Negoex::InvalidConversationId`], [`Negoex::UnsupportedVersion`],
    /// [`Negoex::UnsupportedCriticalExtension`], [`Negoex::UnknownChecksumScheme`]
    /// and [`Negoex::TooManySchemes`] or [`Negoex::TooManyEntries`] above the bounds.
    #[inline]
    pub fn parse(&mut self, token: &[u8]) -> Result<Vec<Message>, Negoex> {
        if token.len() > MAX_TOKEN_LEN {
            return Err(Negoex::TokenTooLarge {
                maximum: MAX_TOKEN_LEN,
                actual: token.len(),
            });
        }
        if token.is_empty() {
            return Err(Negoex::InvalidMessageSize);
        }
        let mut next = self.next_sequence;
        let mut id = self.id;
        let mut messages = Vec::new();
        let mut offset = 0_usize;
        while let Some(rest) = token.get(offset..).filter(|rest| !rest.is_empty()) {
            if messages.len() >= MAX_MESSAGES {
                return Err(Negoex::TooManyMessages {
                    maximum: MAX_MESSAGES,
                });
            }
            let (message, length) = parse_message(rest, offset, &mut next, &mut id)?;
            messages.push(message);
            offset = offset
                .checked_add(length)
                .ok_or(Negoex::InvalidMessageSize)?;
        }
        self.next_sequence = next;
        self.id = id;
        Ok(messages)
    }

    /// Encode `message` as the next message of the conversation and advance the
    /// sequence number.
    ///
    /// # Errors
    ///
    /// Returns [`Negoex::UnexpectedStep`] before the conversation id is known,
    /// and [`Negoex::TokenTooLarge`] when the message does not fit its length fields.
    #[inline]
    pub fn encode(&mut self, message: &Message) -> Result<Vec<u8>, Negoex> {
        let mut out = Vec::new();
        self.encode_into(message, &mut out)?;
        Ok(out)
    }

    /// Append the encoding of `message` to `out`, as [`Conversation::encode`].
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Conversation::encode`]; `out` is unchanged then.
    #[inline]
    pub fn encode_into(&mut self, message: &Message, out: &mut Vec<u8>) -> Result<(), Negoex> {
        let id = self
            .id
            .ok_or(Negoex::UnexpectedStep("the conversation id is not known"))?;
        let body = encode_body(message)?;
        let header_len = body.header_len;
        let message_len = header_len
            .checked_add(body.payload.len())
            .and_then(|total| u32::try_from(total).ok())
            .ok_or(Negoex::TokenTooLarge {
                maximum: MAX_TOKEN_LEN,
                actual: usize::MAX,
            })?;
        let sequence = self.next_sequence;
        self.next_sequence = sequence
            .checked_add(1)
            .ok_or(Negoex::UnexpectedStep("the sequence number is exhausted"))?;
        out.extend_from_slice(&SIGNATURE);
        out.extend_from_slice(&message.message_type().code().to_le_bytes());
        out.extend_from_slice(&sequence.to_le_bytes());
        out.extend_from_slice(
            &u32::try_from(header_len)
                .map_err(|_wide| Negoex::InvalidMessageSize)?
                .to_le_bytes(),
        );
        out.extend_from_slice(&message_len.to_le_bytes());
        out.extend_from_slice(id.as_bytes());
        out.extend_from_slice(&body.fixed);
        out.extend_from_slice(&body.payload);
        Ok(())
    }
}

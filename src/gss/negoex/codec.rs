/// Parse the message at the start of `rest`, which starts at `offset` in its
/// token; return it with its length (MIT `parse_message`, `negoex_util.c:325-413`).
///
/// `next` and `id` are advanced for the message only when it parses.
///
/// # Errors
///
/// Returns the errors of [`Conversation::parse`].
fn parse_message(
    rest: &[u8],
    offset: usize,
    next: &mut u32,
    id: &mut Option<ConversationId>,
) -> Result<(Message, usize), Negoex> {
    let mut header = Cursor { rest };
    let signature = header.array::<8>()?;
    let code = header.u32()?;
    let sequence = header.u32()?;
    let header_len = index(header.u32()?)?;
    let message_len = index(header.u32()?)?;
    let conversation = ConversationId::from_bytes(header.array()?);
    if message_len > rest.len() || header_len > message_len || header_len < HEADER_LEN {
        return Err(Negoex::InvalidMessageSize);
    }
    if signature != SIGNATURE {
        return Err(Negoex::InvalidMessageSignature);
    }
    if sequence != *next {
        return Err(Negoex::MessageOutOfSequence {
            expected: *next,
            actual: sequence,
        });
    }
    if id.is_some_and(|known| known != conversation) {
        return Err(Negoex::InvalidConversationId);
    }
    let kind = MessageType::from_code(code).ok_or(Negoex::InvalidMessageType(code))?;
    let whole = rest.get(..message_len).ok_or(Negoex::InvalidMessageSize)?;
    let mut fixed = Cursor {
        rest: whole
            .get(HEADER_LEN..header_len)
            .ok_or(Negoex::InvalidMessageSize)?,
    };
    let message = match kind {
        MessageType::InitiatorNego | MessageType::AcceptorNego => {
            Message::Nego(parse_nego(kind, &mut fixed, whole, header_len)?)
        }
        MessageType::InitiatorMetaData
        | MessageType::AcceptorMetaData
        | MessageType::Challenge
        | MessageType::ApRequest => {
            Message::Exchange(parse_exchange(kind, &mut fixed, whole, header_len)?)
        }
        MessageType::Verify => Message::Verify(parse_verify(&mut fixed, whole, offset, header_len)?),
        MessageType::Alert => Message::Alert(parse_alert(&mut fixed, whole, header_len)?),
    };
    *next = sequence
        .checked_add(1)
        .ok_or(Negoex::UnexpectedStep("the sequence number is exhausted"))?;
    *id = Some(conversation);
    Ok((message, message_len))
}

/// Refuse a header shorter than the type's fixed fields.
///
/// # Errors
///
/// Returns [`Negoex::InvalidMessageSize`] when it is shorter.
const fn require_header(header_len: usize, minimum: usize) -> Result<(), Negoex> {
    if header_len < minimum {
        return Err(Negoex::InvalidMessageSize);
    }
    Ok(())
}

/// A `NEGO_MESSAGE` (MIT `parse_nego_message`).
///
/// # Errors
///
/// Returns the errors of [`Conversation::parse`] for a `NEGO_MESSAGE`.
fn parse_nego(
    kind: MessageType,
    fixed: &mut Cursor<'_>,
    whole: &[u8],
    header_len: usize,
) -> Result<NegoMessage, Negoex> {
    require_header(header_len, NEGO_HEADER_LEN)?;
    let random = fixed.array::<32>()?;
    let version = fixed.u64()?;
    if version != 0 {
        return Err(Negoex::UnsupportedVersion(version));
    }
    let schemes_offset = fixed.u32()?;
    let count = usize::from(fixed.u16()?);
    if count > MAX_SCHEMES {
        return Err(Negoex::TooManySchemes {
            maximum: MAX_SCHEMES,
            actual: count,
        });
    }
    let (chunks, _) = vector(whole, schemes_offset, count, 16)?.as_chunks::<16>();
    let schemes = chunks.iter().copied().map(AuthScheme::from_bytes).collect();
    let extensions_offset = fixed.u32()?;
    let extensions = usize::from(fixed.u16()?);
    if extensions > MAX_EXTENSIONS {
        return Err(Negoex::TooManyEntries {
            field: "extensions",
            maximum: MAX_EXTENSIONS,
            actual: extensions,
        });
    }
    let (entries, _) = vector(whole, extensions_offset, extensions, EXTENSION_LEN)?.as_chunks::<12>();
    for entry in entries {
        let extension_type = Cursor { rest: entry }.u32()?;
        if extension_type & EXTENSION_FLAG_CRITICAL != 0 {
            return Err(Negoex::UnsupportedCriticalExtension);
        }
    }
    NegoMessage::new(kind, random, schemes)
}

/// An `EXCHANGE_MESSAGE` (MIT `parse_exchange_message`).
///
/// # Errors
///
/// Returns the errors of [`Conversation::parse`] for an `EXCHANGE_MESSAGE`.
fn parse_exchange(
    kind: MessageType,
    fixed: &mut Cursor<'_>,
    whole: &[u8],
    header_len: usize,
) -> Result<ExchangeMessage, Negoex> {
    require_header(header_len, EXCHANGE_HEADER_LEN)?;
    let scheme = AuthScheme::from_bytes(fixed.array()?);
    let offset = fixed.u32()?;
    let length = index(fixed.u32()?)?;
    ExchangeMessage::new(kind, scheme, vector(whole, offset, length, 1)?.to_vec())
}

/// A `VERIFY_MESSAGE` (MIT `parse_verify_message`).
///
/// # Errors
///
/// Returns the errors of [`Conversation::parse`] for a `VERIFY_MESSAGE`.
fn parse_verify(
    fixed: &mut Cursor<'_>,
    whole: &[u8],
    offset_in_token: usize,
    header_len: usize,
) -> Result<VerifyMessage, Negoex> {
    require_header(header_len, VERIFY_HEADER_LEN)?;
    let scheme = AuthScheme::from_bytes(fixed.array()?);
    if fixed.u32()? != CHECKSUM_HEADER_LEN {
        return Err(Negoex::InvalidMessageSize);
    }
    let checksum_scheme = fixed.u32()?;
    if checksum_scheme != CHECKSUM_SCHEME_RFC3961 {
        return Err(Negoex::UnknownChecksumScheme(checksum_scheme));
    }
    let checksum_type = fixed.i32()?;
    let offset = fixed.u32()?;
    let length = index(fixed.u32()?)?;
    Ok(VerifyMessage {
        scheme,
        checksum_type,
        checksum: vector(whole, offset, length, 1)?.to_vec(),
        offset_in_token,
    })
}

/// An `ALERT_MESSAGE` (MIT `parse_alert_message`).
///
/// The alert count is the specified `u16`; MIT reads four bytes, which
/// includes two padding bytes.
///
/// # Errors
///
/// Returns the errors of [`Conversation::parse`] for an `ALERT_MESSAGE`.
fn parse_alert(
    fixed: &mut Cursor<'_>,
    whole: &[u8],
    header_len: usize,
) -> Result<AlertMessage, Negoex> {
    require_header(header_len, ALERT_HEADER_LEN)?;
    let scheme = AuthScheme::from_bytes(fixed.array()?);
    let _error_code = fixed.u32()?;
    let offset = fixed.u32()?;
    let count = usize::from(fixed.u16()?);
    if count > MAX_ALERTS {
        return Err(Negoex::TooManyEntries {
            field: "alerts",
            maximum: MAX_ALERTS,
            actual: count,
        });
    }
    let mut verify_no_key = false;
    let (entries, _) = vector(whole, offset, count, ALERT_LEN)?.as_chunks::<12>();
    for entry in entries {
        let mut alert = Cursor { rest: entry };
        let alert_type = alert.u32()?;
        let value_offset = alert.u32()?;
        let value_len = index(alert.u32()?)?;
        let value = vector(whole, value_offset, value_len, 1)?;
        if alert_type == ALERT_TYPE_PULSE && value_len >= ALERT_PULSE_LEN {
            let mut pulse = Cursor { rest: value };
            let _pulse_header_len = pulse.u32()?;
            if pulse.u32()? == ALERT_VERIFY_NO_KEY {
                verify_no_key = true;
            }
        }
    }
    Ok(AlertMessage {
        scheme,
        verify_no_key,
    })
}

/// The type-specific part of an encoded message.
struct Body {
    /// Bytes of the whole header, the common 40 included.
    header_len: usize,
    /// The header bytes after the common 40.
    fixed: Vec<u8>,
    /// The payload after the header.
    payload: Vec<u8>,
}

/// A length as the 32-bit wire field.
///
/// # Errors
///
/// Returns [`Negoex::TokenTooLarge`] when it does not fit.
fn wire_len(length: usize) -> Result<u32, Negoex> {
    u32::try_from(length).map_err(|_wide| Negoex::TokenTooLarge {
        maximum: MAX_TOKEN_LEN,
        actual: length,
    })
}

/// A header length as a wire offset.
fn wire_offset(header_len: usize) -> u32 {
    u32::try_from(header_len).unwrap_or(u32::MAX)
}

/// Encode the type-specific fields and payload of `message` (MIT `negoex_add_*`).
///
/// # Errors
///
/// Returns [`Negoex::TooManySchemes`] and [`Negoex::TokenTooLarge`] for a message that does not fit its fields.
fn encode_body(message: &Message) -> Result<Body, Negoex> {
    match message {
        Message::Nego(nego) => {
            let count = u16::try_from(nego.schemes.len()).map_err(|_wide| Negoex::TooManySchemes {
                maximum: MAX_SCHEMES,
                actual: nego.schemes.len(),
            })?;
            let mut fixed = Vec::with_capacity(NEGO_HEADER_LEN);
            fixed.extend_from_slice(&nego.random);
            fixed.extend_from_slice(&0_u64.to_le_bytes());
            fixed.extend_from_slice(&wire_offset(NEGO_HEADER_LEN).to_le_bytes());
            fixed.extend_from_slice(&count.to_le_bytes());
            fixed.extend_from_slice(&wire_offset(NEGO_HEADER_LEN).to_le_bytes());
            fixed.extend_from_slice(&0_u16.to_le_bytes());
            fixed.extend_from_slice(&[0; 4]);
            let payload = nego
                .schemes
                .iter()
                .flat_map(|scheme| scheme.as_bytes().iter().copied())
                .collect();
            Ok(Body {
                header_len: NEGO_HEADER_LEN,
                fixed,
                payload,
            })
        }
        Message::Exchange(exchange) => {
            let mut fixed = Vec::with_capacity(EXCHANGE_HEADER_LEN);
            fixed.extend_from_slice(exchange.scheme.as_bytes());
            fixed.extend_from_slice(&wire_offset(EXCHANGE_HEADER_LEN).to_le_bytes());
            fixed.extend_from_slice(&wire_len(exchange.token.len())?.to_le_bytes());
            Ok(Body {
                header_len: EXCHANGE_HEADER_LEN,
                fixed,
                payload: exchange.token.clone(),
            })
        }
        Message::Verify(verify) => {
            let mut fixed = Vec::with_capacity(VERIFY_HEADER_LEN);
            fixed.extend_from_slice(verify.scheme.as_bytes());
            fixed.extend_from_slice(&CHECKSUM_HEADER_LEN.to_le_bytes());
            fixed.extend_from_slice(&CHECKSUM_SCHEME_RFC3961.to_le_bytes());
            fixed.extend_from_slice(&verify.checksum_type.to_le_bytes());
            fixed.extend_from_slice(&wire_offset(VERIFY_HEADER_LEN).to_le_bytes());
            fixed.extend_from_slice(&wire_len(verify.checksum.len())?.to_le_bytes());
            fixed.extend_from_slice(&[0; 4]);
            Ok(Body {
                header_len: VERIFY_HEADER_LEN,
                fixed,
                payload: verify.checksum.clone(),
            })
        }
        Message::Alert(alert) => {
            let mut fixed = Vec::with_capacity(ALERT_HEADER_LEN);
            fixed.extend_from_slice(alert.scheme.as_bytes());
            fixed.extend_from_slice(&0_u32.to_le_bytes());
            fixed.extend_from_slice(&wire_offset(ALERT_HEADER_LEN).to_le_bytes());
            fixed.extend_from_slice(&u16::from(alert.verify_no_key).to_le_bytes());
            fixed.extend_from_slice(&[0; 6]);
            let mut payload = Vec::new();
            if alert.verify_no_key {
                payload.extend_from_slice(&ALERT_TYPE_PULSE.to_le_bytes());
                payload.extend_from_slice(
                    &wire_offset(ALERT_HEADER_LEN.saturating_add(ALERT_LEN)).to_le_bytes(),
                );
                payload.extend_from_slice(&wire_offset(ALERT_PULSE_LEN).to_le_bytes());
                payload.extend_from_slice(&wire_offset(ALERT_PULSE_LEN).to_le_bytes());
                payload.extend_from_slice(&ALERT_VERIFY_NO_KEY.to_le_bytes());
            }
            Ok(Body {
                header_len: ALERT_HEADER_LEN,
                fixed,
                payload,
            })
        }
    }
}

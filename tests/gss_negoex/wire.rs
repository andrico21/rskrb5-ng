//! The MS-NEGOEX message framework: byte-exact layouts (built here from the
//! MS-NEGOEX section 2.2 field tables, independently of the library), parsing
//! bounds and the conversation (sequence number and conversation id) rules.

use rskrb5_ng::{
    error::Negoex,
    gss::negoex::{
        AlertMessage, AuthScheme, Conversation, ConversationId, ExchangeMessage, Message,
        MessageType, NegoMessage, VerifyMessage,
    },
};

use super::context::{Context as _, TestError};

/// The conversation id used by the vectors.
const CONVERSATION: [u8; 16] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
];

/// Two authentication scheme GUIDs (MIT's `negoextest` schemes).
const SCHEME_A: [u8; 16] = [
    0xc0, 0xa2, 0x85, 0x69, 0x66, 0xac, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];
/// The second scheme.
const SCHEME_B: [u8; 16] = [
    0xd1, 0xb0, 0x84, 0x69, 0x2c, 0xa8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// The 40-byte `MESSAGE_HEADER` (MS-NEGOEX 2.2.6.2).
fn header(kind: u32, sequence: u32, header_len: u32, message_len: u32) -> Vec<u8> {
    let mut out = b"NEGOEXTS".to_vec();
    for field in [kind, sequence, header_len, message_len] {
        out.extend_from_slice(&field.to_le_bytes());
    }
    out.extend_from_slice(&CONVERSATION);
    out
}

/// A `NEGO_MESSAGE` with `schemes` (MS-NEGOEX 2.2.6.3): header 96 bytes.
fn nego(kind: u32, sequence: u32, random: [u8; 32], schemes: &[[u8; 16]]) -> Vec<u8> {
    let count = u16::try_from(schemes.len()).unwrap_or(0);
    let total = 96 + 16 * u32::from(count);
    let mut out = header(kind, sequence, 96, total);
    out.extend_from_slice(&random);
    out.extend_from_slice(&0_u64.to_le_bytes());
    out.extend_from_slice(&96_u32.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&96_u32.to_le_bytes());
    out.extend_from_slice(&0_u16.to_le_bytes());
    out.extend_from_slice(&[0; 4]);
    for scheme in schemes {
        out.extend_from_slice(scheme);
    }
    out
}

/// An `EXCHANGE_MESSAGE` (MS-NEGOEX 2.2.6.4): header 64 bytes.
fn exchange(kind: u32, sequence: u32, scheme: [u8; 16], token: &[u8]) -> Vec<u8> {
    let length = u32::try_from(token.len()).unwrap_or(0);
    let mut out = header(kind, sequence, 64, 64 + length);
    out.extend_from_slice(&scheme);
    out.extend_from_slice(&64_u32.to_le_bytes());
    out.extend_from_slice(&length.to_le_bytes());
    out.extend_from_slice(token);
    out
}

/// A `VERIFY_MESSAGE` (MS-NEGOEX 2.2.6.5): header 80 bytes.
fn verify(sequence: u32, scheme: [u8; 16], checksum_type: i32, checksum: &[u8]) -> Vec<u8> {
    let length = u32::try_from(checksum.len()).unwrap_or(0);
    let mut out = header(6, sequence, 80, 80 + length);
    out.extend_from_slice(&scheme);
    out.extend_from_slice(&20_u32.to_le_bytes());
    out.extend_from_slice(&1_u32.to_le_bytes());
    out.extend_from_slice(&checksum_type.to_le_bytes());
    out.extend_from_slice(&80_u32.to_le_bytes());
    out.extend_from_slice(&length.to_le_bytes());
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(checksum);
    out
}

/// An `ALERT_MESSAGE` with one `ALERT_TYPE_PULSE` alert of `reason` (MS-NEGOEX 2.2.6.6).
fn alert(sequence: u32, scheme: [u8; 16], reason: u32) -> Vec<u8> {
    let mut out = header(7, sequence, 72, 92);
    out.extend_from_slice(&scheme);
    out.extend_from_slice(&0_u32.to_le_bytes());
    out.extend_from_slice(&72_u32.to_le_bytes());
    out.extend_from_slice(&1_u16.to_le_bytes());
    out.extend_from_slice(&[0; 6]);
    out.extend_from_slice(&1_u32.to_le_bytes());
    out.extend_from_slice(&84_u32.to_le_bytes());
    out.extend_from_slice(&8_u32.to_le_bytes());
    out.extend_from_slice(&8_u32.to_le_bytes());
    out.extend_from_slice(&reason.to_le_bytes());
    out
}

/// Overwrite `bytes` at `at` with `value` (the vector must be long enough).
fn put(bytes: &mut [u8], at: usize, value: &[u8]) {
    if let Some(target) = bytes.get_mut(at..at + value.len()) {
        target.copy_from_slice(value);
    }
}

/// A conversation for an acceptor: it learns the id from sequence number 0.
fn accepting() -> Conversation {
    Conversation::accepting()
}

/// The conversation of an initiator that chose [`CONVERSATION`].
fn initiating() -> Conversation {
    Conversation::initiating(ConversationId::from_bytes(CONVERSATION))
}

/// A parse failure the test expects, as a [`Negoex`] value.
fn refusal(conversation: &mut Conversation, token: &[u8]) -> Result<Negoex, TestError> {
    conversation
        .parse(token)
        .err()
        .context("the token must be refused")
}

/// `INITIATOR_NEGO` encodes to the layout of the specification, byte for byte.
#[test]
fn nego_message_layout_is_byte_exact() -> Result<(), TestError> {
    let random = [0x5a; 32];
    let message = Message::Nego(NegoMessage::new(
        MessageType::InitiatorNego,
        random,
        vec![AuthScheme::from_bytes(SCHEME_A), AuthScheme::from_bytes(SCHEME_B)],
    )?);
    let mut conversation = initiating();
    let bytes = conversation.encode(&message)?;
    assert_eq!(bytes, nego(0, 0, random, &[SCHEME_A, SCHEME_B]));
    assert_eq!(conversation.next_sequence(), 1, "the sequence number advances");
    Ok(())
}

/// The three other message shapes encode to their specified layouts.
#[test]
fn exchange_verify_and_alert_layouts_are_byte_exact() -> Result<(), TestError> {
    let scheme = AuthScheme::from_bytes(SCHEME_A);
    let mut conversation = initiating();
    let challenge = ExchangeMessage::new(MessageType::ApRequest, scheme, b"token".to_vec())?;
    assert_eq!(
        conversation.encode(&Message::Exchange(challenge))?,
        exchange(5, 0, SCHEME_A, b"token")
    );
    let checked = VerifyMessage::new(scheme, 16, vec![7; 12]);
    assert_eq!(
        conversation.encode(&Message::Verify(checked))?,
        verify(1, SCHEME_A, 16, &[7; 12])
    );
    assert_eq!(
        conversation.encode(&Message::Alert(AlertMessage::verify_no_key(scheme)))?,
        alert(2, SCHEME_A, 1)
    );
    Ok(())
}

/// A token of every message type parses back to the messages that built it,
/// in order, and the acceptor learns the conversation id from sequence number 0.
#[test]
fn a_multi_message_token_parses_in_order() -> Result<(), TestError> {
    let mut token = nego(0, 0, [1; 32], &[SCHEME_A, SCHEME_B]);
    token.extend(exchange(2, 1, SCHEME_A, b"X"));
    token.extend(exchange(5, 2, SCHEME_A, b"ap-req"));
    token.extend(verify(3, SCHEME_A, 16, &[9; 12]));
    let mut conversation = accepting();
    let messages = conversation.parse(&token)?;
    assert_eq!(messages.len(), 4);
    let Some(Message::Nego(first)) = messages.first() else {
        return Err("the first message is INITIATOR_NEGO".into());
    };
    assert_eq!(first.message_type(), MessageType::InitiatorNego);
    assert_eq!(first.random(), &[1; 32]);
    assert_eq!(first.schemes().len(), 2);
    let Some(Message::Verify(checked)) = messages.get(3) else {
        return Err("the last message is VERIFY".into());
    };
    assert_eq!(checked.checksum_type(), 16);
    assert_eq!(checked.checksum(), &[9; 12]);
    assert_eq!(
        checked.offset_in_token(),
        token.len() - (80 + 12),
        "the VERIFY message starts where the earlier messages end"
    );
    assert_eq!(conversation.next_sequence(), 4);
    assert_eq!(conversation.id().map(ConversationId::as_bytes), Some(&CONVERSATION));
    Ok(())
}

/// A `VERIFY_NO_KEY` pulse alert is recognised.
#[test]
fn a_verify_no_key_alert_is_recognised() -> Result<(), TestError> {
    let messages = initiating().parse(&alert(0, SCHEME_B, 1))?;
    let Some(Message::Alert(parsed)) = messages.first() else {
        return Err("an ALERT message".into());
    };
    assert!(parsed.is_verify_no_key());
    assert_eq!(parsed.scheme(), AuthScheme::from_bytes(SCHEME_B));
    let other = initiating().parse(&alert(0, SCHEME_B, 2))?;
    let Some(Message::Alert(parsed)) = other.first() else {
        return Err("an ALERT message".into());
    };
    assert!(!parsed.is_verify_no_key(), "another pulse reason is not VERIFY_NO_KEY");
    Ok(())
}

/// A message whose signature is wrong is refused.
#[test]
fn a_wrong_signature_is_refused() -> Result<(), TestError> {
    let mut token = nego(0, 0, [0; 32], &[SCHEME_A]);
    put(&mut token, 0, b"NEGOEXTX");
    assert!(matches!(
        refusal(&mut accepting(), &token)?,
        Negoex::InvalidMessageSignature
    ));
    Ok(())
}

/// An unknown message type is refused, and so is a version other than 0 and a
/// critical extension.
#[test]
fn unknown_type_version_and_critical_extension_are_refused() -> Result<(), TestError> {
    let mut token = nego(0, 0, [0; 32], &[SCHEME_A]);
    put(&mut token, 8, &8_u32.to_le_bytes());
    assert!(matches!(
        refusal(&mut accepting(), &token)?,
        Negoex::InvalidMessageType(8)
    ));
    let mut versioned = nego(0, 0, [0; 32], &[SCHEME_A]);
    put(&mut versioned, 72, &1_u64.to_le_bytes());
    assert!(matches!(
        refusal(&mut accepting(), &versioned)?,
        Negoex::UnsupportedVersion(1)
    ));
    // One 12-byte extension after the scheme: type with the critical bit set.
    let mut critical = nego(0, 0, [0; 32], &[SCHEME_A]);
    put(&mut critical, 86, &112_u32.to_le_bytes());
    put(&mut critical, 90, &1_u16.to_le_bytes());
    critical.extend_from_slice(&0x8000_0001_u32.to_le_bytes());
    critical.extend_from_slice(&[0; 8]);
    put(&mut critical, 20, &124_u32.to_le_bytes());
    assert!(matches!(
        refusal(&mut accepting(), &critical)?,
        Negoex::UnsupportedCriticalExtension
    ));
    Ok(())
}

/// Sizes that disagree with the token are refused: a message longer than the
/// token, a header longer than its message, a header shorter than the message
/// type needs (MIT 1.22.2 reads past the token there) and a truncated header.
#[test]
fn inconsistent_sizes_are_refused() -> Result<(), TestError> {
    let valid = exchange(5, 0, SCHEME_A, b"abc");
    let mut long_message = valid.clone();
    put(&mut long_message, 20, &9999_u32.to_le_bytes());
    let mut long_header = valid.clone();
    put(&mut long_header, 16, &80_u32.to_le_bytes());
    let mut short_header = valid.clone();
    put(&mut short_header, 16, &0_u32.to_le_bytes());
    for token in [
        long_message,
        long_header,
        short_header,
        valid.get(..39).context("a prefix")?.to_vec(),
        valid.get(..valid.len() - 1).context("a prefix")?.to_vec(),
    ] {
        assert!(matches!(
            refusal(&mut accepting(), &token)?,
            Negoex::InvalidMessageSize
        ));
    }
    Ok(())
}

/// A vector that leaves its message is refused: the scheme list, the extension
/// list (MIT 1.22.2 dereferences NULL there), the exchange bytes, the checksum
/// and the alert list with its pulse value.
#[test]
fn out_of_range_vectors_are_refused() -> Result<(), TestError> {
    let mut schemes = nego(0, 0, [0; 32], &[SCHEME_A]);
    put(&mut schemes, 84, &2_u16.to_le_bytes());
    let mut extensions = nego(0, 0, [0; 32], &[SCHEME_A]);
    put(&mut extensions, 90, &3_u16.to_le_bytes());
    let mut exchange_bytes = exchange(5, 0, SCHEME_A, b"abc");
    put(&mut exchange_bytes, 60, &4_u32.to_le_bytes());
    let mut checksum = verify(0, SCHEME_A, 16, &[1, 2, 3]);
    put(&mut checksum, 72, &4_u32.to_le_bytes());
    let mut alerts = alert(0, SCHEME_A, 1);
    put(&mut alerts, 64, &2_u16.to_le_bytes());
    let mut pulse = alert(0, SCHEME_A, 1);
    put(&mut pulse, 80, &9_u32.to_le_bytes());
    for token in [schemes, extensions, exchange_bytes, checksum, alerts, pulse] {
        assert!(matches!(
            refusal(&mut accepting(), &token)?,
            Negoex::InvalidMessageSize
        ));
    }
    Ok(())
}

/// A checksum scheme other than RFC 3961 is refused.
#[test]
fn an_unknown_checksum_scheme_is_refused() -> Result<(), TestError> {
    let mut token = verify(0, SCHEME_A, 16, &[1]);
    put(&mut token, 60, &2_u32.to_le_bytes());
    assert!(matches!(
        refusal(&mut accepting(), &token)?,
        Negoex::UnknownChecksumScheme(2)
    ));
    Ok(())
}

/// A sequence number out of order, a changed conversation id and a replayed
/// token are refused, and a refused token leaves the conversation unchanged.
#[test]
fn sequence_and_conversation_are_enforced_atomically() -> Result<(), TestError> {
    let mut conversation = accepting();
    let first = nego(0, 0, [0; 32], &[SCHEME_A]);
    drop(conversation.parse(&first)?);
    assert!(matches!(
        refusal(&mut conversation, &first)?,
        Negoex::MessageOutOfSequence { expected: 1, actual: 0 }
    ));
    let mut other = exchange(5, 1, SCHEME_A, b"x");
    put(&mut other, 24, &[0xee; 16]);
    assert!(matches!(
        refusal(&mut conversation, &other)?,
        Negoex::InvalidConversationId
    ));
    // The second message of a token is bad: the whole token is refused and the
    // conversation has not advanced, so the good first message parses afterwards.
    let mut mixed = exchange(5, 1, SCHEME_A, b"x");
    mixed.extend(exchange(5, 9, SCHEME_A, b"y"));
    assert!(matches!(
        refusal(&mut conversation, &mixed)?,
        Negoex::MessageOutOfSequence { expected: 2, actual: 9 }
    ));
    assert_eq!(conversation.next_sequence(), 1);
    assert_eq!(conversation.parse(&exchange(5, 1, SCHEME_A, b"x"))?.len(), 1);
    Ok(())
}

/// The initiator's own conversation id must match the acceptor's reply.
#[test]
fn the_initiator_checks_the_acceptors_conversation() -> Result<(), TestError> {
    let mut conversation = initiating();
    let mut reply = exchange(3, 0, SCHEME_A, b"x");
    put(&mut reply, 24, &[0xee; 16]);
    assert!(matches!(
        refusal(&mut conversation, &reply)?,
        Negoex::InvalidConversationId
    ));
    Ok(())
}

/// Bounds: an empty token, a token over the byte bound, more messages than the
/// bound and more schemes than the bound are refused.
#[test]
fn token_message_and_scheme_counts_are_bounded() -> Result<(), TestError> {
    assert!(matches!(
        refusal(&mut accepting(), &[])?,
        Negoex::InvalidMessageSize
    ));
    let huge = vec![0_u8; 0x10_0001];
    assert!(matches!(
        refusal(&mut accepting(), &huge)?,
        Negoex::TokenTooLarge { .. }
    ));
    let mut many = Vec::new();
    for sequence in 0..40 {
        many.extend(exchange(5, sequence, SCHEME_A, b""));
    }
    assert!(matches!(
        refusal(&mut accepting(), &many)?,
        Negoex::TooManyMessages { .. }
    ));
    let schemes = vec![SCHEME_A; 65];
    assert!(matches!(
        refusal(&mut accepting(), &nego(0, 0, [0; 32], &schemes))?,
        Negoex::TooManySchemes { .. }
    ));
    Ok(())
}

/// No prefix and no single-byte corruption of a valid token panics.
#[test]
fn damaged_tokens_never_panic() -> Result<(), TestError> {
    let mut token = nego(0, 0, [3; 32], &[SCHEME_A, SCHEME_B]);
    token.extend(exchange(2, 1, SCHEME_A, b"X"));
    token.extend(verify(2, SCHEME_A, 16, &[9; 12]));
    token.extend(alert(3, SCHEME_A, 1));
    for end in 0..token.len() {
        drop(accepting().parse(token.get(..end).context("a prefix")?));
    }
    for index in 0..token.len() {
        for value in [0_u8, 0xff, 0x80] {
            let mut copy = token.clone();
            *copy.get_mut(index).context("a byte")? = value;
            drop(accepting().parse(&copy));
        }
    }
    Ok(())
}

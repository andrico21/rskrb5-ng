//! Tokens captured from MIT krb5 1.22.2's `NegoEx` (2026-11-23, plan 2 todo 21).
//!
//! PROVENANCE. The hex strings are the SPNEGO tokens that MIT krb5 1.22.2
//! (`libgssapi_krb5` with its `negoextest` plugin, built from the release
//! tarball `krb5-1.22.2` by `scripts/interop/peer-mit/Dockerfile`) produced when the
//! external-peer adapter (`scripts/interop/peer-mit/peer/`) ran as an
//! initiator (`mit_initiator_*`) and as an acceptor (`mit_acceptor_reply_*`)
//! against this crate in the live `negoex` suite. The bytes are MIT's: the
//! conversation id and the random of an initiator, the sequence numbers and
//! the `VERIFY` checksums are MIT's own choices. The `rust_*` tokens are this
//! crate's tokens that preceded MIT's reply in the same capture: they are
//! needed because one sequence counter covers both directions and are not
//! evidence of anything. The tests only parse: that the crate accepts MIT's
//! framing is the claim.

use rskrb5_ng::{
    gss::negoex::{AuthScheme, Conversation, Message, MessageType},
    spnego::{NegTokenResp, Token},
};

use super::context::{Context as _, TestError};

/// MIT's first token, one hop: `NegTokenInit` with `INITIATOR_NEGO`, two `INITIATOR_META_DATA`, `AP_REQUEST` and `VERIFY`.
const MIT_INITIATOR_ONE_HOP: &str = concat!(
    "608201d106062b0601050502a08201c5308201c1a00e300c060a2b0601040182",
    "3702021ea28201ad048201a94e45474f45585453000000000000000060000000",
    "80000000a3924de89cf7c724b4aff63b22338bfeebdf36c296c9c54fd28c50c4",
    "92e65adc093c4bcf5c6d6a1894159beb5e69c716000000000000000060000000",
    "0200600000000000000000006985a2c0ac66000000000000000000006984b0d1",
    "a82c000000000000000000004e45474f45585453020000000100000040000000",
    "41000000a3924de89cf7c724b4aff63b22338bfe6985a2c0ac66000000000000",
    "000000004000000001000000584e45474f455854530200000002000000400000",
    "0041000000a3924de89cf7c724b4aff63b22338bfe6984b0d1a82c0000000000",
    "00000000004000000001000000584e45474f4558545305000000030000004000",
    "00004b000000a3924de89cf7c724b4aff63b22338bfe6985a2c0ac6600000000",
    "000000000000400000000b000000600906066985a2c0ac66004e45474f455854",
    "530600000004000000500000005c000000a3924de89cf7c724b4aff63b22338b",
    "fe6985a2c0ac6600000000000000000000140000000100000010000000500000",
    "000c00000000000000fc6a5ea0c440e998399ba894"
);

/// This crate's first token of the one-hop capture, which precedes MIT's reply.
const RUST_FIRST_ONE_HOP: &str = concat!(
    "608201d106062b0601050502a08201c5308201c1a00e300c060a2b0601040182",
    "3702021ea28201ad048201a94e45474f45585453000000000000000060000000",
    "8000000042424242424242424242424242424242424242424242424242424242",
    "4242424242424242424242424242424242424242000000000000000060000000",
    "0200600000000000000000006985a2c0ac66000000000000000000006984b0d1",
    "a82c000000000000000000004e45474f45585453020000000100000040000000",
    "41000000424242424242424242424242424242426985a2c0ac66000000000000",
    "000000004000000001000000584e45474f455854530200000002000000400000",
    "0041000000424242424242424242424242424242426984b0d1a82c0000000000",
    "00000000004000000001000000584e45474f4558545305000000030000004000",
    "00004b000000424242424242424242424242424242426985a2c0ac6600000000",
    "000000000000400000000b000000600906066985a2c0ac66004e45474f455854",
    "530600000004000000500000005c000000424242424242424242424242424242",
    "426985a2c0ac6600000000000000000000140000000100000010000000500000",
    "000c00000000000000fbac9d6d79feba89e828f05b"
);

/// MIT's reply, one hop: `NegTokenResp` with `ACCEPTOR_NEGO`, two `ACCEPTOR_META_DATA` and `VERIFY`.
const MIT_ACCEPTOR_REPLY_ONE_HOP: &str = concat!(
    "a182017d30820179a0030a0100a10c060a2b06010401823702021ea282016204",
    "82015e4e45474f45585453010000000500000060000000800000004242424242",
    "4242424242424242424242ae72340b8d8376f75e94790da797fcaea8f06f8ef1",
    "310cd2898af0f3af76b23a000000000000000060000000020060000000000000",
    "0000006985a2c0ac66000000000000000000006984b0d1a82c00000000000000",
    "0000004e45474f45585453030000000600000040000000410000004242424242",
    "42424242424242424242426985a2c0ac66000000000000000000004000000001",
    "000000584e45474f455854530300000007000000400000004100000042424242",
    "4242424242424242424242426984b0d1a82c0000000000000000000040000000",
    "01000000584e45474f455854530600000008000000500000005c000000424242",
    "424242424242424242424242426985a2c0ac6600000000000000000000140000",
    "000100000010000000500000000c000000000000002ec65c807d3a2bf63d7794",
    "6b"
);

/// This crate's first token of the two-hop capture.
const RUST_FIRST_TWO_HOPS: &str = concat!(
    "6082017506062b0601050502a082016930820165a00e300c060a2b0601040182",
    "3702021ea28201510482014d4e45474f45585453000000000000000060000000",
    "8000000042424242424242424242424242424242424242424242424242424242",
    "4242424242424242424242424242424242424242000000000000000060000000",
    "0200600000000000000000006985a2c0ac66000000000000000000006984b0d1",
    "a82c000000000000000000004e45474f45585453020000000100000040000000",
    "41000000424242424242424242424242424242426985a2c0ac66000000000000",
    "000000004000000001000000584e45474f455854530200000002000000400000",
    "0041000000424242424242424242424242424242426984b0d1a82c0000000000",
    "00000000004000000001000000584e45474f4558545305000000030000004000",
    "00004b000000424242424242424242424242424242426985a2c0ac6600000000",
    "000000000000400000000b000000600906066985a2c0ac6601"
);

/// MIT's reply, two hops: `ACCEPTOR_NEGO`, two `ACCEPTOR_META_DATA`, `CHALLENGE` and `VERIFY`.
const MIT_ACCEPTOR_REPLY_TWO_HOPS: &str = concat!(
    "a18201be308201baa0030a0101a10c060a2b06010401823702021ea28201a304",
    "82019f4e45474f45585453010000000400000060000000800000004242424242",
    "42424242424242424242429043427b6aee60fb98b1817d5b8b2440bb9450ef92",
    "012a07f04c721097bfafbb000000000000000060000000020060000000000000",
    "0000006985a2c0ac66000000000000000000006984b0d1a82c00000000000000",
    "0000004e45474f45585453030000000500000040000000410000004242424242",
    "42424242424242424242426985a2c0ac66000000000000000000004000000001",
    "000000584e45474f455854530300000006000000400000004100000042424242",
    "4242424242424242424242426984b0d1a82c0000000000000000000040000000",
    "01000000584e45474f4558545304000000070000004000000041000000424242",
    "424242424242424242424242426985a2c0ac6600000000000000000000400000",
    "0001000000004e45474f455854530600000008000000500000005c0000004242",
    "42424242424242424242424242426985a2c0ac66000000000000000000001400",
    "00000100000010000000500000000c000000000000000572cd67a0f2c85b8509",
    "1e54"
);

/// The `NEGOEX` messages carried by a captured SPNEGO token.
fn messages(conversation: &mut Conversation, captured: &str) -> Result<Vec<Message>, TestError> {
    let bytes = hex::decode(captured)?;
    let mech_token = if bytes.first() == Some(&0x60) {
        let Token::Init(init) = Token::decode(&bytes)? else {
            return Err("a NegTokenInit was expected".into());
        };
        init.mech_token().context("a mechanism token")?.to_vec()
    } else {
        NegTokenResp::decode(&bytes)?
            .response_token()
            .context("a response token")?
            .to_vec()
    };
    Ok(conversation.parse(&mech_token)?)
}

/// The message types of `parsed`.
fn types(parsed: &[Message]) -> Vec<MessageType> {
    parsed.iter().map(Message::message_type).collect()
}

/// MIT's first initiator token parses: the message types, the offered
/// schemes and the `VERIFY` checksum.
#[test]
fn mit_initiator_token_parses() -> Result<(), TestError> {
    let mut conversation = Conversation::accepting();
    let parsed = messages(&mut conversation, MIT_INITIATOR_ONE_HOP)?;
    assert_eq!(
        types(&parsed),
        [
            MessageType::InitiatorNego,
            MessageType::InitiatorMetaData,
            MessageType::InitiatorMetaData,
            MessageType::ApRequest,
            MessageType::Verify,
        ]
    );
    let Some(Message::Nego(nego)) = parsed.first() else {
        return Err("the first message is INITIATOR_NEGO".into());
    };
    let offered: Vec<[u8; 16]> = nego.schemes().iter().map(|s| *s.as_bytes()).collect();
    assert_eq!(
        offered,
        [
            [0x69, 0x85, 0xa2, 0xc0, 0xac, 0x66, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [0x69, 0x84, 0xb0, 0xd1, 0xa8, 0x2c, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ],
        "MIT offers its two negoextest schemes, in order"
    );
    let Some(Message::Verify(verify)) = parsed.get(4) else {
        return Err("the last message is VERIFY".into());
    };
    assert_eq!(verify.checksum_type(), 16, "the AES-256 SHA-1 checksum type");
    assert_eq!(verify.checksum().len(), 12);
    assert_eq!(conversation.next_sequence(), 5);
    Ok(())
}

/// MIT's one-hop reply parses in the transcript, after the first token.
#[test]
fn mit_acceptor_reply_parses_after_the_first_token() -> Result<(), TestError> {
    let mut conversation = Conversation::accepting();
    drop(messages(&mut conversation, RUST_FIRST_ONE_HOP)?);
    let reply = messages(&mut conversation, MIT_ACCEPTOR_REPLY_ONE_HOP)?;
    assert_eq!(
        types(&reply),
        [
            MessageType::AcceptorNego,
            MessageType::AcceptorMetaData,
            MessageType::AcceptorMetaData,
            MessageType::Verify,
        ]
    );
    assert_eq!(conversation.next_sequence(), 9);
    let Some(Message::Nego(nego)) = reply.first() else {
        return Err("the reply starts with ACCEPTOR_NEGO".into());
    };
    assert_eq!(nego.schemes().len(), 2);
    let scheme = |at: usize| -> Result<AuthScheme, TestError> {
        match reply.get(at) {
            Some(Message::Exchange(meta)) => Ok(meta.scheme()),
            _ => Err("an ACCEPTOR_META_DATA message".into()),
        }
    };
    assert_ne!(scheme(1)?, scheme(2)?, "one metadata message per scheme");
    Ok(())
}

/// MIT's two-hop reply carries a `CHALLENGE` before its `VERIFY`.
#[test]
fn mit_acceptor_reply_with_a_challenge_parses() -> Result<(), TestError> {
    let mut conversation = Conversation::accepting();
    drop(messages(&mut conversation, RUST_FIRST_TWO_HOPS)?);
    let reply = messages(&mut conversation, MIT_ACCEPTOR_REPLY_TWO_HOPS)?;
    assert_eq!(
        types(&reply),
        [
            MessageType::AcceptorNego,
            MessageType::AcceptorMetaData,
            MessageType::AcceptorMetaData,
            MessageType::Challenge,
            MessageType::Verify,
        ]
    );
    assert_eq!(conversation.next_sequence(), 9);
    Ok(())
}

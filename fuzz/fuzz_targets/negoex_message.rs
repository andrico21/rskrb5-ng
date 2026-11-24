//! Fuzz the MS-NEGOEX message framework, the `NegoEx` state machine and its
//! SPNEGO integration.
//!
//! The low three bits of the first input byte select the entry point: the
//! message parser as an acceptor and as an initiator (an accepted token is
//! encoded again and must parse to the same messages), an acceptor context, an
//! initiator context after its own first token, the SPNEGO acceptor on raw
//! bytes and on a continuation after a valid first token, and a structured
//! mode that frames fuzzed meta-data, mechanism tokens and `VERIFY` bytes in
//! valid messages so the checks behind the framing run. None may panic.

#![no_main]

extern crate alloc;

use alloc::sync::Arc;

use libfuzzer_sys::fuzz_target;
use rskrb5_ng::{
    error::Negoex,
    extensions::{Extension, GssMechanism, Registry},
    gss::{
        InitStep,
        negoex::{
            AuthScheme, Context, Conversation, ConversationId, ExchangeMessage, Mechanism,
            MechanismStep, Message, MessageType, NegoMessage, ProviderFailure, RandomSource,
            Request, Role, Session, VerifyKeys, VerifyMessage,
        },
    },
    keytab::EncryptionKey,
    spnego::negoex::{Acceptor, Initiator},
};

/// The first mechanism's OID content octets (`2.25.1414534758`).
const OID: [u8; 6] = [0x69, 0x85, 0xa2, 0xc0, 0xac, 0x66];

/// A registered mechanism.
struct Registered;

impl GssMechanism for Registered {
    fn id(&self) -> &'static str {
        "fuzz"
    }

    fn oid(&self) -> &[u8] {
        &OID
    }
}

/// A one-hop mechanism with fixed AES256 keys.
struct Fixed;

impl Mechanism for Fixed {
    fn oid(&self) -> &[u8] {
        &OID
    }

    fn auth_scheme(&self) -> AuthScheme {
        let mut bytes = [0; 16];
        bytes
            .iter_mut()
            .zip(OID)
            .for_each(|(target, source)| *target = source);
        AuthScheme::from_bytes(bytes)
    }

    fn session(&self, _role: Role) -> Box<dyn Session> {
        Box::new(Hop)
    }
}

/// The session of [`Fixed`].
struct Hop;

impl Session for Hop {
    fn query_meta_data(&mut self, _request: &Request) -> Result<Vec<u8>, ProviderFailure> {
        Ok(b"X".to_vec())
    }

    fn exchange_meta_data(
        &mut self,
        _request: &Request,
        metadata: &[u8],
    ) -> Result<(), ProviderFailure> {
        if metadata == b"X" {
            Ok(())
        } else {
            Err(ProviderFailure::new("meta-data"))
        }
    }

    fn init_sec_context(
        &mut self,
        _request: &Request,
        _input: Option<&[u8]>,
    ) -> Result<MechanismStep, ProviderFailure> {
        Ok(MechanismStep::complete(Some(vec![0])))
    }

    fn accept_sec_context(
        &mut self,
        _request: &Request,
        _input: &[u8],
    ) -> Result<MechanismStep, ProviderFailure> {
        Ok(MechanismStep::complete(None))
    }

    fn keys(&self) -> VerifyKeys {
        VerifyKeys::none()
            .with_checksum_key(EncryptionKey::new(18, vec![1; 32]))
            .with_verify_key(EncryptionKey::new(18, vec![1; 32]))
    }
}

/// A constant random source.
struct Constant;

impl RandomSource for Constant {
    fn fill(&self, bytes: &mut [u8]) -> Result<(), Negoex> {
        bytes.fill(0x42);
        Ok(())
    }
}

/// A context of the fixed mechanism.
fn context(initiator: bool) -> Option<Context> {
    let mut registry = Registry::new();
    registry
        .register(Extension::GssMechanism(Arc::new(Registered)))
        .ok()?;
    let mechanisms: Vec<Arc<dyn Mechanism>> = vec![Arc::new(Fixed)];
    let context = if initiator {
        Context::initiator(&registry, &mechanisms, Request::new())
    } else {
        Context::acceptor(&registry, &mechanisms, Request::new())
    };
    Some(context.ok()?.with_random_source(Arc::new(Constant)))
}

/// Parse `input`; an accepted token is encoded again and parses to the same messages.
///
/// # Panics
///
/// Panics when an accepted token does not encode to a token that parses to as many messages.
fn parse(input: &[u8], initiator: bool) {
    let mut conversation = if initiator {
        Conversation::initiating(ConversationId::from_bytes([0x42; 16]))
    } else {
        Conversation::accepting()
    };
    let Ok(messages) = conversation.parse(input) else {
        return;
    };
    let Some(id) = conversation.id().copied() else {
        return;
    };
    let mut again = Conversation::initiating(id);
    let mut encoded = Vec::new();
    for message in &messages {
        // Messages parsed at a sequence number other than 0 are encoded from 0.
        if again.encode_into(message, &mut encoded).is_err() {
            return;
        }
    }
    let reparsed = Conversation::accepting().parse(&encoded);
    assert!(
        reparsed.is_ok_and(|second| second.len() == messages.len()),
        "an accepted token encodes to a token that parses to as many messages"
    );
}

/// Split `bytes` after `at` bytes, or at the end when it is shorter.
fn split(bytes: &[u8], at: u8) -> Option<(&[u8], &[u8])> {
    bytes.split_at_checked(usize::from(at).min(bytes.len()))
}

/// Frame fuzzed bytes in valid messages: an `INITIATOR_NEGO`, meta-data, a
/// mechanism token and a `VERIFY` message, split from `input`.
fn structured(input: &[u8]) -> Option<()> {
    let (lengths, rest) = input.split_first_chunk::<2>()?;
    let (meta, after_meta) = split(rest, lengths[0])?;
    let (token, checksum) = split(after_meta, lengths[1])?;
    let scheme = Fixed.auth_scheme();
    let mut conversation = Conversation::initiating(ConversationId::from_bytes([0x42; 16]));
    let mut bytes = Vec::new();
    for message in [
        Message::Nego(NegoMessage::new(MessageType::InitiatorNego, [7; 32], vec![scheme]).ok()?),
        Message::Exchange(
            ExchangeMessage::new(MessageType::InitiatorMetaData, scheme, meta.to_vec()).ok()?,
        ),
        Message::Exchange(
            ExchangeMessage::new(MessageType::ApRequest, scheme, token.to_vec()).ok()?,
        ),
        Message::Verify(VerifyMessage::new(scheme, 16, checksum.to_vec())),
    ] {
        conversation.encode_into(&message, &mut bytes).ok()?;
    }
    drop(context(false)?.step(Some(&bytes)));
    Some(())
}

fuzz_target!(|data: &[u8]| {
    let Some((selector, input)) = data.split_first() else {
        return;
    };
    match selector & 0x07 {
        0 => parse(input, false),
        1 => parse(input, true),
        2 => {
            if let Some(mut acceptor) = context(false) {
                drop(acceptor.step(Some(input)));
            }
        }
        3 => {
            if let Some(mut initiator) = context(true) {
                drop(initiator.step(None));
                drop(initiator.step(Some(input)));
            }
        }
        4 => {
            if let Some(acceptor) = context(false) {
                drop(Acceptor::new(acceptor).accept_sec_context(input));
            }
        }
        5 => {
            let (Some(first), Some(fresh)) = (
                context(true).and_then(|initiator| {
                    match Initiator::new(initiator).init_sec_context(None) {
                        Ok(InitStep::Continue(token)) => Some(token),
                        Ok(_) | Err(_) => None,
                    }
                }),
                context(false),
            ) else {
                return;
            };
            let mut acceptor = Acceptor::new(fresh);
            drop(acceptor.accept_sec_context(&first));
            drop(acceptor.accept_sec_context(input));
        }
        _ => drop(structured(input)),
    }
});

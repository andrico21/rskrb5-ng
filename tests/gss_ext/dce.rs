//! DCE-style establishment.
//!
//! `GSS_C_DCE_STYLE` (MS-KILE section 3.4.5.1, MIT 1.22.2
//! `init_sec_context.c:420-430,757-835`, `accept_sec_context.c:283-360,
//! 770-860,933-1080`, `mk_rep.c:69-160`, `rd_rep.c:148-200`): the initiator
//! sends a raw AP-REQ, the acceptor answers with a raw AP-REP that always
//! carries an acceptor subkey and is not yet established, the initiator answers
//! with its own AP-REP (no subkey, the acceptor's sequence number) and the
//! acceptor completes on it. Wrap tokens of a DCE context carry the filler in
//! EC and an RRC that leaves out the filler (`k5sealv3iov.c:110-140`).

use rskrb5_ng::{
    crypto::CryptoPolicy,
    error::Gss,
    gss::{
        Acceptor, AcceptorOptions, ContextFlags, InitStep, Initiator, InitiatorOptions, IovBuffer,
        IovKind, PrfKey,
    },
    service::Validator,
};

use super::{
    context::{Context as _, TestError},
    support::{AES256_SHA1, AES256_SHA384, credential, establish_with, keytab, sequenced, target},
};

/// The krb5 mechanism OID as it appears in a framed token.
const KRB5_OID: [u8; 11] = [
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02,
];

/// The DCE-style flags.
fn dce() -> ContextFlags {
    sequenced() | ContextFlags::DCE_STYLE
}

/// The RFC 2743 framing of a krb5 AP-REQ `body`.
fn framed(body: &[u8]) -> Vec<u8> {
    let inner = [&KRB5_OID[..], &[0x01, 0x00], body].concat();
    let length = inner.len();
    let mut token = vec![0x60];
    if length < 0x80 {
        token.push(u8::try_from(length).unwrap_or(0));
    } else {
        token.extend_from_slice(&[
            0x82,
            u8::try_from(length >> 8).unwrap_or(0),
            u8::try_from(length & 0xff).unwrap_or(0),
        ]);
    }
    token.extend_from_slice(&inner);
    token
}

/// The AP-REQ inside a framed krb5 token.
fn unframed(token: &[u8]) -> Option<Vec<u8>> {
    let at = token
        .windows(KRB5_OID.len())
        .position(|window| window == KRB5_OID)?;
    token.get(at + KRB5_OID.len() + 2..).map(<[u8]>::to_vec)
}

/// The three legs run, with raw tokens, and both ends end mutually
/// authenticated, DCE-style, with the acceptor subkey and working tokens.
#[test]
fn dce_contexts_take_three_raw_legs() -> Result<(), TestError> {
    let credential = credential(AES256_SHA1)?;
    let mut init = Initiator::new(target()?, InitiatorOptions::new().with_flags(dce()));
    let keys = keytab();
    let mut accept = Acceptor::from_validator(Validator::new(&keys), AcceptorOptions::new());
    // Leg 1: a raw AP-REQ, not an RFC 2743 framed token.
    let InitStep::Continue(first) = init.init_sec_context(&credential, None)? else {
        return Err("the DCE initiator waits for the AP-REP".into());
    };
    assert_eq!(first.first(), Some(&0x6e));
    // Leg 2: a raw AP-REP; the acceptor's context is not yet open.
    let mut accepted = accept.accept_sec_context(&first)?;
    let reply = accepted.output_token().context("an AP-REP")?.to_vec();
    assert_eq!(reply.first(), Some(&0x6f));
    assert!(!accepted.is_established());
    assert!(!accepted.context().inquire().open());
    // Leg 3: the initiator's own raw AP-REP completes both ends.
    let InitStep::Complete(Some(third)) = init.init_sec_context(&credential, Some(&reply))? else {
        return Err("the DCE initiator answers the AP-REP".into());
    };
    assert_eq!(third.first(), Some(&0x6f));
    accepted.complete_dce(&third)?;
    assert!(accepted.is_established());
    let mut acceptor = accepted.into_context();
    let mut initiator = init.into_established()?;
    for end in [&initiator, &acceptor] {
        let flags = end.inquire().flags();
        assert!(flags.contains(ContextFlags::DCE_STYLE | ContextFlags::MUTUAL));
        assert!(!flags.contains(ContextFlags::DELEG));
        assert!(end.inquire().open());
    }
    // Both ends use the acceptor subkey.
    assert_eq!(
        initiator.session_key().value(),
        acceptor.session_key().value()
    );
    assert_eq!(
        initiator
            .pseudo_random(PrfKey::Full, b"dce", 40)?
            .as_slice(),
        acceptor.pseudo_random(PrfKey::Full, b"dce", 40)?.as_slice()
    );
    let mic = initiator.get_mic(b"after three legs")?;
    acceptor.verify_mic(b"after three legs", &mic)?;
    Ok(())
}

/// Before the third leg the acceptor's context protects nothing, and a second
/// call to complete it is out of order.
#[test]
fn an_unfinished_dce_acceptor_protects_nothing() -> Result<(), TestError> {
    let credential = credential(AES256_SHA1)?;
    let mut init = Initiator::new(target()?, InitiatorOptions::new().with_flags(dce()));
    let keys = keytab();
    let mut accept = Acceptor::from_validator(Validator::new(&keys), AcceptorOptions::new());
    let InitStep::Continue(first) = init.init_sec_context(&credential, None)? else {
        return Err("a DCE initiator waits".into());
    };
    let mut accepted = accept.accept_sec_context(&first)?;
    let mut context = accepted.into_context();
    assert!(matches!(
        context.wrap(b"early", true),
        Err(Gss::UnexpectedStep(_))
    ));
    assert!(matches!(
        context.get_mic(b"early"),
        Err(Gss::UnexpectedStep(_))
    ));
    assert!(context.pseudo_random(PrfKey::Full, b"early", 8).is_err());
    // A normal context cannot be completed again.
    let mut pair_accept = Acceptor::from_validator(Validator::new(&keys), AcceptorOptions::new());
    let mut plain = Initiator::new(target()?, InitiatorOptions::new());
    let InitStep::Continue(token) = plain.init_sec_context(&credential, None)? else {
        return Err("a mutual initiator waits".into());
    };
    accepted = pair_accept.accept_sec_context(&token)?;
    assert!(accepted.is_established());
    assert!(matches!(
        accepted.complete_dce(&token),
        Err(Gss::UnexpectedStep(_))
    ));
    Ok(())
}

/// A third leg that is not the initiator's DCE AP-REP is refused: garbage, the
/// acceptor's own AP-REP echoed back (it carries a subkey) and a token of
/// another context.
#[test]
fn a_wrong_third_leg_is_refused() -> Result<(), TestError> {
    let credential = credential(AES256_SHA1)?;
    let keys = keytab();
    let run = |third: &dyn Fn(&[u8], &[u8]) -> Vec<u8>| -> Result<bool, TestError> {
        let mut init = Initiator::new(target()?, InitiatorOptions::new().with_flags(dce()));
        let mut accept = Acceptor::from_validator(Validator::new(&keys), AcceptorOptions::new());
        let InitStep::Continue(first) = init.init_sec_context(&credential, None)? else {
            return Err("a DCE initiator waits".into());
        };
        let mut accepted = accept.accept_sec_context(&first)?;
        let reply = accepted.output_token().context("an AP-REP")?.to_vec();
        let InitStep::Complete(Some(genuine)) = init.init_sec_context(&credential, Some(&reply))?
        else {
            return Err("a DCE initiator answers".into());
        };
        Ok(accepted.complete_dce(&third(&reply, &genuine)).is_ok())
    };
    assert!(run(&|_, genuine| genuine.to_vec())?);
    assert!(!run(&|_, _| b"not an AP-REP".to_vec())?);
    assert!(!run(&|reply, _| reply.to_vec())?);
    assert!(!run(&|_, genuine| {
        let mut bytes = genuine.to_vec();
        if let Some(last) = bytes.last_mut() {
            *last ^= 1;
        }
        bytes
    })?);
    Ok(())
}

/// Only a DCE-style initiator may send a raw AP-REQ, and a DCE-style AP-REQ
/// must be raw (`accept_sec_context.c:855-860`).
#[test]
fn raw_and_framed_tokens_must_match_the_dce_flag() -> Result<(), TestError> {
    let credential = credential(AES256_SHA1)?;
    let keys = keytab();
    let mut plain = Initiator::new(target()?, InitiatorOptions::new());
    let InitStep::Continue(token) = plain.init_sec_context(&credential, None)? else {
        return Err("a mutual initiator waits".into());
    };
    let raw = unframed(&token).context("the AP-REQ inside the token")?;
    let mut accept = Acceptor::from_validator(Validator::new(&keys), AcceptorOptions::new());
    assert!(accept.accept_sec_context(&raw).is_err());
    let mut dce_init = Initiator::new(target()?, InitiatorOptions::new().with_flags(dce()));
    let InitStep::Continue(first) = dce_init.init_sec_context(&credential, None)? else {
        return Err("a DCE initiator waits".into());
    };
    let mut accept = Acceptor::from_validator(Validator::new(&keys), AcceptorOptions::new());
    assert!(accept.accept_sec_context(&framed(&first)).is_err());
    Ok(())
}

/// DCE wrap tokens: the filler is one cipher block in EC and the RRC leaves
/// it out, the header rotated by the whole trailer (the Windows rule MIT
/// copies); a non-DCE context unwraps no such token.
#[test]
fn dce_iov_tokens_follow_the_rrc_rule() -> Result<(), TestError> {
    for etype in [AES256_SHA1, AES256_SHA384] {
        let mut ends = establish_with(etype, dce(), &CryptoPolicy::default())?;
        let mut buffers = vec![
            IovBuffer::empty(IovKind::Header),
            IovBuffer::new(IovKind::SignOnly, b"rpc header".to_vec()),
            IovBuffer::new(IovKind::Data, b"stub data!".to_vec()),
        ];
        ends.initiator.wrap_iov(&mut buffers, true)?;
        let header = buffers.first().context("a header")?.value().to_vec();
        let field = |at: usize| {
            header
                .get(at..at + 2)
                .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
                .map(u16::from_be_bytes)
        };
        let ec = field(4).context("EC")?;
        let rrc = field(6).context("RRC")?;
        assert_eq!(ec, 16);
        let trailer = header.len() - 16 - 16;
        assert_eq!(usize::from(rrc), trailer - usize::from(ec));
        ends.acceptor.unwrap_iov(&mut buffers)?;
        assert_eq!(
            buffers.get(2).context("data")?.value(),
            b"stub data!".as_slice()
        );
        // A DCE context refuses STREAM unwrapping (`k5unsealiov.c:381`).
        let token = ends.initiator.wrap(b"x", true)?;
        let mut stream = vec![
            IovBuffer::new(IovKind::Stream, token),
            IovBuffer::empty(IovKind::Data),
        ];
        assert!(ends.acceptor.unwrap_iov(&mut stream).is_err());
    }
    Ok(())
}

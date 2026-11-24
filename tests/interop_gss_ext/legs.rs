//! Multi-leg scenarios with MIT.
//!
//! DCE-style establishment with MIT as either end, context transfer in the
//! middle of a conversation with MIT, and delegation from Rust to MIT and on
//! from MIT back to Rust (register row FU-GSS-P04).

use core::error::Error;

use rskrb5_ng::{
    error::Gss,
    gss::{
        self, AcceptorOptions, ContextFlags, EstablishedContext, InitStep, InitiatorOptions,
        MemoryTransferLedger, TransferKey,
    },
};

use super::{
    Pair, iov_both_ways, prf_matches,
    support::{
        DCE, DELEG, MIT_KDC, PEER, STANDARD_FLAGS, accept_keeping_delegation, acceptor_cred,
        assert_krb5, config, connect, flagged, initiator_cred, messages, mit_init, mit_initiated,
        mit_target, password_credential, runtime, rust_acceptor, rust_initiated, user,
    },
};
use crate::{harness, peer::types::AcceptRequest};

/// A raw (unframed) AP-REQ starts with its `[APPLICATION 14]` tag.
const RAW_AP_REQ: u8 = 0x6e;

/// A Rust DCE-style initiator against MIT's acceptor: three raw legs.
fn rust_dce_initiator() -> Result<Pair, Box<dyn Error>> {
    let credential = password_credential(&mit_target()?, &config("")?)?;
    let mut initiator = gss::Initiator::new(mit_target()?, flagged(ContextFlags::DCE_STYLE));
    let InitStep::Continue(first) = initiator.init_sec_context(&credential, None)? else {
        return Err("the DCE initiator waits for the AP-REP".into());
    };
    assert_eq!(first.first(), Some(&RAW_AP_REQ), "leg 1 is a raw AP-REQ");
    let mut adapter = connect()?;
    let request = AcceptRequest::new(&first).with_cred(acceptor_cred(&mut adapter)?);
    let second = adapter.accept_step(&request)?;
    assert!(second.continue_needed(), "MIT waits for the third leg");
    let InitStep::Complete(Some(third)) =
        initiator.init_sec_context(&credential, Some(second.token()))?
    else {
        return Err("the DCE initiator answers MIT's AP-REP".into());
    };
    let last = adapter.accept_step(&request.stepping(Some(second.context()), &third))?;
    assert!(!last.continue_needed(), "the third leg completes MIT");
    assert_krb5(last.mech())?;
    assert_ne!(last.flags() & DCE, 0, "MIT reports a DCE-style context");
    assert_eq!(last.source(), user()?, "MIT sees the Rust initiator");
    Ok(Pair {
        context: initiator.into_established()?,
        adapter,
        handle: last.context(),
    })
}

/// An MIT DCE-style initiator against the Rust acceptor: three raw legs.
fn mit_dce_initiator() -> Result<Pair, Box<dyn Error>> {
    let mut adapter = connect()?;
    let init = mit_init(STANDARD_FLAGS | DCE)?.with_cred(initiator_cred(&mut adapter)?);
    let first = adapter.init_step(&init)?;
    assert!(first.continue_needed(), "MIT waits for the AP-REP");
    assert_eq!(
        first.token().first(),
        Some(&RAW_AP_REQ),
        "leg 1 is a raw AP-REQ"
    );
    let store = rust_acceptor()?;
    let mut acceptor = gss::Acceptor::new(&store, AcceptorOptions::new())?;
    let mut accepted = acceptor.accept_sec_context(first.token())?;
    assert!(
        !accepted.is_established(),
        "the Rust acceptor waits for leg 3"
    );
    let reply = accepted.output_token().ok_or("an AP-REP")?.to_vec();
    let last = adapter.init_step(&init.continuing(first.context(), &reply))?;
    assert!(!last.continue_needed(), "MIT completes on the AP-REP");
    assert_krb5(last.mech())?;
    accepted.complete_dce(last.token())?;
    assert!(
        accepted.is_established(),
        "the third leg opens the Rust context"
    );
    Ok(Pair {
        context: accepted.into_context(),
        adapter,
        handle: last.context(),
    })
}

/// DCE-style contexts establish in three raw legs with MIT as acceptor and as
/// initiator; wrap, MIC, IOV tokens and the PRF then agree with MIT.
#[test]
fn dce_style_contexts_establish_between_rust_and_mit_both_ways() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "dce_style_contexts_establish_between_rust_and_mit_both_ways",
        &[MIT_KDC, PEER],
    )? {
        return Ok(());
    }
    for mut pair in [rust_dce_initiator()?, mit_dce_initiator()?] {
        assert!(
            pair.context
                .inquire()
                .flags()
                .contains(ContextFlags::DCE_STYLE),
            "a DCE-style context"
        );
        messages(&mut pair, "dce")?;
        iov_both_ways(&mut pair)?;
        prf_matches(&mut pair)?;
    }
    Ok(())
}

/// Transferred contexts continue the conversation with MIT.
///
/// A Rust context exported in mid-conversation and imported continues with
/// MIT (sequence numbers, keys and PRF intact); its second import through the
/// same ledger is refused; MIT's own exported context continues with Rust.
#[test]
fn transferred_contexts_continue_the_conversation_with_mit() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "transferred_contexts_continue_the_conversation_with_mit",
        &[MIT_KDC, PEER],
    )? {
        return Ok(());
    }
    for mut pair in [rust_initiated()?, mit_initiated()?] {
        messages(&mut pair, "before the transfer")?;
        let key = TransferKey::generate()?;
        let mut ledger = MemoryTransferLedger::new();
        let blob = pair.context.export(&key)?;
        let context = EstablishedContext::import(&blob, &key, &mut ledger)?;
        assert!(
            matches!(
                EstablishedContext::import(&blob, &key, &mut ledger),
                Err(Gss::TransferReplayed)
            ),
            "the ledger refuses a second import"
        );
        let mut moved = Pair {
            context,
            adapter: pair.adapter,
            handle: pair.handle,
        };
        messages(&mut moved, "after the Rust transfer")?;
        prf_matches(&mut moved)?;
        let token = moved.adapter.export_context(moved.handle)?;
        moved.handle = moved.adapter.import_context(&token)?;
        messages(&mut moved, "after the MIT transfer")?;
    }
    Ok(())
}

/// Delegation crosses from Rust to MIT and from MIT back to Rust.
///
/// A Rust initiator delegates its forwardable TGT to MIT's acceptor; MIT uses
/// the delegated credential to initiate, delegating again, to the Rust
/// acceptor, which uses what it received to reach MIT as the original user.
#[test]
fn delegation_crosses_between_rust_and_mit_both_ways() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "delegation_crosses_between_rust_and_mit_both_ways",
        &[MIT_KDC, PEER],
    )? {
        return Ok(());
    }
    let config = config(" forwardable = true\n")?;
    // Rust to MIT.
    let credential = password_credential(&mit_target()?, &config)?;
    let mut initiator = gss::Initiator::new(mit_target()?, flagged(ContextFlags::from_bits(DELEG)));
    let InitStep::Continue(token) = initiator.init_sec_context(&credential, None)? else {
        return Err("mutual authentication waits".into());
    };
    let mut adapter = connect()?;
    let cred = acceptor_cred(&mut adapter)?;
    let accepted = accept_keeping_delegation(&mut adapter, cred, &token)?;
    assert_krb5(&accepted.mech)?;
    assert_eq!(accepted.source, user()?, "MIT sees the Rust user");
    assert_ne!(accepted.flags & DELEG, 0, "MIT reports the delegation");
    let delegated = accepted
        .delegated
        .ok_or("MIT holds the credential Rust delegated")?;
    let InitStep::Complete(None) =
        initiator.init_sec_context(&credential, Some(&accepted.token))?
    else {
        return Err("the MIT AP-REP completes the Rust initiator".into());
    };
    // MIT to Rust, with the credential Rust delegated.
    let init = mit_init(STANDARD_FLAGS | DELEG)?.with_cred(delegated);
    let first = adapter.init_step(&init)?;
    let store = rust_acceptor()?;
    let mut acceptor = gss::Acceptor::new(&store, AcceptorOptions::new())?;
    let accepted_by_rust = acceptor.accept_sec_context(first.token())?;
    let reply = accepted_by_rust.output_token().ok_or("an AP-REP")?.to_vec();
    let mut context = accepted_by_rust.into_context();
    let info = context.inquire();
    assert_eq!(
        info.source().display().0,
        user()?,
        "MIT initiated as the Rust user"
    );
    assert!(info.flags().contains(ContextFlags::DELEG), "MIT delegated");
    let last = adapter.init_step(&init.continuing(first.context(), &reply))?;
    assert!(!last.continue_needed(), "the Rust AP-REP completes MIT");
    assert_krb5(last.mech())?;
    // The TGT MIT forwarded serves the Rust side against MIT's acceptor.
    let mut forwarded = context
        .take_delegated_credential()
        .ok_or("the Rust acceptor holds the TGT MIT delegated")?;
    assert_eq!(
        forwarded.inquire().name().ok_or("a name")?.display().0,
        user()?
    );
    runtime()?.block_on(forwarded.acquire_service_ticket(&mit_target()?, &config))?;
    let mut again = gss::Initiator::new(mit_target()?, InitiatorOptions::new());
    let InitStep::Continue(token_again) = again.init_sec_context(&forwarded, None)? else {
        return Err("mutual authentication waits".into());
    };
    let mut second = connect()?;
    let request = AcceptRequest::new(&token_again).with_cred(acceptor_cred(&mut second)?);
    let step = second.accept_step(&request)?;
    assert_eq!(
        step.source(),
        user()?,
        "MIT sees the user behind the forwarded TGT"
    );
    assert_krb5(step.mech())?;
    Ok(())
}

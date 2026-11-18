//! Framing limits, krb5, SPNEGO and DCE-style contexts, channel bindings and
//! context export between two adapter peers (MIT on both ends).

use core::error::Error;
use std::net::Shutdown;

use super::{
    CONF, DCE_STYLE, INTEG, KRB5, MUTUAL, PEER, SPNEGO, STANDARD_FLAGS, acceptor_cred,
    assert_mechanism, connect_main, establish, harness, initiator_cred, is_spnego_token, messages,
    service_name, service_principal, user_principal,
};
use crate::peer::{
    frame::{Fields, STATUS_PROTOCOL},
    reply::Protection,
    types::{AcceptRequest, InitRequest, PeerError},
};

/// The text of a status-3 reply.
///
/// # Errors
///
/// Returns an error when the reply is not a status-3 reply carrying text.
fn refusal(reply: (u8, Vec<u8>)) -> Result<String, Box<dyn Error>> {
    let (status, body) = reply;
    if status != STATUS_PROTOCOL {
        return Err(format!("expected the protocol-error status 3, got {status}").into());
    }
    Ok(Fields::split(&body)?.text()?)
}

/// The adapter refuses a frame above 1 MiB, an empty frame, a truncated frame, an
/// unknown command and too many fields, naming the reason, and keeps serving.
#[test]
fn adapter_enforces_its_frame_limits() -> Result<(), Box<dyn Error>> {
    if !harness::require("adapter_enforces_its_frame_limits", &[PEER])? {
        return Ok(());
    }
    let ping = connect_main()?.ping()?;
    assert_eq!(
        (ping.version(), ping.limits()),
        ("rskrb5-peer/1", (0x10_0000, 16, 16)),
        "the adapter advertises the documented limits"
    );
    let mut oversize = connect_main()?;
    assert!(
        refusal(oversize.exchange_raw(&[0, 0x10, 0, 1])?)?.contains("frame too large"),
        "1 MiB + 1 is refused by its length alone"
    );
    assert!(
        matches!(oversize.read_raw(), Err(PeerError::Io(_))),
        "the adapter closes after an oversize frame"
    );
    assert!(
        refusal(connect_main()?.exchange_raw(&[0xff; 4])?)?.contains("frame too large"),
        "4 GiB - 1 is refused by its length alone"
    );
    assert!(
        refusal(connect_main()?.exchange_raw(&[0; 4])?)?.contains("empty frame"),
        "a zero-length frame is refused"
    );
    let mut truncated = connect_main()?;
    truncated.send_raw(&[0, 0, 0, 16, 1, 2, 3, 4])?;
    truncated.stream().shutdown(Shutdown::Write)?;
    assert!(
        refusal(truncated.read_raw()?)?.contains("truncated frame"),
        "a stream that ends inside a frame is refused"
    );
    assert!(
        refusal(connect_main()?.exchange_raw(&[0, 0, 0, 1, b'Z'])?)?.contains("unknown command"),
        "an unknown command byte"
    );
    let mut crowded = vec![0, 0, 0, 69, b'P'];
    crowded.extend_from_slice(&[0; 68]);
    assert!(
        refusal(connect_main()?.exchange_raw(&crowded)?)?.contains("malformed fields"),
        "17 fields exceed the limit of 16"
    );
    assert_eq!(
        connect_main()?.ping()?.version(),
        "rskrb5-peer/1",
        "the adapter still serves after every malformed frame"
    );
    Ok(())
}

/// An MIT krb5 initiator and acceptor establish a context (one AP-REQ, one
/// AP-REP), the mechanism is krb5, the acceptor sees the initiator, and every
/// message operation works in both directions.
#[test]
fn krb5_contexts_between_adapter_peers_support_every_message_operation()
-> Result<(), Box<dyn Error>> {
    if !harness::require(
        "krb5_contexts_between_adapter_peers_support_every_message_operation",
        &[PEER],
    )? {
        return Ok(());
    }
    let (mut initiator, mut acceptor) = (connect_main()?, connect_main()?);
    let init = InitRequest::new(service_name()?)
        .with_cred(initiator_cred(&mut initiator, &[KRB5])?)
        .with_mech(KRB5)
        .with_flags(STANDARD_FLAGS);
    let accept = AcceptRequest::new(b"").with_cred(acceptor_cred(&mut acceptor, &[KRB5])?);
    let pair = establish(&mut initiator, &mut acceptor, &init, &accept)?;
    assert_mechanism(KRB5, pair.init.mech())?;
    assert_mechanism(KRB5, pair.accept.mech())?;
    assert_eq!(
        pair.accept_steps, 1,
        "krb5 with mutual authentication needs one accept step"
    );
    assert_eq!(
        pair.accept.source(),
        user_principal()?,
        "the acceptor sees the initiator"
    );
    for flags in [pair.init.flags(), pair.accept.flags()] {
        assert_eq!(
            flags & (MUTUAL | CONF | INTEG),
            MUTUAL | CONF | INTEG,
            "mutual, confidentiality and integrity were granted"
        );
    }
    let info = initiator.inquire(pair.init_ctx)?;
    assert_eq!(
        (info.source(), info.target(), info.initiated(), info.open()),
        (
            user_principal()?.as_str(),
            service_principal()?.as_str(),
            true,
            true
        ),
        "the initiator's context names both principals"
    );
    messages::exercise(&mut initiator, &mut acceptor, &pair, true)
}

/// SPNEGO between adapter peers negotiates the krb5 mechanism underneath (the first
/// token is a SPNEGO token, both ends report krb5), and the message operations
/// work through the SPNEGO context.
#[test]
fn spnego_contexts_between_adapter_peers_negotiate_krb5() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "spnego_contexts_between_adapter_peers_negotiate_krb5",
        &[PEER],
    )? {
        return Ok(());
    }
    let (mut initiator, mut acceptor) = (connect_main()?, connect_main()?);
    let init = InitRequest::new(service_name()?)
        .with_cred(initiator_cred(&mut initiator, &[SPNEGO])?)
        .with_mech(SPNEGO)
        .with_flags(STANDARD_FLAGS);
    let accept = AcceptRequest::new(b"").with_cred(acceptor_cred(&mut acceptor, &[SPNEGO])?);
    let pair = establish(&mut initiator, &mut acceptor, &init, &accept)?;
    assert!(
        is_spnego_token(&pair.first_token),
        "the first token is a SPNEGO token"
    );
    assert_mechanism(KRB5, pair.init.mech())?;
    assert_mechanism(KRB5, pair.accept.mech())?;
    assert_eq!(
        pair.accept.source(),
        user_principal()?,
        "the acceptor sees the initiator"
    );
    assert_mechanism(KRB5, initiator.inquire(pair.init_ctx)?.mech())?;
    assert_mechanism(KRB5, acceptor.inquire(pair.accept_ctx)?.mech())?;
    messages::exercise(&mut initiator, &mut acceptor, &pair, true)
}

/// `GSS_C_DCE_STYLE` makes the exchange three-legged: the initiator completes
/// with a final token that the acceptor must process.
#[test]
fn dce_style_context_needs_a_third_leg() -> Result<(), Box<dyn Error>> {
    if !harness::require("dce_style_context_needs_a_third_leg", &[PEER])? {
        return Ok(());
    }
    let (mut initiator, mut acceptor) = (connect_main()?, connect_main()?);
    let init = InitRequest::new(service_name()?)
        .with_cred(initiator_cred(&mut initiator, &[KRB5])?)
        .with_mech(KRB5)
        .with_flags(STANDARD_FLAGS | DCE_STYLE);
    let accept = AcceptRequest::new(b"").with_cred(acceptor_cred(&mut acceptor, &[KRB5])?);
    let pair = establish(&mut initiator, &mut acceptor, &init, &accept)?;
    assert_mechanism(KRB5, pair.accept.mech())?;
    assert_eq!(
        pair.accept_steps, 2,
        "DCE style needs a second accept step for the third leg"
    );
    assert!(
        !pair.init.token().is_empty(),
        "the initiator's last step produced the third-leg token"
    );
    messages::exercise(&mut initiator, &mut acceptor, &pair, false)
}

/// Channel bindings (an application-data blob) that match are accepted; ones that
/// differ are refused by the acceptor with `GSS_S_BAD_BINDINGS`.
#[test]
fn channel_bindings_must_match_between_adapter_peers() -> Result<(), Box<dyn Error>> {
    if !harness::require("channel_bindings_must_match_between_adapter_peers", &[PEER])? {
        return Ok(());
    }
    let blob = b"tls-server-end-point:0a0b0c0d";
    let (mut initiator, mut acceptor) = (connect_main()?, connect_main()?);
    let init = InitRequest::new(service_name()?)
        .with_cred(initiator_cred(&mut initiator, &[KRB5])?)
        .with_mech(KRB5)
        .with_flags(STANDARD_FLAGS)
        .with_bindings(blob);
    let accept = AcceptRequest::new(b"").with_cred(acceptor_cred(&mut acceptor, &[KRB5])?);
    let matching = establish(
        &mut initiator,
        &mut acceptor,
        &init,
        &accept.clone().with_bindings(blob),
    )?;
    assert_mechanism(KRB5, matching.accept.mech())?;

    let mismatch = establish(
        &mut initiator,
        &mut acceptor,
        &init,
        &accept.with_bindings(b"tls-server-end-point:ffffffff"),
    )
    .err()
    .ok_or("different channel bindings must not complete")?;
    assert!(
        matches!(
            mismatch.downcast_ref::<PeerError>(),
            Some(PeerError::Gss { major, minor: _, text: _ }) if major & 0x00ff_0000 == 0x0004_0000
        ),
        "the acceptor refuses with GSS_S_BAD_BINDINGS, got: {mismatch}"
    );
    Ok(())
}

/// An established acceptor context exports and imports within MIT (into another
/// adapter connection) and keeps working; the exported handle is consumed.
#[test]
fn exported_context_imports_and_keeps_working() -> Result<(), Box<dyn Error>> {
    if !harness::require("exported_context_imports_and_keeps_working", &[PEER])? {
        return Ok(());
    }
    let (mut initiator, mut acceptor, mut second) =
        (connect_main()?, connect_main()?, connect_main()?);
    let init = InitRequest::new(service_name()?)
        .with_cred(initiator_cred(&mut initiator, &[KRB5])?)
        .with_mech(KRB5)
        .with_flags(STANDARD_FLAGS);
    let accept = AcceptRequest::new(b"").with_cred(acceptor_cred(&mut acceptor, &[KRB5])?);
    let pair = establish(&mut initiator, &mut acceptor, &init, &accept)?;
    let token = acceptor.export_context(pair.accept_ctx)?;
    let imported = second.import_context(&token)?;
    let sealed = initiator.wrap(pair.init_ctx, Protection::new(true), b"after the export")?;
    assert_eq!(
        second.unwrap(imported, sealed.token())?.message(),
        b"after the export",
        "the imported context unwraps the initiator's token"
    );
    assert!(
        acceptor.inquire(pair.accept_ctx).is_err(),
        "the exported handle is consumed"
    );
    Ok(())
}

//! The krb5 mechanism and IAKERB share one AP exchange.
//!
//! MIT 1.22.2 passes IAKERB's transcript to the krb5 acceptor in an extension
//! record (`krb5_gss_ctx_ext_rec`, `gssapiP_krb5.h:199-205`): without one an
//! `IAKERB-FINISHED` is refused (`KRB5KRB_AP_ERR_MSG_TYPE`,
//! `accept_sec_context.c:381-383`), with one it is verified under the
//! initiator's subkey (`:384-394`), before the authenticator is committed to
//! the replay cache.

use rskrb5_ng::{
    error::{Gss, Iakerb},
    gss::{
        Acceptor, AcceptorOptions, Credential,
        iakerb::{AcceptStep, Context, token::Token},
    },
    spnego::oid::ObjectIdentifier,
};

use super::{
    context::TestError,
    support::{NoRelay, ap_req_der, finished, framed, keytab, policy, subkey},
};

/// Hand `context` a discovery token carrying `cookie` and return the
/// transcript the two tokens form.
fn discover(
    context: &mut Context,
    acceptor: &mut Acceptor<'_>,
    cookie: Option<Vec<u8>>,
) -> Result<Vec<u8>, TestError> {
    let discovery = Token::new("", cookie, Vec::new()).encode()?;
    let AcceptStep::Continue(answer) =
        context.accept_sec_context(acceptor, &mut NoRelay::default(), &discovery)?
    else {
        return Err("discovery continues".into());
    };
    Ok([discovery, answer].concat())
}

/// Both mechanisms check the `IAKERB-FINISHED` before the replay commitment.
///
/// The krb5 acceptor refuses one, an IAKERB context whose transcript differs
/// refuses it, and neither refusal commits the authenticator: the context
/// whose transcript it covers then accepts it.
#[test]
fn shared_ap_path_preserves_iakerb_finished_validation() -> Result<(), TestError> {
    // Given one acceptor (one replay cache) and an IAKERB context after discovery,
    let store = Credential::from_keytab(keytab());
    let mut acceptor = Acceptor::new(&store, AcceptorOptions::new())?;
    let mut covered = Context::acceptor(policy()?);
    let transcript = discover(&mut covered, &mut acceptor, None)?;
    // and one AP-REQ whose IAKERB-FINISHED covers that transcript,
    let request = ap_req_der(Some(&finished(&subkey(), &transcript)?))?;
    // when the krb5 mechanism receives it, it refuses the extension,
    let krb5 = acceptor.accept_sec_context(&framed(&ObjectIdentifier::krb5(), request.clone())?);
    assert!(matches!(krb5, Err(Gss::DefectiveChecksum(_))), "{krb5:?}");
    // and an IAKERB context with another transcript refuses the checksum,
    let mut other = Context::acceptor(policy()?);
    let _other: Vec<u8> = discover(&mut other, &mut acceptor, Some(b"cookie".to_vec()))?;
    let iakerb = framed(&Context::mechanism(), request)?;
    let mismatch = other.accept_sec_context(&mut acceptor, &mut NoRelay::default(), &iakerb);
    assert!(matches!(mismatch, Err(Iakerb::BadFinished)), "{mismatch:?}");
    // then the context whose transcript it covers accepts the same AP-REQ.
    let accepted = covered.accept_sec_context(&mut acceptor, &mut NoRelay::default(), &iakerb);
    assert!(
        matches!(accepted, Ok(AcceptStep::Complete(_))),
        "{accepted:?}"
    );
    Ok(())
}

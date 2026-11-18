//! IAKERB: the initiator cannot reach the KDC, the acceptor proxies for it.
//!
//! The initiator runs in the isolated adapter container (no route to the KDC,
//! asserted by the fixture and again here: a krb5 initiator fails), the acceptor
//! in the connected one. The tokens travel through the test, as they would
//! through any transport.

use core::error::Error;

use super::{
    IAKERB, KRB5, PEER, PEER_ISO, STANDARD_FLAGS, acceptor_cred, assert_mechanism, connect_iso,
    connect_main, establish, initiator_cred, is_gss_error, messages, service_name, user_principal,
};
use crate::{
    harness,
    peer::{
        cred::{CredRequest, Name, Usage},
        types::{AcceptRequest, InitRequest},
    },
};

/// IAKERB completes between an isolated initiator and a connected acceptor, once
/// with the password and once with the client keytab, while the krb5 mechanism
/// fails in the same container.
#[test]
fn iakerb_completes_while_the_initiator_cannot_reach_the_kdc() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "iakerb_completes_while_the_initiator_cannot_reach_the_kdc",
        &[PEER, PEER_ISO],
    )? {
        return Ok(());
    }
    let (mut initiator, mut acceptor) = (connect_iso()?, connect_main()?);
    let blocked = initiator.acquire(
        &CredRequest::new(Usage::Initiate)
            .named(Name::principal(&user_principal()?))
            .with_mechs(&[KRB5])
            .with_keytab(&harness::var("INTEROP_MIT_PEER_USER_KEYTAB_ID")?),
    );
    assert!(
        is_gss_error(&blocked),
        "a krb5 client-keytab credential needs the KDC, which the isolated container cannot reach: {blocked:?}"
    );

    let accept = AcceptRequest::new(b"").with_cred(acceptor_cred(&mut acceptor, &[IAKERB])?);
    let password = harness::var("INTEROP_MIT_PEER_USER_PASSWORD")?;
    let with_password = initiator
        .acquire(
            &CredRequest::new(Usage::Initiate)
                .named(Name::principal(&user_principal()?))
                .with_mechs(&[IAKERB])
                .with_password(password.as_bytes()),
        )?
        .0;
    let keytab = initiator_cred(&mut initiator, &[IAKERB])?;
    for cred in [with_password, keytab] {
        let init = InitRequest::new(service_name()?)
            .with_cred(cred)
            .with_mech(IAKERB)
            .with_flags(STANDARD_FLAGS);
        let pair = establish(&mut initiator, &mut acceptor, &init, &accept)?;
        assert_mechanism(IAKERB, pair.init.mech())?;
        assert_mechanism(IAKERB, pair.accept.mech())?;
        assert!(
            pair.accept_steps >= 3,
            "IAKERB proxies the AS and TGS exchanges before the AP exchange ({} accept steps)",
            pair.accept_steps
        );
        assert_eq!(
            pair.accept.source(),
            user_principal()?,
            "the acceptor sees the initiator"
        );
        messages::exercise(&mut initiator, &mut acceptor, &pair, true)?;
    }
    Ok(())
}

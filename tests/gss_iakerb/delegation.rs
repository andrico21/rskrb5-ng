//! Delegation over IAKERB.
//!
//! MIT 1.22.2 runs the AP exchange of an IAKERB context through the krb5
//! mechanism's (`iakerb.c:1028-1045`), so a delegation request carries the
//! client's forwardable TGT in a KRB-CRED as for krb5
//! (`init_sec_context.c:296-312`). The initiator delegates only when the
//! caller asks for it, and `enforce_ok_as_delegate` refuses it for a service
//! the KDC did not mark `OK-AS-DELEGATE` (`init_sec_context.c:537-586`).

use rskrb5_ng::{
    Config,
    gss::{ContextFlags, InitiatorOptions},
};

use super::{
    context::{Context as _, TestError},
    kdc::Kdc,
    seal::{REALM, USER},
    support::{Pair, Setup, establish_under, password_credential, policy},
};

/// A profile whose AS requests ask for a forwardable TGT.
fn forwardable() -> Result<Config, TestError> {
    Ok(Config::parse(&format!(
        "[libdefaults]\n default_realm = {REALM}\n dns_lookup_kdc = false\n dns_lookup_realm = false\n forwardable = true\n"
    ))?)
}

/// Establish a context whose initiator requests `flags` on top of the defaults.
fn establish(options: InitiatorOptions) -> Result<Pair, TestError> {
    let setup = Setup {
        config: forwardable()?,
        options,
        policy: policy()?,
        responder: None,
        relay: None,
    };
    establish_under(&password_credential(true)?, &Kdc::new(), setup)
}

/// The defaults with a delegation request.
fn delegating() -> InitiatorOptions {
    let options = InitiatorOptions::new();
    let flags = options.flags() | ContextFlags::DELEG;
    options.with_flags(flags)
}

/// A requested delegation hands the acceptor the client's TGT; without the
/// request nothing is delegated.
#[test]
fn iakerb_delegates_only_when_requested() -> Result<(), TestError> {
    // Given a forwardable TGT acquired through the relay,
    // when the initiator requests delegation,
    let mut requested = establish(delegating())?;
    // then both ends agree on it and the acceptor holds the client's TGT,
    assert!(
        requested
            .initiator
            .inquire()
            .flags()
            .contains(ContextFlags::DELEG)
    );
    assert!(
        requested
            .acceptor
            .inquire()
            .flags()
            .contains(ContextFlags::DELEG)
    );
    let delegated = requested
        .acceptor
        .take_delegated_credential()
        .context("a delegated credential")?;
    let name = delegated.inquire();
    assert_eq!(
        name.name().context("a named credential")?.display().0,
        format!("{USER}@{REALM}")
    );
    // and without the request no delegation appears.
    let unrequested = establish(InitiatorOptions::new())?;
    for context in [&unrequested.initiator, &unrequested.acceptor] {
        assert!(!context.inquire().flags().contains(ContextFlags::DELEG));
    }
    assert!(unrequested.acceptor.delegated_credential().is_none());
    Ok(())
}

/// `enforce_ok_as_delegate` turns the request into a policy request, which a
/// service ticket without `OK-AS-DELEGATE` refuses: the context completes
/// without delegation.
#[test]
fn a_delegation_policy_refuses_delegation_over_iakerb() -> Result<(), TestError> {
    let pair = establish(delegating().with_enforce_ok_as_delegate(true))?;
    for context in [&pair.initiator, &pair.acceptor] {
        let flags = context.inquire().flags();
        assert!(!flags.contains(ContextFlags::DELEG), "{flags:?}");
    }
    assert!(pair.acceptor.delegated_credential().is_none());
    Ok(())
}

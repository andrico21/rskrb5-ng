//! `verify_init_creds`: prove that new initial credentials came from the genuine KDC.
//!
//! The credentials obtain a ticket for a host service, and that service's
//! keytab verifies its AP-REQ (MIT 1.22.2 `src/lib/krb5/krb/vfy_increds.c:78-321`).
//!
//! A login that authorizes local access must not trust an AS-REP alone: a
//! spoofed KDC answering with a key derived from a guessed password would pass.
//! Only a ticket the KDC sealed in a key the host holds proves the KDC knew it.
//!
//! The `verify_ap_req_nofail` truth table (plan 2 todo 17; MIT's default is
//! `false`, this crate's is the secure one):
//!
//! | setting | no host key in the keytab | invalid proof |
//! | --- | --- | --- |
//! | unset (default) | error | error |
//! | `true` | error | error |
//! | `false` | [`Verification::Skipped`] | error |
//!
//! An invalid proof (a wrong key, a bad AP-REQ, a ticket for another service)
//! is always an error.

use core::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

use crate::{
    client::{TgsRepSession, build_ap_req_with_confounder, options::ApReq, principal::Principal},
    config::Config,
    crypto::KerberosEtype,
    error::Client as Error,
    keytab::Keytab,
    service::Validator,
};

/// Options of `Tokio::verify_init_creds`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct VerifyOptions {
    /// The service to verify against; `None` tries every `host/*` principal of
    /// the keytab.
    server: Option<Principal>,
    /// `verify_ap_req_nofail` for this call; `None` takes the profile's.
    nofail: Option<bool>,
}

impl VerifyOptions {
    /// Verify against the keytab's host principals with the profile's
    /// `verify_ap_req_nofail` (unset: verification required).
    #[must_use]
    #[inline]
    pub const fn new() -> Self {
        Self {
            server: None,
            nofail: None,
        }
    }

    /// Verify against `server` instead of the keytab's host principals.
    #[must_use]
    #[inline]
    pub fn with_server(mut self, server: Principal) -> Self {
        self.server = Some(server);
        self
    }

    /// Override `verify_ap_req_nofail`: `true` requires verification, `false`
    /// tolerates a keytab without a key for the server.
    #[must_use]
    #[inline]
    pub const fn with_nofail(mut self, nofail: bool) -> Self {
        self.nofail = Some(nofail);
        self
    }
}

/// The outcome of `Tokio::verify_init_creds`.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Verification {
    /// The KDC issued a ticket for this service that its keytab key verified.
    Verified(Principal),
    /// The keytab held no key to verify with and `verify_ap_req_nofail` is
    /// `false`: the credentials are not verified.
    Skipped,
}

/// The services `verify_init_creds` tries, in order, for a client of `realm`:
/// `Ok(None)` when the keytab holds no key to verify with and nofail is
/// `false` (MIT 1.22.2 `vfy_increds.c:259-314`).
///
/// # Errors
///
/// Returns [`Error::VerifyInitCredsNoHostKey`] when the keytab holds no key to
/// verify with and nofail is not `false`.
pub(crate) fn servers(
    config: &Config,
    realm: &str,
    keytab: &Keytab,
    options: VerifyOptions,
) -> Result<Option<Vec<Principal>>, Error> {
    let nofail = options.nofail.unwrap_or_else(|| {
        let defaults = &config.libdefaults;
        !defaults.verify_ap_req_nofail_explicit.is_enabled()
            || defaults.verify_ap_req_nofail.is_enabled()
    });
    let servers = options.server.map_or_else(
        || host_principals(keytab, realm),
        |server| {
            if has_key(keytab, &server) {
                vec![server]
            } else {
                Vec::new()
            }
        },
    );
    if !servers.is_empty() {
        return Ok(Some(servers));
    }
    if nofail {
        Err(Error::VerifyInitCredsNoHostKey)
    } else {
        Ok(None)
    }
}

/// Verify the AP-REQ of `ticket` with `keytab` (`vfy_increds.c:136-153`).
///
/// # Errors
///
/// Returns the AP-REQ construction errors and [`Error::VerifyInitCredsRejected`]
/// for a refused AP-REQ.
pub(crate) fn check(ticket: &TgsRepSession, keytab: &Keytab) -> Result<(), Error> {
    let etype = KerberosEtype::from_etype_id(ticket.session_key().etype())
        .ok_or(Error::UnsupportedEtype(ticket.session_key().etype()))?;
    let mut confounder = Zeroizing::new(vec![0; etype.confounder_len()]);
    getrandom::fill(&mut confounder)?;
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_before_epoch| Error::TimeOverflow)?;
    let now = UNIX_EPOCH
        .checked_add(Duration::from_secs(elapsed.as_secs()))
        .ok_or(Error::TimeOverflow)?;
    let built = build_ap_req_with_confounder(
        ticket,
        ApReq::default(),
        now,
        elapsed.subsec_micros(),
        &confounder,
    )?;
    let accepted = Validator::new(keytab)
        .with_now(now)
        .validate_ap_req(built.der())
        .map_err(|error| Error::VerifyInitCredsRejected(Box::new(error)))?;
    drop(accepted);
    Ok(())
}

/// The distinct `host/<name>` principals of `realm` in `keytab`, in keytab
/// order (`vfy_increds.c:222-257`).
fn host_principals(keytab: &Keytab, realm: &str) -> Vec<Principal> {
    let mut found: Vec<Principal> = Vec::new();
    for entry in keytab.entries() {
        let principal = entry.principal();
        if principal.realm == realm
            && principal.components.len() == 2
            && principal
                .components
                .first()
                .is_some_and(|first| first == "host")
        {
            let candidate = Principal::new(
                principal.realm.as_str(),
                principal.name_type,
                principal.components.iter().map(String::as_str),
            );
            if !found.contains(&candidate) {
                found.push(candidate);
            }
        }
    }
    found
}

/// Whether `keytab` holds a key for `server` (`vfy_increds.c:279-285`).
fn has_key(keytab: &Keytab, server: &Principal) -> bool {
    keytab.entries().iter().any(|entry| {
        entry.principal().realm == server.realm && entry.principal().components == server.components
    })
}

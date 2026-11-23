//! GSS-API for the Kerberos V5 mechanism in pure Rust.
//!
//! RFC 2743, RFC 2744 and RFC 4121: names, credentials, security contexts,
//! channel bindings and credential delegation, without a native GSS library.
//!
//! The flow follows MIT krb5 1.22.2's `gss_init_sec_context` and
//! `gss_accept_sec_context`:
//!
//! - a [`Name`] is imported from bytes and a [`NameType`];
//! - an initiator [`Credential`] holds the client's tickets (a credential cache,
//!   or a client keytab or password that acquires them), an acceptor one a keytab;
//! - an [`Initiator`] turns a credential and a target name into the first context
//!   token, and with mutual authentication verifies the acceptor's AP-REP;
//! - an [`Acceptor`] validates that token and answers with the AP-REP;
//! - both ends end with an [`EstablishedContext`] that signs, seals, verifies and
//!   unseals per-message tokens under the RFC 4121 key and sequence rules, and
//!   answers the inquiry functions through [`ContextInquiry`].
//!
//! [`ChannelBindings`] bind a context to an outer channel (RFC 5554, RFC 5929,
//! RFC 9266). A zero digest in a token means the initiator sent none: it is
//! absent, never a match.
//!
//! # Security
//!
//! - Context tokens, names and channel-binding fields are bounded before they
//!   are parsed or hashed; per-message tokens are verified before they move the
//!   sequence window, and a duplicate, old, out-of-sequence or gap token is
//!   refused (MIT reports these as supplementary statuses and still returns the
//!   message; this module refuses them).
//! - Keys, delegated credentials and unwrapped messages live in zeroizing owners
//!   and never appear in `Debug` output.
//! - Per-message tokens of DES3 and RC4 contexts use the RFC 1964/4757 formats,
//!   which are not implemented here; such contexts establish, and their
//!   per-message calls return [`crate::error::Gss::LegacyTokenFormat`].
//! - Nothing reads the environment except [`Credential::acquire_cred`], which
//!   documents its ambient input.
//!
//! # Extension points
//!
//! IOV and AEAD tokens, the GSS PRF, context export, DCE-style establishment,
//! the legacy token formats, name attributes and impersonation extend
//! [`EstablishedContext`], [`Initiator`], [`Acceptor`], [`Name`] and
//! [`Credential`] from their own submodules; the `IAKERB` and `NegoEx`
//! mechanisms are added beside this one.

use core::{fmt, ops::BitOr, time::Duration};
use std::time::SystemTime;

use zeroize::Zeroizing;

use crate::{
    ccache::{self, CCache},
    client::{TgsRepSession, principal::Principal},
    config::Config,
    crypto::CryptoPolicy,
    keytab::{EncryptionKey, Keytab},
    pac,
    service::{SharedReplayCache, Validator},
    spnego::oid::ObjectIdentifier,
};

/// The krb5 mechanism's acceptor side.
mod acceptor;
/// The RFC 4121 channel-binding digest.
mod bindings;
/// The RFC 4121 section 4.1.1 authenticator checksum.
mod checksum;
/// Per-message tokens of an established context.
mod context;
/// Credential acquisition and storage.
mod cred;
/// IAKERB: Kerberos through an application-mediated KDC relay.
pub mod iakerb;
/// The krb5 mechanism's initiator side.
mod initiator;
/// Name parsing, display and export.
mod name;
/// The sequence and replay window.
mod seq;

include!("gss/types.rs");
include!("gss/creds.rs");
include!("gss/contexts.rs");

use crate::error::Gss as Error;

/// `gss_indicate_mechs`: the mechanisms this module implements: krb5 and
/// IAKERB ([`iakerb`]); MIT also lists the two legacy krb5 OIDs, which this
/// module accepts but does not offer.
#[inline]
#[must_use]
pub fn indicate_mechs() -> Vec<ObjectIdentifier> {
    vec![ObjectIdentifier::krb5(), iakerb::IakerbContext::mechanism()]
}

/// `gss_inquire_names_for_mech`: the name types `mechanism` imports, every
/// [`NameType`] for krb5 (either of its OIDs) and none for another mechanism.
#[inline]
#[must_use]
pub fn inquire_names_for_mech(mechanism: &ObjectIdentifier) -> Vec<NameType> {
    name::types_for(mechanism)
}

/// The MS-KILE `KERB_AP_OPTIONS_CBT` authorization data, for the SPNEGO header
/// initiator.
///
/// # Errors
///
/// Returns [`Error::DefectiveToken`] when the data does not encode.
pub(crate) fn cbt_authorization_data() -> Result<rasn_kerberos::AuthorizationData, Error> {
    checksum::cbt_authorization_data()
}

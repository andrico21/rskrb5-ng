//! The engine-facing side of [`Exchange`].
//!
//! One PA-PK-AS-REQ, then the reply key from the KDC's PA-PK-AS-REP (MIT
//! 1.22.2 `pkinit_clnt.c:71-171` `pa_pkinit_gen_req` and `:494-644`
//! `pkinit_as_rep_parse`).

use core::fmt;
use std::time::SystemTime;

use super::{Credential, Exchange, ops};
use crate::{client::principal::Principal, error::Pkinit as Error, keytab::EncryptionKey};

/// The state between the request and the reply: the ephemeral key (erased
/// when dropped) and the authenticator nonce.
pub(super) struct Pending {
    /// The client's ephemeral key-agreement key.
    ephemeral: ops::Ephemeral,
    /// The `PKAuthenticator` nonce.
    nonce: u32,
}

/// What a request needs from the engine.
pub(crate) struct RequestInput<'input> {
    /// The request's client.
    pub client: &'input Principal,
    /// The DER KDC-REQ-BODY the authenticator checksums.
    pub body: &'input [u8],
    /// The request nonce, reused in the authenticator as MIT does.
    pub nonce: u32,
    /// The client time: whole seconds and microseconds.
    pub time: (SystemTime, u32),
    /// The KDC's freshness token, if it offered one (RFC 8070).
    pub freshness: Option<&'input [u8]>,
}

impl fmt::Debug for RequestInput<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestInput")
            .field("client", self.client)
            .field("body_bytes", &self.body.len())
            .field("nonce", &self.nonce)
            .field("time", &self.time)
            .field("freshness_bytes", &self.freshness.map(<[u8]>::len))
            .finish()
    }
}

/// What a reply needs from the engine.
pub(crate) struct ReplyInput<'input> {
    /// The DER PA-PK-AS-REP.
    pub pk_as_rep: &'input [u8],
    /// The DER AS-REQ as sent (after any FAST armoring).
    pub request: &'input [u8],
    /// The request's client.
    pub client: &'input Principal,
    /// The request's server.
    pub server: &'input Principal,
    /// The AS-REP's enctype.
    pub etype: i32,
    /// The time of the check.
    pub now: SystemTime,
}

impl fmt::Debug for ReplyInput<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReplyInput")
            .field("pk_as_rep_bytes", &self.pk_as_rep.len())
            .field("request_bytes", &self.request.len())
            .field("client", self.client)
            .field("server", self.server)
            .field("etype", &self.etype)
            .field("now", &self.now)
            .finish()
    }
}

/// The PA-PK-AS-REQ value for one request; a fresh ephemeral key replaces
/// any earlier one.
///
/// # Errors
/// Returns [`Error::Unavailable`] without the leaf, the identity
/// provider's failure and the encoding and signing errors.
pub(crate) fn request(exchange: &mut Exchange, input: &RequestInput<'_>) -> Result<Vec<u8>, Error> {
    let supplied;
    let identity = match &exchange.credential {
        Credential::Identity(identity) => Some(identity),
        Credential::Provider(provider) => {
            supplied = provider.identity(input.client).map_err(Error::Provider)?;
            Some(&supplied)
        }
        Credential::Anonymous => None,
    };
    let (value, ephemeral) = ops::request(identity, exchange.policy.group(), input)?;
    exchange.pending = Some(Pending {
        ephemeral,
        nonce: input.nonce,
    });
    Ok(value)
}

/// The reply key from the KDC's PA-PK-AS-REP; the ephemeral key is
/// consumed.
///
/// # Errors
/// Returns [`Error::Unexpected`] before a request, and the CMS,
/// certificate, key-agreement and KDF errors.
pub(crate) fn reply_key(
    exchange: &mut Exchange,
    input: &ReplyInput<'_>,
) -> Result<EncryptionKey, Error> {
    let pending = exchange.pending.take().ok_or(Error::Unexpected {
        reason: "a PA-PK-AS-REP before any PA-PK-AS-REQ",
    })?;
    ops::reply(
        &pending.ephemeral,
        pending.nonce,
        (&exchange.trust, &exchange.policy),
        input,
    )
}

/// Check a fully anonymous reply (RFC 6112 section 4.1).
///
/// MIT `get_in_tkt.c:139-203` `verify_anonymous`: the session key must be
/// `KRB-FX-CF2(kdc_key, reply_key, "PKINIT", "KEYEXCHANGE")` with the KDC
/// key of `PA-PKINIT-KX`.
///
/// # Errors
/// Returns [`Error::Anonymous`].
pub(crate) fn verify_anonymous(
    kx: Option<&[u8]>,
    reply_key: &EncryptionKey,
    session_key: &EncryptionKey,
) -> Result<(), Error> {
    let value = kx.ok_or(Error::Anonymous {
        reason: "the reply has no PA-PKINIT-KX",
    })?;
    ops::verify_anonymous(value, reply_key, session_key)
}

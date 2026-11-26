//! RFC 6113 FAST: armored AS exchanges (WP-05, MIT `fast.c`).
//!
//! [`Exchange`] is the client side of FAST: install it in a stepwise AS
//! exchange with [`InitCreds::with_armor`]. It builds the armor AP-REQ from an
//! [`ArmorSource`], wraps every request in `PA-FX-FAST` with the inner
//! `KrbFastReq`, and unwraps every reply: it decrypts the `KrbFastResponse`,
//! checks its nonce, requires `KrbFastFinished` on a ticket and verifies the
//! finished ticket checksum, and hands the inner error, the strengthen key and
//! the KDC's cookie to the engine. With the armor key it exposes, the engine
//! answers the KDC's encrypted-challenge offer
//! ([`super::encrypted_challenge::EncryptedChallenge`]).
//!
//! # Security
//!
//! [`Policy::Required`] fails closed: without an armor ticket nothing is
//! sent, and no reply is ever accepted without armor. Once a request was
//! armored, [`Policy::Opportunistic`] is equally strict; when it had no armor
//! to start with it reports [`Outcome::Unarmored`], which
//! [`Exchange::require_armored`] refuses. The armor key is fresh for every
//! exchange (a random authenticator subkey, MIT `fast.c:51-108`) and every
//! derived key is an owning [`EncryptionKey`] erased when dropped. Cookies are
//! bounded by [`MAX_COOKIE_BYTES`] and armored rounds by [`MAX_ROUNDS`].
//!
//! [`InitCreds::with_armor`]: crate::client::stepwise::InitCreds::with_armor

use core::fmt;
use std::time::SystemTime;

use zeroize::Zeroizing;

use crate::{
    ccache::CCache,
    client::{
        AsRepSession,
        stepwise::{ArmorRequest, ArmoredExchange, ArmoredReply},
    },
    crypto::CryptoPolicy,
    error::Fast as Error,
    extensions::ProviderError,
    keytab::EncryptionKey,
};

/// The armor AP-REQ and the armor key.
mod armor;
/// RFC 6113 section 5.4 FAST messages.
pub(crate) mod asn1;
/// Key combination, encryption and checksums under FAST keys.
pub(crate) mod keys;
/// Unwrapping armored replies.
mod reply;
/// MIT encoding vectors and the round bound.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests;
/// Implicit armor of TGS requests.
pub(crate) mod tgs;

/// `PA-FX-COOKIE` (RFC 6113 section 5.2).
pub const PA_FX_COOKIE: i32 = 133;
/// `PA-FX-FAST` (RFC 6113 section 5.4.2).
pub const PA_FX_FAST: i32 = 136;
/// `PA-FX-ERROR` (RFC 6113 section 5.4.4).
pub const PA_FX_ERROR: i32 = 137;
/// `PA-ENCRYPTED-CHALLENGE` (RFC 6113 section 5.4.6).
pub const PA_ENCRYPTED_CHALLENGE: i32 = 138;
/// `FX_FAST_ARMOR_AP_REQUEST` (RFC 6113 section 5.4.1).
pub const ARMOR_AP_REQUEST: i32 = 1;
/// `KEY_USAGE_FAST_REQ_CHKSUM`.
pub const KEY_USAGE_FAST_REQ_CHKSUM: u32 = 50;
/// `KEY_USAGE_FAST_ENC`.
pub const KEY_USAGE_FAST_ENC: u32 = 51;
/// `KEY_USAGE_FAST_REP`.
pub const KEY_USAGE_FAST_REP: u32 = 52;
/// `KEY_USAGE_FAST_FINISHED`.
pub const KEY_USAGE_FAST_FINISHED: u32 = 53;
/// The longest KDC cookie an exchange echoes.
pub const MAX_COOKIE_BYTES: usize = 8192;
/// The most armored requests of one exchange (MIT `MAX_IN_TKT_LOOPS`).
pub const MAX_ROUNDS: usize = 16;

/// The armor of one conversation: the armor key, the DER armor AP-REQ and
/// the realm whose TGS issued the armor ticket.
type Armor = (EncryptionKey, Zeroizing<Vec<u8>>, String);

/// When an exchange uses FAST (MIT `krb5_get_init_creds_opt_set_fast_flags`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Policy {
    /// Never armor.
    Off,
    /// Armor when the source yields an armor ticket; report the outcome.
    Opportunistic,
    /// Armor or fail before anything is sent (MIT `KRB5_FAST_REQUIRED`).
    Required,
}

/// Whether an exchange ran armored.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Outcome {
    /// Every request was armored and every reply authenticated by FAST.
    Armored,
    /// No armor was available; the exchange ran as plain RFC 4120.
    Unarmored,
}

/// The anonymous-armor hook: supplies an armor TGT for a realm, for example
/// from anonymous PKINIT (RFC 6112; the PKINIT work package provides it).
pub trait AnonymousArmor: Send {
    /// A TGT of `realm`'s TGS to armor with.
    ///
    /// # Errors
    ///
    /// Returns the provider's failure; the exchange reports [`Error::AnonymousArmor`].
    fn armor_ticket(&mut self, realm: &str) -> Result<AsRepSession, ProviderError>;
}

/// An armor credential cache (MIT `krb5_get_init_creds_opt_set_fast_ccache_name`):
/// its `krbtgt/REALM@REALM` credential armors requests to `REALM`. Its
/// `Debug` output names no key or ticket.
pub struct ArmorCache {
    /// The cache.
    cache: CCache,
}

impl ArmorCache {
    /// Armor from `cache`.
    #[inline]
    #[must_use]
    pub const fn new(cache: CCache) -> Self {
        Self { cache }
    }

    /// The unexpired TGT of `realm`'s TGS at `now`, if the cache holds one.
    #[inline]
    #[must_use]
    pub fn armor_ticket(&self, realm: &str, now: SystemTime) -> Option<AsRepSession> {
        armor::from_cache(&self.cache, realm, now)
    }
}

impl fmt::Debug for ArmorCache {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArmorCache")
            .field("credentials", &self.cache.credentials().len())
            .finish()
    }
}

/// Where the armor ticket comes from.
#[non_exhaustive]
pub enum ArmorSource {
    /// No armor.
    None,
    /// An existing TGT of the request realm's TGS.
    Ticket(Box<AsRepSession>),
    /// An armor credential cache.
    Cache(ArmorCache),
    /// An anonymous-armor provider.
    Anonymous(Box<dyn AnonymousArmor>),
}

impl fmt::Debug for ArmorSource {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::None => "ArmorSource::None",
            Self::Ticket(_) => "ArmorSource::Ticket([REDACTED])",
            Self::Cache(_) => "ArmorSource::Cache",
            Self::Anonymous(_) => "ArmorSource::Anonymous",
        })
    }
}

/// The client side of one FAST conversation; see the [module](self) docs.
pub struct Exchange {
    /// When to armor.
    policy: Policy,
    /// Where the armor ticket comes from, for each realm the exchange armors.
    source: ArmorSource,
    /// The policy the armor ticket and the armor key must satisfy.
    crypto_policy: CryptoPolicy,
    /// The armor key and the armor AP-REQ of an armored exchange.
    armor: Option<Armor>,
    /// The outcome, fixed by the first request.
    outcome: Option<Outcome>,
    /// Requests wrapped so far.
    rounds: usize,
    /// The nonce of the last armored request.
    nonce: Option<u32>,
}

impl Exchange {
    /// A FAST conversation under `policy` with armor from `source` and the
    /// default crypto policy.
    #[inline]
    #[must_use]
    pub fn new(policy: Policy, source: ArmorSource) -> Self {
        Self {
            policy,
            source,
            crypto_policy: CryptoPolicy::default(),
            armor: None,
            outcome: None,
            rounds: 0,
            nonce: None,
        }
    }

    /// Check the armor ticket and the armor key against `crypto_policy`.
    #[inline]
    #[must_use]
    pub fn with_crypto_policy(mut self, crypto_policy: CryptoPolicy) -> Self {
        self.crypto_policy = crypto_policy;
        self
    }

    /// Whether the exchange ran armored, once its first request was built.
    #[inline]
    #[must_use]
    pub const fn outcome(&self) -> Option<Outcome> {
        self.outcome
    }

    /// Succeed only when the exchange ran armored: an opportunistic exchange
    /// that ran unarmored never satisfies a caller that requires FAST.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotArmored`] unless the outcome is [`Outcome::Armored`].
    #[inline]
    pub const fn require_armored(&self) -> Result<(), Error> {
        match self.outcome {
            Some(Outcome::Armored) => Ok(()),
            Some(Outcome::Unarmored) | None => Err(Error::NotArmored),
        }
    }

    /// Wrap one request, choosing the armor on the first.
    ///
    /// # Errors
    /// Returns the armor's failure.
    fn wrap(&mut self, request: &ArmorRequest<'_>) -> Result<Zeroizing<Vec<u8>>, Error> {
        if self.rounds >= MAX_ROUNDS {
            return Err(Error::TooManyRounds { limit: MAX_ROUNDS });
        }
        self.rounds = self.rounds.saturating_add(1);
        let message = armor::decode_request(request.request)?;
        let realm = String::from_utf8(message.0.req_body.realm.as_bytes().to_vec())
            .map_err(|error| keys::codec("decode", "request realm", &error))?;
        let choice = match (&self.armor, self.outcome) {
            (_, None) => Some(self.policy),
            (Some((_, _, armored)), Some(Outcome::Armored)) => {
                (*armored != realm).then_some(Policy::Required)
            }
            (None, Some(_)) | (Some(_), Some(Outcome::Unarmored)) => None,
        };
        if let Some(policy) = choice {
            self.armor = armor::choose(policy, &mut self.source, &self.crypto_policy, &realm)?;
            self.outcome = Some(if self.armor.is_some() {
                Outcome::Armored
            } else {
                Outcome::Unarmored
            });
        }
        let Some((key, ap_req, _)) = &self.armor else {
            return Ok(Zeroizing::new(request.request.to_vec()));
        };
        self.nonce = Some(message.0.req_body.nonce);
        armor::wrap((key, ap_req), message, request)
    }

    /// Unwrap one reply.
    ///
    /// # Errors
    /// Returns the reply's FAST failure.
    fn unwrap(&self, bytes: &[u8]) -> Result<ArmoredReply, Error> {
        match (&self.armor, self.nonce) {
            (Some((key, _, _)), Some(nonce)) => reply::unwrap(key, nonce, bytes),
            _ => Ok(ArmoredReply::new(
                Zeroizing::new(bytes.to_vec()),
                None,
                None,
            )),
        }
    }
}

impl fmt::Debug for Exchange {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Exchange")
            .field("policy", &self.policy)
            .field("source", &self.source)
            .field("armored", &self.armor.is_some())
            .field("outcome", &self.outcome)
            .field("rounds", &self.rounds)
            .finish_non_exhaustive()
    }
}

impl ArmoredExchange for Exchange {
    #[inline]
    fn armor_request(
        &mut self,
        request: &ArmorRequest<'_>,
    ) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
        self.wrap(request).map_err(ProviderError::from)
    }

    #[inline]
    fn unwrap_reply(&mut self, reply: &[u8]) -> Result<ArmoredReply, ProviderError> {
        self.unwrap(reply).map_err(ProviderError::from)
    }

    #[inline]
    fn armor_key(&self) -> Option<&EncryptionKey> {
        self.armor.as_ref().map(|(key, _, _)| key)
    }
}

impl ArmoredExchange for &mut Exchange {
    #[inline]
    fn armor_request(
        &mut self,
        request: &ArmorRequest<'_>,
    ) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
        (**self).armor_request(request)
    }

    #[inline]
    fn unwrap_reply(&mut self, reply: &[u8]) -> Result<ArmoredReply, ProviderError> {
        (**self).unwrap_reply(reply)
    }

    #[inline]
    fn armor_key(&self) -> Option<&EncryptionKey> {
        (**self).armor_key()
    }
}

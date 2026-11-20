//! SPAKE preauthentication: RFC 9588 Kerberos SPAKE (not SPAKE2+), the `spake` leaf.
//!
//! [`Client`] is the client half of the PA-SPAKE exchange (MIT 1.22.2
//! `src/plugins/preauth/spake/spake_client.c`). It answers the KDC's empty
//! PA-SPAKE with a support message, answers a challenge in a permitted group
//! with a response, and replaces the reply key with `K'[0]`. The AS exchange
//! engine (`client::stepwise::InitCreds`) runs it when the KDC offers PA-SPAKE;
//! [`Policy`] carries `spake_preauth_groups`.
//!
//! The groups are those MIT supports: edwards25519 (the default, as MIT's
//! client) and P-256, P-384 and P-521. Without the `spake` Cargo feature the
//! names, the policy and the codec exist, [`AVAILABLE`] is `false`, no group is
//! usable and the engine never answers PA-SPAKE.
//!
//! The gap analysis sketched the names `SpakeClient`, `SpakeGroup` and
//! `SpakePolicy`; the strict lint profile (`module_name_repetitions`) refuses
//! the repeated prefix, so they are `spake::Client`, `spake::Group` and
//! `spake::Policy`.
//!
//! # Security
//!
//! - Points of the KDC are decoded with length and encoding checks, must be
//!   canonical, and the shared element is multiplied by the cofactor (private
//!   scalars are multiples of it, RFC 9588 section 10.1); an identity result is
//!   refused.
//! - Scalar multiplications are the constant-time ones of the admitted crates;
//!   the multiplier `w`, the private scalar, the shared element and every
//!   derived key live in zeroizing owners.
//! - Only `SF-NONE` is offered, as in MIT; a second-factor (`encdata`) round is
//!   refused, and so are a second challenge and a challenge after the response.
//! - A challenge in a group outside the policy is answered with one support
//!   message, never with a response; a second such challenge fails.
//! - Once SPAKE has started, the exchange never falls back to another
//!   mechanism, and `[realms] disable_encrypted_timestamp` removes the
//!   encrypted-timestamp fallback before it (RFC 9588 section 10.5).

use core::fmt;

use rasn_kerberos::{EncryptedData, PaData};
use zeroize::Zeroizing;

use crate::{config::LibDefaults, error::Spake as Error, keytab::EncryptionKey};

/// The client half: [`Client`]'s methods.
#[path = "spake/client.rs"]
mod client;
#[cfg(feature = "spake")]
#[path = "spake/group.rs"]
mod group;
#[cfg(not(feature = "spake"))]
#[path = "spake/unavailable.rs"]
mod group;
#[path = "spake/kdf.rs"]
mod kdf;
#[cfg(test)]
#[path = "spake/vectors.rs"]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod vectors;
#[path = "spake/wire.rs"]
mod wire;

/// PA-SPAKE padata type (RFC 9588 section 4).
pub const PA_SPAKE: i32 = 151;
/// `KEY_USAGE_SPAKE` (RFC 9588 section 11).
pub const KEY_USAGE_SPAKE: u32 = 65;
/// The `SF-NONE` second-factor type (RFC 9588 section 8).
pub const SF_NONE: i32 = 1;
/// `KDC_ERR_MORE_PREAUTH_DATA_REQUIRED` (RFC 6113 section 5.2).
pub const KDC_ERR_MORE_PREAUTH_DATA_REQUIRED: i32 = 91;
/// Largest PA-SPAKE value this client decodes, in bytes.
pub const MAX_MESSAGE_BYTES: usize = wire::MAX_MESSAGE_BYTES;
/// Whether the `spake` leaf feature, and with it the group arithmetic, is compiled in.
pub const AVAILABLE: bool = cfg!(feature = "spake");

/// A SPAKE group of the Kerberos SPAKE Groups registry (RFC 9588 section 12.2).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum Group {
    /// `edwards25519`, group 1: the MIT client default.
    Edwards25519,
    /// `P-256`, group 2.
    P256,
    /// `P-384`, group 3.
    P384,
    /// `P-521`, group 4.
    P521,
}

/// The registry parameters of one group (MIT `iana.c:93-108`).
#[derive(Clone, Copy)]
struct Params {
    /// Group number.
    id: i32,
    /// Registry name.
    name: &'static str,
    /// Multiplier length in bytes.
    mult_len: usize,
    /// Serialized element length in bytes.
    elem_len: usize,
    /// Hash output length in bytes.
    hash_len: usize,
    /// The associated hash function.
    hash: kdf::Hash,
}

impl Group {
    /// Every group, in MIT's registration order (`groups.c:89-97`).
    pub const ALL: [Self; 4] = [Self::Edwards25519, Self::P256, Self::P384, Self::P521];

    /// The registry parameters.
    const fn params(self) -> Params {
        match self {
            Self::Edwards25519 => Params {
                id: 1,
                name: "edwards25519",
                mult_len: 32,
                elem_len: 32,
                hash_len: 32,
                hash: kdf::sha256,
            },
            Self::P256 => Params {
                id: 2,
                name: "P-256",
                mult_len: 32,
                elem_len: 33,
                hash_len: 32,
                hash: kdf::sha256,
            },
            Self::P384 => Params {
                id: 3,
                name: "P-384",
                mult_len: 48,
                elem_len: 49,
                hash_len: 48,
                hash: kdf::sha384,
            },
            Self::P521 => Params {
                id: 4,
                name: "P-521",
                mult_len: 66,
                elem_len: 67,
                hash_len: 64,
                hash: kdf::sha512,
            },
        }
    }

    /// The group number.
    #[inline]
    #[must_use]
    pub const fn id(self) -> i32 {
        self.params().id
    }

    /// The registry name, as `spake_preauth_groups` writes it.
    #[inline]
    #[must_use]
    pub const fn name(self) -> &'static str {
        self.params().name
    }

    /// The group with number `id`.
    #[inline]
    #[must_use]
    pub fn from_id(id: i32) -> Option<Self> {
        Self::ALL.into_iter().find(|group| group.id() == id)
    }

    /// The group named `name`, compared ASCII case-insensitively (MIT
    /// `groups.c:113-124`, `strcasecmp`).
    #[inline]
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|group| group.name().eq_ignore_ascii_case(name))
    }
}

/// The permitted SPAKE groups, most preferred first (`spake_preauth_groups`).
///
/// The default is edwards25519 alone, MIT's client default (`groups.c:59`).
/// An empty policy disables SPAKE (MIT `groups.c:235-239`).
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Policy {
    /// The permitted groups without repeats, in preference order.
    groups: Vec<Group>,
}

impl Default for Policy {
    #[inline]
    fn default() -> Self {
        Self {
            groups: vec![Group::Edwards25519],
        }
    }
}

impl Policy {
    /// A policy permitting `groups` in this order; repeats are dropped, as MIT's
    /// `parse_groups` does (`groups.c:197-198`).
    #[inline]
    #[must_use]
    pub fn new<I>(groups: I) -> Self
    where
        I: IntoIterator<Item = Group>,
    {
        let mut kept: Vec<Group> = Vec::new();
        for group in groups {
            if !kept.contains(&group) {
                kept.push(group);
            }
        }
        Self { groups: kept }
    }

    /// The policy of `[libdefaults] spake_preauth_groups`.
    ///
    /// The profile parser admits only the four registry names.
    #[inline]
    #[must_use]
    pub fn from_libdefaults(defaults: &LibDefaults) -> Self {
        Self::new(
            defaults
                .spake_preauth_groups
                .iter()
                .filter_map(|name| Group::from_name(name)),
        )
    }

    /// The permitted groups, most preferred first.
    #[inline]
    #[must_use]
    pub fn groups(&self) -> &[Group] {
        &self.groups
    }

    /// The permitted group with number `id`, when this build can compute in it.
    #[inline]
    #[must_use]
    pub fn permitted(&self, id: i32) -> Option<Group> {
        self.groups
            .iter()
            .copied()
            .find(|group| AVAILABLE && group.id() == id)
    }

    /// Whether SPAKE can run: a group is permitted and this build has the arithmetic.
    #[inline]
    #[must_use]
    pub const fn is_usable(&self) -> bool {
        AVAILABLE && !self.groups.is_empty()
    }
}

/// What [`Client::process`] asks the caller to send.
#[non_exhaustive]
pub enum Step {
    /// A PA-SPAKE support message; no key was used.
    Support(PaData),
    /// A PA-SPAKE response; the KDC encrypts its reply in `reply_key` (`K'[0]`).
    Response {
        /// The PA-SPAKE response for the request whose body was processed.
        padata: PaData,
        /// The strengthened reply key `K'[0]`.
        reply_key: EncryptionKey,
    },
}

/// Redacted: the step kind and sizes, never key bytes.
impl fmt::Debug for Step {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Support(padata) => f
                .debug_struct("Support")
                .field("padata_bytes", &padata.value.len())
                .finish(),
            Self::Response { padata, reply_key } => f
                .debug_struct("Response")
                .field("padata_bytes", &padata.value.len())
                .field("reply_key_etype", &reply_key.etype())
                .finish_non_exhaustive(),
        }
    }
}

/// The client half of one PA-SPAKE exchange (one per AS exchange).
///
/// It keeps the support message it sent, for the transcript, and refuses a
/// second support message, a second challenge and second-factor rounds.
#[derive(Clone)]
pub struct Client {
    /// The permitted groups.
    policy: Policy,
    /// The DER support message sent, if any (RFC 9588 section 6).
    support: Option<Vec<u8>>,
    /// Whether a response was produced.
    answered: bool,
}

/// Redacted: the policy and the progress flags.
impl fmt::Debug for Client {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("policy", &self.policy)
            .field("support_sent", &self.support.is_some())
            .field("answered", &self.answered)
            .finish()
    }
}

/// A second factor of a challenge.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Factor {
    /// The second-factor type (`SF-NONE` is 1).
    pub kind: i32,
    /// Factor data (unauthenticated in a challenge, RFC 9588 section 10.2).
    pub data: Option<Vec<u8>>,
}

/// A decoded PA-SPAKE value, for inspection and fuzzing.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Message {
    /// `support`: the client's groups.
    Support {
        /// Group numbers, most preferred first.
        groups: Vec<i32>,
    },
    /// `challenge`: the KDC's group, element and second factors.
    Challenge {
        /// Group number.
        group: i32,
        /// Serialized element `T`.
        pubkey: Vec<u8>,
        /// Second factors offered, without repeated types.
        factors: Vec<Factor>,
    },
    /// `response`: the client's element and encrypted factor.
    Response {
        /// Serialized element `S`.
        pubkey: Vec<u8>,
        /// The `SPAKESecondFactor` sealed in `K'[1]`.
        factor: EncryptedData,
    },
    /// `encdata`: a second-factor round.
    Encdata(EncryptedData),
}

impl Message {
    /// Decode one complete PA-SPAKE value.
    ///
    /// # Errors
    /// Returns [`Error::Malformed`] for values over [`MAX_MESSAGE_BYTES`],
    /// non-DER or trailing input, empty or oversized lists and repeated factor types.
    #[inline]
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        wire::decode(bytes)
    }
}

/// A source of uniformly random bytes; the vector tests replay recorded scalars.
type Entropy<'source> = dyn FnMut(&mut [u8]) -> Result<(), Error> + 'source;

/// The client's serialized element `S` and the shared element `K`.
struct Shared {
    /// `S = y*G + w*N`, serialized.
    public: Vec<u8>,
    /// `K = y*(T - w*M)`, serialized.
    result: Zeroizing<Vec<u8>>,
}

/// The inputs of the section 7 derivation that do not change with `n`.
struct Derivation<'input> {
    /// The group's registry parameters.
    params: Params,
    /// The initial reply key.
    key: &'input EncryptionKey,
    /// The PRF+ output that produced `w`.
    wbytes: &'input [u8],
    /// The SPAKE result `K`, serialized.
    result: &'input [u8],
    /// The final transcript hash.
    thash: &'input [u8],
    /// The DER KDC-REQ-BODY of the request being sent.
    body: &'input [u8],
}

/// Check an outgoing PA-SPAKE value for the outgoing PA-DATA admission.
///
/// Only a support message or a response may leave the client
/// (`client::crypto_policy::padata`); a response's factor enctype is returned
/// for the policy check.
///
/// # Errors
/// Returns [`Error::Malformed`] or [`Error::Unexpected`] for any other value.
pub(crate) fn outgoing(value: &[u8]) -> Result<Option<i32>, Error> {
    match wire::decode(value)? {
        Message::Support { groups: _ } => Ok(None),
        Message::Response { factor, pubkey: _ } => Ok(Some(factor.etype)),
        Message::Challenge {
            group: _,
            pubkey: _,
            factors: _,
        } => Err(Error::Unexpected {
            message: "an outgoing challenge",
        }),
        Message::Encdata(_) => Err(Error::Unexpected {
            message: "an outgoing second-factor message",
        }),
    }
}

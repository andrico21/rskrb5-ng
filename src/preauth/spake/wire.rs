//! The PA-SPAKE messages of RFC 9588 (section 4 and appendix A) and their bounded codec.
//!
//! The module uses EXPLICIT TAGS. Extension fields (`...`) are refused rather
//! than skipped: MIT 1.22.2 sends none, and the transcript covers the exact bytes.

use rasn::{
    AsnType, Decode, Decoder as _, Encode, Encoder as _, der,
    types::{OctetString, SequenceOf},
};
use rasn_kerberos::EncryptedData;

use super::{Factor, Message};
use crate::{der::decode_complete, error::Spake as Error};

/// Largest PA-SPAKE value this client decodes, in bytes (executor bound: a
/// P-521 challenge with a few factors is under 200 bytes).
pub(super) const MAX_MESSAGE_BYTES: usize = 4096;
/// Most groups one support message may list.
const MAX_GROUPS: usize = 16;
/// Most second factors one challenge may offer.
const MAX_FACTORS: usize = 16;

/// `SPAKESupport`.
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq)]
struct Support {
    /// The client's groups, most preferred first.
    #[rasn(tag(explicit(0)))]
    groups: SequenceOf<i32>,
}

/// `SPAKEChallenge`.
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq)]
struct Challenge {
    /// The KDC's group.
    #[rasn(tag(explicit(0)))]
    group: i32,
    /// The KDC's public element `T`.
    #[rasn(tag(explicit(1)))]
    pubkey: OctetString,
    /// The offered second factors.
    #[rasn(tag(explicit(2)))]
    factors: SequenceOf<SecondFactor>,
}

/// `SPAKESecondFactor`.
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq)]
struct SecondFactor {
    /// The second-factor type.
    #[rasn(tag(explicit(0)))]
    kind: i32,
    /// Factor data.
    #[rasn(tag(explicit(1)))]
    data: Option<OctetString>,
}

/// `SPAKEResponse`.
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq)]
struct Response {
    /// The client's public element `S`.
    #[rasn(tag(explicit(0)))]
    pubkey: OctetString,
    /// The `SPAKESecondFactor`, encrypted in `K'[1]`.
    #[rasn(tag(explicit(1)))]
    factor: EncryptedData,
}

/// `PA-SPAKE`.
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq)]
#[rasn(choice)]
enum PaSpake {
    /// `support`.
    #[rasn(tag(explicit(0)))]
    Support(Support),
    /// `challenge`.
    #[rasn(tag(explicit(1)))]
    Challenge(Challenge),
    /// `response`.
    #[rasn(tag(explicit(2)))]
    Response(Response),
    /// `encdata`.
    #[rasn(tag(explicit(3)))]
    Encdata(EncryptedData),
}

/// Decode one complete PA-SPAKE value within the bounds.
///
/// # Errors
/// Returns [`Error::Malformed`] for an oversized value, invalid or non-DER
/// input, trailing bytes, an empty or oversized group or factor list, or a
/// repeated factor type.
pub(super) fn decode(bytes: &[u8]) -> Result<Message, Error> {
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(malformed("value exceeds the size bound"));
    }
    let message: PaSpake =
        decode_complete(bytes).map_err(|_detail| malformed("not a DER PA-SPAKE"))?;
    Ok(match message {
        PaSpake::Support(support) => {
            if support.groups.is_empty() || support.groups.len() > MAX_GROUPS {
                return Err(malformed("support group count out of bounds"));
            }
            Message::Support {
                groups: support.groups,
            }
        }
        PaSpake::Challenge(challenge) => {
            if challenge.factors.is_empty() || challenge.factors.len() > MAX_FACTORS {
                return Err(malformed("challenge factor count out of bounds"));
            }
            let repeated = challenge.factors.iter().enumerate().any(|(index, factor)| {
                challenge
                    .factors
                    .iter()
                    .skip(index.saturating_add(1))
                    .any(|other| other.kind == factor.kind)
            });
            if repeated {
                return Err(malformed("challenge repeats a factor type"));
            }
            Message::Challenge {
                group: challenge.group,
                pubkey: challenge.pubkey.to_vec(),
                factors: challenge
                    .factors
                    .into_iter()
                    .map(|factor| Factor {
                        kind: factor.kind,
                        data: factor.data.map(|data| data.to_vec()),
                    })
                    .collect(),
            }
        }
        PaSpake::Response(response) => Message::Response {
            pubkey: response.pubkey.to_vec(),
            factor: response.factor,
        },
        PaSpake::Encdata(data) => Message::Encdata(data),
    })
}

/// The DER support message for `groups`.
///
/// # Errors
/// Returns [`Error::Malformed`] when the encoder fails.
pub(super) fn support(groups: Vec<i32>) -> Result<Vec<u8>, Error> {
    encode(&PaSpake::Support(Support { groups }))
}

/// The DER response message.
///
/// # Errors
/// Returns [`Error::Malformed`] when the encoder fails.
pub(super) fn response(pubkey: Vec<u8>, factor: EncryptedData) -> Result<Vec<u8>, Error> {
    encode(&PaSpake::Response(Response {
        pubkey: pubkey.into(),
        factor,
    }))
}

/// The DER `SPAKESecondFactor { SF-NONE }` (data omitted, RFC 9588 section 8).
///
/// # Errors
/// Returns [`Error::Malformed`] when the encoder fails.
pub(super) fn factor_none() -> Result<Vec<u8>, Error> {
    encode(&SecondFactor {
        kind: super::SF_NONE,
        data: None,
    })
}

/// DER-encode a message this client sends.
///
/// # Errors
/// Returns [`Error::Malformed`] when the encoder fails.
fn encode<T>(value: &T) -> Result<Vec<u8>, Error>
where
    T: Encode,
{
    der::encode(value).map_err(|_detail| malformed("the encoder refused the message"))
}

/// A malformed-message error with a fixed description.
pub(super) fn malformed(message: &str) -> Error {
    Error::Malformed {
        message: message.to_owned(),
    }
}

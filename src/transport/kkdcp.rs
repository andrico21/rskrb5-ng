//! The MS-KKDCP `KDC-PROXY-MESSAGE` (MS-KKDCP section 2.2.2) and MIT's framing of it.
//!
//! ```text
//! KDC-PROXY-MESSAGE ::= SEQUENCE {
//!     kerb-message    [0] OCTET STRING,
//!     target-domain   [1] KERB-REALM OPTIONAL,   -- GeneralString
//!     dclocator-hint  [2] INTEGER OPTIONAL
//! }
//! ```
//!
//! The module uses EXPLICIT TAGS. As MIT 1.22.2 does (`sendto_kdc.c:619-629`,
//! `:1366-1372`), `kerb-message` carries the Kerberos message behind its four-byte
//! big-endian TCP record mark, and `target-domain` names the realm.
//!
//! # Security
//!
//! [`decode_reply`] parses bytes an HTTPS proxy sent: it refuses a message longer
//! than [`MAX_MESSAGE`] before decoding, trailing bytes, a record mark that does not
//! equal the length of what follows it, and an empty Kerberos message. Nothing here
//! authenticates the proxy (TLS does) or the KDC (the reply keys do). The request
//! framing is held in a zeroizing owner.

use core::fmt;

use rasn::{
    AsnType, Decode, Decoder as _, Encode, Encoder as _, der,
    types::{GeneralString, OctetString},
};
use zeroize::Zeroizing;

use crate::{der::decode_complete, error::KdcProxy as Error};

/// The largest KDC-PROXY-MESSAGE accepted from a proxy, 1 MiB: MIT's HTTPS reader
/// stops at the same bound (`sendto_kdc.c:1304-1307`).
pub const MAX_MESSAGE: usize = 1024 * 1024;
/// Length of the record mark in front of the Kerberos message.
const RECORD_MARK: usize = 4;

/// `KDC-PROXY-MESSAGE` on the wire.
#[derive(AsnType, Decode, Encode)]
struct Wire {
    /// The Kerberos message, behind its record mark.
    #[rasn(tag(explicit(0)))]
    kerb_message: OctetString,
    /// The realm of the request.
    #[rasn(tag(explicit(1)))]
    target_domain: Option<GeneralString>,
    /// A domain-controller locator hint (MS-KKDCP); MIT sends none.
    #[rasn(tag(explicit(2)))]
    dclocator_hint: Option<i32>,
}

/// One decoded KDC-PROXY-MESSAGE.
#[derive(Clone, Eq, PartialEq)]
pub struct ProxyMessage {
    /// The `kerb-message` field as it is on the wire, record mark included.
    kerb_message: Zeroizing<Vec<u8>>,
    /// The `target-domain` field.
    target_domain: Option<Vec<u8>>,
    /// The `dclocator-hint` field.
    dclocator_hint: Option<i32>,
}

impl fmt::Debug for ProxyMessage {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyMessage")
            .field("kerb_message_len", &self.kerb_message.len())
            .field("has_target_domain", &self.target_domain.is_some())
            .field("dclocator_hint", &self.dclocator_hint)
            .finish()
    }
}

impl ProxyMessage {
    /// A message with these fields; `kerb_message` is taken as it goes on the wire.
    #[inline]
    #[must_use]
    pub fn new(
        kerb_message: &[u8],
        target_domain: Option<&[u8]>,
        dclocator_hint: Option<i32>,
    ) -> Self {
        Self {
            kerb_message: Zeroizing::new(kerb_message.to_vec()),
            target_domain: target_domain.map(<[u8]>::to_vec),
            dclocator_hint,
        }
    }

    /// The `kerb-message` field, record mark included.
    #[inline]
    #[must_use]
    pub fn kerb_message(&self) -> &[u8] {
        &self.kerb_message
    }

    /// The `target-domain` field.
    #[inline]
    #[must_use]
    pub fn target_domain(&self) -> Option<&[u8]> {
        self.target_domain.as_deref()
    }

    /// The `dclocator-hint` field.
    #[inline]
    #[must_use]
    pub const fn dclocator_hint(&self) -> Option<i32> {
        self.dclocator_hint
    }

    /// The DER encoding.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Malformed`] when the encoder fails.
    #[inline]
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        let target_domain = self
            .target_domain
            .as_deref()
            .map(GeneralString::from_bytes)
            .transpose()
            .map_err(|_alphabet| Error::Malformed {
                reason: "the target domain is not a GeneralString",
            })?;
        let wire = Wire {
            kerb_message: OctetString::from_slice(&self.kerb_message),
            target_domain,
            dclocator_hint: self.dclocator_hint,
        };
        der::encode(&wire)
            .map(Zeroizing::new)
            .map_err(|_encode| Error::Malformed {
                reason: "the message does not encode",
            })
    }

    /// Decode one DER message of at most [`MAX_MESSAGE`] bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TooLarge`] above the bound, and [`Error::Malformed`] for
    /// bytes that are not exactly one KDC-PROXY-MESSAGE.
    #[inline]
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_MESSAGE {
            return Err(Error::TooLarge {
                actual: bytes.len(),
                limit: MAX_MESSAGE,
            });
        }
        let wire: Wire = decode_complete(bytes).map_err(|_detail| Error::Malformed {
            reason: "not one DER KDC-PROXY-MESSAGE",
        })?;
        Ok(Self {
            kerb_message: Zeroizing::new(wire.kerb_message.to_vec()),
            target_domain: wire.target_domain.map(GeneralString::into_vec),
            dclocator_hint: wire.dclocator_hint,
        })
    }
}

/// Frame a KDC or kpasswd request for the proxy of `realm` (MIT `make_proxy_request`,
/// `sendto_kdc.c:603-656`): the record mark, the request, and `realm` as the target.
///
/// # Errors
///
/// Returns [`Error::TooLarge`] for a request whose length does not fit the
/// record mark's 31 bits (RFC 4120 section 7.2.2) or exceeds [`MAX_MESSAGE`], and
/// [`Error::Malformed`] when the realm is not a `GeneralString`.
#[inline]
pub fn encode_request(request: &[u8], realm: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
    let length = u32::try_from(request.len())
        .ok()
        .filter(|length| length & 0x8000_0000 == 0 && request.len() <= MAX_MESSAGE)
        .ok_or(Error::TooLarge {
            actual: request.len(),
            limit: MAX_MESSAGE,
        })?;
    let mut framed = Zeroizing::new(Vec::with_capacity(
        request.len().saturating_add(RECORD_MARK),
    ));
    framed.extend_from_slice(&length.to_be_bytes());
    framed.extend_from_slice(request);
    ProxyMessage {
        kerb_message: framed,
        target_domain: Some(realm.as_bytes().to_vec()),
        dclocator_hint: None,
    }
    .encode()
}

/// The Kerberos message of a proxy's reply (MIT `service_https_read`,
/// `sendto_kdc.c:1342-1384`).
///
/// # Errors
///
/// Returns the errors of [`ProxyMessage::decode`], and [`Error::Malformed`] when the
/// record mark is missing, does not equal the length of the message behind it, or
/// announces an empty message.
#[inline]
pub fn decode_reply(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let message = ProxyMessage::decode(bytes)?;
    let (mark, reply) = message
        .kerb_message()
        .split_first_chunk::<RECORD_MARK>()
        .ok_or(Error::Malformed {
            reason: "the Kerberos message has no record mark",
        })?;
    if usize::try_from(u32::from_be_bytes(*mark)).ok() != Some(reply.len()) {
        return Err(Error::Malformed {
            reason: "the record mark does not match the Kerberos message",
        });
    }
    if reply.is_empty() {
        return Err(Error::Malformed {
            reason: "the Kerberos message is empty",
        });
    }
    Ok(reply.to_vec())
}

/// Codec vectors and bounds.
#[cfg(test)]
#[path = "kkdcp/tests.rs"]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests;

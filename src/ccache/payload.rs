//! Value-attached erasure of credential payloads.

#[cfg(feature = "serde")]
use core::fmt;

#[cfg(feature = "serde")]
use serde::{
    Deserializer, Serialize as _, Serializer,
    de::{SeqAccess, Visitor},
};
use zeroize::{Zeroize as _, Zeroizing};

use super::{AuthorizationDataEntry, Credential};
#[cfg(feature = "serde")]
use crate::keytab::key_bytes::Bytes as KeyBytes;

/// Serialize payload bytes without creating an intermediate copy.
/// # Errors
/// Returns the serializer's output error.
#[cfg(feature = "serde")]
pub(super) fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    bytes.serialize(serializer)
}

/// Deserialize into an erased owner, including partial sequence failures.
/// # Errors
/// Returns the deserializer's malformed-byte error.
#[cfg(feature = "serde")]
pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<Zeroizing<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_seq(Bytes)
}

/// Deserialize key storage without releasing an unprotected intermediate allocation.
/// # Errors
/// Returns the deserializer's malformed-byte error.
#[cfg(feature = "serde")]
pub(super) fn deserialize_key<'de, D>(deserializer: D) -> Result<KeyBytes, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize(deserializer).map(Into::into)
}

/// Sequence visitor retaining payload bytes only in zeroizing storage.
#[cfg(feature = "serde")]
struct Bytes;

#[cfg(feature = "serde")]
impl<'de> Visitor<'de> for Bytes {
    type Value = Zeroizing<Vec<u8>>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a sequence of bytes")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut bytes = Zeroizing::new(Vec::new());
        while let Some(byte) = seq.next_element()? {
            bytes.push(byte);
        }
        Ok(bytes)
    }
}

/// Wipe the live allocation before its zeroizing owner erases spare capacity.
fn erase(bytes: &mut Zeroizing<Vec<u8>>) {
    bytes.as_mut_slice().zeroize();
    #[cfg(test)]
    super::payload_tests::EVENTS.with_borrow_mut(|events| {
        events.push((bytes.len(), bytes.iter().all(|byte| *byte == 0)));
    });
}

// Drop audit: synchronous erasure; field destructors additionally wipe spare capacity.
impl Drop for Credential {
    #[inline]
    fn drop(&mut self) {
        let Self {
            client: _,
            server: _,
            key: _,
            times: _,
            is_skey: _,
            ticket_flags: _,
            addresses: _,
            auth_data: _,
            ticket,
            second_ticket,
        } = self;
        erase(ticket);
        erase(second_ticket);
    }
}

// Drop audit: synchronous erasure with no I/O; the field also erases spare capacity.
impl Drop for AuthorizationDataEntry {
    #[inline]
    fn drop(&mut self) {
        let Self { ad_type: _, data } = self;
        erase(data);
    }
}

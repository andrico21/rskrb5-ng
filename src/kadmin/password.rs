//! Zeroizing password bytes for the kpasswd ASN.1 boundary.

use core::fmt;

use rasn::{
    AsnType, Decode, Decoder, Encode, Encoder,
    types::{Constraints, Identifier, Tag},
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Password bytes erased on drop, including clones and decoded values.
///
/// Generic ASN.1 encoders may retain their own output buffers; this owner
/// erases only its own storage, not an encoder's copies.
#[derive(Clone, Eq, PartialEq)]
pub struct Bytes(Zeroizing<Vec<u8>>);

impl Bytes {
    /// Copy the bytes into caller-owned storage.
    ///
    /// The caller is responsible for erasing the returned allocation.
    #[must_use]
    #[inline]
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl fmt::Debug for Bytes {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl AsRef<[u8]> for Bytes {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for Bytes {
    #[inline]
    fn from(value: Vec<u8>) -> Self {
        Self(Zeroizing::new(value))
    }
}

impl From<&[u8]> for Bytes {
    /// Copy borrowed bytes into an erasing owner.
    ///
    /// # Security
    /// The original slice and caller-made copies remain the caller's erasure
    /// responsibility. Borrow from a zeroizing owner or move an owned vector.
    #[inline]
    fn from(value: &[u8]) -> Self {
        Self(Zeroizing::new(value.to_vec()))
    }
}

impl PartialEq<Vec<u8>> for Bytes {
    #[inline]
    fn eq(&self, other: &Vec<u8>) -> bool {
        self.as_ref() == other.as_slice()
    }
}

impl Zeroize for Bytes {
    #[inline]
    fn zeroize(&mut self) {
        self.0.as_mut_slice().zeroize();
        #[cfg(test)]
        tests::ERASED.with_borrow_mut(|events| {
            events.push((self.0.len(), self.0.iter().all(|byte| *byte == 0)));
        });
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for Bytes {}

impl AsnType for Bytes {
    const TAG: Tag = Tag::OCTET_STRING;
}

impl Decode for Bytes {
    #[inline]
    fn decode_with_tag_and_constraints<D>(
        decoder: &mut D,
        tag: Tag,
        constraints: &Constraints,
    ) -> Result<Self, D::Error>
    where
        D: Decoder,
    {
        decoder.decode_octet_string(tag, constraints)
    }
}

impl Encode for Bytes {
    #[inline]
    fn encode_with_tag_and_constraints<'encoder, E>(
        &self,
        encoder: &mut E,
        tag: Tag,
        constraints: &Constraints,
        identifier: Identifier,
    ) -> Result<(), E::Error>
    where
        E: Encoder<'encoder>,
    {
        encoder
            .encode_octet_string(tag, constraints, self.as_ref(), identifier)
            .map(drop)
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::{cell::RefCell, error::Error};

    use crate::{client::Password, kadmin::ChangePasswdData};

    std::thread_local! {
        /// Live old-allocation byte observations before replacement.
        pub(super) static ERASED: RefCell<Vec<(usize, bool)>> = const { RefCell::new(Vec::new()) };
    }

    /// Replacing password data erases the previous allocation while its container lives.
    #[test]
    fn password_setter_erases_previous_bytes() -> Result<(), Box<dyn Error>> {
        let mut data = ChangePasswdData::decode_der(
            &ChangePasswdData::new(Password::from_vec(vec![0x41; 16])).encode_der()?,
        )?;
        ERASED.with_borrow_mut(Vec::clear);
        data.set_new_passwd(vec![0x52; 17].into());
        ERASED.with_borrow(|events| assert_eq!(events.as_slice(), [(16, true)]));
        Ok(())
    }
}

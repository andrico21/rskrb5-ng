//! Key-byte ownership independent of the enclosing key record.

#[cfg(test)]
use core::cell::RefCell;
use core::{fmt, ops::Deref};

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Key bytes erased before replacement or destruction, with read-only slice access.
#[derive(Clone, Eq, PartialEq)]
pub struct Bytes(Zeroizing<Vec<u8>>);

impl Bytes {
    /// Borrow key bytes without transferring erasure responsibility.
    #[inline]
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl From<Vec<u8>> for Bytes {
    #[inline]
    fn from(value: Vec<u8>) -> Self {
        Self(value.into())
    }
}

impl From<Zeroizing<Vec<u8>>> for Bytes {
    #[inline]
    fn from(value: Zeroizing<Vec<u8>>) -> Self {
        Self(value)
    }
}

impl Deref for Bytes {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl AsRef<[u8]> for Bytes {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl fmt::Debug for Bytes {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self(bytes) = self;
        f.debug_struct("KeyBytes")
            .field("len", &bytes.len())
            .finish()
    }
}

impl Zeroize for Bytes {
    #[inline]
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for Bytes {}

// Drop audit: the field erases spare capacity after synchronous live-byte erasure.
impl Drop for Bytes {
    #[inline]
    fn drop(&mut self) {
        self.0.as_mut_slice().zeroize();
        #[cfg(test)]
        EVENTS.with_borrow_mut(|events| {
            events.push((self.0.len(), self.0.iter().all(|byte| *byte == 0)));
        });
    }
}

#[cfg(test)]
std::thread_local! {
    /// Live old-allocation erasure observations, never a read after free.
    static EVENTS: RefCell<Vec<(usize, bool)>> = const { RefCell::new(Vec::new()) };
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use super::EVENTS;
    use crate::{ccache, keytab};

    /// Replacing a key field erases its old bytes before the enclosing key is dropped.
    #[test]
    fn replacement_erases_old_key_allocation() {
        let mut cache = ccache::EncryptionKey::new(18, vec![0x51; 31]);
        let mut keytab = keytab::EncryptionKey::new(18, vec![0x62; 32]);
        EVENTS.with_borrow_mut(Vec::clear);
        cache.value = vec![0x73; 33].into();
        keytab.value = vec![0x84; 34].into();
        EVENTS.with_borrow(|events| assert_eq!(events.as_slice(), [(31, true), (32, true)]));
    }
}

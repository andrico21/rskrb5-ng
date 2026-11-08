//! Purpose-labelled plaintext staging with observable, deterministic erasure.

use core::ops::{Deref, DerefMut};

use zeroize::{Zeroize as _, Zeroizing};

/// Plaintext staging whose live bytes are erased before its backing owner drops.
pub(super) struct Scratch {
    /// Allocation, including spare capacity erased by Zeroizing on drop.
    bytes: Zeroizing<Vec<u8>>,
    /// Stable owner identity used by erasure regression tests.
    purpose: &'static str,
}

impl Scratch {
    /// Adopt staging without making another plaintext copy.
    pub(super) fn new(bytes: Vec<u8>, purpose: &'static str) -> Self {
        #[cfg(test)]
        super::erasure_tests::observe_capacity(purpose, bytes.len(), bytes.capacity());
        Self {
            bytes: Zeroizing::new(bytes),
            purpose,
        }
    }
}

impl Deref for Scratch {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl DerefMut for Scratch {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.bytes
    }
}

// Drop audit: synchronous in-place erasure; no I/O, locking, or production allocation.
impl Drop for Scratch {
    fn drop(&mut self) {
        let Self { bytes, purpose } = self;
        bytes.as_mut_slice().zeroize();
        #[cfg(test)]
        super::erasure_tests::observe(purpose, bytes.as_slice());
        let _: &str = purpose;
    }
}

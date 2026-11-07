//! Owning erasure and redaction for the PAC UserSessionKey slot.

use core::fmt;

use zeroize::{Zeroize as _, Zeroizing};

/// A sixteen-byte PAC session key, redacted and erased on ordinary drop.
#[derive(Clone, Eq, PartialEq)]
pub struct SessionKey(Zeroizing<[u8; 16]>);

impl SessionKey {
    /// Adopt a zeroizing key owner without exposing its contents through Debug.
    #[must_use]
    #[inline]
    pub const fn new(bytes: Zeroizing<[u8; 16]>) -> Self {
        Self(bytes)
    }

    /// Borrow key bytes; callers must erase any copies they create.
    #[must_use]
    #[inline]
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Debug for SessionKey {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self(_bytes) = self;
        f.debug_struct("SessionKey")
            .field("len", &16_usize)
            .finish_non_exhaustive()
    }
}

// Drop audit: erase live bytes synchronously before releasing the owning value.
impl Drop for SessionKey {
    #[inline]
    fn drop(&mut self) {
        let Self(bytes) = self;
        bytes.zeroize();
        #[cfg(test)]
        tests::ERASED.with_borrow_mut(|events| events.push(bytes.iter().all(|byte| *byte == 0)));
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
    use core::cell::RefCell;

    use crate::pac::{Error, KerbValidationInfo};

    std::thread_local! {
        /// Live post-wipe observations, isolated per test thread.
        pub(super) static ERASED: RefCell<Vec<bool>> = const { RefCell::new(Vec::new()) };
    }

    /// Success and a later malformed-field error both erase the original key owner.
    #[test]
    fn validation_key_erased_on_success_and_failure() -> Result<(), Error> {
        let mut bytes = vec![0; 240];
        bytes
            .get_mut(..8)
            .ok_or(Error::LengthOverflow)?
            .copy_from_slice(&[1, 0x10, 8, 0, 0xcc, 0xcc, 0xcc, 0xcc]);
        bytes
            .get_mut(8..12)
            .ok_or(Error::LengthOverflow)?
            .copy_from_slice(&224_u32.to_le_bytes());
        bytes
            .get_mut(16..20)
            .ok_or(Error::LengthOverflow)?
            .copy_from_slice(&1_u32.to_le_bytes());
        bytes
            .get_mut(140..156)
            .ok_or(Error::LengthOverflow)?
            .fill(0x42);
        ERASED.with_borrow_mut(Vec::clear);
        drop(KerbValidationInfo::parse(&bytes)?);
        ERASED.with_borrow(|events| assert_eq!(events.as_slice(), [true]));
        bytes
            .get_mut(156..158)
            .ok_or(Error::LengthOverflow)?
            .copy_from_slice(&2_u16.to_le_bytes());
        ERASED.with_borrow_mut(Vec::clear);
        assert!(matches!(
            KerbValidationInfo::parse(&bytes),
            Err(Error::InvalidRpcUnicodeString {
                target: _,
                length: 2,
                maximum_length: 0
            })
        ));
        ERASED.with_borrow(|events| assert_eq!(events.as_slice(), [true]));
        Ok(())
    }
}

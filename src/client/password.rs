//! Owning password input and erasure.

#[cfg(test)]
use alloc::sync::Arc;
use core::fmt;
#[cfg(test)]
use core::sync::atomic::{AtomicBool, Ordering};

use zeroize::{Zeroize as _, Zeroizing};

/// Real mutation lifecycle erasure regressions.
#[cfg(all(test, feature = "tokio"))]
#[path = "password_lifecycle_tests.rs"]
mod lifecycle_tests;

/// A password allocation erased on drop, with no implicit copying or display.
///
/// Owned constructors preserve the original allocation. Borrowing its bytes
/// does not transfer erasure duties for any copies made by the caller.
/// Erasure requires normal destruction; process abort does not run destructors.
pub struct Secret {
    /// Original password allocation, including zeroization of spare capacity.
    bytes: Zeroizing<Vec<u8>>,
    /// Observes live bytes after erasure and before deallocation, in unit tests only.
    #[cfg(test)]
    erased: Option<Arc<AtomicBool>>,
}

impl Secret {
    /// Take ownership of a string without copying its allocation.
    #[must_use]
    #[inline]
    pub fn from_string(value: String) -> Self {
        Self::from_vec(value.into_bytes())
    }

    /// Take ownership of arbitrary password bytes without copying their allocation.
    #[must_use]
    #[inline]
    pub fn from_vec(value: Vec<u8>) -> Self {
        Self {
            bytes: Zeroizing::new(value),
            #[cfg(test)]
            erased: None,
        }
    }

    /// Copy borrowed text into an owning password.
    ///
    /// # Security
    ///
    /// The caller retains responsibility for erasing the borrowed input and
    /// any other copies. Prefer [`Self::from_string`] to transfer an allocation.
    #[must_use]
    #[inline]
    pub fn copy_from_str(value: &str) -> Self {
        Self::from_vec(value.as_bytes().to_vec())
    }

    /// Borrow the password bytes without allocating or transferring ownership.
    #[must_use]
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for Secret {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            bytes: _,
            #[cfg(test)]
                erased: _,
        } = self;
        f.write_str("Password([REDACTED])")
    }
}

// Drop audit: the live password slice is zeroized synchronously; the Zeroizing
// field then erases spare capacity before deallocation. No I/O or async work occurs.
impl Drop for Secret {
    #[inline]
    fn drop(&mut self) {
        let Self {
            bytes,
            #[cfg(test)]
            erased,
        } = self;
        bytes.as_mut_slice().zeroize();
        #[cfg(test)]
        if let Some(observation) = erased {
            observation.store(bytes.iter().all(|byte| *byte == 0), Ordering::SeqCst);
        }
        // Zeroizing also erases spare capacity when the field is dropped.
    }
}

/// Password allocation and destruction regressions.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use alloc::sync::Arc;
    use core::{
        error::Error,
        str,
        sync::atomic::{AtomicBool, Ordering},
    };

    use super::Secret;

    /// The moved Vec allocation, rather than a duplicate, is erased at legitimate Drop.
    #[test]
    fn original_allocation_is_erased_on_drop() -> Result<(), Box<dyn Error>> {
        // Given a nonempty Vec with spare capacity and its original allocation identity.
        let mut original = Vec::new();
        original.try_reserve_exact(128)?;
        original.extend_from_slice(b"original-allocation-canary");
        let address = original.as_ptr().addr();
        let erased = Arc::new(AtomicBool::new(false));
        let mut password = Secret::from_vec(original);
        password.erased = Some(Arc::clone(&erased));
        assert_eq!(password.as_bytes().as_ptr().addr(), address);
        assert_eq!(password.as_bytes(), b"original-allocation-canary");
        // When the real owner drops, its observer runs before the allocation is freed.
        drop(password);
        // Then the live original bytes, not just another zeroizing copy, were erased.
        assert!(
            erased.load(Ordering::SeqCst),
            "owned argument still plaintext at Drop"
        );
        Ok(())
    }

    /// String conversion preserves the allocation and exact UTF-8 bytes.
    #[test]
    fn string_allocation_is_preserved() -> Result<(), Box<dyn Error>> {
        // Given owned UTF-8 input.
        let original = String::from_utf8("password-\u{e9}".as_bytes().to_vec())?;
        let address = original.as_ptr().addr();
        // When ownership is transferred.
        let password = Secret::from_string(original);
        // Then no replacement allocation or normalization occurs.
        assert_eq!(password.as_bytes().as_ptr().addr(), address);
        assert_eq!(password.as_bytes(), "password-\u{e9}".as_bytes());
        Ok(())
    }

    /// Borrowed construction copies bytes and Debug never discloses them.
    #[test]
    fn borrowed_input_and_debug_are_explicit() -> Result<(), Box<dyn Error>> {
        // Given a distinctive borrowed password.
        let input = str::from_utf8(b"redaction-canary")?;
        assert!(
            format!("{:?}", Secret::copy_from_str(input)).starts_with("Password("),
            "redacted password retains its diagnostic kind"
        );
        // When an owning copy is constructed.
        let password = Secret::copy_from_str(input);
        // Then the borrowed input remains unchanged and both Debug forms redact it.
        assert_eq!(password.as_bytes(), input.as_bytes());
        assert!(!format!("{password:?} {password:#?}").contains(input));
        Ok(())
    }
}

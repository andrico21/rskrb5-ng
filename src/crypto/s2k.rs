//! Trusted password-derivation floors; never loaded from profile or peer input.
use crate::error::Policy;

/// String-to-key family sharing a minimum across both key sizes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Family {
    /// RFC 3962 section 4, enctypes 17 and 18.
    AesSha1,
    /// RFC 8009 section 4, enctypes 19 and 20.
    AesSha2,
    /// RFC 6803 section 4, enctypes 25 and 26.
    Camellia,
}

/// Validated trusted minima; private fields prevent unchecked mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Minima {
    /// SHA1-based AES minimum.
    sha1: u32,
    /// SHA2-based AES minimum.
    sha2: u32,
    /// Camellia minimum.
    camellia: u32,
}

impl Minima {
    /// RFC defaults: 4096 for AES-SHA1, 32768 for AES-SHA2 and 32768 for Camellia.
    /// See [RFC 3962 section 4](https://www.rfc-editor.org/rfc/rfc3962#section-4),
    /// [RFC 8009 section 4](https://www.rfc-editor.org/rfc/rfc8009#section-4) and
    /// [RFC 6803 section 6](https://www.rfc-editor.org/rfc/rfc6803#section-6).
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            sha1: 4096,
            sha2: 0x8000,
            camellia: 0x8000,
        }
    }

    /// Return the minimum for a PBKDF2 enctype, or None for other profiles.
    #[inline]
    #[must_use]
    pub const fn for_etype(self, etype: i32) -> Option<u32> {
        match etype {
            17 | 18 => Some(self.sha1),
            19 | 20 => Some(self.sha2),
            25 | 26 => Some(self.camellia),
            _ => None,
        }
    }

    /// Install a trusted override within the existing work ceiling.
    /// # Security
    /// Lowering a floor makes captured password proofs cheaper to guess offline.
    /// Never derive this value from a KDC response or untrusted configuration.
    /// # Errors
    /// Rejects zero and values above the local 2^24 iteration ceiling.
    #[inline]
    pub fn with_minimum(mut self, family: Family, minimum: u32) -> Result<Self, Policy> {
        (minimum != 0 && minimum <= super::MAX_S2K_ITERATIONS)
            .ok_or(Policy::InvalidS2kMinimum { minimum })?;
        match family {
            Family::AesSha1 => self.sha1 = minimum,
            Family::AesSha2 => self.sha2 = minimum,
            Family::Camellia => self.camellia = minimum,
        }
        Ok(self)
    }
}

impl Default for Minima {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

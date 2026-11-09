//! Error diagnostics never recursively format credential-bearing causes.

use core::{fmt, mem::discriminant};

impl fmt::Debug for super::Any {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Error")
            .field(&discriminant(self))
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "messages")]
impl fmt::Debug for super::Client {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Client")
            .field(&discriminant(self))
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "spnego")]
impl fmt::Debug for super::Spnego {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Spnego")
            .field(&discriminant(self))
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "http")]
impl fmt::Debug for super::Http {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Http")
            .field(&discriminant(self))
            .finish_non_exhaustive()
    }
}

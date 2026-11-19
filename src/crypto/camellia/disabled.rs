//! The stand-in used when the `camellia` leaf feature is off: a type with no values.

use super::CtsCmacEtype;
use crate::error::Crypto as Error;

impl CtsCmacEtype {
    /// Unavailable without the feature.
    #[inline]
    #[must_use]
    pub const fn from_etype_id(_etype_id: i32) -> Option<Self> {
        None
    }

    /// Unavailable without the feature.
    #[inline]
    #[must_use]
    pub const fn from_checksum_type_id(_checksum_type_id: i32) -> Option<Self> {
        None
    }

    /// Unreachable: no value exists.
    #[inline]
    #[must_use]
    pub const fn etype_id(self) -> i32 {
        match self.0 {}
    }

    /// Unreachable: no value exists.
    #[inline]
    #[must_use]
    pub const fn checksum_type_id(self) -> i32 {
        match self.0 {}
    }

    /// Unreachable: no value exists.
    #[inline]
    #[must_use]
    pub const fn ename(self) -> &'static str {
        match self.0 {}
    }

    /// Unreachable: no value exists.
    #[inline]
    #[must_use]
    pub const fn key_len(self) -> usize {
        match self.0 {}
    }

    /// Confounder size in bytes.
    #[inline]
    #[must_use]
    pub const fn confounder_len() -> usize {
        16
    }

    /// CMAC checksum size in bytes.
    #[inline]
    #[must_use]
    pub const fn hmac_len() -> usize {
        16
    }

    /// Default string-to-key parameters.
    #[inline]
    #[must_use]
    pub const fn default_s2kparams() -> &'static str {
        "00008000"
    }

    /// Unreachable: no value exists.
    ///
    /// # Errors
    /// Never returns.
    #[inline]
    pub const fn string_to_key(
        self,
        _secret: &[u8],
        _salt: &[u8],
        _s2kparams: &str,
    ) -> Result<Vec<u8>, Error> {
        match self.0 {}
    }

    /// Unreachable: no value exists.
    ///
    /// # Errors
    /// Never returns.
    #[inline]
    pub const fn checksum(
        self,
        _protocol_key: &[u8],
        _data: &[u8],
        _usage: u32,
    ) -> Result<Vec<u8>, Error> {
        match self.0 {}
    }

    /// Unreachable: no value exists.
    #[inline]
    #[must_use]
    pub const fn verify_checksum(
        self,
        _protocol_key: &[u8],
        _data: &[u8],
        _checksum: &[u8],
        _usage: u32,
    ) -> bool {
        match self.0 {}
    }

    /// Unreachable: no value exists.
    ///
    /// # Errors
    /// Never returns.
    #[inline]
    pub const fn encrypt_message_with_confounder(
        self,
        _protocol_key: &[u8],
        _message: &[u8],
        _usage: u32,
        _confounder: &[u8],
    ) -> Result<Vec<u8>, Error> {
        match self.0 {}
    }

    /// Unreachable: no value exists.
    ///
    /// # Errors
    /// Never returns.
    #[inline]
    pub const fn decrypt_message(
        self,
        _protocol_key: &[u8],
        _ciphertext: &[u8],
        _usage: u32,
    ) -> Result<Vec<u8>, Error> {
        match self.0 {}
    }

    /// Unreachable: no value exists.
    ///
    /// # Errors
    /// Never returns.
    pub(crate) const fn prf_subkey(self, _protocol_key: &[u8]) -> Result<Vec<u8>, Error> {
        match self.0 {}
    }

    /// Unreachable: no value exists.
    ///
    /// # Errors
    /// Never returns.
    pub(crate) const fn prf_block(self, _subkey: &[u8], _input: &[u8]) -> Result<Vec<u8>, Error> {
        match self.0 {}
    }
}

//! Signed key-version conversion for encrypted data.

use rasn::types::{Integer, OctetString};

use super::{EncryptedData, Error};

impl EncryptedData {
    /// Return the encryption algorithm identifier.
    #[inline]
    #[must_use]
    pub const fn etype(&self) -> i32 {
        self.etype
    }
    /// Borrow the raw key version.
    #[inline]
    #[must_use]
    pub const fn kvno(&self) -> Option<&Integer> {
        self.kvno.as_ref()
    }
    /// Borrow ciphertext; the dependency-owned ASN.1 allocation is a residual copy.
    #[inline]
    #[must_use]
    pub fn cipher(&self) -> &[u8] {
        self.cipher.as_ref()
    }
    /// Creates a `EncryptedData` from its required fields.
    #[must_use]
    #[inline]
    pub const fn new(etype: i32, cipher: OctetString) -> Self {
        Self {
            etype,
            kvno: None,
            cipher,
        }
    }
    /// Sets `kvno`, preserving the other fields.
    #[must_use]
    #[inline]
    pub fn with_kvno(mut self, value: Option<Integer>) -> Self {
        self.kvno = value;
        self
    }

    /// Build the preserving wrapper from the upstream rasn Kerberos type.
    #[inline]
    pub fn from_rasn(value: rasn_kerberos::EncryptedData) -> Self {
        Self {
            etype: value.etype,
            kvno: value.kvno.map(Integer::from),
            cipher: value.cipher,
        }
    }

    /// Convert to the upstream rasn Kerberos type when `kvno` is a valid `u32`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KvnoOutOfRange`] when `kvno` is negative or does not fit
    /// a `u32`.
    #[inline]
    pub fn try_to_rasn(&self) -> Result<rasn_kerberos::EncryptedData, Error> {
        Ok(rasn_kerberos::EncryptedData {
            etype: self.etype,
            kvno: self.kvno_u32()?,
            cipher: self.cipher.clone(),
        })
    }

    /// Return `kvno` as a signed 32-bit value, matching gokrb5's `int` tests.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KvnoOutOfRange`] when `kvno` does not fit an `i32`.
    #[inline]
    pub fn kvno_i32(&self) -> Result<Option<i32>, Error> {
        self.kvno
            .as_ref()
            .map(|kvno| {
                i32::try_from(kvno)
                    .ok()
                    .ok_or_else(|| Error::KvnoOutOfRange {
                        target: "i32",
                        kvno: kvno.clone(),
                    })
            })
            .transpose()
    }

    /// Return `kvno` as the normal non-negative Kerberos `u32` representation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KvnoOutOfRange`] when `kvno` is negative or does not fit
    /// a `u32`.
    #[inline]
    pub fn kvno_u32(&self) -> Result<Option<u32>, Error> {
        self.kvno
            .as_ref()
            .map(|kvno| {
                u32::try_from(kvno)
                    .ok()
                    .ok_or_else(|| Error::KvnoOutOfRange {
                        target: "u32",
                        kvno: kvno.clone(),
                    })
            })
            .transpose()
    }
}

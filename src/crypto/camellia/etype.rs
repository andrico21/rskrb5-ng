//! The Camellia-CTS-CMAC encryption types of RFC 6803.

use sha1::Sha1;

use super::{CtsCmacEtype, cts, kdf};
use crate::{
    crypto::{
        KERBEROS_CONSTANT, Purpose, SecretScratch, s2kparams_to_iterations, split_trailing_mac,
        strip_confounder, usage_constant,
    },
    error::Crypto as Error,
};

/// RFC 6803 confounder size, one Camellia block.
const CONFOUNDER_SIZE: usize = 16;
/// RFC 6803 CMAC checksum size.
const CMAC_SIZE: usize = 16;
/// RFC 6803 section 6: 32768 iterations.
const DEFAULT_S2KPARAMS: &str = "00008000";

impl CtsCmacEtype {
    /// Probe an encryption type ID without selecting use.
    #[inline]
    #[must_use]
    pub const fn from_etype_id(etype_id: i32) -> Option<Self> {
        match etype_id {
            25 => Some(Self::Camellia128),
            26 => Some(Self::Camellia256),
            _ => None,
        }
    }

    /// Probe a checksum type ID without selecting use.
    #[inline]
    #[must_use]
    pub const fn from_checksum_type_id(checksum_type_id: i32) -> Option<Self> {
        match checksum_type_id {
            17 => Some(Self::Camellia128),
            18 => Some(Self::Camellia256),
            _ => None,
        }
    }

    /// Kerberos encryption type ID.
    #[inline]
    #[must_use]
    pub const fn etype_id(self) -> i32 {
        match self {
            Self::Camellia128 => 25,
            Self::Camellia256 => 26,
        }
    }

    /// Kerberos checksum type ID (`cmac-camellia128`, `cmac-camellia256`).
    #[inline]
    #[must_use]
    pub const fn checksum_type_id(self) -> i32 {
        match self {
            Self::Camellia128 => 17,
            Self::Camellia256 => 18,
        }
    }

    /// Canonical MIT name, also the enctype name RFC 6803 section 4 prepends to the salt.
    #[inline]
    #[must_use]
    pub const fn ename(self) -> &'static str {
        match self {
            Self::Camellia128 => "camellia128-cts-cmac",
            Self::Camellia256 => "camellia256-cts-cmac",
        }
    }

    /// Protocol key size in bytes.
    #[inline]
    #[must_use]
    pub const fn key_len(self) -> usize {
        match self {
            Self::Camellia128 => 16,
            Self::Camellia256 => 32,
        }
    }

    /// Confounder size in bytes.
    #[inline]
    #[must_use]
    pub const fn confounder_len() -> usize {
        CONFOUNDER_SIZE
    }

    /// CMAC checksum size in bytes.
    #[inline]
    #[must_use]
    pub const fn hmac_len() -> usize {
        CMAC_SIZE
    }

    /// Default string-to-key parameters, 32768 iterations as big-endian hex.
    #[inline]
    #[must_use]
    pub const fn default_s2kparams() -> &'static str {
        DEFAULT_S2KPARAMS
    }

    /// `enctype-name | 0x00 | salt`, the salt of RFC 6803 section 4.
    #[inline]
    #[must_use]
    pub fn saltp(self, salt: &[u8]) -> Vec<u8> {
        [self.ename().as_bytes(), &[0], salt].concat()
    }

    /// PBKDF2-HMAC-SHA1 intermediate of string-to-key over `saltp`.
    ///
    /// This low-level primitive takes a trusted work factor; use
    /// [`Self::string_to_key`] for bounded peer-provided parameters.
    #[inline]
    #[must_use]
    pub fn string_to_pbkdf2(self, secret: &[u8], saltp: &[u8], iterations: u32) -> Vec<u8> {
        #[cfg(test)]
        crate::crypto::pbkdf2_observation::record();
        let mut out = SecretScratch::new(vec![0; self.key_len()]);
        pbkdf2::pbkdf2_hmac::<Sha1>(secret, saltp, iterations, &mut out);
        out.into_vec()
    }

    /// Derive a protocol key from a password and salt (RFC 6803 section 4).
    ///
    /// # Errors
    /// Returns the `s2kparams` errors of [`crate::crypto::s2kparams_to_iterations`]:
    /// zero iterations and counts above 2^24 are refused before any PBKDF2 work.
    #[inline]
    pub fn string_to_key(
        self,
        secret: &[u8],
        salt: &[u8],
        s2kparams: &str,
    ) -> Result<Vec<u8>, Error> {
        let iterations = s2kparams_to_iterations(s2kparams)?;
        let tkey = SecretScratch::for_purpose(
            self.string_to_pbkdf2(secret, &self.saltp(salt), iterations),
            Purpose::Pbkdf2,
        );
        self.derive_key(&tkey, KERBEROS_CONSTANT)
    }

    /// `KDF-FEEDBACK-CMAC(protocol_key, constant)`; the random-to-key function is the identity.
    ///
    /// # Errors
    /// Returns [`Error::InvalidKeyLength`] for a key of the wrong size and
    /// [`Error::EmptyUsage`] for an empty constant.
    #[inline]
    pub fn derive_key(self, protocol_key: &[u8], constant: &[u8]) -> Result<Vec<u8>, Error> {
        kdf::derive(self, protocol_key, constant).map(|key| key.to_vec())
    }

    /// CMAC of `data` under the checksum key `Kc` of `usage`.
    ///
    /// # Errors
    /// Returns [`Error::InvalidKeyLength`] when `protocol_key` has the wrong size.
    #[inline]
    pub fn checksum(self, protocol_key: &[u8], data: &[u8], usage: u32) -> Result<Vec<u8>, Error> {
        let key = SecretScratch::new(self.derive_key(protocol_key, &usage_constant(usage, 0x99))?);
        Ok(kdf::cmac(self, &key, &[data])?.to_vec())
    }

    /// Verify a checksum in constant time.
    #[inline]
    #[must_use]
    pub fn verify_checksum(
        self,
        protocol_key: &[u8],
        data: &[u8],
        checksum: &[u8],
        usage: u32,
    ) -> bool {
        self.derive_key(protocol_key, &usage_constant(usage, 0x99))
            .is_ok_and(|key| kdf::verify(self, &SecretScratch::new(key), data, checksum))
    }

    /// CBC-CTS encrypt `plaintext` with a zero IV; returns `(next_iv, ciphertext)`.
    ///
    /// # Errors
    /// Returns [`Error::InvalidKeyLength`] or [`Error::EmptyPlaintext`].
    #[inline]
    pub fn encrypt_data(self, key: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
        cts::encrypt(self, key, plaintext)
    }

    /// CBC-CTS decrypt `ciphertext` with a zero IV.
    ///
    /// # Errors
    /// Returns [`Error::InvalidKeyLength`] or [`Error::CiphertextTooShort`].
    #[inline]
    pub fn decrypt_data(self, key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        cts::decrypt(self, key, ciphertext)
    }

    /// Encrypt `confounder | message` under `Ke` and append the CMAC under `Ki`.
    ///
    /// # Errors
    /// Returns [`Error::InvalidKeyLength`] or [`Error::InvalidConfounderLength`].
    #[inline]
    pub fn encrypt_message_with_confounder(
        self,
        protocol_key: &[u8],
        message: &[u8],
        usage: u32,
        confounder: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if confounder.len() != CONFOUNDER_SIZE {
            return Err(Error::InvalidConfounderLength {
                expected: CONFOUNDER_SIZE,
                actual: confounder.len(),
            });
        }
        let plain = SecretScratch::new([confounder, message].concat());
        let ke = SecretScratch::new(self.derive_key(protocol_key, &usage_constant(usage, 0xaa))?);
        let (_, mut encrypted) = self.encrypt_data(&ke, &plain)?;
        let ki = SecretScratch::new(self.derive_key(protocol_key, &usage_constant(usage, 0x55))?);
        encrypted.extend_from_slice(&kdf::cmac(self, &ki, &[&plain])?);
        Ok(encrypted)
    }

    /// Decrypt a message and verify its CMAC in constant time.
    ///
    /// # Errors
    /// Returns [`Error::InvalidKeyLength`], [`Error::CiphertextTooShort`] for less than a
    /// confounder and a CMAC, and [`Error::IntegrityCheckFailed`].
    #[inline]
    pub fn decrypt_message(
        self,
        protocol_key: &[u8],
        ciphertext: &[u8],
        usage: u32,
    ) -> Result<Vec<u8>, Error> {
        let (encrypted, mac) = split_trailing_mac(
            ciphertext,
            CMAC_SIZE,
            CMAC_SIZE.saturating_add(CONFOUNDER_SIZE),
        )?;
        let ke = SecretScratch::new(self.derive_key(protocol_key, &usage_constant(usage, 0xaa))?);
        let plain =
            SecretScratch::for_purpose(self.decrypt_data(&ke, encrypted)?, Purpose::Plaintext);
        let message = strip_confounder(&plain, CONFOUNDER_SIZE)?;
        let ki = SecretScratch::new(self.derive_key(protocol_key, &usage_constant(usage, 0x55))?);
        if !kdf::verify(self, &ki, &plain, mac) {
            return Err(Error::IntegrityCheckFailed);
        }
        Ok(message.to_vec())
    }

    /// `Kp = KDF-FEEDBACK-CMAC(protocol_key, "prf")`, the key of the RFC 6803 PRF.
    ///
    /// # Errors
    /// Returns [`Error::InvalidKeyLength`] for a key of the wrong size.
    pub(crate) fn prf_subkey(self, protocol_key: &[u8]) -> Result<Vec<u8>, Error> {
        self.derive_key(protocol_key, b"prf")
    }

    /// `PRF = CMAC(Kp, input)`, 16 bytes.
    ///
    /// # Errors
    /// Returns [`Error::InvalidKeyLength`] when `subkey` has the wrong size.
    pub(crate) fn prf_block(self, subkey: &[u8], input: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(kdf::cmac(self, subkey, &[input])?.to_vec())
    }
}

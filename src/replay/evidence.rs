//! Construction of the evidence a store is asked about.

use core::time::Duration;
use std::time::SystemTime;

use super::{Evidence, Presentation, TAG_LEN, Tag};
use crate::{
    crypto::{KerberosEtype, selection},
    service::Principal,
};

impl Tag {
    /// The tag of a checksum: truncated, or right-padded with zero bytes, to
    /// [`TAG_LEN`] bytes (MIT `rc_file2.c:211-218`).
    #[must_use]
    #[inline]
    pub fn from_checksum(checksum: &[u8]) -> Self {
        let mut bytes = [0_u8; TAG_LEN];
        for (slot, byte) in bytes.iter_mut().zip(checksum) {
            *slot = *byte;
        }
        Self { bytes }
    }

    /// The tag of an authenticator ciphertext whose checksum is its last
    /// `checksum_len` bytes (MIT `rc_base.c:k5_rc_tag_from_ciphertext`), or
    /// `None` when the ciphertext is shorter than its checksum (MIT `EINVAL`).
    #[must_use]
    #[inline]
    pub fn from_ciphertext(ciphertext: &[u8], checksum_len: usize) -> Option<Self> {
        let start = ciphertext.len().checked_sub(checksum_len)?;
        ciphertext.get(start..).map(Self::from_checksum)
    }

    /// The tag of an AP-REQ authenticator: its checksum is the last
    /// `hmac_len` bytes of the ciphertext of its enctype. A ciphertext shorter
    /// than that, which no successful decryption yields, uses all of itself.
    #[must_use]
    #[inline]
    pub fn from_authenticator(etype: i32, ciphertext: &[u8]) -> Self {
        let checksum_len = selection::enctype(etype)
            .ok()
            .flatten()
            .map_or(TAG_LEN, KerberosEtype::hmac_len);
        Self::from_ciphertext(ciphertext, checksum_len)
            .unwrap_or_else(|| Self::from_checksum(ciphertext))
    }

    /// The twelve tag bytes.
    #[must_use]
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; TAG_LEN] {
        &self.bytes
    }
}

impl Presentation {
    /// Name the authenticator by its RFC 4120 section 3.2.3 replay key.
    #[must_use]
    #[inline]
    pub const fn new(
        service: Principal,
        client: Principal,
        ctime_seconds: i64,
        cusec: u32,
    ) -> Self {
        Self {
            service,
            client,
            ctime_seconds,
            cusec,
        }
    }
}

impl Evidence {
    /// Evidence for one authenticator, validated at the Unix epoch with no skew
    /// until [`Self::with_window`] sets the real time and window.
    #[must_use]
    #[inline]
    pub const fn new(tag: Tag, digest: [u8; 32], presentation: Presentation) -> Self {
        Self {
            tag,
            digest,
            presentation,
            presented_at: SystemTime::UNIX_EPOCH,
            skew: Duration::ZERO,
        }
    }

    /// Set the validation time and the validator's accepted clock skew.
    #[must_use]
    #[inline]
    pub const fn with_window(mut self, presented_at: SystemTime, skew: Duration) -> Self {
        self.presented_at = presented_at;
        self.skew = skew;
        self
    }
}

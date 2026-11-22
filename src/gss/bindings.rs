//! The channel-binding digest.
//!
//! The RFC 4121 section 4.1.1.2 channel-binding digest (MIT
//! `kg_checksum_channel_bindings`, `util_cksum.c:30-76`).

use md5::{Digest as _, Md5};

use super::{ChannelBindings, Error};

/// The longest application data, in bytes.
pub(super) const MAX_DATA: usize = 0x1_0000;
/// The longest address, in bytes.
pub(super) const MAX_ADDRESS: usize = 0xff;

/// Refuse a field longer than `maximum`.
///
/// # Errors
///
/// Returns [`Error::BindingTooLong`].
pub(super) const fn check(field: &'static str, value: &[u8], maximum: usize) -> Result<(), Error> {
    if value.len() > maximum {
        return Err(Error::BindingTooLong {
            field,
            maximum,
            actual: value.len(),
        });
    }
    Ok(())
}

/// The little-endian 32-bit length of a bounded field.
fn length(value: &[u8]) -> [u8; 4] {
    u32::try_from(value.len()).unwrap_or(u32::MAX).to_le_bytes()
}

/// MD5 over the initiator address, the acceptor address and the application
/// data, each type and length as a little-endian 32-bit word.
pub(super) fn digest(bindings: &ChannelBindings) -> [u8; 16] {
    let mut hash = Md5::new();
    hash.update(bindings.initiator_address_type.to_le_bytes());
    hash.update(length(&bindings.initiator_address));
    hash.update(&bindings.initiator_address);
    hash.update(bindings.acceptor_address_type.to_le_bytes());
    hash.update(length(&bindings.acceptor_address));
    hash.update(&bindings.acceptor_address);
    hash.update(length(&bindings.application_data));
    hash.update(&bindings.application_data);
    hash.finalize().into()
}

/// Whether two digests are equal, in time independent of where they differ.
pub(super) fn same(left: &[u8; 16], right: &[u8; 16]) -> bool {
    left.iter()
        .zip(right)
        .fold(0_u8, |differ, (one, other)| differ | (one ^ other))
        == 0
}

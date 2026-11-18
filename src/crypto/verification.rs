//! Audited HMAC verification with independent public tag-length checks.

use hmac::{Hmac, KeyInit as _, Mac as _};
use md5::{Digest as _, Md5};
use sha1::Sha1;
use sha2::{Sha256, Sha384};
use zeroize::Zeroize as _;

use super::{
    AesSha2Etype, KerberosEtype, SecretScratch, hmac_md5, rc4_hmac_usage_to_ms_msg_type,
    usage_constant,
};

/// Verify a family's keyed checksum at the common authentication boundary.
pub(super) fn verify_checksum(
    etype: KerberosEtype,
    protocol_key: &[u8],
    data: &[u8],
    checksum: &[u8],
    usage: u32,
) -> bool {
    if protocol_key.len() != etype.key_len() || checksum.len() != etype.hmac_len() {
        return false;
    }
    match etype {
        KerberosEtype::Sha1(family) => family
            .derive_key(protocol_key, &usage_constant(usage, 0x99))
            .is_ok_and(|key| sha1(&SecretScratch::new(key), data, checksum, 12)),
        KerberosEtype::Sha2(family) => family
            .derive_key(protocol_key, &usage_constant(usage, 0x99))
            .is_ok_and(|key| sha2(family, &SecretScratch::new(key), &[data], checksum)),
        KerberosEtype::Des3CbcSha1Kd(_) => {
            super::Des3CbcSha1KdEtype::derive_key(protocol_key, &usage_constant(usage, 0x99))
                .is_ok_and(|key| sha1(&SecretScratch::new(key), data, checksum, 20))
        }
        KerberosEtype::Camellia(family) => {
            family.verify_checksum(protocol_key, data, checksum, usage)
        }
        KerberosEtype::Rc4Hmac(_) => {
            let signing_key =
                SecretScratch::new(hmac_md5(protocol_key, super::RC4_HMAC_SIGNATURE_KEY));
            let mut digest = Md5::new();
            digest.update(rc4_hmac_usage_to_ms_msg_type(usage));
            digest.update(data);
            let mut hash = digest.finalize();
            let valid = md5(&signing_key, &hash, checksum);
            hash.as_mut_slice().zeroize();
            valid
        }
    }
}

/// Verify SHA1 tags with exactly the protocol's public tag length.
pub(super) fn sha1(key: &[u8], data: &[u8], tag: &[u8], length: usize) -> bool {
    tag.len() == length
        && Hmac::<Sha1>::new_from_slice(key).is_ok_and(|mut mac| {
            mac.update(data);
            if length == 20 {
                mac.verify_slice(tag).is_ok()
            } else {
                mac.verify_truncated_left(tag).is_ok()
            }
        })
}

/// Verify RFC8009's exact truncated tag over one or more byte slices.
pub(super) fn sha2(etype: AesSha2Etype, key: &[u8], parts: &[&[u8]], tag: &[u8]) -> bool {
    if tag.len() != etype.hmac_len() {
        return false;
    }
    match etype {
        AesSha2Etype::Aes128 => Hmac::<Sha256>::new_from_slice(key).is_ok_and(|mut mac| {
            for part in parts {
                mac.update(part);
            }
            mac.verify_truncated_left(tag).is_ok()
        }),
        AesSha2Etype::Aes256 => Hmac::<Sha384>::new_from_slice(key).is_ok_and(|mut mac| {
            for part in parts {
                mac.update(part);
            }
            mac.verify_truncated_left(tag).is_ok()
        }),
    }
}

/// Verify RFC4757's full sixteen-byte MD5 HMAC tag.
pub(super) fn md5(key: &[u8], data: &[u8], tag: &[u8]) -> bool {
    Hmac::<Md5>::new_from_slice(key).is_ok_and(|mut mac| {
        mac.update(data);
        mac.verify_slice(tag).is_ok()
    })
}

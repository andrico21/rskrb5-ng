//! The SipHash-2-4 reference vectors (Aumasson and Bernstein, "SipHash: a fast short-input PRF", appendix A).

use super::siphash24;

/// The key of the reference vectors: bytes 0 to 15.
const KEY: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

/// Pins the published outputs for the empty input and the 15-byte input of the paper.
#[test]
fn reference_vectors_hold() -> Result<(), core::convert::Infallible> {
    assert_eq!(siphash24(&[], &KEY), 0x726f_db47_dd0e_0e31);
    assert_eq!(
        siphash24(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14], &KEY),
        0xa129_ca61_49be_45e5
    );
    Ok(())
}

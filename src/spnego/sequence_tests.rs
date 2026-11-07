//! Deterministic entropy range checks.

/// Full-width entropy is reduced to the low thirty bits without becoming a constant.
#[test]
fn sequence_entropy_is_masked() -> Result<(), super::Error> {
    assert_eq!(
        super::random_sequence_number(|bytes| {
            bytes.copy_from_slice(&0xffff_ffff_u32.to_be_bytes());
            Ok(())
        })?,
        0x3fff_ffff
    );
    assert_eq!(
        super::random_sequence_number(|bytes| {
            bytes.copy_from_slice(&42_u32.to_be_bytes());
            Ok(())
        })?,
        42
    );
    Ok(())
}

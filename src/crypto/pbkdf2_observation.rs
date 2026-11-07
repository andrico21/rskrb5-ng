//! Observe real primitive entry without replacing cryptographic work.
use core::cell::Cell;

std::thread_local! {
    /// PBKDF2 calls on this test thread only.
    static CALLS: Cell<usize> = const { Cell::new(0) };
}

/// Record entry immediately before the real PBKDF2 implementation.
pub(crate) fn record() {
    CALLS.with(|count| count.set(count.get().saturating_add(1)));
}

/// Read and reset this thread's observation count.
pub(crate) fn take() -> usize {
    CALLS.with(|count| count.replace(0))
}

/// Raw RFC vector APIs intentionally retain low-count support without peer policy.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error::Error;

    use crate::crypto::AesSha1Etype;

    /// Checked derivation enforces default and trusted floors before primitive entry.
    #[test]
    fn checked_derivation_enforces_floors_before_pbkdf2() -> Result<(), Box<dyn Error>> {
        use crate::{
            config::LibDefaults,
            crypto::{CryptoPolicy, checked, s2k::Family},
            error,
        };
        for (id, family, default) in [
            (17_i32, Family::AesSha1, 4096_u32),
            (18, Family::AesSha1, 4096),
            (19, Family::AesSha2, 32768),
            (20, Family::AesSha2, 32768),
        ] {
            for minimum in [default, default.saturating_add(1), 1] {
                let defaults = LibDefaults::new().with_min_s2k_iterations(family, minimum)?;
                let policy = CryptoPolicy::from_libdefaults(&defaults)?;
                let etype = checked::Etype::new(&policy, id)?;
                if minimum > 1 {
                    let actual = minimum.checked_sub(1).ok_or("minimum")?;
                    let _prior = super::take();
                    let result =
                        etype.string_to_key(b"password", b"salt", &format!("{actual:08x}"));
                    assert_eq!(
                        super::take(),
                        0,
                        "checked boundary entered PBKDF2 below floor"
                    );
                    assert_eq!(
                        result,
                        Err(error::Crypto::Policy(error::Policy::S2kIterationsTooLow {
                            etype: id,
                            minimum,
                            actual
                        }))
                    );
                }
                let _prior = super::take();
                let key = etype.string_to_key(b"password", b"salt", &format!("{minimum:08x}"))?;
                assert_eq!(super::take(), 1);
                assert!(!key.is_empty(), "floor produces a key");
            }
        }
        Ok(())
    }

    /// Observe actual raw work while preserving the low-count vector contract.
    #[test]
    fn raw_vector_still_derives_at_one() -> Result<(), Box<dyn Error>> {
        // Given a raw RFC-vector call rather than KDC-derived parameters.
        let _prior = super::take();
        // When executing the real primitive at one iteration.
        let key = AesSha1Etype::Aes128.string_to_key(b"password", b"salt", "00000001")?;
        // Then the observation is live and raw derivation is unchanged.
        assert_eq!(super::take(), 1);
        assert_eq!(key.len(), 16);
        Ok(())
    }
}

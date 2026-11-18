//! Kerberos PRF primitives: PRF+ of RFC 6113 (`fast_prf_plus`, `krb_fx_cf2`) and RFC 4402 (`gss_prf_plus`).
//!
//! The vectors are MIT krb5 1.22.2's own tests and fixtures from MIT's libk5crypto
//! (`tests/crypto_prf/vectors.rs` names each source). The two PRF+ counters are different
//! functions and carry different vectors.

/// The PRF+ tests.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error;

    use pretty_assertions::assert_eq;
    use rskrb5_ng::{
        crypto::{
            KerberosEtype,
            prf::{self, CfInput, Key},
        },
        error::Crypto as Error,
    };

    /// Error type of the `Result`-returning tests.
    type TestError = Box<dyn error::Error>;

    include!("crypto_prf/vectors.rs");

    /// The 61-byte input of `src/tests/gssapi/t_prf.c`.
    const GSS_INPUT: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz123456789";

    /// Resolve an implemented etype.
    fn etype(id: i32) -> Result<KerberosEtype, TestError> {
        KerberosEtype::from_etype_id(id).ok_or_else(|| format!("etype {id} not implemented").into())
    }

    /// Derive the key of a `t_cf2.in` passphrase with the default parameters.
    fn s2k_key(etype: KerberosEtype, pass: &str) -> Result<Vec<u8>, TestError> {
        Ok(etype.string_to_key(pass.as_bytes(), pass.as_bytes(), etype.default_s2kparams())?)
    }

    /// MIT's raw `krb5_c_prf` vectors.
    #[test]
    fn matches_mit_raw_prf_vectors() -> Result<(), TestError> {
        for RawPrfVector {
            etype: id,
            key,
            input,
            expected,
        } in RAW
        {
            let material = hex::decode(key)?;
            let out = prf::pseudo_random(&Key::new(etype(*id)?, &material), &hex::decode(input)?)?;
            assert_eq!(hex::encode(&*out), *expected, "etype {id}");
        }
        Ok(())
    }

    /// MIT's `gss_pseudo_random` vectors: RFC 4402 counters from zero, 44 bytes.
    #[test]
    fn gss_prf_plus_matches_mit_gss_vectors() -> Result<(), TestError> {
        for GssVector {
            etype: id,
            key1,
            out1,
            key2,
            out2,
        } in GSS
        {
            let (first, second) = (hex::decode(key1)?, hex::decode(key2)?);
            let empty = prf::gss_prf_plus(&Key::new(etype(*id)?, &first), b"", 44)?;
            assert_eq!(hex::encode(&*empty), *out1, "etype {id} empty input");
            let full = prf::gss_prf_plus(&Key::new(etype(*id)?, &second), GSS_INPUT, 44)?;
            assert_eq!(hex::encode(&*full), *out2, "etype {id} 61-byte input");
        }
        Ok(())
    }

    /// MIT's `t_cf2` vectors: RFC 6113 section 5.1 with counters from one.
    #[test]
    fn krb_fx_cf2_matches_mit_t_cf2() -> Result<(), TestError> {
        for CfS2kVector {
            etype: id,
            pass1,
            pass2,
            pepper1,
            pepper2,
            expected,
        } in CF2_MIT
        {
            let kind = etype(*id)?;
            let (first, second) = (s2k_key(kind, pass1)?, s2k_key(kind, pass2)?);
            let out = prf::krb_fx_cf2(
                &CfInput::new(Key::new(kind, &first), pepper1.as_bytes()),
                &CfInput::new(Key::new(kind, &second), pepper2.as_bytes()),
            )?;
            assert_eq!(hex::encode(&*out), *expected, "etype {id}");
        }
        Ok(())
    }

    /// `krb5_c_prfplus` of libk5crypto, several lengths per etype.
    #[test]
    fn fast_prf_plus_matches_libk5crypto() -> Result<(), TestError> {
        for PlusVector {
            etype: id,
            key,
            input,
            len,
            expected,
        } in PLUS
        {
            let material = hex::decode(key)?;
            let out = prf::fast_prf_plus(
                &Key::new(etype(*id)?, &material),
                &hex::decode(input)?,
                *len,
            )?;
            assert_eq!(hex::encode(&*out), *expected, "etype {id} len {len}");
        }
        Ok(())
    }

    /// `krb5_c_fx_cf2_simple` of libk5crypto with explicit keys.
    #[test]
    fn krb_fx_cf2_matches_libk5crypto() -> Result<(), TestError> {
        for CfVector {
            etype: id,
            key1,
            key2,
            pepper1,
            pepper2,
            expected,
        } in CF2_HOST
        {
            let (kind, first, second) = (etype(*id)?, hex::decode(key1)?, hex::decode(key2)?);
            let out = prf::krb_fx_cf2(
                &CfInput::new(Key::new(kind, &first), pepper1.as_bytes()),
                &CfInput::new(Key::new(kind, &second), pepper2.as_bytes()),
            )?;
            assert_eq!(hex::encode(&*out), *expected, "etype {id}");
        }
        Ok(())
    }

    /// The two PRF+ functions differ in counter width and origin, block by block.
    #[test]
    fn counters_differ_between_rfc6113_and_rfc4402() -> Result<(), TestError> {
        // Given an AES-SHA1 key, whose PRF has 16 output bytes.
        let material = vec![0x42; 16];
        let key = Key::new(etype(17)?, &material);
        let input = b"counter";
        // When both functions produce two blocks.
        let fast = prf::fast_prf_plus(&key, input, 32)?;
        let gss = prf::gss_prf_plus(&key, input, 32)?;
        // Then RFC 6113 prepends the one-octet counters 1 and 2.
        for (index, block) in fast.chunks(16).enumerate() {
            let one_octet = [&[u8::try_from(index + 1)?][..], input].concat();
            assert_eq!(block, &*prf::pseudo_random(&key, &one_octet)?);
        }
        // And RFC 4402 prepends the four-octet big-endian counters 0 and 1.
        for (index, block) in gss.chunks(16).enumerate() {
            let four_octets = [&u32::try_from(index)?.to_be_bytes()[..], input].concat();
            assert_eq!(block, &*prf::pseudo_random(&key, &four_octets)?);
        }
        assert_ne!(fast, gss);
        Ok(())
    }

    /// A partial final block is truncated, an empty request is empty.
    #[test]
    fn output_lengths_are_exact() -> Result<(), TestError> {
        let material = vec![7; 32];
        let key = Key::new(etype(18)?, &material);
        for len in [0, 1, 15, 16, 17, 33] {
            assert_eq!(prf::fast_prf_plus(&key, b"x", len)?.len(), len);
            assert_eq!(prf::gss_prf_plus(&key, b"x", len)?.len(), len);
        }
        Ok(())
    }

    /// RFC 6113's one-octet counter ends at 255 blocks; RFC 4402's output is bounded locally.
    #[test]
    fn output_limits_are_rejected() -> Result<(), TestError> {
        let material = vec![7; 16];
        let key = Key::new(etype(17)?, &material);
        let longest = 255 * prf::output_len(etype(17)?);
        assert_eq!(prf::fast_prf_plus(&key, b"x", longest)?.len(), longest);
        assert_eq!(
            prf::fast_prf_plus(&key, b"x", longest + 1).err(),
            Some(Error::PrfOutputTooLong {
                maximum: longest,
                requested: longest + 1
            })
        );
        assert_eq!(
            prf::gss_prf_plus(&key, b"x", prf::GSS_PRF_PLUS_MAX_OUTPUT + 1).err(),
            Some(Error::PrfOutputTooLong {
                maximum: prf::GSS_PRF_PLUS_MAX_OUTPUT,
                requested: prf::GSS_PRF_PLUS_MAX_OUTPUT + 1,
            })
        );
        Ok(())
    }

    /// A key of the wrong length is refused before any output exists.
    #[test]
    fn wrong_key_length_is_rejected() -> Result<(), TestError> {
        /// Etype ID and a key length the etype does not have.
        const CASES: [(i32, usize); 6] =
            [(17, 15), (18, 16), (19, 32), (20, 16), (23, 17), (16, 21)];
        for (id, bad) in CASES {
            let key = vec![1; bad];
            let kind = etype(id)?;
            let expected = Error::InvalidKeyLength {
                expected: kind.key_len(),
                actual: bad,
            };
            assert_eq!(
                prf::pseudo_random(&Key::new(kind, &key), b"in").err(),
                Some(expected)
            );
            assert_eq!(
                prf::fast_prf_plus(&Key::new(kind, &key), b"in", 8).err(),
                Some(expected)
            );
            assert_eq!(
                prf::gss_prf_plus(&Key::new(kind, &key), b"in", 8).err(),
                Some(expected)
            );
        }
        Ok(())
    }

    /// The combined key has the first key's etype; a mixed pair is accepted.
    #[test]
    fn cf2_output_follows_the_first_key() -> Result<(), TestError> {
        let (short, long) = (vec![3; 16], vec![4; 32]);
        let out = prf::krb_fx_cf2(
            &CfInput::new(Key::new(etype(17)?, &short), b"a"),
            &CfInput::new(Key::new(etype(18)?, &long), b"b"),
        )?;
        assert_eq!(out.len(), 16);
        Ok(())
    }

    /// The Debug output of a key view never shows key bytes.
    #[test]
    fn prf_key_debug_is_redacted() -> Result<(), TestError> {
        let key = vec![0xab; 16];
        let shown = format!("{:?}", Key::new(etype(17)?, &key));
        assert!(
            !shown.contains("171") && !shown.to_lowercase().contains("ab"),
            "{shown}"
        );
        Ok(())
    }
}

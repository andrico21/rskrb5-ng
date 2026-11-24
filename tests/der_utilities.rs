//! The public checked DER length and application-tag utilities (`rskrb5_ng::asn1`).

/// Turns `Option` and `Result` failures into test errors.
#[path = "support/context.rs"]
mod context;

/// DER utility tests.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod der_utilities {
    use rskrb5_ng::{
        asn1::{
            Class, Limits, add_application_tag, application_tag, decode_length, encode_length,
            read_complete, read_element, validate,
        },
        error::Der,
    };

    use crate::context::{Context as _, TestError};

    /// The gokrb5 AP-REQ fixture: an `[APPLICATION 14]` with a two-byte length.
    const AP_REQ: &[u8] = include_bytes!("fixtures/valid_ap_req.der");

    /// Pins the minimal definite encodings at the length boundaries.
    #[test]
    fn lengths_encode_minimally() -> Result<(), TestError> {
        assert_eq!(encode_length(0), [0x00]);
        assert_eq!(encode_length(127), [0x7f]);
        assert_eq!(encode_length(128), [0x81, 0x80]);
        assert_eq!(encode_length(255), [0x81, 0xff]);
        assert_eq!(encode_length(256), [0x82, 0x01, 0x00]);
        assert_eq!(encode_length(0xffff), [0x82, 0xff, 0xff]);
        assert_eq!(encode_length(0x1_0000), [0x83, 0x01, 0x00, 0x00]);
        let limits = Limits::new();
        for length in [0_usize, 1, 127, 128, 255, 256, 0xffff, 0x1_0000] {
            let encoded = encode_length(length);
            let (decoded, consumed) =
                decode_length(&encoded, &Limits::new().with_max_length(0x10_0000))?;
            assert_eq!((decoded, consumed), (length, encoded.len()));
        }
        assert!(limits.max_length() > 0);
        Ok(())
    }

    /// Pins that every non-canonical length is refused, each with its own error.
    #[test]
    fn non_canonical_lengths_are_refused() -> Result<(), TestError> {
        let limits = Limits::new();
        assert_eq!(decode_length(&[0x05], &limits)?, (5, 1));
        assert!(matches!(
            decode_length(&[0x80], &limits),
            Err(Der::IndefiniteLength)
        ));
        assert!(matches!(
            decode_length(&[0xff], &limits),
            Err(Der::ReservedLength)
        ));
        assert!(matches!(
            decode_length(&[0x81, 0x7f], &limits),
            Err(Der::NonMinimalLength)
        ));
        assert!(matches!(
            decode_length(&[0x82, 0x00, 0xff], &limits),
            Err(Der::NonMinimalLength)
        ));
        assert!(matches!(
            decode_length(&[0x82, 0x01], &limits),
            Err(Der::Truncated)
        ));
        assert!(matches!(decode_length(&[], &limits), Err(Der::Truncated)));
        Ok(())
    }

    /// Pins that a length above the budget is refused before any content is read.
    #[test]
    fn lengths_are_bounded_by_the_budget() -> Result<(), TestError> {
        let small = Limits::new().with_max_length(100);
        assert_eq!(decode_length(&[0x64], &small)?, (100, 1));
        assert!(matches!(
            decode_length(&[0x65], &small),
            Err(Der::LengthTooLarge { limit: 100 })
        ));
        let huge = [0x88, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        assert!(matches!(
            decode_length(&huge, &Limits::new()),
            Err(Der::LengthTooLarge { limit: _ })
        ));
        Ok(())
    }

    /// Pins reading one element and its remainder, and refusing content past the input.
    #[test]
    fn elements_split_content_and_rest() -> Result<(), TestError> {
        let input = [0x30, 0x03, 0x02, 0x01, 0x05, 0xaa];
        let (element, rest) = read_element(&input, &Limits::new())?;
        assert_eq!(element.identifier().class(), Class::Universal);
        assert!(element.identifier().is_constructed());
        assert_eq!(element.identifier().number(), 16);
        assert_eq!(element.content(), [0x02, 0x01, 0x05]);
        assert_eq!(rest, [0xaa]);
        assert!(matches!(
            read_complete(&input, &Limits::new()),
            Err(Der::TrailingData)
        ));
        assert_eq!(
            read_complete(&input[..5], &Limits::new())?.content(),
            [0x02, 0x01, 0x05]
        );
        assert!(matches!(
            read_element(&[0x30, 0x05, 0x01], &Limits::new()),
            Err(Der::Truncated)
        ));
        Ok(())
    }

    /// Pins the application tag of a real AP-REQ and its re-encoding byte for byte.
    #[test]
    fn application_tags_round_trip_on_a_real_message() -> Result<(), TestError> {
        let (number, content) = application_tag(AP_REQ, &Limits::new())?;
        assert_eq!(number, 14);
        assert_eq!(content.len(), 0x1f8);
        assert_eq!(add_application_tag(14, content), AP_REQ);
        Ok(())
    }

    /// Pins the high tag number form: minimal only.
    #[test]
    fn high_tag_numbers_are_minimal() -> Result<(), TestError> {
        let (number, content) = application_tag(&[0x7f, 0x20, 0x01, 0x00], &Limits::new())?;
        assert_eq!((number, content), (32, &[0x00_u8][..]));
        assert_eq!(add_application_tag(32, &[0x00]), [0x7f, 0x20, 0x01, 0x00]);
        assert!(matches!(
            application_tag(&[0x7f, 0x1e, 0x00], &Limits::new()),
            Err(Der::NonMinimalTag)
        ));
        assert!(matches!(
            application_tag(&[0x7f, 0x80, 0x20, 0x00], &Limits::new()),
            Err(Der::NonMinimalTag)
        ));
        assert!(matches!(
            application_tag(&[0x30, 0x00], &Limits::new()),
            Err(Der::NotApplication)
        ));
        Ok(())
    }

    /// Pins that a whole structure is walked under the nesting budget, and that a bad length deep inside is found.
    #[test]
    fn validate_walks_nested_structures_under_a_depth_budget() -> Result<(), TestError> {
        let nested = [0x30, 0x06, 0x30, 0x04, 0x30, 0x02, 0x02, 0x00];
        validate(&nested, &Limits::new())?;
        assert!(matches!(
            validate(&nested, &Limits::new().with_max_depth(2)),
            Err(Der::TooDeep { limit: 2 })
        ));
        let sloppy = [0x30, 0x04, 0x04, 0x81, 0x01, 0xaa];
        assert!(matches!(
            validate(&sloppy, &Limits::new()),
            Err(Der::NonMinimalLength)
        ));
        validate(AP_REQ, &Limits::new()).context("the AP-REQ fixture is canonical")?;
        Ok(())
    }
}

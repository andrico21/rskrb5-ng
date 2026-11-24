/// Checked DER utility error ([`crate::asn1`]): the input is not canonical DER
/// or exceeds the caller's budget.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Der {
    /// The input ends inside an element.
    #[error("the DER input is truncated")]
    Truncated,
    /// A length of `0x80`: indefinite lengths are not DER.
    #[error("indefinite lengths are not DER")]
    IndefiniteLength,
    /// A length octet of `0xFF`, reserved by X.690.
    #[error("the length octet 0xFF is reserved")]
    ReservedLength,
    /// A length not in its shortest form: a long form for a value below 128,
    /// or a leading zero octet.
    #[error("the DER length is not minimal")]
    NonMinimalLength,
    /// A length above the budget.
    #[error("the DER length exceeds the limit of {limit} bytes")]
    LengthTooLarge {
        /// The budget.
        limit: usize,
    },
    /// A tag number not in its shortest form.
    #[error("the DER tag number is not minimal")]
    NonMinimalTag,
    /// A tag number that does not fit 32 bits.
    #[error("the DER tag number is too large")]
    TagTooLarge,
    /// An element nested deeper than the budget.
    #[error("the DER nesting exceeds the limit of {limit} levels")]
    TooDeep {
        /// The budget.
        limit: usize,
    },
    /// Bytes remain after a complete element.
    #[error("trailing data follows the DER element")]
    TrailingData,
    /// The element is not in the application class.
    #[error("the DER element is not an application-tagged element")]
    NotApplication,
}

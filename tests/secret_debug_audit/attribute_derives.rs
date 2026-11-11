//! Reviewed derive consumers for credential inventory admission.

/// These implementations do not append independent storage owners.
pub(super) const DERIVES: &[&str] = &[
    "Clone",
    "Copy",
    "Debug",
    "Default",
    "Eq",
    "PartialEq",
    "Ord",
    "PartialOrd",
    "Hash",
    "core::fmt::Debug",
    "std::fmt::Debug",
    "serde::Serialize",
    "serde::Deserialize",
    "thiserror::Error",
    "zeroize::Zeroize",
    "zeroize::ZeroizeOnDrop",
    "rasn::AsnType",
    "rasn::Encode",
    "rasn::Decode",
];

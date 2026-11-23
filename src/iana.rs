//! Public tables of the Kerberos assigned numbers, with lookup both ways.
//!
//! [`encryption_type`], [`checksum_type`], [`padata_type`] (pre-authentication
//! and typed data), [`fast_armor_type`], [`fast_option`], [`transport_type`],
//! [`second_factor_type`] and [`spake_group`] are the registries IANA hosts
//! under `Kerberos Parameters`, copied from the revision **Last Updated
//! 2024-12-06**. IANA hosts no registry for the numbers RFC 4120 assigns itself:
//! [`message_type`], [`name_type`], [`address_type`], [`authorization_data_type`]
//! and [`error_code`] are read from MIT krb5 1.22.2 (`krb5.hin`, `krb5_err.et`)
//! plus the RFC 4120 values MIT does not define; each entry's
//! [`Entry::reference`] names its source.
//!
//! Each registry is a module of named `i32` constants and a
//! `REGISTRY` table; the tables answer `name(number)` and `number(name)`.
//!
//! # Security
//!
//! A number in these tables is only a name for the number. Listing a
//! deprecated or removed algorithm (single DES, RC4 export, ...) never enables
//! it: runtime permission is [`crate::crypto::CryptoPolicy`], and the permanent
//! rejections of `docs/security-policy.md` still apply.

pub mod address_type;
pub mod authorization_data_type;
pub mod checksum_type;
pub mod encryption_type;
pub mod error_code;
pub mod fast_armor_type;
pub mod fast_option;
pub mod message_type;
pub mod name_type;
pub mod padata_type;
pub mod second_factor_type;
pub mod spake_group;
pub mod transport_type;

/// One assigned number of a registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Entry {
    /// The assigned number.
    number: i32,
    /// The registered name, without a deprecation note.
    name: &'static str,
    /// Where the assignment comes from.
    reference: &'static str,
    /// Whether the registry marks the entry deprecated.
    deprecated: bool,
}

/// A registry: its title and every assigned number, in ascending order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Registry {
    /// The registry title.
    title: &'static str,
    /// The assigned numbers; reserved and unassigned numbers have no entry.
    entries: &'static [Entry],
}

impl Entry {
    /// An entry of a table.
    #[must_use]
    #[inline]
    pub const fn new(
        number: i32,
        name: &'static str,
        reference: &'static str,
        deprecated: bool,
    ) -> Self {
        Self {
            number,
            name,
            reference,
            deprecated,
        }
    }

    /// The assigned number.
    #[must_use]
    #[inline]
    pub const fn number(&self) -> i32 {
        self.number
    }

    /// The registered name.
    #[must_use]
    #[inline]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// The RFC, or the MIT source and message text, the assignment comes from.
    #[must_use]
    #[inline]
    pub const fn reference(&self) -> &'static str {
        self.reference
    }

    /// Whether the registry marks the entry deprecated.
    #[must_use]
    #[inline]
    pub const fn is_deprecated(&self) -> bool {
        self.deprecated
    }
}

impl Registry {
    /// A registry over `entries`.
    #[must_use]
    #[inline]
    pub const fn new(title: &'static str, entries: &'static [Entry]) -> Self {
        Self { title, entries }
    }

    /// The registry title.
    #[must_use]
    #[inline]
    pub const fn title(&self) -> &'static str {
        self.title
    }

    /// Every assigned number, in ascending order.
    #[must_use]
    #[inline]
    pub const fn entries(&self) -> &'static [Entry] {
        self.entries
    }

    /// The entry of `number`, if assigned. A registry may give one number two
    /// names (pre-authentication types 20 and 22): this is the first.
    #[must_use]
    #[inline]
    pub fn get(&self, number: i32) -> Option<&'static Entry> {
        self.entries.iter().find(|entry| entry.number == number)
    }

    /// The registered name of `number`, if assigned.
    #[must_use]
    #[inline]
    pub fn name(&self, number: i32) -> Option<&'static str> {
        self.get(number).map(Entry::name)
    }

    /// The number registered under `name`, compared ASCII case-insensitively.
    #[must_use]
    #[inline]
    pub fn number(&self, name: &str) -> Option<i32> {
        self.entries
            .iter()
            .find(|entry| entry.name.eq_ignore_ascii_case(name))
            .map(Entry::number)
    }
}

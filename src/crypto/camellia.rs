//! Camellia-CTS-CMAC (RFC 6803, enctypes 25 and 26, checksum types 17 and 18).
//!
//! The leaf feature `camellia` compiles the implementation; without it the type
//! `CtsCmacEtype` has no values, so
//! [`KerberosEtype::Camellia`] cannot be
//! built and every dispatch arm is unreachable. Names, wire IDs and
//! [`KerberosEtype::from_etype_id`]
//! then behave as before the leaf existed.
//!
//! # Security
//! Enabling the feature never grants runtime permission: an application still names
//! Camellia in `permitted_enctypes` (see [`crate::crypto::CryptoPolicy`]). The
//! implementation is the RustCrypto `camellia` crate, which reads secret-indexed
//! S-box tables on every round, so it is **not** constant-time on CPUs with data
//! caches (`CONSTANT_TIME`). `DEFAULT` therefore never expands to Camellia and the
//! enctypes are usable only when named explicitly. See
//! `docs/security-policy.md#camellia` and the admission record in
//! `docs/dependency-admission.md`.

#[cfg(not(feature = "camellia"))]
use core::convert::Infallible;

use super::KerberosEtype;

#[cfg(feature = "camellia")]
#[path = "camellia/cts.rs"]
mod cts;
#[cfg(not(feature = "camellia"))]
#[path = "camellia/disabled.rs"]
mod disabled;
#[cfg(feature = "camellia")]
#[path = "camellia/etype.rs"]
mod etype;
#[cfg(feature = "camellia")]
#[path = "camellia/kdf.rs"]
mod kdf;

/// Camellia-CTS-CMAC encryption type of RFC 6803.
#[cfg(feature = "camellia")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CtsCmacEtype {
    /// `camellia128-cts-cmac`, etype 25, checksum type 17.
    Camellia128,
    /// `camellia256-cts-cmac`, etype 26, checksum type 18.
    Camellia256,
}

/// Camellia-CTS-CMAC encryption type of RFC 6803; no value exists without the
/// `camellia` feature, so [`KerberosEtype::Camellia`] cannot be built.
#[cfg(not(feature = "camellia"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct CtsCmacEtype(Infallible);

/// Both enctypes in MIT's `camellia` family order: 256 first; none without the feature.
#[cfg(feature = "camellia")]
pub(crate) const ALL: &[KerberosEtype] = &[
    KerberosEtype::Camellia(CtsCmacEtype::Camellia256),
    KerberosEtype::Camellia(CtsCmacEtype::Camellia128),
];
/// `camellia128-cts-cmac` alone; none without the feature.
#[cfg(feature = "camellia")]
pub(crate) const ONLY_128: &[KerberosEtype] = &[KerberosEtype::Camellia(CtsCmacEtype::Camellia128)];
/// `camellia256-cts-cmac` alone; none without the feature.
#[cfg(feature = "camellia")]
pub(crate) const ONLY_256: &[KerberosEtype] = &[KerberosEtype::Camellia(CtsCmacEtype::Camellia256)];
/// No enctype without the feature.
#[cfg(not(feature = "camellia"))]
pub(crate) const ALL: &[KerberosEtype] = &[];
/// No enctype without the feature.
#[cfg(not(feature = "camellia"))]
pub(crate) const ONLY_128: &[KerberosEtype] = &[];
/// No enctype without the feature.
#[cfg(not(feature = "camellia"))]
pub(crate) const ONLY_256: &[KerberosEtype] = &[];

/// Whether the `camellia` leaf feature is compiled in.
pub const AVAILABLE: bool = cfg!(feature = "camellia");

/// Whether the admitted Camellia implementation is recorded as constant-time.
///
/// It is not: the `camellia` crate indexes four 256-byte S-box tables with secret
/// bytes (`camellia-0.2.1/src/utils.rs`, `f`). While this is `false`, the `DEFAULT`
/// enctype list excludes Camellia.
pub const CONSTANT_TIME: bool = false;

/// Text that names the leaf in the diagnostics of an unavailable Camellia selector.
pub(crate) const UNAVAILABLE_UNTIL: &str = "the `camellia` Cargo feature is enabled";

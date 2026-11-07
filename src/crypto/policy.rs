//! Runtime enctype permission, distinct from raw cryptographic capability.

use core::fmt;

#[cfg(feature = "serde")]
use crate::config::protocol;
use crate::{
    config::{
        EnctypeDefaults as _, EnctypeExpr, LibDefaults, ParseMode, ResolvedEnctypes, Toggle,
        restrictions,
    },
    crypto::{AesSha1Etype, AesSha2Etype, KerberosEtype},
    error,
};

/// Consumer boundary at which an encryption type is used.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Use {
    /// AS/TGS request preference list.
    RequestList,
    /// KDC reply encryption key.
    ReplyKey,
    /// Ticket session key.
    SessionKey,
    /// Ticket-encryption key.
    TicketKey,
    /// Service-side ticket acceptance.
    AcceptorTicket,
    /// Service-side authenticator subkey.
    AcceptorSubkey,
    /// Credential import or cache insertion.
    ImportedCredential,
    /// Explicitly policy-checked low-level operation.
    CheckedLowLevel,
}

impl fmt::Display for Use {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RequestList => "request list",
            Self::ReplyKey => "reply key",
            Self::SessionKey => "session key",
            Self::TicketKey => "ticket key",
            Self::AcceptorTicket => "acceptor ticket",
            Self::AcceptorSubkey => "acceptor subkey",
            Self::ImportedCredential => "imported credential",
            Self::CheckedLowLevel => "checked low-level operation",
        })
    }
}

/// Immutable runtime permission snapshot built from current `LibDefaults`.
///
/// Both permitted membership and explicit legacy flags are required. Unlike
/// MIT's KDC-side relations, `allow_rc4`/`allow_des3` apply client-side too.
/// Cargo features never grant permission. Raw RFC-vector APIs remain policy-free;
/// consumers must explicitly check the intended use before cryptographic work.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Policy {
    /// Application-trusted per-family derivation floors.
    minima: super::s2k::Minima,
    /// Ordered permitted encryption types.
    permitted: Vec<KerberosEtype>,
    /// Explicit RC4 runtime opt-in.
    allow_rc4: Toggle,
    /// Explicit DES3 runtime opt-in.
    allow_des3: Toggle,
    /// How secure unsupported selectors are handled.
    mode: ParseMode,
}

impl Policy {
    /// Minimum peer PBKDF2 iterations for an enctype; non-PBKDF2 profiles return None.
    #[inline]
    #[must_use]
    pub const fn min_s2k_iterations(&self, etype: i32) -> Option<u32> {
        self.minima.for_etype(etype)
    }

    /// Validate peer string-to-key parameters before any password derivation.
    /// # Errors
    /// Returns malformed/zero/above-maximum parameter errors, or a typed minimum rejection.
    /// The upper bound remains 2^24 even with a trusted minimum override.
    #[inline]
    pub fn check_s2k_params(&self, etype: i32, params: &str) -> Result<(), error::Crypto> {
        if let Some(minimum) = self.min_s2k_iterations(etype) {
            let actual = super::s2kparams_to_iterations(params)?;
            (actual >= minimum).ok_or(error::Policy::S2kIterationsTooLow {
                etype,
                minimum,
                actual,
            })?;
        }
        Ok(())
    }
    /// Build a validated snapshot; public field mutation is never trusted.
    ///
    /// # Errors
    /// Rejects weak crypto and invalid, disabled, forbidden or empty permitted lists.
    #[inline]
    pub fn from_libdefaults(defaults: &LibDefaults) -> Result<Self, error::Config> {
        restrictions::defaults(defaults)?;
        #[cfg(feature = "serde")]
        for (key, value) in &defaults.protocol_relations {
            protocol::relation(key, value)?;
        }
        super::selection::reject_checksum(defaults.safe_checksum_type)?;
        let resolved = defaults.resolve_names(&defaults.permitted_enctypes)?;
        for names in [
            &defaults.default_tkt_enctypes,
            &defaults.default_tgs_enctypes,
        ] {
            drop(EnctypeExpr::parse(&names.join(" "))?.resolve(
                Toggle::Enabled,
                Toggle::Enabled,
                ParseMode::Compatible,
            )?);
        }
        Ok(Self {
            minima: defaults.min_s2k_iterations,
            permitted: resolved.enctypes().to_vec(),
            allow_rc4: defaults.allow_rc4,
            allow_des3: defaults.allow_des3,
            mode: defaults.parse_mode(),
        })
    }

    /// Check a wire enctype ID before its specified use; no crypto or I/O occurs.
    ///
    /// # Errors
    /// Returns permanent typed rejection for single-DES/RC4-EXP, otherwise
    /// `EnctypeNotPermitted` for unavailable, disabled or excluded encryption types.
    #[inline]
    pub fn check_use(&self, etype: i32, usage: Use) -> Result<(), error::Policy> {
        super::selection::reject_enctype(etype)?;
        let enabled = match etype {
            16_i32 => self.allow_des3.is_enabled(),
            23_i32 => self.allow_rc4.is_enabled(),
            _ => true,
        };
        (enabled && self.permitted.iter().any(|entry| entry.etype_id() == etype))
            .ok_or(error::Policy::EnctypeNotPermitted { etype, usage })
    }

    /// Resolve an expression under this policy, retaining compatibility diagnostics.
    ///
    /// # Errors
    /// Returns expression errors or a typed rejection of an excluded request entry.
    #[inline]
    pub fn resolve_with_diagnostics(
        &self,
        expression: &EnctypeExpr,
    ) -> Result<ResolvedEnctypes, error::Config> {
        let resolved = expression.resolve(self.allow_rc4, self.allow_des3, self.mode)?;
        for etype in resolved.enctypes() {
            self.check_use(etype.etype_id(), Use::RequestList)?;
        }
        Ok(resolved)
    }

    /// Resolve to permitted encryption types; use `resolve_with_diagnostics` to
    /// retain secure-unsupported warnings, as the configuration parser does.
    ///
    /// # Errors
    /// Returns the errors of [`Self::resolve_with_diagnostics`].
    #[inline]
    pub fn resolve(&self, expression: &EnctypeExpr) -> Result<Vec<KerberosEtype>, error::Config> {
        Ok(self
            .resolve_with_diagnostics(expression)?
            .enctypes()
            .to_vec())
    }
}

impl Default for Policy {
    #[inline]
    fn default() -> Self {
        Self {
            minima: super::s2k::Minima::new(),
            permitted: vec![
                KerberosEtype::Sha2(AesSha2Etype::Aes256),
                KerberosEtype::Sha2(AesSha2Etype::Aes128),
                KerberosEtype::Sha1(AesSha1Etype::Aes256),
                KerberosEtype::Sha1(AesSha1Etype::Aes128),
            ],
            allow_rc4: Toggle::Disabled,
            allow_des3: Toggle::Disabled,
            mode: ParseMode::Compatible,
        }
    }
}

impl TryFrom<&LibDefaults> for Policy {
    type Error = error::Config;
    #[inline]
    fn try_from(value: &LibDefaults) -> Result<Self, Self::Error> {
        Self::from_libdefaults(value)
    }
}

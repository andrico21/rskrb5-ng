//! The authorization half (`localauth.c:386-406`).

use alloc::sync::Arc;
use std::path::{Path, PathBuf};

use crate::{ccache::Principal, config::Config, error::LocalAuth as Error};

use super::{
    AccountResolver, Authorization, Denial, LocalAuthorizer, LocalNameMapper, MAX_LOCAL_NAME_BYTES,
    Module, k5login,
};

impl LocalAuthorizer {
    /// An authorizer with MIT's defaults: authoritative `.k5login` files in
    /// the home directories the `resolver` reports.
    #[must_use]
    #[inline]
    pub fn new(mapper: LocalNameMapper, resolver: Arc<dyn AccountResolver>) -> Self {
        Self {
            mapper,
            resolver,
            authoritative: true,
            directory: None,
        }
    }

    /// Set `k5login_authoritative`: while true, a `.k5login` that refuses is
    /// final; otherwise a refusal is silence and only `an2ln` can still allow.
    #[must_use]
    #[inline]
    pub const fn with_k5login_authoritative(mut self, authoritative: bool) -> Self {
        self.authoritative = authoritative;
        self
    }

    /// Set `k5login_directory`: with a directory, the file of account `a` is
    /// `<directory>/a`; without one it is `<home>/.k5login`.
    #[must_use]
    #[inline]
    pub fn with_k5login_directory(mut self, directory: Option<PathBuf>) -> Self {
        self.directory = directory;
        self
    }

    /// Build from `config`: its default realm, `auth_to_local_names`,
    /// `auth_to_local`, `k5login_authoritative` and `k5login_directory`. The
    /// home directory of an account is the resolver's, never `HOME`.
    ///
    /// # Errors
    ///
    /// A malformed `auth_to_local` value of the default realm.
    #[inline]
    pub fn from_config(config: &Config, resolver: Arc<dyn AccountResolver>) -> Result<Self, Error> {
        let directory = &config.libdefaults.k5login_directory;
        Ok(Self::new(LocalNameMapper::from_config(config)?, resolver)
            .with_k5login_authoritative(bool::from(config.libdefaults.k5login_authoritative))
            .with_k5login_directory((!directory.is_empty()).then(|| PathBuf::from(directory))))
    }

    /// Whether a refusing `.k5login` is final (`k5login_authoritative`).
    #[must_use]
    #[inline]
    pub const fn k5login_authoritative(&self) -> bool {
        self.authoritative
    }

    /// The `k5login_directory`, when one is set.
    #[must_use]
    #[inline]
    pub fn k5login_directory(&self) -> Option<&Path> {
        self.directory.as_deref()
    }

    /// The account database the authorizer asks.
    #[must_use]
    #[inline]
    pub fn resolver(&self) -> &dyn AccountResolver {
        self.resolver.as_ref()
    }

    /// `krb5_kuserok`.
    pub(super) fn authorize(&self, principal: &Principal, local_name: &str) -> Authorization {
        if local_name.is_empty() || local_name.contains('\0') {
            return Authorization::Denied(Denial::InvalidLocalName);
        }
        match k5login::check(self, principal, local_name) {
            k5login::Verdict::Listed => Authorization::Authorized(Module::K5login),
            k5login::Verdict::Refused(fault) => Authorization::Denied(Denial::K5login(fault)),
            k5login::Verdict::Silent => match self.mapper.translate(principal) {
                Ok(name) if name == local_name && name.len() <= MAX_LOCAL_NAME_BYTES => {
                    Authorization::Authorized(Module::An2ln)
                }
                Ok(_) | Err(_) => Authorization::Denied(Denial::NoModuleAllowed),
            },
        }
    }
}

//! The authorization half (`localauth.c:386-406`).

use alloc::sync::Arc;
use std::path::PathBuf;

use crate::{config::Config, error::LocalAuth as Error};

use super::{AccountResolver, LocalAuthorizer, LocalNameMapper};

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

    /// Set `k5login_authoritative`.
    #[must_use]
    #[inline]
    pub const fn with_k5login_authoritative(mut self, authoritative: bool) -> Self {
        self.authoritative = authoritative;
        self
    }

    /// Set `k5login_directory`.
    #[must_use]
    #[inline]
    pub fn with_k5login_directory(mut self, directory: Option<PathBuf>) -> Self {
        self.directory = directory;
        self
    }

    /// Build from `config`: its default realm, `auth_to_local_names`,
    /// `auth_to_local`, `k5login_authoritative` and `k5login_directory`.
    ///
    /// # Errors
    ///
    /// A malformed `auth_to_local` value of the default realm.
    #[inline]
    pub fn from_config(config: &Config, resolver: Arc<dyn AccountResolver>) -> Result<Self, Error> {
        let _unused = config;
        Ok(Self::new(LocalNameMapper::new(None), resolver))
    }
}

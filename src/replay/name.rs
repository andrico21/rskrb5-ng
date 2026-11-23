//! MIT replay-cache names (`rc_base.c:k5_rc_resolve`, `krb5_rc_default`).

#[cfg(feature = "messages")]
use alloc::sync::Arc;
use std::{env, path::PathBuf};

use super::{Error, RcacheName};
#[cfg(feature = "messages")]
use super::{File2ReplayStore, MemoryReplayStore, NoneReplayStore, Store};
use crate::{config::Config, file_name::expand_path_tokens, secure_env};

impl RcacheName {
    /// Parse `type:residual`: `dfl:` (residual ignored), `file2:<path>`,
    /// `none:` (residual ignored) or `memory:` (residual ignored).
    ///
    /// Types are matched exactly, as MIT does. A name without a colon is
    /// MIT's `KRB5_RC_PARSE` and a bare path is not a name; an unknown type is
    /// MIT's `KRB5_RC_TYPE_NOTFOUND`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidName`], [`Error::UnsupportedType`] or
    /// [`Error::EmptyPath`].
    #[inline]
    pub fn parse(name: &str) -> Result<Self, Error> {
        let (kind, residual) = name.split_once(':').ok_or(Error::InvalidName)?;
        match kind {
            "dfl" => Ok(Self::Dfl),
            "none" => Ok(Self::None),
            "memory" => Ok(Self::Memory),
            "file2" if residual.is_empty() => Err(Error::EmptyPath),
            "file2" => Ok(Self::File2 {
                path: PathBuf::from(residual),
            }),
            other => Err(Error::UnsupportedType {
                name_type: other.to_owned(),
            }),
        }
    }

    /// The name MIT's `krb5_rc_default` selects (`rc_base.c:30-62`): the
    /// environment `KRB5RCACHENAME`, then `KRB5RCACHETYPE` (as `<type>:`),
    /// then `[libdefaults] default_rcache_name` of `config` with its path
    /// tokens expanded, then `dfl:`. The environment is ignored in a set-uid
    /// process.
    ///
    /// # Ambient input
    ///
    /// Reads `KRB5RCACHENAME` and `KRB5RCACHETYPE`. [`Self::parse`] takes the
    /// name explicitly and reads no variable.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::parse`] and
    /// [`Error::IdentityUnavailable`] for an unexpandable path token.
    #[inline]
    pub fn default_for(config: &Config) -> Result<Self, Error> {
        if let Ok(name) = secure_env::ambient(|| env::var("KRB5RCACHENAME")) {
            return Self::parse(&name);
        }
        if let Ok(kind) = secure_env::ambient(|| env::var("KRB5RCACHETYPE")) {
            return Self::parse(&format!("{kind}:"));
        }
        let configured = &config.libdefaults.default_rcache_name;
        if configured.is_empty() {
            return Ok(Self::Dfl);
        }
        let expanded =
            expand_path_tokens(configured).map_err(|_unavailable| Error::IdentityUnavailable)?;
        Self::parse(&expanded)
    }

    /// Open the store this name selects.
    ///
    /// # Ambient input
    ///
    /// `dfl:` reads `KRB5RCACHEDIR`, else `TMPDIR` (`LOCALAPPDATA` on Windows);
    /// a `file2:` name opens its path and reads no variable, and [`Self::parse`]
    /// takes any name explicitly.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IdentityUnavailable`] when `dfl:` cannot find the
    /// user id.
    #[cfg(feature = "messages")]
    #[inline]
    pub fn open(&self) -> Result<Arc<dyn Store>, Error> {
        Ok(match self {
            Self::Dfl => Arc::new(File2ReplayStore::dfl()?),
            Self::File2 { path } => Arc::new(File2ReplayStore::new(path.clone())),
            Self::None => Arc::new(NoneReplayStore::opt_out()),
            Self::Memory => Arc::new(MemoryReplayStore::new()),
        })
    }
}

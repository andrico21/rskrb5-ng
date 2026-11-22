//! Principals, `krb5.conf` text, accounts and a scratch directory.

#![cfg(feature = "localauth")]

extern crate alloc;

use alloc::sync::Arc;
use core::{
    error::Error,
    sync::atomic::{AtomicU32, Ordering},
};
use std::{
    env, fs,
    path::{Path, PathBuf},
    process,
};

use rskrb5_ng::{
    ccache::Principal,
    config::Config,
    localauth::{
        Account, AccountResolver, LocalAuthorizer, LocalNameMapper, table::StaticAccounts,
    },
};

/// The error type of the `Result`-returning tests.
pub(crate) type TestError = Box<dyn Error>;

/// The realm of MIT's own `t_localauth.py`.
pub(crate) const REALM: &str = "KRBTEST.COM";

/// `a/b@REALM` as a principal: the last `@` starts the realm, `/` separates
/// components (no escapes).
pub(crate) fn principal(text: &str) -> Principal {
    let (name, realm) = text.rsplit_once('@').unwrap_or((text, ""));
    Principal::new(realm, 1, name.split('/').map(str::to_owned).collect())
}

/// A configuration whose default realm [`REALM`] has `realm_lines` in its
/// section (the lines are `krb5.conf` text, one per element).
pub(crate) fn config(realm_lines: &str) -> Result<Config, TestError> {
    Ok(Config::parse(&format!(
        "[libdefaults]\n default_realm = {REALM}\n[realms]\n {REALM} = {{\n{realm_lines}\n }}\n"
    ))?)
}

/// The mapper of [`config`] with `realm_lines`.
pub(crate) fn mapper(realm_lines: &str) -> Result<LocalNameMapper, TestError> {
    Ok(LocalNameMapper::from_config(&config(realm_lines)?)?)
}

/// A directory that is removed when it goes out of scope.
#[derive(Debug)]
pub(crate) struct Scratch {
    /// The directory.
    path: PathBuf,
}

/// Makes every scratch directory of a process distinct.
static COUNTER: AtomicU32 = AtomicU32::new(0);

impl Scratch {
    /// A new empty directory.
    pub(crate) fn new(label: &str) -> Result<Self, TestError> {
        let path = env::temp_dir().join(format!(
            "localauth-{label}-{}-{}",
            process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    /// The directory.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        drop(fs::remove_dir_all(&self.path));
    }
}

/// A resolver that knows `name` with `uid` and `home`.
pub(crate) fn resolver(name: &str, uid: u32, home: &Path) -> Arc<dyn AccountResolver> {
    Arc::new(StaticAccounts::new().with_account(name, Account::new(uid, home.to_path_buf())))
}

/// An authorizer over [`config`] with `realm_lines` and `resolver`.
pub(crate) fn authorizer(
    realm_lines: &str,
    resolver: Arc<dyn AccountResolver>,
) -> Result<LocalAuthorizer, TestError> {
    Ok(LocalAuthorizer::from_config(
        &config(realm_lines)?,
        resolver,
    )?)
}

/// Homes with a `.k5login` of a chosen content and mode, and the decision for it (Unix only).
#[cfg(unix)]
pub(crate) mod homes {
    use std::{
        fs,
        os::unix::fs::{MetadataExt as _, PermissionsExt as _},
        path::Path,
    };

    use rskrb5_ng::{
        ccache::Principal,
        localauth::{Authorization, Denial, Module, authorize_local, k5login::Fault},
    };

    use super::{Scratch, TestError, authorizer, principal, resolver};

    /// The account the scenarios authorize.
    pub(crate) const USER: &str = "lauth";

    /// Granted by the `.k5login` module.
    pub(crate) const LISTED: Authorization = Authorization::Authorized(Module::K5login);

    /// Refused by the `.k5login` module for `fault`.
    pub(crate) const fn refused(fault: Fault) -> Authorization {
        Authorization::Denied(Denial::K5login(fault))
    }

    /// The principal every scenario authorizes.
    pub(crate) fn alice() -> Principal {
        principal("alice@KRBTEST.COM")
    }

    /// A home directory with a `.k5login` of `content` and `mode`, and the
    /// user id that owns it (this process's).
    pub(crate) fn home_with(content: &[u8], mode: u32) -> Result<(Scratch, u32), TestError> {
        let home = Scratch::new("home")?;
        let file = home.path().join(".k5login");
        fs::write(&file, content)?;
        fs::set_permissions(&file, fs::Permissions::from_mode(mode))?;
        let owner = fs::metadata(&file)?.uid();
        Ok((home, owner))
    }

    /// The decision for `alice` as `USER` with `uid` and `home`.
    pub(crate) fn decide(uid: u32, home: &Path) -> Result<Authorization, TestError> {
        let authorizer = authorizer("", resolver(USER, uid, home))?;
        Ok(authorize_local(&authorizer, &alice(), USER))
    }
}

//! The local accounts of `provision.d/85-localauth.sh`, rebuilt on the host.
//!
//! The host cannot chown a file to root or to another user, so each state is
//! rebuilt with the account's user id chosen to match or to differ from the
//! owner (this process's).

use core::{
    error::Error,
    sync::atomic::{AtomicU32, Ordering},
};
use std::{
    env, fs,
    os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink},
    path::{Path, PathBuf},
    process,
    time::{SystemTime, UNIX_EPOCH},
};

use rskrb5_ng::localauth::{Account, table::StaticAccounts};

/// Makes every scratch directory of a process distinct.
static COUNTER: AtomicU32 = AtomicU32::new(0);

/// A directory that is removed when it goes out of scope.
pub(crate) struct Scratch {
    /// The directory.
    path: PathBuf,
}

impl Scratch {
    /// A new empty directory.
    pub(crate) fn new() -> Result<Self, Box<dyn Error>> {
        let path = env::temp_dir().join(format!(
            "interop-localauth-{}-{}-{}",
            process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
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

/// The state of an account's `.k5login`, rebuilt on the host.
#[derive(Clone, Copy, Debug)]
enum State {
    /// No file.
    Missing,
    /// Owned by the account, mode 0644, lists the verified client.
    Listed,
    /// Lists the client but the account's uid is not the owner's.
    Foreign,
    /// Owned by the account, mode 0666.
    Wide,
    /// A symbolic link to a file that lists the client.
    Link,
}

/// The accounts of `provision.d/85-localauth.sh`, with the state of each file.
const ACCOUNTS: [(&str, State); 6] = [
    ("lauthmapped", State::Missing),
    ("lauthnone", State::Missing),
    ("lauthlist", State::Listed),
    ("lauthother", State::Foreign),
    ("lauthwide", State::Wide),
    ("lauthlink", State::Link),
];

/// The accounts rebuilt under `root`, as the resolver the authorizer is given.
pub(crate) fn accounts(root: &Path, client: &str) -> Result<StaticAccounts, Box<dyn Error>> {
    let mut table = StaticAccounts::new();
    let line = format!("{client}\n");
    for (account, state) in ACCOUNTS {
        let home = root.join(account);
        fs::create_dir_all(&home)?;
        let file = home.join(".k5login");
        let write = |path: &Path, mode: u32| -> Result<(), Box<dyn Error>> {
            fs::write(path, &line)?;
            fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
            Ok(())
        };
        let uid = fs::metadata(&home)?.uid();
        let account_uid = match state {
            State::Missing => uid,
            State::Listed => {
                write(&file, 0o644)?;
                uid
            }
            State::Foreign => {
                write(&file, 0o644)?;
                uid.wrapping_add(1)
            }
            State::Wide => {
                write(&file, 0o666)?;
                uid
            }
            State::Link => {
                let real = home.join("k5login.real");
                write(&real, 0o644)?;
                symlink(&real, &file)?;
                uid
            }
        };
        table = table.with_account(account, Account::new(account_uid, home));
    }
    Ok(table)
}

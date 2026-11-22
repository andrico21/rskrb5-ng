//! A caller-filled account table.

use alloc::collections::BTreeMap;

use super::{Account, AccountResolver};

/// An in-memory [`AccountResolver`]: the accounts the caller registers.
///
/// This is the only resolver the crate ships. A server fills it from its own
/// audited source (a passwd lookup the caller owns, a fixed service account)
/// and a test fills it with temporary home directories.
#[derive(Clone, Debug, Default)]
pub struct StaticAccounts {
    /// Account name to metadata.
    table: BTreeMap<String, Account>,
}

impl StaticAccounts {
    /// An empty table: every lookup fails.
    #[must_use]
    #[inline]
    pub const fn new() -> Self {
        Self {
            table: BTreeMap::new(),
        }
    }

    /// Register `name`, replacing an earlier entry of the same name.
    #[must_use]
    #[inline]
    pub fn with_account<N>(mut self, name: N, account: Account) -> Self
    where
        N: Into<String>,
    {
        drop(self.table.insert(name.into(), account));
        self
    }
}

impl AccountResolver for StaticAccounts {
    #[inline]
    fn lookup(&self, local_name: &str) -> Option<Account> {
        self.table.get(local_name).cloned()
    }
}

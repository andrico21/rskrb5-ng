//! The secure-environment decision: whether this process may trust its environment.
//!
//! MIT krb5 1.22.2 reads `KRB5_CONFIG`, `KRB5CCNAME`, `KRB5_KTNAME`,
//! `KRB5_CLIENT_KTNAME`, `TMPDIR` and `HOME` through `secure_getenv`, which
//! returns nothing in a process running with elevated privilege
//! (`src/util/support/secure_getenv.c:105-111`). Every ambient reader of this
//! crate consults [`ambient`] before it reads one of those variables, and in a
//! restricted process it behaves as if the variable were unset.
//!
//! The decision is derived from the operating system once per process, never
//! from an environment variable:
//!
//! - Linux and Android: `AT_SECURE` (auxiliary vector type 23) from
//!   `/proc/self/auxv`, the value glibc's `secure_getenv` uses. A vector that
//!   cannot be read or parsed, or one without `AT_SECURE`, is restricted.
//! - Other Unix: the real and effective user and group ids differ (MIT's
//!   fallback, `secure_getenv.c:83-99`, without the saved ids `getresuid`
//!   would add).
//! - Windows has no set-id processes: never restricted.

use std::{env, ffi::OsString, sync::OnceLock};

#[cfg(test)]
#[path = "secure_env/tests.rs"]
mod tests;

/// Whether the environment of this process may be trusted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Decision {
    /// The process runs with elevated privilege: ambient variables are ignored.
    Restricted,
    /// Ambient variables are read.
    Unrestricted,
}

/// A value an ambient read returns when the variable is unset.
pub(crate) trait Unset {
    /// The result of reading an unset variable.
    fn unset() -> Self;
}

impl Unset for Result<String, env::VarError> {
    fn unset() -> Self {
        Err(env::VarError::NotPresent)
    }
}

impl Unset for Option<OsString> {
    fn unset() -> Self {
        None
    }
}

/// Run one ambient read, or return its unset value in a restricted process.
///
/// The decision is consulted before `read` runs, so a restricted process
/// never reads the variable.
pub(crate) fn ambient<T, F>(read: F) -> T
where
    T: Unset,
    F: FnOnce() -> T,
{
    match decision() {
        Decision::Restricted => T::unset(),
        Decision::Unrestricted => read(),
    }
}

/// The OS decision, derived once per process like MIT's library initializer.
static DECISION: OnceLock<Decision> = OnceLock::new();

/// The decision of this process: the injected one in tests, else the OS one.
fn decision() -> Decision {
    #[cfg(test)]
    if let Some(injected) = tests::injected() {
        return injected;
    }
    *DECISION.get_or_init(os_decision)
}

/// `AT_SECURE` from this process's auxiliary vector; unreadable means restricted.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn os_decision() -> Decision {
    use std::fs;
    fs::read("/proc/self/auxv").map_or(Decision::Restricted, |auxv| parse_auxv(&auxv))
}

/// Real and effective ids differ: a set-uid or set-gid process (MIT's fallback).
#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
fn os_decision() -> Decision {
    use rustix::process::{getegid, geteuid, getgid, getuid};
    if getuid() == geteuid() && getgid() == getegid() {
        Decision::Unrestricted
    } else {
        Decision::Restricted
    }
}

/// Platforms without set-id processes are never restricted.
#[cfg(not(unix))]
const fn os_decision() -> Decision {
    Decision::Unrestricted
}

/// The auxiliary vector entry type of `AT_NULL`, which ends the vector.
#[cfg(any(target_os = "linux", target_os = "android", test))]
const AT_NULL: usize = 0;
/// The auxiliary vector entry type of `AT_SECURE`.
#[cfg(any(target_os = "linux", target_os = "android", test))]
const AT_SECURE: usize = 23;

/// Decide from auxiliary vector bytes: pairs of native-endian `usize` words.
///
/// Only `AT_SECURE` equal to zero before `AT_NULL` is unrestricted; a length
/// that is not a whole number of pairs, a vector without `AT_SECURE` and any
/// other value are restricted.
#[cfg(any(target_os = "linux", target_os = "android", test))]
fn parse_auxv(auxv: &[u8]) -> Decision {
    const WORD: usize = size_of::<usize>();
    #[cfg(target_endian = "little")]
    let word = usize::from_le_bytes;
    #[cfg(target_endian = "big")]
    let word = usize::from_be_bytes;
    let (pairs, rest) = auxv.as_chunks::<{ size_of::<[usize; 2]>() }>();
    if !rest.is_empty() {
        return Decision::Restricted;
    }
    for pair in pairs {
        let ([kind, value], []) = pair.as_chunks::<WORD>() else {
            return Decision::Restricted;
        };
        match (word(*kind), word(*value)) {
            (AT_NULL, _) => break,
            (AT_SECURE, 0) => return Decision::Unrestricted,
            (AT_SECURE, _) => return Decision::Restricted,
            _ => {}
        }
    }
    Decision::Restricted
}

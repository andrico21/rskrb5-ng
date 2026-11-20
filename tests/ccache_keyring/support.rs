//! Probing the kernel keyring, required mode and shared helpers.

use core::error;
use std::{
    env, fs,
    io::{self, Write as _},
    process,
    time::{SystemTime, UNIX_EPOCH},
};

use rskrb5_ng::{
    ccache::{
        Credential, CredentialTimes, EncryptionKey, Principal, file_store,
        keyring::{Fault, KernelError},
        stores::{CacheHandle, CacheVersion},
    },
    error::Ccache as Error,
};
use zeroize::Zeroizing;

/// Error type of the `Result`-returning tests.
pub(crate) type TestError = Box<dyn error::Error>;

/// The environment variable that turns an unusable keyring into a failure.
const REQUIRED: &str = "RSKRB5_KEYRING_REQUIRED";

/// Whether an unavailable keyring must fail the test instead of skipping it:
/// the hosted `ccache-keyring` job runs on a VM where keyctl works.
pub(crate) fn required() -> bool {
    env::var(REQUIRED).as_deref() == Ok("1")
}

/// Resolve a `KEYRING:` name through the built-in dispatch.
pub(crate) fn open(name: &str) -> Result<Box<dyn CacheHandle>, Error> {
    file_store::resolve(&format!("KEYRING:{name}"), CacheVersion::V4)
}

/// Whether the kernel keyring works here. When it does not (a sandbox that
/// filters keyctl answers `ENOSYS` or `EPERM`), the test prints why it skips,
/// or fails in required mode.
///
/// # Errors
///
/// In required mode, the typed failure; any error other than the kernel's
/// refusal; a failed write of the skip notice.
pub(crate) fn available(test: &str) -> Result<bool, TestError> {
    match open(&format!("process:probe{}", process::id())) {
        Ok(_) => Ok(true),
        Err(Error::Keyring(Fault::Kernel {
            error: error @ (KernelError::Unavailable | KernelError::PermissionDenied),
            operation,
        })) if !required() => {
            writeln!(io::stderr(), "keyring: SKIP {test}: {operation}: {error}")?;
            Ok(false)
        }
        Err(other) => Err(other.into()),
    }
}

/// The real user id of this process.
pub(crate) fn uid() -> Result<u32, TestError> {
    let status = fs::read_to_string("/proc/self/status")?;
    let line = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .ok_or("no Uid line in /proc/self/status")?;
    Ok(line
        .split_whitespace()
        .next()
        .ok_or("empty Uid line")?
        .parse()?)
}

/// A principal `name@EXAMPLE.COM`.
pub(crate) fn principal(name: &str) -> Principal {
    Principal::new(
        "EXAMPLE.COM",
        1,
        name.split('/').map(str::to_owned).collect(),
    )
}

/// A credential of `alice` for `server` with a `ticket` of the given bytes.
pub(crate) fn credential(server: &str, ticket: Vec<u8>) -> Credential {
    let mut times = CredentialTimes::default();
    times.end_time = now().saturating_add(36_000);
    Credential::new(
        principal("alice"),
        principal(server),
        EncryptionKey::new(18, vec![7; 32]),
        times,
        [0; 4],
        Zeroizing::new(ticket),
    )
}

/// The current time in seconds.
fn now() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u32::try_from(elapsed.as_secs()).unwrap_or(u32::MAX)
        })
}

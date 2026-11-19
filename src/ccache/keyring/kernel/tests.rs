//! The `errno` mapping of the key calls and the checks before them.

use core::num::NonZeroI32;

use super::{Kernel, failure};
use crate::ccache::keyring::{
    KernelError,
    backend::{Backend as _, Kind, Ring},
};

/// Every `errno` this crate acts on maps to its typed failure; any other
/// number is kept.
#[test]
fn errno_values_map_to_typed_failures() {
    let cases = [
        (libc::ENOSYS, KernelError::Unavailable),
        (libc::EOPNOTSUPP, KernelError::NotSupported),
        (libc::EPERM, KernelError::PermissionDenied),
        (libc::EACCES, KernelError::AccessDenied),
        (libc::EDQUOT, KernelError::QuotaExceeded),
        (libc::ENOKEY, KernelError::KeyNotFound),
        (libc::EKEYREVOKED, KernelError::KeyRevoked),
        (libc::EKEYEXPIRED, KernelError::KeyExpired),
        (libc::EINVAL, KernelError::InvalidArgument),
        (libc::ENODEV, KernelError::NoDevice),
    ];
    for case in cases {
        assert_eq!(failure(case.0), case.1, "errno {}", case.0);
    }
    assert_eq!(failure(libc::EIO), KernelError::Other(libc::EIO), "other");
}

/// A NUL in a description is refused before the call, where `keyutils-raw`
/// would panic.
#[test]
fn nul_in_a_description_is_refused() {
    assert_eq!(
        Kernel.add(Ring::Process, Kind::User, "a\0b", b"payload"),
        Err(KernelError::InvalidArgument),
        "add"
    );
    assert_eq!(
        Kernel.search(Ring::Process, Kind::Keyring, "a\0b", None),
        Err(KernelError::InvalidArgument),
        "search"
    );
}

/// The kernel's answer for a key that does not exist.
fn missing_key() -> Result<(), KernelError> {
    Kernel.read(Ring::Key(NonZeroI32::MAX)).map(drop)
}

/// The kernel's own answer for a key that does not exist is `ENOKEY`; a
/// sandbox that filters the key calls answers `ENOSYS` or `EPERM`, and the
/// integration tests of `tests/ccache_keyring.rs` fail on that in required
/// mode.
#[test]
fn the_kernel_answers_enokey_for_a_missing_key() {
    assert!(
        matches!(
            missing_key(),
            Err(KernelError::KeyNotFound
                | KernelError::Unavailable
                | KernelError::PermissionDenied)
        ),
        "{:?}",
        missing_key()
    );
}

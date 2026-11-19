//! The real kernel through `keyutils-raw` (docs/dependency-admission.md).

use keyutils_raw::{
    add_key, keyctl_clear, keyctl_describe, keyctl_get_keyring_id, keyctl_get_persistent,
    keyctl_link, keyctl_read, keyctl_search, keyctl_set_timeout, keyctl_unlink,
};
use zeroize::Zeroizing;

use super::{
    KernelError,
    backend::{Backend, Kind, Ring, Serial},
};

/// The Linux key-management facility.
#[derive(Clone, Copy, Debug)]
pub(super) struct Kernel;

/// The failure for an `errno` of the key calls.
pub(super) const fn failure(errno: i32) -> KernelError {
    match errno {
        libc::ENOSYS => KernelError::Unavailable,
        libc::EOPNOTSUPP => KernelError::NotSupported,
        libc::EPERM => KernelError::PermissionDenied,
        libc::EACCES => KernelError::AccessDenied,
        libc::EDQUOT => KernelError::QuotaExceeded,
        libc::ENOKEY => KernelError::KeyNotFound,
        libc::EKEYREVOKED => KernelError::KeyRevoked,
        libc::EKEYEXPIRED => KernelError::KeyExpired,
        libc::EINVAL => KernelError::InvalidArgument,
        libc::ENODEV => KernelError::NoDevice,
        other => KernelError::Other(other),
    }
}

/// The serial of an operand.
///
/// # Errors
///
/// [`KernelError::InvalidArgument`] for the serial 0, which no key has.
fn serial(ring: Ring) -> Result<Serial, KernelError> {
    Serial::new(ring.raw()).ok_or(KernelError::InvalidArgument)
}

/// A description the key calls can take: `keyutils-raw` panics on a NUL.
///
/// # Errors
///
/// [`KernelError::InvalidArgument`] for a NUL.
fn text(description: &str) -> Result<&str, KernelError> {
    if description.contains('\0') {
        Err(KernelError::InvalidArgument)
    } else {
        Ok(description)
    }
}

/// The failure of a call that returned an `errno`.
fn errno_of<E>(error: E) -> KernelError
where
    E: Into<i32>,
{
    failure(error.into())
}

impl Backend for Kernel {
    fn lookup(&self, ring: Ring) -> Result<Serial, KernelError> {
        keyctl_get_keyring_id(serial(ring)?, false).map_err(errno_of)
    }

    fn persistent(&self, uid: Option<u32>) -> Result<Serial, KernelError> {
        keyctl_get_persistent(uid.unwrap_or(u32::MAX), serial(Ring::Process)?).map_err(errno_of)
    }

    fn search(
        &self,
        ring: Ring,
        kind: Kind,
        description: &str,
        destination: Option<Ring>,
    ) -> Result<Serial, KernelError> {
        keyctl_search(
            serial(ring)?,
            kind.name(),
            text(description)?,
            destination.map(serial).transpose()?,
        )
        .map_err(errno_of)
    }

    fn add(
        &self,
        ring: Ring,
        kind: Kind,
        description: &str,
        payload: &[u8],
    ) -> Result<Serial, KernelError> {
        add_key(kind.name(), text(description)?, payload, serial(ring)?).map_err(errno_of)
    }

    fn link(&self, key: Ring, ring: Ring) -> Result<(), KernelError> {
        keyctl_link(serial(key)?, serial(ring)?).map_err(errno_of)
    }

    fn unlink(&self, key: Ring, ring: Ring) -> Result<(), KernelError> {
        keyctl_unlink(serial(key)?, serial(ring)?).map_err(errno_of)
    }

    fn clear(&self, ring: Ring) -> Result<(), KernelError> {
        keyctl_clear(serial(ring)?).map_err(errno_of)
    }

    fn read(&self, key: Ring) -> Result<Zeroizing<Vec<u8>>, KernelError> {
        let id = serial(key)?;
        let mut size = keyctl_read(id, None).map_err(errno_of)?;
        loop {
            // A fresh buffer each round: the payload may have grown, and the
            // dropped one is wiped.
            let mut buffer = Zeroizing::new(vec![0_u8; size]);
            let length = keyctl_read(id, Some(buffer.as_mut_slice().into())).map_err(errno_of)?;
            if length <= buffer.len() {
                buffer.truncate(length);
                return Ok(buffer);
            }
            size = length;
        }
    }

    fn describe(&self, key: Ring) -> Result<String, KernelError> {
        let id = serial(key)?;
        let mut size = keyctl_describe(id, None).map_err(errno_of)?;
        loop {
            let mut buffer = vec![0_u8; size];
            let length =
                keyctl_describe(id, Some(buffer.as_mut_slice().into())).map_err(errno_of)?;
            if length <= buffer.len() {
                buffer.truncate(length);
                // The kernel counts the terminating NUL.
                if buffer.last() == Some(&0) {
                    buffer.truncate(buffer.len().saturating_sub(1));
                }
                return String::from_utf8(buffer)
                    .map_err(|_invalid| KernelError::Other(libc::EILSEQ));
            }
            size = length;
        }
    }

    fn set_timeout(&self, key: Ring, seconds: u32) -> Result<(), KernelError> {
        keyctl_set_timeout(serial(key)?, seconds).map_err(errno_of)
    }
}

/// The `errno` mapping and the checks before the key calls.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests;

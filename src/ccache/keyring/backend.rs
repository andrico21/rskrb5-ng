//! The kernel operations the keyring cache needs, behind a trait so that the
//! cache logic runs against an in-memory kernel in tests and against
//! `keyutils-raw` in production.

use core::{fmt, num::NonZeroI32};

use zeroize::Zeroizing;

use super::KernelError;

/// The serial number of a key or keyring.
pub(super) type Serial = NonZeroI32;

/// A keyring operand: one of the kernel's special rings or a serial number
/// (`KEY_SPEC_*` in `keyutils.h`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Ring {
    /// The calling thread's keyring.
    Thread,
    /// The calling process's keyring.
    Process,
    /// The calling process's session keyring.
    Session,
    /// The real user's keyring.
    User,
    /// The real user's default session keyring.
    UserSession,
    /// A keyring or key by serial number.
    Key(Serial),
}

impl Ring {
    /// The kernel's number for this operand.
    #[cfg(all(feature = "ccache-keyring", target_os = "linux"))]
    pub(super) const fn raw(self) -> i32 {
        match self {
            Self::Thread => -1,
            Self::Process => -2,
            Self::Session => -3,
            Self::User => -4,
            Self::UserSession => -5,
            Self::Key(serial) => serial.get(),
        }
    }
}

/// The key types this cache uses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Kind {
    /// A keyring (one per cache and per collection).
    Keyring,
    /// A key whose payload user space may read and update.
    User,
    /// A user key of up to 1 MiB that the kernel may keep encrypted.
    BigKey,
}

impl Kind {
    /// The type name the kernel knows.
    pub(super) const fn name(self) -> &'static str {
        match self {
            Self::Keyring => "keyring",
            Self::User => "user",
            Self::BigKey => "big_key",
        }
    }
}

/// The calls of `keyutils.h` that `cc_keyring.c` makes. Every method is one
/// system call.
pub(super) trait Backend: fmt::Debug + Send + Sync {
    /// `keyctl_get_keyring_ID(ring, 0)`: the serial of a special keyring that
    /// already exists.
    ///
    /// # Errors
    ///
    /// The kernel's refusal.
    fn lookup(&self, ring: Ring) -> Result<Serial, KernelError>;

    /// `keyctl_get_persistent(uid, KEY_SPEC_PROCESS_KEYRING)`: the persistent
    /// keyring of `uid`, or of the calling user for `None`, created when
    /// absent and linked into the process keyring.
    ///
    /// # Errors
    ///
    /// The kernel's refusal.
    fn persistent(&self, uid: Option<u32>) -> Result<Serial, KernelError>;

    /// `keyctl_search(ring, kind, description, destination)`: a recursive
    /// search, linking the key found into `destination` when given.
    ///
    /// # Errors
    ///
    /// The kernel's refusal.
    fn search(
        &self,
        ring: Ring,
        kind: Kind,
        description: &str,
        destination: Option<Ring>,
    ) -> Result<Serial, KernelError>;

    /// `add_key(kind, description, payload, ring)`: create the key, or update
    /// the one of the same kind and description that `ring` already holds.
    ///
    /// # Errors
    ///
    /// The kernel's refusal.
    fn add(
        &self,
        ring: Ring,
        kind: Kind,
        description: &str,
        payload: &[u8],
    ) -> Result<Serial, KernelError>;

    /// `keyctl_link(key, ring)`.
    ///
    /// # Errors
    ///
    /// The kernel's refusal.
    fn link(&self, key: Ring, ring: Ring) -> Result<(), KernelError>;

    /// `keyctl_unlink(key, ring)`.
    ///
    /// # Errors
    ///
    /// The kernel's refusal.
    fn unlink(&self, key: Ring, ring: Ring) -> Result<(), KernelError>;

    /// `keyctl_clear(ring)`: unlink every key of the keyring.
    ///
    /// # Errors
    ///
    /// The kernel's refusal.
    fn clear(&self, ring: Ring) -> Result<(), KernelError>;

    /// `keyctl_read_alloc(key)`: the payload of a key, or the serial numbers
    /// (native-endian `i32`) a keyring links.
    ///
    /// # Errors
    ///
    /// The kernel's refusal.
    fn read(&self, key: Ring) -> Result<Zeroizing<Vec<u8>>, KernelError>;

    /// `keyctl_describe_alloc(key)`: `type;uid;gid;permissions;description`.
    ///
    /// # Errors
    ///
    /// The kernel's refusal.
    fn describe(&self, key: Ring) -> Result<String, KernelError>;

    /// `keyctl_set_timeout(key, seconds)`: the key expires after `seconds`.
    ///
    /// # Errors
    ///
    /// The kernel's refusal.
    fn set_timeout(&self, key: Ring, seconds: u32) -> Result<(), KernelError>;
}

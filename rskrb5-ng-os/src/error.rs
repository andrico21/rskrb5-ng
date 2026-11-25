//! Platform-store failures.
//!
//! They reach callers inside
//! [`rskrb5_ng::error::Ccache::Io`] as an [`std::io::Error`] whose inner
//! error is a [`Platform`]; `downcast_ref::<Platform>()` recovers it.

use core::{error, fmt};
use std::io;

use rskrb5_ng::error::Ccache;

/// A failure of a platform credential store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Platform {
    /// A store mutation was asked of a store built without the explicit
    /// authorization (`MslsaStore::with_mutation(true)`).
    MutationNotAuthorized {
        /// The cache type.
        cache_type: &'static str,
    },
    /// The operation is not supported by this cache type (as in MIT).
    UnsupportedOperation {
        /// The cache type.
        cache_type: &'static str,
        /// The refused operation.
        operation: &'static str,
    },
    /// The KCM server answered with a nonzero status (a Kerberos error code).
    Kcm {
        /// The status the server returned.
        code: i32,
    },
    /// A reply did not have the shape its request requires.
    MalformedReply {
        /// The cache type.
        cache_type: &'static str,
        /// Which rule failed.
        reason: &'static str,
    },
    /// A request or reply exceeds its bound.
    TooLarge {
        /// The cache type.
        cache_type: &'static str,
        /// The length.
        length: usize,
    },
    /// No KCM service is registered under the configured Mach name.
    NoServer {
        /// The `bootstrap_look_up` result.
        code: i32,
    },
    /// A Mach call failed.
    MachRpc {
        /// The `kern_return_t` or `mach_msg_return_t`.
        code: i32,
    },
    /// A Kerberos.framework CCAPI call failed.
    Ccapi {
        /// The `cc_int32` error.
        code: i32,
    },
    /// An LSA call failed.
    Lsa {
        /// The NTSTATUS of the call.
        status: u32,
        /// The NTSTATUS the Kerberos package returned.
        sub_status: u32,
    },
}

impl From<Platform> for Ccache {
    #[inline]
    fn from(value: Platform) -> Self {
        Self::Io(io::Error::other(value))
    }
}

impl fmt::Display for Platform {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::MutationNotAuthorized { cache_type } => {
                write!(
                    f,
                    "{cache_type}: the store was not authorized to change credentials"
                )
            }
            Self::UnsupportedOperation {
                cache_type,
                operation,
            } => write!(f, "{cache_type}: {operation} is not supported"),
            Self::Kcm { code } => write!(f, "KCM server error {code}"),
            Self::MalformedReply { cache_type, reason } => {
                write!(f, "{cache_type}: malformed reply ({reason})")
            }
            Self::TooLarge { cache_type, length } => {
                write!(
                    f,
                    "{cache_type}: message of {length} bytes exceeds the bound"
                )
            }
            Self::NoServer { code } => write!(
                f,
                "KCM: no Mach service is registered under the configured name ({code})"
            ),
            Self::MachRpc { code } => write!(f, "KCM: Mach RPC failed ({code})"),
            Self::Ccapi { code } => write!(f, "API: CCAPI error {code}"),
            Self::Lsa { status, sub_status } => write!(
                f,
                "MSLSA: LSA call failed (status {status:#x}, sub-status {sub_status:#x})"
            ),
        }
    }
}

impl error::Error for Platform {}

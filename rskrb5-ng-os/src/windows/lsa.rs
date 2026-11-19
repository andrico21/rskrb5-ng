//! The Local Security Authority calls of `MSLSA:`.
//!
//! They are those of `NTSecAPI.h` (secur32): an untrusted connection, the
//! Kerberos package id, and one
//! `LsaCallAuthenticationPackage` per message, as MIT 1.22.2
//! `src/lib/krb5/ccache/cc_mslsa.c` makes them (`PackageConnectLookup`
//! :387-426).
//!
//! Requests are built as bytes by [`crate::lsa_wire`] in an 8-byte aligned
//! buffer; replies are copied out of the LSA buffer and parsed by safe,
//! bounds-checked code before the buffer is freed.

use core::{
    ffi::{c_char, c_void},
    ptr::{self, NonNull},
    slice,
};

use rskrb5_ng::{ccache::Credential, keytab::EncryptionKey};

use super::Lsa;
use crate::{
    error::Platform,
    lsa_wire::{
        self, CacheInfo,
        parse::{self, View},
    },
};

/// `NTSTATUS`.
type Status = i32;

/// `LSA_STRING`.
#[repr(C)]
#[derive(Debug)]
struct LsaString {
    /// Length in bytes, without a terminator.
    length: u16,
    /// Buffer size in bytes.
    maximum_length: u16,
    /// The text.
    buffer: *const c_char,
}

// The secur32 declarations of `NTSecAPI.h`, with their Windows types
// (`HANDLE` is a pointer, `ULONG` is `u32`, `NTSTATUS` is `i32`).
#[expect(unsafe_code, reason = "the LSA FFI declarations")]
#[link(name = "secur32")]
unsafe extern "system" {
    fn LsaConnectUntrusted(handle: *mut *mut c_void) -> Status;
    fn LsaLookupAuthenticationPackage(
        handle: *mut c_void,
        name: *const LsaString,
        package: *mut u32,
    ) -> Status;
    fn LsaCallAuthenticationPackage(
        handle: *mut c_void,
        package: u32,
        submit: *const c_void,
        submit_length: u32,
        returned: *mut *mut c_void,
        returned_length: *mut u32,
        protocol_status: *mut Status,
    ) -> Status;
    fn LsaFreeReturnBuffer(buffer: *mut c_void) -> Status;
    fn LsaDeregisterLogonProcess(handle: *mut c_void) -> Status;
}

/// `MICROSOFT_KERBEROS_NAME_A`.
const KERBEROS: &[u8] = b"Kerberos\0";

/// An LSA failure from two `NTSTATUS` values (`FAILED` is negative).
/// # Errors
/// Returns [`Platform::Lsa`] when either failed.
const fn check(status: Status, sub_status: Status) -> Result<(), Platform> {
    if status < 0 || sub_status < 0 {
        Err(Platform::Lsa {
            status: status.cast_unsigned(),
            sub_status: sub_status.cast_unsigned(),
        })
    } else {
        Ok(())
    }
}

/// An untrusted LSA connection and the Kerberos package id.
#[derive(Debug)]
struct Connection {
    /// The LSA handle.
    handle: NonNull<c_void>,
    /// The Kerberos package.
    package: u32,
}

// Drop audit: one LSA handle release; it does not wait on the network.
impl Drop for Connection {
    fn drop(&mut self) {
        // SAFETY: the handle came from `LsaConnectUntrusted` and is released
        // exactly once here.
        #[expect(unsafe_code, reason = "FFI call")]
        let _ignored: Status = unsafe { LsaDeregisterLogonProcess(self.handle.as_ptr()) };
    }
}

/// A buffer the LSA returned, freed on drop.
#[derive(Debug)]
struct Returned {
    /// The buffer.
    buffer: NonNull<c_void>,
    /// Its length in bytes.
    length: usize,
}

impl Returned {
    /// The bytes and the address they were returned at.
    fn view(&self) -> View<'_> {
        // SAFETY: the LSA returned `length` readable bytes at `buffer`, which
        // stay allocated until `LsaFreeReturnBuffer` in `drop`.
        #[expect(unsafe_code, reason = "reading the LSA reply")]
        let bytes =
            unsafe { slice::from_raw_parts(self.buffer.as_ptr().cast::<u8>(), self.length) };
        let base = u64::try_from(self.buffer.as_ptr().expose_provenance()).unwrap_or_default();
        View::new(bytes, base)
    }
}

// Drop audit: one LSA buffer release; it does not block.
impl Drop for Returned {
    fn drop(&mut self) {
        // SAFETY: the buffer came from `LsaCallAuthenticationPackage` and is
        // freed exactly once here.
        #[expect(unsafe_code, reason = "FFI call")]
        let _ignored: Status = unsafe { LsaFreeReturnBuffer(self.buffer.as_ptr()) };
    }
}

impl Connection {
    /// Connect and look up the Kerberos package.
    /// # Errors
    /// Returns [`Platform::Lsa`].
    fn open() -> Result<Self, Platform> {
        let mut handle = ptr::null_mut();
        // SAFETY: `handle` is a valid out pointer.
        #[expect(unsafe_code, reason = "FFI call")]
        let status = unsafe { LsaConnectUntrusted(&raw mut handle) };
        check(status, 0)?;
        let connection = Self {
            handle: NonNull::new(handle).ok_or(Platform::Lsa {
                status: 0,
                sub_status: 0,
            })?,
            package: 0,
        };
        let name = LsaString {
            length: 8,
            maximum_length: 9,
            buffer: KERBEROS.as_ptr().cast::<c_char>(),
        };
        let mut package = 0_u32;
        // SAFETY: the handle is open; `name` points to the static package
        // name and `package` is a valid out pointer.
        #[expect(unsafe_code, reason = "FFI call")]
        let found = unsafe {
            LsaLookupAuthenticationPackage(
                connection.handle.as_ptr(),
                &raw const name,
                &raw mut package,
            )
        };
        check(found, 0)?;
        Ok(Self {
            package,
            ..connection
        })
    }

    /// Send the request `build` lays out for its buffer address.
    /// # Errors
    /// Returns [`Platform::Lsa`] and [`Platform::TooLarge`].
    fn call<F>(&self, build: F) -> Result<Option<Returned>, Platform>
    where
        F: Fn(u64) -> Vec<u8>,
    {
        let length = build(0).len();
        let mut words = vec![0_u64; length.div_ceil(8)];
        let base = u64::try_from(words.as_ptr().expose_provenance()).unwrap_or_default();
        for (word, chunk) in words.iter_mut().zip(build(base).chunks(8)) {
            let mut bytes = [0_u8; 8];
            bytes
                .get_mut(..chunk.len())
                .ok_or(Platform::TooLarge {
                    cache_type: "MSLSA",
                    length,
                })?
                .copy_from_slice(chunk);
            *word = u64::from_le_bytes(bytes);
        }
        let submit_length = u32::try_from(length).map_err(|_length| Platform::TooLarge {
            cache_type: "MSLSA",
            length,
        })?;
        let (mut returned, mut returned_length, mut sub_status) = (ptr::null_mut(), 0_u32, 0_i32);
        // SAFETY: `words` holds `submit_length` request bytes, 8-aligned,
        // whose embedded pointers point into `words` itself; the outputs are
        // valid out pointers.
        #[expect(unsafe_code, reason = "FFI call")]
        let status = unsafe {
            LsaCallAuthenticationPackage(
                self.handle.as_ptr(),
                self.package,
                words.as_ptr().cast::<c_void>(),
                submit_length,
                &raw mut returned,
                &raw mut returned_length,
                &raw mut sub_status,
            )
        };
        let reply = NonNull::new(returned).map(|buffer| Returned {
            buffer,
            length: usize::try_from(returned_length).unwrap_or_default(),
        });
        check(status, sub_status)?;
        Ok(reply)
    }
}

/// The LSA of the caller's logon session.
#[derive(Clone, Copy, Debug)]
pub(super) struct System;

impl Lsa for System {
    fn entries(&self) -> Result<Vec<CacheInfo>, Platform> {
        let reply = Connection::open()?.call(|_base| lsa_wire::query_cache())?;
        reply.map_or_else(
            || Ok(Vec::new()),
            |buffer| parse::cache_entries(buffer.view()),
        )
    }

    fn retrieve(&self, info: &CacheInfo) -> Result<Option<Credential>, Platform> {
        let target = info.target();
        let reply = Connection::open()?.call(|base| lsa_wire::retrieve(base, &target))?;
        reply.map_or(Ok(None), |buffer| {
            parse::credential(buffer.view(), info.client_realm())
        })
    }

    fn submit(&self, krb_cred: &[u8], key: &EncryptionKey) -> Result<(), Platform> {
        let request = lsa_wire::submit(krb_cred, key.etype(), key.value().as_ref()).ok_or(
            Platform::TooLarge {
                cache_type: "MSLSA",
                length: krb_cred.len(),
            },
        )?;
        Connection::open()?.call(|_base| request.clone()).map(drop)
    }

    fn purge(&self, info: Option<&CacheInfo>) -> Result<(), Platform> {
        let connection = Connection::open()?;
        info.map_or_else(
            || connection.call(|_base| lsa_wire::purge_all()),
            |entry| connection.call(|base| lsa_wire::purge(base, entry)),
        )
        .map(drop)
    }
}

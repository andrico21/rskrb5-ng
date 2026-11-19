//! Platform credential stores for `rskrb5-ng` (owner decision D11).
//!
//! They are the Windows LSA cache `MSLSA:`, and on macOS the native `API:`
//! cache (Kerberos.framework CCAPI) and `KCM:` over Mach RPC.
//!
//! `rskrb5-ng` itself has no `unsafe` code and never depends on this crate.
//! An application that wants the platform stores adds this crate and calls
//! [`register`]; names of these types then resolve through
//! `Registry::resolve_cache`.
//!
//! # Security
//!
//! The unsafe code is confined to the OS calls of `windows/lsa.rs`,
//! `macos/mach.rs` and `macos/ccapi.rs`; each block has a `SAFETY` comment
//! and an `#[expect(unsafe_code)]`. Everything the OS returns is copied into
//! owned values and parsed by safe, bounds-checked code that Miri checks
//! (`marshal`, `kcm_wire`, `mig`, `lsa_wire`). `MSLSA:`
//! mutations act on the whole logon session and need
//! `MslsaStore::with_mutation(true)`. Reads never ask a KDC for a ticket.

extern crate alloc;

/// An owned byte buffer erased on drop.
///
/// It is the zeroizing owner of `rskrb5-ng`, so this crate needs no
/// dependency besides `rskrb5-ng`.
#[cfg(any(target_os = "macos", windows, test))]
type Secret = Bytes;

use alloc::sync::Arc;

#[cfg(any(target_os = "macos", windows, test))]
use rskrb5_ng::keytab::key_bytes::Bytes;
use rskrb5_ng::{
    ccache::stores::CredentialStore,
    error::Extensions,
    extensions::{Extension, Registry},
};

pub mod error;
#[cfg(test)]
mod kcm_fixture;
#[cfg(any(target_os = "macos", test))]
mod kcm_store;
#[cfg(any(target_os = "macos", test))]
mod kcm_wire;
#[cfg(any(windows, test))]
mod lsa_wire;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(any(target_os = "macos", test))]
mod marshal;
#[cfg(any(target_os = "macos", test))]
mod mig;
#[cfg(any(target_os = "macos", test))]
mod principal_text;
#[cfg(any(windows, test))]
pub mod windows;

/// The stores of this platform with their default settings.
fn stores() -> Vec<Arc<dyn CredentialStore>> {
    vec![
        #[cfg(windows)]
        Arc::new(windows::MslsaStore::new()),
        #[cfg(target_os = "macos")]
        Arc::new(macos::ApiStore::new()),
        #[cfg(target_os = "macos")]
        Arc::new(macos::KcmMachStore::new(macos::DEFAULT_KCM_MACH_SERVICE)),
    ]
}

/// Register the platform stores in `registry` with their default settings.
///
/// They are `MSLSA` (read-only) on Windows, `API` and `KCM` (Mach service
/// `org.h5l.kcm`) on macOS, and none elsewhere. Register a store yourself
/// for other settings, for example `MslsaStore::with_mutation(true)` or
/// `KcmMachStore::from_libdefaults`.
///
/// # Errors
///
/// The registration errors of [`Registry::register`], for example
/// `DuplicateId` when a store of the same type is already registered.
#[inline]
pub fn register(registry: &mut Registry) -> Result<(), Extensions> {
    for store in stores() {
        registry.register(Extension::CredentialStore(store))?;
    }
    Ok(())
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use rskrb5_ng::{
        error::Extensions,
        extensions::{Interface, Registry},
    };

    use super::register;

    /// Each platform registers its own stores, once.
    #[test]
    fn registers_the_platform_stores() -> Result<(), Extensions> {
        // Given an empty registry.
        let mut registry = Registry::new();
        // When the platform stores are registered, twice.
        register(&mut registry)?;
        let again = register(&mut registry);
        // Then the platform's types are listed, and a second registration of
        // a type is refused.
        let expected: &[&str] = if cfg!(windows) {
            &["MSLSA"]
        } else if cfg!(target_os = "macos") {
            &["API", "KCM"]
        } else {
            &[]
        };
        assert_eq!(registry.ids(Interface::CredentialStore), expected);
        assert_eq!(again.is_err(), !expected.is_empty());
        Ok(())
    }
}

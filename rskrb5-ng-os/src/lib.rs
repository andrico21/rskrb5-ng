//! Platform credential stores for `rskrb5-ng` (owner decision D11).
//!
//! They are the Windows LSA cache `MSLSA:`, and on macOS the native `API:`
//! cache (Kerberos.framework CCAPI) and `KCM:` over Mach RPC.
//!
//! `rskrb5-ng` itself has no `unsafe` code and never depends on this crate.
//! An application that wants the platform stores adds this crate, calls
//! [`register`] and then `Registry::install_stores`; from then on `MSLSA:`
//! and `API:` names resolve through every name route of `rskrb5-ng`
//! (`CCache::load_name` and `save_name`, `file_store::resolve` and
//! `collection`, the client's named and default cache lookups).
//!
//! `KCM:` is a built-in cache type of `rskrb5-ng` (plan todo 12), so this
//! crate never registers it. `macos::KcmMachStore` is its Mach backend,
//! usable directly; its transport `macos::MachTransport` becomes the
//! transport of the built-in `KCM:` store once `rskrb5-ng` offers
//! `ccache::kcm::install_transport`.
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
    error::Extensions,
    extensions::{Extension, Registry, StoreProvider},
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

/// The store providers of this platform with their default settings.
fn providers() -> Vec<Arc<dyn StoreProvider>> {
    vec![
        #[cfg(windows)]
        Arc::new(windows::MslsaStore::new()),
        #[cfg(target_os = "macos")]
        Arc::new(macos::ApiStore::new()),
    ]
}

/// Register the platform store providers in `registry` with their default
/// settings; `Registry::install_stores` then publishes them process-wide.
///
/// They are `MSLSA` (read-only) on Windows, `API` on macOS, and none
/// elsewhere. For other settings register a provider yourself, for example
/// `Extension::StoreProvider(Arc::new(MslsaStore::with_mutation(true)))`.
///
/// # Errors
///
/// The registration errors of [`Registry::register`], for example
/// `DuplicateId` when a provider of the same id is already registered.
#[inline]
pub fn register(registry: &mut Registry) -> Result<(), Extensions> {
    for provider in providers() {
        registry.register(Extension::StoreProvider(provider))?;
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

    /// Each platform registers its own store providers, once.
    #[test]
    fn registers_the_platform_stores() -> Result<(), Extensions> {
        // Given an empty registry.
        let mut registry = Registry::new();
        // When the platform stores are registered, twice.
        register(&mut registry)?;
        let again = register(&mut registry);
        // Then the platform's prefixes are listed, and a second registration
        // of a prefix is refused.
        let expected: &[&str] = if cfg!(windows) {
            &["MSLSA"]
        } else if cfg!(target_os = "macos") {
            &["API"]
        } else {
            &[]
        };
        assert_eq!(registry.ids(Interface::StoreProvider), expected);
        assert_eq!(again.is_err(), !expected.is_empty());
        Ok(())
    }
}

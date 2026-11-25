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
//! crate never registers it. On macOS it supplies the Mach transport of that
//! store: `install_kcm_transport` (macOS only) installs a transport factory
//! (`rskrb5_ng::ccache::kcm::seam::install_transport_factory`), and every
//! `KCM:` store built from a configuration then reaches the Mach service
//! that configuration's `kcm_mach_service` names (MIT 1.22.2
//! `src/lib/krb5/ccache/cc_kcm.c:189-281`), through the same KCM client and
//! name routes as the Unix socket. Without that call a configuration that
//! names another Mach service is refused with
//! `rskrb5_ng::error::Kcm::NoMachTransport`.
//!
//! # Security
//!
//! The unsafe code is confined to the OS calls of `windows/lsa.rs`,
//! `macos/mach.rs` and `macos/ccapi.rs`; each block has a `SAFETY` comment
//! and an `#[expect(unsafe_code)]`. Everything the OS returns is copied into
//! owned values and parsed by safe, bounds-checked code that Miri checks
//! (`mig`, `lsa_wire`, `principal_text`). `MSLSA:`
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
#[cfg(target_os = "macos")]
use rskrb5_ng::{ccache::kcm::seam, error::Kcm};
use rskrb5_ng::{
    error::Extensions,
    extensions::{Extension, Registry, StoreProvider},
};

pub mod error;
#[cfg(all(unix, test))]
mod kcm_fixture;
#[cfg(any(windows, test))]
mod lsa_wire;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(all(unix, test))]
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

/// Make the `KCM:` store of `rskrb5-ng` reach the Mach service of each
/// configuration's `kcm_mach_service`, process-wide. Only macOS has Mach RPC,
/// so the function exists there only.
///
/// The factory it installs makes a transport per service name, so two
/// configurations naming two services reach two services; nothing is captured
/// from the first configuration. A service that is not registered hands the
/// request to the configured `kcm_socket`, as MIT falls back from Mach to the
/// socket; `kcm_mach_service = -` disables Mach.
///
/// # Security
///
/// The installation is process-wide and the first one wins: call it before
/// any other code reaches a `KCM:` cache.
///
/// # Errors
///
/// `rskrb5_ng::error::Kcm::TransportInstalled` when a transport factory is
/// installed already.
#[cfg(target_os = "macos")]
#[inline]
pub fn install_kcm_transport() -> Result<(), Kcm> {
    seam::install_transport_factory(Arc::new(macos::MachFactory))
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
    #[cfg(target_os = "macos")]
    use core::error::Error;
    #[cfg(target_os = "macos")]
    use std::sync::OnceLock;

    #[cfg(target_os = "macos")]
    use rskrb5_ng::{ccache::kcm::Store, config::Config};
    use rskrb5_ng::{
        error::Extensions,
        extensions::{Interface, Registry},
    };

    #[cfg(target_os = "macos")]
    use super::install_kcm_transport;
    use super::register;

    /// Install the KCM transport once per test process: the installation is
    /// process-wide, and every test that needs it shares it.
    #[cfg(target_os = "macos")]
    pub(crate) fn install_once() -> Result<(), String> {
        static INSTALLED: OnceLock<Result<(), String>> = OnceLock::new();
        INSTALLED
            .get_or_init(|| install_kcm_transport().map_err(|error| error.to_string()))
            .clone()
    }

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

    /// Installing the KCM transport makes a configured Mach service reachable.
    #[cfg(target_os = "macos")]
    #[test]
    fn installing_the_kcm_transport_serves_a_configured_mach_service() -> Result<(), Box<dyn Error>>
    {
        // Given a configuration that names a Mach service of its own.
        let config = Config::parse("[libdefaults]\n kcm_mach_service = org.example.kcm\n")?;
        // When the transport is installed.
        install_once()?;
        // Then the store for that service exists, where the main crate
        // refuses the same configuration while nothing is installed.
        let store = Store::from_libdefaults(&config.libdefaults);
        assert!(store.is_ok(), "{store:?}");
        Ok(())
    }
}

//! Cross-realm routing (WP-11, plan 2 todo 17): `[capaths]` and hierarchical
//! realm paths, DOMAIN-X500-COMPRESS transited encodings and the certificate
//! identity of certificate `S4U2Self`.

extern crate alloc;

use core::error::Error;

/// Error type of the `Result`-returning tests.
type TestError = Box<dyn Error + Send + Sync>;

/// MIT 1.22.2 realm-path vectors (`walktree-tests`) and the path bounds.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "routing/paths.rs"]
mod paths;

/// MIT 1.22.2 transited-expansion vectors (`transit-tests`) and the codec bounds.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "routing/transited.rs"]
mod transited;

/// The certificate identity of certificate S4U2Self and its inspection seam.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "routing/certificate.rs"]
mod certificate;

/// Forged AP-REQs with a chosen transited path.
#[cfg(test)]
#[cfg(feature = "messages")]
#[expect(
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
#[path = "routing/forge.rs"]
mod forge;

/// Acceptor transit validation: the multi-pair policy and `[capaths]`.
#[cfg(test)]
#[cfg(feature = "messages")]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "routing/acceptor.rs"]
mod acceptor;

/// A fake KDC for the sans-I/O TGS engine.
#[cfg(test)]
#[cfg(feature = "messages")]
#[expect(
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
#[path = "routing/kdc.rs"]
mod kdc;

/// Client referrals and `[capaths]` paths (FU-IOP-P12).
#[cfg(test)]
#[cfg(feature = "messages")]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "routing/referrals.rs"]
mod referrals;

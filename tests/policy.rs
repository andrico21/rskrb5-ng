//! Autonomous public policy API tests use local fixtures, including loopback UDP,
//! without an external KDC or ambient configuration.

/// Typed rejection propagation.
#[cfg(test)]
#[path = "policy/rejections.rs"]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod rejections;

/// MIT expression resolution without profile-parser wiring.
#[cfg(test)]
#[path = "policy/expressions.rs"]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod expressions;

/// Property-based ordered-list regression coverage.
#[cfg(test)]
#[path = "policy/ordering.rs"]
mod ordering;

/// Profile and common runtime policy integration.
#[cfg(test)]
#[path = "policy/profile.rs"]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod profile;

/// Repeated-relation security constraints.
#[cfg(test)]
#[path = "policy/repeated.rs"]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod repeated;

/// Checked cryptographic dispatch enforces policy before primitive validation.
#[cfg(test)]
#[path = "policy/checked.rs"]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod checked;

/// Policy checks at semantic credential-import boundaries.
#[cfg(test)]
#[cfg(feature = "messages")]
#[path = "policy/imports.rs"]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod imports;

/// Client request and cache policy boundaries.
#[cfg(test)]
#[cfg(feature = "tokio")]
#[path = "policy/client.rs"]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod client;

/// Cache-use and preauthentication early-effect regression tests.
#[cfg(test)]
#[cfg(feature = "tokio")]
#[path = "policy/client_effects.rs"]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod client_effects;

/// Independently encrypted reply policy isolation fixtures.
#[cfg(test)]
#[cfg(feature = "tokio")]
#[path = "policy/reply_isolation.rs"]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod reply_isolation;

/// Explicit legacy permission propagation through SPNEGO.
#[cfg(test)]
#[cfg(all(feature = "tokio", feature = "spnego"))]
#[path = "policy/legacy_context.rs"]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod legacy_context;

/// Checked import must not call public policy-free conversion entry points.
#[cfg(test)]
#[path = "policy/import_guard.rs"]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod import_guard;

/// Acceptor and AP-REP policy enforcement with encrypted fixtures.
#[cfg(test)]
#[cfg(all(feature = "tokio", feature = "spnego"))]
#[path = "policy/acceptor.rs"]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod acceptor;

/// Outgoing accepted-context policy enforcement.
#[cfg(test)]
#[cfg(all(feature = "tokio", feature = "spnego"))]
#[path = "policy/acceptor_reply.rs"]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod acceptor_reply;

/// Config and HTTP constructor policy propagation.
#[cfg(test)]
#[cfg(feature = "tower")]
#[cfg(feature = "tokio")]
#[path = "policy/acceptor_http.rs"]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod acceptor_http;

/// Trusted per-family string-to-key policy API.
#[cfg(test)]
#[path = "policy/s2k.rs"]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod s2k;

/// Permanent algorithm-selection rejection across F1 boundaries.
#[cfg(test)]
#[path = "policy/selection.rs"]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod selection;

/// Raw algorithm selection and pre-effect refusal regressions.
#[cfg(feature = "messages")]
#[cfg(test)]
#[path = "policy/raw_selection.rs"]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod raw_selection;

/// Removed protocol selections cannot be enabled through configuration or APIs.
#[cfg(test)]
#[path = "policy/protocols.rs"]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod protocols;

/// Security-policy documentation and serde diagnostic contracts.
#[cfg(test)]
#[path = "policy/documentation.rs"]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod documentation;

/// Checked request representation and outgoing credential admission.
#[cfg(test)]
#[cfg(feature = "tokio")]
#[path = "policy/exchange_admission.rs"]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod exchange_admission;

/// Additional-ticket policy before TGS and S4U cryptography.
#[cfg(test)]
#[cfg(feature = "tokio")]
#[path = "policy/additional_tickets.rs"]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod additional_tickets;

/// Programmatic request selection and causal admission errors.
#[cfg(test)]
#[cfg(feature = "tokio")]
#[path = "policy/staged_requests.rs"]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod staged_requests;

/// Nested credential encryption admission before transport and request cryptography.
#[cfg(test)]
#[cfg(feature = "tokio")]
#[path = "policy/nested_padata.rs"]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod nested_padata;

/// Encrypted body admission at synchronous and Tokio transport boundaries.
#[cfg(test)]
#[cfg(feature = "tokio")]
#[path = "policy/body_authorization.rs"]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod body_authorization;

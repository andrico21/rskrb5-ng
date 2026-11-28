//! Fuzz the RFC 5929 `tls-server-end-point` derivation of the HTTP client
//! (plan 2 todo 28, FU-HTC-P07).
//!
//! The input is the DER end-entity certificate a TLS peer presented.
//! `http::wire::TlsChannel::from_end_entity` decodes its outer structure and
//! signature algorithm (RSASSA-PSS parameters included); an accepted
//! certificate keeps its bytes, and its bindings, when defined, are the
//! `tls-server-end-point:` prefix and one SHA-2 digest.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rskrb5_ng::http::wire::TlsChannel;

/// The `tls-server-end-point` application-data prefix.
const PREFIX: &[u8] = b"tls-server-end-point:";

fuzz_target!(|data: &[u8]| {
    let Ok(channel) = TlsChannel::from_end_entity(data.to_vec()) else {
        return;
    };
    assert_eq!(
        channel.certificate(),
        data,
        "the certificate is kept as given"
    );
    if let Some(bindings) = channel.server_end_point() {
        let digest = bindings
            .application_data()
            .strip_prefix(PREFIX)
            .unwrap_or_default();
        assert!(
            [28, 32, 48, 64].contains(&digest.len()),
            "one SHA-2 digest follows the prefix"
        );
    }
});

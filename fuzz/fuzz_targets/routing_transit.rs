//! Fuzz the cross-realm routing parsers (plan 2 todo 17).
//!
//! The first input byte selects the parser and the rest is its input: a
//! ticket's DOMAIN-X500-COMPRESS transited encoding (`transited::decode`
//! between two fixed realms; an accepted list stays within the realm bound
//! and, when it encodes, encodes to an encoding that decodes to the same
//! list), a KDC's `PA-S4U-X509-USER` (`PaS4uX509User::decode_der`, then encode
//! and decode again, which must give the same element), or the text of two
//! realm names (`RealmPath::hierarchical`, whose path starts at the first,
//! ends at the second and stays within the path bound). None may panic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rskrb5_ng::routing::{RealmPath, s4u::PaS4uX509User, transited};

/// The client realm of the fuzzed transited encodings.
const CLIENT: &str = "ATHENA.MIT.EDU";
/// The server realm of the fuzzed transited encodings.
const SERVER: &str = "HACK.FOOBAR.COM";

fuzz_target!(|data: &[u8]| {
    let Some((selector, input)) = data.split_first() else {
        return;
    };
    match selector & 0x03 {
        0 => {
            if let Ok(realms) = transited::decode(input, CLIENT, SERVER) {
                assert!(realms.len() <= transited::MAX_REALMS, "realm bound");
                if let Ok(encoded) = transited::encode(&realms) {
                    assert_eq!(
                        transited::decode(&encoded, CLIENT, SERVER).ok(),
                        Some(realms),
                        "an encoded list decodes to itself"
                    );
                }
            }
        }
        1 => {
            if let Ok(element) = PaS4uX509User::decode_der(input) {
                let again = element
                    .encode_der()
                    .ok()
                    .and_then(|encoded| PaS4uX509User::decode_der(&encoded).ok());
                assert_eq!(again, Some(element), "decode and encode round-trip");
            }
        }
        _ => {
            let text = String::from_utf8_lossy(input);
            let (client, server) = text.split_once(' ').unwrap_or((&text, SERVER));
            if let Ok(path) = RealmPath::hierarchical(client, server) {
                let realms = path.realms();
                assert!(realms.len() <= RealmPath::MAX_REALMS, "path bound");
                assert_eq!(
                    realms.first().map(String::as_str),
                    Some(client),
                    "starts at the client"
                );
                assert_eq!(
                    realms.last().map(String::as_str),
                    Some(server),
                    "ends at the server"
                );
            }
        }
    }
});

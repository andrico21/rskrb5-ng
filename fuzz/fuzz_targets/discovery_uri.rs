//! Fuzz the parsers of the data that DNS hands to server discovery.
//!
//! The first input byte selects the parser and the rest is its input: the target of
//! a `krb5srv:flags:transport:host` URI record and then the `host[:port]` of an
//! accepted one, the data of a URI record (priority, weight, target), the first
//! string of a TXT realm record, or a bare `host[:port]`. None may panic, and a
//! host that was split must come back non-empty and a TXT realm must stay within its
//! bound.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rskrb5_ng::discovery::uri;

fuzz_target!(|data: &[u8]| {
    let Some((selector, input)) = data.split_first() else {
        return;
    };
    match selector & 0x03 {
        0 => {
            if let Some(target) = uri::parse(input) {
                assert!(target.spec.len() <= uri::MAX_TARGET_BYTES);
                if let Some((host, _port)) = uri::host_port(&target.spec, 88) {
                    assert!(!host.is_empty(), "an empty host was accepted");
                }
            }
        }
        1 => {
            if let Some((_priority, target)) = uri::split_rdata(input) {
                assert!(target.len() <= input.len());
            }
        }
        2 => {
            if let Some(realm) = uri::realm_from_txt(input) {
                assert!(!realm.is_empty() && realm.len() <= 255);
            }
        }
        _ => {
            let text = String::from_utf8_lossy(input);
            if let Some((host, _port)) = uri::host_port(&text, 464) {
                assert!(!host.is_empty(), "an empty host was accepted");
            }
        }
    }
});

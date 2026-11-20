//! Fuzz the primary-name key of a `KEYRING:` collection.
//!
//! The key `krb_ccache:primary` is writable by every process of the user, so
//! its payload is untrusted bytes: the version, the length and the name of the
//! primary cache (MIT `cc_keyring.c:541-571`). Nothing may panic, and a payload
//! that is accepted must encode and decode again to the same name.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rskrb5_ng::ccache::keyring::index;

fuzz_target!(|data: &[u8]| {
    if let Ok(name) = index::parse(data) {
        assert!(!name.is_empty(), "accepted an empty cache name");
        assert!(!name.contains('\0'), "accepted a NUL in a cache name");
        assert_eq!(
            index::parse(&index::encode(&name)).ok().as_deref(),
            Some(name.as_str()),
            "encode and parse disagree"
        );
    }
});

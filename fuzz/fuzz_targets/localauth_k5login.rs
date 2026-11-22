//! Fuzz the `.k5login` reader (plan 2 todo 25, WP-17).
//!
//! The input is a principal name (`a/b@REALM`, up to the first newline) and
//! then the bytes of a `.k5login` file. `k5login::lists` scans the bytes for
//! the unparsed principal under the size, line-count and line-length bounds.
//! It may not panic, and a file past the size bound is refused.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rskrb5_ng::{
    ccache::Principal,
    localauth::k5login::{Fault, MAX_FILE_BYTES, lists},
};

fuzz_target!(|data: &[u8]| {
    let split = data.iter().position(|byte| *byte == b'\n');
    let (head, contents) = split.map_or((data, &[][..]), |index| {
        (
            data.get(..index).unwrap_or_default(),
            data.get(index.saturating_add(1)..).unwrap_or_default(),
        )
    });
    let head = String::from_utf8_lossy(head);
    let (name, realm) = head.rsplit_once('@').unwrap_or((&head, "EXAMPLE.COM"));
    let principal = Principal::new(realm, 1, name.split('/').map(str::to_owned).collect());
    let verdict = lists(contents, &principal);
    if contents.len() > MAX_FILE_BYTES {
        assert_eq!(verdict, Err(Fault::TooLarge), "the size bound");
    }
});

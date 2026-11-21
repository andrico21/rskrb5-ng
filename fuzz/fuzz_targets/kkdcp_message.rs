//! Fuzz the MS-KKDCP codec and the proxy URL parser (plan 2 todo 16).
//!
//! The first input byte selects the parser and the rest is its input: a proxy's
//! KDC-PROXY-MESSAGE (`ProxyMessage::decode`, then encode and decode again, which
//! must give the same message), the same bytes as a reply (`decode_reply`, whose
//! message must be non-empty and shorter than the input), or the text of an
//! `https://` server entry or DNS URI target (`Url::parse`, whose accepted URL must
//! parse again from its display form to the same URL). None may panic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rskrb5_ng::transport::{
    kkdcp::{ProxyMessage, decode_reply},
    proxy::Url,
};

fuzz_target!(|data: &[u8]| {
    let Some((selector, input)) = data.split_first() else {
        return;
    };
    match selector & 0x03 {
        0 => {
            if let Ok(message) = ProxyMessage::decode(input) {
                let encoded = message.encode().expect("a decoded message encodes");
                let again = ProxyMessage::decode(&encoded).expect("an encoded message decodes");
                assert_eq!(again, message, "decode and encode round-trip");
            }
        }
        1 => {
            if let Ok(reply) = decode_reply(input) {
                assert!(!reply.is_empty(), "an empty reply was accepted");
                assert!(reply.len() < input.len(), "the reply outgrew its message");
            }
        }
        _ => {
            let text = String::from_utf8_lossy(input);
            if let Ok(Some(url)) = Url::parse(&text) {
                let shown = url.to_string();
                let again = Url::parse(&shown).expect("a shown URL parses");
                assert_eq!(again, Some(url), "a URL survives its display form");
            }
        }
    }
});

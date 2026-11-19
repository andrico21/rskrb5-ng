//! Fuzz the extension-point parsers that read text.
//!
//! The first input byte selects the mode and the rest is its input. An even
//! selector feeds the bytes to the built-in `k5identity` selector as
//! `.k5identity` contents and selects for a host-based and a plain server; an
//! odd one parses the UTF-8-lossy text with `Registry::parse_config`, whose
//! registry resolves the `site` profile provider and the built-in `ccselect`
//! modules. None may panic.

#![no_main]

extern crate alloc;

use alloc::sync::Arc;

use libfuzzer_sys::fuzz_target;
use rskrb5_ng::{
    ccache::Principal,
    config::ParseMode,
    extensions::{
        CacheCandidate, CacheSelector as _, Extension, K5Identity, ProfileProvider, ProviderError,
        Registry, SelectionRequest,
    },
};

/// A profile provider that turns its residual into a default realm.
struct Site;

impl ProfileProvider for Site {
    fn id(&self) -> &'static str {
        "site"
    }

    fn profile(&self, residual: &str) -> Result<String, ProviderError> {
        Ok(format!("[libdefaults]\n default_realm = {residual}\n"))
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((selector, input)) = data.split_first() else {
        return;
    };
    if selector & 1 == 0 {
        let caches = [CacheCandidate::new(
            "MEMORY:alice",
            Principal::new("EXAMPLE.ORG", 1, vec!["alice".to_owned()]),
        )];
        let identity = K5Identity::from_bytes(input);
        for server in [
            Principal::new(
                "EXAMPLE.ORG",
                3,
                vec!["HTTP".to_owned(), "www.example.org".to_owned()],
            ),
            Principal::new("EXAMPLE.ORG", 1, vec!["svc".to_owned()]),
        ] {
            drop(identity.choose(&SelectionRequest::new(
                &server,
                &caches,
                Some("DEFAULT.ORG"),
            )));
        }
    } else {
        let text = String::from_utf8_lossy(input);
        let mut registry = Registry::with_builtins(None);
        drop(registry.register(Extension::ProfileProvider(Arc::new(Site))));
        for mode in [ParseMode::Compatible, ParseMode::Strict] {
            drop(registry.parse_config(&text, mode));
        }
    }
});

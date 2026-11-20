//! Unit tests of the keyring cache logic against the in-memory kernel.

use alloc::sync::Arc;
use core::error;
use std::time::{SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

use super::{
    backend::{Backend as _, Kind, Ring},
    engine::Engine,
    fake::Fake,
};
use crate::ccache::{
    Credential, CredentialTimes, EncryptionKey, Error, Principal,
    stores::{CacheCollection, CacheHandle},
};

/// Collections, anchors and unique caches.
mod collections;
/// Kernel failures and malformed keys.
mod failures;
/// The legacy anchor, an old kernel and time offsets.
mod legacy;
/// Residual names, descriptions and payloads.
mod names;
/// Cache operations.
mod operations;

/// The error of a test that propagates with `?`.
type TestError = Box<dyn error::Error>;

/// A fake kernel and the engine over it.
fn kernel() -> (Fake, Engine) {
    let fake = Fake::new();
    let engine = Engine::new(Arc::new(fake.clone()));
    (fake, engine)
}

/// The principal `name@EXAMPLE.COM` with a `/`-separated name.
fn principal(name: &str) -> Principal {
    Principal::new(
        "EXAMPLE.COM",
        1,
        name.split('/').map(str::to_owned).collect(),
    )
}

/// The current time in seconds.
fn now() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u32::try_from(elapsed.as_secs()).unwrap_or(u32::MAX)
        })
}

/// A credential of `alice` for `server` that ends at `end_time`.
fn credential(server: &str, end_time: u32, ticket: &[u8]) -> Credential {
    let times = CredentialTimes {
        end_time,
        ..CredentialTimes::default()
    };
    Credential::new(
        principal("alice"),
        principal(server),
        EncryptionKey::new(18, vec![7; 32]),
        times,
        [0; 4],
        Zeroizing::new(ticket.to_vec()),
    )
}

/// The cache a residual names, on `engine`.
fn cache(engine: &Engine, residual: &str) -> Result<Box<dyn CacheHandle>, Error> {
    engine.resolve(residual)
}

/// The collection a residual names, on `engine`.
fn collection(engine: &Engine, residual: &str) -> Result<Box<dyn CacheCollection>, Error> {
    engine.collection(residual)
}

/// The ring of the keyring `name` in `parent`.
fn ring_of(fake: &Fake, parent: Ring, name: &str) -> Result<Ring, TestError> {
    Ok(Ring::Key(fake.search(parent, Kind::Keyring, name, None)?))
}

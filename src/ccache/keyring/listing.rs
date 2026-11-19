//! What a cache keyring holds (`krcc_start_seq_get`, `krcc_next_cred`,
//! `update_keyring_expiration`).

use super::{
    Fault, KernelError,
    backend::{Kind, Ring, Serial},
    engine::Engine,
    payload::{parse_credential, seconds_until},
    residual::{PRINCIPAL_KEY, TIME_OFFSETS_KEY},
};
use crate::ccache::{Credential, Error};

/// What a cache keyring holds.
pub(super) struct Listing {
    /// The default principal key.
    pub principal: Option<Serial>,
    /// The time offsets key.
    pub offsets: Option<Serial>,
    /// The credential keys with their credentials, in keyring order.
    pub credentials: Vec<(Serial, Credential)>,
}

/// The principal key and the credentials of a cache keyring
/// (`krcc_start_seq_get`, `krcc_next_cred`). A key that vanished or cannot
/// be read is skipped, as MIT does.
///
/// # Errors
///
/// Kernel and parse errors.
pub(super) fn list(engine: &Engine, cache: Serial) -> Result<Listing, Error> {
    let ring = Ring::Key(cache);
    let principal = engine.lookup(ring, Kind::User, PRINCIPAL_KEY, None)?;
    let offsets = engine.lookup(ring, Kind::User, TIME_OFFSETS_KEY, None)?;
    let mut credentials = Vec::new();
    for key in engine.children(cache)? {
        if Some(key) == principal || Some(key) == offsets {
            continue;
        }
        match engine.backend().read(Ring::Key(key)) {
            Ok(payload) => credentials.push((key, parse_credential(&payload)?)),
            Err(KernelError::KeyNotFound | KernelError::AccessDenied) => {}
            Err(error) => {
                return Err(Fault::Kernel {
                    operation: "keyctl_read",
                    error,
                }
                .into());
            }
        }
    }
    Ok(Listing {
        principal,
        offsets,
        credentials,
    })
}

/// Expire the cache keyring with its last credential
/// (`update_keyring_expiration`): a cache whose credentials all expired
/// lingers one second.
///
/// # Errors
///
/// The errors of [`list`] and kernel errors.
pub(super) fn expire_with_credentials(engine: &Engine, cache: Serial) -> Result<(), Error> {
    let latest = list(engine, cache)?
        .credentials
        .iter()
        .map(|(_, credential)| credential.times.end_time)
        .max()
        .unwrap_or(0);
    if latest == 0 {
        return Ok(());
    }
    let seconds = seconds_until(latest).unwrap_or(1);
    Engine::call(
        "keyctl_set_timeout",
        engine.backend().set_timeout(Ring::Key(cache), seconds),
    )
}

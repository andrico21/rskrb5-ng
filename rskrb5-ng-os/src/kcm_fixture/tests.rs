//! The fixture against the KCM requests of `rskrb5-ng`.
//!
//! The Mach tests of macOS serve the fixture to the main crate's `KCM:`
//! routes; this test keeps the fixture honest on every unix target, by
//! speaking to it with the requests of that codec.

use core::error::Error;

use rskrb5_ng::{
    ccache::{
        Credential, CredentialTimes, EncryptionKey, Principal,
        kcm::{
            seam::KcmTransport as _,
            wire::{
                Residual, Uuid,
                calls::{self, Call},
            },
        },
    },
    error::Kcm,
};

use super::Fixture;
use crate::marshal;

/// Send `call` to `fixture`: the daemon's status and its payload.
fn send<S>(fixture: &Fixture, call: &Call<S>) -> Result<(i32, Vec<u8>), Kcm> {
    let reply = fixture.call(call.request().as_bytes())?;
    let (status, payload) = reply.split_first_chunk::<4>().ok_or(Kcm::Unencodable)?;
    Ok((i32::from_be_bytes(*status), payload.to_vec()))
}

/// A cache initialized, given a credential and read back with the requests
/// of the main crate, then destroyed.
#[test]
fn the_fixture_answers_the_main_requests() -> Result<(), Box<dyn Error>> {
    // Given the fixture and a credential of alice for a web server.
    let fixture = Fixture::default();
    let alice = Principal::new("EXAMPLE.ORG", 1, vec!["alice".to_owned()]);
    let mut times = CredentialTimes::default();
    times.end_time = 2_000_000_000;
    let ticket = Credential::new(
        alice.clone(),
        Principal::new("EXAMPLE.ORG", 2, vec!["HTTP".to_owned(), "web".to_owned()]),
        EncryptionKey::new(18, vec![9; 32]),
        times,
        [0x40, 0, 0, 0],
        vec![0x61, 0x01, 0x00].into(),
    );
    let name = Residual::new("fixture").ok_or(Kcm::Unencodable)?;
    // When the cache is initialized, stored into and read.
    let initialized = send(&fixture, &calls::initialize(&name, &alice)?)?;
    let stored = send(&fixture, &calls::store(&name, &ticket)?)?;
    let principal = send(&fixture, &calls::get_principal(&name))?;
    let (_, uuids) = send(&fixture, &calls::get_cred_uuid_list(&name))?;
    let uuid = *uuids.first_chunk::<16>().ok_or(Kcm::Unencodable)?;
    let credential = send(&fixture, &calls::get_cred_by_uuid(&name, Uuid::new(uuid)))?;
    let destroyed = send(&fixture, &calls::destroy(&name))?;
    let gone = send(&fixture, &calls::get_principal(&name))?;
    // Then the requests were understood, the replies hold the bytes the main
    // crate wrote, and the destroyed cache is gone.
    assert_eq!(
        (initialized.0, stored.0, destroyed.0),
        (0_i32, 0_i32, 0_i32)
    );
    assert_eq!(principal.1, marshal::principal(&alice)?.to_vec());
    assert_eq!(uuids.len(), 16);
    assert_eq!(credential.1, marshal::credential(&ticket)?.to_vec());
    assert_ne!(gone.0, 0_i32);
    Ok(())
}

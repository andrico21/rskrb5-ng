//! The tickets the IAKERB initiator's exchanges acquired: kept for the
//! AP-REQ's delegation and for an explicit output cache (MIT `out_ccache`,
//! `iakerb.c:484-487`).

use super::{super::Error, State};
use crate::{
    ccache::CCache,
    client::TgsRepSession,
    error::Gss,
    gss::{CredStore, Credential, cred},
};

/// Keep `ticket`, which an exchange of `state` acquired.
pub(super) fn keep(state: &mut State, ticket: &TgsRepSession) {
    let entry = cred::entry_of(ticket);
    let cache = state
        .acquired
        .get_or_insert_with(|| CCache::new(entry.client().clone()));
    drop(cache.upsert_credential(entry));
}

/// The credential the AP-REQ is built from: `credential`'s tickets and the
/// acquired ones, so a delegation finds the TGT wherever it came from;
/// `None` when nothing was acquired.
///
/// # Errors
///
/// Returns [`Gss::NoCredential`] for a cache without a client.
pub(super) fn holding(state: &State, credential: &Credential) -> Result<Option<Credential>, Error> {
    let Some(acquired) = &state.acquired else {
        return Ok(None);
    };
    let mut cache = credential
        .cache
        .clone()
        .unwrap_or_else(|| CCache::new(acquired.default_principal().clone()));
    for entry in acquired.credentials() {
        drop(cache.upsert_credential(entry.clone()));
    }
    Ok(Some(cred::from_ccache(cache)?))
}

/// Store the acquired tickets as `gss_store_cred_into` does.
///
/// # Errors
///
/// Returns [`Gss::NoCredential`] when no ticket was acquired, and the
/// errors of [`cred::store_into`].
pub(in crate::gss::iakerb) fn store_acquired_into(
    state: &State,
    store: &CredStore,
    overwrite: bool,
) -> Result<(), Error> {
    let acquired = state
        .acquired
        .clone()
        .ok_or(Gss::NoCredential("the context acquired no tickets"))?;
    Ok(cred::store_into(
        &cred::from_ccache(acquired)?,
        store,
        overwrite,
    )?)
}

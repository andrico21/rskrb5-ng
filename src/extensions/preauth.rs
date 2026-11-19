//! Client preauthentication sessions.

use alloc::sync::Arc;

use rasn_kerberos::PaData;

use super::{
    ClientPreauth, Error, Event, Interface, MAX_PADATA_BYTES, MAX_PADATA_OUTPUTS,
    MAX_PREAUTH_ROUNDS, PreauthInput, PreauthSession, PreauthState, Refusal, Registry, checks,
    order,
};
use crate::{
    client,
    config::Config,
    crypto::CryptoPolicy,
    error::{Client as ClientError, Crypto},
};

/// One session mechanism and its lazily started per-exchange state.
pub(super) type Mechanism = (Arc<dyn ClientPreauth>, Option<Box<dyn PreauthState>>);

/// The enabled mechanisms in order, each skipped when an earlier kept one
/// already answers one of its PA types (MIT `preauth2.c:171-180`).
pub(super) fn session<'registry>(
    registry: &'registry Registry,
    config: &Config,
    policy: &CryptoPolicy,
) -> PreauthSession<'registry> {
    let interface = Interface::ClientPreauth;
    let mut mechanisms: Vec<Mechanism> = Vec::new();
    for mechanism in order::enabled(&registry.preauth, interface, Some(config), |item| item.id()) {
        let conflict = mechanisms.iter().any(|(kept, _)| {
            kept.pa_types()
                .iter()
                .any(|pa_type| mechanism.pa_types().contains(pa_type))
        });
        if conflict {
            order::notify(
                &registry.observers,
                &Event::Refused {
                    interface,
                    id: mechanism.id(),
                    reason: Refusal::Conflict,
                },
            );
        } else {
            mechanisms.push((Arc::clone(mechanism), None));
        }
    }
    PreauthSession {
        mechanisms,
        policy: policy.clone(),
        rounds: 0,
        observers: &registry.observers,
    }
}

/// Run one round and admit its output.
/// # Errors
/// Returns the round bound, the mechanism's failure, or the refusal of its output.
pub(super) fn respond(
    session: &mut PreauthSession<'_>,
    pa_type: i32,
    method_data: &[PaData],
    request_body: &[u8],
) -> Result<Option<Vec<PaData>>, Error> {
    let interface = Interface::ClientPreauth;
    let observers = session.observers;
    let Some((mechanism, state)) = session
        .mechanisms
        .iter_mut()
        .find(|(mechanism, _)| mechanism.pa_types().contains(&pa_type))
    else {
        return Ok(None);
    };
    if session.rounds >= MAX_PREAUTH_ROUNDS {
        return Err(Error::TooManyRounds {
            limit: MAX_PREAUTH_ROUNDS,
        });
    }
    session.rounds = session.rounds.saturating_add(1);
    let id = mechanism.id();
    order::notify(observers, &Event::Consulted { interface, id });
    let refused = |reason: Refusal| {
        order::notify(
            observers,
            &Event::Refused {
                interface,
                id,
                reason,
            },
        );
    };
    let input = PreauthInput::new(pa_type, method_data, request_body, session.rounds);
    let output = state
        .get_or_insert_with(|| mechanism.start())
        .process(&input)
        .map_err(|source| {
            refused(Refusal::Failed);
            Error::CallFailed {
                interface,
                id: id.to_owned(),
                source,
            }
        })?;
    let oversized = output.len() > MAX_PADATA_OUTPUTS
        || output
            .iter()
            .any(|entry| entry.value.len() > MAX_PADATA_BYTES);
    if oversized {
        refused(Refusal::TooLarge);
        return Err(Error::OutputTooLarge {
            interface,
            id: id.to_owned(),
            limit: MAX_PADATA_BYTES,
        });
    }
    if output
        .iter()
        .any(|entry| !mechanism.pa_types().contains(&entry.r#type))
    {
        refused(Refusal::Malformed);
        return Err(checks::malformed(
            interface,
            id,
            "PA type the mechanism did not register",
        ));
    }
    if let Err(refusal) = client::admit_padata(&session.policy, &output) {
        let policy = if let ClientError::Crypto(Crypto::Policy(source)) = refusal {
            Some(source)
        } else {
            None
        };
        refused(if policy.is_some() {
            Refusal::Policy
        } else {
            Refusal::Malformed
        });
        return Err(policy.map_or_else(
            || checks::malformed(interface, id, "PA-DATA the outgoing admission refuses"),
            |source| Error::PolicyRefused {
                id: id.to_owned(),
                source,
            },
        ));
    }
    order::notify(observers, &Event::Chosen { interface, id });
    Ok(Some(output))
}

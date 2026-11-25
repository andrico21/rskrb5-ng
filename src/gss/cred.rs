//! Credential acquisition, ticket lookup and storage.
//!
//! Credential acquisition, ticket lookup and storage (MIT 1.22.2
//! `acquire_cred.c:150-215,560-760`, `store_cred.c`, `cred_store.c`).

use core::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

use super::{
    CCache, CredStore, Credential, CredentialInquiry, CredentialUsage, Error, Keytab, Name,
    ObjectIdentifier, Principal, TgsRepSession, ccache,
};
use crate::{
    ccache::{file_store, stores::CacheVersion},
    keytab::EncryptionKey,
    replay::RcacheName,
    service::AcceptorName,
};
#[cfg(feature = "tokio")]
use crate::{client, error::Client as ClientError};

/// The `FORWARDABLE` ticket flag in ccache byte order (RFC 4120 flag 1).
const FORWARDABLE: u8 = 0x40;
/// The `OK-AS-DELEGATE` ticket flag in ccache byte order (RFC 4120 flag 13).
pub(super) const OK_AS_DELEGATE: [u8; 4] = [0x00, 0x04, 0x00, 0x00];

/// A client principal from its ccache form.
fn principal_of(value: &ccache::Principal) -> Principal {
    Principal::new(
        value.realm.clone(),
        value.name_type,
        value.components.clone(),
    )
}

/// The ccache form of a principal.
pub(super) fn cache_principal(value: &Principal) -> ccache::Principal {
    ccache::Principal::new(
        value.realm.clone(),
        value.name_type,
        value.components.clone(),
    )
}

/// Whole POSIX seconds of `at`, saturated to the ccache range.
fn seconds(at: SystemTime) -> u32 {
    at.duration_since(UNIX_EPOCH).map_or(0, |since| {
        u32::try_from(since.as_secs()).unwrap_or(u32::MAX)
    })
}

/// The time of POSIX `value` seconds.
fn time_of(value: u32) -> SystemTime {
    UNIX_EPOCH
        .checked_add(Duration::from_secs(value.into()))
        .unwrap_or(UNIX_EPOCH)
}

/// The ccache entry of a ticket session.
pub(super) fn entry_of(ticket: &TgsRepSession) -> ccache::Credential {
    let times = ccache::CredentialTimes {
        auth_time: seconds(ticket.auth_time()),
        start_time: seconds(ticket.start_time()),
        end_time: seconds(ticket.end_time()),
        renew_till: ticket.renew_till().map_or(0, seconds),
    };
    ccache::Credential::new(
        cache_principal(ticket.client()),
        cache_principal(ticket.service()),
        ccache::EncryptionKey::new(
            ticket.session_key().etype(),
            ticket.session_key().value().to_vec(),
        ),
        times,
        ticket.ticket_flags(),
        Zeroizing::new(ticket.ticket().to_vec()),
    )
}

/// The ticket session of a ccache entry.
pub(super) fn session_of(entry: &ccache::Credential) -> TgsRepSession {
    let times = entry.times();
    let start = if times.start_time == 0 {
        times.auth_time
    } else {
        times.start_time
    };
    TgsRepSession::new(
        principal_of(entry.client()),
        principal_of(entry.server()),
        EncryptionKey::new(entry.key().etype(), entry.key().value().to_vec()),
        Zeroizing::new(entry.ticket().to_vec()),
        entry.ticket_flags(),
        time_of(times.auth_time),
        time_of(times.end_time),
    )
    .with_start_time(time_of(start))
    .with_renew_till((times.renew_till != 0).then(|| time_of(times.renew_till)))
}

/// A credential with nothing in it yet.
pub(super) const fn empty(usage: CredentialUsage) -> Credential {
    Credential {
        name: None,
        usage,
        cache: None,
        client_keytab: None,
        password: None,
        keytab: None,
        replay: None,
        verify_keytab: None,
        verify_server: None,
        impersonator: None,
    }
}

/// A copy of `credential`, for a proxy credential's impersonator.
pub(super) fn duplicate(credential: &Credential) -> Credential {
    Credential {
        name: credential.name.clone(),
        usage: credential.usage,
        cache: credential.cache.clone(),
        client_keytab: credential.client_keytab.clone(),
        password: credential.password.clone(),
        keytab: credential.keytab.clone(),
        replay: credential.replay.clone(),
        verify_keytab: credential.verify_keytab.clone(),
        verify_server: credential.verify_server.clone(),
        impersonator: credential
            .impersonator
            .as_deref()
            .map(|inner| Box::new(duplicate(inner))),
    }
}

/// An initiator credential of a cache.
///
/// # Errors
///
/// Returns [`Error::NoCredential`] for a cache without a client.
pub(super) fn from_ccache(cache: CCache) -> Result<Credential, Error> {
    let client = principal_of(cache.default_principal());
    if client.components.is_empty() {
        return Err(Error::NoCredential("the cache names no client"));
    }
    let mut credential = empty(CredentialUsage::Initiate);
    credential.name = Some(Name::from_principal(&client));
    credential.cache = Some(cache);
    Ok(credential)
}

/// An initiator credential of one service ticket.
pub(super) fn from_service_ticket(ticket: &TgsRepSession) -> Credential {
    let mut cache = CCache::new(cache_principal(ticket.client()));
    drop(cache.upsert_credential(entry_of(ticket)));
    let mut credential = empty(CredentialUsage::Initiate);
    credential.name = Some(Name::from_principal(ticket.client()));
    credential.cache = Some(cache);
    credential
}

/// The acceptor matching rule of `name` (MIT `kg_acceptor_princ`,
/// `naming_exts.c:136-168`, and `krb5_sname_match`, `sname_match.c:30-58`).
pub(super) fn acceptor_name(name: &Name, ignore_hostname: bool) -> AcceptorName {
    AcceptorName::new(
        name.principal().realm.clone(),
        name.principal().components.clone(),
        name.is_hostbased(),
        ignore_hostname,
    )
}

/// Whether `keytab` holds a key for the acceptor `name`.
fn keytab_matches(keytab: &Keytab, name: &Name) -> bool {
    let rule = acceptor_name(name, false);
    keytab
        .entries()
        .iter()
        .any(|entry| rule.matches(&entry.principal().realm, &entry.principal().components))
}

/// Whether `keytab` holds a key for the client principal `name`.
fn client_keytab_matches(keytab: &Keytab, name: &Name) -> bool {
    keytab.entries().iter().any(|entry| {
        entry.principal().realm == name.principal().realm
            && entry.principal().components == name.principal().components
    })
}

/// Name a credential.
///
/// # Errors
///
/// Returns [`Error::NoCredential`] when the name does not fit the credential.
pub(super) fn with_name(mut credential: Credential, name: Name) -> Result<Credential, Error> {
    if credential.usage != CredentialUsage::Initiate {
        let keytab = credential
            .keytab
            .as_ref()
            .ok_or(Error::NoCredential("the credential holds no keytab"))?;
        if !keytab_matches(keytab, &name) {
            return Err(Error::NoCredential("the keytab holds no key for the name"));
        }
    }
    if credential.usage != CredentialUsage::Accept
        && let Some(current) = &credential.name
        && !current.compare(&name)
    {
        return Err(Error::NoCredential("the credential is another principal"));
    }
    credential.name = Some(name);
    Ok(credential)
}

/// Make `cache` the credential's tickets, named by its default principal.
fn take_cache(credential: &mut Credential, cache: CCache) {
    credential.name = Some(Name::from_principal(&principal_of(
        cache.default_principal(),
    )));
    credential.cache = Some(cache);
}

/// The cache of the collection `name` whose default principal is `desired`:
/// realm and ordered components equal (MIT `krb5_cc_cache_match`,
/// `cccursor.c:184-219`). The collection's primary cache is not switched.
///
/// # Errors
///
/// Returns the errors of opening the collection, walking it and loading the
/// matching cache; caches that cannot be read are skipped, as MIT does.
fn matching_cache(
    name: &str,
    desired: &Name,
    version: CacheVersion,
) -> Result<Option<CCache>, Error> {
    let client = cache_principal(desired.principal());
    Ok(file_store::collection(name, version)?
        .cache_match(&client)?
        .map(|cache| cache.load())
        .transpose()?)
}

/// The initiator half of `acquire_cred_from`.
///
/// # Errors
///
/// Returns [`Error::NoCredential`] when the store names no usable initiator
/// credential, and the errors of loading it.
fn initiator_from(
    credential: &mut Credential,
    desired: Option<&Name>,
    store: &CredStore,
) -> Result<(), Error> {
    if let Some(cache_name) = &store.ccache {
        let cache = match desired {
            Some(name) => matching_cache(cache_name, name, CacheVersion::default())?.ok_or(
                Error::NoCredential("no cache of the collection holds the desired name"),
            )?,
            None => CCache::load_name(cache_name).map_err(Error::Ccache)?,
        };
        take_cache(credential, cache);
        return Ok(());
    }
    let need = Error::NoCredential("a client keytab or password needs the desired name");
    if let Some(keytab_name) = &store.client_keytab {
        let name = desired.ok_or(need)?;
        let keytab = Keytab::load_name(keytab_name).map_err(Error::Keytab)?;
        if !client_keytab_matches(&keytab, name) {
            return Err(Error::NoCredential(
                "the client keytab holds no key for the name",
            ));
        }
        credential.name = Some(name.clone());
        credential.client_keytab = Some(keytab);
        return Ok(());
    }
    if let Some(password) = &store.password {
        let name = desired.ok_or(need)?;
        credential.name = Some(name.clone());
        credential.password = Some(Zeroizing::new(password.as_bytes().to_vec()));
        return Ok(());
    }
    Err(Error::NoCredential(
        "the store names no initiator credential",
    ))
}

/// The acceptor half of `acquire_cred_from`.
///
/// # Errors
///
/// Returns [`Error::NoCredential`] without a keytab or a key for the desired
/// name, [`Error::UnsupportedReplayCache`] for an `rcache` that is not a replay
/// cache name (`dfl:`, `file2:<path>`, `none:` or `memory:`) or cannot be
/// opened, and the errors of loading the keytab.
fn acceptor_from(
    credential: &mut Credential,
    desired: Option<&Name>,
    store: &CredStore,
) -> Result<(), Error> {
    let keytab_name = store
        .keytab
        .as_ref()
        .ok_or(Error::NoCredential("the store names no keytab"))?;
    credential.replay = match &store.rcache {
        None => None,
        Some(rcache) => Some(
            RcacheName::parse(rcache)
                .and_then(|name| name.open())
                .map_err(|_unusable| Error::UnsupportedReplayCache(rcache.clone()))?,
        ),
    };
    let keytab = Keytab::load_name(keytab_name)?;
    if let Some(name) = desired {
        if !keytab_matches(&keytab, name) {
            return Err(Error::NoCredential("the keytab holds no key for the name"));
        }
        credential.name = Some(name.clone());
    }
    credential.keytab = Some(keytab);
    Ok(())
}

/// `gss_acquire_cred_from`.
///
/// # Errors
///
/// Returns the errors of [`super::Credential::acquire_cred_from`].
pub(super) fn acquire_from(
    desired: Option<&Name>,
    usage: CredentialUsage,
    store: &CredStore,
) -> Result<Credential, Error> {
    let mut credential = empty(usage);
    if usage != CredentialUsage::Accept {
        initiator_from(&mut credential, desired, store)?;
    }
    if usage != CredentialUsage::Initiate {
        acceptor_from(&mut credential, desired, store)?;
    }
    if let Some(requested) = &store.verify {
        // The verify key needs a password (`acquire_cred.c:1298-1320`).
        if store.password.is_none() || usage == CredentialUsage::Accept {
            return Err(Error::NoCredential("the verify key needs a password"));
        }
        let keytab_name = store
            .keytab
            .as_ref()
            .ok_or(Error::NoCredential("the verify key needs the keytab key"))?;
        let server = if requested.is_empty() {
            None
        } else {
            Some(
                Name::import(requested.as_bytes(), super::NameType::Principal)?
                    .principal()
                    .clone(),
            )
        };
        credential.verify_keytab = Some(Keytab::load_name(keytab_name)?);
        credential.verify_server = server;
    }
    Ok(credential)
}

/// The initiator half of `gss_acquire_cred`.
///
/// That is the default cache, or with a desired name its cache in the default
/// collection, else the default client keytab (MIT `acquire_init_cred` and
/// `get_cache_for_name`, `acquire_cred.c:446-500,681-780`).
///
/// # Errors
///
/// Returns [`Error::NoCredential`] when neither a cache nor the client keytab
/// holds the desired name, and the errors of the default names, the collection
/// and the client keytab.
#[cfg(feature = "tokio")]
fn default_initiator(
    credential: &mut Credential,
    desired: Option<&Name>,
    config: &super::Config,
) -> Result<(), Error> {
    let default_name = client::default_ccache_name(config);
    let Some(name) = desired else {
        let loaded = CCache::load_resolved_name(&default_name?).map_err(ClientError::from)?;
        take_cache(credential, loaded);
        return Ok(());
    };
    if let Ok(cache_name) = default_name
        && let Some(loaded) = matching_cache(&cache_name, name, CacheVersion::default())?
    {
        take_cache(credential, loaded);
        return Ok(());
    }
    let keytab = client::default_client_keytab_name(config)?;
    if !client_keytab_matches(&keytab, name) {
        return Err(Error::NoCredential(
            "the client keytab holds no key for the name",
        ));
    }
    credential.name = Some(name.clone());
    credential.client_keytab = Some(keytab);
    Ok(())
}

/// `gss_acquire_cred` from the default names.
///
/// # Errors
///
/// Returns the errors of [`super::Credential::acquire_cred`].
#[cfg(feature = "tokio")]
pub(super) fn acquire_default(
    desired: Option<&Name>,
    usage: CredentialUsage,
    config: &super::Config,
) -> Result<Credential, Error> {
    use crate::keytab;

    let mut credential = empty(usage);
    if usage != CredentialUsage::Accept {
        default_initiator(&mut credential, desired, config)?;
    }
    if usage != CredentialUsage::Initiate {
        let keytab = keytab::default_keytab_name(&config.libdefaults)?;
        if let Some(name) = desired {
            if !keytab_matches(&keytab, name) {
                return Err(Error::NoCredential("the keytab holds no key for the name"));
            }
            credential.name = Some(name.clone());
        }
        credential.keytab = Some(keytab);
    }
    Ok(credential)
}

/// The components a target name's tickets are for.
///
/// # Errors
///
/// Returns [`Error::BadName`] for a host-based name without a host or a
/// certificate name.
pub(super) fn target_components(target: &Name) -> Result<&[String], Error> {
    let components = target.principal().components.as_slice();
    if target.certificate().is_some() || components.is_empty() {
        return Err(Error::BadName("a certificate name is not a target"));
    }
    if target.is_hostbased() && components.get(1).is_none_or(String::is_empty) {
        return Err(Error::BadName("a host-based target needs a host"));
    }
    Ok(components)
}

/// Whether `entry` is live at `now`.
fn live(entry: &ccache::Credential, now: SystemTime) -> bool {
    time_of(entry.times().end_time) > now
}

/// A live service ticket for `target` in the credential's cache.
pub(super) fn service_ticket(credential: &Credential, target: &Name) -> Option<TgsRepSession> {
    let components = target_components(target).ok()?;
    let realm = &target.principal().realm;
    let now = SystemTime::now();
    credential
        .cache
        .as_ref()?
        .credentials()
        .iter()
        .find(|entry| {
            entry.server().components == components
                && (realm.is_empty() || entry.server().realm == *realm)
                && live(entry, now)
        })
        .map(session_of)
}

/// The client's live, forwardable TGT in the credential's cache.
pub(super) fn forwardable_tgt(credential: &Credential) -> Option<&ccache::Credential> {
    let cache = credential.cache.as_ref()?;
    let realm = cache.client_realm();
    let now = SystemTime::now();
    cache.credentials().iter().find(|entry| {
        entry.server().components == ["krbtgt", realm]
            && entry.server().realm == realm
            && entry
                .ticket_flags()
                .first()
                .is_some_and(|byte| byte & FORWARDABLE != 0)
            && live(entry, now)
    })
}

/// `gss_store_cred_into`.
///
/// # Errors
///
/// Returns the errors of [`super::Credential::store_cred_into`].
pub(super) fn store_into(
    credential: &Credential,
    store: &CredStore,
    overwrite: bool,
) -> Result<(), Error> {
    let cache = credential
        .cache
        .as_ref()
        .ok_or(Error::NoCredential("no initiator tickets to store"))?;
    let cache_name = store
        .ccache
        .as_ref()
        .ok_or(Error::NoCredential("the store names no ccache"))?;
    if !overwrite
        && CCache::load_name(cache_name).is_ok_and(|existing| !existing.credentials().is_empty())
    {
        return Err(Error::DuplicateElement);
    }
    cache.save_name(cache_name)?;
    Ok(())
}

/// `gss_inquire_cred`.
pub(super) fn inquire(credential: &Credential) -> CredentialInquiry {
    let expires = credential.cache.as_ref().and_then(|cache| {
        let realm = cache.client_realm();
        let entries = cache.credentials();
        entries
            .iter()
            .find(|entry| entry.server().components == ["krbtgt", realm])
            .or_else(|| entries.first())
            .map(|entry| time_of(entry.times().end_time))
    });
    CredentialInquiry {
        name: credential.name.clone(),
        usage: credential.usage,
        expires,
        mechanisms: vec![ObjectIdentifier::krb5()],
    }
}

/// Acquire and keep a service ticket for `target`.
///
/// # Errors
///
/// Returns the errors of [`super::Credential::acquire_service_ticket`].
///
/// # Cancel safety
///
/// Cancel-safe: the ticket is stored only after its exchange completes.
#[cfg(feature = "tokio")]
pub(super) async fn acquire_service_ticket(
    credential: &mut Credential,
    target: &Name,
    config: &super::Config,
) -> Result<(), Error> {
    use client::{Tokio, transport::KdcProtocol};

    use crate::routing::init_creds::VerifyOptions;

    if credential.usage == CredentialUsage::Accept {
        return Err(Error::WrongCredentialUsage("initiate"));
    }
    let service = Principal::new(
        target.principal().realm.clone(),
        target.principal().name_type,
        target_components(target)?.to_vec(),
    );
    if credential.impersonator.is_some() {
        let ticket = super::impersonate::proxy_ticket(credential, service, config).await?;
        if let Some(cache) = &mut credential.cache {
            drop(cache.upsert_credential(entry_of(&ticket)));
        }
        return Ok(());
    }
    let client = credential
        .name
        .as_ref()
        .map(|name| name.principal().clone())
        .ok_or(Error::NoCredential("the credential names no client"))?;
    let mut kerberos = if let Some(cache) = &credential.cache {
        Tokio::try_from_ccache(config.clone(), KdcProtocol::Auto, cache)?
    } else if let Some(keytab) = &credential.client_keytab {
        Tokio::with_keytab(
            config.clone(),
            KdcProtocol::Auto,
            client.clone(),
            keytab.clone(),
        )
    } else if let Some(password) = &credential.password {
        let mut password_client = Tokio::with_password(
            config.clone(),
            KdcProtocol::Auto,
            client.clone(),
            password.to_vec(),
        );
        if let Some(host_keys) = &credential.verify_keytab {
            let mut options = VerifyOptions::new().with_nofail(true);
            if let Some(server) = &credential.verify_server {
                options = options.with_server(server.clone());
            }
            drop(
                password_client
                    .verify_init_creds(host_keys, options)
                    .await?,
            );
        }
        password_client
    } else {
        return Err(Error::NoCredential("no ticket source"));
    };
    let ticket = kerberos
        .get_service_ticket(service)
        .await
        .map_err(Error::Client)?;
    let cache = credential
        .cache
        .get_or_insert_with(|| CCache::new(cache_principal(&client)));
    if let Some(tgt) = kerberos.tgt_session() {
        drop(cache.upsert_credential(entry_of(tgt)));
    }
    drop(cache.upsert_credential(entry_of(&ticket)));
    Ok(())
}

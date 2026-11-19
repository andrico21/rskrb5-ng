//! The `MSLSA:` store against an in-memory LSA, and, in the Windows CI job
//! (`--ignored`), against the runner's own logon session.

use alloc::sync::Arc;
use core::error::Error as StdError;
use std::sync::{Mutex, PoisonError};
#[cfg(windows)]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(windows)]
use rskrb5_ng::extensions::Interface;
use rskrb5_ng::{
    ccache::{
        CCache, Credential, CredentialTimes, EncryptionKey, Principal, file_store,
        stores::{CacheVersion, CredentialStore as _},
    },
    error::Ccache as Error,
    extensions::{Extension, Registry},
    keytab, krb_cred,
};

use super::{Lsa, MslsaStore};
use crate::{error::Platform, lsa_wire::CacheInfo};

/// The fixture realm.
const REALM: &str = "FIXTURE.RSKRB5-NG.TEST";

/// One DER TLV with a short or two-byte length.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let length = content.len();
    let header = match (u8::try_from(length), u16::try_from(length)) {
        (Ok(short), _) if short < 0x80 => vec![tag, short],
        (Ok(byte), _) => vec![tag, 0x81, byte],
        (_, Ok(word)) => [vec![tag, 0x82], word.to_be_bytes().to_vec()].concat(),
        (_, Err(_)) => vec![tag, 0x80],
    };
    [header.as_slice(), content].concat()
}

/// A DER Ticket for `HTTP/fixture.rskrb5-ng.test` with an opaque `enc-part`.
fn ticket() -> Vec<u8> {
    let name = [
        tlv(0xa0, &tlv(0x02, &[2])),
        tlv(
            0xa1,
            &tlv(
                0x30,
                &[tlv(0x1b, b"HTTP"), tlv(0x1b, b"fixture.rskrb5-ng.test")].concat(),
            ),
        ),
    ]
    .concat();
    let enc_part = [
        tlv(0xa0, &tlv(0x02, &[18])),
        tlv(0xa1, &tlv(0x02, &[1])),
        tlv(0xa2, &tlv(0x04, &[0x5a; 64])),
    ]
    .concat();
    let body = [
        tlv(0xa0, &tlv(0x02, &[5])),
        tlv(0xa1, &tlv(0x1b, REALM.as_bytes())),
        tlv(0xa2, &tlv(0x30, &name)),
        tlv(0xa3, &tlv(0x30, &enc_part)),
    ]
    .concat();
    tlv(0x61, &tlv(0x30, &body))
}

/// The fixture server principal.
fn server() -> Principal {
    Principal::new(
        REALM,
        2,
        vec!["HTTP".to_owned(), "fixture.rskrb5-ng.test".to_owned()],
    )
}

/// A fixture credential of `rskrb5-ng-fixture` with session key `key`.
fn credential(key: &[u8], now: u32) -> Credential {
    let mut times = CredentialTimes::default();
    times.auth_time = now;
    times.start_time = now;
    times.end_time = now.saturating_add(3600);
    times.renew_till = now.saturating_add(3600);
    Credential::new(
        Principal::new(REALM, 1, vec!["rskrb5-ng-fixture".to_owned()]),
        server(),
        EncryptionKey::new(18, key.to_vec()),
        times,
        [0x40, 0x81, 0, 0],
        ticket().into(),
    )
}

/// An in-memory LSA: it decrypts submissions with the key they carry.
#[derive(Debug, Default)]
struct Memory(Mutex<Vec<Credential>>);

impl Memory {
    /// The cached credentials.
    fn tickets(&self) -> Vec<Credential> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl Lsa for Memory {
    fn entries(&self) -> Result<Vec<CacheInfo>, Platform> {
        Ok(self.tickets().iter().map(CacheInfo::of).collect())
    }

    fn retrieve(&self, info: &CacheInfo) -> Result<Option<Credential>, Platform> {
        Ok(self
            .tickets()
            .into_iter()
            .find(|credential| CacheInfo::of(credential) == *info))
    }

    fn submit(&self, krb_cred: &[u8], key: &keytab::EncryptionKey) -> Result<(), Platform> {
        let credentials = krb_cred::decode_decrypt_krb_cred_to_ccache_credentials(krb_cred, key)
            .map_err(|_decode| Platform::MalformedReply {
                cache_type: "MSLSA",
                reason: "KRB-CRED",
            })?;
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend(credentials);
        Ok(())
    }

    fn purge(&self, info: Option<&CacheInfo>) -> Result<(), Platform> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|credential| info.is_some_and(|wanted| CacheInfo::of(credential) != *wanted));
        Ok(())
    }
}

/// A store over an in-memory LSA.
fn store(mutation: bool) -> (MslsaStore, Arc<Memory>) {
    let memory = Arc::new(Memory::default());
    let lsa: Arc<dyn Lsa> = Arc::<Memory>::clone(&memory);
    (MslsaStore { mutation, lsa }, memory)
}

/// The platform error inside a cache error.
fn platform(error: &Error) -> Option<Platform> {
    if let Error::Io(io) = error {
        io.get_ref()
            .and_then(|inner| inner.downcast_ref::<Platform>())
            .copied()
    } else {
        None
    }
}

/// Without `with_mutation(true)` every change is the typed authorization
/// error and the LSA is not called.
#[test]
fn changes_need_authorization() -> Result<(), Box<dyn StdError>> {
    // Given a read-only store.
    let (read_only, memory) = store(false);
    let cache = read_only.resolve("")?;
    // When each change is asked.
    let results = [
        cache.store(credential(&[1; 32], 1000)).err(),
        cache.remove(&server()).err(),
        cache.destroy().err(),
        cache.initialize(&server()).err(),
    ];
    // Then each is refused with MutationNotAuthorized and nothing changed.
    for result in results {
        let error = result.ok_or("change accepted")?;
        assert_eq!(
            platform(&error),
            Some(Platform::MutationNotAuthorized {
                cache_type: "MSLSA"
            }),
            "{error}"
        );
    }
    assert!(memory.tickets().is_empty(), "the LSA was not changed");
    Ok(())
}

/// A stored ticket travels as a KRB-CRED the LSA can decrypt and reads back.
#[test]
#[cfg_attr(
    miri,
    ignore = "KRB-CRED encoding reaches bitvec 1.1.1 through rasn, whose Miri findings are third-party"
)]
fn store_submits_and_load_reads_back() -> Result<(), Box<dyn StdError>> {
    // Given an authorized store.
    let (writable, memory) = store(true);
    let cache = writable.resolve("")?;
    // When a ticket and a configuration entry are stored and the cache read.
    cache.store(credential(&[7; 32], 1000))?;
    cache.store(Credential::config_entry(
        server(),
        "pa_type",
        None,
        vec![2].into(),
    ))?;
    let loaded = cache.load()?;
    // Then the ticket, key and client came back and the entry was skipped.
    assert_eq!(cache.name(), "MSLSA:");
    assert_eq!(memory.tickets().len(), 1);
    assert_eq!(loaded.default_principal().components, ["rskrb5-ng-fixture"]);
    let read = loaded.credentials().first().ok_or("no ticket")?;
    assert_eq!(read.server(), &server());
    assert_eq!(read.key().value().as_ref(), [7; 32]);
    assert_eq!(read.ticket().as_slice(), ticket().as_slice());
    Ok(())
}

/// Removal purges each ticket of the server; destroy purges every ticket.
#[test]
#[cfg_attr(
    miri,
    ignore = "KRB-CRED encoding reaches bitvec 1.1.1 through rasn, whose Miri findings are third-party"
)]
fn remove_and_destroy_purge() -> Result<(), Box<dyn StdError>> {
    // Given two tickets for the fixture server.
    let (writable, memory) = store(true);
    let cache = writable.resolve("x")?;
    cache.store(credential(&[1; 32], 1000))?;
    let mut other = credential(&[2; 32], 1000);
    other.set_client(Principal::new(REALM, 1, vec!["second".to_owned()]));
    cache.store(other)?;
    // When the server's tickets are removed, then the cache destroyed.
    let none = cache.remove(&Principal::new(REALM, 2, vec!["HTTP".to_owned()]))?;
    let removed = cache.remove(&server())?;
    cache.store(credential(&[3; 32], 1000))?;
    cache.destroy()?;
    // Then the counts match and the cache is empty.
    assert_eq!((none, removed), (0, 2));
    assert!(memory.tickets().is_empty(), "destroyed");
    assert!(
        matches!(cache.load(), Err(Error::CacheNotFound { name: _ })),
        "empty"
    );
    Ok(())
}

/// An installed `MSLSA` provider serves `MSLSA:` names on the name routes of
/// `rskrb5-ng` (todo 32's `StoreProvider`).
#[test]
#[cfg_attr(
    miri,
    ignore = "KRB-CRED encoding reaches bitvec 1.1.1 through rasn, whose Miri findings are third-party"
)]
fn installed_provider_serves_mslsa_names() -> Result<(), Box<dyn StdError>> {
    // Given an authorized store over an in-memory LSA, installed as the
    // process's `MSLSA` provider.
    let (writable, memory) = store(true);
    let mut registry = Registry::new();
    registry.register(Extension::StoreProvider(Arc::new(writable)))?;
    registry.install_stores()?;
    // When a ticket is stored through a resolved name and the name is loaded.
    file_store::resolve("MSLSA:", CacheVersion::V4)?.store(credential(&[5; 32], 1000))?;
    let loaded = CCache::load_name("MSLSA:")?;
    // Then the provider's LSA got the ticket and the name route read it back.
    assert_eq!(memory.tickets().len(), 1);
    let read = loaded.credentials().first().ok_or("no ticket")?;
    assert_eq!(read.key().value().as_ref(), [5; 32]);
    Ok(())
}

/// The collection is the one cache; new caches are not supported (MIT).
#[test]
#[cfg_attr(
    miri,
    ignore = "KRB-CRED encoding reaches bitvec 1.1.1 through rasn, whose Miri findings are third-party"
)]
fn collection_of_one_cache() -> Result<(), Box<dyn StdError>> {
    // Given an authorized store with one ticket.
    let (writable, _memory) = store(true);
    let collection = writable.collection("")?;
    let before = collection.caches()?.count();
    writable.resolve("")?.store(credential(&[1; 32], 1000))?;
    // When the collection is listed, switched and asked for a new cache.
    let names: Vec<String> = collection.caches()?.map(|cache| cache.name()).collect();
    let unique = collection.new_unique().err().ok_or("new cache")?;
    // Then it has the one cache and refuses a new one with a typed error.
    assert_eq!((before, names), (0, vec!["MSLSA:".to_owned()]));
    collection.switch(collection.primary()?.as_ref())?;
    assert_eq!(
        platform(&unique),
        Some(Platform::UnsupportedOperation {
            cache_type: "MSLSA",
            operation: "new_unique"
        })
    );
    Ok(())
}

/// The runner's own LSA, reached through installed `MSLSA:` names.
///
/// The default read-only store refuses a change; a fixture ticket submitted
/// with `KerbSubmitTicketMessage` through an installed authorized provider
/// reads back by name and is purged.
#[cfg(windows)]
#[test]
#[ignore = "changes the logon session's ticket cache: run in the Windows CI job"]
fn system_lsa_round_trip() -> Result<(), Box<dyn StdError>> {
    // Given the default read-only store, an authorized store installed as the
    // process's `MSLSA` provider, and a fresh fixture ticket.
    let now = u32::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
    let key: [u8; 32] = now
        .to_be_bytes()
        .repeat(8)
        .try_into()
        .map_err(|_size| "key")?;
    let mut defaults = Registry::new();
    crate::register(&mut defaults)?;
    let mut registry = Registry::new();
    registry.register(Extension::StoreProvider(Arc::new(
        MslsaStore::with_mutation(true),
    )))?;
    registry.install_stores()?;
    let cache = file_store::resolve("MSLSA:", CacheVersion::V4)?;
    // When the read-only store is asked to store it, then the installed one
    // stores it, the name is loaded, and the ticket is removed.
    let refused = MslsaStore::new()
        .resolve("")?
        .store(credential(&key, now))
        .err()
        .ok_or("the read-only store accepted a change")?;
    cache.store(credential(&key, now))?;
    let loaded = CCache::load_name("MSLSA:")?;
    let removed = cache.remove(&server())?;
    let after = cache
        .load()
        .map_or_else(|_absent| Vec::new(), |value| value.credentials().to_vec());
    // Then the refusal is the typed authorization error, the LSA returned the
    // ticket with its session key, and the removal purged exactly it.
    assert_eq!(
        platform(&refused),
        Some(Platform::MutationNotAuthorized {
            cache_type: "MSLSA"
        }),
        "{refused}"
    );
    assert_eq!(defaults.ids(Interface::StoreProvider), ["MSLSA"]);
    let read = loaded
        .credentials()
        .iter()
        .find(|credential| credential.server().components == server().components)
        .ok_or("the seeded ticket was not read back")?;
    assert_eq!(read.key().value().as_ref(), key);
    assert_eq!(read.ticket().as_slice(), ticket().as_slice());
    assert_eq!(removed, 1);
    assert!(
        !after
            .iter()
            .any(|credential| credential.server().components == server().components),
        "purged"
    );
    Ok(())
}

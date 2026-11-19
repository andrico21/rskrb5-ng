//! An in-memory KCM server for the tests.
//!
//! It answers the operations the store uses with the status codes of
//! Heimdal and MIT. The macOS tests serve it over Mach RPC under a test
//! service name; the portable tests call it directly.

use std::sync::{Mutex, PoisonError};

use rskrb5_ng::{ccache::Credential, error::Ccache as CacheError};

use crate::{Secret, kcm_store::KcmTransport, kcm_wire::UUID_LEN, marshal};

/// `KRB5_FCC_NOFILE`.
const NO_CACHE: i32 = -1_765_328_189;
/// `KRB5_CC_NOTFOUND`.
const NOT_FOUND: i32 = -1_765_328_243;
/// Success.
const OK: i32 = 0;
/// `KRB5_FCC_INTERNAL`, Heimdal's answer to an unknown operation.
const UNSUPPORTED: i32 = -1_765_328_188;

/// One cache of the server.
#[derive(Debug)]
struct Entry {
    /// Its name.
    name: String,
    /// Its UUID.
    uuid: [u8; UUID_LEN],
    /// The encoded default principal, once initialized.
    principal: Vec<u8>,
    /// UUID, encoding and decoded value of each credential.
    credentials: Vec<([u8; UUID_LEN], Secret, Credential)>,
}

/// The server state.
#[derive(Debug, Default)]
struct State {
    /// The caches.
    caches: Vec<Entry>,
    /// The primary cache name.
    default: String,
    /// The next UUID number.
    next: u8,
}

impl State {
    /// A fresh UUID.
    fn uuid(&mut self) -> [u8; UUID_LEN] {
        self.next = self.next.wrapping_add(1);
        [self.next; UUID_LEN]
    }

    /// The cache `name`.
    fn cache(&mut self, name: &str) -> Option<&mut Entry> {
        self.caches.iter_mut().find(|entry| entry.name == name)
    }

    /// Create the cache `name` unless it exists.
    fn create(&mut self, name: &str) {
        if !self.caches.iter().any(|entry| entry.name == name) {
            let uuid = self.uuid();
            self.caches.push(Entry {
                name: name.to_owned(),
                uuid,
                principal: Vec::new(),
                credentials: Vec::new(),
            });
        }
    }

    /// `GEN_NEW`.
    fn gen_new(&mut self) -> Reply {
        let name = format!("fixture-{}", self.next);
        self.create(&name);
        (OK, terminated(&name))
    }

    /// `INITIALIZE`.
    fn initialize(&mut self, name: &str, principal: &[u8]) -> Reply {
        self.create(name);
        self.cache(name).map_or((NO_CACHE, Vec::new()), |entry| {
            principal.clone_into(&mut entry.principal);
            entry.credentials.clear();
            (OK, Vec::new())
        })
    }

    /// `DESTROY`.
    fn destroy(&mut self, name: &str) -> Reply {
        let before = self.caches.len();
        self.caches.retain(|entry| entry.name != name);
        (
            if self.caches.len() < before {
                OK
            } else {
                NO_CACHE
            },
            Vec::new(),
        )
    }

    /// `STORE`.
    fn store(&mut self, name: &str, bytes: &[u8]) -> Reply {
        let uuid = self.uuid();
        let parsed = marshal::parse_credential(bytes);
        match (self.cache(name), parsed) {
            (Some(entry), Ok(credential)) if !entry.principal.is_empty() => {
                entry
                    .credentials
                    .push((uuid, Secret::from(bytes.to_vec()), credential));
                (OK, Vec::new())
            }
            (_, _) => (NO_CACHE, Vec::new()),
        }
    }

    /// `REMOVE_CRED` with a matching credential that names the server.
    fn remove(&mut self, name: &str, args: &[u8]) -> Reply {
        let wanted = args
            .get(8..)
            .and_then(|rest| rest.get(..principal_len(rest)?))
            .and_then(|bytes| marshal::parse_principal(bytes).ok());
        match (self.cache(name), wanted) {
            (Some(entry), Some(server)) => {
                let before = entry.credentials.len();
                entry.credentials.retain(|item| {
                    item.2.server().realm != server.realm
                        || item.2.server().components != server.components
                });
                let removed = entry.credentials.len() < before;
                (if removed { OK } else { NOT_FOUND }, Vec::new())
            }
            (_, _) => (NO_CACHE, Vec::new()),
        }
    }

    /// The cache operations (`name` is set).
    fn named(&mut self, opcode: u16, name: &str, args: &[u8]) -> Reply {
        match opcode {
            4 => self.initialize(name, args),
            5 => self.destroy(name),
            6 => self.store(name, args),
            8 => self.cache(name).map_or((NO_CACHE, Vec::new()), |entry| {
                (OK, entry.principal.clone())
            }),
            9 => self.cache(name).map_or((NO_CACHE, Vec::new()), |entry| {
                (
                    OK,
                    entry.credentials.iter().flat_map(|item| item.0).collect(),
                )
            }),
            10 => self
                .cache(name)
                .and_then(|entry| {
                    entry
                        .credentials
                        .iter()
                        .find(|item| item.0.as_slice() == args)
                })
                .map_or((NOT_FOUND, Vec::new()), |item| (OK, item.1.to_vec())),
            11 => self.remove(name, args),
            21 => {
                name.clone_into(&mut self.default);
                (OK, Vec::new())
            }
            _ => (UNSUPPORTED, Vec::new()),
        }
    }

    /// The collection operations.
    fn global(&mut self, opcode: u16, args: &[u8]) -> Reply {
        match opcode {
            3 => self.gen_new(),
            18 => (
                OK,
                self.caches.iter().flat_map(|entry| entry.uuid).collect(),
            ),
            19 => self
                .caches
                .iter()
                .find(|entry| entry.uuid.as_slice() == args)
                .map_or((NO_CACHE, Vec::new()), |entry| {
                    (OK, terminated(&entry.name))
                }),
            20 => {
                if self.default.is_empty() {
                    "fixture".clone_into(&mut self.default);
                }
                (OK, terminated(&self.default))
            }
            _ => (UNSUPPORTED, Vec::new()),
        }
    }
}

/// A status and a result.
type Reply = (i32, Vec<u8>);

/// `text` with a terminating NUL.
fn terminated(text: &str) -> Vec<u8> {
    [text.as_bytes(), &[0]].concat()
}

/// An in-memory KCM server.
#[derive(Debug, Default)]
pub(crate) struct Fixture(Mutex<State>);

/// Split a NUL-terminated name off `bytes`.
fn split_name(bytes: &[u8]) -> Option<(String, &[u8])> {
    let end = bytes.iter().position(|byte| *byte == 0)?;
    let (text, rest) = bytes.split_at_checked(end)?;
    Some((String::from_utf8(text.to_vec()).ok()?, rest.get(1..)?))
}

/// The length of the version-4 principal at the start of `bytes`.
fn principal_len(bytes: &[u8]) -> Option<usize> {
    let count = u32::from_be_bytes(*bytes.get(4..8)?.first_chunk::<4>()?);
    let mut at = 8_usize;
    for _ in 0..=count {
        let length = u32::from_be_bytes(*bytes.get(at..)?.first_chunk::<4>()?);
        at = at
            .checked_add(4)?
            .checked_add(usize::try_from(length).ok()?)?;
    }
    (at <= bytes.len()).then_some(at)
}

impl Fixture {
    /// Answer `request` with the status and result framed as a reply.
    pub(crate) fn reply(&self, request: &[u8]) -> Secret {
        let (status, result) = match request.split_first_chunk::<4>() {
            Some((&[2, 0, high, low], body)) => {
                let opcode = u16::from_be_bytes([high, low]);
                let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
                if matches!(opcode, 4..=6 | 8..=11 | 21) {
                    split_name(body).map_or((UNSUPPORTED, Vec::new()), |(name, args)| {
                        state.named(opcode, &name, args)
                    })
                } else {
                    state.global(opcode, body)
                }
            }
            Some(_) | None => (UNSUPPORTED, Vec::new()),
        };
        Secret::from([status.to_be_bytes().as_slice(), &result].concat())
    }
}

impl KcmTransport for Fixture {
    fn call(&self, request: &[u8]) -> Result<Vec<u8>, CacheError> {
        Ok(self.reply(request).to_vec())
    }
}

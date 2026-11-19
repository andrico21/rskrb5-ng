//! A stateful in-memory KCM daemon on a temporary Unix socket.
//!
//! It is modelled on the replies SSSD 2.10.1 gave when probed live: an
//! unsupported opcode is answered with a transport status and an empty body,
//! other failures with the body status, and an unknown opcode closes the
//! connection. It keeps principals and credentials as the raw bytes of the
//! wire, so it checks the client's encoding independently of the crate's own
//! ccache writer.

extern crate alloc;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};
use std::{
    fs,
    os::unix::net::{UnixListener, UnixStream},
    path::{Path, PathBuf},
    sync::{Mutex, PoisonError},
    thread::{self, JoinHandle},
};

use super::mock::{self, TestError};

/// `KRB5_FCC_NOFILE`.
pub(super) const NOFILE: i32 = -1_765_328_189;
/// `KRB5_FCC_INTERNAL`.
pub(super) const INTERNAL: i32 = -1_765_328_188;
/// `KRB5_CC_NOTFOUND`.
pub(super) const NOTFOUND: i32 = -1_765_328_243;
/// `KRB5_CC_END`.
pub(super) const END: i32 = -1_765_328_242;

/// Opcodes the fake can leave unimplemented, as SSSD leaves `REPLACE` and an
/// older Heimdal leaves `GET_CRED_LIST`.
#[derive(Clone, Copy, Debug)]
pub(super) struct Features {
    /// `REPLACE` is implemented.
    pub replace: bool,
    /// `GET_CRED_LIST` is implemented.
    pub cred_list: bool,
}

/// One cache of the fake.
struct Cache {
    /// The daemon's name for it.
    name: String,
    /// The principal bytes once initialized.
    principal: Option<Vec<u8>>,
    /// The credential bytes, in storage order.
    credentials: Vec<Vec<u8>>,
    /// The KDC offset.
    offset: i32,
}

/// What the fake daemon holds.
struct State {
    /// The caches in creation order.
    caches: Vec<Cache>,
    /// The primary cache name.
    primary: Option<String>,
    /// Every opcode received, in order.
    seen: Vec<u16>,
    /// Which opcodes are implemented.
    features: Features,
}

/// What the fake answers.
enum Answer {
    /// Success with a payload.
    Ok(Vec<u8>),
    /// A failure in the body status.
    Status(i32),
    /// A failure in the transport status, with an empty body.
    Transport(i32),
}

/// The fake daemon; dropping it stops it.
pub(super) struct Fake {
    /// The socket path.
    path: PathBuf,
    /// The private directory holding it.
    directory: PathBuf,
    /// The shared state.
    state: Arc<Mutex<State>>,
    /// Set to stop the accept loop.
    stop: Arc<AtomicBool>,
    /// The accept loop.
    thread: Option<JoinHandle<()>>,
}

impl Fake {
    /// Start a daemon holding no caches.
    pub(super) fn start(features: Features) -> Result<Self, TestError> {
        let directory = mock::scratch("fake")?;
        let path = directory.join("kcm.sock");
        let listener = UnixListener::bind(&path)?;
        let state = Arc::new(Mutex::new(State {
            caches: Vec::new(),
            primary: None,
            seen: Vec::new(),
            features,
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let (shared, halt) = (Arc::clone(&state), Arc::clone(&stop));
        let thread = thread::spawn(move || {
            while let Ok((stream, _peer)) = listener.accept() {
                if halt.load(Ordering::SeqCst) {
                    return;
                }
                let connection = Arc::clone(&shared);
                drop(thread::spawn(move || serve(&connection, stream)));
            }
        });
        Ok(Self {
            path,
            directory,
            state,
            stop,
            thread: Some(thread),
        })
    }

    /// The socket path.
    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    /// Every opcode received so far.
    pub(super) fn seen(&self) -> Vec<u16> {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .seen
            .clone()
    }
}

impl Drop for Fake {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        drop(UnixStream::connect(&self.path));
        if let Some(thread) = self.thread.take() {
            drop(thread.join());
        }
        drop(fs::remove_dir_all(&self.directory));
    }
}

/// Serve one connection until it closes.
fn serve(state: &Mutex<State>, mut stream: UnixStream) {
    while let Ok((opcode, parameters)) = mock::read_request(&mut stream) {
        let answer = state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .handle(opcode, &parameters);
        let sent = match answer {
            Some(Answer::Ok(payload)) => mock::ok(&mut stream, &payload),
            Some(Answer::Status(status)) => mock::reply(&mut stream, 0, status, &[]),
            Some(Answer::Transport(code)) => mock::transport_error(&mut stream, code),
            None => return,
        };
        if sent.is_err() {
            return;
        }
    }
}

/// A zero-terminated string.
fn cstring(text: &str) -> Vec<u8> {
    let mut bytes = text.as_bytes().to_vec();
    bytes.push(0_u8);
    bytes
}

/// A big-endian 32-bit integer at the front of `bytes`.
fn be32(bytes: &[u8]) -> Option<(usize, &[u8])> {
    let (head, rest) = bytes.split_first_chunk::<4>()?;
    Some((usize::try_from(u32::from_be_bytes(*head)).ok()?, rest))
}

/// The length of the principal at the front of `bytes`: name type, component
/// count, realm and components, each string counted.
fn principal_length(bytes: &[u8]) -> Option<usize> {
    let (_name_type, after_type) = bytes.split_first_chunk::<4>()?;
    let (count, mut cursor) = be32(after_type)?;
    for _ in 0..=count {
        let (size, tail) = be32(cursor)?;
        cursor = tail.get(size..)?;
    }
    bytes.len().checked_sub(cursor.len())
}

/// A UUID built from two indices.
fn uuid(cache: usize, credential: usize) -> Vec<u8> {
    let mut bytes = vec![0_u8; 16];
    for (slot, index) in bytes.iter_mut().zip([cache, credential]) {
        *slot = u8::try_from(index).unwrap_or(0);
    }
    bytes
}

impl State {
    /// The cache called `name`.
    fn cache_mut(&mut self, name: &str) -> Option<&mut Cache> {
        self.caches.iter_mut().find(|cache| cache.name == name)
    }

    /// Answer one request; `None` closes the connection (an unknown opcode).
    fn handle(&mut self, opcode: u16, parameters: &[u8]) -> Option<Answer> {
        self.seen.push(opcode);
        if (opcode == 13_002 && !self.features.replace)
            || (opcode == 13_001 && !self.features.cred_list)
        {
            return Some(Answer::Transport(INTERNAL));
        }
        Some(match opcode {
            3 => {
                let name = format!("0:{}", self.caches.len().checked_add(100)?);
                self.caches.push(Cache {
                    name: name.clone(),
                    principal: None,
                    credentials: Vec::new(),
                    offset: 0,
                });
                Answer::Ok(cstring(&name))
            }
            18 => self.cache_uuids(),
            19 => self.cache_by_uuid(parameters),
            20 => self
                .primary
                .as_deref()
                .map_or(Answer::Transport(INTERNAL), |name| {
                    Answer::Ok(cstring(name))
                }),
            21 => self.set_primary(parameters)?,
            4..=6 | 8..=10 | 22 | 23 | 13_001 | 13_002 => {
                let end = parameters.iter().position(|byte| *byte == 0)?;
                let name = String::from_utf8(parameters.get(..end)?.to_vec()).ok()?;
                self.cache_op(opcode, &name, parameters.get(end.checked_add(1)?..)?)?
            }
            _ => return None,
        })
    }

    /// `GET_CACHE_UUID_LIST`.
    fn cache_uuids(&self) -> Answer {
        let initialized: Vec<usize> = (0..self.caches.len())
            .filter(|index| {
                self.caches
                    .get(*index)
                    .is_some_and(|held| held.principal.is_some())
            })
            .collect();
        if initialized.is_empty() {
            return Answer::Status(NOFILE);
        }
        Answer::Ok(
            initialized
                .into_iter()
                .flat_map(|index| uuid(index, 0))
                .collect(),
        )
    }

    /// `GET_CACHE_BY_UUID`.
    fn cache_by_uuid(&self, parameters: &[u8]) -> Answer {
        parameters
            .first()
            .and_then(|index| self.caches.get(usize::from(*index)))
            .filter(|cache| cache.principal.is_some())
            .map_or(Answer::Status(END), |cache| {
                Answer::Ok(cstring(&cache.name))
            })
    }

    /// `SET_DEFAULT_CACHE`.
    fn set_primary(&mut self, parameters: &[u8]) -> Option<Answer> {
        let name = String::from_utf8(parameters.strip_suffix(&[0])?.to_vec()).ok()?;
        if self.cache_mut(&name).is_some() {
            self.primary = Some(name);
            Some(Answer::Ok(Vec::new()))
        } else {
            Some(Answer::Status(NOFILE))
        }
    }

    /// The opcodes that name one cache.
    fn cache_op(&mut self, opcode: u16, name: &str, rest: &[u8]) -> Option<Answer> {
        if opcode == 4 {
            let known = self.cache_mut(name).is_some();
            if !known {
                self.caches.push(Cache {
                    name: name.to_owned(),
                    principal: None,
                    credentials: Vec::new(),
                    offset: 0,
                });
            }
            let cache = self.cache_mut(name)?;
            cache.principal = Some(rest.to_vec());
            cache.credentials.clear();
            if self.primary.is_none() {
                self.primary = Some(name.to_owned());
            }
            return Some(Answer::Ok(Vec::new()));
        }
        let missing = if opcode == 5 {
            NOFILE
        } else if opcode == 6 {
            NOTFOUND
        } else {
            NOFILE
        };
        let Some(cache) = self
            .cache_mut(name)
            .filter(|cache| cache.principal.is_some())
        else {
            return Some(Answer::Status(missing));
        };
        Some(match opcode {
            5 => {
                self.caches.retain(|held| held.name != name);
                Answer::Ok(Vec::new())
            }
            6 => {
                cache.credentials.push(rest.to_vec());
                Answer::Ok(Vec::new())
            }
            8 => Answer::Ok(cache.principal.clone().unwrap_or_default()),
            13_001 => {
                let mut payload = u32::try_from(cache.credentials.len())
                    .ok()?
                    .to_be_bytes()
                    .to_vec();
                for credential in &cache.credentials {
                    payload.extend_from_slice(&u32::try_from(credential.len()).ok()?.to_be_bytes());
                    payload.extend_from_slice(credential);
                }
                Answer::Ok(payload)
            }
            9 => {
                let index = self.caches.iter().position(|held| held.name == name)?;
                let count = self.caches.get(index)?.credentials.len();
                Answer::Ok(
                    (0..count)
                        .flat_map(|credential| uuid(index, credential))
                        .collect(),
                )
            }
            10 => rest
                .get(1..2)
                .and_then(|slot| cache.credentials.get(usize::from(*slot.first()?)))
                .map_or(Answer::Status(END), |credential| {
                    Answer::Ok(credential.clone())
                }),
            22 => Answer::Ok(cache.offset.to_be_bytes().to_vec()),
            23 => {
                cache.offset = i32::from_be_bytes(*rest.first_chunk::<4>()?);
                Answer::Ok(Vec::new())
            }
            _ => self.replace(name, rest)?,
        })
    }

    /// `REPLACE`: offset, principal, count and counted credentials.
    fn replace(&mut self, name: &str, parameters: &[u8]) -> Option<Answer> {
        let (offset, after_offset) = parameters.split_first_chunk::<4>()?;
        let (principal, after_principal) =
            after_offset.split_at_checked(principal_length(after_offset)?)?;
        let (count, mut cursor) = be32(after_principal)?;
        let mut credentials = Vec::new();
        for _ in 0..count {
            let (size, tail) = be32(cursor)?;
            let (credential, next) = tail.split_at_checked(size)?;
            credentials.push(credential.to_vec());
            cursor = next;
        }
        let cache = self.cache_mut(name)?;
        cache.principal = Some(principal.to_vec());
        cache.credentials = credentials;
        cache.offset = i32::from_be_bytes(*offset);
        Some(Answer::Ok(Vec::new()))
    }
}

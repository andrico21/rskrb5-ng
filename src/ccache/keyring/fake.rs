//! An in-memory kernel for the unit tests: keyrings, keys, the special
//! rings, recursive search, replacement by description, and injected
//! failures.

use alloc::{collections::BTreeMap, sync::Arc};
use std::sync::{Mutex, MutexGuard, PoisonError};

use super::{
    KernelError,
    backend::{Kind, Ring},
};

/// The calls of the fake kernel.
mod calls;

/// The calls a failure can be injected into.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Op {
    /// `keyctl_get_keyring_ID`.
    Lookup,
    /// `keyctl_get_persistent`.
    Persistent,
    /// `keyctl_search`.
    Search,
    /// `add_key` of any type.
    Add,
    /// `add_key` of a `big_key` or `user` key, not a keyring.
    AddKey,
    /// `keyctl_link`.
    Link,
    /// `keyctl_unlink`.
    Unlink,
    /// `keyctl_clear`.
    Clear,
    /// `keyctl_read` of any key or keyring.
    Read,
    /// `keyctl_read` of a key that is not a keyring.
    ReadKey,
    /// `keyctl_describe`.
    Describe,
    /// `keyctl_set_timeout`.
    SetTimeout,
}

/// One key or keyring.
#[derive(Debug)]
struct Key {
    /// The key type.
    kind: Kind,
    /// The description.
    description: String,
    /// The payload of a key.
    payload: Vec<u8>,
    /// The serials a keyring links.
    children: Vec<i32>,
    /// Whether the key was revoked.
    revoked: bool,
}

/// The serials of the special keyrings.
#[derive(Clone, Copy, Debug)]
struct Specials {
    /// The thread keyring.
    thread: i32,
    /// The process keyring.
    process: i32,
    /// The session keyring.
    session: i32,
    /// The user keyring.
    user: i32,
    /// The user session keyring.
    user_session: i32,
}

/// The state of the fake kernel.
#[derive(Debug)]
struct World {
    /// The next serial.
    next: i32,
    /// Every key by serial.
    keys: BTreeMap<i32, Key>,
    /// The special keyrings.
    specials: Specials,
    /// The user id of the caller.
    uid: u32,
    /// Whether the persistent keyring exists in this kernel.
    persistent: bool,
    /// Whether `big_key` exists in this kernel.
    big_key: bool,
    /// Failures to inject: the call, how often, and the error.
    failures: Vec<(Op, usize, KernelError)>,
    /// The timeouts set, by serial.
    timeouts: BTreeMap<i32, u32>,
}

/// The fake kernel; clones share it.
#[derive(Clone, Debug)]
pub(super) struct Fake {
    /// The kernel.
    world: Arc<Mutex<World>>,
}

impl World {
    /// Add a key and return its serial.
    fn create(&mut self, kind: Kind, description: &str, payload: &[u8]) -> i32 {
        self.next = self.next.saturating_add(1);
        let _previous = self.keys.insert(
            self.next,
            Key {
                kind,
                description: description.to_owned(),
                payload: payload.to_vec(),
                children: Vec::new(),
                revoked: false,
            },
        );
        self.next
    }

    /// The serial an operand names.
    ///
    /// # Errors
    ///
    /// [`KernelError::KeyNotFound`] and [`KernelError::KeyRevoked`].
    fn resolve(&self, ring: Ring) -> Result<i32, KernelError> {
        let serial = match ring {
            Ring::Thread => self.specials.thread,
            Ring::Process => self.specials.process,
            Ring::Session => self.specials.session,
            Ring::User => self.specials.user,
            Ring::UserSession => self.specials.user_session,
            Ring::Key(serial) => serial.get(),
        };
        match self.keys.get(&serial) {
            None => Err(KernelError::KeyNotFound),
            Some(key) if key.revoked => Err(KernelError::KeyRevoked),
            Some(_) => Ok(serial),
        }
    }

    /// Take an injected failure for `op`, if one is armed.
    ///
    /// # Errors
    ///
    /// The injected error.
    fn injected(&mut self, op: Op) -> Result<(), KernelError> {
        match self
            .failures
            .iter_mut()
            .find(|(armed, left, _)| *armed == op && *left > 0)
        {
            Some((_, left, error)) => {
                *left = left.saturating_sub(1);
                Err(*error)
            }
            None => Ok(()),
        }
    }

    /// Breadth-first search below `ring`, six levels deep as the kernel does.
    fn find(&self, ring: i32, kind: Kind, description: &str) -> Option<i32> {
        let mut pending = vec![ring];
        for _depth in 0..6_u8 {
            let mut next = Vec::new();
            for holder in &pending {
                for child in self.keys.get(holder).map_or(&[][..], |key| &key.children) {
                    let key = self.keys.get(child)?;
                    if key.kind == kind && key.description == description && !key.revoked {
                        return Some(*child);
                    }
                    if key.kind == Kind::Keyring {
                        next.push(*child);
                    }
                }
            }
            pending = next;
        }
        None
    }

    /// The child of `ring` of this kind and description, if any.
    fn child(&self, ring: i32, kind: Kind, description: &str) -> Option<i32> {
        self.keys
            .get(&ring)?
            .children
            .iter()
            .copied()
            .find(|child| {
                self.keys
                    .get(child)
                    .is_some_and(|key| key.kind == kind && key.description == description)
            })
    }

    /// Link `key` into `ring`, displacing a key of the same kind and description.
    ///
    /// # Errors
    ///
    /// [`KernelError::Other`] (`ENOTDIR`) when `ring` is not a keyring.
    fn attach(&mut self, key: i32, ring: i32) -> Result<(), KernelError> {
        let (kind, description) = self
            .keys
            .get(&key)
            .map(|found| (found.kind, found.description.clone()))
            .ok_or(KernelError::KeyNotFound)?;
        let same = self
            .child(ring, kind, &description)
            .filter(|other| *other != key);
        let holder = self.keys.get_mut(&ring).ok_or(KernelError::KeyNotFound)?;
        if holder.kind != Kind::Keyring {
            return Err(KernelError::Other(20));
        }
        holder.children.retain(|child| Some(*child) != same);
        if !holder.children.contains(&key) {
            holder.children.push(key);
        }
        Ok(())
    }
}

impl Fake {
    /// A kernel with the five special keyrings and every feature.
    pub(super) fn new() -> Self {
        let mut world = World {
            next: 100,
            keys: BTreeMap::new(),
            specials: Specials {
                thread: 0,
                process: 0,
                session: 0,
                user: 0,
                user_session: 0,
            },
            uid: 1000,
            persistent: true,
            big_key: true,
            failures: Vec::new(),
            timeouts: BTreeMap::new(),
        };
        world.specials = Specials {
            thread: world.create(Kind::Keyring, "_tid", &[]),
            process: world.create(Kind::Keyring, "_pid", &[]),
            session: world.create(Kind::Keyring, "_ses", &[]),
            user: world.create(Kind::Keyring, "_uid.1000", &[]),
            user_session: world.create(Kind::Keyring, "_uid_ses.1000", &[]),
        };
        Self {
            world: Arc::new(Mutex::new(world)),
        }
    }

    /// The state.
    fn world(&self) -> MutexGuard<'_, World> {
        self.world.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Run one call: take the injected failure, then `call`, then release the
    /// kernel.
    ///
    /// # Errors
    ///
    /// The injected error and the error of `call`.
    fn run<T, F>(&self, op: Op, call: F) -> Result<T, KernelError>
    where
        F: FnOnce(&mut World) -> Result<T, KernelError>,
    {
        let mut world = self.world();
        let result = world.injected(op).and_then(|()| call(&mut world));
        drop(world);
        result
    }

    /// Make the next `times` calls of `op` fail with `error`.
    pub(super) fn fail(&self, op: Op, times: usize, error: KernelError) {
        self.world().failures.push((op, times, error));
    }

    /// Remove `big_key` and the persistent keyring from the kernel.
    pub(super) fn old_kernel(&self) {
        let mut world = self.world();
        world.big_key = false;
        world.persistent = false;
    }

    /// Make the session keyring the user session keyring, as for a process
    /// that never joined a session.
    pub(super) fn share_session(&self) {
        let mut world = self.world();
        world.specials.session = world.specials.user_session;
    }

    /// Revoke a key or keyring.
    pub(super) fn revoke(&self, ring: Ring) {
        let mut world = self.world();
        if let Ok(serial) = world.resolve(ring)
            && let Some(key) = world.keys.get_mut(&serial)
        {
            key.revoked = true;
        }
    }

    /// The kind and description of everything `ring` links.
    pub(super) fn contents(&self, ring: Ring) -> Vec<(Kind, String)> {
        let world = self.world();
        let found = world
            .resolve(ring)
            .ok()
            .and_then(|serial| world.keys.get(&serial))
            .map_or_else(Vec::new, |key| {
                key.children
                    .iter()
                    .filter_map(|child| world.keys.get(child))
                    .map(|child| (child.kind, child.description.clone()))
                    .collect()
            });
        drop(world);
        found
    }

    /// The payload of the key `description` of `ring`, of either key type.
    pub(super) fn payload(&self, ring: Ring, description: &str) -> Option<Vec<u8>> {
        let world = self.world();
        let start = world.resolve(ring).ok()?;
        let found = world
            .find(start, Kind::User, description)
            .or_else(|| world.find(start, Kind::BigKey, description))
            .and_then(|serial| world.keys.get(&serial))
            .map(|key| key.payload.clone());
        drop(world);
        found
    }

    /// The timeout set on the key `description` of `kind` in `ring`.
    pub(super) fn timeout(&self, ring: Ring, kind: Kind, description: &str) -> Option<u32> {
        let world = self.world();
        let start = world.resolve(ring).ok()?;
        let found = world
            .find(start, kind, description)
            .and_then(|serial| world.timeouts.get(&serial).copied());
        drop(world);
        found
    }
}

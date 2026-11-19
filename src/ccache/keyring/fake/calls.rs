//! The calls of the fake kernel, as the [`Backend`] trait.

use zeroize::Zeroizing;

use super::{Fake, Op};
use crate::ccache::keyring::{
    KernelError,
    backend::{Backend, Kind, Ring, Serial},
};

/// A serial as the trait returns it.
///
/// # Errors
///
/// [`KernelError::KeyNotFound`] for the serial 0.
fn serial(raw: i32) -> Result<Serial, KernelError> {
    Serial::new(raw).ok_or(KernelError::KeyNotFound)
}

/// The bytes of a serial in the byte order a keyring read returns.
fn native_bytes(raw: i32) -> [u8; 4] {
    if cfg!(target_endian = "little") {
        raw.to_le_bytes()
    } else {
        raw.to_be_bytes()
    }
}

impl Backend for Fake {
    fn lookup(&self, ring: Ring) -> Result<Serial, KernelError> {
        self.run(Op::Lookup, |world| serial(world.resolve(ring)?))
    }

    fn persistent(&self, uid: Option<u32>) -> Result<Serial, KernelError> {
        self.run(Op::Persistent, |world| {
            if !world.persistent {
                return Err(KernelError::NotSupported);
            }
            if uid.is_some_and(|other| other != world.uid) {
                return Err(KernelError::PermissionDenied);
            }
            let description = format!("_persistent.{}", world.uid);
            let existing = world.keys.iter().find_map(|(serial_of, key)| {
                (key.description == description).then_some(*serial_of)
            });
            let created =
                existing.unwrap_or_else(|| world.create(Kind::Keyring, &description, &[]));
            let process = world.specials.process;
            world.attach(created, process)?;
            serial(created)
        })
    }

    fn search(
        &self,
        ring: Ring,
        kind: Kind,
        description: &str,
        destination: Option<Ring>,
    ) -> Result<Serial, KernelError> {
        self.run(Op::Search, |world| {
            let start = world.resolve(ring)?;
            let found = world
                .find(start, kind, description)
                .ok_or(KernelError::KeyNotFound)?;
            if let Some(target) = destination {
                let holder = world.resolve(target)?;
                world.attach(found, holder)?;
            }
            serial(found)
        })
    }

    fn add(
        &self,
        ring: Ring,
        kind: Kind,
        description: &str,
        payload: &[u8],
    ) -> Result<Serial, KernelError> {
        self.run(Op::Add, |world| {
            if kind != Kind::Keyring {
                world.injected(Op::AddKey)?;
            }
            if kind == Kind::BigKey && !world.big_key {
                return Err(KernelError::NoDevice);
            }
            let holder = world.resolve(ring)?;
            // A key that can be updated is updated in place; a keyring is
            // replaced by a new one.
            if kind != Kind::Keyring
                && let Some(found) = world.child(holder, kind, description)
                && let Some(key) = world.keys.get_mut(&found)
            {
                key.payload = payload.to_vec();
                return serial(found);
            }
            let created = world.create(kind, description, payload);
            world.attach(created, holder)?;
            serial(created)
        })
    }

    fn link(&self, key: Ring, ring: Ring) -> Result<(), KernelError> {
        self.run(Op::Link, |world| {
            let linked = world.resolve(key)?;
            let holder = world.resolve(ring)?;
            world.attach(linked, holder)
        })
    }

    fn unlink(&self, key: Ring, ring: Ring) -> Result<(), KernelError> {
        self.run(Op::Unlink, |world| {
            let unlinked = world.resolve(key)?;
            let holder = world.resolve(ring)?;
            let children = &mut world
                .keys
                .get_mut(&holder)
                .ok_or(KernelError::KeyNotFound)?
                .children;
            let before = children.len();
            children.retain(|child| *child != unlinked);
            if children.len() == before {
                return Err(KernelError::KeyNotFound);
            }
            Ok(())
        })
    }

    fn clear(&self, ring: Ring) -> Result<(), KernelError> {
        self.run(Op::Clear, |world| {
            let holder = world.resolve(ring)?;
            world
                .keys
                .get_mut(&holder)
                .ok_or(KernelError::KeyNotFound)?
                .children
                .clear();
            Ok(())
        })
    }

    fn read(&self, key: Ring) -> Result<Zeroizing<Vec<u8>>, KernelError> {
        self.run(Op::Read, |world| {
            let read = world.resolve(key)?;
            if world
                .keys
                .get(&read)
                .is_some_and(|found| found.kind != Kind::Keyring)
            {
                world.injected(Op::ReadKey)?;
            }
            let found = world.keys.get(&read).ok_or(KernelError::KeyNotFound)?;
            Ok(Zeroizing::new(if found.kind == Kind::Keyring {
                found
                    .children
                    .iter()
                    .flat_map(|child| native_bytes(*child))
                    .collect()
            } else {
                found.payload.clone()
            }))
        })
    }

    fn describe(&self, key: Ring) -> Result<String, KernelError> {
        self.run(Op::Describe, |world| {
            let described = world.resolve(key)?;
            let found = world.keys.get(&described).ok_or(KernelError::KeyNotFound)?;
            Ok(format!(
                "{};{};-1;3f010000;{}",
                found.kind.name(),
                world.uid,
                found.description
            ))
        })
    }

    fn set_timeout(&self, key: Ring, seconds: u32) -> Result<(), KernelError> {
        self.run(Op::SetTimeout, |world| {
            let timed = world.resolve(key)?;
            let _previous = world.timeouts.insert(timed, seconds);
            Ok(())
        })
    }
}

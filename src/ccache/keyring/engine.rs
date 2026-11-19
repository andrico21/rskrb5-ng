//! Collection lookup and the primary name (`cc_keyring.c:182-338,423-646`).

use alloc::sync::Arc;

use super::{
    Fault, KernelError,
    backend::{Backend, Kind, Ring, Serial},
    cache::Handle,
    collection::{Collection, Single},
    residual::{
        Anchor, PERSISTENT_KEYRING, PRIMARY_KEY, Residual, parse_owner, parse_primary,
        parse_serials, primary_payload,
    },
};
use crate::ccache::{
    Error,
    stores::{CacheCollection, CacheHandle},
};

/// The prefix of a collection keyring name.
const COLLECTION_PREFIX: &str = "_krb_";
/// The primary cache of a collection with the empty name (a key cannot be
/// named with the empty string).
const EMPTY_COLLECTION_PRIMARY: &str = "tkt";

/// The cache logic over one kernel.
#[derive(Clone, Debug)]
pub(super) struct Engine {
    /// The kernel.
    backend: Arc<dyn Backend>,
}

impl Engine {
    /// The engine over the real kernel.
    #[cfg(all(feature = "ccache-keyring", target_os = "linux"))]
    pub(super) fn kernel() -> Self {
        Self::new(Arc::new(super::kernel::Kernel))
    }

    /// The engine over `backend`.
    pub(super) fn new(backend: Arc<dyn Backend>) -> Self {
        Self { backend }
    }

    /// The kernel.
    pub(super) fn backend(&self) -> &dyn Backend {
        &*self.backend
    }

    /// Name the call that failed.
    ///
    /// # Errors
    ///
    /// [`Fault::Kernel`] naming `operation`.
    pub(super) fn call<T>(
        operation: &'static str,
        result: Result<T, KernelError>,
    ) -> Result<T, Error> {
        result.map_err(|error| Fault::Kernel { operation, error }.into())
    }

    /// The cache a residual names (MIT `krcc_resolve`): the collection and its
    /// primary name are created when absent.
    ///
    /// # Errors
    ///
    /// Residual, version and kernel errors.
    pub(super) fn resolve(&self, text: &str) -> Result<Box<dyn CacheHandle>, Error> {
        let residual = Residual::parse(text)?;
        let collection = self.collection_ring(&residual)?;
        let subsidiary = match residual.subsidiary.clone() {
            Some(subsidiary) => subsidiary,
            None => self.primary_name(&residual, collection)?,
        };
        Ok(Box::new(Handle::new(
            self.clone(),
            residual,
            collection,
            subsidiary,
        )))
    }

    /// The collection a residual names.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::resolve`].
    pub(super) fn collection(&self, text: &str) -> Result<Box<dyn CacheCollection>, Error> {
        let residual = Residual::parse(text)?;
        let collection = self.collection_ring(&residual)?;
        match residual.subsidiary.clone() {
            Some(subsidiary) => Ok(Box::new(Single::new(Handle::new(
                self.clone(),
                residual,
                collection,
                subsidiary,
            )))),
            None => Ok(Box::new(Collection::new(
                self.clone(),
                residual,
                collection,
            ))),
        }
    }

    /// The key or keyring `description` of `kind` in `ring`, if there is one.
    /// A missing, expired or revoked key is absent.
    ///
    /// # Errors
    ///
    /// Any other kernel error.
    pub(super) fn lookup(
        &self,
        ring: Ring,
        kind: Kind,
        description: &str,
        destination: Option<Ring>,
    ) -> Result<Option<Serial>, Error> {
        match self.backend.search(ring, kind, description, destination) {
            Ok(serial) => Ok(Some(serial)),
            Err(KernelError::KeyNotFound | KernelError::KeyExpired | KernelError::KeyRevoked) => {
                Ok(None)
            }
            Err(error) => Err(Fault::Kernel {
                operation: "keyctl_search",
                error,
            }
            .into()),
        }
    }

    /// The keyring `name` of `parent`, created when absent. When `possess` is
    /// given it is also linked from there, so that the caller keeps
    /// possession rights on a keyring of the user or persistent keyring
    /// (`cc_keyring.c:229-250`).
    ///
    /// # Errors
    ///
    /// Kernel errors.
    pub(super) fn find_or_create(
        &self,
        parent: Ring,
        possess: Option<Ring>,
        name: &str,
    ) -> Result<Serial, Error> {
        if let Some(found) = self.lookup(parent, Kind::Keyring, name, possess)? {
            return Ok(found);
        }
        match possess {
            Some(possess_ring) => {
                let key = Self::call(
                    "add_key",
                    self.backend.add(possess_ring, Kind::Keyring, name, &[]),
                )?;
                Self::call("keyctl_link", self.backend.link(Ring::Key(key), parent))?;
                Ok(key)
            }
            None => Self::call(
                "add_key",
                self.backend.add(parent, Kind::Keyring, name, &[]),
            ),
        }
    }

    /// The keyring written for the session anchor: the user session keyring
    /// when it is the session keyring, because writing to the special session
    /// keyring may create an empty private one (`cc_keyring.c:197-207`).
    pub(super) fn session_anchor(&self) -> Ring {
        if self.backend.lookup(Ring::Session).ok() == self.backend.lookup(Ring::UserSession).ok() {
            Ring::UserSession
        } else {
            Ring::Session
        }
    }

    /// The collection keyring of a residual, created when absent (MIT
    /// `get_collection`).
    ///
    /// # Errors
    ///
    /// [`Fault::InvalidUid`] and kernel errors.
    fn collection_ring(&self, residual: &Residual) -> Result<Serial, Error> {
        let (anchor, possess) = match residual.anchor {
            Anchor::Persistent => {
                let persistent = self.persistent_ring(&residual.collection)?;
                return self.find_or_create(persistent, Some(Ring::Process), PERSISTENT_KEYRING);
            }
            Anchor::Process => (Ring::Process, None),
            Anchor::Thread => (Ring::Thread, None),
            Anchor::Session | Anchor::Legacy => (self.session_anchor(), None),
            Anchor::User => (Ring::User, Some(Ring::Process)),
        };
        self.find_or_create(
            anchor,
            possess,
            &format!("{COLLECTION_PREFIX}{}", residual.collection),
        )
    }

    /// The persistent keyring of the user a `persistent` collection names:
    /// the caller for the empty name, falling back to the user keyring when
    /// the kernel has none (`cc_keyring.c:182-195,456-473`).
    ///
    /// # Errors
    ///
    /// [`Fault::InvalidUid`] for a name that is not a decimal user id, and
    /// the kernel's refusal, `EPERM` for another user without `CAP_SETUID`.
    fn persistent_ring(&self, collection: &str) -> Result<Ring, Error> {
        let uid = if collection.is_empty() {
            None
        } else if collection.bytes().all(|byte| byte.is_ascii_digit()) {
            Some(
                collection
                    .parse::<u32>()
                    .map_err(|_overflow| Fault::InvalidUid)?,
            )
        } else {
            return Err(Fault::InvalidUid.into());
        };
        match self.backend.persistent(uid) {
            Ok(serial) => Ok(Ring::Key(serial)),
            Err(KernelError::NotSupported) if uid.is_none() => Ok(Ring::User),
            Err(KernelError::NotSupported) => {
                let owner = Self::call("keyctl_describe", self.backend.describe(Ring::User))?;
                if parse_owner(&owner) == uid {
                    Ok(Ring::User)
                } else {
                    Err(Fault::InvalidUid.into())
                }
            }
            Err(error) => Err(Fault::Kernel {
                operation: "keyctl_get_persistent",
                error,
            }
            .into()),
        }
    }

    /// The primary cache name of a collection, initialized when absent
    /// (MIT `get_primary_name`). Initializing a legacy collection adopts the
    /// cache that old code left in the session keyring.
    ///
    /// # Errors
    ///
    /// [`Fault::MalformedPrimary`], [`Fault::UnknownCollectionVersion`] and
    /// kernel errors.
    pub(super) fn primary_name(
        &self,
        residual: &Residual,
        collection: Serial,
    ) -> Result<String, Error> {
        let ring = Ring::Key(collection);
        let Some(primary) = self.lookup(ring, Kind::User, PRIMARY_KEY, None)? else {
            let name = if residual.collection.is_empty() {
                EMPTY_COLLECTION_PRIMARY.to_owned()
            } else {
                residual.collection.clone()
            };
            self.set_primary(collection, &name)?;
            if residual.anchor == Anchor::Legacy
                && let Some(legacy) = self.lookup(Ring::Session, Kind::Keyring, &name, None)?
            {
                Self::call("keyctl_link", self.backend.link(Ring::Key(legacy), ring))?;
            }
            return Ok(name);
        };
        let payload = Self::call("keyctl_read", self.backend.read(Ring::Key(primary)))?;
        parse_primary(&payload)
    }

    /// Make `name` the primary cache of a collection (MIT `set_primary_name`).
    ///
    /// # Errors
    ///
    /// Kernel errors.
    pub(super) fn set_primary(&self, collection: Serial, name: &str) -> Result<(), Error> {
        Self::call(
            "add_key",
            self.backend.add(
                Ring::Key(collection),
                Kind::User,
                PRIMARY_KEY,
                &primary_payload(name),
            ),
        )
        .map(drop)
    }

    /// The keys and keyrings a keyring links.
    ///
    /// # Errors
    ///
    /// Kernel errors.
    pub(super) fn children(&self, ring: Serial) -> Result<Vec<Serial>, Error> {
        let bytes = Self::call("keyctl_read", self.backend.read(Ring::Key(ring)))?;
        Ok(parse_serials(&bytes))
    }
}

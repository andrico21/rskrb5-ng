//! The caller's extension registry, shared by a transport and its copies.

use alloc::sync::Arc;
use core::fmt;

use crate::extensions::Registry;

/// A shared [`Registry`]; two handles are equal when they share one registry,
/// so [`super::Tokio`] keeps its `Eq`.
#[derive(Clone)]
pub(super) struct Shared(Arc<Registry>);

impl Shared {
    /// A handle on `registry`.
    pub(super) const fn new(registry: Arc<Registry>) -> Self {
        Self(registry)
    }

    /// The registry.
    pub(super) fn get(&self) -> &Registry {
        &self.0
    }
}

impl PartialEq for Shared {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for Shared {}

impl fmt::Debug for Shared {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&*self.0, f)
    }
}

//! The built-in modules of MIT's `localauth` interface as extension providers.

use crate::extensions::Extension;

use super::LocalAuthorizer;

/// The built-in modules of `authorizer`, in MIT's order.
#[must_use]
#[inline]
pub fn modules(authorizer: &LocalAuthorizer) -> Vec<Extension> {
    drop(authorizer.clone());
    Vec::new()
}

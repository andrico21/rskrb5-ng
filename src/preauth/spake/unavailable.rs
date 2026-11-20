//! Without the `spake` feature no group arithmetic is compiled: every group is
//! unavailable, so [`super::Policy::is_usable`] is `false` and the
//! exchange never reaches this function.

use super::{Entropy, Group, Shared};
use crate::error::Spake as Error;

/// No group can be computed in this build.
///
/// # Errors
/// Always [`Error::NoGroups`].
pub(super) const fn exchange(
    _group: Group,
    _wbytes: &[u8],
    _theirs: &[u8],
    _entropy: &mut Entropy<'_>,
) -> Result<Shared, Error> {
    Err(Error::NoGroups)
}

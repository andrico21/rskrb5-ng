//! MIT `none`: no replay protection.

use super::{Admission, Error, Evidence, NoneReplayStore, Store};

impl NoneReplayStore {
    /// Opt out of replay protection.
    ///
    /// # Security
    ///
    /// Every authenticator is accepted, however often it is presented.
    #[must_use]
    #[inline]
    pub const fn opt_out() -> Self {
        Self
    }
}

impl Store for NoneReplayStore {
    #[inline]
    fn admit(&self, _evidence: &Evidence) -> Result<Admission, Error> {
        Ok(Admission::Fresh)
    }
}

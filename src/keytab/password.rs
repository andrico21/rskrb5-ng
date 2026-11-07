//! Password erasure boundary with live-owner test observation.

use zeroize::{Zeroize as _, Zeroizing};

/// A moved caller allocation, erased before release even on early rejection.
pub(super) struct Owner(pub Zeroizing<Vec<u8>>);

// Drop audit: synchronous wipe before deallocation; the field also erases spare capacity.
impl Drop for Owner {
    fn drop(&mut self) {
        let Self(bytes) = self;
        bytes.as_mut_slice().zeroize();
        #[cfg(test)]
        tests::EVENTS.with_borrow_mut(|events| {
            events.push((bytes.len(), bytes.iter().all(|byte| *byte == 0)));
        });
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use crate::keytab::{Keytab, Principal};
    use core::{cell::RefCell, error::Error, time::Duration};
    use std::time::UNIX_EPOCH;

    std::thread_local! {
        /// Live owner lengths and erasure state before deallocation.
        pub(super) static EVENTS: RefCell<Vec<(usize, bool)>> = const { RefCell::new(Vec::new()) };
    }

    /// Success, enctype/time errors and invalid names erase the original owned password.
    #[test]
    fn keytab_password_erases_on_every_exit() -> Result<(), Box<dyn Error>> {
        for (name, etype, time, success) in [
            ("alice", 17_i32, UNIX_EPOCH, true),
            ("alice", -1_i32, UNIX_EPOCH, false),
            (
                "alice",
                17_i32,
                UNIX_EPOCH
                    .checked_sub(Duration::from_secs(1))
                    .ok_or("time")?,
                false,
            ),
            ("", 17_i32, UNIX_EPOCH, false),
        ] {
            EVENTS.with_borrow_mut(Vec::clear);
            let result = Keytab::new().add_entry_from_password_name(
                name,
                "R",
                b"password".to_vec().into(),
                time,
                1,
                etype,
            );
            assert_eq!(result.is_ok(), success);
            EVENTS.with_borrow(|events| {
                assert!(events.contains(&(8, true)) && events.iter().all(|(_, wiped)| *wiped));
            });
        }
        let mut keys = Keytab::new();
        EVENTS.with_borrow_mut(Vec::clear);
        keys.add_entry_from_password(
            Principal::new("R", 1, ["alice"]),
            b"password".to_vec().into(),
            UNIX_EPOCH,
            1,
            17,
        )?;
        EVENTS.with_borrow(|events| assert_eq!(events.as_slice(), [(8, true)]));
        Ok(())
    }
}

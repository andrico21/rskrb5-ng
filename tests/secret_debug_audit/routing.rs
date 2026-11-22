//! Credential owners of the routing work package (WP-11).

#[cfg(test)]
pub(super) mod tests {
    use std::time::UNIX_EPOCH;

    use rskrb5_ng::{
        client::{AsRepSession, principal::Principal},
        keytab::EncryptionKey,
        routing::impersonation::Delegation,
    };

    use crate::tests::{pattern, redacted};

    pub(crate) fn run_audit() {
        delegation_redacts_both_tickets();
    }

    /// A delegation shows neither ticket's session key nor ticket bytes.
    fn delegation_redacts_both_tickets() {
        let session = |marker: u8| {
            AsRepSession::new(
                Principal::user("USER.TEST", "alice"),
                Principal::new("USER.TEST", 2, ["HTTP", "backend.user.test"]),
                EncryptionKey::new(18, pattern(marker)),
                pattern(marker.wrapping_add(1)).into(),
                [0; 4],
                UNIX_EPOCH,
                UNIX_EPOCH,
            )
        };
        redacted(
            &Delegation::new(session(41), session(61)),
            &[&pattern(41), &pattern(42), &pattern(61), &pattern(62)],
        );
    }
}

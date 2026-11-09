//! Exhaustive metadata-only formatting at password-frame ownership boundaries.

use core::fmt;

use super::{BuiltChangePasswordRequest, PasswordEncryption, Reply, Request};

/// Observe live bytes before replacing retained frame storage.
#[cfg(test)]
pub(super) fn observe_frame(bytes: &[u8]) {
    tests::ERASED
        .with_borrow_mut(|events| events.push((bytes.len(), bytes.iter().all(|byte| *byte == 0))));
}

impl fmt::Debug for Request {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { ap_req, krb_priv } = self;
        f.debug_struct("Request")
            .field("ticket_etype", &ap_req.ticket.enc_part.etype)
            .field("authenticator_len", &ap_req.authenticator.cipher.len())
            .field("private_len", &krb_priv.enc_part.cipher.len())
            .finish()
    }
}

impl fmt::Debug for Reply {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            message_length,
            version,
            ap_rep_length,
            ap_rep,
            krb_priv,
            krb_error,
            result,
        } = self;
        f.debug_struct("Reply")
            .field("message_length", message_length)
            .field("version", version)
            .field("ap_rep_length", ap_rep_length)
            .field("ap_rep_present", &ap_rep.is_some())
            .field("krb_priv_present", &krb_priv.is_some())
            .field("krb_error_present", &krb_error.is_some())
            .field("result_code", &result.as_ref().map(|value| value.code))
            .finish()
    }
}

impl fmt::Debug for BuiltChangePasswordRequest {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            request,
            der,
            reply_key,
        } = self;
        f.debug_struct("BuiltChangePasswordRequest")
            .field("request", request)
            .field("der_len", &der.len())
            .field("reply_key", reply_key)
            .finish()
    }
}

impl fmt::Debug for PasswordEncryption<'_> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            reply_key,
            ap_req_confounder,
            krb_priv_confounder,
        } = self;
        f.debug_struct("PasswordEncryption")
            .field("reply_key", reply_key)
            .field("ap_req_confounder_len", &ap_req_confounder.len())
            .field("krb_priv_confounder_len", &krb_priv_confounder.len())
            .finish()
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
    use core::{cell::RefCell, error::Error};

    use super::{BuiltChangePasswordRequest, Request};
    use crate::keytab::EncryptionKey;

    std::thread_local! {
        /// Previous frame lengths and actual zero-byte observations.
        pub(super) static ERASED: RefCell<Vec<(usize, bool)>> = const { RefCell::new(Vec::new()) };
    }

    /// Frame replacement erases old bytes before the result container is destroyed.
    #[test]
    fn built_password_frame_replacement_erases_old_bytes() -> Result<(), Box<dyn Error>> {
        let request = Request::parse(&hex::decode(
            include_str!("../../tests/fixtures/kpasswd-request.hex").trim(),
        )?)?;
        let mut built = BuiltChangePasswordRequest {
            request,
            der: vec![0x41; 16].into(),
            reply_key: EncryptionKey::new(17, vec![0x52; 16]),
        };
        ERASED.with_borrow_mut(Vec::clear);
        built.set_der(vec![0x63; 17].into());
        ERASED.with_borrow(|events| assert_eq!(events.as_slice(), [(16, true)]));
        Ok(())
    }
}

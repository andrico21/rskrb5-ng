//! Credential owners expose only metadata and byte lengths to diagnostics.

use core::fmt;

use super::{Krb5MechToken, NegTokenInit, NegTokenResp};

impl fmt::Debug for Krb5MechToken {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            oid,
            token_id,
            message,
        } = self;
        f.debug_struct("Krb5MechToken")
            .field("oid", oid)
            .field("token_id", token_id)
            .field("message_len", &message.len())
            .finish()
    }
}

impl fmt::Debug for NegTokenInit {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            mech_types,
            req_flags,
            mech_token,
            mech_list_mic,
        } = self;
        f.debug_struct("NegTokenInit")
            .field("mech_types", mech_types)
            .field("req_flags", req_flags)
            .field(
                "mech_token_len",
                &mech_token.as_ref().map(|bytes| bytes.len()),
            )
            .field(
                "mech_list_mic_len",
                &mech_list_mic.as_ref().map(|bytes| bytes.len()),
            )
            .finish()
    }
}

impl fmt::Debug for NegTokenResp {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            neg_state,
            supported_mech,
            response_token,
            mech_list_mic,
        } = self;
        f.debug_struct("NegTokenResp")
            .field("neg_state", neg_state)
            .field("supported_mech", supported_mech)
            .field(
                "response_token_len",
                &response_token.as_ref().map(|bytes| bytes.len()),
            )
            .field(
                "mech_list_mic_len",
                &mech_list_mic.as_ref().map(|bytes| bytes.len()),
            )
            .finish()
    }
}

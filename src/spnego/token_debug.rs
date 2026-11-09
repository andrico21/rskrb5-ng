//! Credential owners expose only metadata and byte lengths to diagnostics.

use core::fmt;

use super::{
    AcceptedContext, InitiatorContextOptions, Krb5MechToken, NegTokenInit, NegTokenResp,
    NegotiationToken, Token,
};

impl fmt::Debug for NegotiationToken {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Init(value) => f.debug_tuple("Init").field(value).finish(),
            Self::Resp(value) => f.debug_tuple("Resp").field(value).finish(),
        }
    }
}

impl fmt::Debug for Token {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Init(value) => f.debug_tuple("Init").field(value).finish(),
            Self::Resp(value) => f.debug_tuple("Resp").field(value).finish(),
        }
    }
}

impl fmt::Debug for InitiatorContextOptions {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            crypto_policy,
            context_flags,
            ap_option_bits,
            subkey,
            sequence_number,
        } = self;
        f.debug_struct("InitiatorContextOptions")
            .field("crypto_policy", crypto_policy)
            .field("context_flags", context_flags)
            .field("ap_option_bits", ap_option_bits)
            .field("subkey", subkey)
            .field("sequence_number", sequence_number)
            .finish()
    }
}

impl fmt::Debug for AcceptedContext {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            ap_req,
            selected_mechanism,
            token_mechanism,
            mech_types_der,
        } = self;
        f.debug_struct("AcceptedContext")
            .field("ap_req", ap_req)
            .field("selected_mechanism", selected_mechanism)
            .field("token_mechanism", token_mechanism)
            .field("mech_types_der_len", &mech_types_der.as_ref().map(Vec::len))
            .finish()
    }
}

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

//! Redacted diagnostics for credential-bearing client results.

use core::fmt;

use super::{AsRepSession, BuiltApReq, BuiltAsReq, BuiltTgsReq, KdcError, ReferralTgsResult};

impl fmt::Debug for ReferralTgsResult {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            ticket,
            referral_tgts,
        } = self;
        f.debug_struct("ReferralTgsResult")
            .field("ticket", ticket)
            .field("referral_tgts", referral_tgts)
            .finish()
    }
}

impl fmt::Debug for KdcError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            ctime,
            cusec,
            stime,
            susec,
            error_code,
            text,
            client,
            service,
            e_data,
            method_data,
            preauth_key_info,
        } = self;
        f.debug_struct("KdcError")
            .field("ctime", ctime)
            .field("cusec", cusec)
            .field("stime", stime)
            .field("susec", susec)
            .field("error_code", error_code)
            .field("text_len", &text.as_ref().map(String::len))
            .field("client", client)
            .field("service", service)
            .field("e_data_len", &e_data.as_ref().map(|bytes| bytes.len()))
            .field("method_data_count", &method_data.len())
            .field("preauth_key_info", preauth_key_info)
            .finish()
    }
}

impl fmt::Debug for BuiltAsReq {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            crypto_policy,
            reply_clock,
            message: _,
            der,
            client,
            service,
            nonce,
        } = self;
        f.debug_struct("BuiltAsReq")
            .field("crypto_policy", crypto_policy)
            .field("reply_clock", reply_clock)
            .field("der_len", &der.len())
            .field("client", client)
            .field("service", service)
            .field("nonce", nonce)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for BuiltTgsReq {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            reply_key_usage,
            crypto_policy,
            reply_clock,
            delegation_keytab: _,
            message: _,
            der,
            client,
            service,
            kdc_realm,
            nonce,
        } = self;
        f.debug_struct("BuiltTgsReq")
            .field("reply_key_usage", reply_key_usage)
            .field("crypto_policy", crypto_policy)
            .field("reply_clock", reply_clock)
            .field("der_len", &der.len())
            .field("client", client)
            .field("service", service)
            .field("kdc_realm", kdc_realm)
            .field("nonce", nonce)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for BuiltApReq {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            message: _,
            der,
            client,
            service,
            session_key,
            authenticator_ctime,
            authenticator_cusec,
            authenticator_time,
            sequence_number,
            subkey,
        } = self;
        f.debug_struct("BuiltApReq")
            .field("der_len", &der.len())
            .field("client", client)
            .field("service", service)
            .field("session_key", session_key)
            .field("authenticator_ctime", authenticator_ctime)
            .field("authenticator_cusec", authenticator_cusec)
            .field("authenticator_time", authenticator_time)
            .field("sequence_number", sequence_number)
            .field("subkey", subkey)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for AsRepSession {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            client,
            service,
            session_key,
            ticket,
            ticket_flags,
            auth_time,
            start_time,
            end_time,
            renew_till,
            key_expiration,
        } = self;
        f.debug_struct("AsRepSession")
            .field("client", client)
            .field("service", service)
            .field("session_key", session_key)
            .field("ticket_len", &ticket.len())
            .field("ticket_flags", ticket_flags)
            .field("auth_time", auth_time)
            .field("start_time", start_time)
            .field("end_time", end_time)
            .field("renew_till", renew_till)
            .field("key_expiration", key_expiration)
            .finish_non_exhaustive()
    }
}

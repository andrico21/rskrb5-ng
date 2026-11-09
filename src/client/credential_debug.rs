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
        f.debug_struct("BuiltApReq")
            .field("der_len", &self.der().len())
            .field("client", &self.client)
            .field("service", &self.service)
            .field("session_key", self.session_key())
            .field("authenticator_ctime", &self.authenticator_ctime)
            .field("authenticator_cusec", &self.authenticator_cusec)
            .field("authenticator_time", &self.authenticator_time)
            .field("sequence_number", &self.sequence_number)
            .field("subkey", &self.subkey())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for AsRepSession {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AsRepSession")
            .field("client", &self.client)
            .field("service", &self.service)
            .field("session_key", self.session_key())
            .field("ticket_len", &self.ticket().len())
            .field("ticket_flags", &self.ticket_flags)
            .field("auth_time", &self.auth_time)
            .field("start_time", &self.start_time)
            .field("end_time", &self.end_time)
            .field("renew_till", &self.renew_till)
            .field("key_expiration", &self.key_expiration)
            .finish_non_exhaustive()
    }
}

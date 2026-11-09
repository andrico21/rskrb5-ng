//! Explicit formatting of service-side credential owners.

use core::fmt;

use super::{ApRepOptions, ValidatedApReq, Validator, VerifiedApRep};

impl fmt::Debug for ValidatedApReq {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            crypto_policy,
            client,
            service,
            session_key,
            subkey,
            sequence_number,
            ticket_start,
            ticket_end,
            authenticator_ctime,
            authenticator_cusec,
            authenticator_time,
            pac,
        } = self;
        f.debug_struct("ValidatedApReq")
            .field("crypto_policy", crypto_policy)
            .field("client", client)
            .field("service", service)
            .field("session_key", session_key)
            .field("subkey", subkey)
            .field("sequence_number", sequence_number)
            .field("ticket_start", ticket_start)
            .field("ticket_end", ticket_end)
            .field("authenticator_ctime", authenticator_ctime)
            .field("authenticator_cusec", authenticator_cusec)
            .field("authenticator_time", authenticator_time)
            .field("pac", pac)
            .finish()
    }
}

impl fmt::Debug for ApRepOptions {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            subkey,
            sequence_number,
            kvno,
        } = self;
        f.debug_struct("ApRepOptions")
            .field("subkey", subkey)
            .field("sequence_number", sequence_number)
            .field("kvno", kvno)
            .finish()
    }
}

impl fmt::Debug for VerifiedApRep {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            ctime,
            cusec,
            authenticator_time,
            subkey,
            sequence_number,
        } = self;
        f.debug_struct("VerifiedApRep")
            .field("ctime", ctime)
            .field("cusec", cusec)
            .field("authenticator_time", authenticator_time)
            .field("subkey", subkey)
            .field("sequence_number", sequence_number)
            .finish()
    }
}

impl fmt::Debug for Validator<'_> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            crypto_policy,
            keytab,
            max_clock_skew,
            now,
            keytab_principal,
            client_address,
            require_client_address,
            replay_cache,
            shared_replay_cache,
            transit_policy,
        } = self;
        f.debug_struct("Validator")
            .field("crypto_policy", crypto_policy)
            .field("keytab_entries", &keytab.entries().len())
            .field("max_clock_skew", max_clock_skew)
            .field("now", now)
            .field("keytab_principal", keytab_principal)
            .field("client_address", client_address)
            .field("require_client_address", require_client_address)
            .field("replay_cache", replay_cache)
            .field("shared_replay_cache", shared_replay_cache)
            .field("transit_policy", transit_policy)
            .finish()
    }
}

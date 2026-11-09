//! Exhaustive metadata-only formatting of credential payload owners.

use core::fmt;

use super::{AuthorizationDataEntry, CCache, ConfigEntry, Credential};

impl fmt::Debug for CCache {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            version,
            header,
            default_principal,
            credentials,
        } = self;
        f.debug_struct("CCache")
            .field("version", version)
            .field("header", header)
            .field("default_principal", default_principal)
            .field("credentials", credentials)
            .finish()
    }
}

impl fmt::Debug for ConfigEntry<'_> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            key,
            principal,
            value,
        } = self;
        f.debug_struct("ConfigEntry")
            .field("key", key)
            .field("principal", principal)
            .field("value_len", &value.len())
            .finish()
    }
}

impl fmt::Debug for AuthorizationDataEntry {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { ad_type, data } = self;
        f.debug_struct("AuthorizationDataEntry")
            .field("ad_type", ad_type)
            .field("data_len", &data.len())
            .finish()
    }
}

impl fmt::Debug for Credential {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            client,
            server,
            key,
            times,
            is_skey,
            ticket_flags,
            addresses,
            auth_data,
            ticket,
            second_ticket,
        } = self;
        f.debug_struct("Credential")
            .field("client", client)
            .field("server", server)
            .field("key", key)
            .field("times", times)
            .field("is_skey", is_skey)
            .field("ticket_flags", ticket_flags)
            .field("addresses", addresses)
            .field("auth_data", auth_data)
            .field("ticket_len", &ticket.len())
            .field("second_ticket_len", &second_ticket.len())
            .finish()
    }
}

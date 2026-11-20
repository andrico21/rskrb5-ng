//! Server discovery and hostname canonicalization (plan 2 WP-10a).
//!
//! The built-in discovery chain of MIT's `locate_kdc.c` (registered locators, the
//! profile, DNS URI records, DNS SRV records), host-to-realm mapping as in
//! `hostrealm.c` (registered mappers, `[domain_realm]`, opt-in DNS TXT records,
//! `realm_try_domains`) and the hostname canonicalization of `sn2princ.c`.
//!
//! # Security
//!
//! DNS never authenticates a KDC: every answer here only says where to send a
//! request, and the reply is still validated by its keys. A DNS TXT realm is
//! used only when `dns_lookup_realm` is enabled (it is off by default) and the
//! host is not an address literal. Parent-domain and parent-realm searches are
//! bounded by the name and by `realm_try_domains`.
//!
//! The paths are submodule paths (`discovery::locate::ServerLocator`,
//! `discovery::realm::HostRealmResolver`, `discovery::hostname::CanonicalizationPolicy`), because the facade gate allows a re-export only in `src/lib.rs`.

/// Hostname canonicalization (`dns_canonicalize_hostname`, `rdns`, `qualify_shortname`).
pub mod hostname;
/// Server location: locators, the profile, DNS URI and SRV records.
pub mod locate;
/// Host-to-realm mapping.
pub mod realm;
/// DNS lookups and answer classification.
pub(crate) mod records;
/// MIT's `krb5srv:` URI record target.
pub mod uri;

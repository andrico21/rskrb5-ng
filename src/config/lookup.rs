//! Read-only lookups over a parsed configuration: realms, routes, endpoints and appdefaults.

use super::{Config, ConfigDiagnostic, Realm, restrictions, section_values};
use crate::error::Config as Error;

/// Lookup application text using MIT's four-level precedence.
pub(super) fn appdefault<'config>(
    this: &'config Config,
    app: &str,
    realm: &str,
    relation: &str,
) -> Option<&'config str> {
    this.applications.get(app, realm, relation)
}

/// Lookup a boolean without coercing malformed strings into false.
///
/// # Errors
/// Returns `InvalidBoolean` for a selected non-boolean application value.
pub(super) fn appdefault_boolean(
    this: &Config,
    app: &str,
    realm: &str,
    relation: &str,
) -> Result<Option<bool>, Error> {
    this.applications.boolean(app, realm, relation)
}

/// Return a declared route, preserving missing versus direct.
pub(super) fn capath<'config>(
    this: &'config Config,
    client: &str,
    server: &str,
) -> Option<&'config section_values::Route> {
    this.capaths.get(client)?.get(server)
}

/// Diagnostics for selected profile relations: unknown, unavailable or out-of-scope policy.
pub(super) fn diagnostics(this: &Config) -> &[ConfigDiagnostic] {
    &this.libdefaults.enctype_diagnostics
}

/// Resolve a host mapping, then the explicitly configured default realm.
pub(super) fn realm_for_host<'config>(this: &'config Config, host: &str) -> Option<&'config str> {
    this.resolve_realm(host).or_else(|| {
        (!this.libdefaults.default_realm.is_empty())
            .then_some(this.libdefaults.default_realm.as_str())
    })
}

/// Return the configured realm with this name.
pub(super) fn realm<'config>(this: &'config Config, realm: &str) -> Option<&'config Realm> {
    this.realms.iter().find(|entry| entry.name == realm)
}

/// Resolve a DNS name to a Kerberos realm using `[domain_realm]`.
pub(super) fn resolve_realm<'config>(
    this: &'config Config,
    dns_name: &str,
) -> Option<&'config str> {
    let folded = dns_name.trim_end_matches('.').to_ascii_lowercase();
    let domain_name = folded.as_str();
    if let Some(realm) = this.domain_realm.get(domain_name) {
        return Some(realm);
    }

    let parts: Vec<_> = domain_name.split('.').collect();
    for start in 1..parts.len() {
        let bare = parts.get(start..).unwrap_or_default().join(".");
        let dotted = format!(".{bare}");
        if let Some(realm) = this.domain_realm.get(&dotted) {
            return Some(realm);
        }
        if let Some(realm) = this.domain_realm.get(&bare) {
            return Some(realm);
        }
    }
    None
}

/// Return KDC hosts configured for a realm.
///
/// # Errors
/// Returns [`Error::NoRealm`] when the realm is not configured, and
/// [`Error::NoKdc`] when it lists no KDC.
pub(super) fn configured_kdcs<'config>(
    this: &'config Config,
    realm: &str,
) -> Result<&'config [String], Error> {
    restrictions::config(this)?;
    let realm_entry = this
        .realm(realm)
        .ok_or_else(|| Error::NoRealm(realm.to_owned()))?;
    if realm_entry.kdc.is_empty() {
        return Err(Error::NoKdc(realm.to_owned()));
    }
    Ok(&realm_entry.kdc)
}

/// Return password-change servers configured for a realm.
///
/// # Errors
/// Returns [`Error::NoRealm`] when the realm is not configured, and
/// [`Error::NoKpasswdServer`] when it lists no password-change server.
pub(super) fn configured_kpasswd_servers<'config>(
    this: &'config Config,
    realm: &str,
) -> Result<&'config [String], Error> {
    restrictions::config(this)?;
    let realm_entry = this
        .realm(realm)
        .ok_or_else(|| Error::NoRealm(realm.to_owned()))?;
    if realm_entry.kpasswd_server.is_empty() {
        return Err(Error::NoKpasswdServer(realm.to_owned()));
    }
    Ok(&realm_entry.kpasswd_server)
}

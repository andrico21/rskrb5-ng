//! Host-to-realm mapping (MIT `hostrealm.c` and its built-in modules).
//!
//! The chain is MIT's: registered mappers, then the profile (`[domain_realm]`, then
//! `default_realm`), then DNS TXT records (`dns_lookup_realm`, off by default), then
//! the domain heuristic (`realm_try_domains`).

use crate::{
    client::transport::{KdcProtocol, Tokio},
    config::Config,
    discovery::{
        locate::EndpointRole,
        records::{dns_resolver, txt_realm},
    },
    error::Client as Error,
    extensions::{RealmQuery, Registry},
};

/// The longest host name mapped: a DNS name.
const MAX_HOST_BYTES: usize = 253;

/// Maps host names to Kerberos realms.
///
/// Built with [`Tokio::host_realms`].
#[derive(Clone, Copy, Debug)]
pub struct HostRealmResolver<'config> {
    /// The transport whose DNS server is used.
    transport: Tokio,
    /// The profile.
    config: &'config Config,
    /// Registered mappers, asked first.
    registry: Option<&'config Registry>,
}

impl<'config> HostRealmResolver<'config> {
    /// A resolver over `config` that asks DNS through `transport`.
    pub(crate) const fn new(transport: Tokio, config: &'config Config) -> Self {
        Self {
            transport,
            config,
            registry: None,
        }
    }

    /// Ask the host-realm mappers registered in `registry` first.
    #[must_use]
    #[inline]
    pub const fn with_registry(mut self, registry: &'config Registry) -> Self {
        self.registry = Some(registry);
        self
    }

    /// The realm of `host` by registered mappers and `[domain_realm]`: `None` when
    /// none maps it (MIT then asks the KDC for a referral).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Locate`] for a registered mapper that fails or answers
    /// malformed data.
    #[inline]
    pub fn host_realm(&self, host: &str) -> Result<Option<String>, Error> {
        let Some(cleaned) = clean(host) else {
            return Ok(None);
        };
        if let Some(realms) = self.mapped(&RealmQuery::Host(&cleaned))? {
            return Ok(realms.into_iter().next());
        }
        if is_numeric_address(&cleaned) {
            return Ok(None);
        }
        Ok(self.config.resolve_realm(&cleaned).map(str::to_owned))
    }

    /// The realm for a host that [`Self::host_realm`] did not map: registered
    /// mappers, DNS TXT records, then the domain heuristic.
    ///
    /// The domain heuristic is MIT's `hostrealm_domain.c`: with `realm_try_domains`
    /// of `n` (default `-1`, off), the domain of the host and `n` of its parents
    /// that are realms (a realm is a name that has servers), and in any case the
    /// host's parent domain in upper case.
    ///
    /// # Security
    ///
    /// DNS TXT lookup is used only with `dns_lookup_realm = true`, never for an
    /// address literal. The answer names a realm; it authenticates nothing.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Locate`] for a failing mapper and [`Error::DnsSrvLookup`]
    /// for a TXT lookup that fails other than by finding no record.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: DNS lookups change no state.
    #[inline]
    pub async fn fallback_realm(&self, host: &str) -> Result<Option<String>, Error> {
        let Some(cleaned) = clean(host) else {
            return Ok(None);
        };
        if let Some(realms) = self.mapped(&RealmQuery::Fallback(&cleaned))? {
            return Ok(realms.into_iter().next());
        }
        if let Some(realm) = self.txt_for_host(&cleaned).await? {
            return Ok(Some(realm));
        }
        if is_numeric_address(&cleaned) {
            return Ok(None);
        }
        if let Some(realm) = self.try_domains(&cleaned).await {
            return Ok(Some(realm));
        }
        Ok(cleaned
            .split_once('.')
            .map(|(_, parent)| parent.to_ascii_uppercase()))
    }

    /// The realm of the service host `host` for a ticket request: the first of
    /// [`Self::host_realm`], an opt-in TXT record (`dns_lookup_realm`), an opt-in
    /// domain search (`realm_try_domains` of `0` or more), then `default_realm`.
    ///
    /// Without those opt-ins this is the lookup the transport always made:
    /// `[domain_realm]`, then `default_realm`.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::host_realm`] and [`Self::fallback_realm`].
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: DNS lookups change no state.
    #[inline]
    pub async fn service_realm(&self, host: &str) -> Result<Option<String>, Error> {
        if let Some(realm) = self.host_realm(host)? {
            return Ok(Some(realm));
        }
        if let Some(cleaned) = clean(host) {
            if let Some(realm) = self.txt_for_host(&cleaned).await? {
                return Ok(Some(realm));
            }
            if !is_numeric_address(&cleaned)
                && let Some(realm) = self.try_domains(&cleaned).await
            {
                return Ok(Some(realm));
            }
        }
        Ok((!self.config.libdefaults.default_realm.is_empty())
            .then(|| self.config.libdefaults.default_realm.clone()))
    }

    /// The default realm: registered mappers, `default_realm`, then, with
    /// `dns_lookup_realm` and the local host's fully qualified name, the TXT
    /// record of that name or of a parent and last the global `_kerberos` record.
    ///
    /// The library has no source for the local host name (reading it is an
    /// ambient input), so the caller supplies `local_fqdn` when it wants DNS.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::fallback_realm`].
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: DNS lookups change no state.
    #[inline]
    pub async fn default_realm(&self, local_fqdn: Option<&str>) -> Result<Option<String>, Error> {
        if let Some(realms) = self.mapped(&RealmQuery::Default)? {
            return Ok(realms.into_iter().next());
        }
        let configured = &self.config.libdefaults.default_realm;
        if !configured.is_empty() {
            return Ok(Some(configured.clone()));
        }
        if !self.config.libdefaults.dns_lookup_realm.is_enabled() {
            return Ok(None);
        }
        if let Some(local) = local_fqdn.and_then(clean)
            && let Some(realm) = self.txt_for_host(&local).await?
        {
            return Ok(Some(realm));
        }
        let resolver = dns_resolver(self.transport.dns_server())?;
        txt_realm(&resolver, "_kerberos", "").await
    }

    /// The first registered mapper's answer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Locate`] for a mapper that fails or answers malformed data.
    fn mapped(&self, query: &RealmQuery<'_>) -> Result<Option<Vec<String>>, Error> {
        self.registry.map_or(Ok(None), |registry| {
            registry
                .realms(self.config, query)
                .map_err(|source| Error::Locate(Box::new(source)))
        })
    }

    /// The `_kerberos` TXT realm of `host` or of the first parent that has one.
    ///
    /// # Errors
    ///
    /// The errors of [`txt_realm`], and [`Error::DnsResolverConfig`].
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: DNS lookups change no state.
    async fn txt_for_host(&self, host: &str) -> Result<Option<String>, Error> {
        if !self.config.libdefaults.dns_lookup_realm.is_enabled() || is_numeric_address(host) {
            return Ok(None);
        }
        let resolver = dns_resolver(self.transport.dns_server())?;
        let mut name = host;
        loop {
            if let Some(realm) = txt_realm(&resolver, &format!("_kerberos.{name}."), host).await? {
                return Ok(Some(realm));
            }
            match name.split_once('.') {
                Some((_, parent)) if !parent.is_empty() => name = parent,
                _ => return Ok(None),
            }
        }
    }

    /// The first of the host's domain and `realm_try_domains` parents that is a realm.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: DNS lookups change no state.
    async fn try_domains(&self, host: &str) -> Option<String> {
        let limit = self.config.libdefaults.realm_try_domains;
        if limit < 0_i32 {
            return None;
        }
        let locator = self.transport.locator(self.config);
        let mut candidate = host.split_once('.')?.1;
        let mut remaining = limit;
        while remaining >= 0_i32 && candidate.contains('.') {
            let realm = candidate.to_ascii_uppercase();
            if locator
                .locate(&realm, EndpointRole::Kdc, KdcProtocol::Auto)
                .await
                .is_ok_and(|found| !found.is_empty())
            {
                return Some(realm);
            }
            remaining = remaining.saturating_sub(1);
            candidate = candidate.split_once('.')?.1;
        }
        None
    }
}

/// `host` folded to lower case without a trailing dot (MIT `clean_hostname`), or
/// `None` when it is empty or longer than a DNS name.
fn clean(host: &str) -> Option<String> {
    let bare = host.strip_suffix('.').unwrap_or(host);
    (!bare.is_empty() && bare.len() <= MAX_HOST_BYTES).then(|| bare.to_ascii_lowercase())
}

/// Whether `name` looks like an IPv4 or IPv6 address (MIT `k5_is_numeric_address`,
/// `src/lib/krb5/os/hostrealm.c:230-251`).
fn is_numeric_address(name: &str) -> bool {
    let ipv4 = name
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'.')
        && name.bytes().filter(|byte| *byte == b'.').count() == 3;
    ipv4 || name.contains(':')
}

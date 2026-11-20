//! Hostname canonicalization for host-based service names (MIT `sn2princ.c`).
//!
//! `dns_canonicalize_hostname` selects DNS canonicalization (`true`), none
//! (`false`) or none first and DNS second (`fallback`); `rdns` adds a reverse
//! lookup of the address to the forward lookup; `qualify_shortname` gives the
//! domain suffix of a one-label name that DNS did not canonicalize.

use core::net::IpAddr;

use hickory_resolver::proto::rr;

use crate::{
    client::transport::Tokio,
    config::{Config, hostname::Canonicalization},
    discovery::records::dns_resolver,
    error::Client as Error,
};

/// The longest host name canonicalized: a DNS name.
const MAX_HOST_BYTES: usize = 253;

/// The suffix source for a one-label host name.
#[derive(Clone, Debug, Eq, PartialEq)]
enum Qualify {
    /// `qualify_shortname` is not set: no suffix.
    ///
    /// MIT falls back to the first search domain of the system's DNS
    /// configuration (`src/lib/krb5/os/sn2princ.c:62-74`); this crate does not
    /// read the system resolver configuration to name a service, so a suffix
    /// must be set explicitly.
    Unset,
    /// `qualify_shortname = ""`: qualification is disabled.
    Disabled,
    /// The domain suffix.
    Suffix(String),
}

/// The canonicalization rules of a profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalizationPolicy {
    /// `dns_canonicalize_hostname`.
    mode: Canonicalization,
    /// `rdns`.
    reverse: bool,
    /// `qualify_shortname`.
    qualify: Qualify,
}

impl CanonicalizationPolicy {
    /// The policy of `config`'s `[libdefaults]`.
    #[must_use]
    #[inline]
    pub fn from_config(config: &Config) -> Self {
        let defaults = &config.libdefaults;
        Self {
            mode: defaults.dns_canonicalize_hostname,
            reverse: defaults.rdns.is_enabled(),
            qualify: match defaults.qualify_shortname.as_deref() {
                None => Qualify::Unset,
                Some("") => Qualify::Disabled,
                Some(suffix) => Qualify::Suffix(suffix.to_owned()),
            },
        }
    }

    /// Whether each form of the host name is made with DNS, in the order to try
    /// them (MIT `k5_canonprinc`, `sn2princ.c:301-327`): `true` is DNS only,
    /// `false` none, and `fallback` none first, then DNS.
    #[must_use]
    #[inline]
    pub const fn uses_dns(&self) -> &'static [bool] {
        match self.mode {
            Canonicalization::Never => &[false],
            Canonicalization::Fallback => &[false, true],
            Canonicalization::Always => &[true],
        }
    }

    /// The host name `host` in its canonical shape without DNS: lower case, no
    /// trailing dot, and the `qualify_shortname` suffix on a one-label name.
    #[must_use]
    #[inline]
    pub fn expand_without_dns(&self, host: &str) -> String {
        self.finish(host, host)
    }

    /// The canonical host name of `host`, with DNS when `use_dns`.
    ///
    /// With DNS the forward lookup's canonical name replaces `host`, and with
    /// `rdns` the name of a reverse lookup of the first address replaces that. A
    /// lookup that fails leaves the name as it was (MIT ignores every lookup
    /// failure here, `sn2princ.c:107-128`). A name longer than a DNS name is
    /// never looked up.
    ///
    /// # Security
    ///
    /// The answer is DNS data: it names the service principal to ask a KDC for
    /// and authenticates nothing. `dns_canonicalize_hostname = false` removes the
    /// reliance on DNS.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DnsResolverConfig`] when the resolver of `transport` cannot
    /// be built; no other failure is reported.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: DNS lookups change no state.
    #[inline]
    pub async fn expand(
        &self,
        transport: &Tokio,
        host: &str,
        use_dns: bool,
    ) -> Result<String, Error> {
        if !use_dns || host.len() > MAX_HOST_BYTES {
            return Ok(self.expand_without_dns(host));
        }
        let resolver = dns_resolver(transport.dns_server())?;
        let mut canonical = host.to_owned();
        let mut address = host.parse::<IpAddr>().ok();
        if address.is_none()
            && let Ok(lookup) = resolver.lookup_ip(host).await
        {
            address = lookup.iter().next();
            if let Some(name) = lookup
                .as_lookup()
                .answers()
                .iter()
                .find(|record| matches!(record.data, rr::RData::A(_) | rr::RData::AAAA(_)))
                .map(|record| record.name.to_ascii())
            {
                canonical = name;
            }
        }
        if self.reverse
            && let Some(ip) = address
            && let Ok(reverse) = resolver.reverse_lookup(ip).await
            && let Some(name) = reverse.answers().iter().find_map(|record| {
                if let rr::RData::PTR(ptr) = &record.data {
                    Some(ptr.0.to_ascii())
                } else {
                    None
                }
            })
        {
            canonical = name;
        }
        Ok(self.finish(host, &canonical))
    }

    /// The distinct canonical names of `host` in the order to try them.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::expand`].
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: DNS lookups change no state.
    #[inline]
    pub async fn candidates(&self, transport: &Tokio, host: &str) -> Result<Vec<String>, Error> {
        let mut names: Vec<String> = Vec::new();
        for use_dns in self.uses_dns() {
            let name = self.expand(transport, host, *use_dns).await?;
            if !names.contains(&name) {
                names.push(name);
            }
        }
        Ok(names)
    }

    /// Qualify, fold and strip `canonical` (MIT `expand_hostname`, `sn2princ.c:130-144`).
    fn finish(&self, host: &str, canonical: &str) -> String {
        let mut name = match &self.qualify {
            Qualify::Suffix(suffix) if canonical == host && !host.contains('.') => {
                format!("{host}.{suffix}")
            }
            Qualify::Suffix(_) | Qualify::Unset | Qualify::Disabled => canonical.to_owned(),
        };
        name.make_ascii_lowercase();
        if name.ends_with('.') {
            name.truncate(name.len().saturating_sub(1));
        }
        name
    }
}

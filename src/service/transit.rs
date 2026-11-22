/// Caller-owned policy for unchecked cross-realm transit (RFC 4120 section 2.7).
///
/// Implementations must validate both endpoint realms and the complete encoded
/// path. Empty contents mean direct cross-realm transit, not same-realm use.
/// Unsupported encodings must be rejected unless the implementation understands
/// their semantics. This policy is called only when the KDC has not set
/// TRANSITED-POLICY-CHECKED and either the endpoint realms differ or the
/// transited path is nonempty: a same-realm ticket with a nonempty unchecked
/// path needs the same explicit approval.
///
/// The transited path is part of the encrypted ticket: only the acceptor that
/// decrypts the ticket sees it. A client that receives a service ticket from a
/// KDC cannot see the path and makes no claim about it.
pub trait TransitValidator: Debug + Send + Sync {
    /// Return whether this realm path is explicitly trusted by the application.
    fn accepts(
        &self,
        client_realm: &str,
        service_realm: &str,
        transited: &rasn_kerberos::TransitedEncoding,
    ) -> bool;
}

/// Explicit trust in exact DOMAIN-X500-COMPRESS paths between endpoint realms.
///
/// Active Directory does not set TRANSITED-POLICY-CHECKED (MS-KILE 3.1.5.4).
/// Attach this opt-in through [`Validator::with_transit_validator`]; the default
/// still rejects unchecked cross-realm tickets, as required by RFC 4120 §2.7.
/// Paths are matched byte-for-byte, not decoded or inferred from realm suffixes.
/// One policy holds any number of endpoint pairs, each with its own paths; a
/// pair never borrows the paths of another pair.
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct TransitPolicy {
    /// The trusted endpoint pairs, each with its complete paths.
    pairs: Vec<TrustedPair>,
}

/// One trusted endpoint pair of a [`TransitPolicy`].
#[derive(Clone, Debug)]
struct TrustedPair {
    /// Trusted client endpoint realm, compared case-sensitively.
    client_realm: String,
    /// Trusted service endpoint realm, compared case-sensitively.
    service_realm: String,
    /// Complete trusted DOMAIN-X500-COMPRESS encodings, including direct paths.
    paths: Vec<Vec<u8>>,
}

impl TransitPolicy {
    /// A policy that trusts no pair; add pairs with [`Self::and_direct`] and
    /// [`Self::and_domain_x500_paths`].
    #[must_use]
    #[inline]
    pub const fn new() -> Self {
        Self { pairs: Vec::new() }
    }

    /// Trust only a direct cross-realm ticket between the named endpoint realms.
    ///
    /// Requires encoding type 1 (DOMAIN-X500-COMPRESS) with empty contents.
    /// Empty endpoint names and all other encodings are rejected.
    #[must_use]
    #[inline]
    pub fn direct(client_realm: &str, service_realm: &str) -> Self {
        Self::new().and_direct(client_realm, service_realm)
    }

    /// Trust a caller-supplied allow-list of complete DOMAIN-X500-COMPRESS paths.
    ///
    /// Each entry is the exact RFC 4120 §3.3.3.2 encoded path, not an individual
    /// realm. Include an empty entry explicitly to permit direct transit. An
    /// empty allow-list rejects every unchecked path. Unknown encoding types
    /// are always rejected, even if their contents match an allowed entry.
    #[must_use]
    #[inline]
    pub fn domain_x500_paths<I, P>(client_realm: &str, service_realm: &str, paths: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: AsRef<[u8]>,
    {
        Self::new().and_domain_x500_paths(client_realm, service_realm, paths)
    }

    /// Also trust a direct cross-realm ticket between another endpoint pair.
    #[must_use]
    #[inline]
    pub fn and_direct(self, client_realm: &str, service_realm: &str) -> Self {
        self.and_domain_x500_paths(client_realm, service_realm, [b""])
    }

    /// Also trust complete DOMAIN-X500-COMPRESS paths between another endpoint
    /// pair, with the rules of [`Self::domain_x500_paths`].
    #[must_use]
    #[inline]
    pub fn and_domain_x500_paths<I, P>(
        mut self,
        client_realm: &str,
        service_realm: &str,
        paths: I,
    ) -> Self
    where
        I: IntoIterator<Item = P>,
        P: AsRef<[u8]>,
    {
        self.pairs.push(TrustedPair {
            client_realm: client_realm.to_owned(),
            service_realm: service_realm.to_owned(),
            paths: paths
                .into_iter()
                .map(|path| path.as_ref().to_vec())
                .collect(),
        });
        self
    }
}

impl TransitValidator for TransitPolicy {
    #[inline]
    fn accepts(
        &self,
        client_realm: &str,
        service_realm: &str,
        transited: &rasn_kerberos::TransitedEncoding,
    ) -> bool {
        transited.r#type == transited::DOMAIN_X500_COMPRESS
            && self.pairs.iter().any(|pair| {
                !pair.client_realm.is_empty()
                    && !pair.service_realm.is_empty()
                    && client_realm == pair.client_realm
                    && service_realm == pair.service_realm
                    && pair
                        .paths
                        .iter()
                        .any(|path| path.as_slice() == transited.contents.as_ref())
            })
    }
}

/// Transit validation from the profile's `[capaths]`: MIT 1.22.2
/// `krb5_check_transited_list` (`chk_trans.c:308-356`).
///
/// The DOMAIN-X500-COMPRESS path is decoded ([`transited::decode`]) and every
/// realm it names must lie on [`RealmPath::walk`] between the endpoint realms
/// before the service realm: the `[capaths]` path of the pair when the profile
/// has one, else (unless [`Self::configured_only`] is set) the hierarchical
/// path. An empty path (a direct cross-realm ticket) is admitted, as MIT does
/// (`rd_req_dec.c:606-610`). Other encodings, malformed or oversized paths and
/// same-realm tickets with a nonempty path are rejected.
///
/// [`Validator::from_default_keytab_name`] and [`Validator::from_default_keytab`]
/// attach the configured-only form when the profile has a `[capaths]` section.
///
/// # Security
///
/// The hierarchical fallback trusts every realm a hierarchy names between the
/// endpoints, as MIT does; [`Self::configured_only`] trusts only the pairs the
/// profile lists. The decoded path is bounded (see [`transited`]).
#[derive(Clone, Debug)]
pub struct CapathsTransit {
    /// The profile's `[capaths]` section.
    capaths: Capaths,
    /// Whether a pair without a `[capaths]` entry is refused.
    configured_only: bool,
}

impl CapathsTransit {
    /// Validate with the `[capaths]` of `config`, falling back to the hierarchy.
    #[must_use]
    #[inline]
    pub fn from_config(config: &Config) -> Self {
        Self {
            capaths: config.capaths.clone(),
            configured_only: false,
        }
    }

    /// Refuse a pair the profile's `[capaths]` does not list, instead of
    /// falling back to the realm hierarchy.
    #[must_use]
    #[inline]
    pub const fn configured_only(mut self) -> Self {
        self.configured_only = true;
        self
    }
}

impl TransitValidator for CapathsTransit {
    #[inline]
    fn accepts(
        &self,
        client_realm: &str,
        service_realm: &str,
        transited: &rasn_kerberos::TransitedEncoding,
    ) -> bool {
        if transited.r#type != transited::DOMAIN_X500_COMPRESS {
            return false;
        }
        let Ok(realms) = transited::decode(&transited.contents, client_realm, service_realm) else {
            return false;
        };
        let path = if self.configured_only {
            RealmPath::configured(&self.capaths, client_realm, service_realm)
                .ok()
                .flatten()
        } else {
            RealmPath::walk(&self.capaths, client_realm, service_realm).ok()
        };
        path.is_some_and(|walked| walked.admits_transited(&realms))
    }
}

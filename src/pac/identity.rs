// A mutable, serializable identity attribute set (gokrb5 `Credentials` attributes), included
// into `pac`.
//
// gokrb5 `credentials.Credentials` keeps a map of attributes (`AddAttribute`, `RemoveAttribute`,
// `GetAttribute`, `Marshal`; `v8/credentials/credentials.go:250-386`) and stores the AD
// credentials from the PAC under one of them. The set here has typed names and string values,
// derives from a verified PAC only, and serializes with `serde` (a JSON object of name to list of
// values). It never holds a credential, an NTLM hash or a session key.

/// A mutable set of named, multi-valued identity attributes.
///
/// [`IdentityAttributes::from_verified`] fills it from a [`Verified`] PAC, so its attributes
/// describe a client the KDC vouched for to the degree [`Verified::checks`] says; a set built or
/// edited by hand carries no such claim. Names are case-sensitive; values keep insertion order.
///
/// The attributes `from_verified` writes:
///
/// | Name | Values |
/// |---|---|
/// | `pac:client-name` | the client info name |
/// | `pac:verified` | the checks that passed: `server`, `kdc`, `ticket`, `full`, `client` |
/// | `ad:effective-name`, `ad:full-name`, `ad:logon-domain-name`, `ad:logon-server` | from `KERB_VALIDATION_INFO` |
/// | `ad:logon-domain-sid` | the logon domain SID |
/// | `ad:user-id`, `ad:primary-group-id` | the RIDs, decimal |
/// | `ad:group-sid` | every group SID, one value each |
/// | `upn:name`, `upn:dns-domain` | from the UPN/DNS info |
/// | `claim:<id>` | the values of the client claim `<id>`, one value each |
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
#[non_exhaustive]
pub struct IdentityAttributes {
    /// Attribute name to values.
    values: BTreeMap<String, Vec<String>>,
}

impl IdentityAttributes {
    /// An empty set.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            values: BTreeMap::new(),
        }
    }

    /// The identity attributes of a verified PAC (the table in the type documentation).
    #[inline]
    #[must_use]
    pub fn from_verified(pac: &Verified) -> Self {
        let mut set = Self::new();
        let checks = pac.checks();
        for (name, passed) in [
            ("server", checks.server()),
            ("kdc", checks.kdc()),
            ("ticket", checks.ticket()),
            ("full", checks.full()),
            ("client", checks.client()),
        ] {
            if passed {
                set.add("pac:verified", name);
            }
        }
        if let Some(info) = pac.client_info() {
            set.add("pac:client-name", &info.name);
        }
        if let Some(credentials) = pac.ad_credentials() {
            set.add("ad:effective-name", &credentials.effective_name);
            set.add("ad:full-name", &credentials.full_name);
            set.add("ad:logon-domain-name", &credentials.logon_domain_name);
            set.add("ad:logon-server", &credentials.logon_server);
            set.add("ad:user-id", &credentials.user_id.to_string());
            set.add(
                "ad:primary-group-id",
                &credentials.primary_group_id.to_string(),
            );
            if let Some(domain) = &credentials.logon_domain_id {
                set.add("ad:logon-domain-sid", domain);
            }
            for sid in &credentials.group_membership_sids {
                set.add("ad:group-sid", sid);
            }
        }
        if let Some(upn) = pac.upn_dns_info() {
            set.add("upn:name", &upn.upn);
            set.add("upn:dns-domain", &upn.dns_domain);
        }
        if let Some(claims) = pac.client_claims_info() {
            for entry in claims
                .claims_set
                .claims_arrays
                .iter()
                .flat_map(|array| array.claim_entries.iter())
            {
                let name = format!("claim:{}", entry.id);
                match &entry.values {
                    ClaimValues::Int64(values) => {
                        for value in values {
                            set.add(&name, &value.to_string());
                        }
                    }
                    ClaimValues::UInt64(values) => {
                        for value in values {
                            set.add(&name, &value.to_string());
                        }
                    }
                    ClaimValues::String(values) => {
                        for value in values {
                            set.add(&name, value);
                        }
                    }
                    ClaimValues::Boolean(values) => {
                        for value in values {
                            set.add(&name, &value.to_string());
                        }
                    }
                }
            }
        }
        set
    }

    /// Append a value to an attribute, creating it.
    #[inline]
    pub fn add(&mut self, name: &str, value: &str) {
        self.values
            .entry(name.to_owned())
            .or_default()
            .push(value.to_owned());
    }

    /// Replace the values of an attribute; an empty list removes it.
    #[inline]
    pub fn set(&mut self, name: &str, values: Vec<String>) {
        if values.is_empty() {
            drop(self.values.remove(name));
        } else {
            drop(self.values.insert(name.to_owned(), values));
        }
    }

    /// Remove an attribute; `true` when it was present.
    #[inline]
    pub fn remove(&mut self, name: &str) -> bool {
        self.values.remove(name).is_some()
    }

    /// The values of an attribute.
    #[inline]
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&[String]> {
        self.values.get(name).map(Vec::as_slice)
    }

    /// The attribute names, in sorted order.
    #[inline]
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.values.keys().map(String::as_str)
    }

    /// The number of attributes.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Whether the set holds no attribute.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

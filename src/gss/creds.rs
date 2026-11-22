/// What a credential may be used for (`gss_cred_usage_t`).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum CredentialUsage {
    /// `GSS_C_INITIATE`: start contexts.
    Initiate,
    /// `GSS_C_ACCEPT`: accept contexts.
    Accept,
    /// `GSS_C_BOTH`: both.
    Both,
}

/// The key-value credential store of `gss_acquire_cred_from`.
///
/// It is also the target of `gss_store_cred_into` (MIT `doc/appdev/gssapi.rst`,
/// "Credential store extensions"); the keys are `ccache`, `client_keytab`,
/// `keytab`, `rcache` and `password`.
///
/// The password is held in a zeroizing owner and never shown by `Debug`.
#[derive(Clone, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct CredStore {
    /// `ccache`: the credential cache name.
    ccache: Option<String>,
    /// `client_keytab`: the client keytab name.
    client_keytab: Option<String>,
    /// `keytab`: the acceptor keytab name.
    keytab: Option<String>,
    /// `rcache`: the replay cache name.
    rcache: Option<String>,
    /// `password`: the initiator's password.
    password: Option<Zeroizing<String>>,
}

impl fmt::Debug for CredStore {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredStore")
            .field("ccache", &self.ccache)
            .field("client_keytab", &self.client_keytab)
            .field("keytab", &self.keytab)
            .field("rcache", &self.rcache)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl CredStore {
    /// An empty store.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add the pair `key = value`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedCredStoreKey`] for a key other than `ccache`,
    /// `client_keytab`, `keytab`, `rcache` and `password` (`verify` and the
    /// impersonation keys come with their extensions), and
    /// [`Error::DuplicateCredStoreKey`] for a key given twice.
    #[inline]
    pub fn with(mut self, key: &str, value: &str) -> Result<Self, Error> {
        let slot = match key {
            "ccache" => &mut self.ccache,
            "client_keytab" => &mut self.client_keytab,
            "keytab" => &mut self.keytab,
            "rcache" => &mut self.rcache,
            "password" => {
                if self.password.is_some() {
                    return Err(Error::DuplicateCredStoreKey(key.to_owned()));
                }
                self.password = Some(Zeroizing::new(value.to_owned()));
                return Ok(self);
            }
            _ => return Err(Error::UnsupportedCredStoreKey(key.to_owned())),
        };
        if slot.is_some() {
            return Err(Error::DuplicateCredStoreKey(key.to_owned()));
        }
        *slot = Some(value.to_owned());
        Ok(self)
    }
}

/// A GSS credential of the Kerberos mechanism: initiator tickets (or the
/// client keytab or password that acquires them) and acceptor keys.
///
/// Every key, ticket and password it holds is erased when it is dropped and is
/// never shown by `Debug`.
#[non_exhaustive]
pub struct Credential {
    /// The credential's name: the cache's client, the desired initiator or the
    /// desired acceptor.
    name: Option<Name>,
    /// What the credential may be used for.
    usage: CredentialUsage,
    /// The initiator's tickets.
    cache: Option<CCache>,
    /// The client keytab that acquires initial tickets.
    client_keytab: Option<Keytab>,
    /// The password that acquires initial tickets.
    password: Option<Zeroizing<Vec<u8>>>,
    /// The acceptor's keys.
    keytab: Option<Keytab>,
    /// The acceptor's replay cache.
    replay: Option<SharedReplayCache>,
}

impl fmt::Debug for Credential {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credential")
            .field("name", &self.name)
            .field("usage", &self.usage)
            .field(
                "tickets",
                &self.cache.as_ref().map(|cache| cache.credentials().len()),
            )
            .field("client_keytab", &self.client_keytab.is_some())
            .field("password", &self.password.is_some())
            .field(
                "keytab_entries",
                &self.keytab.as_ref().map(|keys| keys.entries().len()),
            )
            .finish_non_exhaustive()
    }
}

impl Credential {
    /// An initiator credential of the tickets in `cache`, named for its client.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoCredential`] for a cache without a client.
    #[inline]
    pub fn from_ccache(cache: CCache) -> Result<Self, Error> {
        cred::from_ccache(cache)
    }

    /// An initiator credential holding one service ticket.
    #[inline]
    #[must_use]
    pub fn from_service_ticket(ticket: &TgsRepSession) -> Self {
        cred::from_service_ticket(ticket)
    }

    /// An acceptor credential of the keys in `keytab`, accepting any principal
    /// it holds a key for until [`Self::with_name`] names one.
    #[inline]
    #[must_use]
    pub const fn from_keytab(keytab: Keytab) -> Self {
        Self {
            name: None,
            usage: CredentialUsage::Accept,
            cache: None,
            client_keytab: None,
            password: None,
            keytab: Some(keytab),
            replay: None,
        }
    }

    /// Name the credential: an acceptor accepts only tickets for `name`, an
    /// initiator must be `name`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoCredential`] when the keytab holds no key for `name`
    /// (MIT `check_keytab`) or the initiator is another principal.
    #[inline]
    pub fn with_name(self, name: Name) -> Result<Self, Error> {
        cred::with_name(self, name)
    }

    /// `gss_acquire_cred_from`: acquire a credential from the store's explicit
    /// names, with no ambient default.
    ///
    /// An initiator credential comes from `ccache`; failing that, `client_keytab`
    /// or `password` with `desired_name` make one that acquires its tickets when
    /// used. An acceptor credential comes from `keytab`; `rcache` names an
    /// in-memory replay cache (`memory:<name>`), since the persistent replay
    /// caches are not implemented and replay detection cannot be switched off.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoCredential`] when the store names nothing usable or
    /// the desired name does not match, [`Error::UnsupportedReplayCache`] for
    /// another `rcache`, and the errors of loading the named cache or keytab.
    #[inline]
    pub fn acquire_cred_from(
        desired_name: Option<&Name>,
        usage: CredentialUsage,
        store: &CredStore,
    ) -> Result<Self, Error> {
        cred::acquire_from(desired_name, usage, store)
    }

    /// `gss_acquire_cred`: acquire a credential from the default stores.
    ///
    /// # Ambient input
    /// Reads `KRB5CCNAME` before the configured `default_ccache_name`,
    /// `KRB5_CLIENT_KTNAME` before `default_client_keytab_name` and
    /// `KRB5_KTNAME` before `default_keytab_name`; the configured names expand
    /// `TMPDIR`, `TEMP`, `APPDATA` and process identity. Use
    /// [`Self::acquire_cred_from`] with literal names, which `CCache::load_name`,
    /// `Keytab::load_name` and `with_keytab_name` also take, to avoid this
    /// discovery.
    ///
    /// In a set-uid or set-gid process the variables named here are ignored, as MIT 1.22.2
    /// ignores them (`secure_getenv`); see the secure-environment decision of
    /// `docs/security-policy.md`.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::acquire_cred_from`] and of reading the
    /// default names.
    #[cfg(feature = "tokio")]
    #[inline]
    pub fn acquire_cred(
        desired_name: Option<&Name>,
        usage: CredentialUsage,
        config: &Config,
    ) -> Result<Self, Error> {
        cred::acquire_default(desired_name, usage, config)
    }

    /// Acquire a service ticket for `target` from the KDC and keep it.
    ///
    /// The ticket comes through the cache's TGT, the client keytab or the
    /// password, and is kept in this credential's cache; a client keytab or
    /// password credential acquires its TGT first.
    ///
    /// # Errors
    ///
    /// Returns [`Error::WrongCredentialUsage`] for an acceptor credential,
    /// [`Error::NoCredential`] without a ticket source, [`Error::BadName`] for
    /// a host-based target without a host, and the errors of the exchanges.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: the ticket is kept only after its exchange completes.
    #[cfg(feature = "tokio")]
    #[inline]
    pub async fn acquire_service_ticket(
        &mut self,
        target: &Name,
        config: &Config,
    ) -> Result<(), Error> {
        cred::acquire_service_ticket(self, target, config).await
    }

    /// `gss_store_cred_into`: store the initiator tickets into the store's `ccache`.
    ///
    /// Without `overwrite`, a cache that already holds tickets is not replaced
    /// (MIT `GSS_S_DUPLICATE_ELEMENT`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoCredential`] without initiator tickets or a `ccache`
    /// key, [`Error::DuplicateElement`] for a cache that holds tickets, and the
    /// errors of writing the cache.
    #[inline]
    pub fn store_cred_into(&self, store: &CredStore, overwrite: bool) -> Result<(), Error> {
        cred::store_into(self, store, overwrite)
    }

    /// `gss_inquire_cred`: the credential's name, usage, lifetime and mechanism.
    #[inline]
    #[must_use]
    pub fn inquire(&self) -> CredentialInquiry {
        cred::inquire(self)
    }

    /// The initiator's credential cache.
    #[inline]
    #[must_use]
    pub const fn ccache(&self) -> Option<&CCache> {
        self.cache.as_ref()
    }

    /// The acceptor's keytab.
    #[inline]
    #[must_use]
    pub const fn keytab(&self) -> Option<&Keytab> {
        self.keytab.as_ref()
    }
}

/// What `gss_inquire_cred` reports about a [`Credential`].
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct CredentialInquiry {
    /// The credential's name.
    name: Option<Name>,
    /// What it may be used for.
    usage: CredentialUsage,
    /// When its TGT, or its first ticket, expires.
    expires: Option<SystemTime>,
    /// Its mechanisms: krb5.
    mechanisms: Vec<ObjectIdentifier>,
}

impl CredentialInquiry {
    /// The credential's name.
    #[inline]
    #[must_use]
    pub const fn name(&self) -> Option<&Name> {
        self.name.as_ref()
    }

    /// What it may be used for.
    #[inline]
    #[must_use]
    pub const fn usage(&self) -> CredentialUsage {
        self.usage
    }

    /// When its TGT, or its first ticket, expires; `None` when it holds no
    /// ticket yet.
    #[inline]
    #[must_use]
    pub const fn expires(&self) -> Option<SystemTime> {
        self.expires
    }

    /// Its mechanisms.
    #[inline]
    #[must_use]
    pub fn mechanisms(&self) -> &[ObjectIdentifier] {
        &self.mechanisms
    }
}

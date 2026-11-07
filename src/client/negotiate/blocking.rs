//! Synchronous Negotiate operations.

use super::{
    BlockingClient, BlockingRuntime, ChangePasswordResult, Client, Config, Error, InitiatorContext,
    InitiatorContextOptions, Keytab, Principal, RequestOptions,
};

impl BlockingClient {
    /// Wrap an existing Negotiate client.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BlockingRuntimeUnavailable`] inside an entered Tokio runtime,
    /// or an I/O error when the blocking runtime cannot be created.
    #[inline]
    pub fn new(client: Client) -> Result<Self, Error> {
        Ok(Self {
            runtime: BlockingRuntime::new()?,
            client,
        })
    }

    /// Create a password-backed blocking Negotiate client.
    ///
    /// # Errors
    ///
    /// Returns the runtime errors of [`Self::new`].
    #[inline]
    pub fn with_password<P>(config: Config, client: Principal, password: P) -> Result<Self, Error>
    where
        P: Into<Vec<u8>>,
    {
        Self::new(Client::with_password(config, client, password))
    }

    /// Create a keytab-backed blocking Negotiate client.
    ///
    /// # Errors
    ///
    /// Returns the runtime errors of [`Self::new`].
    #[inline]
    pub fn with_keytab(config: Config, client: Principal, keytab: Keytab) -> Result<Self, Error> {
        Self::new(Client::with_keytab(config, client, keytab))
    }

    /// Create a keytab-backed blocking Negotiate client by loading a file-backed keytab name.
    ///
    /// # Errors
    ///
    /// Returns an error when the keytab name selects an unsupported keytab store
    /// or the keytab file cannot be read or parsed.
    /// Returns the runtime errors of [`Self::new`].
    #[inline]
    pub fn with_keytab_name<P>(
        config: Config,
        client: Principal,
        keytab_name: P,
    ) -> Result<Self, Error>
    where
        P: AsRef<str>,
    {
        Self::new(Client::with_keytab_name(config, client, keytab_name)?)
    }

    /// Create a cache-only blocking Negotiate client by loading a ccache name.
    ///
    /// # Errors
    ///
    /// Returns an error when the cache name selects an unsupported credential
    /// cache store or the cache cannot be read or parsed.
    /// Returns the runtime errors of [`Self::new`].
    #[inline]
    pub fn from_ccache_name<P>(config: Config, cache_name: P) -> Result<Self, Error>
    where
        P: AsRef<str>,
    {
        Self::new(Client::from_ccache_name(config, cache_name)?)
    }

    /// Create a cache-only blocking Negotiate client from the default credential cache.
    ///
    /// # Ambient input
    /// Reads `KRB5CCNAME` before the configured fallback; invalid Unicode is an
    /// expansion error when `TMPDIR`, `TEMP` or `APPDATA` supplies invalid text;
    /// process identity is read for identity tokens. An invalid `KRB5CCNAME` is an
    /// error. Use [`Self::from_ccache_name`] for an explicit cache name.
    ///
    /// # Errors
    ///
    /// Returns an error when `KRB5CCNAME` is set but not valid Unicode, when no
    /// default cache name is configured, or when the selected cache cannot be
    /// read or parsed.
    /// Returns the runtime errors of [`Self::new`].
    #[inline]
    pub fn from_default_ccache(config: Config) -> Result<Self, Error> {
        Self::new(Client::from_default_ccache(config)?)
    }

    /// Create a cache-only blocking Negotiate client by loading the cache named by `KRB5CCNAME`.
    ///
    /// # Ambient input
    /// Reads `KRB5CCNAME`; unset or non-Unicode values are errors. Use
    /// [`Self::from_ccache_name`] for an explicit cache name.
    ///
    /// # Errors
    ///
    /// Returns an error when `KRB5CCNAME` is unset or not valid Unicode, or when
    /// the cache it names cannot be read or parsed.
    /// Returns the runtime errors of [`Self::new`].
    #[inline]
    pub fn from_ccache_env(config: Config) -> Result<Self, Error> {
        Self::new(Client::from_ccache_env(config)?)
    }

    /// Borrow the wrapped async client.
    #[inline]
    pub const fn client(&self) -> &Client {
        &self.client
    }

    /// Mutably borrow the wrapped async client.
    #[inline]
    pub const fn client_mut(&mut self) -> &mut Client {
        &mut self.client
    }

    /// Build an HTTP `Authorization` header for a Kerberos service principal.
    ///
    /// # Errors
    ///
    /// Returns an error when a TGT or service ticket for `service` cannot be
    /// obtained from the cache or the KDC, or when the AP-REQ or SPNEGO token
    /// cannot be built.
    /// Returns [`Error::BlockingRuntimeUnavailable`] inside an entered Tokio runtime.
    #[inline]
    pub fn authorization_header(&mut self, service: Principal) -> Result<String, Error> {
        Ok(self.authorization_context(service)?.header.to_string())
    }

    /// Build an HTTP `Authorization` header for a host-based service.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPrincipalName`] when the service or host name is
    /// empty, and otherwise the errors of obtaining a service ticket for the
    /// host-based principal or building its token.
    /// Returns [`Error::BlockingRuntimeUnavailable`] inside an entered Tokio runtime.
    #[inline]
    pub fn authorization_header_for_host<P, Q>(
        &mut self,
        service: P,
        host: Q,
    ) -> Result<String, Error>
    where
        P: AsRef<str>,
        Q: AsRef<str>,
    {
        Ok(self
            .authorization_context_for_host(service, host)?
            .header
            .to_string())
    }

    /// Build a SPNEGO initiator context for a Kerberos service principal.
    ///
    /// # Errors
    ///
    /// Returns an error when a TGT or service ticket for `service` cannot be
    /// obtained from the cache or the KDC, or when the AP-REQ or SPNEGO token
    /// cannot be built.
    /// Returns [`Error::BlockingRuntimeUnavailable`] inside an entered Tokio runtime.
    #[inline]
    pub fn authorization_context(&mut self, service: Principal) -> Result<InitiatorContext, Error> {
        self.runtime
            .block_on(self.client.authorization_context(service))
    }

    /// Build a SPNEGO initiator context with explicit initiator options.
    ///
    /// # Errors
    ///
    /// Returns an error when a TGT or service ticket for `service` cannot be
    /// obtained from the cache or the KDC, or when the AP-REQ or SPNEGO token
    /// cannot be built.
    /// Returns [`Error::BlockingRuntimeUnavailable`] inside an entered Tokio runtime.
    #[inline]
    pub fn authorization_context_with_options(
        &mut self,
        service: Principal,
        options: InitiatorContextOptions,
    ) -> Result<InitiatorContext, Error> {
        self.runtime.block_on(
            self.client
                .authorization_context_with_options(service, options),
        )
    }

    /// Build a SPNEGO initiator context for a host-based service.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPrincipalName`] when the service or host name is
    /// empty, and otherwise the errors of obtaining a service ticket for the
    /// host-based principal or building its token.
    /// Returns [`Error::BlockingRuntimeUnavailable`] inside an entered Tokio runtime.
    #[inline]
    pub fn authorization_context_for_host<P, Q>(
        &mut self,
        service: P,
        host: Q,
    ) -> Result<InitiatorContext, Error>
    where
        P: AsRef<str>,
        Q: AsRef<str>,
    {
        self.runtime
            .block_on(self.client.authorization_context_for_host(service, host))
    }

    /// Change this client's password using generated timestamp and sequence metadata.
    ///
    /// # Errors
    ///
    /// Returns an error when reading the clock or the random source fails, when
    /// the `kadmin/changepw` service ticket cannot be obtained, when the request
    /// cannot be built or exchanged with a kpasswd server, when the reply fails
    /// verification or decryption, or when the server reports a non-success
    /// result code.
    /// Returns [`Error::BlockingRuntimeUnavailable`] inside an entered Tokio runtime.
    #[inline]
    pub fn change_password(
        &mut self,
        new_password: super::Password,
        sender_address: rasn_kerberos::HostAddress,
    ) -> Result<ChangePasswordResult, Error> {
        self.runtime
            .block_on(self.client.change_password(new_password, sender_address))
    }

    /// Change the given target principal's password using generated timestamp and
    /// sequence metadata.
    ///
    /// # Errors
    ///
    /// Returns an error when reading the clock or the random source fails, when
    /// the `kadmin/changepw` service ticket cannot be obtained, when the request
    /// cannot be built or exchanged with a kpasswd server, when the reply fails
    /// verification or decryption, or when the server reports a non-success
    /// result code.
    /// Returns [`Error::BlockingRuntimeUnavailable`] inside an entered Tokio runtime.
    #[inline]
    pub fn change_password_for(
        &mut self,
        target: Principal,
        new_password: super::Password,
        sender_address: rasn_kerberos::HostAddress,
    ) -> Result<ChangePasswordResult, Error> {
        self.runtime.block_on(
            self.client
                .change_password_for(target, new_password, sender_address),
        )
    }

    /// Change this client's password using explicit kpasswd request metadata.
    ///
    /// # Errors
    ///
    /// Returns an error when the `kadmin/changepw` service ticket cannot be
    /// obtained, when the request cannot be built or exchanged with a kpasswd
    /// server, when the reply fails verification or decryption, or when the
    /// server reports a non-success result code.
    /// Returns [`Error::BlockingRuntimeUnavailable`] inside an entered Tokio runtime.
    #[inline]
    pub fn change_password_with_options(
        &mut self,
        new_password: super::Password,
        options: RequestOptions,
    ) -> Result<ChangePasswordResult, Error> {
        self.runtime.block_on(
            self.client
                .change_password_with_options(new_password, options),
        )
    }

    /// Change the given target principal's password using explicit kpasswd
    /// request metadata.
    ///
    /// # Errors
    ///
    /// Returns an error when the `kadmin/changepw` service ticket cannot be
    /// obtained, when the request cannot be built or exchanged with a kpasswd
    /// server, when the reply fails verification or decryption, or when the
    /// server reports a non-success result code.
    /// Returns [`Error::BlockingRuntimeUnavailable`] inside an entered Tokio runtime.
    #[inline]
    pub fn change_password_for_with_options(
        &mut self,
        target: Principal,
        new_password: super::Password,
        options: RequestOptions,
    ) -> Result<ChangePasswordResult, Error> {
        self.runtime
            .block_on(
                self.client
                    .change_password_for_with_options(target, new_password, options),
            )
    }
}

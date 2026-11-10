use alloc::fmt;

/// Synchronous constructors and operations for the blocking wrapper.
mod blocking;
/// Guarded execution and nonblocking destruction of the owned runtime.
mod runtime;

use runtime::BlockingRuntime;

use super::{Error, KdcProtocol, Password, Principal, RequestOptions, Tokio};
use crate::{
    config::Config,
    kadmin::ChangePasswordResult,
    keytab::Keytab,
    spnego::{InitiatorContext, InitiatorContextOptions},
};

/// Small client API for HTTP Negotiate/SPNEGO initiator headers.
///
/// This wrapper keeps the stable HTTP-Negotiate surface narrow while reusing
/// [`Tokio`] for ticket acquisition, cache reuse, and SPNEGO token
/// construction. Advanced Kerberos flows remain available on `Tokio`.
#[derive(Clone, Eq, PartialEq)]
pub struct Client {
    /// High-level client that acquires tickets and builds tokens.
    inner: Tokio,
}

impl fmt::Debug for Client {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { inner } = self;
        f.debug_struct("Client").field("inner", inner).finish()
    }
}

impl Client {
    #[must_use]
    /// Wrap an existing high-level Tokio client.
    #[inline]
    pub const fn from_tokio_client(client: Tokio) -> Self {
        Self { inner: client }
    }

    /// Create a password-backed Negotiate client using automatic UDP/TCP KDC transport.
    ///
    /// # Security
    ///
    /// Borrowed inputs are copied; the caller remains responsible for erasing the original and
    /// any copies; pass an owned `String`/`Vec<u8>` to transfer the allocation.
    #[inline]
    pub fn with_password<P>(config: Config, client: Principal, password: P) -> Self
    where
        P: Into<Vec<u8>>,
    {
        Self::from_tokio_client(Tokio::with_password(
            config,
            KdcProtocol::Auto,
            client,
            password,
        ))
    }

    #[must_use]
    /// Create a keytab-backed Negotiate client using automatic UDP/TCP KDC transport.
    #[inline]
    pub const fn with_keytab(config: Config, client: Principal, keytab: Keytab) -> Self {
        Self::from_tokio_client(Tokio::with_keytab(
            config,
            KdcProtocol::Auto,
            client,
            keytab,
        ))
    }

    /// Create a keytab-backed Negotiate client by loading a file-backed keytab name.
    ///
    /// # Errors
    ///
    /// Returns an error when the keytab name selects an unsupported keytab store
    /// or the keytab file cannot be read or parsed.
    #[inline]
    pub fn with_keytab_name<P>(
        config: Config,
        client: Principal,
        keytab_name: P,
    ) -> Result<Self, Error>
    where
        P: AsRef<str>,
    {
        Ok(Self::from_tokio_client(Tokio::with_keytab_name(
            config,
            KdcProtocol::Auto,
            client,
            keytab_name,
        )?))
    }

    /// Create a cache-only Negotiate client by loading a ccache name.
    ///
    /// # Errors
    ///
    /// Returns an error when the cache name selects an unsupported credential
    /// cache store or the cache cannot be read or parsed.
    #[inline]
    pub fn from_ccache_name<P>(config: Config, cache_name: P) -> Result<Self, Error>
    where
        P: AsRef<str>,
    {
        Ok(Self::from_tokio_client(Tokio::from_ccache_name(
            config,
            KdcProtocol::Auto,
            cache_name,
        )?))
    }

    /// Create a cache-only Negotiate client from the default credential cache.
    ///
    /// # Ambient input
    /// Reads `KRB5CCNAME` before the configured fallback; invalid Unicode is an
    /// expansion error when `TMPDIR`, `TEMP` or `APPDATA` supplies invalid text;
    /// process identity is read for identity tokens. An invalid `KRB5CCNAME` is an
    /// error. Use [`Self::from_ccache_name`] for an explicit cache name.
    ///
    /// `KRB5CCNAME` takes precedence when set. Otherwise this falls back to
    /// `config.libdefaults.default_ccache_name`.
    ///
    /// # Errors
    ///
    /// Returns an error when `KRB5CCNAME` is set but not valid Unicode, when no
    /// default cache name is configured, or when the selected cache cannot be
    /// read or parsed.
    #[inline]
    pub fn from_default_ccache(config: Config) -> Result<Self, Error> {
        Ok(Self::from_tokio_client(Tokio::from_default_ccache(
            config,
            KdcProtocol::Auto,
        )?))
    }

    /// Create a cache-only Negotiate client by loading the cache named by `KRB5CCNAME`.
    ///
    /// # Ambient input
    /// Reads `KRB5CCNAME`; unset or non-Unicode values are errors. Use
    /// [`Self::from_ccache_name`] for an explicit cache name.
    ///
    /// # Errors
    ///
    /// Returns an error when `KRB5CCNAME` is unset or not valid Unicode, or when
    /// the cache it names cannot be read or parsed.
    #[inline]
    pub fn from_ccache_env(config: Config) -> Result<Self, Error> {
        Ok(Self::from_tokio_client(Tokio::from_ccache_env(
            config,
            KdcProtocol::Auto,
        )?))
    }

    #[must_use]
    /// Borrow the wrapped `Tokio`.
    #[inline]
    pub const fn inner(&self) -> &Tokio {
        &self.inner
    }

    /// Mutably borrow the wrapped `Tokio`.
    #[inline]
    pub const fn inner_mut(&mut self) -> &mut Tokio {
        &mut self.inner
    }

    #[must_use]
    /// Consume this wrapper and return the wrapped `Tokio`.
    #[inline]
    pub fn into_inner(self) -> Tokio {
        self.inner
    }

    /// Build an HTTP `Authorization` header for a Kerberos service principal.
    ///
    /// # Errors
    ///
    /// Returns an error when a TGT or service ticket for `service` cannot be
    /// obtained from the cache or the KDC, or when the AP-REQ or SPNEGO token
    /// cannot be built.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: a service ticket is cached only after its exchange completes,
    /// so dropping the future leaves the client's caches consistent and the call
    /// can be repeated.
    #[inline]
    pub async fn authorization_header(&mut self, service: Principal) -> Result<String, Error> {
        Ok(self
            .authorization_context(service)
            .await?
            .header_ref()
            .to_owned())
    }

    /// Build an HTTP `Authorization` header for a host-based service.
    ///
    /// The service realm is left empty so `Tokio` can resolve it from
    /// `[domain_realm]` or fall back to the client realm.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPrincipalName`] when the service or host name is
    /// empty, and otherwise the errors of obtaining a service ticket for the
    /// host-based principal or building its token.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: a service ticket is cached only after its exchange completes,
    /// so dropping the future leaves the client's caches consistent and the call
    /// can be repeated.
    #[inline]
    pub async fn authorization_header_for_host<P, Q>(
        &mut self,
        service: P,
        host: Q,
    ) -> Result<String, Error>
    where
        P: AsRef<str>,
        Q: AsRef<str>,
    {
        Ok(self
            .authorization_context_for_host(service, host)
            .await?
            .header_ref()
            .to_owned())
    }

    /// Build a SPNEGO initiator context for a Kerberos service principal.
    ///
    /// # Errors
    ///
    /// Returns an error when a TGT or service ticket for `service` cannot be
    /// obtained from the cache or the KDC, or when the AP-REQ or SPNEGO token
    /// cannot be built.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: a service ticket is cached only after its exchange completes,
    /// so dropping the future leaves the client's caches consistent and the call
    /// can be repeated.
    #[inline]
    pub async fn authorization_context(
        &mut self,
        service: Principal,
    ) -> Result<InitiatorContext, Error> {
        self.inner.spnego_context(service).await
    }

    /// Build a SPNEGO initiator context with explicit initiator options.
    ///
    /// # Errors
    ///
    /// Returns an error when a TGT or service ticket for `service` cannot be
    /// obtained from the cache or the KDC, or when the AP-REQ or SPNEGO token
    /// cannot be built.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: a service ticket is cached only after its exchange completes,
    /// so dropping the future leaves the client's caches consistent and the call
    /// can be repeated.
    #[inline]
    pub async fn authorization_context_with_options(
        &mut self,
        service: Principal,
        options: InitiatorContextOptions,
    ) -> Result<InitiatorContext, Error> {
        self.inner
            .spnego_context_with_options(service, options)
            .await
    }

    /// Build a SPNEGO initiator context for a host-based service.
    ///
    /// The service realm is left empty so `Tokio` can resolve it from
    /// `[domain_realm]` or fall back to the client realm.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPrincipalName`] when the service or host name is
    /// empty, and otherwise the errors of obtaining a service ticket for the
    /// host-based principal or building its token.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: a service ticket is cached only after its exchange completes,
    /// so dropping the future leaves the client's caches consistent and the call
    /// can be repeated.
    #[inline]
    pub async fn authorization_context_for_host<P, Q>(
        &mut self,
        service: P,
        host: Q,
    ) -> Result<InitiatorContext, Error>
    where
        P: AsRef<str>,
        Q: AsRef<str>,
    {
        self.authorization_context(Principal::host_based_service(service, host)?)
            .await
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
    ///
    /// # Cancel safety
    ///
    /// NOT cancel-safe: this mutates credentials on the KDC. Dropping the future
    /// after the kpasswd request is sent does not roll the server back, so the
    /// password may or may not have changed; treat the outcome as unknown and
    /// verify it (for example with a fresh login) before retrying.
    #[inline]
    pub async fn change_password(
        &mut self,
        new_password: Password,
        sender_address: rasn_kerberos::HostAddress,
    ) -> Result<ChangePasswordResult, Error> {
        self.inner
            .change_password(new_password, sender_address)
            .await
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
    ///
    /// # Cancel safety
    ///
    /// NOT cancel-safe: this mutates credentials on the KDC. Dropping the future
    /// after the kpasswd request is sent does not roll the server back, so the
    /// password may or may not have changed; treat the outcome as unknown and
    /// verify it (for example with a fresh login) before retrying.
    #[inline]
    pub async fn change_password_for(
        &mut self,
        target: Principal,
        new_password: Password,
        sender_address: rasn_kerberos::HostAddress,
    ) -> Result<ChangePasswordResult, Error> {
        self.inner
            .change_password_for(target, new_password, sender_address)
            .await
    }

    /// Change this client's password using explicit kpasswd request metadata.
    ///
    /// # Errors
    ///
    /// Returns an error when the `kadmin/changepw` service ticket cannot be
    /// obtained, when the request cannot be built or exchanged with a kpasswd
    /// server, when the reply fails verification or decryption, or when the
    /// server reports a non-success result code.
    ///
    /// # Cancel safety
    ///
    /// NOT cancel-safe: this mutates credentials on the KDC. Dropping the future
    /// after the kpasswd request is sent does not roll the server back, so the
    /// password may or may not have changed; treat the outcome as unknown and
    /// verify it (for example with a fresh login) before retrying.
    #[inline]
    pub async fn change_password_with_options(
        &mut self,
        new_password: Password,
        options: RequestOptions,
    ) -> Result<ChangePasswordResult, Error> {
        self.inner
            .change_password_with_options(new_password, options)
            .await
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
    ///
    /// # Cancel safety
    ///
    /// NOT cancel-safe: this mutates credentials on the KDC. Dropping the future
    /// after the kpasswd request is sent does not roll the server back, so the
    /// password may or may not have changed; treat the outcome as unknown and
    /// verify it (for example with a fresh login) before retrying.
    #[inline]
    pub async fn change_password_for_with_options(
        &mut self,
        target: Principal,
        new_password: Password,
        options: RequestOptions,
    ) -> Result<ChangePasswordResult, Error> {
        self.inner
            .change_password_for_with_options(target, new_password, options)
            .await
    }
}

/// Blocking wrapper for synchronous CLI consumers of HTTP Negotiate.
///
/// Async applications should use [`Client`] directly. This type owns a
/// small current-thread Tokio runtime so callers can generate headers without
/// managing a runtime.
///
/// Runtime construction and blocking operations return
/// [`Error::BlockingRuntimeUnavailable`] whenever a Tokio runtime is entered
/// on the calling thread, including `spawn_blocking` and an explicit enter guard.
/// Use [`Client`] in async applications. Borrowing the wrapped client is unrestricted.
///
/// Dropping this wrapper is safe inside Tokio: it shuts down its runtime without
/// waiting for blocking jobs. Pending async tasks are cancelled; already-running
/// blocking jobs (including system DNS lookups) retain their resources until they
/// return. The owned runtime is private and is never handed out to callers.
pub struct BlockingClient {
    /// Current-thread runtime that drives the async client.
    runtime: BlockingRuntime,
    /// Async client whose futures `runtime` blocks on.
    client: Client,
}

impl fmt::Debug for BlockingClient {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { runtime: _, client } = self;
        f.debug_struct("BlockingNegotiateClient")
            .field("client", client)
            .finish_non_exhaustive()
    }
}

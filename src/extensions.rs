//! Typed, in-process extension points: the Rust form of MIT krb5's plugin interfaces.
//!
//! A [`Registry`] holds providers for nine interfaces. Registration is static
//! and in-process: an application constructs its providers and registers them;
//! nothing is ever loaded from a path, and no C ABI exists (MIT's `dlopen`
//! modules and symbol interposition are excluded by D3/D7).
//!
//! # Order and selection
//!
//! Providers keep their registration order per interface.
//! [`Registry::with_builtins`] registers the built-in credential-cache
//! selectors in MIT's order (`k5identity`, `realm`, `hostname`; MIT 1.22.2
//! `src/lib/krb5/ccache/ccselect.c:69-84`). For the four interfaces that MIT
//! configures in `[plugins]` (`clpreauth`, `ccselect`, `hostrealm`,
//! `localauth`), [`Registry::enabled`] applies that section like MIT's
//! `configure_interface` (`src/lib/krb5/krb/plugin.c:302-347`): `disable`
//! removes the named providers, then a non-empty `enable_only` keeps only the
//! named ones, in the order it names them. Names match exactly and
//! case-sensitively (`strcmp`, `plugin.c:178-187`).
//!
//! `[plugins] <interface> = { module = <id>:<path> }` and the profile directive
//! `module <id>:<residual>` resolve to registered providers through
//! [`Registry::parse_config`]; the path part names no file and is ignored. Any
//! other `module` stays [`crate::error::Config::UnsupportedDynamicModule`].
//!
//! # Security
//!
//! Providers are trusted code, but their outputs are not trusted data. Every
//! driver validates what a provider returns before using it: client
//! preauthentication data passes the same outgoing PA-DATA admission as
//! caller-supplied data (so a provider cannot reach a D2-rejected enctype or
//! PA type), a provider's profile text passes the same parser and policy as a
//! file, and names, realms, addresses, cache indices and rounds are bounded.
//! [`LibraryObserver`]s receive [`Event`]s that carry interface names,
//! provider ids and static reasons only, never principals, keys or protocol
//! bytes.

use alloc::sync::Arc;
use core::{error::Error as StdError, fmt};
use std::path::PathBuf;

#[cfg(feature = "messages")]
use crate::crypto::CryptoPolicy;
use crate::{
    ccache::{Principal, stores::CredentialStore},
    config::{Config, ParseMode},
    error::Extensions as Error,
    keytab::stores::KeytabType,
};

/// Credential-cache selection: the built-in selectors and the selection driver.
mod ccselect;
/// Output and registration validation shared by every driver.
mod checks;
/// Host-realm, local-authorization and server-location drivers.
mod drivers;
/// The `.k5identity` file grammar and its pattern matcher.
mod k5identity;
/// Registration and `[plugins]` filtering.
mod order;
/// Client preauthentication sessions.
#[cfg(feature = "messages")]
mod preauth;
/// Profile providers and `module` resolution.
mod profile;
/// Store-provider registration and the installed prefixes.
pub(crate) mod stores;

#[cfg(test)]
#[path = "extensions/k5identity_tests.rs"]
mod k5identity_tests;

/// Largest number of providers one interface accepts.
pub const MAX_EXTENSIONS: usize = 32;
/// Largest provider id, in bytes.
pub const MAX_ID_BYTES: usize = 64;
/// Most client preauthentication rounds one session runs (MIT 1.22.2
/// `MAX_IN_TKT_LOOPS`, `src/lib/krb5/krb/get_in_tkt.c:398`).
pub const MAX_PREAUTH_ROUNDS: usize = 16;
/// Most PA-DATA entries one preauthentication round may return.
pub const MAX_PADATA_OUTPUTS: usize = 16;
/// Largest PA-DATA value a provider may return, in bytes.
pub const MAX_PADATA_BYTES: usize = 0x0001_0000;
/// Largest realm, principal component, local name or host name, in bytes.
pub const MAX_NAME_BYTES: usize = 1024;
/// Most realms, principal components or server addresses in one output.
pub const MAX_NAMES: usize = 32;
/// Largest `.k5identity` file the built-in selector reads, in bytes.
pub const MAX_K5IDENTITY_BYTES: usize = 0x0001_0000;
/// Largest object identifier a GSS mechanism may register, in content bytes.
pub const MAX_OID_BYTES: usize = 64;

/// An error a provider returns; the driver wraps it in
/// [`crate::error::Extensions::CallFailed`].
pub type ProviderError = Box<dyn StdError + Send + Sync>;

/// One extension interface.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum Interface {
    /// Client preauthentication (`clpreauth`).
    ClientPreauth,
    /// Credential-cache selection (`ccselect`).
    CacheSelector,
    /// Host-to-realm mapping (`hostrealm`).
    HostRealm,
    /// Local authorization and name mapping (`localauth`).
    LocalAuth,
    /// Configuration profile providers (`profile`).
    ProfileProvider,
    /// KDC and server location (`locate`).
    ServerLocator,
    /// GSS-API mechanisms (`gssapi`).
    GssMechanism,
    /// Observers of redacted library events (`observer`).
    LibraryObserver,
    /// Credential-cache and keytab types under their own name prefix (`store`).
    StoreProvider,
}

impl Interface {
    /// The interface name: MIT's `[plugins]` subsection name where MIT has one.
    #[must_use]
    #[inline]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ClientPreauth => "clpreauth",
            Self::CacheSelector => "ccselect",
            Self::HostRealm => "hostrealm",
            Self::LocalAuth => "localauth",
            Self::ProfileProvider => "profile",
            Self::ServerLocator => "locate",
            Self::GssMechanism => "gssapi",
            Self::LibraryObserver => "observer",
            Self::StoreProvider => "store",
        }
    }

    /// Whether `[plugins]` `disable`, `enable_only` and `module` apply, as in MIT.
    #[must_use]
    #[inline]
    pub const fn configurable(self) -> bool {
        matches!(
            self,
            Self::ClientPreauth | Self::CacheSelector | Self::HostRealm | Self::LocalAuth
        )
    }
}

impl fmt::Display for Interface {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// One provider to register, tagged with its interface.
#[derive(Clone)]
#[non_exhaustive]
pub enum Extension {
    /// A client preauthentication mechanism.
    #[cfg(feature = "messages")]
    ClientPreauth(Arc<dyn ClientPreauth>),
    /// A credential-cache selector.
    CacheSelector(Arc<dyn CacheSelector>),
    /// A host-to-realm mapper.
    HostRealm(Arc<dyn HostRealm>),
    /// A local authorizer or name mapper.
    LocalAuth(Arc<dyn LocalAuth>),
    /// A configuration profile provider.
    ProfileProvider(Arc<dyn ProfileProvider>),
    /// A server locator.
    ServerLocator(Arc<dyn ServerLocator>),
    /// A GSS-API mechanism.
    GssMechanism(Arc<dyn GssMechanism>),
    /// An observer of redacted events.
    LibraryObserver(Arc<dyn LibraryObserver>),
    /// A credential-cache and/or keytab type for a name prefix.
    StoreProvider(Arc<dyn StoreProvider>),
}

impl fmt::Debug for Extension {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (interface, id) = match self {
            #[cfg(feature = "messages")]
            Self::ClientPreauth(item) => (Interface::ClientPreauth, item.id()),
            Self::CacheSelector(item) => (Interface::CacheSelector, item.id()),
            Self::HostRealm(item) => (Interface::HostRealm, item.id()),
            Self::LocalAuth(item) => (Interface::LocalAuth, item.id()),
            Self::ProfileProvider(item) => (Interface::ProfileProvider, item.id()),
            Self::ServerLocator(item) => (Interface::ServerLocator, item.id()),
            Self::GssMechanism(item) => (Interface::GssMechanism, item.id()),
            Self::LibraryObserver(item) => (Interface::LibraryObserver, item.id()),
            Self::StoreProvider(item) => (Interface::StoreProvider, item.id()),
        };
        f.debug_struct("Extension")
            .field("interface", &interface)
            .field("id", &id)
            .finish()
    }
}

/// A client preauthentication mechanism (MIT `clpreauth`).
///
/// # Security
///
/// Every PA-DATA a mechanism returns must be one of its own [`Self::pa_types`]
/// and passes the outgoing PA-DATA admission under the session's
/// [`CryptoPolicy`] before anything uses it.
#[cfg(feature = "messages")]
pub trait ClientPreauth: Send + Sync {
    /// Unique id within the interface, matched by `[plugins] clpreauth`.
    fn id(&self) -> &str;
    /// The PA types this mechanism answers; a D2-rejected type cannot be registered.
    fn pa_types(&self) -> &[i32];
    /// Fresh per-exchange state, created on the mechanism's first round of a session.
    fn start(&self) -> Box<dyn PreauthState>;
}

/// The per-exchange state of one [`ClientPreauth`] mechanism.
#[cfg(feature = "messages")]
pub trait PreauthState: Send {
    /// Answer one round.
    ///
    /// # Errors
    ///
    /// Returns the mechanism's failure; the session reports it as
    /// [`crate::error::Extensions::CallFailed`].
    fn process(
        &mut self,
        input: &PreauthInput<'_>,
    ) -> Result<Vec<rasn_kerberos::PaData>, ProviderError>;
}

/// What a [`PreauthState`] sees in one round.
///
/// Its `Debug` output names the PA type, the round and the sizes only, never
/// PA-DATA or request bytes.
#[cfg(feature = "messages")]
#[derive(Clone, Copy)]
#[non_exhaustive]
pub struct PreauthInput<'input> {
    /// The PA type being answered.
    pub pa_type: i32,
    /// The KDC's METHOD-DATA.
    pub method_data: &'input [rasn_kerberos::PaData],
    /// The DER-encoded KDC-REQ-BODY the answer protects.
    pub request_body: &'input [u8],
    /// The session round, starting at one.
    pub round: usize,
}

#[cfg(feature = "messages")]
impl<'input> PreauthInput<'input> {
    /// One round's input, for a session or for testing a mechanism directly.
    #[must_use]
    #[inline]
    pub const fn new(
        pa_type: i32,
        method_data: &'input [rasn_kerberos::PaData],
        request_body: &'input [u8],
        round: usize,
    ) -> Self {
        Self {
            pa_type,
            method_data,
            request_body,
            round,
        }
    }
}

#[cfg(feature = "messages")]
impl fmt::Debug for PreauthInput<'_> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreauthInput")
            .field("pa_type", &self.pa_type)
            .field("method_data_entries", &self.method_data.len())
            .field("request_body_bytes", &self.request_body.len())
            .field("round", &self.round)
            .finish()
    }
}

/// A preauthentication session: the enabled mechanisms, their per-exchange
/// state and the round count of one AS exchange.
#[cfg(feature = "messages")]
pub struct PreauthSession<'registry> {
    /// Enabled, conflict-free mechanisms and their lazily started state.
    mechanisms: Vec<preauth::Mechanism>,
    /// The policy every output must pass.
    policy: CryptoPolicy,
    /// Rounds run so far.
    rounds: usize,
    /// Observers of the session's events.
    observers: &'registry [Arc<dyn LibraryObserver>],
}

#[cfg(feature = "messages")]
impl fmt::Debug for PreauthSession<'_> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreauthSession")
            .field(
                "mechanisms",
                &self
                    .mechanisms
                    .iter()
                    .map(|(mechanism, _)| mechanism.id())
                    .collect::<Vec<_>>(),
            )
            .field("rounds", &self.rounds)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "messages")]
impl PreauthSession<'_> {
    /// Answer `pa_type` with the first enabled mechanism that registered it.
    ///
    /// Returns `Ok(None)` when no enabled mechanism answers the type.
    ///
    /// # Errors
    ///
    /// [`crate::error::Extensions::TooManyRounds`] after
    /// [`MAX_PREAUTH_ROUNDS`] rounds, `CallFailed` for a mechanism failure,
    /// `MalformedOutput` or `OutputTooLarge` for output outside the bounds or
    /// refused by the outgoing PA-DATA admission, and `PolicyRefused` when the
    /// enctype or PA-type policy refuses it.
    ///
    /// # Cancel safety
    ///
    /// Not async; a dropped session drops every mechanism's state.
    #[inline]
    pub fn respond(
        &mut self,
        pa_type: i32,
        method_data: &[rasn_kerberos::PaData],
        request_body: &[u8],
    ) -> Result<Option<Vec<rasn_kerberos::PaData>>, Error> {
        preauth::respond(self, pa_type, method_data, request_body)
    }
}

/// Selector priority: authoritative selectors run before heuristic ones
/// (MIT `ccselect.c:162-185`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Priority {
    /// The selector knows which identity a server needs.
    Authoritative,
    /// The selector guesses from names.
    Heuristic,
}

/// A credential cache a selector may choose.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct CacheCandidate {
    /// The cache name, for example `FILE:/tmp/krb5cc_1000`.
    pub name: String,
    /// The cache's default client principal.
    pub principal: Principal,
}

impl CacheCandidate {
    /// A candidate cache.
    #[must_use]
    #[inline]
    pub fn new<N>(name: N, principal: Principal) -> Self
    where
        N: Into<String>,
    {
        Self {
            name: name.into(),
            principal,
        }
    }
}

/// What a [`CacheSelector`] sees.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct SelectionRequest<'request> {
    /// The server principal credentials are needed for.
    pub server: &'request Principal,
    /// The candidate caches, in collection order.
    pub caches: &'request [CacheCandidate],
    /// The configured default realm, if any.
    pub default_realm: Option<&'request str>,
}

impl<'request> SelectionRequest<'request> {
    /// A request, for drivers and for calling a selector directly.
    #[must_use]
    #[inline]
    pub const fn new(
        server: &'request Principal,
        caches: &'request [CacheCandidate],
        default_realm: Option<&'request str>,
    ) -> Self {
        Self {
            server,
            caches,
            default_realm,
        }
    }
}

/// A selector's answer.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Selection {
    /// Use the candidate at this index.
    Cache(usize),
    /// The server needs this client principal, but no candidate holds it
    /// (MIT `KRB5_CC_NOTFOUND` with a principal).
    Principal(Principal),
    /// The selector has no opinion (MIT `KRB5_PLUGIN_NO_HANDLE`).
    NoHandle,
}

/// A credential-cache selector (MIT `ccselect`).
pub trait CacheSelector: Send + Sync {
    /// Unique id within the interface, matched by `[plugins] ccselect`.
    fn id(&self) -> &str;
    /// When the selector runs; heuristic unless overridden.
    #[inline]
    fn priority(&self) -> Priority {
        Priority::Heuristic
    }
    /// Choose a cache for `request.server`.
    ///
    /// # Errors
    ///
    /// Returns the selector's failure, which stops the selection.
    fn choose(&self, request: &SelectionRequest<'_>) -> Result<Selection, ProviderError>;
}

/// The built-in `k5identity` selector: the first `.k5identity` line whose
/// constraints the server satisfies names the client principal (MIT
/// `ccselect_k5identity.c`).
///
/// A line is `principal [realm=PATTERN] [service=PATTERN] [host=PATTERN]`,
/// fields separated by blanks; patterns are `fnmatch` globs, and the host is
/// folded to lower case before it is matched. A line starting with `#` is a
/// comment, an unknown or malformed constraint never matches, and a principal
/// without a realm takes the default realm.
///
/// # Security
///
/// The file is read on every selection (as MIT does), bounded by
/// [`MAX_K5IDENTITY_BYTES`]; a line longer than 255 bytes never matches, where
/// MIT's `fgets` would split it into several lines. No environment variable is
/// read: the caller names the file.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct K5Identity {
    /// Where the identity lines come from.
    source: IdentitySource,
}

/// Where a [`K5Identity`] reads its lines.
#[derive(Clone, Debug, Eq, PartialEq)]
enum IdentitySource {
    /// A file read at every selection; a file that cannot be opened is no answer.
    File(PathBuf),
    /// Caller-supplied file contents.
    Bytes(Vec<u8>),
}

impl K5Identity {
    /// The selector over the file at `path`, usually `$HOME/.k5identity`.
    #[must_use]
    #[inline]
    pub fn new<P>(path: P) -> Self
    where
        P: Into<PathBuf>,
    {
        Self {
            source: IdentitySource::File(path.into()),
        }
    }

    /// The selector over caller-supplied `.k5identity` contents.
    #[must_use]
    #[inline]
    pub fn from_bytes<B>(bytes: B) -> Self
    where
        B: Into<Vec<u8>>,
    {
        Self {
            source: IdentitySource::Bytes(bytes.into()),
        }
    }
}

impl CacheSelector for K5Identity {
    #[inline]
    fn id(&self) -> &'static str {
        "k5identity"
    }

    #[inline]
    fn priority(&self) -> Priority {
        Priority::Authoritative
    }

    #[inline]
    fn choose(&self, request: &SelectionRequest<'_>) -> Result<Selection, ProviderError> {
        ccselect::k5identity(&self.source, request)
    }
}

/// The built-in `realm` selector: the first cache whose principal is in the
/// server's realm (MIT `ccselect_realm.c`).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct RealmSelector;

impl RealmSelector {
    /// The selector.
    #[must_use]
    #[inline]
    pub const fn new() -> Self {
        Self
    }
}

impl CacheSelector for RealmSelector {
    #[inline]
    fn id(&self) -> &'static str {
        "realm"
    }

    #[inline]
    fn choose(&self, request: &SelectionRequest<'_>) -> Result<Selection, ProviderError> {
        Ok(ccselect::realm(request))
    }
}

/// The built-in `hostname` selector: for a two-component host-based server,
/// the cache whose realm is the longest upper-cased domain tail of the host
/// (MIT `ccselect_hostname.c`).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct HostnameSelector;

impl HostnameSelector {
    /// The selector.
    #[must_use]
    #[inline]
    pub const fn new() -> Self {
        Self
    }
}

impl CacheSelector for HostnameSelector {
    #[inline]
    fn id(&self) -> &'static str {
        "hostname"
    }

    #[inline]
    fn choose(&self, request: &SelectionRequest<'_>) -> Result<Selection, ProviderError> {
        Ok(ccselect::hostname(request))
    }
}

/// A host-realm question (MIT `hostrealm` methods).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RealmQuery<'query> {
    /// The realms of a host (`host_realm`).
    Host(&'query str),
    /// Fallback realms of a host (`fallback_realm`).
    Fallback(&'query str),
    /// The default realm (`default_realm`).
    Default,
}

/// A host-to-realm mapper (MIT `hostrealm`).
pub trait HostRealm: Send + Sync {
    /// Unique id within the interface, matched by `[plugins] hostrealm`.
    fn id(&self) -> &str;
    /// Answer `query`, or `Ok(None)` for no answer.
    ///
    /// # Errors
    ///
    /// Returns the mapper's failure, which stops the lookup.
    fn realms(&self, query: &RealmQuery<'_>) -> Result<Option<Vec<String>>, ProviderError>;
}

/// A local authorizer's answer (MIT `localauth` `userok`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Decision {
    /// The principal may use the local account.
    Allow,
    /// The principal may not use the local account; this answer always wins.
    Deny,
    /// No opinion.
    Pass,
}

/// A local authorizer and name mapper (MIT `localauth`).
pub trait LocalAuth: Send + Sync {
    /// Unique id within the interface, matched by `[plugins] localauth`.
    fn id(&self) -> &str;
    /// Whether `principal` may use `local_name`; [`Decision::Pass`] for no opinion.
    ///
    /// # Errors
    ///
    /// Returns the authorizer's failure, which denies access.
    fn userok(&self, principal: &Principal, local_name: &str) -> Result<Decision, ProviderError>;
    /// The local account name of `principal`, or `Ok(None)` for no answer.
    ///
    /// # Errors
    ///
    /// Returns the mapper's failure, which stops the mapping.
    fn local_name(&self, principal: &Principal) -> Result<Option<String>, ProviderError>;
}

/// The service a [`ServerLocator`] is asked for (MIT `locate` service types).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum LocateService {
    /// Any KDC.
    Kdc,
    /// The primary KDC.
    PrimaryKdc,
    /// The administration server.
    Kadmin,
    /// The password-change server.
    Kpasswd,
}

/// The transport a [`ServerLocator`] is asked for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum LocateTransport {
    /// UDP.
    Udp,
    /// TCP.
    Tcp,
}

/// What a [`ServerLocator`] is asked.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct LocateRequest<'request> {
    /// The realm.
    pub realm: &'request str,
    /// The service.
    pub service: LocateService,
    /// The transport.
    pub transport: LocateTransport,
}

impl<'request> LocateRequest<'request> {
    /// A request.
    #[must_use]
    #[inline]
    pub const fn new(
        realm: &'request str,
        service: LocateService,
        transport: LocateTransport,
    ) -> Self {
        Self {
            realm,
            service,
            transport,
        }
    }
}

/// One server a [`ServerLocator`] names.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ServerAddress {
    /// Host name or address literal.
    pub host: String,
    /// Port, never zero.
    pub port: u16,
}

impl ServerAddress {
    /// An address.
    #[must_use]
    #[inline]
    pub fn new<H>(host: H, port: u16) -> Self
    where
        H: Into<String>,
    {
        Self {
            host: host.into(),
            port,
        }
    }
}

/// A KDC and server locator (MIT `locate`).
pub trait ServerLocator: Send + Sync {
    /// Unique id within the interface.
    fn id(&self) -> &str;
    /// The servers for `request`, or `Ok(None)` for no answer.
    ///
    /// # Errors
    ///
    /// Returns the locator's failure, which stops the lookup.
    fn locate(
        &self,
        request: &LocateRequest<'_>,
    ) -> Result<Option<Vec<ServerAddress>>, ProviderError>;
}

/// A GSS-API mechanism registration (MIT mechanism configuration).
///
/// # Security
///
/// A mechanism cannot take the object identifier of a built-in mechanism
/// (Kerberos, its Microsoft alias, SPNEGO, IAKERB, `NegoEx`) or of another
/// registered mechanism.
pub trait GssMechanism: Send + Sync {
    /// Unique id within the interface.
    fn id(&self) -> &str;
    /// The DER content octets of the mechanism's object identifier.
    fn oid(&self) -> &[u8];
}

/// A configuration profile provider (MIT `profile` modules).
pub trait ProfileProvider: Send + Sync {
    /// Unique id, named by the profile directive `module <id>:<residual>`.
    fn id(&self) -> &str;
    /// The profile, in `krb5.conf` syntax, for `residual`.
    ///
    /// # Errors
    ///
    /// Returns the provider's failure, which fails the configuration load.
    fn profile(&self, residual: &str) -> Result<String, ProviderError>;
}

/// Why a driver refused or skipped a provider.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Refusal {
    /// The provider returned an error.
    Failed,
    /// The output broke the interface's shape.
    Malformed,
    /// The output exceeded a bound.
    TooLarge,
    /// The output failed policy admission.
    Policy,
    /// An earlier enabled provider already answers one of its PA types.
    Conflict,
}

/// A redacted library event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Event<'event> {
    /// A provider was asked.
    Consulted {
        /// Its interface.
        interface: Interface,
        /// Its id.
        id: &'event str,
    },
    /// A provider's answer was accepted.
    Chosen {
        /// Its interface.
        interface: Interface,
        /// Its id.
        id: &'event str,
    },
    /// A provider had no answer.
    Declined {
        /// Its interface.
        interface: Interface,
        /// Its id.
        id: &'event str,
    },
    /// A provider's answer was refused, or the provider was skipped.
    Refused {
        /// Its interface.
        interface: Interface,
        /// Its id.
        id: &'event str,
        /// Why.
        reason: Refusal,
    },
}

/// An observer of redacted library events (the Rust counterpart of MIT
/// interposer modules for instrumentation).
pub trait LibraryObserver: Send + Sync {
    /// Unique id within the interface.
    fn id(&self) -> &str;
    /// Receive one event. Observers cannot change any outcome.
    fn observe(&self, event: &Event<'_>);
}

/// A credential-store provider: a cache type, a keytab type or both under one
/// name prefix.
///
/// It is the Rust form of MIT `krb5_cc_register` and `krb5_kt_register`.
/// [`Registry::install_stores`] publishes registered providers process-wide;
/// from then on `PREFIX:residual` names reach the provider through every
/// name-based route: [`crate::ccache::CCache::load_name`] and
/// [`crate::ccache::CCache::save_name`], the client's named and default cache
/// lookups and its cache write-back,
/// [`crate::ccache::file_store::resolve`] and
/// [`crate::ccache::file_store::collection`], and
/// [`crate::keytab::Keytab::load_name`] with the default keytab lookups.
/// Prefixes match exactly, as MIT's `strcmp` does.
///
/// # Security
///
/// A provider is trusted code: it receives every credential stored under its
/// prefix. It can never take a built-in type (`FILE`, `WRFILE`, `DIR`,
/// `MEMORY`) or a prefix another provider holds, in any letter case, so no
/// registration can redirect a name that already resolves elsewhere. A
/// prefix is 2 to [`MAX_ID_BYTES`] bytes of `[A-Za-z0-9_.-]`: it contains no
/// `:` and is never a one-letter drive name.
///
/// # Cancel safety
///
/// Store methods are synchronous; see [`crate::ccache::stores`].
pub trait StoreProvider: Send + Sync {
    /// Unique id within the interface.
    fn id(&self) -> &str;
    /// The type prefix it claims, without the colon.
    fn prefix(&self) -> &str;
    /// Its credential-cache type, whose [`CredentialStore::cache_type`] is
    /// [`Self::prefix`].
    #[inline]
    fn credential_store(&self) -> Option<&dyn CredentialStore> {
        None
    }
    /// Its keytab type.
    #[inline]
    fn keytab_type(&self) -> Option<&dyn KeytabType> {
        None
    }
}

/// The extension registry.
#[derive(Clone, Default)]
#[non_exhaustive]
pub struct Registry {
    /// `clpreauth` providers, in registration order.
    #[cfg(feature = "messages")]
    preauth: Vec<Arc<dyn ClientPreauth>>,
    /// `ccselect` providers.
    selectors: Vec<Arc<dyn CacheSelector>>,
    /// `hostrealm` providers.
    realms: Vec<Arc<dyn HostRealm>>,
    /// `localauth` providers.
    local: Vec<Arc<dyn LocalAuth>>,
    /// Profile providers.
    profiles: Vec<Arc<dyn ProfileProvider>>,
    /// Server locators.
    locators: Vec<Arc<dyn ServerLocator>>,
    /// GSS-API mechanisms.
    mechanisms: Vec<Arc<dyn GssMechanism>>,
    /// Event observers.
    observers: Vec<Arc<dyn LibraryObserver>>,
    /// Credential-store providers.
    stores: Vec<Arc<dyn StoreProvider>>,
}

impl fmt::Debug for Registry {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entries(
                order::INTERFACES
                    .iter()
                    .map(|interface| (interface, self.ids(*interface))),
            )
            .finish()
    }
}

impl Registry {
    /// An empty registry: no built-ins.
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// A registry with the built-in credential-cache selectors, in MIT's order:
    /// `k5identity` (only when `k5identity` is given), `realm`, `hostname`.
    #[must_use]
    #[inline]
    pub fn with_builtins(k5identity: Option<K5Identity>) -> Self {
        ccselect::builtins(k5identity)
    }

    /// Register a provider after the ones already registered for its interface.
    ///
    /// # Errors
    ///
    /// `InvalidId` for an id that is empty, longer than [`MAX_ID_BYTES`] or
    /// uses a byte outside `[A-Za-z0-9_.-]`; `DuplicateId` for an id the
    /// interface already has (exact match); `TooManyProviders` beyond
    /// [`MAX_EXTENSIONS`]; `InvalidRegistration` for a preauthentication
    /// mechanism without PA types or with a D2-rejected one, a GSS mechanism
    /// with a malformed, reserved or taken object identifier, or a store
    /// provider with a malformed prefix, with neither a cache nor a keytab
    /// type, or whose cache type names another prefix; `PrefixTaken` for a
    /// store prefix that is built in or registered already (any letter case).
    #[inline]
    pub fn register(&mut self, extension: Extension) -> Result<(), Error> {
        order::register(self, extension)
    }

    /// Provider ids of `interface`, in registration order.
    #[must_use]
    #[inline]
    pub fn ids(&self, interface: Interface) -> Vec<&str> {
        order::ids(self, interface, None)
    }

    /// Provider ids of `interface` in the order drivers consult them, after
    /// `[plugins]` `disable` and `enable_only` of `config`.
    #[must_use]
    #[inline]
    pub fn enabled(&self, interface: Interface, config: &Config) -> Vec<&str> {
        order::ids(self, interface, Some(config))
    }

    /// Parse `krb5.conf` text, resolving `module` against this registry.
    ///
    /// A text whose only directive is `module <id>:<residual>` takes its
    /// profile from the [`ProfileProvider`] `<id>`, given `<residual>`; the
    /// provider's text is parsed like a file, so it cannot name another profile
    /// module. `[plugins] <interface> = { module = <id>:<path> }` is accepted
    /// when `<id>` is a registered provider of that interface. Every other
    /// input parses exactly like [`Config::parse_with_mode`].
    ///
    /// # Errors
    ///
    /// The [`Config::parse_with_mode`] errors (an unresolved `module` is still
    /// `UnsupportedDynamicModule`), `CallFailed` when the profile provider
    /// fails, and `OutputTooLarge` when its text exceeds
    /// [`crate::config::MAX_INCLUDE_BYTES`].
    #[inline]
    pub fn parse_config(&self, text: &str, mode: ParseMode) -> Result<Config, Error> {
        profile::compose(self, text, mode)
    }

    /// Choose a credential cache for `server` (MIT `krb5_cc_select`):
    /// authoritative selectors first, then heuristic ones, each in enabled order.
    ///
    /// # Errors
    ///
    /// `CallFailed` for a selector failure and `MalformedOutput` for an
    /// index outside `caches` or an invalid principal.
    #[inline]
    pub fn select_cache(
        &self,
        config: &Config,
        server: &Principal,
        caches: &[CacheCandidate],
    ) -> Result<Selection, Error> {
        ccselect::select(self, config, server, caches)
    }

    /// Ask the enabled host-realm mappers in order; the first answer wins.
    ///
    /// # Errors
    ///
    /// `CallFailed` for a mapper failure, `MalformedOutput` for an empty
    /// answer or an invalid realm, and `OutputTooLarge` for more than
    /// [`MAX_NAMES`] realms.
    #[inline]
    pub fn realms(
        &self,
        config: &Config,
        query: &RealmQuery<'_>,
    ) -> Result<Option<Vec<String>>, Error> {
        drivers::realms(self, config, query)
    }

    /// Whether `principal` may use `local_name` (MIT `krb5_kuserok`): any
    /// enabled authorizer's denial or failure denies, and at least one must allow.
    #[must_use]
    #[inline]
    pub fn authorize_local(
        &self,
        config: &Config,
        principal: &Principal,
        local_name: &str,
    ) -> bool {
        drivers::authorize(self, config, principal, local_name)
    }

    /// The local account name of `principal`; the first answer wins.
    ///
    /// # Errors
    ///
    /// `CallFailed` for a mapper failure and `MalformedOutput` for an
    /// empty, oversized or control-character name, or one containing `/`.
    #[inline]
    pub fn local_name(
        &self,
        config: &Config,
        principal: &Principal,
    ) -> Result<Option<String>, Error> {
        drivers::local_name(self, config, principal)
    }

    /// Ask the server locators in order; the first answer wins.
    ///
    /// # Errors
    ///
    /// `CallFailed` for a locator failure, `MalformedOutput` for an empty
    /// answer, an invalid host or port zero, and `OutputTooLarge` for more than
    /// [`MAX_NAMES`] addresses.
    #[inline]
    pub fn locate(&self, request: &LocateRequest<'_>) -> Result<Option<Vec<ServerAddress>>, Error> {
        drivers::locate(self, request)
    }

    /// Publish the registered store providers process-wide, so that names
    /// with their prefixes resolve through them (MIT `krb5_cc_register` and
    /// `krb5_kt_register`, which also act process-wide).
    ///
    /// Installation is all or nothing and permanent for the process.
    /// Installing a provider that is installed already changes nothing.
    ///
    /// # Security
    ///
    /// This is the only process-wide state of the registry: an installed
    /// prefix cannot be replaced or removed, and another provider claiming it
    /// (in any letter case) is refused.
    ///
    /// # Errors
    ///
    /// `PrefixTaken` when another provider holds one of the prefixes, and
    /// `TooManyProviders` beyond [`MAX_EXTENSIONS`] installed providers; then
    /// nothing is installed.
    ///
    /// # Cancel safety
    ///
    /// Not async; it holds a process-wide lock only while it updates the table.
    #[inline]
    pub fn install_stores(&self) -> Result<(), Error> {
        stores::install(&self.stores)
    }

    /// The registered GSS-API mechanism with object identifier `oid`.
    #[must_use]
    #[inline]
    pub fn gss_mechanism(&self, oid: &[u8]) -> Option<Arc<dyn GssMechanism>> {
        self.mechanisms
            .iter()
            .find(|mechanism| mechanism.oid() == oid)
            .map(Arc::clone)
    }

    /// Start a preauthentication session for one AS exchange: the enabled
    /// mechanisms in order, each skipped when an earlier one already answers
    /// one of its PA types (MIT `preauth2.c:171-180`).
    #[cfg(feature = "messages")]
    #[must_use]
    #[inline]
    pub fn preauth_session(&self, config: &Config, policy: &CryptoPolicy) -> PreauthSession<'_> {
        preauth::session(self, config, policy)
    }
}

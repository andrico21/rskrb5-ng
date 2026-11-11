//! Kerberos `krb5.conf` parsing.
//!
//! Configuration includes bounded include expansion, libdefaults, realm host
//! mappings, domain-realm lookup, durations and KDC discovery. Enctype ID
//! accessors apply the configured family opt-ins and permitted list.

/// Explicit-context expansion of credential-name profile parameters.
#[path = "config/expansion.rs"]
pub mod parameters;

/// Ambient credential-name resolution, separate from profile parsing.
#[cfg(feature = "messages")]
#[path = "config/credential_names.rs"]
pub(crate) mod credential_names;

use alloc::{borrow::Cow, collections::BTreeMap};
use core::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use std::{
    env, fs,
    io::{self, Read as _},
    path::{Path, PathBuf},
};

use crate::crypto::{
    s2k::{Family, Minima},
    selection,
};
/// Removed protocol mode selection boundaries.
#[path = "config/protocol.rs"]
pub mod protocol;
/// Effective restrictions shared by all configuration construction paths.
#[path = "config/restrictions.rs"]
pub(crate) mod restrictions;
/// Reject forbidden serde configuration selections.
#[cfg(feature = "serde")]
#[path = "config/serde_policy.rs"]
mod serde_policy;

/// Ordered profile composition.
#[path = "config/profile.rs"]
mod profile;
/// Independent source syntax state.
#[path = "config/profile_syntax.rs"]
mod profile_syntax;

/// Per-row fail-closed classification review.
#[cfg(test)]
#[path = "config/classification_e.rs"]
mod classification_e;
/// Exhaustive diagnostic promotion regressions.
#[cfg(test)]
#[path = "config/diagnostic_tests.rs"]
mod diagnostic_tests;
/// Typed DNS canonicalization policy.
#[path = "config/hostname.rs"]
pub mod hostname;
/// C1 relation parsing and classification.
#[path = "config/libdefaults.rs"]
mod libdefaults;
/// Documented realm relation inventory.
#[path = "config/realm_relations.rs"]
mod realm_relations;
/// Typed realm values and policy diagnostics.
#[path = "config/realm_values.rs"]
mod realm_values;
/// Non-libdefaults subtree decoding.
#[path = "config/section_decode.rs"]
mod section_decode;
/// Independent catalogue count and name regressions.
#[cfg(test)]
#[path = "config/section_inventory_tests.rs"]
mod section_inventory_tests;
/// Typed application, route and realm relation data.
#[path = "config/section_values.rs"]
pub mod section_values;
/// Unknown profile path diagnostics.
#[path = "config/unknown.rs"]
mod unknown;

/// The environment variable naming the `krb5.conf` path list.
const KRB5_CONFIG_ENV: &str = "KRB5_CONFIG";
/// The configuration files tried, in order, when `KRB5_CONFIG` is unset.
#[cfg(target_family = "unix")]
const PLATFORM_DEFAULT_CONFIG_PATHS: &[&str] = &["/etc/krb5.conf"];
/// The configuration files tried, in order, when `KRB5_CONFIG` is unset.
#[cfg(target_family = "windows")]
const PLATFORM_DEFAULT_CONFIG_PATHS: &[&str] = &["C:\\ProgramData\\MIT\\Kerberos5\\krb5.ini"];
/// The configuration files tried, in order, when `KRB5_CONFIG` is unset.
#[cfg(not(any(target_family = "unix", target_family = "windows")))]
const PLATFORM_DEFAULT_CONFIG_PATHS: &[&str] = &[];

/// The enctype names every default request and permitted list starts from.
const DEFAULT_ENCTYPES: &[&str] = &[
    "aes256-cts-hmac-sha384-192",
    "aes128-cts-hmac-sha256-128",
    "aes256-cts-hmac-sha1-96",
    "aes128-cts-hmac-sha1-96",
];

/// The default `preferred_preauth_types`, most preferred first.
const DEFAULT_PREAUTH_TYPES: &[i32] = &[17, 16];

/// The deepest `include` nesting a configuration may reach before parsing fails
/// with [`Error::IncludeTooDeep`].
///
/// MIT's parser recurses without a bound; this one is a deliberate divergence so
/// a pathological configuration cannot nest without limit.
pub const MAX_INCLUDE_DEPTH: usize = 8;

/// The most files one configuration may pull in through `include` and
/// `includedir` before parsing fails with [`Error::IncludeTooMany`].
pub const MAX_INCLUDE_FILES: usize = 256;

/// The most bytes one configuration may pull in through `include` and
/// `includedir` - counted across every included file - before parsing fails with
/// [`Error::IncludeTooLarge`] (4 MiB, including root sources).
pub const MAX_INCLUDE_BYTES: usize = 4 * 1024 * 1024;

/// Parsed Kerberos configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[non_exhaustive]
pub struct Config {
    /// `[libdefaults]` values.
    pub libdefaults: LibDefaults,
    /// `[realms]` entries in file order.
    #[cfg_attr(feature = "serde", serde(deserialize_with = "serde_policy::realms"))]
    pub realms: Vec<Realm>,
    /// `[domain_realm]` mappings keyed by lower-case domain names.
    pub domain_realm: BTreeMap<String, String>,
    /// Declared cross-realm routes; not an active transit policy.
    #[cfg_attr(feature = "serde", serde(default))]
    pub capaths: section_values::Capaths,
    /// Hierarchical application defaults with MIT precedence.
    #[cfg_attr(feature = "serde", serde(default))]
    pub applications: section_values::Applications,
    /// Plugin restrictions by interface, without executable module loading.
    #[cfg_attr(feature = "serde", serde(default))]
    #[cfg_attr(feature = "serde", serde(deserialize_with = "serde_policy::plugins"))]
    pub plugins: BTreeMap<String, section_values::Plugins>,
}

impl Config {
    /// Lookup application text using MIT's four-level precedence.
    #[inline]
    #[must_use]
    pub fn appdefault(&self, app: &str, realm: &str, relation: &str) -> Option<&str> {
        self.applications.get(app, realm, relation)
    }

    /// Lookup a boolean without coercing malformed strings into false.
    /// # Errors
    /// Returns `InvalidBoolean` for a selected non-boolean application value.
    #[inline]
    pub fn appdefault_boolean(
        &self,
        app: &str,
        realm: &str,
        relation: &str,
    ) -> Result<Option<bool>, Error> {
        self.applications.boolean(app, realm, relation)
    }

    /// Return a declared route, preserving missing versus direct.
    #[inline]
    #[must_use]
    pub fn capath(&self, client: &str, server: &str) -> Option<&section_values::Route> {
        self.capaths.get(client)?.get(server)
    }
    /// Diagnostics for selected profile relations, including deferred consumers.
    #[inline]
    #[must_use]
    pub fn diagnostics(&self) -> &[ConfigDiagnostic] {
        &self.libdefaults.enctype_diagnostics
    }

    /// Resolve a host mapping, then the explicitly configured default realm.
    #[inline]
    #[must_use]
    pub fn realm_for_host(&self, host: &str) -> Option<&str> {
        self.resolve_realm(host).or_else(|| {
            (!self.libdefaults.default_realm.is_empty())
                .then_some(self.libdefaults.default_realm.as_str())
        })
    }
    #[must_use]
    /// Create a config with MIT/gokrb5-style defaults and no parsed sections.
    #[inline]
    pub fn new() -> Self {
        Self {
            libdefaults: LibDefaults::new(),
            realms: Vec::new(),
            domain_realm: BTreeMap::new(),
            capaths: BTreeMap::new(),
            applications: section_values::Applications::default(),
            plugins: BTreeMap::new(),
        }
    }

    /// Load and parse a `krb5.conf` file.
    ///
    /// The file's canonical path is on the open chain before its own directives
    /// expand, so a configuration that includes itself - under any spelling of
    /// its own name - is [`Error::IncludeCycle`] rather than a recursion that
    /// only runs out of depth.
    ///
    /// # Errors
    ///
    /// Returns [`Error::File`] when the file cannot be resolved or read, and the
    /// [`Config::parse`] errors for its contents.
    #[inline]
    pub fn load<P>(path: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        Self::load_paths([path])
    }

    /// Load and parse the `krb5.conf` path list named by `KRB5_CONFIG`.
    ///
    /// The environment value is split with the platform path-list separator.
    /// On Unix this matches the colon-separated list used by MIT Kerberos.
    ///
    /// # Ambient input
    /// Reads `KRB5_CONFIG`; use [`Config::load_paths`] for explicit paths.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DefaultConfigName`] when `KRB5_CONFIG` is unset, and
    /// the [`Config::load_paths`] errors for the list it names.
    #[inline]
    pub fn load_from_env() -> Result<Self, Error> {
        let value = env::var_os(KRB5_CONFIG_ENV).ok_or(Error::DefaultConfigName)?;
        Self::load_paths(env::split_paths(&value))
    }

    /// Load the default Kerberos configuration.
    ///
    /// `KRB5_CONFIG` takes precedence when set. Otherwise this tries platform
    /// defaults such as `/etc/krb5.conf` on Unix.
    ///
    /// # Ambient input
    /// Reads `KRB5_CONFIG` and discovers platform files; use [`Config::load`]
    /// or [`Config::parse`] to choose the source explicitly.
    ///
    /// # Errors
    ///
    /// Returns the [`Config::load_from_env`] errors when `KRB5_CONFIG` is set,
    /// [`Error::NoDefault`] when no platform default file exists, and the
    /// [`Config::load_paths`] errors for the files that do.
    #[inline]
    pub fn load_default() -> Result<Self, Error> {
        if env::var_os(KRB5_CONFIG_ENV).is_some() {
            return Self::load_from_env();
        }
        Self::load_default_paths(PLATFORM_DEFAULT_CONFIG_PATHS.iter().copied())
    }

    /// Load the default Kerberos configuration or parse an embedded fallback.
    ///
    /// The embedded config is used only when no environment or platform
    /// default config source exists. If a configured file exists but cannot be
    /// read or parsed, that error is returned.
    ///
    /// # Ambient input
    /// Reads `KRB5_CONFIG` and discovers platform files before using the fallback.
    /// Use [`Config::parse`] to use only caller-supplied text.
    ///
    /// # Errors
    ///
    /// Returns the [`Config::load_from_env`] errors when `KRB5_CONFIG` is set,
    /// the [`Config::load_paths`] errors for an existing platform default file,
    /// and the [`Config::parse`] errors for the embedded text.
    #[inline]
    pub fn load_default_or_parse(embedded_krb5_conf: &str) -> Result<Self, Error> {
        if env::var_os(KRB5_CONFIG_ENV).is_some() {
            return Self::load_from_env();
        }
        Self::load_default_or_parse_paths(
            embedded_krb5_conf,
            PLATFORM_DEFAULT_CONFIG_PATHS.iter().copied(),
        )
    }

    /// Load and parse one or more `krb5.conf` files.
    ///
    /// Sources compose in iterator order. Directory entries use MIT's filename
    /// filter and bytewise order. Each file has independent syntax state; scalar
    /// relations select their first value and endpoint relations accumulate.
    /// Missing explicitly named sources fail closed rather than being skipped.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EmptyConfigPathList`] when the list names no non-empty
    /// path, [`Error::File`] when a named file cannot be resolved or read, and
    /// the [`Config::parse`] errors for each independent source.
    #[inline]
    pub fn load_paths<I, P>(paths: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        let mut loader = IncludeExpansion::default();
        let mut found = false;
        for entry in paths {
            let path = entry.as_ref();
            if path.as_os_str().is_empty() {
                continue;
            }
            found = true;
            let metadata = fs::metadata(path).map_err(|source| Error::File {
                path: path.to_path_buf(),
                source,
            })?;
            if metadata.is_dir() {
                loader.include_dir(path, 0)?;
            } else {
                loader.include_file(path, 0)?;
            }
        }
        if !found {
            return Err(Error::EmptyConfigPathList);
        }
        loader.profile.finish(ParseMode::Compatible)
    }

    /// Load the platform default files of `paths` that exist.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoDefault`] when none of them exists, and the
    /// [`Config::load_paths`] errors for those that do.
    fn load_default_paths<I, P>(paths: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        let existing = existing_default_config_paths(paths);
        if existing.is_empty() {
            return Err(Error::NoDefault);
        }
        Self::load_paths(existing)
    }

    /// Load the platform default files of `paths` that exist, or parse
    /// `embedded_krb5_conf` when none does.
    ///
    /// # Errors
    ///
    /// Returns the [`Config::load_paths`] errors for existing files, and the
    /// [`Config::parse`] errors for the embedded text.
    fn load_default_or_parse_paths<I, P>(embedded_krb5_conf: &str, paths: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        match Self::load_default_paths(paths) {
            Ok(config) => Ok(config),
            Err(Error::NoDefault) => Self::parse(embedded_krb5_conf),
            Err(error) => Err(error),
        }
    }

    /// Parse a `krb5.conf` string.
    ///
    /// A line beginning with `include <absolute-file>` or
    /// `includedir <absolute-dir>` loads independent sources at the directive
    /// site, then resumes the parent's section and nesting state. Directory
    /// entries use MIT's eligibility filter and bytewise order. Loading is bounded by
    /// [`MAX_INCLUDE_DEPTH`], [`MAX_INCLUDE_FILES`] and [`MAX_INCLUDE_BYTES`], and
    /// a cycle, an unreadable file or directory, or a bound that is passed is a
    /// named [`Error`] rather than a skipped directive.
    ///
    /// Fails with [`Error::EnctypeNotPermitted`] when an explicit
    /// `default_tkt_enctypes` or `default_tgs_enctypes` list names an enctype
    /// outside an explicit `permitted_enctypes` allowlist. The check runs once,
    /// on the final values after every `[libdefaults]` section of the expanded
    /// input (included files included) is applied.
    ///
    /// Enctype lists use [`EnctypeExpr`], including ordered families, `DEFAULT`
    /// and subtraction. Forbidden, disabled and unknown positive selections fail
    /// by name. Compatible mode skips only secure unsupported Camellia, recorded
    /// by [`LibDefaults::diagnostics`]; use [`Self::parse_with_mode`] for strict mode.
    /// Empty resolved lists fail closed. Implicit request lists inherit the
    /// permitted list. Family permissions apply after all sections are read.
    ///
    /// # Errors
    ///
    /// Returns the include-expansion errors ([`Error::IncludeFile`],
    /// [`Error::IncludeDir`], [`Error::IncludeCycle`], [`Error::IncludeTooDeep`],
    /// [`Error::IncludeTooMany`], [`Error::IncludeTooLarge`]), the error of any
    /// line or value a section parser refuses, and the enctype policy
    /// errors above.
    #[inline]
    pub fn parse(input: &str) -> Result<Self, Error> {
        Self::parse_with_roots(input, [])
    }

    /// Parse caller text, equivalent to gokrb5's `NewFromString`.
    ///
    /// # Errors
    /// Returns the bounded profile-composition errors of [`Self::parse`].
    #[inline]
    pub fn from_string(input: &str) -> Result<Self, Error> {
        Self::parse(input)
    }

    /// Load an explicit path, equivalent to gokrb5's `Load`.
    ///
    /// # Errors
    /// Returns the pathful I/O and composition errors of [`Self::load`].
    #[inline]
    pub fn from_path<P>(path: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        Self::load(path)
    }

    /// Parse a reader, including buffered readers, through profile composition.
    ///
    /// # Errors
    /// Returns typed I/O, UTF-8, size and include-composition failures.
    #[inline]
    pub fn from_reader<R>(reader: R) -> Result<Self, Error>
    where
        R: io::Read,
    {
        let mut bytes = Vec::new();
        let limit = u64::try_from(MAX_INCLUDE_BYTES)
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        let _: usize = reader.take(limit).read_to_end(&mut bytes)?;
        if bytes.len() > MAX_INCLUDE_BYTES {
            return Err(Error::IncludeTooLarge {
                bytes: bytes.len(),
                limit: MAX_INCLUDE_BYTES,
            });
        }
        let text = String::from_utf8(bytes)
            .map_err(|source| io::Error::new(io::ErrorKind::InvalidData, source))?;
        Self::parse(&text)
    }

    /// Parse a profile with explicit secure-unsupported handling.
    ///
    /// # Errors
    /// Returns the errors of [`Self::parse`], including Camellia errors in strict mode.
    #[inline]
    pub fn parse_with_mode(input: &str, mode: ParseMode) -> Result<Self, Error> {
        Self::parse_with_roots_mode(input, [], mode)
    }

    /// Parse caller-provided text with an optional active source chain.
    ///
    /// # Errors
    ///
    /// Returns the [`IncludeExpansion::expand`] error of an `include` or
    /// `includedir` the text names, and the error of any line or section the
    /// parser refuses.
    fn parse_with_roots<I>(text: &str, roots: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = PathBuf>,
    {
        Self::parse_with_roots_mode(text, roots, ParseMode::Compatible)
    }

    /// Expand sources and apply the requested enctype parsing mode.
    ///
    /// # Errors
    /// Returns include, profile and expression-policy errors without fallback.
    fn parse_with_roots_mode<I>(text: &str, roots: I, mode: ParseMode) -> Result<Self, Error>
    where
        I: IntoIterator<Item = PathBuf>,
    {
        let mut loader = IncludeExpansion::default().with_roots(roots);
        if text.len() > MAX_INCLUDE_BYTES {
            return Err(Error::IncludeTooLarge {
                bytes: text.len(),
                limit: MAX_INCLUDE_BYTES,
            });
        }
        loader.bytes = text.len();
        loader.expand(text, 0)?;
        loader.profile.finish(mode)
    }

    /// Render a gokrb5-style JSON snapshot of the parsed configuration.
    ///
    /// # Errors
    ///
    /// Returns [`serde_json::Error`] when the snapshot cannot be serialized.
    #[cfg(feature = "serde")]
    #[inline]
    pub fn json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&ConfigJson::from(self))
    }

    #[must_use]
    /// Return the configured realm with this name.
    #[inline]
    pub fn realm(&self, realm: &str) -> Option<&Realm> {
        self.realms.iter().find(|entry| entry.name == realm)
    }

    /// Resolve a DNS name to a Kerberos realm using `[domain_realm]`.
    ///
    /// DNS names compare case-insensitively (RFC 4120 section 6.1) while realm
    /// values stay case-sensitive, and mapping keys are stored lower-cased.
    /// Lookup order: the exact hostname first, then the most specific suffix,
    /// where a leading-dot tag covers subdomains only and a bare tag covers the
    /// domain and its subdomains (MIT `krb5.conf(5)`); within one level the
    /// leading-dot tag wins.
    #[inline]
    #[must_use]
    pub fn resolve_realm(&self, dns_name: &str) -> Option<&str> {
        let folded = dns_name.trim_end_matches('.').to_ascii_lowercase();
        let domain_name = folded.as_str();
        if let Some(realm) = self.domain_realm.get(domain_name) {
            return Some(realm);
        }

        let parts: Vec<_> = domain_name.split('.').collect();
        for start in 1..parts.len() {
            let bare = parts.get(start..).unwrap_or_default().join(".");
            let dotted = format!(".{bare}");
            if let Some(realm) = self.domain_realm.get(&dotted) {
                return Some(realm);
            }
            if let Some(realm) = self.domain_realm.get(&bare) {
                return Some(realm);
            }
        }
        None
    }

    /// Return KDC hosts configured for a realm.
    ///
    /// DNS lookup is intentionally not performed here; the first port keeps
    /// host configuration deterministic and leaves DNS transport for the Tokio
    /// adapter layer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoRealm`] when the realm is not configured, and
    /// [`Error::NoKdc`] when it lists no KDC.
    #[inline]
    pub fn configured_kdcs(&self, realm: &str) -> Result<&[String], Error> {
        restrictions::config(self)?;
        let realm_entry = self
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
    ///
    /// Returns [`Error::NoRealm`] when the realm is not configured, and
    /// [`Error::NoKpasswdServer`] when it lists no password-change server.
    #[inline]
    pub fn configured_kpasswd_servers(&self, realm: &str) -> Result<&[String], Error> {
        restrictions::config(self)?;
        let realm_entry = self
            .realm(realm)
            .ok_or_else(|| Error::NoRealm(realm.to_owned()))?;
        if realm_entry.kpasswd_server.is_empty() {
            return Err(Error::NoKpasswdServer(realm.to_owned()));
        }
        Ok(&realm_entry.kpasswd_server)
    }
}

impl Default for Config {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

/// The paths of `paths` that name an existing regular file, in order.
fn existing_default_config_paths<I, P>(paths: I) -> Vec<PathBuf>
where
    I: IntoIterator<Item = P>,
    P: AsRef<Path>,
{
    paths
        .into_iter()
        .map(|path| path.as_ref().to_path_buf())
        .filter(|path| path.is_file())
        .collect()
}

include!("config/toggle.rs");
/// Configuration parsing modes and diagnostics.
#[path = "config/diagnostic.rs"]
pub mod diagnostic;
include!("config/enctype_expr.rs");

/// `[libdefaults]` configuration values, constructed through [`Self::new`] and builders.
///
/// Secure defaults are AES-SHA2 then AES-SHA1: IDs `[20, 19, 18, 17]`.
/// Legacy permissions never insert entries into explicit request lists. Configuration
/// parsing validates original terms and final list relationships before returning;
/// runtime `CryptoPolicy` snapshots revalidate publicly mutated fields before use.
/// See the [security policy](https://github.com/andrico21/rskrb5-ng/blob/main/docs/security-policy.md#policy).
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[non_exhaustive]
pub struct LibDefaults {
    /// Unknown serde relations are checked for prohibited protocol selections.
    #[cfg(feature = "serde")]
    #[serde(
        flatten,
        deserialize_with = "serde_policy::relations",
        skip_serializing
    )]
    pub protocol_relations: BTreeMap<String, String>,
    /// API-only trusted minima; serde always restores secure RFC defaults.
    #[cfg_attr(feature = "serde", serde(skip))]
    pub min_s2k_iterations: Minima,
    /// Permit explicitly configured RC4-HMAC (23); export RC4 (24) is forbidden.
    #[cfg_attr(feature = "serde", serde(default))]
    pub allow_rc4: Toggle,
    /// Permit explicitly configured DES3 (16); disabled by default.
    #[cfg_attr(feature = "serde", serde(default))]
    pub allow_des3: Toggle,
    /// Blanket weakening is permanently rejected when enabled.
    #[cfg_attr(feature = "serde", serde(deserialize_with = "serde_policy::weak"))]
    pub allow_weak_crypto: Toggle,
    /// Whether clients should request canonicalization.
    pub canonicalize: Toggle,
    /// Credential cache type.
    pub ccache_type: i32,
    /// Accepted clock skew.
    pub clockskew: Duration,
    /// Default credential cache name.
    pub default_ccache_name: String,
    /// Default client keytab path.
    pub default_client_keytab_name: String,
    /// Default service keytab path.
    pub default_keytab_name: String,
    /// Requested replay store; explicit persistent stores fail closed until WP-20.
    #[cfg_attr(feature = "serde", serde(default))]
    #[cfg_attr(feature = "serde", serde(deserialize_with = "serde_policy::replay"))]
    pub default_rcache_name: String,
    /// Default realm.
    pub default_realm: String,
    /// Preferred TGS enctype names.
    #[cfg_attr(feature = "serde", serde(deserialize_with = "serde_policy::enctypes"))]
    pub default_tgs_enctypes: Vec<String>,
    /// Preferred ticket enctype names.
    #[cfg_attr(feature = "serde", serde(deserialize_with = "serde_policy::enctypes"))]
    pub default_tkt_enctypes: Vec<String>,
    /// Whether hostnames should be DNS-canonicalized.
    pub dns_canonicalize_hostname: hostname::Canonicalization,
    /// Whether KDC DNS lookup is enabled.
    pub dns_lookup_kdc: Toggle,
    /// Whether realm DNS lookup is enabled.
    pub dns_lookup_realm: Toggle,
    /// Requested URI discovery; no URI resolver is enabled by parsing this value.
    #[cfg_attr(feature = "serde", serde(default))]
    pub dns_uri_lookup: Toggle,
    /// Requested GSS delegation restriction; credential forwarding is unavailable.
    #[cfg_attr(feature = "serde", serde(default))]
    pub enforce_ok_as_delegate: Toggle,
    /// Requested error presentation template; typed errors remain unchanged.
    #[cfg_attr(feature = "serde", serde(default))]
    pub err_fmt: String,
    /// Extra local addresses.
    pub extra_addresses: Vec<IpAddr>,
    /// Whether tickets should be forwardable.
    pub forwardable: Toggle,
    /// Whether acceptor hostname mismatches are ignored.
    pub ignore_acceptor_hostname: Toggle,
    /// Whether `.k5login` is authoritative.
    pub k5login_authoritative: Toggle,
    /// `.k5login` directory.
    pub k5login_directory: String,
    /// Requested KCM Mach service; KCM support remains unavailable.
    #[cfg_attr(feature = "serde", serde(default))]
    pub kcm_mach_service: String,
    /// Requested KCM Unix socket; parsing never connects to it.
    #[cfg_attr(feature = "serde", serde(default))]
    pub kcm_socket: String,
    /// Plugin location template; never used to load executable code.
    #[cfg_attr(feature = "serde", serde(default))]
    pub plugin_base_dir: String,
    /// Requested shortname suffix; None means unspecified, Some("") disables it.
    #[cfg_attr(feature = "serde", serde(default))]
    pub qualify_shortname: Option<String>,
    /// Total request deadline; nonzero profile values fail until a total budget exists.
    #[cfg_attr(feature = "serde", serde(default))]
    #[cfg_attr(feature = "serde", serde(deserialize_with = "serde_policy::deadline"))]
    pub request_timeout: Duration,
    /// Recognized SPAKE group names; no SPAKE exchange is enabled.
    #[cfg_attr(feature = "serde", serde(default))]
    pub spake_preauth_groups: Vec<String>,
    /// Requested channel-binding-aware GSS signaling; not yet implemented.
    #[cfg_attr(feature = "serde", serde(default))]
    #[cfg_attr(
        feature = "serde",
        serde(deserialize_with = "serde_policy::channel_binding")
    )]
    pub client_aware_channel_bindings: Toggle,
    /// KDC default options bit string as a 32-bit integer.
    pub kdc_default_options: u32,
    /// KDC time sync setting.
    pub kdc_time_sync: i32,
    /// Whether addresses should be omitted from tickets.
    #[cfg_attr(feature = "serde", serde(deserialize_with = "serde_policy::addresses"))]
    pub no_addresses: Toggle,
    /// Permitted enctype names.
    #[cfg_attr(feature = "serde", serde(deserialize_with = "serde_policy::enctypes"))]
    pub permitted_enctypes: Vec<String>,
    /// Whether `[libdefaults] permitted_enctypes` was explicitly configured.
    ///
    /// Parsing a `[libdefaults] permitted_enctypes` line sets this flag. The
    /// seeded default list is SHA2-first AES `[20, 19, 18, 17]`.
    /// Explicit request lists outside an explicit permitted list are rejected.
    /// `CryptoPolicy` always enforces permitted membership, regardless of this flag.
    ///
    /// The flag round-trips through serde. Serialized `LibDefaults` that lack
    /// this field deserialize it as `false`.
    ///
    /// Use [`Self::new`] and builders for programmatic construction; policy
    /// construction revalidates public fields and rejects an empty permitted list.
    #[cfg_attr(feature = "serde", serde(default))]
    pub permitted_enctypes_explicit: Toggle,
    /// Informational preauthentication preferences. Removed IDs 14/15 from serde
    /// remain visible here but are ignored and reported by [`Self::diagnostics`].
    #[cfg_attr(
        feature = "serde",
        serde(deserialize_with = "serde_policy::preferences")
    )]
    pub preferred_preauth_types: Vec<i32>,
    /// Whether tickets should be proxiable.
    pub proxiable: Toggle,
    /// Whether reverse DNS is enabled.
    pub rdns: Toggle,
    /// Realm suffix search setting.
    pub realm_try_domains: i32,
    /// Renewable ticket lifetime.
    pub renew_lifetime: Duration,
    /// Safe checksum type.
    #[cfg_attr(feature = "serde", serde(deserialize_with = "serde_policy::checksum"))]
    pub safe_checksum_type: i32,
    /// Ticket lifetime.
    pub ticket_lifetime: Duration,
    /// UDP preference limit.
    pub udp_preference_limit: i32,
    /// Whether AP-REQ verification failure should be fatal.
    #[cfg_attr(feature = "serde", serde(deserialize_with = "serde_policy::verify"))]
    pub verify_ap_req_nofail: Toggle,
    /// Mode applied to secure unsupported enctype selections.
    #[cfg_attr(feature = "serde", serde(default))]
    pub enctype_parse_mode: ParseMode,
    /// Diagnostics accumulated while resolving profile enctype expressions.
    #[cfg_attr(feature = "serde", serde(skip))]
    pub enctype_diagnostics: Vec<ConfigDiagnostic>,
}

impl LibDefaults {
    /// Override a family's minimum through trusted application code only.
    /// # Security
    /// Lower values weaken resistance to offline password guessing. Never copy
    /// a KDC-provided value into this override. No krb5.conf relation or serde
    /// field can set it; deserialization restores RFC defaults.
    /// # Errors
    /// Rejects zero and minima above the existing 2^24 work ceiling.
    #[inline]
    pub fn with_min_s2k_iterations(mut self, family: Family, minimum: u32) -> Result<Self, Policy> {
        self.min_s2k_iterations = self.min_s2k_iterations.with_minimum(family, minimum)?;
        Ok(self)
    }
    /// Diagnostics for skipped secure enctypes and ignored draft-9 preferences.
    /// Serde retains preference IDs for diagnostics, never for outgoing selection.
    #[inline]
    #[must_use]
    pub fn diagnostics(&self) -> Cow<'_, [ConfigDiagnostic]> {
        let ignored = self
            .preferred_preauth_types
            .iter()
            .copied()
            .filter(|id| matches!(*id, 14_i32 | 15_i32));
        let mut diagnostics = Cow::Borrowed(self.enctype_diagnostics.as_slice());
        for id in ignored {
            diagnostics
                .to_mut()
                .push(ConfigDiagnostic::IgnoredPreauthType { id });
        }
        diagnostics
    }

    /// Parsing mode used for subsequent expression resolution.
    #[inline]
    #[must_use]
    pub const fn parse_mode(&self) -> ParseMode {
        self.enctype_parse_mode
    }
    /// Stage `allow_weak_crypto`; enabled values are rejected by runtime policy construction.
    #[must_use]
    #[inline]
    pub const fn with_allow_weak_crypto(mut self, value: Toggle) -> Self {
        self.allow_weak_crypto = value;
        self
    }
    /// Sets `canonicalize`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_canonicalize(mut self, value: Toggle) -> Self {
        self.canonicalize = value;
        self
    }
    /// Sets `ccache_type`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_ccache_type(mut self, value: i32) -> Self {
        self.ccache_type = value;
        self
    }
    /// Sets `clockskew`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_clockskew(mut self, value: Duration) -> Self {
        self.clockskew = value;
        self
    }
    /// Sets `default_ccache_name`, preserving the other fields.
    #[must_use]
    #[inline]
    pub fn with_default_ccache_name(mut self, value: String) -> Self {
        self.default_ccache_name = value;
        self
    }
    /// Sets `default_client_keytab_name`, preserving the other fields.
    #[must_use]
    #[inline]
    pub fn with_default_client_keytab_name(mut self, value: String) -> Self {
        self.default_client_keytab_name = value;
        self
    }
    /// Sets `default_keytab_name`, preserving the other fields.
    #[must_use]
    #[inline]
    pub fn with_default_keytab_name(mut self, value: String) -> Self {
        self.default_keytab_name = value;
        self
    }
    /// Sets `default_realm`, preserving the other fields.
    #[must_use]
    #[inline]
    pub fn with_default_realm(mut self, value: String) -> Self {
        self.default_realm = value;
        self
    }
    /// Sets `default_tgs_enctypes`, preserving the other fields.
    #[must_use]
    #[inline]
    pub fn with_default_tgs_enctypes(mut self, value: Vec<String>) -> Self {
        self.default_tgs_enctypes = value;
        self
    }
    /// Sets `default_tkt_enctypes`, preserving the other fields.
    #[must_use]
    #[inline]
    pub fn with_default_tkt_enctypes(mut self, value: Vec<String>) -> Self {
        self.default_tkt_enctypes = value;
        self
    }
    /// Derives supported TGS enctype IDs from the current names and policy.
    #[must_use]
    #[inline]
    pub fn default_tgs_enctype_ids(&self) -> Vec<i32> {
        self.effective_enctype_ids(&self.default_tgs_enctypes)
    }
    /// Derives supported ticket enctype IDs from the current names and policy.
    #[must_use]
    #[inline]
    pub fn default_tkt_enctype_ids(&self) -> Vec<i32> {
        self.effective_enctype_ids(&self.default_tkt_enctypes)
    }
    /// Sets `dns_canonicalize_hostname`, preserving the other fields.
    #[must_use]
    #[inline]
    pub fn with_dns_canonicalize_hostname(mut self, value: Toggle) -> Self {
        self.dns_canonicalize_hostname = value.into();
        self
    }
    /// Sets `dns_lookup_kdc`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_dns_lookup_kdc(mut self, value: Toggle) -> Self {
        self.dns_lookup_kdc = value;
        self
    }
    /// Sets `dns_lookup_realm`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_dns_lookup_realm(mut self, value: Toggle) -> Self {
        self.dns_lookup_realm = value;
        self
    }
    /// Sets `extra_addresses`, preserving the other fields.
    #[must_use]
    #[inline]
    pub fn with_extra_addresses(mut self, value: Vec<IpAddr>) -> Self {
        self.extra_addresses = value;
        self
    }
    /// Sets `forwardable`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_forwardable(mut self, value: Toggle) -> Self {
        self.forwardable = value;
        self
    }
    /// Sets `ignore_acceptor_hostname`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_ignore_acceptor_hostname(mut self, value: Toggle) -> Self {
        self.ignore_acceptor_hostname = value;
        self
    }
    /// Sets `k5login_authoritative`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_k5login_authoritative(mut self, value: Toggle) -> Self {
        self.k5login_authoritative = value;
        self
    }
    /// Sets `k5login_directory`, preserving the other fields.
    #[must_use]
    #[inline]
    pub fn with_k5login_directory(mut self, value: String) -> Self {
        self.k5login_directory = value;
        self
    }
    /// Sets `kdc_default_options`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_kdc_default_options(mut self, value: u32) -> Self {
        self.kdc_default_options = value;
        self
    }
    /// Sets `kdc_time_sync`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_kdc_time_sync(mut self, value: i32) -> Self {
        self.kdc_time_sync = value;
        self
    }
    /// Sets `no_addresses`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_no_addresses(mut self, value: Toggle) -> Self {
        self.no_addresses = value;
        self
    }
    /// Sets `permitted_enctypes`, preserving the other fields.
    #[must_use]
    #[inline]
    pub fn with_permitted_enctypes(mut self, value: Vec<String>) -> Self {
        self.permitted_enctypes = value;
        self
    }
    /// Derives supported permitted enctype IDs from the current names and policy.
    #[must_use]
    #[inline]
    pub fn permitted_enctype_ids(&self) -> Vec<i32> {
        self.effective_enctype_ids(&self.permitted_enctypes)
    }
    /// Sets `permitted_enctypes_explicit`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_permitted_enctypes_explicit(mut self, value: Toggle) -> Self {
        self.permitted_enctypes_explicit = value;
        self
    }
    /// Sets `preferred_preauth_types`, preserving the other fields.
    #[must_use]
    #[inline]
    pub fn with_preferred_preauth_types(mut self, value: Vec<i32>) -> Self {
        self.preferred_preauth_types = value;
        self
    }
    /// Sets `proxiable`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_proxiable(mut self, value: Toggle) -> Self {
        self.proxiable = value;
        self
    }
    /// Sets `rdns`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_rdns(mut self, value: Toggle) -> Self {
        self.rdns = value;
        self
    }
    /// Sets `realm_try_domains`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_realm_try_domains(mut self, value: i32) -> Self {
        self.realm_try_domains = value;
        self
    }
    /// Sets `renew_lifetime`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_renew_lifetime(mut self, value: Duration) -> Self {
        self.renew_lifetime = value;
        self
    }
    /// Stage `safe_checksum_type`; forbidden values are rejected by runtime policy construction.
    #[must_use]
    #[inline]
    pub const fn with_safe_checksum_type(mut self, value: i32) -> Self {
        self.safe_checksum_type = value;
        self
    }
    /// Sets `ticket_lifetime`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_ticket_lifetime(mut self, value: Duration) -> Self {
        self.ticket_lifetime = value;
        self
    }
    /// Sets `udp_preference_limit`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_udp_preference_limit(mut self, value: i32) -> Self {
        self.udp_preference_limit = value;
        self
    }
    /// Sets `verify_ap_req_nofail`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_verify_ap_req_nofail(mut self, value: Toggle) -> Self {
        self.verify_ap_req_nofail = value;
        self
    }

    #[must_use]
    /// Create default libdefaults without reading the environment.
    #[inline]
    pub fn new() -> Self {
        Self::with_home(None)
    }

    /// Create defaults with an explicitly requested home-directory override.
    ///
    /// # Ambient input
    /// Reads `HOME` for `k5login_directory`; unset/non-Unicode means empty.
    /// The keytab identity template never reads `UID`.
    /// Use [`Self::new`] and set `k5login_directory` explicitly to avoid discovery.
    #[inline]
    #[must_use]
    pub fn from_env() -> Self {
        Self::with_home(env::var("HOME").ok())
    }

    /// Create defaults from an optional, already-read home directory.
    fn with_home(home: Option<String>) -> Self {
        let default_enctypes = DEFAULT_ENCTYPES
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>();
        Self {
            allow_rc4: Toggle::Disabled,
            min_s2k_iterations: Minima::new(),
            allow_des3: Toggle::Disabled,
            allow_weak_crypto: Toggle::Disabled,
            canonicalize: Toggle::Disabled,
            ccache_type: 4,
            clockskew: Duration::from_secs(300),
            default_ccache_name: String::new(),
            default_client_keytab_name: "/usr/local/var/krb5/user/%{euid}/client.keytab".to_owned(),
            default_keytab_name: "/etc/krb5.keytab".to_owned(),
            default_rcache_name: String::new(),
            default_realm: String::new(),
            default_tgs_enctypes: default_enctypes.clone(),
            default_tkt_enctypes: default_enctypes.clone(),
            dns_canonicalize_hostname: hostname::Canonicalization::Always,
            dns_lookup_kdc: Toggle::Disabled,
            dns_lookup_realm: Toggle::Disabled,
            dns_uri_lookup: Toggle::Disabled,
            enforce_ok_as_delegate: Toggle::Disabled,
            err_fmt: String::new(),
            extra_addresses: Vec::new(),
            forwardable: Toggle::Disabled,
            ignore_acceptor_hostname: Toggle::Disabled,
            k5login_authoritative: Toggle::Enabled,
            k5login_directory: home.unwrap_or_default(),
            kcm_mach_service: "org.h5l.kcm".to_owned(),
            kcm_socket: "/var/run/.heim_org.h5l.kcm-socket".to_owned(),
            plugin_base_dir: "%{LIBDIR}/krb5/plugins".to_owned(),
            qualify_shortname: None,
            request_timeout: Duration::ZERO,
            spake_preauth_groups: vec!["edwards25519".to_owned()],
            client_aware_channel_bindings: Toggle::Disabled,
            kdc_default_options: 0x0000_0010,
            kdc_time_sync: 1,
            no_addresses: Toggle::Enabled,
            permitted_enctypes: default_enctypes,
            permitted_enctypes_explicit: Toggle::Disabled,
            preferred_preauth_types: DEFAULT_PREAUTH_TYPES.to_vec(),
            proxiable: Toggle::Disabled,
            rdns: Toggle::Enabled,
            realm_try_domains: -1,
            renew_lifetime: Duration::ZERO,
            safe_checksum_type: 15,
            ticket_lifetime: Duration::from_hours(24),
            udp_preference_limit: 1465,
            verify_ap_req_nofail: Toggle::Disabled,
            enctype_parse_mode: ParseMode::Compatible,
            enctype_diagnostics: Vec::new(),
            #[cfg(feature = "serde")]
            protocol_relations: BTreeMap::new(),
        }
    }

    /// Apply one `[libdefaults]` section's lines, recording in `enctypes` which
    /// request enctype lists the section set explicitly.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed assignments, enabling removed protocols,
    /// invalid scalar values or unknown enctype tokens. Records expressions for
    /// final family-permission and request/permitted validation after all sections;
    /// `Config::parse` never returns a configuration with deferred parse errors.
    fn parse_lines(
        &mut self,
        lines: &[Line],
        enctypes: &mut EnctypeParseState,
    ) -> Result<(), Error> {
        for line in lines {
            let (raw_key, value) = parse_assignment(line, "libdefaults")?;
            let lowered = raw_key.to_ascii_lowercase();
            let key = lowered.as_str();
            protocol::relation(key, value)?;

            match key {
                "allow_rc4" => self.allow_rc4 = Toggle::from_bool(parse_boolean(value)?),
                "allow_des3" => self.allow_des3 = Toggle::from_bool(parse_boolean(value)?),
                "allow_weak_crypto" => {
                    self.allow_weak_crypto = Toggle::from_bool(parse_boolean(value)?);
                    self.reject_weak_crypto()?;
                }
                "canonicalize" => self.canonicalize = Toggle::from_bool(parse_boolean(value)?),
                "ccache_type" => self.ccache_type = parse_i32(value, line, key)?,
                "clockskew" => self.clockskew = libdefaults::duration::parse(value)?,
                "default_ccache_name" => value.clone_into(&mut self.default_ccache_name),
                "default_client_keytab_name" => {
                    value.clone_into(&mut self.default_client_keytab_name);
                }
                "default_keytab_name" => value.clone_into(&mut self.default_keytab_name),
                "default_rcache_name" => value.clone_into(&mut self.default_rcache_name),
                "err_fmt" => value.clone_into(&mut self.err_fmt),
                "default_realm" => value.clone_into(&mut self.default_realm),
                "default_tgs_enctypes" => {
                    enctypes.expressions.push(EnctypeExpr::parse(value)?);
                    self.default_tgs_enctypes = vec![value.to_owned()];
                    enctypes.tgs_explicit = true;
                }
                "default_tkt_enctypes" => {
                    enctypes.expressions.push(EnctypeExpr::parse(value)?);
                    self.default_tkt_enctypes = vec![value.to_owned()];
                    enctypes.tkt_explicit = true;
                }
                "dns_canonicalize_hostname" => {
                    self.dns_canonicalize_hostname = hostname::Canonicalization::parse(value)?;
                }
                "dns_lookup_kdc" => self.dns_lookup_kdc = Toggle::from_bool(parse_boolean(value)?),
                "dns_lookup_realm" => {
                    self.dns_lookup_realm = Toggle::from_bool(parse_boolean(value)?);
                }
                "dns_uri_lookup" => self.dns_uri_lookup = Toggle::from_bool(parse_boolean(value)?),
                "enforce_ok_as_delegate" => {
                    self.enforce_ok_as_delegate = Toggle::from_bool(parse_boolean(value)?);
                }
                "extra_addresses" => self.extra_addresses = parse_ip_addresses(value)?,
                "forwardable" => self.forwardable = Toggle::from_bool(parse_boolean(value)?),
                "ignore_acceptor_hostname" => {
                    self.ignore_acceptor_hostname = Toggle::from_bool(parse_boolean(value)?);
                }
                "k5login_authoritative" => {
                    self.k5login_authoritative = Toggle::from_bool(parse_boolean(value)?);
                }
                "k5login_directory" => value.clone_into(&mut self.k5login_directory),
                "kdc_default_options" => {
                    self.kdc_default_options = libdefaults::c2::option_bits(value, line)?;
                }
                "kdc_timesync" => self.kdc_time_sync = parse_i32(value, line, key)?,
                "noaddresses" | "no_addresses" => {
                    self.no_addresses = Toggle::from_bool(parse_boolean(value)?);
                }
                "permitted_enctypes" => {
                    enctypes.expressions.push(EnctypeExpr::parse(value)?);
                    self.permitted_enctypes = vec![value.to_owned()];
                    self.permitted_enctypes_explicit = Toggle::Enabled;
                }
                "preferred_preauth_types" => {
                    self.preferred_preauth_types = parse_i32_list(value, line, key)?;
                }
                "proxiable" => self.proxiable = Toggle::from_bool(parse_boolean(value)?),
                "rdns" => self.rdns = Toggle::from_bool(parse_boolean(value)?),
                "realm_try_domains" => self.realm_try_domains = parse_i32(value, line, key)?,
                "renew_lifetime" => self.renew_lifetime = libdefaults::duration::parse(value)?,
                "safe_checksum_type" => {
                    let id = selection::checksum_name(value)
                        .map_or_else(|| parse_i32(value, line, key), Ok)?;
                    selection::reject_checksum(id)?;
                    self.safe_checksum_type = id;
                }
                "ticket_lifetime" => self.ticket_lifetime = libdefaults::duration::parse(value)?,
                "udp_preference_limit" => {
                    self.udp_preference_limit = parse_i32(value, line, key)?;
                }
                "verify_ap_req_nofail" => {
                    self.verify_ap_req_nofail = Toggle::from_bool(parse_boolean(value)?);
                }
                _ => libdefaults::c2::parse(self, line)?,
            }
        }

        Ok(())
    }
}

include!("config/enctype_policy.rs");

impl Default for LibDefaults {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

/// One `[realms]` entry.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[non_exhaustive]
pub struct Realm {
    /// Unknown serde relations cannot enable removed protocol modes.
    #[cfg(feature = "serde")]
    #[serde(
        flatten,
        deserialize_with = "serde_policy::relations",
        skip_serializing
    )]
    pub protocol_relations: BTreeMap<String, String>,
    /// Realm name.
    #[cfg_attr(feature = "serde", serde(rename = "realm"))]
    pub name: String,
    /// Administrative server hosts.
    pub admin_server: Vec<String>,
    /// Default DNS domain.
    pub default_domain: String,
    /// KDC hosts.
    pub kdc: Vec<String>,
    /// Password-change server hosts.
    pub kpasswd_server: Vec<String>,
    /// Master KDC hosts.
    pub master_kdc: Vec<String>,
    /// Preferred primary KDC list; falls back to `master_kdc` only when absent.
    #[cfg_attr(feature = "serde", serde(default))]
    pub primary_kdc: Vec<String>,
    /// Typed explicitly configured realm relations.
    #[cfg_attr(feature = "serde", serde(default))]
    #[cfg_attr(
        feature = "serde",
        serde(deserialize_with = "serde_policy::realm_relations")
    )]
    pub relations: BTreeMap<String, section_values::Value>,
    /// Case-sensitive local principal-name mappings; no authorization is performed.
    #[cfg_attr(feature = "serde", serde(default))]
    pub auth_to_local_names: BTreeMap<String, String>,
}

impl Realm {
    /// Create a named realm with empty server lists.
    ///
    /// # Errors
    /// Returns [`Error::InvalidRealmsSection`] for an empty realm name.
    #[inline]
    pub fn new(realm: String) -> Result<Self, Error> {
        if realm.is_empty() {
            return Err(Error::InvalidRealmsSection("empty realm name".to_owned()));
        }
        Ok(Self {
            #[cfg(feature = "serde")]
            protocol_relations: BTreeMap::new(),
            name: realm,
            admin_server: Vec::new(),
            default_domain: String::new(),
            kdc: Vec::new(),
            kpasswd_server: Vec::new(),
            master_kdc: Vec::new(),
            primary_kdc: Vec::new(),
            relations: BTreeMap::new(),
            auth_to_local_names: BTreeMap::new(),
        })
    }

    /// Parse the lines of one realm's `{ ... }` block.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLine`] for a line that is not an assignment, and
    /// [`Error::Policy`] for an enabled removed-protocol directive.
    fn parse(name: &str, lines: &[Line]) -> Result<Self, Error> {
        let mut realm = Self::new(name.to_owned())?;

        for line in lines {
            let (raw_key, value) = parse_assignment(line, "realms")?;
            let lowered = raw_key.to_ascii_lowercase();
            let key = lowered.as_str();
            protocol::relation(key, value)?;

            match key {
                "admin_server" => {
                    realm.admin_server.push(value.to_owned());
                }
                "default_domain" => value.clone_into(&mut realm.default_domain),
                "kdc" => {
                    let with_port = add_default_port(value, 88);
                    realm.kdc.push(with_port);
                }
                "kpasswd_server" => {
                    realm.kpasswd_server.push(value.to_owned());
                }
                "master_kdc" => {
                    realm.master_kdc.push(value.to_owned());
                }
                "primary_kdc" => realm.primary_kdc.push(value.to_owned()),
                _ => {}
            }
        }

        if realm.primary_kdc.is_empty() {
            realm.primary_kdc.clone_from(&realm.master_kdc);
        }
        if realm.kpasswd_server.is_empty() {
            realm.kpasswd_server = realm
                .admin_server
                .iter()
                .map(|admin| {
                    if let Ok(address) = admin.parse::<SocketAddr>() {
                        return SocketAddr::new(address.ip(), 464).to_string();
                    }
                    if let Ok(address) = admin.parse::<IpAddr>() {
                        return SocketAddr::new(address, 464).to_string();
                    }
                    let host = admin.strip_circumfix('[', ']').unwrap_or_else(|| {
                        admin
                            .split_once(':')
                            .map_or(admin.as_str(), |(host, _)| host)
                    });
                    if host.contains(':') {
                        format!("[{host}]:464")
                    } else {
                        format!("{host}:464")
                    }
                })
                .collect();
        }

        Ok(realm)
    }
}

use crate::error::Config as Error;

/// Which `[libdefaults]` request enctype lists one parse set explicitly.
///
/// The state spans every `[libdefaults]` section of the parse, so a request
/// list from an earlier section is still validated against a
/// `permitted_enctypes` line from a later one.
#[derive(Clone, Debug, Default)]
pub(crate) struct EnctypeParseState {
    /// Selected explicit expressions, before family-permission resolution.
    expressions: Vec<EnctypeExpr>,
    /// A `default_tkt_enctypes` line was parsed.
    tkt_explicit: bool,
    /// A `default_tgs_enctypes` line was parsed.
    tgs_explicit: bool,
}

/// One non-empty, comment-stripped line of a section.
#[derive(Clone, Debug)]
struct Line {
    /// One-based line number in its independent source.
    number: usize,
    /// The line text after comment stripping and trimming.
    text: String,
    /// Decoded scalar content, distinct from source whitespace and syntax.
    value: Option<String>,
}

include!("config/sections.rs");

/// Parse a krb5 duration value.
///
/// Supported forms match gokrb5's `parseDuration`: seconds (`100`), unit
/// suffixes (`12h30m15s`), days plus suffixes (`1d12h`), and `h:m[:s]`.
///
/// # Errors
///
/// Returns [`Error::InvalidDuration`] for a value in none of these forms, and
/// [`Error::DurationOverflow`] for one whose seconds do not fit a `u64`.
#[inline]
pub fn parse_duration(value: &str) -> Result<Duration, Error> {
    let normalized = value.split_whitespace().collect::<String>();
    if normalized.is_empty() {
        return Err(Error::InvalidDuration(value.to_owned()));
    }

    if let Some((day_text, rest)) = normalized.split_once('d') {
        let Ok(days) = day_text.parse::<u64>() else {
            return Err(Error::InvalidDuration(value.to_owned()));
        };
        let day_seconds = days
            .checked_mul(24 * 60 * 60)
            .ok_or_else(|| Error::DurationOverflow(value.to_owned()))?;
        let mut duration = Duration::from_secs(day_seconds);
        if !rest.is_empty() {
            duration = duration
                .checked_add(parse_unit_duration(rest, value)?)
                .ok_or_else(|| Error::DurationOverflow(value.to_owned()))?;
        }
        return Ok(duration);
    }

    if let Ok(duration) = parse_unit_duration(&normalized, value) {
        return Ok(duration);
    }

    if let Ok(seconds) = normalized.parse::<u64>() {
        return Ok(Duration::from_secs(seconds));
    }

    if normalized.contains(':') {
        return parse_colon_duration(&normalized, value);
    }

    Err(Error::InvalidDuration(value.to_owned()))
}

/// Parse a krb5 boolean value.
///
/// # Errors
///
/// Returns [`Error::InvalidBoolean`] outside MIT's case-insensitive vocabulary:
/// `1`, `t`, `true`, `y`, `yes`, `on`, `0`, `false`, `n`, `no`, `nil`, `off`.
/// The existing gokrb5 `f` spelling remains a compatible extension.
#[inline]
pub fn parse_boolean(value: &str) -> Result<bool, Error> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "t" | "true" | "y" | "yes" | "on" => Ok(true),
        "0" | "f" | "false" | "n" | "no" | "nil" | "off" => Ok(false),
        _ => Err(Error::InvalidBoolean(value.to_owned())),
    }
}

#[must_use]
/// Parse enctype names to the subset of IDs implemented by gokrb5-compatible
/// crypto.
#[cfg(test)]
#[inline]
pub(crate) fn parse_supported_enctype_ids(
    enctypes: &[String],
    _allow_weak_crypto: bool,
) -> Vec<i32> {
    EnctypeExpr::parse(&enctypes.join(" "))
        .and_then(|expr| expr.resolve(Toggle::Enabled, Toggle::Enabled, ParseMode::Compatible))
        .map_or_else(
            |_| Vec::new(),
            |resolved| {
                resolved
                    .enctypes()
                    .iter()
                    .copied()
                    .map(KerberosEtype::etype_id)
                    .collect()
            },
        )
}

/// The gokrb5 JSON snapshot of a [`Config`], borrowing from it.
#[cfg(feature = "serde")]
#[derive(serde::Serialize)]
struct ConfigJson<'config> {
    /// [`Config::libdefaults`], as gokrb5's `LibDefaults`.
    #[serde(rename = "LibDefaults")]
    libdefaults: LibDefaultsJson<'config>,
    /// [`Config::realms`], as gokrb5's `Realms`.
    #[serde(rename = "Realms")]
    realms: Vec<RealmJson<'config>>,
    /// [`Config::domain_realm`], as gokrb5's `DomainRealm`.
    #[serde(rename = "DomainRealm")]
    domain_realm: &'config BTreeMap<String, String>,
}

#[cfg(feature = "serde")]
impl<'config> From<&'config Config> for ConfigJson<'config> {
    fn from(config: &'config Config) -> Self {
        Self {
            libdefaults: LibDefaultsJson::from(&config.libdefaults),
            realms: config.realms.iter().map(RealmJson::from).collect(),
            domain_realm: &config.domain_realm,
        }
    }
}

/// The gokrb5 JSON snapshot of a [`LibDefaults`], borrowing from it.
#[cfg(feature = "serde")]
#[derive(serde::Serialize)]
struct LibDefaultsJson<'config> {
    /// [`LibDefaults::allow_weak_crypto`], as gokrb5's `AllowWeakCrypto`.
    #[serde(rename = "AllowWeakCrypto")]
    allow_weak_crypto: Toggle,
    /// [`LibDefaults::canonicalize`], as gokrb5's `Canonicalize`.
    #[serde(rename = "Canonicalize")]
    canonicalize: Toggle,
    /// [`LibDefaults::ccache_type`], as gokrb5's `CCacheType`.
    #[serde(rename = "CCacheType")]
    ccache_type: i32,
    /// [`LibDefaults::clockskew`] in nanoseconds, as gokrb5's `Clockskew`.
    #[serde(rename = "Clockskew")]
    clockskew: u128,
    /// [`LibDefaults::default_ccache_name`], as gokrb5's `DefaultCCacheName`.
    #[serde(rename = "DefaultCCacheName")]
    default_ccache_name: &'config str,
    /// [`LibDefaults::default_client_keytab_name`], as gokrb5's `DefaultClientKeytabName`.
    #[serde(rename = "DefaultClientKeytabName")]
    default_client_keytab_name: &'config str,
    /// [`LibDefaults::default_keytab_name`], as gokrb5's `DefaultKeytabName`.
    #[serde(rename = "DefaultKeytabName")]
    default_keytab_name: &'config str,
    /// [`LibDefaults::default_realm`], as gokrb5's `DefaultRealm`.
    #[serde(rename = "DefaultRealm")]
    default_realm: &'config str,
    /// [`LibDefaults::default_tgs_enctypes`], as gokrb5's `DefaultTGSEnctypes`.
    #[serde(rename = "DefaultTGSEnctypes")]
    default_tgs_enctypes: &'config [String],
    /// [`LibDefaults::default_tkt_enctypes`], as gokrb5's `DefaultTktEnctypes`.
    #[serde(rename = "DefaultTktEnctypes")]
    default_tkt_enctypes: &'config [String],
    /// [`LibDefaults::default_tgs_enctype_ids`], as gokrb5's `DefaultTGSEnctypeIDs`.
    #[serde(rename = "DefaultTGSEnctypeIDs")]
    default_tgs_enctype_ids: Vec<i32>,
    /// [`LibDefaults::default_tkt_enctype_ids`], as gokrb5's `DefaultTktEnctypeIDs`.
    #[serde(rename = "DefaultTktEnctypeIDs")]
    default_tkt_enctype_ids: Vec<i32>,
    /// [`LibDefaults::dns_canonicalize_hostname`], as gokrb5's `DNSCanonicalizeHostname`.
    #[serde(rename = "DNSCanonicalizeHostname")]
    dns_canonicalize_hostname: hostname::Canonicalization,
    /// [`LibDefaults::dns_lookup_kdc`], as gokrb5's `DNSLookupKDC`.
    #[serde(rename = "DNSLookupKDC")]
    dns_lookup_kdc: Toggle,
    /// [`LibDefaults::dns_lookup_realm`], as gokrb5's `DNSLookupRealm`.
    #[serde(rename = "DNSLookupRealm")]
    dns_lookup_realm: Toggle,
    /// [`LibDefaults::extra_addresses`] as strings, or `None` when empty, as gokrb5's `ExtraAddresses`.
    #[serde(rename = "ExtraAddresses")]
    extra_addresses: Option<Vec<String>>,
    /// [`LibDefaults::forwardable`], as gokrb5's `Forwardable`.
    #[serde(rename = "Forwardable")]
    forwardable: Toggle,
    /// [`LibDefaults::ignore_acceptor_hostname`], as gokrb5's `IgnoreAcceptorHostname`.
    #[serde(rename = "IgnoreAcceptorHostname")]
    ignore_acceptor_hostname: Toggle,
    /// [`LibDefaults::k5login_authoritative`], as gokrb5's `K5LoginAuthoritative`.
    #[serde(rename = "K5LoginAuthoritative")]
    k5login_authoritative: Toggle,
    /// [`LibDefaults::k5login_directory`], as gokrb5's `K5LoginDirectory`.
    #[serde(rename = "K5LoginDirectory")]
    k5login_directory: &'config str,
    /// [`LibDefaults::kdc_default_options`] as a bit string, as gokrb5's `KDCDefaultOptions`.
    #[serde(rename = "KDCDefaultOptions")]
    kdc_default_options: KerberosBitStringJson,
    /// [`LibDefaults::kdc_time_sync`], as gokrb5's `KDCTimeSync`.
    #[serde(rename = "KDCTimeSync")]
    kdc_time_sync: i32,
    /// [`LibDefaults::no_addresses`], as gokrb5's `NoAddresses`.
    #[serde(rename = "NoAddresses")]
    no_addresses: Toggle,
    /// [`LibDefaults::permitted_enctypes`], as gokrb5's `PermittedEnctypes`.
    #[serde(rename = "PermittedEnctypes")]
    permitted_enctypes: &'config [String],
    /// [`LibDefaults::permitted_enctype_ids`], as gokrb5's `PermittedEnctypeIDs`.
    #[serde(rename = "PermittedEnctypeIDs")]
    permitted_enctype_ids: Vec<i32>,
    /// [`LibDefaults::preferred_preauth_types`], as gokrb5's `PreferredPreauthTypes`.
    #[serde(rename = "PreferredPreauthTypes")]
    preferred_preauth_types: &'config [i32],
    /// [`LibDefaults::proxiable`], as gokrb5's `Proxiable`.
    #[serde(rename = "Proxiable")]
    proxiable: Toggle,
    /// [`LibDefaults::rdns`], as gokrb5's `RDNS`.
    #[serde(rename = "RDNS")]
    rdns: Toggle,
    /// [`LibDefaults::realm_try_domains`], as gokrb5's `RealmTryDomains`.
    #[serde(rename = "RealmTryDomains")]
    realm_try_domains: i32,
    /// [`LibDefaults::renew_lifetime`] in nanoseconds, as gokrb5's `RenewLifetime`.
    #[serde(rename = "RenewLifetime")]
    renew_lifetime: u128,
    /// [`LibDefaults::safe_checksum_type`], as gokrb5's `SafeChecksumType`.
    #[serde(rename = "SafeChecksumType")]
    safe_checksum_type: i32,
    /// [`LibDefaults::ticket_lifetime`] in nanoseconds, as gokrb5's `TicketLifetime`.
    #[serde(rename = "TicketLifetime")]
    ticket_lifetime: u128,
    /// [`LibDefaults::udp_preference_limit`], as gokrb5's `UDPPreferenceLimit`.
    #[serde(rename = "UDPPreferenceLimit")]
    udp_preference_limit: i32,
    /// [`LibDefaults::verify_ap_req_nofail`], as gokrb5's `VerifyAPReqNofail`.
    #[serde(rename = "VerifyAPReqNofail")]
    verify_ap_req_nofail: Toggle,
}

#[cfg(feature = "serde")]
impl<'config> From<&'config LibDefaults> for LibDefaultsJson<'config> {
    fn from(libdefaults: &'config LibDefaults) -> Self {
        Self {
            allow_weak_crypto: libdefaults.allow_weak_crypto,
            canonicalize: libdefaults.canonicalize,
            ccache_type: libdefaults.ccache_type,
            clockskew: duration_nanos(libdefaults.clockskew),
            default_ccache_name: &libdefaults.default_ccache_name,
            default_client_keytab_name: &libdefaults.default_client_keytab_name,
            default_keytab_name: &libdefaults.default_keytab_name,
            default_realm: &libdefaults.default_realm,
            default_tgs_enctypes: &libdefaults.default_tgs_enctypes,
            default_tkt_enctypes: &libdefaults.default_tkt_enctypes,
            default_tgs_enctype_ids: libdefaults.default_tgs_enctype_ids(),
            default_tkt_enctype_ids: libdefaults.default_tkt_enctype_ids(),
            dns_canonicalize_hostname: libdefaults.dns_canonicalize_hostname,
            dns_lookup_kdc: libdefaults.dns_lookup_kdc,
            dns_lookup_realm: libdefaults.dns_lookup_realm,
            extra_addresses: optional_ip_addresses(&libdefaults.extra_addresses),
            forwardable: libdefaults.forwardable,
            ignore_acceptor_hostname: libdefaults.ignore_acceptor_hostname,
            k5login_authoritative: libdefaults.k5login_authoritative,
            k5login_directory: &libdefaults.k5login_directory,
            kdc_default_options: KerberosBitStringJson::from_u32(libdefaults.kdc_default_options),
            kdc_time_sync: libdefaults.kdc_time_sync,
            no_addresses: libdefaults.no_addresses,
            permitted_enctypes: &libdefaults.permitted_enctypes,
            permitted_enctype_ids: libdefaults.permitted_enctype_ids(),
            preferred_preauth_types: &libdefaults.preferred_preauth_types,
            proxiable: libdefaults.proxiable,
            rdns: libdefaults.rdns,
            realm_try_domains: libdefaults.realm_try_domains,
            renew_lifetime: duration_nanos(libdefaults.renew_lifetime),
            safe_checksum_type: libdefaults.safe_checksum_type,
            ticket_lifetime: duration_nanos(libdefaults.ticket_lifetime),
            udp_preference_limit: libdefaults.udp_preference_limit,
            verify_ap_req_nofail: libdefaults.verify_ap_req_nofail,
        }
    }
}

/// The gokrb5 JSON snapshot of a [`Realm`], borrowing from it.
#[cfg(feature = "serde")]
#[derive(serde::Serialize)]
struct RealmJson<'config> {
    /// [`Realm::realm`], as gokrb5's `Realm`.
    #[serde(rename = "Realm")]
    realm: &'config str,
    /// [`Realm::admin_server`], or `None` when empty, as gokrb5's `AdminServer`.
    #[serde(rename = "AdminServer")]
    admin_server: Option<&'config [String]>,
    /// [`Realm::default_domain`], as gokrb5's `DefaultDomain`.
    #[serde(rename = "DefaultDomain")]
    default_domain: &'config str,
    /// [`Realm::kdc`], or `None` when empty, as gokrb5's `KDC`.
    #[serde(rename = "KDC")]
    kdc: Option<&'config [String]>,
    /// [`Realm::kpasswd_server`], or `None` when empty, as gokrb5's `KPasswdServer`.
    #[serde(rename = "KPasswdServer")]
    kpasswd_server: Option<&'config [String]>,
    /// [`Realm::master_kdc`], or `None` when empty, as gokrb5's `MasterKDC`.
    #[serde(rename = "MasterKDC")]
    master_kdc: Option<&'config [String]>,
}

#[cfg(feature = "serde")]
impl<'config> From<&'config Realm> for RealmJson<'config> {
    fn from(realm: &'config Realm) -> Self {
        Self {
            realm: &realm.name,
            admin_server: optional_slice(&realm.admin_server),
            default_domain: &realm.default_domain,
            kdc: optional_slice(&realm.kdc),
            kpasswd_server: optional_slice(&realm.kpasswd_server),
            master_kdc: optional_slice(&realm.master_kdc),
        }
    }
}

/// A gokrb5 `asn1.BitString` JSON snapshot.
#[cfg(feature = "serde")]
#[derive(serde::Serialize)]
struct KerberosBitStringJson {
    /// The standard base64 of the big-endian bytes, as gokrb5's `Bytes`.
    #[serde(rename = "Bytes")]
    bytes: String,
    /// The number of bits, as gokrb5's `BitLength`.
    #[serde(rename = "BitLength")]
    bit_length: usize,
}

#[cfg(feature = "serde")]
impl KerberosBitStringJson {
    /// The 32-bit string whose bits are `value`, most significant first.
    fn from_u32(value: u32) -> Self {
        let bytes = value.to_be_bytes();
        Self {
            bytes: base64_standard(&bytes),
            // Saturating: four bytes are 32 bits.
            bit_length: bytes.len().saturating_mul(8),
        }
    }
}

/// `values`, or `None` when it is empty (gokrb5 renders an empty list as
/// `null`).
#[cfg(feature = "serde")]
const fn optional_slice<T>(values: &[T]) -> Option<&[T]> {
    if values.is_empty() {
        None
    } else {
        Some(values)
    }
}

/// `values` rendered as strings, or `None` when it is empty.
#[cfg(feature = "serde")]
fn optional_ip_addresses(values: &[IpAddr]) -> Option<Vec<String>> {
    if values.is_empty() {
        None
    } else {
        Some(values.iter().map(ToString::to_string).collect())
    }
}

/// `duration` in nanoseconds, as Go's `time.Duration` serializes.
#[cfg(feature = "serde")]
const fn duration_nanos(duration: Duration) -> u128 {
    duration.as_nanos()
}

/// The standard (RFC 4648, padded) base64 encoding of `bytes`.
#[cfg(feature = "serde")]
fn base64_standard(bytes: &[u8]) -> String {
    // Saturating: a capacity hint; the length of a real slice cannot reach it.
    let mut output = String::with_capacity(bytes.len().div_ceil(3).saturating_mul(4));

    for chunk in bytes.chunks(3) {
        let (first, second, third) = match *chunk {
            [first] => (first, 0_u8, 0_u8),
            [first, second] => (first, second, 0_u8),
            [first, second, third, ..] => (first, second, third),
            [] => continue,
        };
        let value = (u32::from(first) << 16_u32) | (u32::from(second) << 8_u32) | u32::from(third);

        output.push(base64_char(value >> 18_u32));
        output.push(base64_char(value >> 12_u32));
        if chunk.len() > 1 {
            output.push(base64_char(value >> 6_u32));
        } else {
            output.push('=');
        }
        if chunk.len() > 2 {
            output.push(base64_char(value));
        } else {
            output.push('=');
        }
    }

    output
}

/// The standard base64 alphabet character for the low six bits of `value`.
#[cfg(feature = "serde")]
fn base64_char(value: u32) -> char {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    // The six-bit index is always within the 64-entry table; the padding
    // character stands in for the impossible miss.
    usize::try_from(value & 0x3f_u32)
        .ok()
        .and_then(|index| TABLE.get(index))
        .map_or('=', |byte| char::from(*byte))
}

/// Parse a duration made of `<number><unit>` groups, where the unit is `h`,
/// `m` or `s` (`12h30m15s`).
///
/// # Errors
///
/// Returns [`Error::InvalidDuration`] naming `original` for an empty input, a
/// group without digits, a number that does not fit a `u64`, or an unknown
/// unit, and [`Error::DurationOverflow`] when the total does not fit.
fn parse_unit_duration(input: &str, original: &str) -> Result<Duration, Error> {
    let mut chars = input.char_indices().peekable();
    let mut duration = Duration::ZERO;
    let mut parsed_any = false;

    while chars.peek().is_some() {
        let start = chars.peek().map_or(0, |(index, _)| *index);
        while matches!(chars.peek(), Some((_, ch)) if ch.is_ascii_digit()) {
            let _: Option<(usize, char)> = chars.next();
        }
        let number_end = chars.peek().map_or(input.len(), |(index, _)| *index);
        if number_end == start {
            return Err(Error::InvalidDuration(original.to_owned()));
        }
        // Both ends are `char_indices` boundaries, so the slice always exists.
        let Some(Ok(number)) = input.get(start..number_end).map(str::parse::<u64>) else {
            return Err(Error::InvalidDuration(original.to_owned()));
        };

        let unit_start = number_end;
        while matches!(chars.peek(), Some((_, ch)) if ch.is_ascii_alphabetic()) {
            let _: Option<(usize, char)> = chars.next();
        }
        let unit_end = chars.peek().map_or(input.len(), |(index, _)| *index);
        let unit = input.get(unit_start..unit_end).unwrap_or_default();
        let seconds = match unit {
            "h" => number
                .checked_mul(60 * 60)
                .ok_or_else(|| Error::DurationOverflow(original.to_owned()))?,
            "m" => number
                .checked_mul(60)
                .ok_or_else(|| Error::DurationOverflow(original.to_owned()))?,
            "s" => number,
            _ => return Err(Error::InvalidDuration(original.to_owned())),
        };
        duration = duration
            .checked_add(Duration::from_secs(seconds))
            .ok_or_else(|| Error::DurationOverflow(original.to_owned()))?;
        parsed_any = true;
    }

    if parsed_any {
        Ok(duration)
    } else {
        Err(Error::InvalidDuration(original.to_owned()))
    }
}

/// Parse an `h:m[:s]` duration.
///
/// # Errors
///
/// Returns [`Error::InvalidDuration`] naming `original` unless the input has
/// two or three `:`-separated `u64` fields, and [`Error::DurationOverflow`]
/// when the total seconds do not fit.
fn parse_colon_duration(input: &str, original: &str) -> Result<Duration, Error> {
    let parts = input.split(':').collect::<Vec<_>>();
    let (hours_text, minutes_text, seconds_text) = match *parts.as_slice() {
        [hours, minutes] => (hours, minutes, None),
        [hours, minutes, seconds] => (hours, minutes, Some(seconds)),
        _ => return Err(Error::InvalidDuration(original.to_owned())),
    };
    let invalid = || Error::InvalidDuration(original.to_owned());
    let hours = hours_text.parse::<u64>().ok().ok_or_else(invalid)?;
    let minutes = minutes_text.parse::<u64>().ok().ok_or_else(invalid)?;
    let seconds = match seconds_text {
        Some(text) => text.parse::<u64>().ok().ok_or_else(invalid)?,
        None => 0_u64,
    };

    let total = hours
        .checked_mul(60 * 60)
        .and_then(|value| value.checked_add(minutes.checked_mul(60)?))
        .and_then(|value| value.checked_add(seconds))
        .ok_or_else(|| Error::DurationOverflow(original.to_owned()))?;
    Ok(Duration::from_secs(total))
}

/// Parse a decimal `i32` value of `key`.
///
/// # Errors
///
/// Returns [`Error::InvalidInteger`] when the value is not a decimal `i32`.
fn parse_i32(value: &str, line: &Line, key: &str) -> Result<i32, Error> {
    value
        .parse()
        .ok()
        .ok_or_else(|| invalid_integer(value, line, key))
}

/// Parse a list of decimal `i32` values of `key`, separated by commas or
/// whitespace.
///
/// # Errors
///
/// Returns [`Error::InvalidInteger`] for the first item that is not a decimal
/// `i32`.
fn parse_i32_list(value: &str, line: &Line, key: &str) -> Result<Vec<i32>, Error> {
    value
        .split([',', ' ', '\t'])
        .filter(|part| !part.trim().is_empty())
        .map(|part| parse_i32(part.trim(), line, key))
        .collect()
}

/// The [`Error::InvalidInteger`] for `value` of `key` on `line`.
fn invalid_integer(value: &str, line: &Line, key: &str) -> Error {
    Error::InvalidInteger {
        line: line.number,
        key: key.to_owned(),
        value: value.to_owned(),
    }
}

/// Decode an address list without silently narrowing malformed input.
/// # Errors
/// Returns a typed failure naming the malformed address token.
fn parse_ip_addresses(value: &str) -> Result<Vec<IpAddr>, Error> {
    value
        .split(|ch: char| ch == ',' || ch.is_ascii_whitespace())
        .filter(|part| !part.is_empty())
        .map(|part| {
            part.parse()
                .map_err(|_invalid_address| Error::InvalidAddress(part.to_owned()))
        })
        .collect()
}

/// Append a default port to a literal endpoint already admitted by the profile.
fn add_default_port(value: &str, port: u16) -> String {
    if value.contains(':') {
        value.to_owned()
    } else {
        format!("{value}:{port}")
    }
}

/// One `include`/`includedir` directive, split from its argument.
#[derive(Clone, Copy, Debug)]
enum IncludeDirective<'line> {
    /// `include <file>`: splice one file.
    File(&'line str),
    /// `includedir <dir>`: splice every file MIT's filter accepts, in
    /// alphanumeric order.
    Directory(&'line str),
}

impl<'line> IncludeDirective<'line> {
    /// The directive a line carries, or `None` when it carries neither.
    ///
    /// Recognized as the first token of the line - which is where MIT's
    /// `krb5.conf` documentation places them ("at the beginning of a line") and
    /// where `prof_parse.c:282-291` tests for them. MIT requires the keyword at
    /// column 0; leading whitespace is accepted here too, because a line this
    /// parser does not recognize at the top level is skipped silently, and a
    /// directive must never be ignored silently.
    fn parse(line: &'line str) -> Option<Self> {
        // `includedir` first: `include` is a prefix of it.
        if let Some(rest) = line.strip_prefix("includedir")
            && starts_with_whitespace(rest)
        {
            return Some(Self::Directory(rest.trim()));
        }
        let rest = line.strip_prefix("include")?;
        if starts_with_whitespace(rest) {
            return Some(Self::File(rest.trim()));
        }
        None
    }
}

/// Whether `text` begins with whitespace (and so the keyword before it was a
/// whole token).
fn starts_with_whitespace(text: &str) -> bool {
    text.chars()
        .next()
        .is_some_and(profile_syntax::tag_whitespace)
}

/// Whether `name` is one an `includedir` accepts, per MIT's `valid_name`.
///
/// MIT's rule (`krb5-1.21-final`, `src/util/profile/prof_parse.c:224-243`):
/// dotfiles - "editor or filesystem artifacts" - are skipped, a name ending in
/// `.conf` is included, and so is a name made only of alphanumeric characters,
/// dashes and underscores. Like MIT's, it works on the name's bytes.
fn includedir_name_is_valid(name: &[u8]) -> bool {
    if name.starts_with(b".") {
        return false;
    }
    if name.len() >= 5 && name.ends_with(b".conf") {
        return true;
    }
    !name.is_empty()
        && name
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-' || *byte == b'_')
}

/// The `include`/`includedir` budget one parse runs under, and the files and
/// directories whose directives it is expanding right now.
///
/// MIT's parser has neither: it recurses on whatever the configuration names.
/// The caps ([`MAX_INCLUDE_DEPTH`], [`MAX_INCLUDE_FILES`], [`MAX_INCLUDE_BYTES`])
/// and the cycle check on canonical paths are a deliberate divergence from MIT.
#[derive(Default)]
struct IncludeExpansion {
    /// Ordered shared tree; syntax state belongs to each `expand` invocation.
    profile: profile::Profile,
    /// Canonical paths of the files and directories being expanded, outermost
    /// first: the cycle check is a membership test on this chain, so a file - or
    /// a directory reached again through a symlink - that is re-entered by one
    /// of its own descendants is a named [`Error::IncludeCycle`] rather than
    /// unbounded recursion. The configuration's own top-level files are on it
    /// before the first directive expands ([`Self::with_roots`]), so a root that
    /// includes itself is a cycle too.
    open: Vec<PathBuf>,
    /// How many files the directives have included so far.
    files: usize,
    /// How many bytes of included content have been read so far.
    bytes: usize,
}

impl IncludeExpansion {
    /// The same expansion, with the canonical paths the configuration's own
    /// text came from already on the open chain.
    ///
    /// A caller that read its text from files hands them over; a caller parsing
    /// a string hands over nothing, because a string has no path to re-enter.
    fn with_roots<I>(mut self, roots: I) -> Self
    where
        I: IntoIterator<Item = PathBuf>,
    {
        self.open.extend(roots);
        self
    }

    /// Replace every directive in `input` with what it names, recursively.
    ///
    /// `depth` is the include depth of the text itself: the configuration a
    /// caller handed over is depth 0, and each `include` adds one. Included
    /// sources have independent grammar state at every nesting level; parsing
    /// resumes the parent's section and open groups after each include.
    ///
    /// # Errors
    ///
    /// Returns the [`Self::include_file`] or [`Self::include_dir`] error of the
    /// first directive whose target cannot be read or breaks a limit.
    fn expand(&mut self, input: &str, depth: usize) -> Result<(), Error> {
        let mut state = profile_syntax::State::default();
        let mut lines = input.lines().enumerate();
        while let Some((index, line)) = lines.next() {
            let cleaned = profile_syntax::comments(line)
                .trim_start_matches(profile_syntax::tag_whitespace)
                .trim_end_matches(profile_syntax::tag_whitespace);
            if cleaned.is_empty() {
                continue;
            }
            if cleaned
                .split(profile_syntax::tag_whitespace)
                .next()
                .is_some_and(|word| word.eq_ignore_ascii_case("module"))
                && !state.local_mapping_assignment(cleaned)
            {
                return Err(Error::UnsupportedDynamicModule);
            }
            if !state.local_mapping_assignment(cleaned)
                && let Some(directive) = IncludeDirective::parse(cleaned)
            {
                let opens_subsection = state.needs_include_lookahead()
                    && lines
                        .clone()
                        .map(|(_, text)| {
                            #[cfg(test)]
                            fork_tests::LOOKAHEAD_SCANS
                                .with(|count| count.set(count.get().saturating_add(1)));
                            profile_syntax::comments(text).trim()
                        })
                        .find(|text| !text.is_empty() && IncludeDirective::parse(text).is_none())
                        == Some("{");
                state.before_include(opens_subsection, &mut self.profile)?;
                self.splice(directive, depth)?;
                continue;
            }
            state.line(
                &Line {
                    number: index.saturating_add(1),
                    text: cleaned.to_owned(),
                    value: None,
                },
                &mut self.profile,
            )?;
        }
        state.finish(&mut self.profile)
    }

    /// What one directive contributes to the expanded text.
    ///
    /// # Errors
    ///
    /// Returns the [`Self::include_file`] or [`Self::include_dir`] error for
    /// the directive's target.
    fn splice(&mut self, directive: IncludeDirective<'_>, depth: usize) -> Result<(), Error> {
        let argument = match directive {
            IncludeDirective::File(value) | IncludeDirective::Directory(value) => value,
        };
        if !Path::new(argument).is_absolute() {
            return Err(Error::IncludeFile {
                path: PathBuf::from(argument),
                source: io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "include path must be absolute",
                ),
            });
        }
        let next_depth = depth.saturating_add(1);
        match directive {
            IncludeDirective::File(value) => self.include_file(Path::new(value), next_depth),
            IncludeDirective::Directory(value) => self.include_dir(Path::new(value), next_depth),
        }
    }

    /// One `include`: read the file and expand its own directives in turn.
    ///
    /// A path is used exactly as the configuration spells it, which is what MIT
    /// does (`fopen` on the token, relative to the process's working directory
    /// when it is relative) - no rebasing on the including file's directory.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IncludeTooDeep`] past [`MAX_INCLUDE_DEPTH`],
    /// [`Error::IncludeFile`] for a file that cannot be resolved or read,
    /// [`Error::IncludeCycle`] for a file already being expanded, the
    /// [`Self::read_include`] limit errors, and the errors of its own
    /// directives.
    fn include_file(&mut self, path: &Path, depth: usize) -> Result<(), Error> {
        // Saturating: `MAX_INCLUDE_DEPTH` refuses the chain long before
        // `usize::MAX`.
        let file_depth = depth;
        if file_depth > MAX_INCLUDE_DEPTH {
            return Err(Error::IncludeTooDeep {
                depth: file_depth,
                limit: MAX_INCLUDE_DEPTH,
            });
        }
        // Resolving the path is how a file that does not exist is named rather
        // than skipped; it also gives the cycle check its canonical key.
        let canonical =
            fs::canonicalize(path).map_err(|source| profile_file_error(path, depth, source))?;
        if self.open.contains(&canonical) {
            return Err(Error::IncludeCycle {
                path: path.to_path_buf(),
            });
        }
        let content = self.read_include(path, depth)?;
        self.open.push(canonical);
        let expanded = self.expand(&content, file_depth);
        drop(self.open.pop());
        expanded
    }

    /// One included file's text, counted against the file and byte caps.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IncludeTooMany`] past [`MAX_INCLUDE_FILES`],
    /// [`Error::IncludeTooLarge`] past [`MAX_INCLUDE_BYTES`], and
    /// [`Error::IncludeFile`] for a file that cannot be opened or read, or that
    /// is not UTF-8 text.
    fn read_include(&mut self, path: &Path, depth: usize) -> Result<String, Error> {
        use std::fs::File;

        // Saturating: `MAX_INCLUDE_FILES` refuses long before `usize::MAX`.
        let count = self.files.saturating_add(1);
        if count > MAX_INCLUDE_FILES {
            return Err(Error::IncludeTooMany {
                count,
                limit: MAX_INCLUDE_FILES,
            });
        }
        // Read at most one byte past what is left of the budget, so an oversize
        // file is refused without reading it into memory first.
        let remaining = MAX_INCLUDE_BYTES.saturating_sub(self.bytes);
        let file = File::open(path).map_err(|source| profile_file_error(path, depth, source))?;
        // Saturating: the limit plus one is what is read, and a `usize` budget
        // past `u64` is clamped rather than wrapped.
        let limit = u64::try_from(remaining)
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        let mut bytes = Vec::new();
        let _: usize = file
            .take(limit)
            .read_to_end(&mut bytes)
            .map_err(|source| profile_file_error(path, depth, source))?;
        if bytes.len() > remaining {
            return Err(Error::IncludeTooLarge {
                bytes: self.bytes.saturating_add(bytes.len()),
                limit: MAX_INCLUDE_BYTES,
            });
        }
        let content = String::from_utf8(bytes).map_err(|error| Error::IncludeFile {
            path: path.to_path_buf(),
            source: io::Error::new(
                io::ErrorKind::InvalidData,
                format!("not UTF-8 text: {error}"),
            ),
        })?;
        self.files = count;
        // Saturating: the byte check above keeps the total within
        // `MAX_INCLUDE_BYTES`.
        self.bytes = self.bytes.saturating_add(content.len());
        Ok(content)
    }

    /// One `includedir`: every accepted name, in alphanumeric order.
    ///
    /// The file cap is enforced while the directory is scanned, so a directory
    /// with more accepted names than the budget allows is refused before any
    /// name is sorted or any file is read.
    ///
    /// The directory's canonical path joins the open chain for as long as its
    /// files are being expanded, so a directory that is reached again through a
    /// symlink while it is being read - and an entry that is one of the
    /// directories already being read - is [`Error::IncludeCycle`] naming the
    /// path the configuration spelled, rather than a chain that only runs out of
    /// depth. The path is used exactly as the configuration spells it, as an
    /// `include` path is (`fopen` on the token, MIT's own rule).
    ///
    /// # Errors
    ///
    /// Returns [`Error::IncludeTooDeep`] past [`MAX_INCLUDE_DEPTH`],
    /// [`Error::IncludeDir`] for a directory that cannot be resolved or
    /// listed, [`Error::IncludeCycle`] for a directory already being expanded,
    /// [`Error::IncludeTooMany`] once its accepted names pass
    /// [`MAX_INCLUDE_FILES`], and the [`Self::include_file`] error of any
    /// accepted file.
    fn include_dir(&mut self, dir: &Path, depth: usize) -> Result<(), Error> {
        (depth <= MAX_INCLUDE_DEPTH).ok_or(Error::IncludeTooDeep {
            depth,
            limit: MAX_INCLUDE_DEPTH,
        })?;
        let canonical = fs::canonicalize(dir).map_err(|source| Error::IncludeDir {
            path: dir.to_path_buf(),
            source,
        })?;
        if self.open.contains(&canonical) {
            return Err(Error::IncludeCycle {
                path: dir.to_path_buf(),
            });
        }
        let entries = fs::read_dir(dir).map_err(|source| Error::IncludeDir {
            path: dir.to_path_buf(),
            source,
        })?;
        let mut names = Vec::new();
        for listed in entries {
            let entry = listed.map_err(|source| Error::IncludeDir {
                path: dir.to_path_buf(),
                source,
            })?;
            // Matched as bytes, like MIT's `valid_name`, so a `.conf` name that is
            // not UTF-8 is included too; the path used to open a file is always
            // the one the directory entry carries.
            let name = entry.file_name();
            if includedir_name_is_valid(name.as_encoded_bytes()) {
                // Saturating: `MAX_INCLUDE_FILES` refuses long before
                // `usize::MAX`.
                let count = self.files.saturating_add(names.len()).saturating_add(1);
                if count > MAX_INCLUDE_FILES {
                    return Err(Error::IncludeTooMany {
                        count,
                        limit: MAX_INCLUDE_FILES,
                    });
                }
                names.push(name);
            }
        }
        // Byte order, which is `strcmp` order: MIT reads the directory's accepted
        // files in alphanumeric order.
        names.sort_by(|left, right| left.as_encoded_bytes().cmp(right.as_encoded_bytes()));
        self.open.push(canonical);
        for name in names {
            self.include_file(&dir.join(name), depth)?;
        }
        drop(self.open.pop());
        Ok(())
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error;
    use std::{
        env, fs,
        path::PathBuf,
        process,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::{Config, Error};

    /// An existing platform default file is loaded even when an earlier
    /// candidate is missing.
    #[test]
    fn load_default_paths_loads_existing_platform_candidate() -> Result<(), Box<dyn error::Error>> {
        let path = temp_file("load-default-paths")?;
        fs::write(
            &path,
            "
[libdefaults]
 default_realm = DEFAULT.GOKRB5
",
        )?;

        let loaded =
            Config::load_default_paths([PathBuf::from("/missing/krb5.conf"), path.clone()]);
        fs::remove_file(&path)?;
        let config = loaded?;

        assert_eq!(config.libdefaults.default_realm, "DEFAULT.GOKRB5");
        Ok(())
    }

    /// The embedded configuration is parsed when no platform default exists.
    #[test]
    fn load_default_or_parse_paths_uses_embedded_when_no_default_exists()
    -> Result<(), Box<dyn error::Error>> {
        let config = Config::load_default_or_parse_paths(
            "
[libdefaults]
 default_realm = EMBEDDED.GOKRB5
",
            [PathBuf::from("/missing/krb5.conf")],
        )?;

        assert_eq!(config.libdefaults.default_realm, "EMBEDDED.GOKRB5");
        Ok(())
    }

    /// An existing but invalid platform default is an error, not a reason to
    /// fall back to the embedded configuration.
    #[test]
    fn load_default_or_parse_paths_does_not_fallback_when_default_is_invalid()
    -> Result<(), Box<dyn error::Error>> {
        let path = temp_file("load-default-invalid")?;
        fs::write(
            &path,
            "
[libdefaults]
 dns_lookup_kdc = maybe
",
        )?;

        let loaded = Config::load_default_or_parse_paths(
            "
[libdefaults]
 default_realm = EMBEDDED.GOKRB5
",
            [path.clone()],
        );
        fs::remove_file(&path)?;
        let Err(error) = loaded else {
            return Err("an invalid existing default must be returned as an error".into());
        };

        assert!(
            matches!(&error, Error::InvalidBoolean(value) if value == "maybe"),
            "the invalid boolean must be reported: {error:?}"
        );
        Ok(())
    }

    /// A fresh path in the temporary directory, unique to this process and
    /// call.
    fn temp_file(name: &str) -> Result<PathBuf, Box<dyn error::Error>> {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        Ok(env::temp_dir().join(format!(
            "rskrb5-config-unit-{name}-{}-{nanos}",
            process::id()
        )))
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::too_long_first_doc_paragraph,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod fork_tests {
    use core::{cell::Cell, error};
    use std::{
        env, fs,
        io::{self, Write as _},
        path::{Path, PathBuf},
        process::{self, Command},
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::{
        Config, Error, LibDefaults, MAX_INCLUDE_BYTES, MAX_INCLUDE_DEPTH, MAX_INCLUDE_FILES,
    };

    thread_local! {
        /// Suffix lines visited by include lookahead, isolated per test thread.
        pub(super) static LOOKAHEAD_SCANS: Cell<usize> = const { Cell::new(0) };
    }

    /// Include runs scan their suffix at most once while resolving a pending scalar.
    #[test]
    fn include_lookahead_work_is_linear() -> Result<(), Box<dyn error::Error>> {
        let directory = fixture_dir("linear-lookahead")?;
        let child = directory.join("empty.conf");
        fs::write(&child, "")?;
        let directive = format!("include {}\n", child.display());
        for prefix in ["[libdefaults]\n", "[libdefaults]\ndefault_realm =\n"] {
            let mut input = prefix.to_owned();
            input.push_str(&directive.repeat(MAX_INCLUDE_FILES));
            input.push_str(&"# comment\n".repeat(4096));
            assert!(input.len() < MAX_INCLUDE_BYTES);
            LOOKAHEAD_SCANS.with(|count| count.set(0));
            drop(Config::parse(&input)?);
            LOOKAHEAD_SCANS.with(|count| {
                assert!(
                    count.get() <= input.lines().count(),
                    "suffix scans {} exceed source lines {}",
                    count.get(),
                    input.lines().count()
                );
            });
        }
        fs::remove_dir_all(directory)?;
        Ok(())
    }

    /// The marker the parent sets when it re-executes this binary as a probe, so
    /// a normal run leaves the probe test inert.
    const PROBE_MARKER: &str = "RSKRB5_ENV_FREE_PROBE";
    /// Every probe line carries this prefix, so the parent can ignore the test
    /// harness's own output.
    const PROBE_PREFIX: &str = "rskrb5-probe:";
    /// This probe test's name in this binary, for the child's `--exact`.
    const PROBE_TEST: &str = "configuration::fork_tests::env_free_fields_probe_child";
    /// The hostile `UID` the parent gives the child.
    const HOSTILE_UID: &str = "4242";
    /// The hostile `HOME` the parent gives the child.
    const HOSTILE_HOME: &str = "/attacker/home";

    /// The unexpanded identity template every default constructor preserves.
    const ENV_FREE_CLIENT_KEYTAB: &str = "/usr/local/var/krb5/user/%{euid}/client.keytab";

    /// The environment-free constructor's fields, and - as the control - the
    /// environment-reading constructor's, printed for the parent to assert on.
    #[test]
    fn env_free_fields_probe_child() -> Result<(), Box<dyn error::Error>> {
        assert_eq!(
            super::parse_supported_enctype_ids(&["rc4-hmac".to_owned()], false),
            [23_i32]
        );
        if env::var_os(PROBE_MARKER).is_none() {
            return Ok(());
        }
        let config = Config::new();
        let defaults = LibDefaults::new();
        let parsed = Config::parse("[libdefaults]\n")?;
        let reading = LibDefaults::from_env();
        let mut stdout = io::stdout().lock();
        for (name, keytab, k5login) in [
            (
                "config",
                &config.libdefaults.default_client_keytab_name,
                &config.libdefaults.k5login_directory,
            ),
            (
                "defaults",
                &defaults.default_client_keytab_name,
                &defaults.k5login_directory,
            ),
            (
                "parsed",
                &parsed.libdefaults.default_client_keytab_name,
                &parsed.libdefaults.k5login_directory,
            ),
            (
                "reading",
                &reading.default_client_keytab_name,
                &reading.k5login_directory,
            ),
        ] {
            writeln!(stdout, "{PROBE_PREFIX}{name}_client_keytab={keytab}")?;
            writeln!(stdout, "{PROBE_PREFIX}{name}_k5login={k5login}")?;
        }
        Ok(())
    }

    /// Run this binary as a child with a hostile `UID`/`HOME` - a child process,
    /// never this one's environment - and return the probe lines it
    /// printed.
    fn hostile_env_probe() -> Result<Vec<String>, Box<dyn error::Error>> {
        let executable = env::current_exe()?;
        let output = Command::new(executable)
            .args(["--exact", PROBE_TEST, "--nocapture"])
            .env_clear()
            .env(PROBE_MARKER, "1")
            .env("UID", HOSTILE_UID)
            .env("HOME", HOSTILE_HOME)
            .output()?;
        assert!(
            output.status.success(),
            "the probe child must exit 0: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| line.strip_prefix(PROBE_PREFIX))
            .map(str::to_owned)
            .collect())
    }

    /// The value of one probe line, or an error naming the line the child did
    /// not print.
    fn probe_field(lines: &[String], key: &str) -> Result<String, Box<dyn error::Error>> {
        lines
            .iter()
            .find_map(|line| line.strip_prefix(key)?.strip_prefix('=').map(str::to_owned))
            .ok_or_else(|| format!("the probe must print {key}: {lines:?}").into())
    }

    /// The control, asserted by every test below: the child's environment really
    /// is hostile, so `LibDefaults::from_env` in that child follows it. Without this,
    /// an inert probe would make the env-free assertions pass for the wrong
    /// reason.
    fn assert_the_child_environment_is_hostile(
        lines: &[String],
    ) -> Result<(), Box<dyn error::Error>> {
        assert_eq!(
            probe_field(lines, "reading_client_keytab")?,
            ENV_FREE_CLIENT_KEYTAB,
            "even the opt-in constructor must preserve the identity template"
        );
        assert_eq!(probe_field(lines, "reading_k5login")?, HOSTILE_HOME);
        Ok(())
    }

    /// `Config::new` reads neither `UID` nor `HOME`: hostile values
    /// in the process environment leave both derived fields at their
    /// deterministic non-env values.
    #[test]
    fn env_free_config_constructor_does_not_read_uid_or_home() -> Result<(), Box<dyn error::Error>>
    {
        let lines = hostile_env_probe()?;
        assert_the_child_environment_is_hostile(&lines)?;
        assert_eq!(
            probe_field(&lines, "config_client_keytab")?,
            ENV_FREE_CLIENT_KEYTAB,
            "the config preserves its unexpanded process-identity template"
        );
        assert_eq!(probe_field(&lines, "config_k5login")?, "");
        Ok(())
    }

    /// The same for the `LibDefaults` constructor the two env-free config
    /// constructors share.
    #[test]
    fn env_free_libdefaults_constructor_does_not_read_uid_or_home()
    -> Result<(), Box<dyn error::Error>> {
        let lines = hostile_env_probe()?;
        assert_the_child_environment_is_hostile(&lines)?;
        assert_eq!(
            probe_field(&lines, "defaults_client_keytab")?,
            ENV_FREE_CLIENT_KEYTAB
        );
        assert_eq!(probe_field(&lines, "defaults_k5login")?, "");
        Ok(())
    }

    /// Ordinary parsing preserves deterministic defaults under hostile ambient input.
    #[test]
    fn parse_does_not_read_uid_or_home() -> Result<(), Box<dyn error::Error>> {
        let lines = hostile_env_probe()?;
        assert_the_child_environment_is_hostile(&lines)?;
        assert_eq!(
            probe_field(&lines, "parsed_client_keytab")?,
            ENV_FREE_CLIENT_KEYTAB
        );
        assert_eq!(probe_field(&lines, "parsed_k5login")?, "");
        Ok(())
    }

    /// A fresh directory for one fixture tree, unique per process and call.
    fn fixture_dir(name: &str) -> Result<PathBuf, Box<dyn error::Error>> {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let dir = env::temp_dir().join(format!(
            "rskrb5-config-include-{name}-{}-{nanos}",
            process::id()
        ));
        fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    /// Write `contents` to `dir/name`.
    fn write_file(dir: &Path, name: &str, contents: &str) -> Result<(), Box<dyn error::Error>> {
        fs::write(dir.join(name), contents)?;
        Ok(())
    }

    /// Write `contents` to `dir/name` and return the path it wrote.
    fn write_fixture(
        dir: &Path,
        name: &str,
        contents: &str,
    ) -> Result<PathBuf, Box<dyn error::Error>> {
        let path = dir.join(name);
        fs::write(&path, contents)?;
        Ok(path)
    }

    /// Remove a fixture tree. Cleanup never fails a test: a tree that cannot be
    /// removed is left in the temporary directory.
    fn remove_fixture(dir: &Path) {
        fs::remove_dir_all(dir).unwrap_or_default();
    }

    /// The error a load that must be refused returned, or a test failure saying
    /// what was expected when it loaded instead.
    fn refusal(
        loaded: Result<Config, Error>,
        expected: &str,
    ) -> Result<Error, Box<dyn error::Error>> {
        loaded.err().ok_or_else(|| expected.into())
    }

    /// Included scalar values precede values written after the directive site.
    #[test]
    fn include_file_splices_settings_at_directive_site() -> Result<(), Box<dyn error::Error>> {
        let dir = fixture_dir("splice")?;
        let fragment = write_fixture(
            &dir,
            "fragment.conf",
            "[libdefaults]\n default_realm = FRAGMENT.EXAMPLE\n\
             [realms]\n FRAGMENT.EXAMPLE = {\n  kdc = kdc.fragment.example:88\n }\n",
        )?;
        let root = write_fixture(
            &dir,
            "krb5.conf",
            &format!(
                "include {}\n[libdefaults]\n default_realm = PARENT.EXAMPLE\n",
                fragment.display()
            ),
        )?;

        let config = Config::load(&root)?;
        remove_fixture(&dir);

        assert!(
            config.realm("FRAGMENT.EXAMPLE").is_some(),
            "the fragment's realm is spliced into the configuration"
        );
        assert_eq!(
            config.libdefaults.default_realm, "FRAGMENT.EXAMPLE",
            "the first setting is in the included fragment"
        );
        Ok(())
    }

    /// `includedir` applies MIT's filename filter - a `.conf` name or a
    /// name made only of alphanumerics, dashes and underscores, never a dotfile -
    /// and reads the accepted names in alphanumeric order.
    ///
    /// The order assertion is the `default_realm` one: two accepted names set it,
    /// and the one that sorts first wins. The filter assertion is the empty realm
    /// list: only the two rejected names carry a `[realms]` section, so a realm
    /// appearing at all would mean one of them was read.
    #[test]
    fn includedir_filters_names_like_mit_and_sorts_alphanumerically()
    -> Result<(), Box<dyn error::Error>> {
        let dir = fixture_dir("filter")?;
        let fragments = dir.join("fragments");
        fs::create_dir_all(&fragments)?;
        write_file(
            &fragments,
            "10-first.conf",
            "[libdefaults]\n default_realm = FIRST.EXAMPLE\n",
        )?;
        write_file(
            &fragments,
            "20-flag",
            "[libdefaults]\n udp_preference_limit = 1\n",
        )?;
        write_file(
            &fragments,
            "30-last.conf",
            "[libdefaults]\n default_realm = LAST.EXAMPLE\n",
        )?;
        write_file(
            &fragments,
            "40-dotfile-suffix.bak",
            "[realms]\n REJECTED.EXAMPLE = {\n  kdc = kdc.rejected.example:88\n }\n",
        )?;
        write_file(
            &fragments,
            ".50-hidden.conf",
            "[realms]\n HIDDEN.EXAMPLE = {\n  kdc = kdc.hidden.example:88\n }\n",
        )?;
        let root = write_fixture(
            &dir,
            "krb5.conf",
            &format!("includedir {}\n", fragments.display()),
        )?;

        let config = Config::load(&root)?;
        remove_fixture(&dir);

        assert_eq!(
            config.libdefaults.default_realm, "FIRST.EXAMPLE",
            "the accepted names are read in byte order, so the first one wins"
        );
        assert_eq!(config.libdefaults.udp_preference_limit, 1_i32);
        assert!(
            config.realms.is_empty(),
            "a `.bak` name and a dotfile are not included: {:?}",
            config.realms
        );
        Ok(())
    }

    /// An include chain that returns to a file it is already reading is a
    /// named cycle error, not unbounded recursion.
    ///
    /// `a.conf` is the file the caller loaded, so it is on the open chain from
    /// the start: the chain returns to it, and that is the file the error
    /// names. Before the root was tracked the parser read `a.conf` a second time
    /// and detected the cycle one level further down, at `b.conf`.
    #[test]
    fn include_cycle_is_a_named_error() -> Result<(), Box<dyn error::Error>> {
        let dir = fixture_dir("cycle")?;
        let second = write_fixture(&dir, "b.conf", "")?;
        let first = write_fixture(&dir, "a.conf", &format!("include {}\n", second.display()))?;
        fs::write(&second, format!("include {}\n", first.display()))?;

        let error = refusal(Config::load(&first), "a cycle is refused")?;
        remove_fixture(&dir);

        assert!(
            matches!(&error, Error::IncludeCycle { path } if path == &first),
            "the cycle names the file it returned to, which is already being read: {error:?}"
        );
        Ok(())
    }

    /// Nesting past [`MAX_INCLUDE_DEPTH`] is a named error carrying the
    /// depth it reached and the limit.
    #[test]
    fn include_depth_limit_is_named() -> Result<(), Box<dyn error::Error>> {
        let dir = fixture_dir("depth")?;
        let paths = (1..=10_u8)
            .map(|level| write_fixture(&dir, &format!("level{level}.conf"), ""))
            .collect::<Result<Vec<_>, _>>()?;
        for (index, path) in paths.iter().enumerate() {
            let next = paths.get(index.saturating_add(1));
            let contents = next.map_or_else(String::new, |target| {
                format!("include {}\n", target.display())
            });
            fs::write(path, contents)?;
        }
        let first = paths.first().ok_or("the chain has ten files")?;

        let error = refusal(Config::load(first), "a chain past the limit is refused")?;
        remove_fixture(&dir);

        assert!(
            matches!(
                error,
                Error::IncludeTooDeep {
                    depth: 9,
                    limit: MAX_INCLUDE_DEPTH
                }
            ),
            "eight levels of include are read; the ninth is past the limit of {MAX_INCLUDE_DEPTH}: {error:?}"
        );
        Ok(())
    }

    /// More included files than [`MAX_INCLUDE_FILES`] is a named error.
    #[test]
    fn include_file_count_limit_is_named() -> Result<(), Box<dyn error::Error>> {
        let dir = fixture_dir("count")?;
        let fragments = dir.join("fragments");
        fs::create_dir_all(&fragments)?;
        for index in 0..=MAX_INCLUDE_FILES {
            write_file(
                &fragments,
                &format!("f{index:02}.conf"),
                "[libdefaults]\n default_realm = COUNT.EXAMPLE\n",
            )?;
        }
        let root = write_fixture(
            &dir,
            "krb5.conf",
            &format!("includedir {}\n", fragments.display()),
        )?;

        let error = refusal(Config::load(&root), "too many included files are refused")?;
        remove_fixture(&dir);

        assert!(
            matches!(
                error,
                Error::IncludeTooMany {
                    count: 257,
                    limit: MAX_INCLUDE_FILES
                }
            ),
            "the 257th file is past the limit of {MAX_INCLUDE_FILES}: {error:?}"
        );
        Ok(())
    }

    /// An `includedir` with more accepted names than the file cap is refused while
    /// the directory is scanned: its first entry cannot be read, and the cap is
    /// still what is reported, so no file was opened.
    #[test]
    fn includedir_past_the_file_cap_is_refused_before_any_file_is_read()
    -> Result<(), Box<dyn error::Error>> {
        let dir = fixture_dir("count-early")?;
        let fragments = dir.join("fragments");
        fs::create_dir_all(fragments.join("f00.conf"))?;
        for index in 1..=MAX_INCLUDE_FILES {
            write_file(&fragments, &format!("f{index:02}.conf"), "[libdefaults]\n")?;
        }
        let root = write_fixture(
            &dir,
            "krb5.conf",
            &format!("includedir {}\n", fragments.display()),
        )?;

        let error = refusal(Config::load(&root), "too many accepted names are refused")?;
        remove_fixture(&dir);

        assert!(
            matches!(
                error,
                Error::IncludeTooMany {
                    count: _,
                    limit: MAX_INCLUDE_FILES
                }
            ),
            "the cap is reported before the unreadable first entry is opened: {error:?}"
        );
        Ok(())
    }

    /// `includedir` matches names as bytes, like MIT's `valid_name`: a `.conf`
    /// name that is not UTF-8 is included. Linux only, because some filesystems
    /// refuse such names.
    #[cfg(target_os = "linux")]
    #[test]
    fn includedir_matches_names_as_bytes_like_mit() -> Result<(), Box<dyn error::Error>> {
        use std::{ffi::OsStr, os::unix::ffi::OsStrExt as _};

        let dir = fixture_dir("byte-names")?;
        let fragments = dir.join("fragments");
        fs::create_dir_all(&fragments)?;
        let name = OsStr::from_bytes(b"\xff-realm.conf");
        fs::write(
            fragments.join(name),
            "[libdefaults]\n default_realm = BYTES.EXAMPLE\n",
        )?;
        let root = write_fixture(
            &dir,
            "krb5.conf",
            &format!("includedir {}\n", fragments.display()),
        )?;

        let config = Config::load(&root)?;
        remove_fixture(&dir);

        assert_eq!(config.libdefaults.default_realm, "BYTES.EXAMPLE");
        Ok(())
    }

    /// Included bytes past [`MAX_INCLUDE_BYTES`] are a named error - and the
    /// oversize file is refused rather than read into memory whole.
    #[test]
    fn include_total_byte_limit_is_named() -> Result<(), Box<dyn error::Error>> {
        let dir = fixture_dir("bytes")?;
        let oversize = write_fixture(
            &dir,
            "big.conf",
            &format!(
                "#{}\n[libdefaults]\n default_realm = BIG.EXAMPLE\n",
                "x".repeat(MAX_INCLUDE_BYTES)
            ),
        )?;
        let root = write_fixture(
            &dir,
            "krb5.conf",
            &format!("include {}\n", oversize.display()),
        )?;

        let error = refusal(Config::load(&root), "an oversize include is refused")?;
        remove_fixture(&dir);

        assert!(
            matches!(
                error,
                Error::IncludeTooLarge {
                    bytes: 0x0040_0001,
                    limit: MAX_INCLUDE_BYTES
                }
            ),
            "the read stops one byte past the limit of {MAX_INCLUDE_BYTES}: {error:?}"
        );
        Ok(())
    }

    /// An `include` naming a file that cannot be read is a named error
    /// carrying the path - MIT's `PROF_FAIL_INCLUDE_FILE`, never a silent skip.
    #[test]
    fn unreadable_include_file_is_named() -> Result<(), Box<dyn error::Error>> {
        let dir = fixture_dir("unreadable-file")?;
        let missing = dir.join("missing.conf");
        let root = write_fixture(
            &dir,
            "krb5.conf",
            &format!("include {}\n", missing.display()),
        )?;

        let error = refusal(Config::load(&root), "a missing include is refused")?;
        remove_fixture(&dir);

        assert!(
            matches!(&error, Error::IncludeFile { path, source } if path == &missing && source.kind() == io::ErrorKind::NotFound),
            "the error names the file the directive named: {error:?}"
        );
        Ok(())
    }

    /// An `includedir` naming a directory that cannot be listed is a named
    /// error - MIT's `PROF_FAIL_INCLUDE_DIR`.
    #[test]
    fn unreadable_includedir_is_named() -> Result<(), Box<dyn error::Error>> {
        let dir = fixture_dir("unreadable-dir")?;
        let missing = dir.join("missing-dir");
        let root = write_fixture(
            &dir,
            "krb5.conf",
            &format!("includedir {}\n", missing.display()),
        )?;

        let error = refusal(Config::load(&root), "a missing includedir is refused")?;
        remove_fixture(&dir);

        assert!(
            matches!(&error, Error::IncludeDir { path, source } if path == &missing && source.kind() == io::ErrorKind::NotFound),
            "the error names the directory the directive named: {error:?}"
        );
        Ok(())
    }

    /// A `KRB5_CONFIG` path list keeps MIT's order with an include in it -
    /// files are read in list order, each file's includes are expanded where the
    /// directive sits, and the first scalar value wins.
    #[test]
    fn krb5_config_path_list_preserves_mit_order_with_includes() -> Result<(), Box<dyn error::Error>>
    {
        let dir = fixture_dir("path-list")?;
        let fragment = write_fixture(
            &dir,
            "fragment.conf",
            "[libdefaults]\n default_realm = INCLUDE.EXAMPLE\n\
             [realms]\n INCLUDE.EXAMPLE = {\n  kdc = kdc.include.example:88\n }\n",
        )?;
        let first = write_fixture(
            &dir,
            "first.conf",
            &format!(
                "include {}\n[libdefaults]\n udp_preference_limit = 1\n",
                fragment.display()
            ),
        )?;
        let second = write_fixture(
            &dir,
            "second.conf",
            "[libdefaults]\n default_realm = SECOND.EXAMPLE\n udp_preference_limit = 2\n",
        )?;

        let config = Config::load_paths([first, second])?;
        remove_fixture(&dir);

        assert_eq!(
            config.libdefaults.default_realm, "INCLUDE.EXAMPLE",
            "the included fragment provides the first value"
        );
        assert_eq!(
            config.libdefaults.udp_preference_limit, 1_i32,
            "the first root provides the first preference value"
        );
        assert!(
            config.realm("INCLUDE.EXAMPLE").is_some(),
            "the include inside the first file was expanded at its directive site"
        );
        Ok(())
    }

    /// A root file that includes itself is a cycle, and the root is what
    /// the cycle returns to - so the root is on the open stack before its own
    /// directives expand.
    ///
    /// The chain is seven files long on purpose: the root is reached again while
    /// the parser is already eight levels down, which is the deepest include the
    /// limit allows. Without the root on the open stack the recursion runs one
    /// level past [`MAX_INCLUDE_DEPTH`] and is named as merely deep.
    #[test]
    fn a_root_file_including_itself_is_a_cycle() -> Result<(), Box<dyn error::Error>> {
        let dir = fixture_dir("root-self")?;
        let root = write_fixture(&dir, "krb5.conf", "")?;
        let chain = (1..=7_u8)
            .map(|level| write_fixture(&dir, &format!("level{level}.conf"), ""))
            .collect::<Result<Vec<_>, _>>()?;
        for (index, path) in chain.iter().enumerate() {
            let next = chain.get(index.saturating_add(1)).unwrap_or(&root);
            fs::write(path, format!("include {}\n", next.display()))?;
        }
        let first = chain.first().ok_or("the chain has seven files")?;
        fs::write(&root, format!("include {}\n", first.display()))?;

        let error = refusal(
            Config::load(&root),
            "a root that includes itself is refused",
        )?;
        remove_fixture(&dir);

        assert!(
            matches!(&error, Error::IncludeCycle { path } if path == &root),
            "the root file is already being read, so returning to it is a cycle: {error:?}"
        );
        Ok(())
    }

    /// Re-including a completed root is not an active-chain cycle.
    #[test]
    fn a_completed_path_list_root_can_be_reincluded() -> Result<(), Box<dyn error::Error>> {
        let dir = fixture_dir("path-list-root")?;
        let first = write_fixture(
            &dir,
            "first.conf",
            "[libdefaults]\n default_realm = FIRST.EXAMPLE\n",
        )?;
        let second = write_fixture(
            &dir,
            "second.conf",
            &format!("include {}\n", first.display()),
        )?;

        let config = Config::load_paths([&first, &second])?;
        remove_fixture(&dir);

        assert_eq!(config.libdefaults.default_realm, "FIRST.EXAMPLE");
        Ok(())
    }

    /// An `includedir` reached again through a symlink while its files
    /// are being expanded is a cycle, named at the path the directive spelled -
    /// the canonical directories being expanded are tracked, so the chain is
    /// named rather than merely deep.
    ///
    /// `top/up` is `top` itself, and the directive that names it sits at the
    /// eighth include level. The ninth edge fails the depth cap first; the same
    /// cycle at the eighth edge is still named.
    #[cfg(target_family = "unix")]
    #[test]
    fn a_symlinked_includedir_cycle_is_named() -> Result<(), Box<dyn error::Error>> {
        use std::os::unix::fs::symlink;

        let dir = fixture_dir("symlinked-dir")?;
        let top = dir.join("top");
        fs::create_dir_all(&top)?;
        symlink(&top, top.join("up"))?;
        write_file(
            &top,
            "00.conf",
            "[libdefaults]\n udp_preference_limit = 1\n",
        )?;
        let chain: Vec<PathBuf> = (1..=7_u8)
            .map(|level| top.join(format!("tmp{level}.conf")))
            .collect();
        let last = chain.last().ok_or("the chain has seven files")?;
        fs::write(last, format!("includedir {}\n", top.join("up").display()))?;
        for (path, next) in chain.iter().zip(chain.iter().skip(1)).rev() {
            fs::write(path, format!("include {}\n", next.display()))?;
        }
        let first = chain.first().ok_or("the chain has seven files")?;
        write_file(&top, "10.conf", &format!("include {}\n", first.display()))?;
        let cycle = top.join("up");
        let root = write_fixture(
            &dir,
            "krb5.conf",
            &format!("includedir {}\n", top.display()),
        )?;

        let error = refusal(Config::load(&root), "the symlinked cycle is refused")?;
        let earlier = chain.get(5).ok_or("the chain has a sixth file")?;
        fs::write(earlier, format!("includedir {}\n", cycle.display()))?;
        let within_limit = refusal(Config::load(&root), "the shallower cycle is refused")?;
        remove_fixture(&dir);

        assert!(
            matches!(error, Error::IncludeTooDeep { depth: 9, limit: 8 }),
            "the ninth edge is rejected before resolving the directory"
        );
        assert!(
            matches!(&within_limit, Error::IncludeCycle { path } if path == &cycle),
            "the symlink names the directory that is already being read: {within_limit:?}"
        );
        Ok(())
    }
}

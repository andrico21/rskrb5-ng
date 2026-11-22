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

use alloc::{borrow::Cow, collections::BTreeMap, sync::Arc};
use core::{net::IpAddr, time::Duration};
use std::{
    env, io,
    path::{Path, PathBuf},
};

use crate::{
    crypto::s2k::{Family, Minima},
    secure_env,
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

/// Wrong-case twins of every catalogued section and relation name.
#[cfg(test)]
#[path = "config/name_case_tests.rs"]
mod name_case_tests;

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

/// `LibDefaults` builders and derived accessors.
#[path = "config/builders.rs"]
mod builders;
/// Profile composition entry points, including registered profile modules.
#[path = "config/compose.rs"]
mod compose;
/// Typed decoding of `[libdefaults]` and `[realms]` relation lines.
#[path = "config/decode.rs"]
mod decode;
/// Default configuration values and the ambient home-directory defaults.
#[path = "config/defaults.rs"]
mod defaults;
/// Ordered MIT enctype-list expressions.
#[path = "config/enctype_expr.rs"]
mod enctype_expr;
/// Checked enctype-list policy shared by parsing and runtime policy.
#[path = "config/enctype_policy.rs"]
mod enctype_policy;
/// Include expansion: directive recognition and in-place source splicing.
#[path = "config/include.rs"]
mod include;
/// Bounded reading of included files and `includedir` directories.
#[path = "config/include_source.rs"]
mod include_source;
/// Configuration source selection: explicit paths, `KRB5_CONFIG`, platform defaults and text.
#[path = "config/load.rs"]
mod load;
/// Read-only lookups over a parsed configuration: realms, routes, endpoints and appdefaults.
#[path = "config/lookup.rs"]
mod lookup;
/// Shared relation-line helpers of the section parsers.
#[path = "config/sections.rs"]
mod sections;
/// The `[libdefaults]` part of the JSON snapshot.
#[cfg(feature = "serde")]
#[path = "config/serde_libdefaults.rs"]
mod serde_libdefaults;
/// The redacted gokrb5-style JSON snapshot of a parsed configuration.
#[cfg(feature = "serde")]
#[path = "config/serde_stage.rs"]
mod serde_stage;
/// The configuration option state.
#[path = "config/toggle.rs"]
mod toggle;
/// Profile scalar value grammars: durations and booleans.
#[path = "config/values.rs"]
mod values;

use decode::{invalid_integer, parse_i32};
use load::PLATFORM_DEFAULT_CONFIG_PATHS;
use sections::parse_assignment;

/// The environment variable naming the `krb5.conf` path list.
const KRB5_CONFIG_ENV: &str = "KRB5_CONFIG";

/// The deepest `include` or subsection nesting a configuration may reach before
/// parsing fails with [`Error::IncludeTooDeep`].
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
        lookup::appdefault(self, app, realm, relation)
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
        lookup::appdefault_boolean(self, app, realm, relation)
    }

    /// Return a declared route, preserving missing versus direct.
    #[inline]
    #[must_use]
    pub fn capath(&self, client: &str, server: &str) -> Option<&section_values::Route> {
        lookup::capath(self, client, server)
    }
    /// Diagnostics for selected profile relations, including deferred consumers.
    #[inline]
    #[must_use]
    pub fn diagnostics(&self) -> &[ConfigDiagnostic] {
        lookup::diagnostics(self)
    }

    /// Resolve a host mapping, then the explicitly configured default realm.
    #[inline]
    #[must_use]
    pub fn realm_for_host(&self, host: &str) -> Option<&str> {
        lookup::realm_for_host(self, host)
    }
    #[must_use]
    /// Create a config with MIT/gokrb5-style defaults and no parsed sections.
    #[inline]
    pub fn new() -> Self {
        defaults::new_config()
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
        load::load(path)
    }

    /// Load and parse the `krb5.conf` path list named by `KRB5_CONFIG`.
    ///
    /// The environment value is split with the platform path-list separator.
    /// On Unix this matches the colon-separated list used by MIT Kerberos.
    ///
    /// # Ambient input
    /// Reads `KRB5_CONFIG`; use [`Config::load_paths`] for explicit paths.
    ///
    /// In a set-uid or set-gid process the variables named here are ignored, as MIT 1.22.2
    /// ignores them (`secure_getenv`); see the secure-environment decision of
    /// `docs/security-policy.md`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DefaultConfigName`] when `KRB5_CONFIG` is unset, and
    /// the [`Config::load_paths`] errors for the list it names.
    #[inline]
    pub fn load_from_env() -> Result<Self, Error> {
        let value =
            secure_env::ambient(|| env::var_os(KRB5_CONFIG_ENV)).ok_or(Error::DefaultConfigName)?;
        load::load_paths(env::split_paths(&value))
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
    /// In a set-uid or set-gid process the variables named here are ignored, as MIT 1.22.2
    /// ignores them (`secure_getenv`); see the secure-environment decision of
    /// `docs/security-policy.md`.
    ///
    /// # Errors
    ///
    /// Returns the [`Config::load_from_env`] errors when `KRB5_CONFIG` is set,
    /// [`Error::NoDefault`] when no platform default file exists, and the
    /// [`Config::load_paths`] errors for the files that do.
    #[inline]
    pub fn load_default() -> Result<Self, Error> {
        if secure_env::ambient(|| env::var_os(KRB5_CONFIG_ENV)).is_some() {
            return Self::load_from_env();
        }
        load::load_default_paths(PLATFORM_DEFAULT_CONFIG_PATHS.iter().copied())
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
    /// In a set-uid or set-gid process the variables named here are ignored, as MIT 1.22.2
    /// ignores them (`secure_getenv`); see the secure-environment decision of
    /// `docs/security-policy.md`.
    ///
    /// # Errors
    ///
    /// Returns the [`Config::load_from_env`] errors when `KRB5_CONFIG` is set,
    /// the [`Config::load_paths`] errors for an existing platform default file,
    /// and the [`Config::parse`] errors for the embedded text.
    #[inline]
    pub fn load_default_or_parse(embedded_krb5_conf: &str) -> Result<Self, Error> {
        if secure_env::ambient(|| env::var_os(KRB5_CONFIG_ENV)).is_some() {
            return Self::load_from_env();
        }
        let paths = PLATFORM_DEFAULT_CONFIG_PATHS.iter().copied();
        load::load_default_or_parse_paths(embedded_krb5_conf, paths)
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
    /// path, [`Error::File`] when a named file cannot be resolved or read,
    /// [`Error::IncludeDir`] when a named directory cannot be listed, and the
    /// [`Config::parse`] errors for each independent source.
    #[inline]
    pub fn load_paths<I, P>(paths: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        load::load_paths(paths)
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
        load::load_default_paths(paths)
    }

    /// Load the platform default files of `paths` that exist, or parse
    /// `embedded_krb5_conf` when none does.
    ///
    /// # Errors
    ///
    /// Returns the [`Config::load_paths`] errors for existing files, and the
    /// [`Config::parse`] errors for the embedded text.
    #[cfg(test)]
    fn load_default_or_parse_paths<I, P>(embedded_krb5_conf: &str, paths: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        load::load_default_or_parse_paths(embedded_krb5_conf, paths)
    }

    /// Parse a `krb5.conf` string.
    ///
    /// A line beginning with `include <file>` or `includedir <dir>` loads
    /// independent sources at the directive site, then resumes the parent's
    /// section and nesting state. A relative path is resolved against the
    /// process's working directory, as MIT does and 0.2.2 did, not against the
    /// including file. Directory
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
        load::parse(input)
    }

    /// Parse caller text, equivalent to gokrb5's `NewFromString`.
    ///
    /// # Errors
    /// Returns the bounded profile-composition errors of [`Self::parse`].
    #[inline]
    pub fn from_string(input: &str) -> Result<Self, Error> {
        load::from_string(input)
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
        load::from_path(path)
    }

    /// Parse a reader, including buffered readers, through profile composition.
    ///
    /// A reader has no base directory of its own: a relative `include` or
    /// `includedir` path in its bytes is resolved against the process's working
    /// directory, as in [`Config::parse`].
    ///
    /// # Errors
    /// Returns typed I/O, UTF-8, size and include-composition failures.
    #[inline]
    pub fn from_reader<R>(reader: R) -> Result<Self, Error>
    where
        R: io::Read,
    {
        load::from_reader(reader)
    }

    /// Parse a profile with explicit secure-unsupported handling.
    ///
    /// # Errors
    /// Returns the errors of [`Self::parse`], including Camellia errors in strict mode.
    #[inline]
    pub fn parse_with_mode(input: &str, mode: ParseMode) -> Result<Self, Error> {
        load::parse_with_mode(input, mode)
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
        load::parse_with_roots(text, roots)
    }

    /// Expand sources and apply the requested enctype parsing mode.
    ///
    /// # Errors
    /// Returns include, profile and expression-policy errors without fallback.
    fn parse_with_roots_mode<I>(text: &str, roots: I, mode: ParseMode) -> Result<Self, Error>
    where
        I: IntoIterator<Item = PathBuf>,
    {
        load::parse_with_roots_mode(text, roots, mode)
    }

    /// Render a gokrb5-style JSON snapshot of the parsed configuration.
    ///
    /// # Errors
    ///
    /// Returns [`serde_json::Error`] when the snapshot cannot be serialized.
    #[cfg(feature = "serde")]
    #[inline]
    pub fn json(&self) -> Result<String, serde_json::Error> {
        serde_stage::json(self)
    }

    #[must_use]
    /// Return the configured realm with this name.
    #[inline]
    pub fn realm(&self, realm: &str) -> Option<&Realm> {
        lookup::realm(self, realm)
    }

    /// Resolve a DNS name to a Kerberos realm using `[domain_realm]`.
    ///
    /// The host name is folded to lower case (RFC 4120 section 6.1, MIT
    /// `hostrealm.c`) while realm values stay case-sensitive; a profile key
    /// with an upper-case letter is never stored, as MIT never matches it.
    /// Lookup order: the exact hostname first, then the most specific suffix,
    /// where a leading-dot tag covers subdomains only and a bare tag covers the
    /// domain and its subdomains (MIT `krb5.conf(5)`); within one level the
    /// leading-dot tag wins.
    #[inline]
    #[must_use]
    pub fn resolve_realm(&self, dns_name: &str) -> Option<&str> {
        lookup::resolve_realm(self, dns_name)
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
        lookup::configured_kdcs(self, realm)
    }

    /// Return password-change servers configured for a realm.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoRealm`] when the realm is not configured, and
    /// [`Error::NoKpasswdServer`] when it lists no password-change server.
    #[inline]
    pub fn configured_kpasswd_servers(&self, realm: &str) -> Result<&[String], Error> {
        lookup::configured_kpasswd_servers(self, realm)
    }
}

/// Whether a configuration option is enabled; serialized as its original boolean.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(from = "bool", into = "bool"))]
pub enum Toggle {
    /// The option is disabled.
    #[default]
    Disabled,
    /// The option is enabled.
    Enabled,
}

impl Toggle {
    /// Converts a configuration boolean into its option state.
    #[must_use]
    #[inline]
    pub const fn from_bool(value: bool) -> Self {
        toggle::from_bool(value)
    }

    /// Returns whether the option is enabled.
    #[must_use]
    #[inline]
    pub const fn is_enabled(self) -> bool {
        toggle::is_enabled(self)
    }
}

/// Configuration parsing modes and diagnostics.
#[path = "config/diagnostic.rs"]
pub mod diagnostic;

use crate::{crypto::KerberosEtype, error::Policy};

/// Selector vocabulary separated from ordered expression evaluation.
#[path = "config/enctype_names.rs"]
mod enctype_names;

/// Configuration parsing diagnostic, including skipped secure enctypes.
pub type ConfigDiagnostic = diagnostic::Diagnostic;

/// Compatible or strict treatment of secure unsupported configuration.
pub type ParseMode = diagnostic::ParseMode;

/// A parsed, ordered MIT enctype-list expression, not yet runtime-authorized.
///
/// Names and aliases are case-insensitive. Only space, tab, CR, LF and comma
/// delimit terms. `+` or no prefix adds; `-` removes. Adding an existing entry
/// keeps its position; adding a removed entry appends it. `aes` expands in MIT
/// order `[18, 17, 20, 19]`; `DEFAULT` uses this crate's secure SHA2-first list
/// `[20, 19, 18, 17]`, never DES3/RC4, even when those families are enabled.
///
/// See [krb5.conf](https://web.mit.edu/kerberos/krb5-1.22/doc/admin/conf_files/krb5_conf.html)
/// and its linked [Encryption types section](https://web.mit.edu/kerberos/krb5-1.22/doc/admin/conf_files/kdc_conf.html#encryption-types).
/// Ordering and tokenization follow
/// [MIT `init_ctx.c:411-492`](https://github.com/krb5/krb5/blob/krb5-1.22.2-final/src/lib/krb5/krb/init_ctx.c#L411-L492).
/// Unlike MIT's unknown-token filtering, positive forbidden/disabled terms and
/// unknown terms fail closed. Known removal terms never need permission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnctypeExpr {
    /// Parsed terms retain original spelling for operator diagnostics.
    terms: Vec<EnctypeTerm>,
}

/// One bounded expression token and its validated selector.
#[derive(Clone, Debug, Eq, PartialEq)]
struct EnctypeTerm {
    /// Original token, including any operator.
    token: String,
    /// Validated vocabulary entry.
    selector: enctype_names::Selector,
    /// Whether to insert or remove the selector's entries.
    operation: EnctypeOperation,
}

/// Ordered-list operations are separate from algorithm permission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EnctypeOperation {
    /// Append an entry only when not already present.
    Add,
    /// Remove any present matching entries.
    Remove,
}

/// Successfully resolved nonempty enctypes and compatible-mode diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedEnctypes {
    /// Authorized implemented entries in preference order.
    enctypes: Vec<KerberosEtype>,
    /// Explicitly skipped secure unsupported selections.
    diagnostics: Vec<ConfigDiagnostic>,
}

impl ResolvedEnctypes {
    /// Ordered, nonempty implemented encryption types.
    #[must_use]
    #[inline]
    pub fn enctypes(&self) -> &[KerberosEtype] {
        enctype_expr::enctypes(self)
    }

    /// Diagnostics for every skipped positive secure unsupported term.
    #[must_use]
    #[inline]
    pub fn diagnostics(&self) -> &[ConfigDiagnostic] {
        enctype_expr::diagnostics(self)
    }
}

impl EnctypeExpr {
    /// Parse at most 64 KiB into known selectors, retaining their order and spelling.
    ///
    /// # Errors
    /// Returns [`Error::EnctypeExpressionTooLarge`] before allocating tokens for
    /// oversized input, or [`Error::UnknownEnctype`] naming an unknown token.
    /// Recognition of a forbidden name is not permission; call [`Self::resolve`].
    #[inline]
    pub fn parse(text: &str) -> Result<Self, Error> {
        enctype_expr::parse(text)
    }

    /// Resolve using explicit RC4 and DES3 runtime permissions and parsing mode.
    ///
    /// `allow_rc4` and `allow_des3` are enforced client-side too, deliberately
    /// stricter than MIT's KDC-side relations. No Cargo feature grants permission.
    /// Compatible mode skips only secure Camellia names whose `camellia` leaf is not
    /// compiled in, with diagnostics; strict mode rejects them. With the leaf compiled
    /// in, a Camellia name resolves like any secure name, and `DEFAULT` never includes it.
    /// A later removal cannot erase an earlier refusal.
    ///
    /// # Errors
    /// Returns [`Error::RejectedEnctype`] with a typed policy cause for D2 terms,
    /// [`Error::DisabledEnctype`] for disabled legacy terms,
    /// [`Error::UnsupportedSecureEnctype`] for Camellia in strict mode, and
    /// [`Error::EmptyEnctypeExpression`] when nothing remains.
    #[inline]
    pub fn resolve(
        &self,
        allow_rc4: Toggle,
        allow_des3: Toggle,
        mode: ParseMode,
    ) -> Result<ResolvedEnctypes, Error> {
        enctype_expr::resolve(self, allow_rc4, allow_des3, mode)
    }
}

impl EnctypeTerm {
    /// Reject positive insecure or disabled selections before expanding them.
    ///
    /// # Errors
    /// Returns a named disabled error or a named error with a typed policy cause.
    fn check_permission(&self, allow_rc4: Toggle, allow_des3: Toggle) -> Result<(), Error> {
        enctype_expr::check_permission(self, allow_rc4, allow_des3)
    }
}

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
    /// Whether addresses should be omitted from tickets; when disabled, AS
    /// requests are bound to [`Self::extra_addresses`].
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
    /// A snapshot built by `CryptoPolicy::from_libdefaults`, and so every acceptor,
    /// reads the permitted list only. Client request construction also rejects
    /// request lists outside the permitted list, set programmatically or parsed,
    /// by name ([`Error::EnctypeNotPermitted`]), regardless of this flag.
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
    /// Whether `verify_init_creds` fails when it cannot verify (no host key):
    /// MIT's `verify_ap_req_nofail`. It applies only when
    /// [`Self::verify_ap_req_nofail_explicit`] is set; unset, verification is
    /// required (`routing::verify`).
    pub verify_ap_req_nofail: Toggle,
    /// Whether the profile or the caller set [`Self::verify_ap_req_nofail`];
    /// unset, `verify_init_creds` requires verification as if it were `true`.
    /// Serialized `LibDefaults` that lack this field deserialize it as `false`.
    #[cfg_attr(feature = "serde", serde(default))]
    pub verify_ap_req_nofail_explicit: Toggle,
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
    pub fn with_min_s2k_iterations(self, family: Family, minimum: u32) -> Result<Self, Policy> {
        builders::with_min_s2k_iterations(self, family, minimum)
    }
    /// Diagnostics for skipped secure enctypes and ignored draft-9 preferences.
    /// Serde retains preference IDs for diagnostics, never for outgoing selection.
    #[inline]
    #[must_use]
    pub fn diagnostics(&self) -> Cow<'_, [ConfigDiagnostic]> {
        builders::diagnostics(self)
    }

    /// Parsing mode used for subsequent expression resolution.
    #[inline]
    #[must_use]
    pub const fn parse_mode(&self) -> ParseMode {
        builders::parse_mode(self)
    }
    /// Stage `allow_weak_crypto`; enabled values are rejected by runtime policy construction.
    #[must_use]
    #[inline]
    pub const fn with_allow_weak_crypto(self, value: Toggle) -> Self {
        builders::with_allow_weak_crypto(self, value)
    }
    /// Sets `canonicalize`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_canonicalize(self, value: Toggle) -> Self {
        builders::with_canonicalize(self, value)
    }
    /// Sets `ccache_type`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_ccache_type(self, value: i32) -> Self {
        builders::with_ccache_type(self, value)
    }
    /// Sets `clockskew`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_clockskew(self, value: Duration) -> Self {
        builders::with_clockskew(self, value)
    }
    /// Sets `default_ccache_name`, preserving the other fields.
    #[must_use]
    #[inline]
    pub fn with_default_ccache_name(self, value: String) -> Self {
        builders::with_default_ccache_name(self, value)
    }
    /// Sets `default_client_keytab_name`, preserving the other fields.
    #[must_use]
    #[inline]
    pub fn with_default_client_keytab_name(self, value: String) -> Self {
        builders::with_default_client_keytab_name(self, value)
    }
    /// Sets `default_keytab_name`, preserving the other fields.
    #[must_use]
    #[inline]
    pub fn with_default_keytab_name(self, value: String) -> Self {
        builders::with_default_keytab_name(self, value)
    }
    /// Sets `default_realm`, preserving the other fields.
    #[must_use]
    #[inline]
    pub fn with_default_realm(self, value: String) -> Self {
        builders::with_default_realm(self, value)
    }
    /// Sets `default_tgs_enctypes`, preserving the other fields.
    #[must_use]
    #[inline]
    pub fn with_default_tgs_enctypes(self, value: Vec<String>) -> Self {
        builders::with_default_tgs_enctypes(self, value)
    }
    /// Sets `default_tkt_enctypes`, preserving the other fields.
    #[must_use]
    #[inline]
    pub fn with_default_tkt_enctypes(self, value: Vec<String>) -> Self {
        builders::with_default_tkt_enctypes(self, value)
    }
    /// Derives supported TGS enctype IDs from the current names and policy.
    #[must_use]
    #[inline]
    pub fn default_tgs_enctype_ids(&self) -> Vec<i32> {
        builders::default_tgs_enctype_ids(self)
    }
    /// Derives supported ticket enctype IDs from the current names and policy.
    #[must_use]
    #[inline]
    pub fn default_tkt_enctype_ids(&self) -> Vec<i32> {
        builders::default_tkt_enctype_ids(self)
    }
    /// Sets `dns_canonicalize_hostname`, preserving the other fields.
    #[must_use]
    #[inline]
    pub fn with_dns_canonicalize_hostname(self, value: Toggle) -> Self {
        builders::with_dns_canonicalize_hostname(self, value)
    }
    /// Sets `dns_lookup_kdc`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_dns_lookup_kdc(self, value: Toggle) -> Self {
        builders::with_dns_lookup_kdc(self, value)
    }
    /// Sets `dns_lookup_realm`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_dns_lookup_realm(self, value: Toggle) -> Self {
        builders::with_dns_lookup_realm(self, value)
    }
    /// Sets `extra_addresses`, preserving the other fields.
    #[must_use]
    #[inline]
    pub fn with_extra_addresses(self, value: Vec<IpAddr>) -> Self {
        builders::with_extra_addresses(self, value)
    }
    /// Sets `forwardable`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_forwardable(self, value: Toggle) -> Self {
        builders::with_forwardable(self, value)
    }
    /// Sets `ignore_acceptor_hostname`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_ignore_acceptor_hostname(self, value: Toggle) -> Self {
        builders::with_ignore_acceptor_hostname(self, value)
    }
    /// Sets `k5login_authoritative`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_k5login_authoritative(self, value: Toggle) -> Self {
        builders::with_k5login_authoritative(self, value)
    }
    /// Sets `k5login_directory`, preserving the other fields.
    #[must_use]
    #[inline]
    pub fn with_k5login_directory(self, value: String) -> Self {
        builders::with_k5login_directory(self, value)
    }
    /// Sets `kdc_default_options`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_kdc_default_options(self, value: u32) -> Self {
        builders::with_kdc_default_options(self, value)
    }
    /// Sets `kdc_time_sync`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_kdc_time_sync(self, value: i32) -> Self {
        builders::with_kdc_time_sync(self, value)
    }
    /// Sets `no_addresses`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_no_addresses(self, value: Toggle) -> Self {
        builders::with_no_addresses(self, value)
    }
    /// Sets `permitted_enctypes`, preserving the other fields.
    #[must_use]
    #[inline]
    pub fn with_permitted_enctypes(self, value: Vec<String>) -> Self {
        builders::with_permitted_enctypes(self, value)
    }
    /// Derives supported permitted enctype IDs from the current names and policy.
    #[must_use]
    #[inline]
    pub fn permitted_enctype_ids(&self) -> Vec<i32> {
        builders::permitted_enctype_ids(self)
    }
    /// Sets `permitted_enctypes_explicit`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_permitted_enctypes_explicit(self, value: Toggle) -> Self {
        builders::with_permitted_enctypes_explicit(self, value)
    }
    /// Sets `preferred_preauth_types`, preserving the other fields.
    #[must_use]
    #[inline]
    pub fn with_preferred_preauth_types(self, value: Vec<i32>) -> Self {
        builders::with_preferred_preauth_types(self, value)
    }
    /// Sets `proxiable`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_proxiable(self, value: Toggle) -> Self {
        builders::with_proxiable(self, value)
    }
    /// Sets `rdns`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_rdns(self, value: Toggle) -> Self {
        builders::with_rdns(self, value)
    }
    /// Sets `realm_try_domains`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_realm_try_domains(self, value: i32) -> Self {
        builders::with_realm_try_domains(self, value)
    }
    /// Sets `renew_lifetime`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_renew_lifetime(self, value: Duration) -> Self {
        builders::with_renew_lifetime(self, value)
    }
    /// Stage `safe_checksum_type`; forbidden values are rejected by runtime policy construction.
    #[must_use]
    #[inline]
    pub const fn with_safe_checksum_type(self, value: i32) -> Self {
        builders::with_safe_checksum_type(self, value)
    }
    /// Sets `ticket_lifetime`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_ticket_lifetime(self, value: Duration) -> Self {
        builders::with_ticket_lifetime(self, value)
    }
    /// Sets `udp_preference_limit`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_udp_preference_limit(self, value: i32) -> Self {
        builders::with_udp_preference_limit(self, value)
    }
    /// Sets `verify_ap_req_nofail_explicit`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_verify_ap_req_nofail_explicit(self, value: Toggle) -> Self {
        builders::with_verify_ap_req_nofail_explicit(self, value)
    }
    /// Sets `verify_ap_req_nofail`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_verify_ap_req_nofail(self, value: Toggle) -> Self {
        builders::with_verify_ap_req_nofail(self, value)
    }

    #[must_use]
    /// Create default libdefaults without reading the environment.
    #[inline]
    pub fn new() -> Self {
        defaults::new_libdefaults()
    }

    /// Create the defaults of [`Self::new`]; no environment variable is read.
    ///
    /// `k5login_directory` stays empty, which means the `.k5login` file of the
    /// target user's home directory as the account database reports it. MIT
    /// 1.22.2 never reads `HOME` for it either (`localauth_k5login.c:106` uses
    /// the passwd home directory of the target user), and since WP-17 the
    /// authorizer takes the home from its `AccountResolver`. Earlier versions
    /// copied `HOME` into `k5login_directory` here; that was never MIT's
    /// behaviour and would have made `HOME` select the file.
    #[inline]
    #[must_use]
    pub fn from_env() -> Self {
        Self::new()
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
        decode::parse_lines(self, lines, enctypes)
    }
}

/// Internal checked expression operations shared by parsing and runtime policy.
pub(crate) trait EnctypeDefaults {
    /// Resolve final profile lists or return a named expression error.
    /// # Errors
    /// Rejects invalid expressions or out-of-policy explicit requests.
    fn validate_explicit_enctypes(&mut self, enctypes: EnctypeParseState) -> Result<(), Error>;
    /// Reject blanket weakening with a typed policy error.
    /// # Errors
    /// Rejects enabled weak crypto.
    fn reject_weak_crypto(&self) -> Result<(), Error>;
    /// Resolve names or return a named expression error.
    /// # Errors
    /// Rejects invalid, disabled or forbidden selections and empty results.
    fn resolve_names(&self, names: &[String]) -> Result<ResolvedEnctypes, Error>;
    /// Validate staged request names against the permitted list.
    /// # Errors
    /// Returns named expression or request-membership errors without narrowing.
    #[cfg(feature = "messages")]
    fn validate_request_enctypes(&self) -> Result<(), Error>;
    /// Legacy accessor returns no usable IDs for invalid public mutation.
    fn effective_enctype_ids(&self, names: &[String]) -> Vec<i32>;
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
        defaults::new_realm(realm)
    }

    /// Parse the lines of one realm's `{ ... }` block.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLine`] for a line that is not an assignment, and
    /// [`Error::Policy`] for an enabled removed-protocol directive.
    fn parse(name: &str, lines: &[Line]) -> Result<Self, Error> {
        decode::realm(name, lines)
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
    values::parse_duration(value)
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
    values::parse_boolean(value)
}

#[must_use]
/// Parse enctype names to the subset of IDs implemented by gokrb5-compatible
/// crypto.
#[cfg(test)]
#[inline]
pub(crate) fn parse_supported_enctype_ids(
    enctypes: &[String],
    allow_weak_crypto: bool,
) -> Vec<i32> {
    values::parse_supported_enctype_ids(enctypes, allow_weak_crypto)
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
    /// parser does not recognize at the top level is an `InvalidLine`, and an
    /// indented directive inside a section would otherwise be a relation
    /// without `=`.
    fn parse(line: &'line str) -> Option<Self> {
        include::directive(line)
    }
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
    /// `[plugins]` module names a registry resolves, as `(interface, id)`;
    /// empty unless `extensions::Registry::parse_config` composes the text.
    modules: Arc<[(&'static str, String)]>,
}

/// Compose `text` with the `[plugins]` module names a registry resolves; the
/// resolution point of `extensions::Registry::parse_config`.
///
/// # Errors
/// Returns the [`Config::parse_with_mode`] errors; a `module` outside `modules`
/// is still [`Error::UnsupportedDynamicModule`].
pub(crate) fn compose_with_modules(
    text: &str,
    mode: ParseMode,
    modules: Arc<[(&'static str, String)]>,
) -> Result<Config, Error> {
    compose::compose_with_modules(text, mode, modules)
}

/// The `module <id>:<residual>` profile directive, when it is the only content of `text`.
///
/// MIT 1.22.2 (`prof_parse.c:309-324`) accepts it before the first section
/// header and stops reading the file there; content after it is refused here
/// instead of ignored. The `<id>` ends at the first `:`.
pub(crate) fn profile_module_directive(text: &str) -> Option<(&str, &str)> {
    compose::profile_module_directive(text)
}

impl IncludeExpansion {
    /// The same expansion, with the canonical paths the configuration's own
    /// text came from already on the open chain.
    ///
    /// A caller that read its text from files hands them over; a caller parsing
    /// a string hands over nothing, because a string has no path to re-enter.
    fn with_roots<I>(self, roots: I) -> Self
    where
        I: IntoIterator<Item = PathBuf>,
    {
        include::with_roots(self, roots)
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
        include::expand(self, input, depth)
    }

    /// What one directive contributes to the expanded text.
    ///
    /// # Errors
    ///
    /// Returns the [`Self::include_file`] or [`Self::include_dir`] error for
    /// the directive's target.
    fn splice(&mut self, directive: IncludeDirective<'_>, depth: usize) -> Result<(), Error> {
        include::splice(self, directive, depth)
    }

    /// One `include`: read the file and expand its own directives in turn.
    ///
    /// A path is used exactly as the configuration spells it, which is what MIT
    /// does (`fopen` on the token): a relative path is resolved against the
    /// process's working directory, also inside an included file, with no
    /// rebasing on the including file's directory. A top-level path handed to
    /// [`Config::load_paths`] is opened as given.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IncludeTooDeep`] past [`MAX_INCLUDE_DEPTH`],
    /// [`Error::IncludeFile`] for an included file that cannot be resolved or
    /// read, [`Error::File`] for a top-level file that cannot,
    /// [`Error::IncludeCycle`] for a file already being expanded, the
    /// [`Self::read_include`] limit errors, and the errors of its own
    /// directives.
    fn include_file(&mut self, path: &Path, depth: usize) -> Result<(), Error> {
        include_source::include_file(self, path, depth)
    }

    /// One included file's text, counted against the file and byte caps.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IncludeTooMany`] past [`MAX_INCLUDE_FILES`],
    /// [`Error::IncludeTooLarge`] past [`MAX_INCLUDE_BYTES`], and
    /// [`Error::IncludeFile`] for an included file that cannot be opened or
    /// read, or that is not UTF-8 text ([`Error::File`] for a top-level file).
    fn read_include(&mut self, path: &Path, depth: usize) -> Result<String, Error> {
        include_source::read_include(self, path, depth)
    }

    /// One `includedir`: every accepted name, in alphanumeric order.
    ///
    /// An entry that is a directory - or a symlink to one - is skipped, as MIT
    /// does (it opens the name with `fopen` and reads nothing from a directory),
    /// so it is neither read nor counted against the file cap.
    ///
    /// The file cap is enforced while the directory is scanned, so a directory
    /// with more accepted names than the budget allows is refused before any
    /// name is sorted or any file is read.
    ///
    /// The directory's canonical path joins the open chain for as long as its
    /// files are being expanded, so a directory that is reached again through a
    /// symlink while it is being read is [`Error::IncludeCycle`] naming the
    /// path the configuration spelled, rather than a chain that only runs out of
    /// depth; an entry that is a symlink to a directory being read is skipped
    /// with the other directory entries, not a cycle. The path is used exactly
    /// as the configuration spells it, as an `include` path is: a relative path
    /// is resolved against the process's working directory, as MIT does. A
    /// top-level directory handed to [`Config::load_paths`] is opened as given.
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
        include_source::include_dir(self, dir, depth)
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "config/load_tests.rs"]
mod tests;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::too_long_first_doc_paragraph,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "config/fork_tests.rs"]
mod fork_tests;

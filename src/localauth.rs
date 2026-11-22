//! Local authorization and name translation (WP-17, MIT `localauth`).
//!
//! Two questions, as in MIT krb5 1.22.2 (`src/lib/krb5/os/localauth.c`):
//!
//! * [`principal_to_local_name`] is `krb5_aname_to_localname`: which local
//!   account name does a verified principal map to, by the explicit
//!   `auth_to_local_names` of the default realm, then its `auth_to_local`
//!   rules (`DEFAULT` and `RULE:[n:format](regex)s/re/text/`)?
//! * [`authorize_local`] is `krb5_kuserok`: may this verified principal act as
//!   this local account, by the account's `.k5login` file (or the file of
//!   `k5login_directory`) and by the `an2ln` rule, that is, the principal maps
//!   to exactly that account name?
//!
//! The leaf is the `localauth` Cargo feature; it adds the `regex` crate
//! (admission record: `docs/dependency-admission.md#regex`).
//!
//! # Security
//!
//! * Only a **verified** principal may be passed: the caller takes it from a
//!   validated ticket, never from a request. Nothing here reads the
//!   environment: the home directory and the numeric user id of a local
//!   account come from the caller's [`AccountResolver`], never from `HOME`,
//!   `UID` or `USER`. The crate has no default resolver (it forbids `unsafe`
//!   and admits no OS wrapper for `getpwnam`); [`accounts::StaticAccounts`]
//!   is the caller-filled table.
//! * Every denial is a [`Denial`] value and the function never grants on an
//!   error: a missing account, an unreadable, oversized, symlinked,
//!   group- or world-writable or foreign-owned `.k5login`, a rule that is
//!   too large or does not compile, and a translation that is empty, longer
//!   than [`MAX_LOCAL_NAME_BYTES`] or contains a NUL byte.
//! * Patterns run on the linear-time Pike VM of `regex` and are bounded
//!   before they compile (see the `MAX_*` constants), so a hostile rule can
//!   neither take exponential time nor allocate without limit.
//! * Realm and case are never folded: `Alice@REALM` and `alice@REALM` are
//!   different principals, and the explicit and `DEFAULT` mappings apply only
//!   to principals of the default realm.
//!
//! # Platforms
//!
//! The `.k5login` module needs Unix file ownership and modes. On other
//! platforms it never allows or denies (MIT 1.22.2 `localauth_k5login.c:164`
//! does the same on Windows) and only the `an2ln` rule can authorize.

use alloc::sync::Arc;
use std::{collections::BTreeMap, path::PathBuf};

use crate::ccache::Principal;

pub mod accounts;
mod authorizer;
pub mod k5login;
mod mapper;
mod rule;
mod unparse;

/// The longest local account name that a translation may yield: MIT's
/// `MAX_USERNAME` (65, `localauth_an2ln.c:37`) less the terminating NUL.
pub const MAX_LOCAL_NAME_BYTES: usize = 64;
/// The longest `auth_to_local` rule text in bytes.
pub const MAX_RULE_BYTES: usize = 2048;
/// The longest `(regex)` or `s/regex/text/` pattern in bytes.
pub const MAX_PATTERN_BYTES: usize = 512;
/// The longest `s/regex/text/` replacement text in bytes.
pub const MAX_REPLACEMENT_BYTES: usize = 256;
/// The most `s/regex/text/` expressions in one rule.
pub const MAX_SUBSTITUTIONS: usize = 16;
/// The most replacements one `s/regex/text/g` expression may make.
pub const MAX_MATCHES: usize = 256;
/// The longest selection string (and intermediate result) in bytes.
pub const MAX_SELECTION_BYTES: usize = 1024;
/// The most rules in one [`LocalNameMapper`].
pub const MAX_RULES: usize = 64;

/// A local account as the caller's [`AccountResolver`] knows it: trusted,
/// injected metadata (never read from the environment).
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Account {
    /// The numeric user id; a `.k5login` must be owned by it or by root.
    pub uid: u32,
    /// The absolute home directory; the `.k5login` file is `<home>/.k5login`.
    pub home: PathBuf,
}

impl Account {
    /// An account with `uid` and the absolute `home` directory.
    #[must_use]
    #[inline]
    pub const fn new(uid: u32, home: PathBuf) -> Self {
        Self { uid, home }
    }
}

/// The caller's account database (MIT: `getpwnam_r`).
///
/// The crate has no default implementation: [`accounts::StaticAccounts`] is
/// a table the caller fills, and a caller that has an audited passwd lookup
/// implements this trait over it.
pub trait AccountResolver: core::fmt::Debug + Send + Sync {
    /// The account named `local_name`, or `None` when there is none or the
    /// lookup failed (both deny, as in MIT `localauth_k5login.c:101-105`).
    fn lookup(&self, local_name: &str) -> Option<Account>;
}

/// One `auth_to_local` value: `DEFAULT` or `RULE:[n:format](regex)s/re/text/[g]`.
#[derive(Clone, Debug)]
pub struct AuthToLocalRule {
    /// The compiled rule.
    kind: rule::Kind,
}

/// The mapping half: explicit names and rules of the default realm.
#[derive(Clone, Debug)]
pub struct LocalNameMapper {
    /// The default realm; with none, nothing translates.
    default_realm: Option<String>,
    /// `auth_to_local_names`: principal name without realm to local name.
    names: BTreeMap<String, String>,
    /// `auth_to_local` values in order; empty means `DEFAULT`.
    rules: Vec<AuthToLocalRule>,
}

/// The authorization half: the mapper, the account database and the
/// `.k5login` policy.
#[derive(Clone, Debug)]
pub struct LocalAuthorizer {
    /// The `an2ln` mapping.
    mapper: LocalNameMapper,
    /// The caller's account database.
    resolver: Arc<dyn AccountResolver>,
    /// `k5login_authoritative`: a `.k5login` denial is final.
    authoritative: bool,
    /// `k5login_directory`: when set, the file of account `a` is `<dir>/a`.
    directory: Option<PathBuf>,
}

/// The module that allowed an authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Module {
    /// The account's `.k5login` lists the principal.
    K5login,
    /// The principal translates to exactly the requested account name.
    An2ln,
}

/// Why an authorization was refused.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Denial {
    /// The requested account name is empty, too long or contains a NUL byte.
    InvalidLocalName,
    /// No module allowed it: no usable `.k5login` and no matching translation.
    NoModuleAllowed,
    /// The `.k5login` module refused it (final while authoritative).
    K5login(k5login::Fault),
}

/// The answer of [`authorize_local`].
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Authorization {
    /// The principal may act as the account.
    Authorized(Module),
    /// It may not.
    Denied(Denial),
}

/// May the verified `principal` act as the local account `local_name`?
///
/// MIT `krb5_kuserok` (`localauth.c:386-406`): the `.k5login` module runs
/// first; its refusal is final while `k5login_authoritative` is true, its
/// permission or its silence (no file) leaves the `an2ln` rule, which allows
/// the account `principal_to_local_name` yields.
#[must_use]
#[inline]
pub fn authorize_local(
    authorizer: &LocalAuthorizer,
    principal: &Principal,
    local_name: &str,
) -> Authorization {
    authorizer.authorize(principal, local_name)
}

/// Translate the verified `principal` to a local account name.
///
/// MIT `krb5_aname_to_localname` (`localauth.c:408-436`): the explicit
/// `auth_to_local_names` mapping first, then the `auth_to_local` rules in
/// order (the first that translates wins; a rule that does not apply is
/// skipped), then `DEFAULT` when no rule is configured.
///
/// # Errors
///
/// [`error::LocalAuth::NoTranslation`](crate::error::LocalAuth::NoTranslation)
/// when nothing translates, and
/// [`error::LocalAuth::InvalidLocalName`](crate::error::LocalAuth::InvalidLocalName)
/// for an empty, over-long or NUL-containing result.
#[inline]
pub fn principal_to_local_name(
    mapper: &LocalNameMapper,
    principal: &Principal,
) -> Result<String, crate::error::LocalAuth> {
    mapper.translate(principal)
}

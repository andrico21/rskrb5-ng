//! Pure credential-name parameter expansion.
//!
//! The [MIT parameter table](https://web.mit.edu/kerberos/krb5-1.22/doc/admin/conf_files/krb5_conf.html#parameter-expansion)
//! defines the replacement facts. `USERCONFIGDIR` is a requested extension
//! aliasing MIT's `USERCONFIG`. Callers supply installation and account facts;
//! no environment, filesystem or identity discovery happens here.

use core::fmt::NumBuffer;

use super::LibDefaults;

/// Caller-supplied facts used by MIT profile name templates.
#[derive(Clone, Copy, Debug, Default)]
#[non_exhaustive]
pub struct ExpansionContext<'value> {
    /// Temporary directory, without an added separator.
    pub temp: Option<&'value str>,
    /// Linux real process UID; never the `UID` environment variable.
    pub uid: Option<u32>,
    /// Linux effective process UID.
    pub euid: Option<u32>,
    /// Username belonging to the effective identity, not an environment hint.
    pub username: Option<&'value str>,
    /// Windows security identifier for `USERID` (Linux uses `uid`).
    pub windows_sid: Option<&'value str>,
    /// Installation library directory.
    pub libdir: Option<&'value str>,
    /// Installation binary directory.
    pub bindir: Option<&'value str>,
    /// Installation administrative binary directory.
    pub sbindir: Option<&'value str>,
    /// Per-user MIT configuration directory (`USERCONFIGDIR` / `USERCONFIG`).
    pub userconfigdir: Option<&'value str>,
    /// Roaming application data directory.
    pub appdata: Option<&'value str>,
}

/// Expansion failures distinguish invalid syntax from unavailable facts.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum Failure {
    /// The token name is not supported (names are case-sensitive).
    #[error("unknown profile parameter: {0}")]
    UnknownToken(String),
    /// An opening `%{` has no closing brace.
    #[error("profile parameter is missing its closing brace")]
    UnterminatedToken,
    /// A recognized token lacks a fact or is unsupported on this platform.
    ///
    /// The payload names what is missing: a token, the environment variable that the
    /// ambient resolver read (`TMPDIR`, `TEMP` or `APPDATA`) or the process identity.
    #[error("profile parameter unavailable: {0}")]
    Unavailable(&'static str),
}

/// Select one of the three parameterized credential-name relations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DefaultName {
    /// `default_ccache_name`.
    Ccache,
    /// `default_keytab_name`.
    Keytab,
    /// `default_client_keytab_name`.
    ClientKeytab,
}

impl DefaultName {
    /// Resolve a profile's selected name without modifying its template.
    ///
    /// # Errors
    /// Returns the syntax, unknown-token or missing-context error from [`expand`].
    #[inline]
    pub fn expand(
        self,
        defaults: &LibDefaults,
        context: &ExpansionContext<'_>,
    ) -> Result<String, Failure> {
        let template = match self {
            Self::Ccache => &defaults.default_ccache_name,
            Self::Keytab => &defaults.default_keytab_name,
            Self::ClientKeytab => &defaults.default_client_keytab_name,
        };
        expand(template, context)
    }
}

/// Expand a credential-name template using only explicit caller facts.
///
/// Like [MIT 1.22.2's scanner](https://github.com/krb5/krb5/blob/krb5-1.22.2-final/src/lib/krb5/os/expand_path.c),
/// this recognizes only `%{name}`: `%%` stays `%%`, `%%{TEMP}` is a literal
/// percent followed by a substitution, and replacement values are never rescanned.
/// Names must match exactly; MIT's incidental prefix matching is not reproduced.
/// No path-separator conversion is performed on caller-provided facts.
///
/// `uid` and `euid` retain this crate's Linux-only policy, including when facts
/// are supplied explicitly. `USERID` aliases `uid` on Linux and accepts a SID
/// on Windows. Directory and username facts may be supplied on any platform.
/// The returned string is resolved data, not another template: use literal-path
/// file APIs rather than passing it through a token-expanding name API again.
///
/// # Errors
/// Returns [`Failure`] for malformed, unknown or unavailable parameters.
#[inline]
pub fn expand(template: &str, context: &ExpansionContext<'_>) -> Result<String, Failure> {
    let mut remaining = template;
    let mut output = String::new();
    while let Some((literal, suffix)) = remaining.split_once("%{") {
        output.push_str(literal);
        let (token, rest) = suffix.split_once('}').ok_or(Failure::UnterminatedToken)?;
        let mut number = NumBuffer::<u32>::new();
        output.push_str(match token {
            "null" => "",
            "TEMP" => context.temp.ok_or(Failure::Unavailable("TEMP"))?,
            "LIBDIR" => context.libdir.ok_or(Failure::Unavailable("LIBDIR"))?,
            "BINDIR" => context.bindir.ok_or(Failure::Unavailable("BINDIR"))?,
            "SBINDIR" => context.sbindir.ok_or(Failure::Unavailable("SBINDIR"))?,
            "username" => context.username.ok_or(Failure::Unavailable("username"))?,
            "USERCONFIGDIR" | "USERCONFIG" => context
                .userconfigdir
                .ok_or(Failure::Unavailable("USERCONFIGDIR"))?,
            "APPDATA" => context.appdata.ok_or(Failure::Unavailable("APPDATA"))?,
            "uid" if cfg!(target_os = "linux") => context
                .uid
                .ok_or(Failure::Unavailable("uid"))?
                .format_into(&mut number),
            "euid" if cfg!(target_os = "linux") => context
                .euid
                .ok_or(Failure::Unavailable("euid"))?
                .format_into(&mut number),
            "USERID" if cfg!(target_os = "linux") => context
                .uid
                .ok_or(Failure::Unavailable("USERID"))?
                .format_into(&mut number),
            "USERID" if cfg!(windows) => {
                context.windows_sid.ok_or(Failure::Unavailable("USERID"))?
            }
            "uid" => return Err(Failure::Unavailable("uid")),
            "euid" => return Err(Failure::Unavailable("euid")),
            "USERID" => return Err(Failure::Unavailable("USERID")),
            _ => return Err(Failure::UnknownToken(token.to_owned())),
        });
        remaining = rest;
    }
    output.push_str(remaining);
    Ok(output)
}

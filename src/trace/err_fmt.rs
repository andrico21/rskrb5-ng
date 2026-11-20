//! The `err_fmt` libdefaults relation: MIT's error-message template.
//!
//! MIT re-formats an error message with `err_fmt` when a caller asks for it
//! (`krb5_get_error_message`, MIT 1.22.2 `src/lib/krb5/krb/kerrs.c:171-190`):
//! `%M` becomes the ordinary message, `%C` the decimal error code, `%%` a
//! percent sign, and any other `%c` stays as written (`kerrs.c:138-169`).
//! The profile relation is read once, in `krb5_init_context`
//! (`src/lib/krb5/krb/init_ctx.c:299-300`).
//!
//! Here the typed error is never altered. [`ErrFmt::report`] wraps a borrowed
//! error in a [`Report`] whose `Display` is the formatted text and whose
//! `source` is the original error, so a handler still matches the typed
//! variant, reads its code and walks its sources.
//!
//! # Security
//!
//! The template is presentation only: it changes no code, no source and no
//! authentication decision. The output is the template plus the message plus
//! at most 20 bytes per `%C`, and nothing is escaped, as in MIT: the caller
//! who prints it to a terminal owns that decision, as with any error text.

use core::{error::Error as StdError, fmt};

use crate::config::Config;
#[cfg(feature = "messages")]
use crate::error::{Any, Client};

/// MIT's `ERROR_TABLE_BASE_krb5`: the `com_err` base of the Kerberos table; a
/// KDC's KRB-ERROR number `n` is the code `BASE + n` (`get_in_tkt.c`).
pub const KRB5_ERROR_BASE: i64 = -1_765_328_384;

/// A parsed `err_fmt` template, or none.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ErrFmt {
    /// The template; `None` leaves messages as they are.
    template: Option<String>,
}

impl ErrFmt {
    /// No template: messages stay as they are.
    #[inline]
    #[must_use]
    pub const fn unset() -> Self {
        Self { template: None }
    }

    /// A template. An empty one counts as none (the library cannot tell an
    /// empty relation from an absent one, and MIT's would erase every message).
    #[inline]
    #[must_use]
    pub fn new(template: &str) -> Self {
        Self {
            template: (!template.is_empty()).then(|| template.to_owned()),
        }
    }

    /// The `err_fmt` of `config`'s `[libdefaults]`.
    #[inline]
    #[must_use]
    pub fn from_config(config: &Config) -> Self {
        Self::new(&config.libdefaults.err_fmt)
    }

    /// The template, if any.
    #[inline]
    #[must_use]
    pub fn template(&self) -> Option<&str> {
        self.template.as_deref()
    }

    /// `message` re-formatted for `code` (MIT `err_fmt_fmt`, `kerrs.c:140-169`).
    #[inline]
    #[must_use]
    pub fn format(&self, code: i64, message: &str) -> String {
        let Some(template) = &self.template else {
            return message.to_owned();
        };
        let mut out = String::with_capacity(template.len().saturating_add(message.len()));
        let mut rest = template.as_str();
        while let Some(at) = rest.find('%') {
            out.push_str(rest.get(..at).unwrap_or_default());
            let tail = rest.get(at..).unwrap_or_default();
            let mut chars = tail.chars();
            let _percent = chars.next();
            match chars.next() {
                None => {
                    out.push('%');
                    return out;
                }
                Some('M') => out.push_str(message),
                Some('C') => out.push_str(&code.to_string()),
                Some('%') => out.push('%'),
                Some(other) => {
                    out.push('%');
                    out.push(other);
                }
            }
            rest = chars.as_str();
        }
        out.push_str(rest);
        out
    }

    /// `error` as a [`Report`]: the formatted text, over the unchanged error.
    #[inline]
    #[must_use]
    pub fn report<'error, E>(&self, error: &'error E) -> Report<'error, E>
    where
        E: StdError + 'static,
    {
        let code = code_of(error);
        Report {
            error,
            code,
            text: self.format(code, &error.to_string()),
        }
    }
}

/// An error presented through `err_fmt`.
///
/// `Display` is the formatted text. [`Self::error`] and `source` return the
/// original, so no code or source is lost. `Debug` shows the code and the size
/// of the text, never the error or its text.
pub struct Report<'error, E> {
    /// The original error.
    error: &'error E,
    /// Its `com_err`-style code, 0 when it has none.
    code: i64,
    /// The formatted text.
    text: String,
}

impl<E> Report<'_, E> {
    /// The unchanged typed error.
    #[inline]
    #[must_use]
    pub const fn error(&self) -> &E {
        self.error
    }

    /// The `%C` code: MIT's `com_err` code of a KDC KRB-ERROR, else 0.
    #[inline]
    #[must_use]
    pub const fn code(&self) -> i64 {
        self.code
    }
}

impl<E> fmt::Debug for Report<'_, E> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Report")
            .field("code", &self.code)
            .field("text_bytes", &self.text.len())
            .finish_non_exhaustive()
    }
}

impl<E> fmt::Display for Report<'_, E> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

impl<E> StdError for Report<'_, E>
where
    E: StdError + 'static,
{
    #[inline]
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(self.error)
    }
}

/// The code of an error: a KDC's KRB-ERROR number on MIT's `com_err` base, else 0.
fn code_of(error: &(dyn StdError + 'static)) -> i64 {
    kdc_error_number(error).map_or(0, |number| {
        KRB5_ERROR_BASE.saturating_add(i64::from(number))
    })
}

/// The KRB-ERROR number of a KDC refusal, if `error` is one.
#[cfg(feature = "messages")]
fn kdc_error_number(error: &(dyn StdError + 'static)) -> Option<i32> {
    match error.downcast_ref::<Any>() {
        Some(Any::Client(Client::Kdc(kdc))) => Some(kdc.error_code()),
        _ => match error.downcast_ref::<Client>() {
            Some(Client::Kdc(kdc)) => Some(kdc.error_code()),
            _ => None,
        },
    }
}

/// Without `messages` there is no KDC error type.
#[cfg(not(feature = "messages"))]
const fn kdc_error_number(_error: &(dyn StdError + 'static)) -> Option<i32> {
    None
}

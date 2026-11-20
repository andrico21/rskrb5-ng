//! Password and account expiry as a KDC reports it (MIT `get_in_tkt.c:1473-1580`).

use core::{fmt, time::Duration};
use std::time::SystemTime;

use chrono::{DateTime, SecondsFormat, Utc};

use super::super::{Error, system_time_from_kerberos_time};

/// RFC 4120 `last-req` type 6: the time the principal's password expires, for all servers.
const LRQ_ALL_PW_EXPTIME: i32 = 6;
/// RFC 4120 `last-req` type -6: the password expiry as known to this server only.
const LRQ_ONE_PW_EXPTIME: i32 = -6;
/// RFC 4120 `last-req` type 7: the time the account expires, for all servers.
const LRQ_ALL_ACCT_EXPTIME: i32 = 7;
/// RFC 4120 `last-req` type -7: the account expiry as known to this server only.
const LRQ_ONE_ACCT_EXPTIME: i32 = -7;
/// MIT warns about an expiry derived from the ambiguous `key-expiration` field only
/// within a week (`get_in_tkt.c:1553`).
const KEY_EXPIRATION_WARNING_WINDOW: Duration = Duration::from_hours(7 * 24);

/// What the KDC said about the lifetime of the password and the account in an AS reply.
///
/// MIT `get_expiry_times` (`get_in_tkt.c:1473-1504`): `last-req` entries of type 6 or
/// -6 give the password expiry and of type 7 or -7 the account expiry; when the reply
/// carries none of them, the ambiguous `key-expiration` field stands for the password.
/// The values are informational: they are read from the encrypted part of an
/// authenticated reply and never change what the exchange does.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct ExpiryNotice {
    /// When the password expires.
    password: Option<SystemTime>,
    /// When the account expires.
    account: Option<SystemTime>,
    /// Whether a `last-req` entry reported an expiry, which MIT takes as the KDC asking
    /// the client to warn.
    from_last_req: bool,
}

impl ExpiryNotice {
    /// No expiry reported, for constructors of sessions that carry no reply.
    pub(in crate::client) const DEFAULT: Self = Self {
        password: None,
        account: None,
        from_last_req: false,
    };

    /// When the password expires, if the KDC said.
    #[inline]
    #[must_use]
    pub const fn password(&self) -> Option<SystemTime> {
        self.password
    }

    /// When the account expires, if the KDC said.
    #[inline]
    #[must_use]
    pub const fn account(&self) -> Option<SystemTime> {
        self.account
    }

    /// Whether the expiry came from a `last-req` entry (MIT `is_last_req`) rather than
    /// from the ambiguous `key-expiration` field.
    #[inline]
    #[must_use]
    pub const fn from_last_req(&self) -> bool {
        self.from_last_req
    }

    /// Read the expiry of an authenticated AS reply's encrypted part.
    ///
    /// # Errors
    ///
    /// Returns the time conversion error of an out-of-range expiry time.
    pub(in crate::client) fn from_enc_part(
        enc_part: &rasn_kerberos::EncKdcRepPart,
    ) -> Result<Self, Error> {
        let mut notice = Self::default();
        for entry in &enc_part.last_req {
            match entry.r#type {
                LRQ_ALL_PW_EXPTIME | LRQ_ONE_PW_EXPTIME => {
                    notice.from_last_req = true;
                    notice.password = Some(system_time_from_kerberos_time(&entry.value)?);
                }
                LRQ_ALL_ACCT_EXPTIME | LRQ_ONE_ACCT_EXPTIME => {
                    notice.from_last_req = true;
                    notice.account = Some(system_time_from_kerberos_time(&entry.value)?);
                }
                _ => {}
            }
        }
        if !notice.from_last_req {
            notice.password = enc_part
                .key_expiration
                .as_ref()
                .map(system_time_from_kerberos_time)
                .transpose()?;
        }
        Ok(notice)
    }

    /// The warning MIT's default prompter shows at `now` (`get_in_tkt.c:1536-1580`), if any.
    ///
    /// An expiry from a `last-req` entry always warns; one from `key-expiration` warns
    /// only while it is still in the future and less than a week away.
    #[inline]
    #[must_use]
    pub fn warning(&self, now: SystemTime) -> Option<ExpiryWarning> {
        let expires = self.password?;
        let remaining = expires.duration_since(now).unwrap_or(Duration::ZERO);
        let in_window = !remaining.is_zero() && remaining <= KEY_EXPIRATION_WARNING_WINDOW;
        (self.from_last_req || in_window).then_some(ExpiryWarning { expires, remaining })
    }
}

/// An impending password expiry, rendered as MIT's warning banner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ExpiryWarning {
    /// When the password expires.
    pub expires: SystemTime,
    /// How long that is from the moment of the warning; zero when it is past.
    pub remaining: Duration,
}

impl fmt::Display for ExpiryWarning {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let when = DateTime::<Utc>::from(self.expires).to_rfc3339_opts(SecondsFormat::Secs, true);
        let seconds = self.remaining.as_secs();
        if seconds < 3600 {
            write!(
                f,
                "Warning: Your password will expire in less than one hour on {when}"
            )
        } else if seconds < 2 * 86_400 {
            let hours = seconds / 3600;
            let plural = if seconds < 7200 { "" } else { "s" };
            write!(
                f,
                "Warning: Your password will expire in {hours} hour{plural} on {when}"
            )
        } else {
            let days = seconds / 86_400;
            write!(
                f,
                "Warning: Your password will expire in {days} days on {when}"
            )
        }
    }
}

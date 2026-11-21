//! Password expiry through a responder: change an expired password and log in again
//! (MIT `krb5_get_init_creds_password`, `gic_pwd.c:171-343`).

use core::fmt;

use super::{
    super::{Error, Password, Principal},
    last_req::ExpiryNotice,
};
use crate::{
    error::Kadmin,
    extensions::ProviderError,
    kadmin::{ChangePasswordResult, KPASSWD_SOFTERROR, result_text::ResultCode},
};

/// MIT asks for a new password three times at most (`gic_pwd.c:248`).
const NEW_PASSWORD_TRIES: u8 = 3;

/// Why the responder is asked for a new password.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ChangeReason {
    /// The password has expired and must be changed to log in.
    Expired,
    /// The previous answer was empty (MIT `KRB5_CHPW_PWDNULL`).
    EmptyPassword,
    /// The server rejected the previous answer, usually by password policy.
    Rejected {
        /// The result code the server answered.
        kind: ResultCode,
        /// The server's message, as MIT's `krb5_chpw_message` renders it.
        message: String,
    },
}

impl fmt::Display for ChangeReason {
    /// MIT's banner for the prompt.
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Expired => f.write_str("Password expired.  You must change it now."),
            Self::EmptyPassword => {
                f.write_str("New password cannot be zero length.  Please try again.")
            }
            Self::Rejected { kind, message } => {
                write!(f, "{}: {message}.  Please try again.", kind.description())
            }
        }
    }
}

/// A request for the user's new password.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct NewPasswordPrompt<'prompt> {
    /// The principal whose password is being changed.
    client: &'prompt Principal,
    /// Why the password is asked for.
    reason: &'prompt ChangeReason,
    /// How many answers the flow will still accept, this one included.
    tries_left: u8,
}

impl<'prompt> NewPasswordPrompt<'prompt> {
    /// The principal whose password is being changed.
    #[inline]
    #[must_use]
    pub const fn client(&self) -> &'prompt Principal {
        self.client
    }

    /// Why the password is asked for; its `Display` is MIT's banner.
    #[inline]
    #[must_use]
    pub const fn reason(&self) -> &'prompt ChangeReason {
        self.reason
    }

    /// How many answers the flow will still accept, this one included.
    #[inline]
    #[must_use]
    pub const fn tries_left(&self) -> u8 {
        self.tries_left
    }
}

/// Answers the questions of a login whose password may expire: MIT's prompter and
/// expire callback (`krb5_get_init_creds_opt_set_expire_callback`).
pub trait ExpiryResponder {
    /// The KDC reported when the password and the account expire; called once after a
    /// successful login, including one that followed a password change. The default
    /// does nothing.
    #[inline]
    fn expiry_notice(&mut self, notice: &ExpiryNotice) {
        let _: &ExpiryNotice = notice;
    }

    /// The new password for the expired password of the prompt's client.
    ///
    /// An empty answer is asked for again; confirming it (MIT's "Enter it again") is the
    /// responder's business.
    ///
    /// # Errors
    ///
    /// Returns the caller's failure, for example a refusal to change the password; the
    /// login fails with [`Error::Responder`] and nothing is changed.
    fn new_password(&mut self, prompt: &NewPasswordPrompt<'_>) -> Result<Password, ProviderError>;
}

/// The responder's turns at giving a new password for an expired one (MIT `gic_pwd.c:231-322`):
/// three answers, each rejected one named to the next prompt.
pub(in crate::client) struct Turns {
    /// Why the next answer is asked for.
    reason: ChangeReason,
    /// The answers the responder may still give.
    tries_left: u8,
    /// The server's last rejection by password policy.
    rejection: Option<Error>,
}

impl Turns {
    /// Three turns for a password that expired.
    pub(in crate::client) const fn new() -> Self {
        Self {
            reason: ChangeReason::Expired,
            tries_left: NEW_PASSWORD_TRIES,
            rejection: None,
        }
    }

    /// The next non-empty new password; `None` once the turns are used up.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Responder`] when the responder fails.
    pub(in crate::client) fn ask<R>(
        &mut self,
        responder: &mut R,
        client: &Principal,
    ) -> Result<Option<Password>, Error>
    where
        R: ExpiryResponder + ?Sized,
    {
        while self.tries_left > 0 {
            let answer = responder
                .new_password(&NewPasswordPrompt {
                    client,
                    reason: &self.reason,
                    tries_left: self.tries_left,
                })
                .map_err(Error::Responder)?;
            self.tries_left = self.tries_left.saturating_sub(1);
            if answer.as_bytes().is_empty() {
                self.reason = ChangeReason::EmptyPassword;
            } else {
                return Ok(Some(answer));
            }
        }
        Ok(None)
    }

    /// Account for a failed change: a rejection by password policy gives the responder
    /// another turn; any other failure ends the flow.
    ///
    /// # Errors
    ///
    /// Returns `failure` unless it is a `KPASSWD_SOFTERROR`.
    pub(in crate::client) fn rejected(&mut self, failure: Error) -> Result<(), Error> {
        let Error::Kadmin(Kadmin::PasswordChangeFailed {
            code,
            text,
            text_raw,
        }) = failure
        else {
            return Err(failure);
        };
        if code != KPASSWD_SOFTERROR {
            return Err(Error::Kadmin(Kadmin::PasswordChangeFailed {
                code,
                text,
                text_raw,
            }));
        }
        let result = ChangePasswordResult {
            code,
            text: text.clone(),
            text_raw: text_raw.clone(),
        };
        self.reason = ChangeReason::Rejected {
            kind: result.kind(),
            message: result.message(),
        };
        self.rejection = Some(Error::Kadmin(Kadmin::PasswordChangeFailed {
            code,
            text,
            text_raw,
        }));
        Ok(())
    }

    /// The error that ends the flow when the turns are used up: the last rejection, or the
    /// responder's empty answers.
    pub(in crate::client) fn exhausted(self) -> Error {
        self.rejection.unwrap_or_else(|| {
            Error::Responder(ProviderError::from(
                "the responder offered only empty passwords",
            ))
        })
    }
}

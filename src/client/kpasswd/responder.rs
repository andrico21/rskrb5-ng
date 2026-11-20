//! Password expiry through a responder: change an expired password and log in again
//! (MIT `krb5_get_init_creds_password`, `gic_pwd.c:171-343`).

use core::fmt;

use super::{
    super::{
        AsRepSession, Error, KDC_ERR_KEY_EXPIRED, Password, Principal, Tokio,
        TokioClientCredentials, current_preauth_time, random_nonce,
    },
    RequestOptions,
    expiry::ExpiryNotice,
};
use crate::{
    error::Kadmin,
    extensions::ProviderError,
    kadmin::{ChangePasswordResult, KPASSWD_SOFTERROR, policy::ResultCode},
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

impl Tokio {
    /// Log in like [`Self::login`], and change an expired password through `responder`.
    ///
    /// When the KDC answers `KDC_ERR_KEY_EXPIRED` to a password login, this follows MIT:
    /// it gets a `kadmin/changepw` ticket with the old password (an AS reply the KDC
    /// could only seal under that password), asks the responder for a new one, sends the
    /// change, and starts the login over with the new password only after the server's
    /// authenticated success; the stored password becomes the new one. A rejection by
    /// password policy (`KPASSWD_SOFTERROR`) is put to the responder again, three
    /// answers in all. After the login `responder` hears the expiry the KDC reported.
    ///
    /// `sender_address` is the address of this host that the kpasswd request names.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PasswordChangePending`] before anything is sent while an earlier
    /// change is unconfirmed, [`Error::Responder`] when the responder fails, the errors
    /// of [`Self::login`] and of [`Self::change_password_with_options`], and the last
    /// `PasswordChangeFailed` when three answers were rejected. A change whose outcome is
    /// unknown ends the flow with [`Error::KpasswdOutcomeUnknown`]; it is never repeated
    /// and the AS is not restarted. KDC errors other than the expiry, and an expiry of a
    /// keytab credential, are returned as they are.
    ///
    /// # Security
    ///
    /// The `KDC_ERR_KEY_EXPIRED` error is unauthenticated: it can only make the client ask
    /// for a new password, and nothing is sent until the `kadmin/changepw` AS reply has
    /// decrypted under the old password. The AS is restarted only after a kpasswd
    /// reply that authenticated under that ticket's session key.
    ///
    /// # Cancel safety
    ///
    /// NOT cancel-safe once the change request is sent: dropping the future then leaves the
    /// outcome unknown, the next call returns [`Error::PasswordChangePending`] and sends
    /// nothing until [`Self::acknowledge_password_change_outcome`]. Before the request is
    /// sent, nothing on the server has changed.
    #[inline]
    pub async fn login_with_expiry<R>(
        &mut self,
        responder: &mut R,
        sender_address: rasn_kerberos::HostAddress,
    ) -> Result<&AsRepSession, Error>
    where
        R: ExpiryResponder + ?Sized,
    {
        if self.unresolved_password_change {
            return Err(Error::PasswordChangePending);
        }
        match self.login().await.map(|_session| ()) {
            Ok(()) => {}
            Err(Error::Kdc(error))
                if error.error_code() == KDC_ERR_KEY_EXPIRED
                    && matches!(self.credentials, Some(TokioClientCredentials::Password(_))) =>
            {
                self.change_expired_password(responder, sender_address)
                    .await?;
            }
            Err(error) => return Err(error),
        }
        // The TGT the login just cached: no further exchange.
        let session = self.affirm_login().await?;
        responder.expiry_notice(session.expiry_notice());
        Ok(session)
    }

    /// Whether a password change may have reached the server without a confirmed result:
    /// its request was sent and the reply was lost, unauthenticated or never read.
    #[inline]
    #[must_use]
    pub const fn has_unresolved_password_change(&self) -> bool {
        self.unresolved_password_change
    }

    /// Record that the caller verified the outcome of the earlier password change, for
    /// example with a fresh login, so that a change may be made again.
    #[inline]
    pub const fn acknowledge_password_change_outcome(&mut self) {
        self.unresolved_password_change = false;
    }

    /// The change of MIT `gic_pwd.c:231-322`, up to three answers of the responder, and
    /// the login with the new password after the authenticated success (`:327-336`).
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::login_with_expiry`] for the change and the login.
    async fn change_expired_password<R>(
        &mut self,
        responder: &mut R,
        sender_address: rasn_kerberos::HostAddress,
    ) -> Result<(), Error>
    where
        R: ExpiryResponder + ?Sized,
    {
        let mut reason = ChangeReason::Expired;
        let mut rejection = None;
        for tries_left in (1..=NEW_PASSWORD_TRIES).rev() {
            let client = self.client.clone();
            let new_password = responder
                .new_password(&NewPasswordPrompt {
                    client: &client,
                    reason: &reason,
                    tries_left,
                })
                .map_err(Error::Responder)?;
            if new_password.as_bytes().is_empty() {
                reason = ChangeReason::EmptyPassword;
                continue;
            }
            let (timestamp, cusec) = current_preauth_time()?;
            let options =
                RequestOptions::new(timestamp, cusec, random_nonce()?, sender_address.clone());
            match self
                .change_password_with_options(new_password, options)
                .await
            {
                Ok(_result) => {
                    // Authenticated success: only now does the AS start over.
                    let _session = self.login().await?;
                    return Ok(());
                }
                Err(Error::Kadmin(Kadmin::PasswordChangeFailed {
                    code,
                    text,
                    text_raw,
                })) if code == KPASSWD_SOFTERROR => {
                    let result = ChangePasswordResult {
                        code,
                        text: text.clone(),
                        text_raw: text_raw.clone(),
                    };
                    reason = ChangeReason::Rejected {
                        kind: result.kind(),
                        message: result.message(),
                    };
                    rejection = Some(Error::Kadmin(Kadmin::PasswordChangeFailed {
                        code,
                        text,
                        text_raw,
                    }));
                }
                Err(error) => return Err(error),
            }
        }
        Err(rejection.unwrap_or_else(|| {
            Error::Responder(ProviderError::from(
                "the responder offered only empty passwords",
            ))
        }))
    }
}

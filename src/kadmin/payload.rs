//! Password payload ownership and encoding.

use core::{fmt, mem};

use rasn::types::Integer;

use super::{
    ChangePasswdData, Error,
    codec::{decode, kerberos_string, principal_name},
    secret_der,
};
use crate::{
    client::Password, crypto::selection, keytab::EncryptionKey, krb_priv::KRB_PRIV_ENCPART_USAGE,
};

impl fmt::Debug for ChangePasswdData {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            new_passwd: _,
            targ_name,
            targ_realm,
        } = self;
        f.debug_struct("ChangePasswdData")
            .field("new_passwd", &"[REDACTED]")
            .field("targ_name", targ_name)
            .field("targ_realm", targ_realm)
            .finish()
    }
}

impl ChangePasswdData {
    /// Create password-change data for the authenticated principal.
    #[must_use]
    #[inline]
    pub fn new(new_passwd: Password) -> Self {
        let payload = Self {
            new_passwd: new_passwd.as_bytes().to_vec().into(),
            targ_name: None,
            targ_realm: None,
        };
        drop(new_passwd);
        payload
    }

    /// Create password-change data for an explicit target principal.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKerberosString`] when a name component or the
    /// realm is not a valid Kerberos string.
    #[inline]
    pub fn for_target<I, S>(
        new_passwd: Password,
        name_type: i32,
        components: I,
        realm: &str,
    ) -> Result<Self, Error>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let targ_name = Some(principal_name(name_type, components)?);
        let targ_realm = Some(kerberos_string(realm)?);
        Ok(Self {
            targ_name,
            targ_realm,
            ..Self::new(new_passwd)
        })
    }

    /// Decode DER-encoded password-change data.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Decode`] when `bytes` is not DER `ChangePasswdData`.
    #[inline]
    pub fn decode_der(bytes: &[u8]) -> Result<Self, Error> {
        decode("ChangePasswdData", bytes)
    }

    /// Encode password-change data using DER.
    ///
    /// The returned allocation belongs to the caller, who must erase it after use.
    /// The request builders retain their encoding in zeroizing storage instead.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Encode`] when the DER encoder fails.
    #[inline]
    pub fn encode_der(&self) -> Result<Vec<u8>, Error> {
        let mut encoded = secret_der::change_data(self)?;
        Ok(mem::take(&mut *encoded))
    }
}

/// Encrypt an already encoded password envelope without copying its plaintext.
///
/// # Errors
/// Returns an unsupported-enctype or encryption error.
pub(super) fn encrypt(
    plaintext: &[u8],
    key: &EncryptionKey,
    confounder: &[u8],
) -> Result<rasn_kerberos::KrbPriv, Error> {
    let etype = selection::enctype(key.etype)?.ok_or(Error::UnsupportedEtype(key.etype))?;
    let cipher = etype.encrypt_message_with_confounder(
        &key.value,
        plaintext,
        KRB_PRIV_ENCPART_USAGE,
        confounder,
    )?;
    Ok(rasn_kerberos::KrbPriv {
        pvno: Integer::from(5_i32),
        msg_type: Integer::from(21_i32),
        enc_part: rasn_kerberos::EncryptedData {
            etype: key.etype,
            kvno: None,
            cipher: cipher.into(),
        },
    })
}

/// Password-storage erasure regression.
#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use zeroize::{Zeroize, ZeroizeOnDrop};

    use super::{ChangePasswdData, Password};

    /// Compile-time proof that the password owner erases itself on drop.
    fn erase<T>(value: &mut T)
    where
        T: Zeroize + ZeroizeOnDrop,
    {
        value.zeroize();
    }

    /// The password value supports explicit erasure and owns its drop erasure.
    #[test]
    fn password_storage_is_zeroizing() -> Result<(), super::Error> {
        // Given a password owned by the protocol payload.
        let mut payload = ChangePasswdData::for_target(
            Password::copy_from_str("erasure-canary"),
            1,
            ["testuser"],
            "TEST.GOKRB5",
        )?;
        // When the same erasure primitive used at drop is invoked.
        erase(&mut payload.new_passwd);
        // Then no password bytes remain accessible through the owner.
        assert!(
            payload.new_passwd.as_ref().is_empty(),
            "password owner must be erased"
        );
        Ok(())
    }
}

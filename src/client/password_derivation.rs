//! One boundary for all KDC-supplied password string-to-key parameters.
use super::{
    EncryptionKey, Error, PreauthKeyInfo, Principal, default_password_salt, encode_hex_lower,
};
use crate::crypto::{CryptoPolicy, selection};

/// Validate the selected family's work factor before salt allocation and PBKDF2.
/// # Errors
/// Returns unsupported enctype, parameter syntax/ceiling, policy minimum or crypto errors.
pub(super) fn derive(
    policy: &CryptoPolicy,
    client: &Principal,
    password: &[u8],
    key_info: &PreauthKeyInfo,
) -> Result<EncryptionKey, Error> {
    let etype =
        selection::enctype(key_info.etype)?.ok_or(Error::UnsupportedEtype(key_info.etype))?;
    let params = key_info.s2kparams.as_ref().map_or_else(
        || etype.default_s2kparams().to_owned(),
        |bytes| encode_hex_lower(bytes),
    );
    policy.check_s2k_params(key_info.etype, &params)?;
    let salt = key_info
        .salt
        .clone()
        .unwrap_or_else(|| default_password_salt(client));
    Ok(EncryptionKey {
        etype: key_info.etype,
        value: etype
            .string_to_key(password, salt.as_bytes(), &params)?
            .into(),
    })
}

//! Policy-checked semantic import, separate from raw ASN.1 conversion.

use super::{convert_credentials, decode, decrypt_part};
use crate::{
    ccache::Credential,
    crypto::{CryptoPolicy, Use},
    error::KrbCred as Error,
    keytab::EncryptionKey,
};

/// Import decrypted credentials only after checking every ticket and session key.
///
/// # Errors
/// Returns typed policy errors before conversion, or raw conversion errors.
#[inline]
pub fn decrypted(
    policy: &CryptoPolicy,
    credential: &rasn_kerberos::KrbCred,
    part: &rasn_kerberos::EncKrbCredPart,
) -> Result<Vec<Credential>, Error> {
    for info in &part.ticket_info {
        policy.check_use(info.key.r#type, Use::ImportedCredential)?;
    }
    for ticket in &credential.tickets {
        policy.check_use(ticket.enc_part.etype, Use::ImportedCredential)?;
    }
    convert_credentials(credential, part)
}

/// Decrypt and import credentials with explicit runtime permission.
///
/// # Errors
/// Rejects wrapping/ticket enctypes before decryption and session enctypes as
/// soon as authenticated plaintext exposes them, before credential conversion.
#[inline]
pub fn decrypt(
    policy: &CryptoPolicy,
    credential: &rasn_kerberos::KrbCred,
    key: &EncryptionKey,
) -> Result<Vec<Credential>, Error> {
    policy.check_use(key.etype(), Use::ImportedCredential)?;
    policy.check_use(credential.enc_part.etype, Use::ImportedCredential)?;
    for ticket in &credential.tickets {
        policy.check_use(ticket.enc_part.etype, Use::ImportedCredential)?;
    }
    let part = decrypt_part(credential, key)?;
    decrypted(policy, credential, &part)
}

/// Decode and import a protected KRB-CRED under explicit runtime policy.
///
/// # Errors
/// Returns policy, DER or authenticated conversion errors.
#[inline]
pub fn decode_decrypt(
    policy: &CryptoPolicy,
    bytes: &[u8],
    key: &EncryptionKey,
) -> Result<Vec<Credential>, Error> {
    policy.check_use(key.etype(), Use::ImportedCredential)?;
    decrypt(policy, &decode(bytes)?, key)
}

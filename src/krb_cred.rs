//! KRB-CRED decoding and encrypted-part helpers.
//!
//! The codec/conversion functions here are raw RFC-vector operations. Use
//! [`import`] for policy-checked semantic import before admitting credentials.
//!
//! # Security
//! Raw conversion preserves opaque enctype IDs and historical records for tools
//! and RFC fixtures; it does not authorize credential use. Raw encrypt/decrypt
//! helpers require caller-authorized keys. Checked import calls private shared
//! machinery only after `ImportedCredential` checks, never these public raw wrappers.

/// Policy-checked semantic credential import.
pub mod import;

/// Conversion of credential fields between ccache and ASN.1.
mod conversion;

use conversion::{ccache_credential_to_krb_cred_info, krb_cred_info_to_ccache_credential};
use rasn::{der, types::Integer};

use crate::{
    ccache,
    crypto::selection,
    der::{decode_complete, encrypted_der},
    error::Ticket as TicketError,
    keytab::EncryptionKey,
    messages::secret_der::SecretDer,
    ticket::{decode as decode_ticket, encode as encode_ticket},
};

/// Kerberos protocol version number carried in every message (RFC 4120).
const KRB5_PVNO: i32 = 5;

/// KRB-CRED message type.
pub const KRB_CRED_MSG_TYPE: i32 = 22;

/// Key usage for KRB-CRED encrypted parts.
pub const KRB_CRED_ENCPART_USAGE: u32 = 14;

/// Decode and validate a DER-encoded KRB-CRED message.
///
/// # Errors
///
/// Returns [`Error::Decode`] when `bytes` is not a DER KRB-CRED, and
/// [`Error::InvalidMessage`] when its protocol version or message type is wrong.
#[inline]
pub fn decode(bytes: &[u8]) -> Result<rasn_kerberos::KrbCred, Error> {
    let krb_cred = decode_der::<rasn_kerberos::KrbCred>("KRB-CRED", bytes)?;
    validate_integer("pvno", &krb_cred.pvno, KRB5_PVNO)?;
    validate_integer("msg-type", &krb_cred.msg_type, KRB_CRED_MSG_TYPE)?;
    Ok(krb_cred)
}

/// Decode a DER-encoded `EncKrbCredPart`.
///
/// # Errors
///
/// Returns [`Error::Decode`] when `bytes` is not a DER `EncKrbCredPart`.
#[inline]
pub fn decode_enc_krb_cred_part(bytes: &[u8]) -> Result<rasn_kerberos::EncKrbCredPart, Error> {
    decode_der::<rasn_kerberos::EncKrbCredPart>("EncKrbCredPart", bytes)
}

/// Decrypt and decode a KRB-CRED encrypted part.
///
/// # Errors
///
/// Returns [`Error::KeyEtypeMismatch`] when the key's enctype differs from the
/// encrypted part's, [`Error::UnsupportedEtype`] for an enctype that is not
/// implemented, [`Error::Crypto`] when decryption fails, and [`Error::Decode`]
/// when the plaintext is not a DER `EncKrbCredPart`.
#[inline]
pub fn decrypt_krb_cred_enc_part(
    krb_cred: &rasn_kerberos::KrbCred,
    key: &EncryptionKey,
) -> Result<rasn_kerberos::EncKrbCredPart, Error> {
    decrypt_part(krb_cred, key)
}

/// Shared decryption machinery; checked import authorizes inputs before entry.
/// # Errors
/// Returns key mismatch, cryptographic integrity or DER errors.
fn decrypt_part(
    krb_cred: &rasn_kerberos::KrbCred,
    key: &EncryptionKey,
) -> Result<rasn_kerberos::EncKrbCredPart, Error> {
    if key.etype != krb_cred.enc_part.etype {
        return Err(Error::KeyEtypeMismatch {
            key_etype: key.etype,
            encrypted_data_etype: krb_cred.enc_part.etype,
        });
    }
    let etype = selection::enctype(key.etype)?.ok_or(Error::UnsupportedEtype(key.etype))?;
    let plaintext = SecretDer::new(
        etype.decrypt_message(
            &key.value,
            krb_cred.enc_part.cipher.as_ref(),
            KRB_CRED_ENCPART_USAGE,
        )?,
        "krb-cred decrypt",
    );
    decode_enc_krb_cred_part(encrypted_der(&plaintext, key.etype))
}

/// Decrypt a KRB-CRED encrypted part and convert its tickets to ccache credentials.
///
/// # Errors
///
/// Returns the errors of [`decrypt_krb_cred_enc_part`] and
/// [`decrypted_krb_cred_to_ccache_credentials`].
#[inline]
pub fn decrypt_krb_cred_to_ccache_credentials(
    krb_cred: &rasn_kerberos::KrbCred,
    key: &EncryptionKey,
) -> Result<Vec<ccache::Credential>, Error> {
    let enc_part = decrypt_krb_cred_enc_part(krb_cred, key)?;
    decrypted_krb_cred_to_ccache_credentials(krb_cred, &enc_part)
}

/// Decode, decrypt, and convert a DER-encoded KRB-CRED to ccache credentials.
///
/// # Errors
///
/// Returns the errors of [`decode`] and
/// [`decrypt_krb_cred_to_ccache_credentials`].
#[inline]
pub fn decode_decrypt_krb_cred_to_ccache_credentials(
    bytes: &[u8],
    key: &EncryptionKey,
) -> Result<Vec<ccache::Credential>, Error> {
    let krb_cred = decode(bytes)?;
    decrypt_krb_cred_to_ccache_credentials(&krb_cred, key)
}

/// Convert ccache credentials into KRB-CRED tickets and a decrypted encrypted part.
///
/// # Errors
///
/// Returns [`Error::UnsupportedCredentialAuthData`] or
/// [`Error::UnsupportedSecondTicket`] for a credential carrying authorization
/// data or a second ticket, [`Error::Decode`] or [`Error::InvalidMessage`] when
/// a credential's ticket is not a valid DER Ticket,
/// [`Error::InvalidKerberosString`] for a realm or name component that is not a
/// Kerberos string, and [`Error::TimeOutOfRange`] for a time that is not a valid
/// Kerberos time.
#[inline]
pub fn ccache_credentials_to_krb_cred_parts(
    credentials: &[ccache::Credential],
) -> Result<(Vec<rasn_kerberos::Ticket>, rasn_kerberos::EncKrbCredPart), Error> {
    let mut tickets = Vec::with_capacity(credentials.len());
    let mut ticket_info = Vec::with_capacity(credentials.len());

    for credential in credentials {
        if !credential.auth_data.is_empty() {
            return Err(Error::UnsupportedCredentialAuthData);
        }
        if !credential.second_ticket.is_empty() {
            return Err(Error::UnsupportedSecondTicket);
        }

        let ticket = decode_ticket(&credential.ticket).map_err(ticket_error)?;
        tickets.push(ticket);
        ticket_info.push(ccache_credential_to_krb_cred_info(credential)?);
    }

    Ok((
        tickets,
        rasn_kerberos::EncKrbCredPart {
            ticket_info,
            nonce: None,
            timestamp: None,
            usec: None,
            sender_address: None,
            recipient_address: None,
        },
    ))
}

/// Encrypt ccache credentials into a KRB-CRED using a random confounder.
///
/// # Errors
///
/// Returns [`Error::UnsupportedEtype`] for a key whose enctype is not
/// implemented, [`Error::Random`] when the confounder cannot be generated, and
/// the errors of [`encrypt_ccache_credentials_to_krb_cred_with_confounder`].
#[inline]
pub fn encrypt_ccache_credentials(
    credentials: &[ccache::Credential],
    key: &EncryptionKey,
) -> Result<rasn_kerberos::KrbCred, Error> {
    let etype = selection::enctype(key.etype)?.ok_or(Error::UnsupportedEtype(key.etype))?;
    let mut confounder = vec![0; etype.confounder_len()];
    getrandom::fill(&mut confounder)?;
    encrypt_ccache_credentials_to_krb_cred_with_confounder(credentials, key, &confounder)
}

/// Encrypt ccache credentials into a KRB-CRED using an explicit confounder.
///
/// # Errors
///
/// Returns the errors of [`ccache_credentials_to_krb_cred_parts`],
/// [`Error::Encode`] when the encrypted part cannot be encoded,
/// [`Error::UnsupportedEtype`] for a key whose enctype is not implemented, and
/// [`Error::Crypto`] when encryption fails.
#[inline]
pub fn encrypt_ccache_credentials_to_krb_cred_with_confounder(
    credentials: &[ccache::Credential],
    key: &EncryptionKey,
    confounder: &[u8],
) -> Result<rasn_kerberos::KrbCred, Error> {
    let etype = selection::enctype(key.etype)?.ok_or(Error::UnsupportedEtype(key.etype))?;
    let (tickets, enc_part) = ccache_credentials_to_krb_cred_parts(credentials)?;
    let plaintext = SecretDer::new(encode_der("EncKrbCredPart", &enc_part)?, "krb-cred encode");
    let cipher = etype.encrypt_message_with_confounder(
        &key.value,
        &plaintext,
        KRB_CRED_ENCPART_USAGE,
        confounder,
    )?;
    Ok(rasn_kerberos::KrbCred {
        pvno: Integer::from(KRB5_PVNO),
        msg_type: Integer::from(KRB_CRED_MSG_TYPE),
        tickets,
        enc_part: rasn_kerberos::EncryptedData {
            etype: key.etype,
            kvno: None,
            cipher: cipher.into(),
        },
    })
}

/// Encode ccache credentials as a DER KRB-CRED using a random confounder.
///
/// # Errors
///
/// Returns the errors of [`encrypt_ccache_credentials`] and
/// [`Error::Encode`] when the KRB-CRED cannot be encoded.
#[inline]
pub fn encode_encrypted_ccache_credentials(
    credentials: &[ccache::Credential],
    key: &EncryptionKey,
) -> Result<Vec<u8>, Error> {
    let krb_cred = encrypt_ccache_credentials(credentials, key)?;
    encode_der("KRB-CRED", &krb_cred)
}

/// Encode ccache credentials as a DER KRB-CRED using an explicit confounder.
///
/// # Errors
///
/// Returns the errors of
/// [`encrypt_ccache_credentials_to_krb_cred_with_confounder`] and
/// [`Error::Encode`] when the KRB-CRED cannot be encoded.
#[inline]
pub fn encode_encrypt_ccache_credentials_to_krb_cred_with_confounder(
    credentials: &[ccache::Credential],
    key: &EncryptionKey,
    confounder: &[u8],
) -> Result<Vec<u8>, Error> {
    let krb_cred =
        encrypt_ccache_credentials_to_krb_cred_with_confounder(credentials, key, confounder)?;
    encode_der("KRB-CRED", &krb_cred)
}

/// Convert decrypted KRB-CRED contents into ccache credentials.
///
/// # Errors
///
/// Returns [`Error::TicketInfoCountMismatch`] when the ticket and ticket-info
/// counts differ, [`Error::MissingKrbCredInfoField`] when a ticket-info entry
/// lacks the client principal or has only half of the server principal,
/// [`Error::InvalidString`] for a name that is not UTF-8,
/// [`Error::TimeOutOfRange`] for a time that does not fit a ccache timestamp,
/// and [`Error::Encode`] when a ticket cannot be re-encoded.
#[inline]
pub fn decrypted_krb_cred_to_ccache_credentials(
    krb_cred: &rasn_kerberos::KrbCred,
    enc_part: &rasn_kerberos::EncKrbCredPart,
) -> Result<Vec<ccache::Credential>, Error> {
    convert_credentials(krb_cred, enc_part)
}

/// Shared representation conversion, never a credential-admission decision.
/// # Errors
/// Returns count mismatch or credential-field conversion errors.
fn convert_credentials(
    krb_cred: &rasn_kerberos::KrbCred,
    enc_part: &rasn_kerberos::EncKrbCredPart,
) -> Result<Vec<ccache::Credential>, Error> {
    if krb_cred.tickets.len() != enc_part.ticket_info.len() {
        return Err(Error::TicketInfoCountMismatch {
            ticket_count: krb_cred.tickets.len(),
            info_count: enc_part.ticket_info.len(),
        });
    }

    krb_cred
        .tickets
        .iter()
        .zip(enc_part.ticket_info.iter())
        .map(|(ticket, info)| krb_cred_info_to_ccache_credential(ticket, info))
        .collect()
}

/// Decode a DER value with a typed error.
///
/// # Errors
///
/// Returns [`Error::Decode`] naming `target` when `bytes` is not valid DER for
/// `T`.
fn decode_der<T>(target: &'static str, bytes: &[u8]) -> Result<T, Error>
where
    T: rasn::Decode,
{
    decode_complete(bytes).map_err(|source| Error::Decode {
        target,
        message: source,
    })
}

/// Encode a value to DER with a typed error.
///
/// # Errors
///
/// Returns [`Error::Encode`] naming `target` when the DER encoder fails.
fn encode_der<T>(target: &'static str, value: &T) -> Result<Vec<u8>, Error>
where
    T: rasn::Encode,
{
    der::encode(value).map_err(|source| Error::Encode {
        target,
        message: source.to_string(),
    })
}

/// Map a Ticket module error to the KRB-CRED error; a key mismatch becomes
/// [`Error::TicketKeyEtypeMismatch`].
fn ticket_error(error: TicketError) -> Error {
    match error {
        TicketError::Decode { target, message } => Error::Decode { target, message },
        TicketError::Encode { target, message } => Error::Encode { target, message },
        TicketError::InvalidMessage {
            field,
            expected,
            actual,
        } => Error::InvalidMessage {
            field,
            expected,
            actual,
        },
        TicketError::UnsupportedEtype(etype) => Error::UnsupportedEtype(etype),
        TicketError::KeyEtypeMismatch {
            key_etype,
            encrypted_data_etype,
        } => Error::TicketKeyEtypeMismatch {
            key_etype,
            encrypted_data_etype,
        },
        TicketError::Random(source) => Error::Random(source),
        TicketError::Crypto(source) => Error::Crypto(source),
    }
}

/// Check that a decoded protocol integer such as `pvno` equals `expected`.
///
/// # Errors
///
/// Returns [`Error::InvalidMessage`] naming `field` when the value differs.
fn validate_integer(field: &'static str, actual: &Integer, expected: i32) -> Result<(), Error> {
    if actual != &Integer::from(expected) {
        return Err(Error::InvalidMessage {
            field,
            expected,
            actual: actual.to_string(),
        });
    }
    Ok(())
}

use crate::error::KrbCred as Error;

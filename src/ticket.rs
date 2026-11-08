//! Ticket decoding and encrypted-part helpers.

use rasn::{der, types::Integer};
use zeroize::Zeroizing;

use crate::{
    crypto::selection,
    der::{decode_complete, encrypted_der},
    keytab::EncryptionKey,
    messages::secret_der::SecretDer,
};

/// Kerberos ticket version.
pub const KRB5_TKT_VNO: i32 = 5;

/// Key usage for ticket encrypted parts.
pub const KDC_REP_TICKET_USAGE: u32 = 2;

/// Decode and validate a DER-encoded Ticket.
///
/// # Errors
///
/// Returns [`Error::Decode`] when `bytes` is not a DER Ticket, and
/// [`Error::InvalidMessage`] when its ticket version is wrong.
#[inline]
pub fn decode(bytes: &[u8]) -> Result<rasn_kerberos::Ticket, Error> {
    let ticket = decode_der::<rasn_kerberos::Ticket>("Ticket", bytes)?;
    validate(&ticket)?;
    Ok(ticket)
}

/// Validate the ticket version on an already decoded value.
///
/// # Errors
///
/// Returns [`Error::InvalidMessage`] when the ticket version is not 5.
#[inline]
pub fn validate(ticket: &rasn_kerberos::Ticket) -> Result<(), Error> {
    validate_integer("tkt-vno", &ticket.tkt_vno, KRB5_TKT_VNO)
}

/// Encode a Ticket as DER.
///
/// # Errors
///
/// Returns [`Error::Encode`] when the DER encoder fails.
#[inline]
pub fn encode(ticket: &rasn_kerberos::Ticket) -> Result<Vec<u8>, Error> {
    encode_der("Ticket", ticket)
}

/// Decode a DER-encoded `EncTicketPart`.
///
/// # Errors
///
/// Returns [`Error::Decode`] when `bytes` is not a DER `EncTicketPart`.
#[inline]
pub fn decode_enc_ticket_part(bytes: &[u8]) -> Result<rasn_kerberos::EncTicketPart, Error> {
    decode_der::<rasn_kerberos::EncTicketPart>("EncTicketPart", bytes)
}

/// Decrypt and decode a ticket encrypted part.
///
/// # Errors
///
/// Returns [`Error::KeyEtypeMismatch`] when the key's enctype differs from the
/// encrypted part's, [`Error::UnsupportedEtype`] for an enctype that is not
/// implemented, [`Error::Crypto`] when decryption fails, and [`Error::Decode`]
/// when the plaintext is not a DER `EncTicketPart`. Returns
/// [`Error::InvalidMessage`] when the ticket version is not 5.
#[inline]
pub fn decrypt_ticket_enc_part(
    ticket: &rasn_kerberos::Ticket,
    key: &EncryptionKey,
) -> Result<rasn_kerberos::EncTicketPart, Error> {
    validate(ticket)?;
    if key.etype != ticket.enc_part.etype {
        return Err(Error::KeyEtypeMismatch {
            key_etype: key.etype,
            encrypted_data_etype: ticket.enc_part.etype,
        });
    }
    let etype = selection::enctype(key.etype)?.ok_or(Error::UnsupportedEtype(key.etype))?;
    let plaintext = SecretDer::new(
        etype.decrypt_message(
            &key.value,
            ticket.enc_part.cipher.as_ref(),
            KDC_REP_TICKET_USAGE,
        )?,
        "ticket decrypt",
    );
    decode_enc_ticket_part(encrypted_der(&plaintext, key.etype))
}

/// Build a Ticket using a random confounder.
///
/// # Errors
///
/// Returns [`Error::UnsupportedEtype`] for a key whose enctype is not
/// implemented, [`Error::Random`] when the confounder cannot be generated, and
/// the errors of [`build_ticket_with_confounder`].
#[inline]
pub fn build(
    realm: rasn_kerberos::Realm,
    sname: rasn_kerberos::PrincipalName,
    enc_part: &rasn_kerberos::EncTicketPart,
    key: &EncryptionKey,
    kvno: Option<u32>,
) -> Result<rasn_kerberos::Ticket, Error> {
    let etype = selection::enctype(key.etype)?.ok_or(Error::UnsupportedEtype(key.etype))?;
    let mut confounder = Zeroizing::new(vec![0; etype.confounder_len()]);
    getrandom::fill(&mut confounder)?;
    build_ticket_with_confounder(realm, sname, enc_part, key, kvno, &confounder)
}

/// Build a Ticket using an explicit confounder.
///
/// # Errors
///
/// Returns [`Error::Encode`] when the encrypted part cannot be encoded,
/// [`Error::UnsupportedEtype`] for a key whose enctype is not implemented, and
/// [`Error::Crypto`] when encryption fails.
#[inline]
pub fn build_ticket_with_confounder(
    realm: rasn_kerberos::Realm,
    sname: rasn_kerberos::PrincipalName,
    enc_part: &rasn_kerberos::EncTicketPart,
    key: &EncryptionKey,
    kvno: Option<u32>,
    confounder: &[u8],
) -> Result<rasn_kerberos::Ticket, Error> {
    let etype = selection::enctype(key.etype)?.ok_or(Error::UnsupportedEtype(key.etype))?;
    let plaintext = SecretDer::new(encode_der("EncTicketPart", enc_part)?, "ticket encode");
    let cipher = etype.encrypt_message_with_confounder(
        &key.value,
        &plaintext,
        KDC_REP_TICKET_USAGE,
        confounder,
    )?;
    Ok(rasn_kerberos::Ticket {
        tkt_vno: Integer::from(KRB5_TKT_VNO),
        realm,
        sname,
        enc_part: rasn_kerberos::EncryptedData {
            etype: key.etype,
            kvno,
            cipher: cipher.into(),
        },
    })
}

/// Encode a Ticket built using a random confounder.
///
/// # Errors
///
/// Returns the errors of [`build`] and [`Error::Encode`] when the Ticket
/// cannot be encoded.
#[inline]
pub fn build_encoded(
    realm: rasn_kerberos::Realm,
    sname: rasn_kerberos::PrincipalName,
    enc_part: &rasn_kerberos::EncTicketPart,
    key: &EncryptionKey,
    kvno: Option<u32>,
) -> Result<Vec<u8>, Error> {
    let ticket = build(realm, sname, enc_part, key, kvno)?;
    encode(&ticket)
}

/// Encode a Ticket built using an explicit confounder.
///
/// # Errors
///
/// Returns the errors of [`build_ticket_with_confounder`] and
/// [`Error::Encode`] when the Ticket cannot be encoded.
#[inline]
pub fn encode_build_ticket_with_confounder(
    realm: rasn_kerberos::Realm,
    sname: rasn_kerberos::PrincipalName,
    enc_part: &rasn_kerberos::EncTicketPart,
    key: &EncryptionKey,
    kvno: Option<u32>,
    confounder: &[u8],
) -> Result<Vec<u8>, Error> {
    let ticket = build_ticket_with_confounder(realm, sname, enc_part, key, kvno, confounder)?;
    encode(&ticket)
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

/// Check that a decoded protocol integer such as `tkt-vno` equals `expected`.
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

use crate::error::Ticket as Error;

//! KRB-PRIV decoding and encrypted-part helpers.

use rasn::{der, types::Integer};
use zeroize::Zeroizing;

use crate::{
    crypto::selection,
    der::{decode_complete, encrypted_der},
    keytab::EncryptionKey,
};

/// Kerberos protocol version used by KRB-PRIV.
pub const KRB_PRIV_PVNO: i32 = 5;

/// KRB-PRIV message type.
pub const KRB_PRIV_MSG_TYPE: i32 = 21;

/// Key usage for encrypted KRB-PRIV payloads.
pub const KRB_PRIV_ENCPART_USAGE: u32 = 13;

/// Options for constructing an encrypted KRB-PRIV payload.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct EncKrbPrivPartOptions {
    /// Optional sender timestamp.
    pub timestamp: Option<rasn_kerberos::KerberosTime>,
    /// Optional sender timestamp microseconds.
    pub usec: Option<rasn_kerberos::Microseconds>,
    /// Optional sender sequence number.
    pub seq_number: Option<u32>,
    /// Sender host address.
    pub sender_address: rasn_kerberos::HostAddress,
    /// Optional recipient host address.
    pub recipient_address: Option<rasn_kerberos::HostAddress>,
}

impl EncKrbPrivPartOptions {
    /// Construct options with the required sender address.
    #[inline]
    pub const fn new(sender_address: rasn_kerberos::HostAddress) -> Self {
        Self {
            timestamp: None,
            usec: None,
            seq_number: None,
            sender_address,
            recipient_address: None,
        }
    }

    #[must_use]
    /// Set the sender timestamp and microseconds.
    #[inline]
    pub fn with_timestamp(mut self, timestamp: rasn_kerberos::KerberosTime, usec: u32) -> Self {
        self.timestamp = Some(timestamp);
        self.usec = Some(Integer::from(usec));
        self
    }

    #[must_use]
    /// Set the sender sequence number.
    #[inline]
    pub const fn with_sequence_number(mut self, seq_number: u32) -> Self {
        self.seq_number = Some(seq_number);
        self
    }

    #[must_use]
    /// Set the optional recipient address.
    #[inline]
    pub fn with_recipient_address(mut self, recipient_address: rasn_kerberos::HostAddress) -> Self {
        self.recipient_address = Some(recipient_address);
        self
    }
}

/// Construct a Kerberos host address.
#[inline]
pub fn host_address<P>(addr_type: i32, address: P) -> rasn_kerberos::HostAddress
where
    P: AsRef<[u8]>,
{
    rasn_kerberos::HostAddress {
        addr_type,
        address: address.as_ref().to_vec().into(),
    }
}

#[must_use]
/// Construct an IPv4 Kerberos host address.
#[inline]
pub fn ipv4_host_address(octets: [u8; 4]) -> rasn_kerberos::HostAddress {
    host_address(rasn_kerberos::HostAddress::IPV4, octets)
}

#[must_use]
/// Construct an IPv6 Kerberos host address.
#[inline]
pub fn ipv6_host_address(octets: [u8; 16]) -> rasn_kerberos::HostAddress {
    host_address(rasn_kerberos::HostAddress::IPV6, octets)
}

/// Build an unencrypted KRB-PRIV part around application data.
#[inline]
pub fn build_enc_krb_priv_part<P>(
    user_data: P,
    options: EncKrbPrivPartOptions,
) -> rasn_kerberos::EncKrbPrivPart
where
    P: AsRef<[u8]>,
{
    rasn_kerberos::EncKrbPrivPart {
        user_data: user_data.as_ref().to_vec().into(),
        timestamp: options.timestamp,
        usec: options.usec,
        seq_number: options.seq_number,
        sender_address: options.sender_address,
        recipient_address: options.recipient_address,
    }
}

/// Decode and validate a DER-encoded KRB-PRIV message.
///
/// # Errors
///
/// Returns [`Error::Decode`] when `bytes` is not a DER KRB-PRIV, and
/// [`Error::InvalidMessage`] when its protocol version or message type is wrong.
#[inline]
pub fn decode(bytes: &[u8]) -> Result<rasn_kerberos::KrbPriv, Error> {
    let krb_priv = decode_der::<rasn_kerberos::KrbPriv>("KRB-PRIV", bytes)?;
    validate(&krb_priv)?;
    Ok(krb_priv)
}

/// Validate KRB-PRIV protocol version and message type.
///
/// # Errors
///
/// Returns [`Error::InvalidMessage`] when the protocol version or message type
/// is wrong.
#[inline]
pub fn validate(krb_priv: &rasn_kerberos::KrbPriv) -> Result<(), Error> {
    validate_integer("pvno", &krb_priv.pvno, KRB_PRIV_PVNO)?;
    validate_integer("msg-type", &krb_priv.msg_type, KRB_PRIV_MSG_TYPE)
}

/// Encode a KRB-PRIV message as DER.
///
/// # Errors
///
/// Returns [`Error::Encode`] when the DER encoder fails.
#[inline]
pub fn encode(krb_priv: &rasn_kerberos::KrbPriv) -> Result<Vec<u8>, Error> {
    encode_der("KRB-PRIV", krb_priv)
}

/// Decode a DER-encoded `EncKrbPrivPart`.
///
/// # Errors
///
/// Returns [`Error::Decode`] when `bytes` is not a DER `EncKrbPrivPart`.
#[inline]
pub fn decode_enc_krb_priv_part(bytes: &[u8]) -> Result<rasn_kerberos::EncKrbPrivPart, Error> {
    decode_der("EncKrbPrivPart", bytes)
}

/// Encode an `EncKrbPrivPart` as DER.
///
/// # Errors
///
/// Returns [`Error::Encode`] when the DER encoder fails.
#[inline]
pub fn encode_enc_krb_priv_part(
    enc_part: &rasn_kerberos::EncKrbPrivPart,
) -> Result<Vec<u8>, Error> {
    encode_der("EncKrbPrivPart", enc_part)
}

/// Build a KRB-PRIV message using a random confounder.
///
/// # Errors
///
/// Returns [`Error::UnsupportedEtype`] for a key whose enctype is not
/// implemented, [`Error::Random`] when the confounder cannot be generated, and
/// the errors of [`build_krb_priv_with_confounder`].
#[inline]
pub fn build<P>(
    user_data: P,
    options: EncKrbPrivPartOptions,
    key: &EncryptionKey,
    kvno: Option<u32>,
) -> Result<rasn_kerberos::KrbPriv, Error>
where
    P: AsRef<[u8]>,
{
    let etype = selection::enctype(key.etype)?.ok_or(Error::UnsupportedEtype(key.etype))?;
    let mut confounder = vec![0; etype.confounder_len()];
    getrandom::fill(&mut confounder)?;
    build_krb_priv_with_confounder(user_data, options, key, kvno, &confounder)
}

/// Build a KRB-PRIV message using a caller-supplied confounder.
///
/// # Errors
///
/// Returns [`Error::Encode`] when the encrypted part cannot be encoded, and the
/// errors of [`encrypt_krb_priv_enc_part`]. Returns [`Error::InvalidMessage`]
/// for fractional timestamps or microseconds outside `0..=999_999`.
#[inline]
pub fn build_krb_priv_with_confounder<P>(
    user_data: P,
    options: EncKrbPrivPartOptions,
    key: &EncryptionKey,
    kvno: Option<u32>,
    confounder: &[u8],
) -> Result<rasn_kerberos::KrbPriv, Error>
where
    P: AsRef<[u8]>,
{
    selection::reject_enctype(key.etype)?;
    if let Some(timestamp) = &options.timestamp
        && timestamp.0.timestamp_subsec_nanos() != 0
    {
        return Err(Error::InvalidMessage {
            field: "KerberosTime fraction",
            expected: 0,
            actual: timestamp.0.timestamp_subsec_nanos().to_string(),
        });
    }
    if let Some(usec) = &options.usec
        && !u32::try_from(usec).is_ok_and(|value| value <= 999_999)
    {
        return Err(Error::InvalidMessage {
            field: "usec upper bound (minimum 0)",
            expected: 999_999,
            actual: usec.to_string(),
        });
    }
    let enc_part = build_enc_krb_priv_part(user_data, options);
    let plaintext = Zeroizing::new(encode_enc_krb_priv_part(&enc_part)?);
    let encrypted_data = encrypt_krb_priv_enc_part(&plaintext, key, kvno, confounder)?;

    Ok(rasn_kerberos::KrbPriv {
        pvno: Integer::from(KRB_PRIV_PVNO),
        msg_type: Integer::from(KRB_PRIV_MSG_TYPE),
        enc_part: encrypted_data,
    })
}

/// Encrypt an already encoded `EncKrbPrivPart` with a caller-supplied confounder.
///
/// # Errors
///
/// Returns [`Error::UnsupportedEtype`] for a key whose enctype is not
/// implemented, and [`Error::Crypto`] when encryption fails.
#[inline]
pub fn encrypt_krb_priv_enc_part(
    plaintext: &[u8],
    key: &EncryptionKey,
    kvno: Option<u32>,
    confounder: &[u8],
) -> Result<rasn_kerberos::EncryptedData, Error> {
    let etype = selection::enctype(key.etype)?.ok_or(Error::UnsupportedEtype(key.etype))?;
    let cipher = etype.encrypt_message_with_confounder(
        &key.value,
        plaintext,
        KRB_PRIV_ENCPART_USAGE,
        confounder,
    )?;
    Ok(rasn_kerberos::EncryptedData {
        etype: key.etype,
        kvno,
        cipher: cipher.into(),
    })
}

/// Decrypt and decode a KRB-PRIV encrypted part.
///
/// # Errors
///
/// Returns [`Error::KeyEtypeMismatch`] when the key's enctype differs from the
/// encrypted part's, [`Error::UnsupportedEtype`] for an enctype that is not
/// implemented, [`Error::Crypto`] when decryption fails, and [`Error::Decode`]
/// when the plaintext is not a DER `EncKrbPrivPart`.
#[inline]
pub fn decrypt_krb_priv_enc_part(
    krb_priv: &rasn_kerberos::KrbPriv,
    key: &EncryptionKey,
) -> Result<rasn_kerberos::EncKrbPrivPart, Error> {
    if krb_priv.enc_part.etype != key.etype {
        return Err(Error::KeyEtypeMismatch {
            key_etype: key.etype,
            encrypted_data_etype: krb_priv.enc_part.etype,
        });
    }

    let etype = selection::enctype(krb_priv.enc_part.etype)?
        .ok_or(Error::UnsupportedEtype(krb_priv.enc_part.etype))?;
    let plaintext = Zeroizing::new(etype.decrypt_message(
        &key.value,
        krb_priv.enc_part.cipher.as_ref(),
        KRB_PRIV_ENCPART_USAGE,
    )?);
    decode_enc_krb_priv_part(encrypted_der(&plaintext, key.etype))
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

use crate::error::KrbPriv as Error;

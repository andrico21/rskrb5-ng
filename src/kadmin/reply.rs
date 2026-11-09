//! Reply parsing and result handling.

use super::{
    CHANGE_PASSWORD_REPLY_VERSION, CHANGE_PASSWORD_REQUEST_VERSION, ChangePasswordResult, Error,
    HEADER_LEN, Reply,
    codec::{ap_rep_error, krb_error_error, parse_header},
    decode_krb_priv, decrypt_krb_priv_enc_part, encode_krb_priv,
};
use crate::{ap_rep, keytab::EncryptionKey, krb_error};

impl Reply {
    /// Parse a password-change reply frame.
    ///
    /// A standalone KRB-ERROR (application 30) is accepted before checking the
    /// framed header. Its synthetic version is `0xff80`
    /// ([`CHANGE_PASSWORD_REQUEST_VERSION`]), preserving its bare wire profile
    /// when re-encoded. Version rejection applies only to framed replies;
    /// standalone errors have no kpasswd version field.
    ///
    /// # Errors
    ///
    /// Returns [`Error::FrameTooShort`] when the input is shorter than the
    /// header, [`Error::InvalidMessageLength`] when the declared frame length
    /// is shorter than the header or differs from the supplied length because
    /// of trailing bytes, and [`Error::TruncatedFrame`] when the declared length
    /// exceeds the supplied length;
    /// [`Error::InvalidReplyVersion`] for a framed version other than
    /// [`CHANGE_PASSWORD_REPLY_VERSION`], [`Error::InvalidApRepLength`] when the
    /// AP-REP length leaves no room for the KRB-PRIV, the decode errors of the
    /// KRB-ERROR, AP-REP or KRB-PRIV, and the [`ChangePasswordResult::parse`]
    /// error of KRB-ERROR e-data.
    #[inline]
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.first() == Some(&0x7e)
            && let Ok(krb_error) = krb_error::decode(bytes)
        {
            let result = krb_error
                .e_data
                .as_ref()
                .map(|data| ChangePasswordResult::parse(data.as_ref()))
                .transpose()?;
            return Ok(Self {
                message_length: u16::try_from(bytes.len()).map_err(|_overflow| {
                    Error::FrameTooLarge {
                        actual: bytes.len(),
                    }
                })?,
                version: CHANGE_PASSWORD_REQUEST_VERSION,
                ap_rep_length: 0,
                ap_rep: None,
                krb_priv: None,
                krb_error: Some(krb_error),
                result,
            });
        }
        let frame = parse_header(bytes)?;
        if frame.version != CHANGE_PASSWORD_REPLY_VERSION {
            return Err(Error::InvalidReplyVersion(frame.version));
        }

        if frame.payload_length == 0 {
            let krb_error = krb_error::decode(frame.body).map_err(krb_error_error)?;
            let result = krb_error
                .e_data
                .as_ref()
                .map(|data| ChangePasswordResult::parse(data.as_ref()))
                .transpose()?;
            return Ok(Self {
                message_length: frame.message_length,
                version: frame.version,
                ap_rep_length: frame.payload_length,
                ap_rep: None,
                krb_priv: None,
                krb_error: Some(krb_error),
                result,
            });
        }

        let ap_rep_end = usize::from(frame.payload_length);
        let invalid_length = Error::InvalidApRepLength {
            ap_rep_length: frame.payload_length,
            body_length: frame.body.len(),
        };
        if ap_rep_end >= frame.body.len() {
            return Err(invalid_length);
        }
        let (ap_rep_bytes, krb_priv_bytes) = frame
            .body
            .split_at_checked(ap_rep_end)
            .ok_or(invalid_length)?;

        let ap_rep = ap_rep::decode(ap_rep_bytes).map_err(ap_rep_error)?;
        let krb_priv = decode_krb_priv(krb_priv_bytes)?;

        Ok(Self {
            message_length: frame.message_length,
            version: frame.version,
            ap_rep_length: frame.payload_length,
            ap_rep: Some(ap_rep),
            krb_priv: Some(krb_priv),
            krb_error: None,
            result: None,
        })
    }

    /// Whether the reply carried KRB-ERROR instead of AP-REP/KRB-PRIV.
    #[inline]
    pub const fn is_krb_error(&self) -> bool {
        self.krb_error.is_some()
    }

    /// Return the password-change result, decrypting KRB-PRIV when needed.
    ///
    /// A result parsed from a KRB-ERROR reply is unauthenticated: a success
    /// code there is rejected with [`Error::UnauthenticatedSuccess`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnauthenticatedSuccess`] as above,
    /// [`Error::MissingReplyResult`] for a KRB-ERROR reply without result data,
    /// [`Error::MissingKrbPriv`] for a reply without KRB-PRIV, the
    /// [`decrypt_krb_priv_enc_part`] errors, and the
    /// [`ChangePasswordResult::parse`] error of the decrypted data.
    #[inline]
    pub fn decrypt_result(&self, key: &EncryptionKey) -> Result<ChangePasswordResult, Error> {
        if let Some(result) = &self.result {
            // `result` is populated only from the unauthenticated KRB-ERROR
            // e-data branch; a success code there is not proof that the
            // password change happened.
            if result.is_success() {
                return Err(Error::UnauthenticatedSuccess);
            }
            return Ok(result.clone());
        }
        if self.krb_error.is_some() {
            return Err(Error::MissingReplyResult);
        }

        let krb_priv = self.krb_priv.as_ref().ok_or(Error::MissingKrbPriv)?;
        let enc_part = decrypt_krb_priv_enc_part(krb_priv, key)?;
        ChangePasswordResult::parse(enc_part.user_data.as_ref())
    }

    /// Re-encode this reply into a framed kpasswd response.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidErrorReplyPayload`] for a KRB-ERROR reply that
    /// also carries an AP-REP or KRB-PRIV, [`Error::MissingKrb`],
    /// [`Error::MissingApRep`] or [`Error::MissingKrbPriv`] for a missing
    /// message, the encode errors of each message, and [`Error::FrameTooLarge`]
    /// when the AP-REP or the whole frame does not fit its 16-bit length field.
    #[inline]
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let (ap_rep_part, krb_priv_part, krb_error_part) = (
            self.ap_rep.as_ref(),
            self.krb_priv.as_ref(),
            self.krb_error.as_ref(),
        );

        if self.is_krb_error() {
            if ap_rep_part.is_some() || krb_priv_part.is_some() {
                return Err(Error::InvalidErrorReplyPayload);
            }
            let body = krb_error_part
                .map(|message| krb_error::encode(message).map_err(krb_error_error))
                .ok_or(Error::MissingKrb)??;
            if self.version == CHANGE_PASSWORD_REQUEST_VERSION {
                return Ok(body);
            }
            // Saturating: a total past `usize::MAX` is past `u16::MAX` too, and
            // is refused as too large just below.
            let frame_length = HEADER_LEN.saturating_add(body.len());
            let Ok(wire_length) = u16::try_from(frame_length) else {
                return Err(Error::FrameTooLarge {
                    actual: frame_length,
                });
            };

            let mut frame = Vec::with_capacity(frame_length);
            frame.extend_from_slice(&wire_length.to_be_bytes());
            frame.extend_from_slice(&CHANGE_PASSWORD_REPLY_VERSION.to_be_bytes());
            frame.extend_from_slice(&0_u16.to_be_bytes());
            frame.extend_from_slice(&body);
            return Ok(frame);
        }

        let ap_rep = ap_rep_part.ok_or(Error::MissingApRep)?;
        let krb_priv = krb_priv_part.ok_or(Error::MissingKrbPriv)?;
        let encoded_ap_rep = ap_rep::encode(ap_rep).map_err(ap_rep_error)?;
        let Ok(ap_rep_length) = u16::try_from(encoded_ap_rep.len()) else {
            return Err(Error::FrameTooLarge {
                actual: encoded_ap_rep.len(),
            });
        };
        let encoded_krb_priv = encode_krb_priv(krb_priv)?;

        // Saturating: a total past `usize::MAX` is past `u16::MAX` too, and is
        // refused as too large just below.
        let frame_length = HEADER_LEN
            .saturating_add(encoded_ap_rep.len())
            .saturating_add(encoded_krb_priv.len());
        let Ok(wire_length) = u16::try_from(frame_length) else {
            return Err(Error::FrameTooLarge {
                actual: frame_length,
            });
        };

        let mut frame = Vec::with_capacity(frame_length);
        frame.extend_from_slice(&wire_length.to_be_bytes());
        frame.extend_from_slice(&CHANGE_PASSWORD_REPLY_VERSION.to_be_bytes());
        frame.extend_from_slice(&ap_rep_length.to_be_bytes());
        frame.extend_from_slice(&encoded_ap_rep);
        frame.extend_from_slice(&encoded_krb_priv);
        Ok(frame)
    }
}

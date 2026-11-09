//! Request frame and option implementations.

use super::{
    CHANGE_PASSWORD_REQUEST_VERSION, ChangePasswdMessageOptions, Error, HEADER_LEN,
    PasswordEncryption, Request,
    codec::{ap_req_error, parse_header},
    decode_krb_priv, encode_krb_priv,
};
use crate::{
    ap_req,
    crypto::selection,
    error::{Policy, RejectedFeature, RejectionReason},
    keytab::EncryptionKey,
};

impl ChangePasswdMessageOptions {
    /// Construct options with the required authenticator timestamp, microseconds,
    /// sequence number, and sender address.
    #[inline]
    pub const fn new(
        timestamp: rasn_kerberos::KerberosTime,
        cusec: u32,
        sequence_number: u32,
        sender_address: rasn_kerberos::HostAddress,
    ) -> Self {
        Self {
            timestamp,
            cusec,
            sequence_number,
            sender_address,
            recipient_address: None,
        }
    }

    #[must_use]
    /// Set the optional recipient address.
    #[inline]
    pub fn with_recipient_address(mut self, recipient_address: rasn_kerberos::HostAddress) -> Self {
        self.recipient_address = Some(recipient_address);
        self
    }
}

impl Request {
    /// Parse a password-change request frame.
    ///
    /// # Errors
    ///
    /// Returns [`Error::FrameTooShort`] when the input is shorter than the
    /// header, [`Error::InvalidMessageLength`] when the declared frame length
    /// is shorter than the header or differs from the supplied length because
    /// of trailing bytes, and [`Error::TruncatedFrame`] when the declared length
    /// exceeds the supplied length;
    /// [`Error::InvalidRequestVersion`] for a version other than
    /// [`CHANGE_PASSWORD_REQUEST_VERSION`], [`Error::InvalidApReqLength`] when
    /// the AP-REQ length leaves no room for the AP-REQ or the KRB-PRIV, and the
    /// decode errors of either message.
    #[inline]
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let frame = parse_header(bytes)?;
        if frame.version != CHANGE_PASSWORD_REQUEST_VERSION {
            return Err(Error::InvalidRequestVersion(frame.version));
        }

        let ap_req_end = usize::from(frame.payload_length);
        let invalid_length = Error::InvalidApReqLength {
            ap_req_length: frame.payload_length,
            body_length: frame.body.len(),
        };
        if ap_req_end == 0 || ap_req_end >= frame.body.len() {
            return Err(invalid_length);
        }
        let (ap_req_bytes, krb_priv_bytes) = frame
            .body
            .split_at_checked(ap_req_end)
            .ok_or(invalid_length)?;

        let ap_req = ap_req::decode(ap_req_bytes).map_err(ap_req_error)?;
        let krb_priv = decode_krb_priv(krb_priv_bytes)?;
        Ok(Self { ap_req, krb_priv })
    }

    /// Encode a password-change request frame.
    ///
    /// # Errors
    ///
    /// Returns the encode errors of either message,
    /// [`Error::ApReqTooLarge`] when the AP-REQ does not fit the 16-bit length
    /// field, and [`Error::FrameTooLarge`] when the whole frame does not.
    #[inline]
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.krb_priv.enc_part.etype == 0_i32 {
            return Err(Policy::RejectedFeature {
                feature: RejectedFeature::UnprotectedPasswordChange,
                reason: RejectionReason::MissingAuthentication,
            }
            .into());
        }
        selection::reject_enctype(self.krb_priv.enc_part.etype)?;
        let ap_req = ap_req::encode(&self.ap_req).map_err(ap_req_error)?;
        let krb_priv = encode_krb_priv(&self.krb_priv)?;
        let Ok(ap_req_length) = u16::try_from(ap_req.len()) else {
            return Err(Error::ApReqTooLarge {
                actual: ap_req.len(),
            });
        };

        // Saturating: a total past `usize::MAX` is past `u16::MAX` too, and is
        // refused as too large just below.
        let message_length = HEADER_LEN
            .saturating_add(ap_req.len())
            .saturating_add(krb_priv.len());
        let Ok(wire_length) = u16::try_from(message_length) else {
            return Err(Error::FrameTooLarge {
                actual: message_length,
            });
        };

        let mut frame = Vec::with_capacity(message_length);
        frame.extend_from_slice(&wire_length.to_be_bytes());
        frame.extend_from_slice(&CHANGE_PASSWORD_REQUEST_VERSION.to_be_bytes());
        frame.extend_from_slice(&ap_req_length.to_be_bytes());
        frame.extend_from_slice(&ap_req);
        frame.extend_from_slice(&krb_priv);
        Ok(frame)
    }
}

impl<'request> PasswordEncryption<'request> {
    /// Creates explicit password-change encryption inputs.
    #[must_use]
    #[inline]
    pub const fn new(
        reply_key: EncryptionKey,
        ap_req_confounder: &'request [u8],
        krb_priv_confounder: &'request [u8],
    ) -> Self {
        Self {
            reply_key,
            ap_req_confounder,
            krb_priv_confounder,
        }
    }
}

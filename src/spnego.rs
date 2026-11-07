//! SPNEGO and GSS-API Kerberos token helpers.
//!
//! This module covers the wrapper layer around the Kerberos messages handled by
//! [`crate::client`] and [`crate::service`]: GSS-API KRB5 mech tokens, SPNEGO
//! NegTokenInit/NegTokenResp negotiation tokens, and HTTP `Negotiate` header
//! encoding/decoding.
//!
//! Returned plain wire vectors and header strings belong to the caller, who must
//! erase them after use. Retained token fields use zeroizing owners.

use core::{fmt, iter, time::Duration};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose};
use rasn::types::Integer;
use zeroize::Zeroizing;

use crate::{
    ap_rep::{decode as decode_ap_rep, decrypt_ap_rep_enc_part},
    client::{TgsRepSession, build_ap_req_with_confounder, options::ApReq, principal::Principal},
    crypto::{CryptoPolicy, KerberosEtype, Use, selection},
    error,
    keytab::EncryptionKey,
    service::{ApRepOptions, ValidatedApReq, Validator, VerifiedApRep},
};

/// Mandatory RFC 4121 authenticator fields.
mod authenticator;
/// Minimal DER reader and writer for the GSS-API and SPNEGO token layer.
mod der;
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod erasure_tests;
/// One-shot SPNEGO mechanism-list integrity processing.
mod negotiation;
/// GSS-API object identifiers.
pub mod oid;
/// Plaintext staging owners.
mod scratch;
/// Redacted formatting for retained wire credentials.
mod token_debug;

/// HTTP Negotiate header size boundary regressions.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod header_tests;

/// SPNEGO sequence structure regressions.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod field_tests;

use self::{
    der::{
        DerReader, TAG_APPLICATION_0, TAG_BIT_STRING, TAG_CONTEXT_0, TAG_CONTEXT_1, TAG_CONTEXT_2,
        TAG_CONTEXT_3, TAG_ENUMERATED, TAG_OBJECT_IDENTIFIER, TAG_OCTET_STRING, TAG_SEQUENCE, Tlv,
        decode_oid_tlv, decode_u32, encode_explicit, encode_oid, encode_tlv, encode_u32,
        read_single_tlv,
    },
    oid::ObjectIdentifier,
};

/// RFC 4121 token ID of a KRB5 mech token that carries an AP-REQ.
const TOK_ID_KRB_AP_REQ: [u8; 2] = [0x01, 0x00];
/// RFC 4121 token ID of a KRB5 mech token that carries an AP-REP.
const TOK_ID_KRB_AP_REP: [u8; 2] = [0x02, 0x00];
/// RFC 4121 token ID of a KRB5 mech token that carries a KRB-ERROR.
const TOK_ID_KRB_ERROR: [u8; 2] = [0x03, 0x00];
/// RFC 4121 token ID of a MIC token.
const TOK_ID_GSS_MIC: [u8; 2] = [0x04, 0x04];
/// RFC 4121 token ID of a Wrap token.
const TOK_ID_GSS_WRAP: [u8; 2] = [0x05, 0x04];
/// Authenticator checksum type that carries GSS-API context flags (RFC 4121 section 4.1.1).
const GSSAPI_CHECKSUM_TYPE: i32 = 0x8003;
/// Byte length of an RFC 4121 MIC token header.
const GSS_MIC_HEADER_LEN: usize = 16;
/// Byte length of an RFC 4121 Wrap token header.
const GSS_WRAP_HEADER_LEN: usize = 16;
/// Filler bytes of an RFC 4121 MIC token header.
const GSS_MIC_FILLER: [u8; 5] = [0xff; 5];
/// Filler byte of an RFC 4121 Wrap token header.
const GSS_WRAP_FILLER: u8 = 0xff;

/// HTTP request header that carries SPNEGO authentication data.
pub const HTTP_AUTHORIZATION: &str = "Authorization";
/// HTTP response header that carries SPNEGO authentication data.
pub const HTTP_WWW_AUTHENTICATE: &str = "WWW-Authenticate";
/// HTTP authentication scheme used by SPNEGO.
pub const HTTP_NEGOTIATE: &str = "Negotiate";

/// Maximum header value size, including scheme and whitespace, before decoding.
const MAX_NEGOTIATE_HEADER_LEN: usize = 64 * 1024;
/// GSS-API context flag: delegation.
pub const CONTEXT_FLAG_DELEG: u32 = 1;
/// GSS-API context flag: mutual authentication.
pub const CONTEXT_FLAG_MUTUAL: u32 = 2;
/// GSS-API context flag: replay detection.
pub const CONTEXT_FLAG_REPLAY: u32 = 4;
/// GSS-API context flag: sequencing.
pub const CONTEXT_FLAG_SEQUENCE: u32 = 8;
/// GSS-API context flag: confidentiality.
pub const CONTEXT_FLAG_CONF: u32 = 16;
/// GSS-API context flag: integrity.
pub const CONTEXT_FLAG_INTEG: u32 = 32;
/// GSS-API context flag: anonymity.
pub const CONTEXT_FLAG_ANON: u32 = 64;

/// RFC4121 token flag: token was sent by the context acceptor.
pub const GSS_TOKEN_FLAG_SENT_BY_ACCEPTOR: u8 = 0x01;
/// RFC4121 token flag: token is sealed.
pub const GSS_TOKEN_FLAG_SEALED: u8 = 0x02;
/// RFC4121 token flag: token uses an acceptor subkey.
pub const GSS_TOKEN_FLAG_ACCEPTOR_SUBKEY: u8 = 0x04;

/// GSS-API acceptor seal key usage.
pub const GSSAPI_ACCEPTOR_SEAL_USAGE: u32 = 22;
/// GSS-API acceptor sign key usage.
pub const GSSAPI_ACCEPTOR_SIGN_USAGE: u32 = 23;
/// GSS-API initiator seal key usage.
pub const GSSAPI_INITIATOR_SEAL_USAGE: u32 = 24;
/// GSS-API initiator sign key usage.
pub const GSSAPI_INITIATOR_SIGN_USAGE: u32 = 25;

/// RFC4121 GSS-API MIC token.
///
/// The payload is authenticated but not transmitted in the token bytes, matching
/// gokrb5's MIC token model.
#[derive(Clone, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct MicToken {
    /// RFC4121 token flags.
    pub flags: u8,
    /// Sender sequence number.
    pub snd_seq_num: u64,
    /// Payload bytes authenticated by this MIC token. Not encoded on the wire.
    pub payload: Option<Zeroizing<Vec<u8>>>,
    /// Token checksum.
    pub checksum: Option<Vec<u8>>,
}

impl MicToken {
    /// Sets `flags`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_flags(mut self, value: u8) -> Self {
        self.flags = value;
        self
    }
    /// Sets `snd_seq_num`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_snd_seq_num(mut self, value: u64) -> Self {
        self.snd_seq_num = value;
        self
    }
    /// Sets `checksum`, preserving the other fields.
    #[must_use]
    #[inline]
    pub fn with_checksum(mut self, value: Option<Vec<u8>>) -> Self {
        self.checksum = value;
        self
    }

    #[must_use]
    /// Build a MIC token with no payload or checksum.
    #[inline]
    pub const fn new(flags: u8, snd_seq_num: u64) -> Self {
        Self {
            flags,
            snd_seq_num,
            payload: None,
            checksum: None,
        }
    }

    /// Decode a MIC token.
    ///
    /// # Errors
    ///
    /// Returns [`Error::GssTokenTooShort`] when `bytes` is shorter than the 16-byte header,
    /// [`Error::InvalidGssTokenId`] for a token ID other than `04 04`,
    /// [`Error::UnexpectedGssTokenSender`] when the acceptor flag does not match
    /// `expect_from_acceptor`, and [`Error::InvalidGssFiller`] for a bad filler.
    #[inline]
    pub fn decode(bytes: &[u8], expect_from_acceptor: bool) -> Result<Self, Error> {
        let Some((header, checksum)) = bytes.split_first_chunk::<GSS_MIC_HEADER_LEN>() else {
            return Err(Error::GssTokenTooShort {
                minimum: GSS_MIC_HEADER_LEN,
                actual: bytes.len(),
            });
        };
        let [
            tok_id_0,
            tok_id_1,
            flags,
            filler @ ..,
            seq_0,
            seq_1,
            seq_2,
            seq_3,
            seq_4,
            seq_5,
            seq_6,
            seq_7,
        ] = *header;
        validate_gss_token_id([tok_id_0, tok_id_1], TOK_ID_GSS_MIC)?;
        validate_gss_sender(flags, expect_from_acceptor)?;
        if filler != GSS_MIC_FILLER {
            return Err(Error::InvalidGssFiller);
        }

        Ok(Self {
            flags,
            snd_seq_num: u64::from_be_bytes([
                seq_0, seq_1, seq_2, seq_3, seq_4, seq_5, seq_6, seq_7,
            ]),
            payload: None,
            checksum: Some(checksum.to_vec()),
        })
    }

    /// Encode this MIC token.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MissingGssChecksum`] when no checksum has been set.
    #[inline]
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let checksum = self.checksum.as_ref().ok_or(Error::MissingGssChecksum)?;
        let mut bytes = self.checksum_header();
        bytes.extend_from_slice(checksum);
        Ok(bytes)
    }

    #[must_use]
    /// Set the authenticated payload bytes.
    /// Borrowed inputs are copied; the caller remains responsible for erasing the original.
    #[inline]
    pub fn with_payload<P>(mut self, payload: P) -> Self
    where
        P: Into<Vec<u8>>,
    {
        self.payload = Some(Zeroizing::new(payload.into()));
        self
    }

    /// Compute and set this token's checksum.
    ///
    /// # Errors
    ///
    /// Returns [`Error::GssChecksumAlreadySet`] when a checksum is already present,
    /// [`Error::MissingGssPayload`] without a payload, [`Error::UnsupportedEtype`] for an unknown
    /// key encryption type, and [`Error::Crypto`] when the checksum computation fails.
    #[inline]
    pub fn set_checksum(&mut self, key: &EncryptionKey, key_usage: u32) -> Result<(), Error> {
        if self.checksum.is_some() {
            return Err(Error::GssChecksumAlreadySet);
        }
        self.checksum = Some(self.compute_checksum(key, key_usage)?);
        Ok(())
    }

    /// Verify this token's checksum.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MissingGssPayload`] without a payload, [`Error::UnsupportedEtype`] for an
    /// unknown key encryption type, [`Error::Crypto`] when the checksum computation fails,
    /// [`Error::MissingGssChecksum`] when the token carries no checksum, and
    /// [`Error::GssChecksumMismatch`] when the checksum does not match.
    #[inline]
    pub fn verify(&self, key: &EncryptionKey, key_usage: u32) -> Result<(), Error> {
        selection::reject_enctype(key.etype)?;
        let payload = self.payload.as_ref().ok_or(Error::MissingGssPayload)?;
        let mut data = scratch::Scratch::new(payload.to_vec(), "mic-checksum");
        data.extend_from_slice(&self.checksum_header());
        let etype = selection::enctype(key.etype)?.ok_or(Error::UnsupportedEtype(key.etype))?;
        let actual = self.checksum.as_ref().ok_or(Error::MissingGssChecksum)?;
        if !etype.verify_checksum(&key.value, &data, actual, key_usage) {
            return Err(Error::GssChecksumMismatch);
        }
        Ok(())
    }

    /// Build an initiator MIC token and compute its checksum.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedEtype`] for an unknown key encryption type and [`Error::Crypto`]
    /// when the checksum computation fails.
    #[inline]
    pub fn new_initiator<P>(payload: P, key: &EncryptionKey) -> Result<Self, Error>
    where
        P: Into<Zeroizing<Vec<u8>>>,
    {
        let owned_payload = payload.into();
        selection::reject_enctype(key.etype)?;
        let mut token = Self {
            flags: 0,
            snd_seq_num: 0,
            payload: Some(owned_payload),
            checksum: None,
        };
        token.set_checksum(key, GSSAPI_INITIATOR_SIGN_USAGE)?;
        Ok(token)
    }

    /// Compute the RFC 4121 checksum over the payload followed by the token header.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MissingGssPayload`] without a payload, [`Error::UnsupportedEtype`] for an
    /// unknown key encryption type, and [`Error::Crypto`] when the checksum computation fails.
    fn compute_checksum(&self, key: &EncryptionKey, key_usage: u32) -> Result<Vec<u8>, Error> {
        selection::reject_enctype(key.etype)?;
        let payload = self.payload.as_ref().ok_or(Error::MissingGssPayload)?;
        let mut data = scratch::Scratch::new(
            Vec::with_capacity(payload.len().saturating_add(GSS_MIC_HEADER_LEN)),
            "mic-checksum",
        );
        data.extend_from_slice(payload);
        data.extend_from_slice(&self.checksum_header());

        let etype = selection::enctype(key.etype)?.ok_or(Error::UnsupportedEtype(key.etype))?;
        etype
            .checksum(&key.value, &data, key_usage)
            .map_err(Error::Crypto)
    }

    /// The 16-byte MIC token header that the checksum covers.
    fn checksum_header(&self) -> Vec<u8> {
        let mut header = Vec::with_capacity(GSS_MIC_HEADER_LEN);
        header.extend_from_slice(&TOK_ID_GSS_MIC);
        header.push(self.flags);
        header.extend_from_slice(&GSS_MIC_FILLER);
        header.extend_from_slice(&self.snd_seq_num.to_be_bytes());
        header
    }
}

impl fmt::Debug for MicToken {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            flags,
            snd_seq_num,
            payload,
            checksum,
        } = self;
        f.debug_struct("MicToken")
            .field("flags", flags)
            .field("snd_seq_num", snd_seq_num)
            .field("payload_len", &payload.as_ref().map(|value| value.len()))
            .field("checksum_len", &checksum.as_ref().map(Vec::len))
            .finish()
    }
}

/// RFC4121 GSS-API Wrap token.
#[derive(Clone, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct WrapToken {
    /// RFC4121 token flags.
    pub flags: u8,
    /// Extra count. This is the checksum length for unsealed tokens and the
    /// filler length for sealed tokens.
    pub ec: u16,
    /// Right rotation count.
    pub rrc: u16,
    /// Sender sequence number.
    pub snd_seq_num: u64,
    /// Wrapped payload bytes.
    pub payload: Option<Zeroizing<Vec<u8>>>,
    /// Token checksum for unsealed tokens.
    pub checksum: Option<Vec<u8>>,
    /// Encrypted token body for sealed tokens, stored exactly as transmitted
    /// after the 16-byte Wrap header, including any right rotation.
    pub encrypted_body: Option<Vec<u8>>,
}

impl WrapToken {
    /// Sets `flags`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_flags(mut self, value: u8) -> Self {
        self.flags = value;
        self
    }
    /// Sets `ec`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_ec(mut self, value: u16) -> Self {
        self.ec = value;
        self
    }
    /// Sets `rrc`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_rrc(mut self, value: u16) -> Self {
        self.rrc = value;
        self
    }
    /// Sets `snd_seq_num`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_snd_seq_num(mut self, value: u64) -> Self {
        self.snd_seq_num = value;
        self
    }
    /// Sets `checksum`, preserving the other fields.
    #[must_use]
    #[inline]
    pub fn with_checksum(mut self, value: Option<Vec<u8>>) -> Self {
        self.checksum = value;
        self
    }
    /// Sets `encrypted_body`, preserving the other fields.
    #[must_use]
    #[inline]
    pub fn with_encrypted_body(mut self, value: Option<Vec<u8>>) -> Self {
        self.encrypted_body = value;
        self
    }

    #[must_use]
    /// Build a wrap token with no payload or checksum.
    #[inline]
    pub const fn new(flags: u8, snd_seq_num: u64) -> Self {
        Self {
            flags,
            ec: 0,
            rrc: 0,
            snd_seq_num,
            payload: None,
            checksum: None,
            encrypted_body: None,
        }
    }

    /// Decode a wrap token.
    ///
    /// Sealed tokens can be parsed without a key, but their payload is only
    /// available after [`Self::decrypt_payload`] or [`Self::decrypt_and_set_payload`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::GssTokenTooShort`] when `bytes` is shorter than the 16-byte header,
    /// [`Error::InvalidGssTokenId`] for a token ID other than `05 04`,
    /// [`Error::UnexpectedGssTokenSender`] when the acceptor flag does not match
    /// `expect_from_acceptor`, [`Error::InvalidGssFiller`] for a bad filler,
    /// [`Error::MissingGssEncryptedBody`] for a sealed token without a body, and
    /// [`Error::InconsistentWrapChecksumLength`] when the extra count exceeds the bytes after the
    /// header.
    #[inline]
    pub fn decode(bytes: &[u8], expect_from_acceptor: bool) -> Result<Self, Error> {
        let Some((header, body)) = bytes.split_first_chunk::<GSS_WRAP_HEADER_LEN>() else {
            return Err(Error::GssTokenTooShort {
                minimum: GSS_WRAP_HEADER_LEN,
                actual: bytes.len(),
            });
        };
        let [
            tok_id_0,
            tok_id_1,
            flags,
            filler,
            ec_0,
            ec_1,
            rrc_0,
            rrc_1,
            seq_0,
            seq_1,
            seq_2,
            seq_3,
            seq_4,
            seq_5,
            seq_6,
            seq_7,
        ] = *header;
        validate_gss_token_id([tok_id_0, tok_id_1], TOK_ID_GSS_WRAP)?;
        validate_gss_sender(flags, expect_from_acceptor)?;
        if filler != GSS_WRAP_FILLER {
            return Err(Error::InvalidGssFiller);
        }

        let ec = u16::from_be_bytes([ec_0, ec_1]);
        let rrc = u16::from_be_bytes([rrc_0, rrc_1]);
        let snd_seq_num =
            u64::from_be_bytes([seq_0, seq_1, seq_2, seq_3, seq_4, seq_5, seq_6, seq_7]);
        if flags & GSS_TOKEN_FLAG_SEALED != 0 {
            if body.is_empty() {
                return Err(Error::MissingGssEncryptedBody);
            }
            return Ok(Self {
                flags,
                ec,
                rrc,
                snd_seq_num,
                payload: None,
                checksum: None,
                encrypted_body: Some(body.to_vec()),
            });
        }

        let unrotated = scratch::Scratch::new(rotate_left(body, usize::from(rrc)), "wrap-decode");
        let checksum_len = usize::from(ec);
        let Some((payload, checksum)) = unrotated
            .len()
            .checked_sub(checksum_len)
            .and_then(|payload_len| unrotated.split_at_checked(payload_len))
        else {
            return Err(Error::InconsistentWrapChecksumLength {
                token_len: bytes.len(),
                checksum_len,
            });
        };

        Ok(Self {
            flags,
            ec,
            rrc,
            snd_seq_num,
            payload: Some(Zeroizing::new(payload.to_vec())),
            checksum: Some(checksum.to_vec()),
            encrypted_body: None,
        })
    }

    /// Encode this wrap token.
    /// The returned unsealed wire bytes contain plaintext; the caller must erase them.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MissingGssEncryptedBody`] for a sealed token without an encrypted body. For
    /// an unsealed token, returns [`Error::MissingGssPayload`] or [`Error::MissingGssChecksum`]
    /// when either is absent, and [`Error::InvalidGssChecksumLength`] when the checksum length
    /// differs from the extra count.
    #[inline]
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.is_sealed() {
            let encrypted_body = self
                .encrypted_body
                .as_ref()
                .ok_or(Error::MissingGssEncryptedBody)?;
            let mut bytes = self.header(self.rrc);
            bytes.extend_from_slice(encrypted_body);
            return Ok(bytes);
        }

        let payload = self.payload.as_ref().ok_or(Error::MissingGssPayload)?;
        let checksum = self.checksum.as_ref().ok_or(Error::MissingGssChecksum)?;
        if checksum.len() != usize::from(self.ec) {
            return Err(Error::InvalidGssChecksumLength {
                expected: usize::from(self.ec),
                actual: checksum.len(),
            });
        }

        let mut bytes = scratch::Scratch::new(
            Vec::with_capacity(
                GSS_WRAP_HEADER_LEN
                    .saturating_add(payload.len())
                    .saturating_add(checksum.len()),
            ),
            "wrap-encode",
        );
        bytes.extend_from_slice(&self.header(self.rrc));
        bytes.extend_from_slice(payload);
        bytes.extend_from_slice(checksum);
        if let Some(body) = bytes.get_mut(GSS_WRAP_HEADER_LEN..)
            && let Some(shift) = usize::from(self.rrc).checked_rem(body.len())
        {
            body.rotate_right(shift);
        }
        Ok(bytes.to_vec())
    }

    #[must_use]
    /// Set wrapped payload bytes.
    /// Borrowed inputs are copied; the caller remains responsible for erasing the original.
    #[inline]
    pub fn with_payload<P>(mut self, payload: P) -> Self
    where
        P: Into<Vec<u8>>,
    {
        self.payload = Some(Zeroizing::new(payload.into()));
        self
    }

    /// Compute and set this token's checksum.
    ///
    /// # Errors
    ///
    /// Returns [`Error::GssChecksumAlreadySet`] when a checksum is already present,
    /// [`Error::SealedGssTokenNeedsEncryption`] for a sealed token, [`Error::MissingGssPayload`]
    /// without a payload, [`Error::UnsupportedEtype`] for an unknown key encryption type,
    /// [`Error::Crypto`] when the checksum computation fails, and
    /// [`Error::InvalidGssChecksumLength`] when the checksum length does not fit the 16-bit extra
    /// count.
    #[inline]
    pub fn set_checksum(&mut self, key: &EncryptionKey, key_usage: u32) -> Result<(), Error> {
        if self.checksum.is_some() {
            return Err(Error::GssChecksumAlreadySet);
        }
        if self.is_sealed() {
            return Err(Error::SealedGssTokenNeedsEncryption);
        }
        let checksum = self.compute_checksum(key, key_usage)?;
        if self.ec == 0 {
            self.ec = u16::try_from(checksum.len()).map_err(|_overflow| {
                Error::InvalidGssChecksumLength {
                    expected: usize::from(u16::MAX),
                    actual: checksum.len(),
                }
            })?;
        }
        self.checksum = Some(checksum);
        Ok(())
    }

    /// Verify this token's checksum.
    ///
    /// # Errors
    ///
    /// For a sealed token, returns the errors of [`Self::decrypt_payload`]. For an unsealed token,
    /// returns [`Error::MissingGssPayload`] without a payload, [`Error::UnsupportedEtype`] for an
    /// unknown key encryption type, [`Error::Crypto`] when the checksum computation fails,
    /// [`Error::MissingGssChecksum`] when the token carries no checksum, and
    /// [`Error::GssChecksumMismatch`] when the checksum does not match.
    #[inline]
    pub fn verify(&self, key: &EncryptionKey, key_usage: u32) -> Result<(), Error> {
        if self.is_sealed() {
            drop(scratch::Scratch::new(
                self.decrypt_payload(key, key_usage)?,
                "wrap-verify",
            ));
            return Ok(());
        }

        selection::reject_enctype(key.etype)?;
        let payload = self.payload.as_ref().ok_or(Error::MissingGssPayload)?;
        let mut data = scratch::Scratch::new(payload.to_vec(), "wrap-checksum");
        data.extend_from_slice(&wrap_checksum_header(self.flags, self.snd_seq_num));
        let etype = selection::enctype(key.etype)?.ok_or(Error::UnsupportedEtype(key.etype))?;
        let actual = self.checksum.as_ref().ok_or(Error::MissingGssChecksum)?;
        if !etype.verify_checksum(&key.value, &data, actual, key_usage) {
            return Err(Error::GssChecksumMismatch);
        }
        Ok(())
    }

    /// Build an initiator wrap token and compute its checksum.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedEtype`] for an unknown key encryption type,
    /// [`Error::InvalidGssChecksumLength`] when the checksum length does not fit the 16-bit extra
    /// count, and [`Error::Crypto`] when the checksum computation fails.
    #[inline]
    pub fn new_initiator<P>(payload: P, key: &EncryptionKey) -> Result<Self, Error>
    where
        P: Into<Zeroizing<Vec<u8>>>,
    {
        let owned_payload = payload.into();
        let etype = selection::enctype(key.etype)?.ok_or(Error::UnsupportedEtype(key.etype))?;
        let mut token = Self {
            flags: 0,
            ec: u16::try_from(etype.hmac_len()).map_err(|_overflow| {
                Error::InvalidGssChecksumLength {
                    expected: usize::from(u16::MAX),
                    actual: etype.hmac_len(),
                }
            })?,
            rrc: 0,
            snd_seq_num: 0,
            payload: Some(owned_payload),
            checksum: None,
            encrypted_body: None,
        };
        token.set_checksum(key, GSSAPI_INITIATOR_SEAL_USAGE)?;
        Ok(token)
    }

    /// Build an initiator sealed wrap token with a random confounder.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedEtype`] for an unknown key encryption type, [`Error::Random`]
    /// when the confounder cannot be generated, and [`Error::Crypto`] when encryption fails.
    #[inline]
    pub fn new_initiator_sealed<P>(payload: P, key: &EncryptionKey) -> Result<Self, Error>
    where
        P: Into<Zeroizing<Vec<u8>>>,
    {
        let owned_payload = payload.into();
        let etype = selection::enctype(key.etype)?.ok_or(Error::UnsupportedEtype(key.etype))?;
        let mut confounder = vec![0; etype.confounder_len()];
        getrandom::fill(&mut confounder)?;
        Self::new_initiator_sealed_with_confounder(owned_payload, key, &confounder)
    }

    /// Build an initiator sealed wrap token with an explicit confounder.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedEtype`] for an unknown key encryption type and [`Error::Crypto`]
    /// when encryption fails.
    #[inline]
    pub fn new_initiator_sealed_with_confounder<P>(
        payload: P,
        key: &EncryptionKey,
        confounder: &[u8],
    ) -> Result<Self, Error>
    where
        P: Into<Zeroizing<Vec<u8>>>,
    {
        let mut token = Self {
            flags: GSS_TOKEN_FLAG_SEALED,
            ec: 0,
            rrc: 0,
            snd_seq_num: 0,
            payload: Some(payload.into()),
            checksum: None,
            encrypted_body: None,
        };
        token.encrypt_payload_with_confounder(key, GSSAPI_INITIATOR_SEAL_USAGE, confounder)?;
        Ok(token)
    }

    /// Encrypt this token's payload as a sealed RFC4121 Wrap token.
    ///
    /// The requested EC is a minimum: DES3 filler grows to prevent trailing crypto-system residue.
    ///
    /// # Errors
    ///
    /// Returns [`Error::GssEncryptedBodyAlreadySet`] when the token already carries an encrypted
    /// body, [`Error::MissingGssPayload`] without a payload, [`Error::UnsupportedEtype`] for an
    /// unknown key encryption type, [`Error::InvalidGssFiller`] if the required filler exceeds
    /// the 16-bit EC field, and [`Error::Crypto`] when encryption fails.
    #[inline]
    pub fn encrypt_payload_with_confounder(
        &mut self,
        key: &EncryptionKey,
        key_usage: u32,
        confounder: &[u8],
    ) -> Result<(), Error> {
        if self.encrypted_body.is_some() {
            return Err(Error::GssEncryptedBodyAlreadySet);
        }

        let flags = self.flags | GSS_TOKEN_FLAG_SEALED;
        let payload = self.payload.as_ref().ok_or(Error::MissingGssPayload)?;
        let etype = selection::enctype(key.etype)?.ok_or(Error::UnsupportedEtype(key.etype))?;
        let ec = match etype {
            KerberosEtype::Des3CbcSha1Kd(_) => {
                // DES3's 8-byte confounder and the 16-byte header are already block-aligned.
                let residue = payload.len().wrapping_add(usize::from(self.ec)) & 7;
                let extra = u16::try_from(residue.wrapping_neg() & 7)
                    .map_err(|_error| Error::InvalidGssFiller)?;
                self.ec.checked_add(extra).ok_or(Error::InvalidGssFiller)?
            }
            KerberosEtype::Sha1(_) | KerberosEtype::Sha2(_) | KerberosEtype::Rc4Hmac(_) => self.ec,
        };
        let mut plaintext = scratch::Scratch::new(
            Vec::with_capacity(
                payload
                    .len()
                    .saturating_add(usize::from(ec))
                    .saturating_add(GSS_WRAP_HEADER_LEN),
            ),
            "wrap-seal",
        );
        plaintext.extend_from_slice(payload);
        plaintext.extend(iter::repeat_n(0, usize::from(ec)));
        plaintext.extend_from_slice(&wrap_header(flags, ec, 0, self.snd_seq_num));

        let encrypted =
            etype.encrypt_message_with_confounder(&key.value, &plaintext, key_usage, confounder)?;
        self.encrypted_body = Some(rotate_right(&encrypted, usize::from(self.rrc)));
        self.flags = flags;
        self.ec = ec;
        self.checksum = None;
        Ok(())
    }

    /// Decrypt and return the payload of a sealed Wrap token.
    /// The caller owns the returned plaintext and must erase it after use.
    ///
    /// # Errors
    ///
    /// Returns [`Error::GssTokenNotSealed`] for an unsealed token,
    /// [`Error::MissingGssEncryptedBody`] without an encrypted body, [`Error::UnsupportedEtype`]
    /// for an unknown key encryption type, [`Error::Crypto`] when decryption or its integrity check
    /// fails, [`Error::GssDecryptedTokenTooShort`] when the plaintext cannot hold the filler and
    /// the embedded header, and [`Error::InvalidGssEncryptedHeader`] when the embedded header
    /// differs from the clear header.
    #[inline]
    pub fn decrypt_payload(&self, key: &EncryptionKey, key_usage: u32) -> Result<Vec<u8>, Error> {
        if !self.is_sealed() {
            return Err(Error::GssTokenNotSealed);
        }

        let encrypted_body = self
            .encrypted_body
            .as_ref()
            .ok_or(Error::MissingGssEncryptedBody)?;
        let etype = selection::enctype(key.etype)?.ok_or(Error::UnsupportedEtype(key.etype))?;
        let encrypted = rotate_left(encrypted_body, usize::from(self.rrc));
        let mut plaintext = scratch::Scratch::new(
            etype.decrypt_message(&key.value, &encrypted, key_usage)?,
            "wrap-decrypt",
        );

        let trailer_len = GSS_WRAP_HEADER_LEN.saturating_add(usize::from(self.ec));
        let too_short = || Error::GssDecryptedTokenTooShort {
            minimum: trailer_len,
            actual: plaintext.len(),
        };
        let payload_len = plaintext
            .len()
            .checked_sub(trailer_len)
            .ok_or_else(too_short)?;
        let (_, embedded_header) = plaintext
            .split_last_chunk::<GSS_WRAP_HEADER_LEN>()
            .ok_or_else(too_short)?;
        if embedded_header.as_slice() != self.header(0).as_slice() {
            return Err(Error::InvalidGssEncryptedHeader);
        }

        plaintext.truncate(payload_len);
        Ok(plaintext.to_vec())
    }

    /// Decrypt a sealed token and store its payload on this value.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::decrypt_payload`] and leaves the stored payload unchanged.
    #[inline]
    pub fn decrypt_and_set_payload(
        &mut self,
        key: &EncryptionKey,
        key_usage: u32,
    ) -> Result<&[u8], Error> {
        let payload = Zeroizing::new(self.decrypt_payload(key, key_usage)?);
        Ok(self.payload.insert(payload).as_slice())
    }

    #[must_use]
    /// Whether this Wrap token has the RFC4121 sealed/confidentiality flag.
    #[inline]
    pub const fn is_sealed(&self) -> bool {
        self.flags & GSS_TOKEN_FLAG_SEALED != 0
    }

    /// Compute the RFC 4121 checksum over the payload followed by the checksum header, which has
    /// zero extra and rotation counts.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MissingGssPayload`] without a payload, [`Error::UnsupportedEtype`] for an
    /// unknown key encryption type, and [`Error::Crypto`] when the checksum computation fails.
    fn compute_checksum(&self, key: &EncryptionKey, key_usage: u32) -> Result<Vec<u8>, Error> {
        selection::reject_enctype(key.etype)?;
        let payload = self.payload.as_ref().ok_or(Error::MissingGssPayload)?;
        let mut data = scratch::Scratch::new(
            Vec::with_capacity(payload.len().saturating_add(GSS_WRAP_HEADER_LEN)),
            "wrap-checksum",
        );
        data.extend_from_slice(payload);
        data.extend_from_slice(&wrap_checksum_header(self.flags, self.snd_seq_num));

        let etype = selection::enctype(key.etype)?.ok_or(Error::UnsupportedEtype(key.etype))?;
        etype
            .checksum(&key.value, &data, key_usage)
            .map_err(Error::Crypto)
    }

    /// The 16-byte Wrap token header with this token's flags, extra count and sequence number, and
    /// the given right rotation count.
    fn header(&self, rrc: u16) -> Vec<u8> {
        wrap_header(self.flags, self.ec, rrc, self.snd_seq_num)
    }
}

impl fmt::Debug for WrapToken {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            flags,
            ec,
            rrc,
            snd_seq_num,
            payload,
            checksum,
            encrypted_body,
        } = self;
        f.debug_struct("WrapToken")
            .field("flags", flags)
            .field("ec", ec)
            .field("rrc", rrc)
            .field("snd_seq_num", snd_seq_num)
            .field("payload_len", &payload.as_ref().map(|value| value.len()))
            .field("checksum_len", &checksum.as_ref().map(Vec::len))
            .field("encrypted_len", &encrypted_body.as_ref().map(Vec::len))
            .finish()
    }
}

/// GSS-API KRB5 mech token type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Krb5TokenId {
    /// AP-REQ token, `01 00`.
    ApReq,
    /// AP-REP token, `02 00`.
    ApRep,
    /// KRB-ERROR token, `03 00`.
    KrbError,
}

impl Krb5TokenId {
    /// The two-byte token ID that RFC 4121 places after the mechanism OID.
    const fn bytes(self) -> [u8; 2] {
        match self {
            Self::ApReq => TOK_ID_KRB_AP_REQ,
            Self::ApRep => TOK_ID_KRB_AP_REP,
            Self::KrbError => TOK_ID_KRB_ERROR,
        }
    }

    /// Parse a two-byte KRB5 token ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnknownKrb5TokenId`] for anything other than an AP-REQ, AP-REP or KRB-ERROR
    /// token ID.
    const fn from_bytes(bytes: [u8; 2]) -> Result<Self, Error> {
        match bytes {
            TOK_ID_KRB_AP_REQ => Ok(Self::ApReq),
            TOK_ID_KRB_AP_REP => Ok(Self::ApRep),
            TOK_ID_KRB_ERROR => Ok(Self::KrbError),
            actual => Err(Error::UnknownKrb5TokenId(actual)),
        }
    }
}

/// GSS-API KRB5 mech token containing one Kerberos message.
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub struct Krb5MechToken {
    /// Token mechanism OID. RFC 4121 KRB5 tokens use [`ObjectIdentifier::krb5`].
    pub oid: ObjectIdentifier,
    /// Two-byte KRB5 token ID.
    pub token_id: Krb5TokenId,
    /// DER-encoded Kerberos message carried by this token.
    pub message: Zeroizing<Vec<u8>>,
}

impl Krb5MechToken {
    #[must_use]
    /// Build a KRB5 AP-REQ mech token.
    #[inline]
    pub fn ap_req(message: Vec<u8>) -> Self {
        Self::new(Krb5TokenId::ApReq, message)
    }

    #[must_use]
    /// Build a KRB5 AP-REP mech token.
    #[inline]
    pub fn ap_rep(message: Vec<u8>) -> Self {
        Self::new(Krb5TokenId::ApRep, message)
    }

    #[must_use]
    /// Build a KRB5 mech token with the standard Kerberos 5 mechanism OID.
    #[inline]
    pub fn new(token_id: Krb5TokenId, message: Vec<u8>) -> Self {
        Self {
            oid: ObjectIdentifier::krb5(),
            token_id,
            message: Zeroizing::new(message),
        }
    }

    /// Decode a GSS-API KRB5 mech token.
    ///
    /// # Errors
    ///
    /// Returns DER errors ([`Error::TruncatedDer`], [`Error::HighTagNumber`],
    /// [`Error::IndefiniteLength`], [`Error::LengthExceedsInput`], [`Error::TrailingData`]) for
    /// malformed input, [`Error::UnexpectedTag`] when the token is not an application 0 element,
    /// [`Error::InvalidOidEncoding`] or [`Error::InvalidOid`] for a malformed mechanism OID,
    /// [`Error::UnsupportedMechanism`] for a mechanism other than Kerberos 5,
    /// [`Error::UnknownKrb5TokenId`] for an unknown token ID, and [`Error::MissingKerberosMessage`]
    /// when no message follows the token ID.
    #[inline]
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut outer = DerReader::new(bytes);
        let token = outer.read_tlv()?;
        outer.finish()?;
        if token.tag() != TAG_APPLICATION_0 {
            return Err(Error::UnexpectedTag {
                expected: TAG_APPLICATION_0,
                actual: token.tag(),
            });
        }

        let mut content = DerReader::new(token.value());
        let oid = decode_oid_tlv(content.read_tlv()?)?;
        if !oid.is_kerberos_mechanism() {
            return Err(Error::UnsupportedMechanism(oid));
        }

        let token_id = Krb5TokenId::from_bytes(*content.read_array::<2>()?)?;
        let message = Zeroizing::new(content.remaining().to_vec());
        if message.is_empty() {
            return Err(Error::MissingKerberosMessage);
        }
        Ok(Self {
            oid,
            token_id,
            message,
        })
    }

    /// Encode this token to DER.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MissingKerberosMessage`] for an empty message and [`Error::InvalidOid`] for
    /// an invalid mechanism OID.
    #[inline]
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.message.is_empty() {
            return Err(Error::MissingKerberosMessage);
        }

        let mut content = encode_oid(&self.oid)?;
        content.extend_from_slice(&self.token_id.bytes());
        content.extend_from_slice(&self.message);
        Ok(encode_tlv(TAG_APPLICATION_0, &content))
    }

    #[must_use]
    /// Return the AP-REQ bytes if this is an AP-REQ token.
    #[inline]
    pub fn ap_req_bytes(&self) -> Option<&[u8]> {
        (self.token_id == Krb5TokenId::ApReq).then_some(self.message.as_slice())
    }

    #[must_use]
    /// Return the AP-REP bytes if this is an AP-REP token.
    #[inline]
    pub fn ap_rep_bytes(&self) -> Option<&[u8]> {
        (self.token_id == Krb5TokenId::ApRep).then_some(self.message.as_slice())
    }
}

/// SPNEGO negotiation state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum NegState {
    /// `accept-completed`.
    AcceptCompleted,
    /// `accept-incomplete`.
    AcceptIncomplete,
    /// `reject`.
    Reject,
    /// `request-mic`.
    RequestMic,
}

impl NegState {
    /// The ASN.1 ENUMERATED value of this state.
    const fn value(self) -> u32 {
        match self {
            Self::AcceptCompleted => 0,
            Self::AcceptIncomplete => 1,
            Self::Reject => 2,
            Self::RequestMic => 3,
        }
    }

    /// Parse an ASN.1 ENUMERATED negotiation state.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidNegState`] for a value outside 0 to 3.
    const fn from_value(value: u32) -> Result<Self, Error> {
        match value {
            0 => Ok(Self::AcceptCompleted),
            1 => Ok(Self::AcceptIncomplete),
            2 => Ok(Self::Reject),
            3 => Ok(Self::RequestMic),
            actual => Err(Error::InvalidNegState(actual)),
        }
    }
}

/// SPNEGO `NegTokenInit`.
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub struct NegTokenInit {
    /// Offered mechanism OIDs.
    pub mech_types: Vec<ObjectIdentifier>,
    /// Optional DER BIT STRING contents, including the unused-bit count byte.
    pub req_flags: Option<Vec<u8>>,
    /// Optional mechanism token bytes.
    pub mech_token: Option<Zeroizing<Vec<u8>>>,
    /// Optional mechanism list MIC bytes.
    pub mech_list_mic: Option<Zeroizing<Vec<u8>>>,
}

impl NegTokenInit {
    #[must_use]
    /// Build a `NegTokenInit` that offers Kerberos 5 and carries a KRB5 mech
    /// token.
    #[inline]
    pub fn krb5(mech_token: Vec<u8>) -> Self {
        Self {
            mech_types: vec![ObjectIdentifier::krb5()],
            req_flags: None,
            mech_token: Some(Zeroizing::new(mech_token)),
            mech_list_mic: None,
        }
    }

    /// Encode this `NegTokenInit` as a SPNEGO negotiation token choice.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MissingMechTypes`] when no mechanism is offered and [`Error::InvalidOid`]
    /// for an invalid mechanism OID.
    #[inline]
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.mech_types.is_empty() {
            return Err(Error::MissingMechTypes);
        }

        let mut fields = Vec::new();
        let mut mech_types = Vec::new();
        for oid in &self.mech_types {
            mech_types.extend_from_slice(&encode_oid(oid)?);
        }
        fields.extend_from_slice(&encode_explicit(
            TAG_CONTEXT_0,
            &encode_tlv(TAG_SEQUENCE, &mech_types),
        ));

        if let Some(req_flags) = &self.req_flags {
            validate_req_flags(req_flags)?;
            fields.extend_from_slice(&encode_explicit(
                TAG_CONTEXT_1,
                &encode_tlv(TAG_BIT_STRING, req_flags),
            ));
        }
        if let Some(mech_token) = &self.mech_token {
            fields.extend_from_slice(&encode_explicit(
                TAG_CONTEXT_2,
                &encode_tlv(TAG_OCTET_STRING, mech_token),
            ));
        }
        if let Some(mech_list_mic) = &self.mech_list_mic {
            fields.extend_from_slice(&encode_explicit(
                TAG_CONTEXT_3,
                &encode_tlv(TAG_OCTET_STRING, mech_list_mic),
            ));
        }

        Ok(encode_explicit(
            TAG_CONTEXT_0,
            &encode_tlv(TAG_SEQUENCE, &fields),
        ))
    }

    /// Decode a `NegTokenInit` from a SPNEGO negotiation token choice.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`NegotiationToken::decode`], and [`Error::WrongNegotiationToken`]
    /// when the token is a `NegTokenResp`.
    #[inline]
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        match NegotiationToken::decode(bytes)? {
            NegotiationToken::Init(token) => Ok(token),
            NegotiationToken::Resp(_) => Err(Error::WrongNegotiationToken {
                expected: "NegTokenInit",
                actual: "NegTokenResp",
            }),
        }
    }

    /// Return a first-choice KRB5 AP-REQ requiring no mechanism-list MIC.
    ///
    /// This extraction helper has no keys. Use [`accept_sec_context_header`] to
    /// validate an initial exchange carrying a MIC or selecting a non-first OID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MissingMechTypes`] when no mechanism is offered,
    /// [`Error::UnsupportedMechanism`] when no offered mechanism is Kerberos 5,
    /// [`Error::MechListMicRequiresState`] when a MIC is supplied,
    /// [`Error::MissingMechListMic`] when the selected mechanism is not first,
    /// [`Error::MissingMechToken`] without a mechanism token, the errors of
    /// [`Krb5MechToken::decode`], and [`Error::MissingApReq`] when the mechanism token is not an
    /// AP-REQ.
    #[inline]
    pub fn krb5_ap_req(&self) -> Result<Vec<u8>, Error> {
        let krb5 = negotiation::optimistic_token(self)?;
        if self.mech_list_mic.is_some() {
            return Err(Error::MechListMicRequiresState);
        }
        Ok(krb5.message.to_vec())
    }
}

/// SPNEGO `NegTokenResp` / `NegTokenTarg`.
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub struct NegTokenResp {
    /// Optional negotiation state.
    pub neg_state: Option<NegState>,
    /// Optional selected mechanism OID.
    pub supported_mech: Option<ObjectIdentifier>,
    /// Optional response token bytes.
    pub response_token: Option<Zeroizing<Vec<u8>>>,
    /// Optional mechanism list MIC bytes.
    pub mech_list_mic: Option<Zeroizing<Vec<u8>>>,
}

impl NegTokenResp {
    #[must_use]
    /// Build an `accept-completed` response selecting Kerberos 5.
    #[inline]
    pub fn accept_completed() -> Self {
        Self {
            neg_state: Some(NegState::AcceptCompleted),
            supported_mech: Some(ObjectIdentifier::krb5()),
            response_token: None,
            mech_list_mic: None,
        }
    }

    #[must_use]
    /// Build an `accept-incomplete` response selecting Kerberos 5.
    #[inline]
    pub fn accept_incomplete_krb5() -> Self {
        Self {
            neg_state: Some(NegState::AcceptIncomplete),
            supported_mech: Some(ObjectIdentifier::krb5()),
            response_token: None,
            mech_list_mic: None,
        }
    }

    #[must_use]
    /// Build a rejection response.
    #[inline]
    pub const fn reject() -> Self {
        Self {
            neg_state: Some(NegState::Reject),
            supported_mech: None,
            response_token: None,
            mech_list_mic: None,
        }
    }

    #[must_use]
    /// Attach a mechanism response token.
    #[inline]
    pub fn with_response_token(mut self, response_token: Vec<u8>) -> Self {
        self.response_token = Some(Zeroizing::new(response_token));
        self
    }

    /// Encode this `NegTokenResp` as a SPNEGO negotiation token choice.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidOid`] when the selected mechanism OID is invalid.
    #[inline]
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut fields = Vec::new();
        if let Some(neg_state) = self.neg_state {
            fields.extend_from_slice(&encode_explicit(
                TAG_CONTEXT_0,
                &encode_tlv(TAG_ENUMERATED, &encode_u32(neg_state.value())),
            ));
        }
        if let Some(supported_mech) = &self.supported_mech {
            fields.extend_from_slice(&encode_explicit(
                TAG_CONTEXT_1,
                &encode_oid(supported_mech)?,
            ));
        }
        if let Some(response_token) = &self.response_token {
            fields.extend_from_slice(&encode_explicit(
                TAG_CONTEXT_2,
                &encode_tlv(TAG_OCTET_STRING, response_token),
            ));
        }
        if let Some(mech_list_mic) = &self.mech_list_mic {
            fields.extend_from_slice(&encode_explicit(
                TAG_CONTEXT_3,
                &encode_tlv(TAG_OCTET_STRING, mech_list_mic),
            ));
        }
        Ok(encode_explicit(
            TAG_CONTEXT_1,
            &encode_tlv(TAG_SEQUENCE, &fields),
        ))
    }

    /// Decode a `NegTokenResp` from a SPNEGO negotiation token choice.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`NegotiationToken::decode`], and [`Error::WrongNegotiationToken`]
    /// when the token is a `NegTokenInit`.
    #[inline]
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        match NegotiationToken::decode(bytes)? {
            NegotiationToken::Init(_) => Err(Error::WrongNegotiationToken {
                expected: "NegTokenResp",
                actual: "NegTokenInit",
            }),
            NegotiationToken::Resp(token) => Ok(token),
        }
    }
}

/// SPNEGO negotiation token choice.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum NegotiationToken {
    /// `NegTokenInit`.
    Init(NegTokenInit),
    /// `NegTokenResp` / `NegTokenTarg`.
    Resp(NegTokenResp),
}

impl NegotiationToken {
    /// Decode a SPNEGO negotiation token choice.
    ///
    /// # Errors
    ///
    /// Returns DER errors ([`Error::TruncatedDer`], [`Error::HighTagNumber`],
    /// [`Error::IndefiniteLength`], [`Error::LengthExceedsInput`], [`Error::TrailingData`]) for
    /// malformed input, [`Error::UnexpectedTag`] for an unknown choice or field tag,
    /// [`Error::MissingMechTypes`] when a `NegTokenInit` offers no mechanism,
    /// [`Error::InvalidInteger`] or [`Error::InvalidNegState`] for a bad negotiation state, and
    /// [`Error::InvalidOidEncoding`] or [`Error::InvalidOid`] for a malformed mechanism OID.
    #[inline]
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut outer = DerReader::new(bytes);
        let choice = outer.read_tlv()?;
        outer.finish()?;
        decode_negotiation_choice(choice)
    }

    /// Encode this negotiation token choice.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`NegTokenInit::encode`] or [`NegTokenResp::encode`].
    #[inline]
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        match self {
            Self::Init(token) => token.encode(),
            Self::Resp(token) => token.encode(),
        }
    }
}

/// Full SPNEGO GSS context token.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Token {
    /// Initial context token with SPNEGO OID and `NegTokenInit`.
    Init(NegTokenInit),
    /// Bare `NegTokenResp` response token.
    Resp(NegTokenResp),
}

impl Token {
    /// Decode a full SPNEGO context token.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EmptyInput`] for empty input, DER errors ([`Error::TruncatedDer`],
    /// [`Error::HighTagNumber`], [`Error::IndefiniteLength`], [`Error::LengthExceedsInput`],
    /// [`Error::TrailingData`]) for a malformed initial context token,
    /// [`Error::InvalidOidEncoding`] or [`Error::InvalidOid`] for a malformed OID,
    /// [`Error::UnexpectedSpnegoOid`] when an initial context token does not carry the SPNEGO OID,
    /// [`Error::WrongNegotiationToken`] when it wraps a `NegTokenResp`, and the errors of
    /// [`NegotiationToken::decode`].
    #[inline]
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let Some(first) = bytes.first() else {
            return Err(Error::EmptyInput);
        };

        if *first == TAG_APPLICATION_0 {
            let mut outer = DerReader::new(bytes);
            let wrapper = outer.read_tlv()?;
            outer.finish()?;

            let mut content = DerReader::new(wrapper.value());
            let oid = decode_oid_tlv(content.read_tlv()?)?;
            if oid != ObjectIdentifier::spnego() {
                return Err(Error::UnexpectedSpnegoOid(oid));
            }
            let negotiation = content.remaining();
            match NegotiationToken::decode(negotiation)? {
                NegotiationToken::Init(token) => Ok(Self::Init(token)),
                NegotiationToken::Resp(_) => Err(Error::WrongNegotiationToken {
                    expected: "NegTokenInit",
                    actual: "NegTokenResp",
                }),
            }
        } else {
            match NegotiationToken::decode(bytes)? {
                NegotiationToken::Init(token) => Ok(Self::Init(token)),
                NegotiationToken::Resp(token) => Ok(Self::Resp(token)),
            }
        }
    }

    /// Encode a full SPNEGO context token.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`NegTokenInit::encode`] or [`NegTokenResp::encode`].
    #[inline]
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        match self {
            Self::Init(token) => {
                let mut content = encode_oid(&ObjectIdentifier::spnego())?;
                content.extend_from_slice(&token.encode()?);
                Ok(encode_tlv(TAG_APPLICATION_0, &content))
            }
            Self::Resp(token) => token.encode(),
        }
    }

    /// Return an optimistic KRB5 AP-REQ without an unfinished MIC exchange.
    ///
    /// # Errors
    ///
    /// For an initial token, returns the errors of [`NegTokenInit::krb5_ap_req`]. For a response
    /// token, returns [`Error::UnsupportedMechanism`] for a non-Kerberos selection,
    /// or [`Error::NegotiationRequiresState`]: the original offer and MIC exchange
    /// phase are unavailable, so a continuation cannot establish a context here.
    #[inline]
    pub fn krb5_ap_req(&self) -> Result<Vec<u8>, Error> {
        match self {
            Self::Init(token) => token.krb5_ap_req(),
            Self::Resp(token) => {
                if let Some(mech) = &token.supported_mech
                    && !mech.is_kerberos_mechanism()
                {
                    return Err(Error::UnsupportedMechanism(mech.clone()));
                }
                Err(Error::NegotiationRequiresState)
            }
        }
    }
}

/// Options for building a client SPNEGO AP-REQ initiator token.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct InitiatorContextOptions {
    /// Runtime policy passed to AP construction; secure defaults when absent.
    pub crypto_policy: Option<CryptoPolicy>,
    /// GSS-API context flags to place in the authenticator checksum.
    pub context_flags: Vec<u32>,
    /// AP-REQ option bit string.
    pub ap_option_bits: u32,
    /// Optional client-selected subkey.
    pub subkey: Option<EncryptionKey>,
    /// Optional client sequence number.
    ///
    /// [`init_sec_context`] fills a random gokrb5-compatible sequence number
    /// when this is absent. [`init_sec_context_with_confounder`] requires an
    /// explicit value so deterministic construction also conforms to RFC 4121.
    pub sequence_number: Option<u32>,
}

impl InitiatorContextOptions {
    /// Set explicit enctype permission for this initiator context.
    #[inline]
    #[must_use]
    pub fn with_crypto_policy(mut self, policy: CryptoPolicy) -> Self {
        self.crypto_policy = Some(policy);
        self
    }
    #[must_use]
    /// Construct options matching gokrb5's default HTTP SPNEGO flags.
    #[inline]
    pub fn new() -> Self {
        Self {
            crypto_policy: None,
            context_flags: vec![CONTEXT_FLAG_INTEG, CONTEXT_FLAG_CONF],
            ap_option_bits: 0,
            subkey: None,
            sequence_number: None,
        }
    }

    #[must_use]
    /// Override GSS-API context flags.
    #[inline]
    pub fn with_context_flags<P>(mut self, context_flags: P) -> Self
    where
        P: Into<Vec<u32>>,
    {
        self.context_flags = context_flags.into();
        self
    }

    #[must_use]
    /// Override AP-REQ option bits.
    #[inline]
    pub const fn with_ap_option_bits(mut self, ap_option_bits: u32) -> Self {
        self.ap_option_bits = ap_option_bits;
        self
    }

    #[must_use]
    /// Set or clear the client-selected subkey.
    #[inline]
    pub fn with_subkey(mut self, subkey: Option<EncryptionKey>) -> Self {
        self.subkey = subkey;
        self
    }

    #[must_use]
    /// Set or clear the client sequence number.
    #[inline]
    pub const fn with_sequence_number(mut self, sequence_number: Option<u32>) -> Self {
        self.sequence_number = sequence_number;
        self
    }
}

impl Default for InitiatorContextOptions {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

/// Built client SPNEGO initiator context.
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub struct InitiatorContext {
    /// Runtime policy retained for reply keys and server-selected subkeys.
    pub crypto_policy: CryptoPolicy,
    /// ASN.1 AP-REQ message.
    pub ap_req: rasn_kerberos::ApReq,
    /// DER-encoded AP-REQ bytes.
    pub ap_req_der: Zeroizing<Vec<u8>>,
    /// KRB5 mech token carrying the AP-REQ.
    pub krb5_token: Krb5MechToken,
    /// SPNEGO `NegTokenInit` context token.
    pub spnego_token: Token,
    /// HTTP `Authorization` header value.
    pub header: Zeroizing<String>,
    /// Client principal placed in the authenticator.
    pub client: Principal,
    /// Service principal from the ticket.
    pub service: Principal,
    /// Service-ticket session key used for AP-REP verification.
    pub session_key: EncryptionKey,
    /// Authenticator `ctime` without `cusec`.
    pub authenticator_ctime: SystemTime,
    /// Authenticator microsecond field.
    pub authenticator_cusec: u32,
    /// Authenticator timestamp including `cusec`.
    pub authenticator_time: SystemTime,
    /// Optional client sequence number supplied in the authenticator.
    pub sequence_number: Option<u32>,
    /// GSS-API context flags requested when this context was built.
    pub context_flags: Vec<u32>,
    /// Initiator subkey retained for acceptor mechanism-list MIC verification.
    pub initiator_subkey: Option<EncryptionKey>,
}

impl fmt::Debug for InitiatorContext {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            crypto_policy: _,
            ap_req: _,
            ap_req_der,
            krb5_token: _,
            spnego_token: _,
            header,
            client,
            service,
            session_key: _,
            authenticator_ctime,
            authenticator_cusec,
            authenticator_time,
            sequence_number,
            context_flags,
            initiator_subkey: _,
        } = self;
        f.debug_struct("InitiatorContext")
            .field("ap_req_len", &ap_req_der.len())
            .field("header_len", &header.len())
            .field("client", client)
            .field("service", service)
            .field("authenticator_ctime", authenticator_ctime)
            .field("authenticator_cusec", authenticator_cusec)
            .field("authenticator_time", authenticator_time)
            .field("sequence_number", sequence_number)
            .field("context_flags", context_flags)
            .finish()
    }
}

impl InitiatorContext {
    /// Validate completion metadata against the retained offer.
    ///
    /// # Errors
    /// Returns a typed error for unfinished negotiation, unoffered mechanisms,
    /// or a MIC exchange this one-shot initiator cannot complete.
    pub(crate) fn validate_completion(&self, response: &NegTokenResp) -> Result<(), Error> {
        match response.neg_state {
            Some(NegState::AcceptCompleted) => {}
            Some(NegState::AcceptIncomplete | NegState::RequestMic | NegState::Reject) | None => {
                return Err(Error::NegotiationRequiresState);
            }
        }
        if let Some(selected) = &response.supported_mech {
            let offered = match &self.spnego_token {
                Token::Init(init) => &init.mech_types,
                Token::Resp(_) => return Err(Error::NegotiationRequiresState),
            };
            if !offered.contains(selected) {
                return Err(Error::UnsupportedMechanism(selected.clone()));
            }
        } else {
            return Err(Error::NegotiationRequiresState);
        }
        if let Some(bytes) = &response.mech_list_mic {
            let token = Krb5MechToken::decode(
                response
                    .response_token
                    .as_ref()
                    .ok_or(Error::MissingApRep)?,
            )?;
            if token.token_id != Krb5TokenId::ApRep {
                return Err(Error::MissingApRep);
            }
            let verified = self.verify_ap_rep(&token.message)?;
            let mic = MicToken::decode(bytes, true).map_err(|_source| Error::InvalidMechListMic)?;
            if mic.flags & GSS_TOKEN_FLAG_SEALED != 0
                || mic.snd_seq_num != u64::from(verified.sequence_number.unwrap_or(0))
            {
                return Err(Error::InvalidMechListMic);
            }
            let key = if mic.flags & GSS_TOKEN_FLAG_ACCEPTOR_SUBKEY != 0 {
                verified.subkey.as_ref().ok_or(Error::InvalidMechListMic)?
            } else {
                self.initiator_subkey.as_ref().unwrap_or(&self.session_key)
            };
            let encoded = self.spnego_token.encode()?;
            let list = negotiation::received_mech_types(&encoded)?;
            mic.with_payload(list)
                .verify(key, GSSAPI_ACCEPTOR_SIGN_USAGE)
                .map_err(|_source| Error::InvalidMechListMic)?;
        }
        Ok(())
    }

    /// Verify an AP-REP wrapped in a SPNEGO `Negotiate` response header.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`parse_negotiate_header`], [`Error::WrongNegotiationToken`] for a
    /// `NegTokenInit`, [`Error::MissingMechToken`] without a response token, the errors of
    /// [`Krb5MechToken::decode`], [`Error::MissingApRep`] when the response token is not an AP-REP,
    /// and the errors of [`Self::verify_ap_rep`].
    #[inline]
    pub fn verify_ap_rep_response_header(&self, header: &str) -> Result<VerifiedApRep, Error> {
        let token = parse_negotiate_header(header)?;
        let response = match token {
            Token::Resp(response) => response,
            Token::Init(_) => {
                return Err(Error::WrongNegotiationToken {
                    expected: "NegTokenResp",
                    actual: "NegTokenInit",
                });
            }
        };
        self.validate_completion(&response)?;
        let response_token = response.response_token.ok_or(Error::MissingMechToken)?;
        let krb5 = Krb5MechToken::decode(&response_token)?;
        if krb5.token_id != Krb5TokenId::ApRep {
            return Err(Error::MissingApRep);
        }
        self.verify_ap_rep(&krb5.message)
    }

    /// Verify an AP-REP message against this initiator's AP-REQ timestamp.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Decode`], [`Error::InvalidMessage`], [`Error::UnsupportedEtype`],
    /// [`Error::ApRepKeyEtypeMismatch`] or [`Error::Crypto`] when the AP-REP cannot be decoded or
    /// decrypted with the session key, [`Error::TimeOverflow`] or [`Error::IntegerOutOfRange`] when
    /// its timestamp cannot be represented, and [`Error::ApRepTimestampMismatch`] when it does not
    /// echo the authenticator timestamp.
    #[inline]
    pub fn verify_ap_rep(&self, bytes: &[u8]) -> Result<VerifiedApRep, Error> {
        self.crypto_policy
            .check_use(self.session_key.etype, Use::SessionKey)?;
        let ap_rep = decode_ap_rep(bytes).map_err(ap_rep_error)?;
        self.crypto_policy
            .check_use(ap_rep.enc_part.etype, Use::SessionKey)?;
        let enc_part = decrypt_ap_rep_enc_part(&ap_rep, &self.session_key).map_err(ap_rep_error)?;
        if let Some(subkey) = &enc_part.subkey {
            self.crypto_policy
                .check_use(subkey.r#type, Use::SessionKey)?;
        }
        let ctime = system_time_from_kerberos_time(&enc_part.ctime)?;
        let cusec = integer_to_u32("ap-rep.cusec", &enc_part.cusec)?;
        let authenticator_time = ctime
            .checked_add(Duration::from_micros(cusec.into()))
            .ok_or(Error::TimeOverflow)?;

        if ctime != self.authenticator_ctime || cusec != self.authenticator_cusec {
            return Err(Error::ApRepTimestampMismatch {
                expected: self.authenticator_time,
                actual: authenticator_time,
            });
        }

        Ok(VerifiedApRep {
            ctime,
            cusec,
            authenticator_time,
            subkey: enc_part.subkey.as_ref().map(encryption_key_from_rasn),
            sequence_number: enc_part.seq_number,
        })
    }
}

/// Validated SPNEGO service context.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct AcceptedContext {
    /// Validated AP-REQ details.
    pub ap_req: ValidatedApReq,
    /// First offered Kerberos OID, echoed as the response's `supportedMech`.
    pub selected_mechanism: ObjectIdentifier,
    /// Optimistic token OID, preserved as the inner AP-REP's `thisMech`.
    pub token_mechanism: ObjectIdentifier,
    /// Received DER `MechTypeList` authenticated by the initiator MIC, if present.
    /// The response helper signs these bytes, excluding the explicit `[0]` tag.
    pub mech_types_der: Option<Vec<u8>>,
}

impl AcceptedContext {
    /// Build a `WWW-Authenticate` header containing an AP-REP response token.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedEtype`] for an unknown session key encryption type,
    /// [`Error::Random`] when the confounder cannot be generated, and the errors of
    /// [`Self::ap_rep_response_header_with_confounder`].
    #[inline]
    pub fn ap_rep_response_header(&self, options: &ApRepOptions) -> Result<String, Error> {
        let etype = KerberosEtype::from_etype_id(self.ap_req.session_key.etype)
            .ok_or(Error::UnsupportedEtype(self.ap_req.session_key.etype))?;
        let mut confounder = vec![0; etype.confounder_len()];
        getrandom::fill(&mut confounder)?;
        self.ap_rep_response_header_with_confounder(&confounder, options)
    }

    /// Build a `WWW-Authenticate` header containing an AP-REP response token.
    ///
    /// With [`Self::mech_types_der`] set, the reply carries a reciprocal MIC. If
    /// `options` names no sequence number, the MIC uses the authenticator's and
    /// the AP-REP carries that same number.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Service`] when the AP-REP cannot be built or encrypted, and
    /// [`Error::InvalidOid`] when the response token cannot be encoded.
    #[inline]
    pub fn ap_rep_response_header_with_confounder(
        &self,
        confounder: &[u8],
        options: &ApRepOptions,
    ) -> Result<String, Error> {
        // A reciprocal MIC consumes an acceptor sequence number; the AP-REP must name it.
        let mic_options = self
            .mech_types_der
            .as_ref()
            .map(|_| negotiation::response_options(&self.ap_req, options));
        let reply_options = mic_options.as_ref().unwrap_or(options);
        let ap_rep = self
            .ap_req
            .build_ap_rep_with_confounder(confounder, reply_options)?;
        let mut krb5_token = Krb5MechToken::ap_rep(ap_rep);
        krb5_token.oid = self.token_mechanism.clone();
        let mut response =
            NegTokenResp::accept_completed().with_response_token(krb5_token.encode()?);
        response.supported_mech = Some(self.selected_mechanism.clone());
        if let Some(list) = &self.mech_types_der {
            response.mech_list_mic = Some(Zeroizing::new(negotiation::response_mic(
                list,
                &self.ap_req,
                reply_options,
            )?));
        }
        response_token_header(&response)
    }
}

/// Validate a SPNEGO HTTP `Authorization` header through a service validator.
///
/// Accepts either Kerberos token OID when Kerberos is offered. Both Kerberos
/// OIDs name the same mechanism: only a non-Kerberos first preference
/// requires a valid RFC 4121 `mechListMIC`; a supplied first-choice MIC must also
/// verify. MIC checks precede replay insertion and the response helper returns
/// a reciprocal MIC. Continuations requiring a previous offer, key or MIC phase
/// remain unsupported: this API only completes exchanges contained in one init.
/// The authenticator must include the RFC 4121 checksum and sequence number.
/// This no-channel-bindings API ignores initiator bindings and unknown extensions;
/// it checks delegation framing but does not import delegated credentials.
///
/// # Errors
///
/// Returns the errors of [`parse_negotiate_header`], [`Error::MissingMechListMic`]
/// for non-first selection without a MIC, [`Error::InvalidMechListMic`] for a bad
/// MIC, [`Error::NegotiationRequiresState`] for a continuation, and
/// [`Error::Service`] when the validator rejects the AP-REQ. Missing or malformed
/// GSS fields return [`Error::MissingAuthenticatorChecksum`],
/// [`Error::InvalidAuthenticatorChecksum`] or [`Error::MissingAuthenticatorSequence`].
#[inline]
pub fn accept_sec_context_header(
    validator: &mut Validator<'_>,
    header: &str,
) -> Result<AcceptedContext, Error> {
    let bytes = decode_negotiate_header(header)?;
    let token = Token::decode(&bytes)
        .or_else(|spnego_error| raw_krb5_negotiate_token(&bytes, spnego_error))?;
    let init = match token {
        Token::Init(init) => init,
        Token::Resp(response) => {
            if let Some(mech) = response.supported_mech
                && !mech.is_kerberos_mechanism()
            {
                return Err(Error::UnsupportedMechanism(mech));
            }
            return Err(Error::NegotiationRequiresState);
        }
    };
    let krb5 = negotiation::optimistic_token(&init)?;
    let selected_mechanism = init
        .mech_types
        .iter()
        .find(|oid| oid.is_kerberos_mechanism())
        .ok_or(Error::MissingMechTypes)?
        .clone();
    let mech_types_der = init
        .mech_list_mic
        .as_ref()
        .map(|_| negotiation::received_mech_types(&bytes))
        .transpose()?;
    let ap_req = validator.validate_ap_req_with_check(&krb5.message, |auth, session_key| {
        authenticator::validate(auth)?;
        if let (Some(mic), Some(list)) = (&init.mech_list_mic, &mech_types_der) {
            negotiation::verify_mic(mic, list, auth, session_key)?;
        }
        Ok::<(), Error>(())
    })?;
    Ok(AcceptedContext {
        ap_req,
        selected_mechanism,
        token_mechanism: krb5.oid,
        mech_types_der,
    })
}

/// Build a client SPNEGO initiator token from a TGS service-ticket session.
///
/// # Errors
///
/// Returns [`Error::TimeOverflow`] when the clock is before the Unix epoch, [`Error::Random`] when
/// the sequence number or the confounder cannot be generated, [`Error::UnsupportedEtype`] for an
/// unknown session key encryption type, and the errors of [`init_sec_context_with_confounder`].
#[inline]
pub fn init_sec_context(
    service_ticket: &TgsRepSession,
    mut options: InitiatorContextOptions,
) -> Result<InitiatorContext, Error> {
    let policy = options.crypto_policy.clone().unwrap_or_default();
    policy.check_use(service_ticket.session_key.etype, Use::SessionKey)?;
    if let Some(subkey) = &options.subkey {
        policy.check_use(subkey.etype, Use::SessionKey)?;
    }
    let (timestamp, cusec) = current_time()?;
    if options.sequence_number.is_none() {
        options.sequence_number = Some(random_sequence_number(getrandom::fill)?);
    }
    let etype = KerberosEtype::from_etype_id(service_ticket.session_key.etype)
        .ok_or(Error::UnsupportedEtype(service_ticket.session_key.etype))?;
    let mut confounder = vec![0; etype.confounder_len()];
    getrandom::fill(&mut confounder)?;
    init_sec_context_with_confounder(service_ticket, options, timestamp, cusec, &confounder)
}

/// Build a client SPNEGO initiator token with deterministic timestamp and confounder.
///
/// # Errors
///
/// Returns [`Error::Decode`], [`Error::Encode`], [`Error::InvalidKerberosString`],
/// [`Error::UnsupportedEtype`], [`Error::Crypto`], [`Error::Random`], [`Error::TimeOverflow`] or
/// [`Error::Client`] when the AP-REQ cannot be built, and [`Error::InvalidOid`] when the tokens
/// cannot be encoded. Returns [`Error::MissingAuthenticatorSequence`] when no
/// explicit sequence number is supplied. Returns [`Error::DelegationRequiresCredential`]
/// for delegation requests because this builder has no delegated-credential input.
#[inline]
pub fn init_sec_context_with_confounder(
    service_ticket: &TgsRepSession,
    options: InitiatorContextOptions,
    timestamp: SystemTime,
    cusec: u32,
    confounder: &[u8],
) -> Result<InitiatorContext, Error> {
    options
        .context_flags
        .iter()
        .all(|flag| flag & CONTEXT_FLAG_DELEG == 0)
        .ok_or(Error::DelegationRequiresCredential)?;
    let sequence_number = options
        .sequence_number
        .ok_or(Error::MissingAuthenticatorSequence)?;
    let mut ap_req_options = ApReq::new()
        .with_ap_option_bits(options.ap_option_bits)
        .with_checksum(Some(rasn_kerberos::Checksum {
            r#type: GSSAPI_CHECKSUM_TYPE,
            checksum: authenticator_checksum(&options.context_flags).into(),
        }))
        .with_subkey(options.subkey.clone())
        .with_sequence_number(Some(sequence_number));
    let crypto_policy = options.crypto_policy.unwrap_or_default();
    ap_req_options.crypto_policy = Some(crypto_policy.clone());
    let built_ap_req =
        build_ap_req_with_confounder(service_ticket, ap_req_options, timestamp, cusec, confounder)
            .map_err(client_error_to_spnego)?;
    let ap_req_der = Zeroizing::new(built_ap_req.der.clone());
    let krb5_token = Krb5MechToken::ap_req(ap_req_der.to_vec());
    let krb5_token_der = krb5_token.encode()?;
    let spnego_token = Token::Init(NegTokenInit::krb5(krb5_token_der));
    let header = Zeroizing::new(negotiate_header(&spnego_token)?);

    Ok(InitiatorContext {
        crypto_policy,
        ap_req: built_ap_req.message,
        ap_req_der,
        krb5_token,
        spnego_token,
        header,
        client: built_ap_req.client,
        service: built_ap_req.service,
        session_key: built_ap_req.session_key,
        authenticator_ctime: built_ap_req.authenticator_ctime,
        authenticator_cusec: built_ap_req.authenticator_cusec,
        authenticator_time: built_ap_req.authenticator_time,
        sequence_number: built_ap_req.sequence_number,
        context_flags: options.context_flags,
        initiator_subkey: options.subkey,
    })
}

/// Build only the HTTP `Authorization` header value for a SPNEGO initiator token.
///
/// # Errors
///
/// Returns the errors of [`init_sec_context`].
#[inline]
pub fn authorization_header(
    service_ticket: &TgsRepSession,
    options: InitiatorContextOptions,
) -> Result<String, Error> {
    Ok(init_sec_context(service_ticket, options)?
        .header
        .to_string())
}

/// Decode an HTTP `Negotiate` header into a SPNEGO token.
///
/// In addition to SPNEGO `NegTokenInit`/`NegTokenResp` values, this accepts
/// raw KRB5 mech tokens and wraps them in the equivalent SPNEGO shape.
/// Header values are limited to 64 KiB, including scheme and whitespace.
/// The byte limit is checked before scanning or allocating decoded token bytes.
///
/// # Errors
///
/// Returns [`Error::NegotiateHeaderTooLong`] when the header exceeds 64 KiB,
/// [`Error::InvalidNegotiateHeader`] when the scheme is not `Negotiate` or the token is
/// missing, [`Error::Base64`] when the token is not valid base64, and the errors of
/// [`Token::decode`] when the bytes are neither a SPNEGO token nor a raw KRB5 mech token.
#[inline]
pub fn parse_negotiate_header(header: &str) -> Result<Token, Error> {
    let bytes = decode_negotiate_header(header)?;
    Token::decode(&bytes).or_else(|spnego_error| raw_krb5_negotiate_token(&bytes, spnego_error))
}

/// Apply the HTTP size boundary before base64 decoding.
///
/// # Errors
/// Returns header size, scheme, missing-token or base64 decoding errors.
fn decode_negotiate_header(header: &str) -> Result<Vec<u8>, Error> {
    if header.len() > MAX_NEGOTIATE_HEADER_LEN {
        return Err(Error::NegotiateHeaderTooLong {
            maximum: MAX_NEGOTIATE_HEADER_LEN,
            actual: header.len(),
        });
    }
    let mut parts = header.splitn(2, char::is_whitespace);
    let scheme = parts.next().unwrap_or_default();
    let encoded = parts.next().ok_or(Error::InvalidNegotiateHeader)?;
    if !scheme.eq_ignore_ascii_case(HTTP_NEGOTIATE) || encoded.trim().is_empty() {
        return Err(Error::InvalidNegotiateHeader);
    }
    general_purpose::STANDARD
        .decode(encoded.trim())
        .map_err(Error::Base64)
}

/// Encode a SPNEGO token as an HTTP `Negotiate` header value.
///
/// # Errors
///
/// Returns the errors of [`Token::encode`].
#[inline]
pub fn negotiate_header(token: &Token) -> Result<String, Error> {
    Ok(format!(
        "{HTTP_NEGOTIATE} {}",
        general_purpose::STANDARD.encode(token.encode()?)
    ))
}

/// Wrap a raw KRB5 mech token in the equivalent SPNEGO shape: an AP-REQ becomes a `NegTokenInit`,
/// an AP-REP an `accept-completed` response and a KRB-ERROR a rejection.
///
/// # Errors
///
/// Returns `spnego_error` unchanged when `bytes` is not a KRB5 mech token.
fn raw_krb5_negotiate_token(bytes: &[u8], spnego_error: Error) -> Result<Token, Error> {
    let Ok(krb5) = Krb5MechToken::decode(bytes) else {
        return Err(spnego_error);
    };
    match krb5.token_id {
        Krb5TokenId::ApReq => {
            let mut init = NegTokenInit::krb5(bytes.to_vec());
            init.mech_types = vec![krb5.oid];
            Ok(Token::Init(init))
        }
        Krb5TokenId::ApRep => Ok(Token::Resp(
            NegTokenResp::accept_completed().with_response_token(bytes.to_vec()),
        )),
        Krb5TokenId::KrbError => Ok(Token::Resp(
            NegTokenResp::reject().with_response_token(bytes.to_vec()),
        )),
    }
}

#[must_use]
/// Header value used to start SPNEGO negotiation.
#[inline]
pub const fn challenge_header() -> &'static str {
    HTTP_NEGOTIATE
}

/// Header value for a Kerberos `accept-completed` SPNEGO response.
///
/// # Errors
///
/// Returns the errors of [`NegTokenResp::encode`].
#[inline]
pub fn accept_completed_header() -> Result<String, Error> {
    response_token_header(&NegTokenResp::accept_completed())
}

/// Header value for a Kerberos `accept-incomplete` SPNEGO response.
///
/// # Errors
///
/// Returns the errors of [`NegTokenResp::encode`].
#[inline]
pub fn accept_incomplete_krb5_header() -> Result<String, Error> {
    response_token_header(&NegTokenResp::accept_incomplete_krb5())
}

/// Header value for a SPNEGO rejection response.
///
/// # Errors
///
/// Returns the errors of [`NegTokenResp::encode`].
#[inline]
pub fn reject_header() -> Result<String, Error> {
    response_token_header(&NegTokenResp::reject())
}

/// Encode a `NegTokenResp` as an HTTP `Negotiate` header value.
///
/// # Errors
///
/// Returns the errors of [`NegTokenResp::encode`].
fn response_token_header(token: &NegTokenResp) -> Result<String, Error> {
    Ok(format!(
        "{HTTP_NEGOTIATE} {}",
        general_purpose::STANDARD.encode(token.encode()?)
    ))
}

#[must_use]
/// Create a SPNEGO authenticator checksum buffer for GSS context flags.
///
/// This low-level helper returns only the 24-byte prefix and ORs all flag masks.
/// With delegation set, it is not a complete checksum: the caller must append
/// RFC 4121 DlgOpt=1, the little-endian credential length, and an encrypted KRB-CRED.
/// Checked context builders reject delegation because they have no credential input.
#[inline]
pub fn authenticator_checksum(flags: &[u32]) -> Vec<u8> {
    let context_flags = flags.iter().fold(0_u32, |merged, flag| merged | *flag);
    let mut checksum = Vec::with_capacity(24);
    checksum.extend_from_slice(&16_u32.to_le_bytes());
    checksum.extend_from_slice(&[0; 16]);
    checksum.extend_from_slice(&context_flags.to_le_bytes());
    checksum
}

/// Check the token ID of a MIC or Wrap token.
///
/// # Errors
///
/// Returns [`Error::InvalidGssTokenId`] when `actual` differs from `expected`.
fn validate_gss_token_id(actual: [u8; 2], expected: [u8; 2]) -> Result<(), Error> {
    if actual != expected {
        return Err(Error::InvalidGssTokenId { expected, actual });
    }
    Ok(())
}

/// Check that the acceptor flag matches the direction the caller expects.
///
/// # Errors
///
/// Returns [`Error::UnexpectedGssTokenSender`] on a mismatch.
const fn validate_gss_sender(flags: u8, expect_from_acceptor: bool) -> Result<(), Error> {
    let actual_from_acceptor = flags & GSS_TOKEN_FLAG_SENT_BY_ACCEPTOR != 0;
    if actual_from_acceptor != expect_from_acceptor {
        return Err(Error::UnexpectedGssTokenSender {
            expected_from_acceptor: expect_from_acceptor,
            actual_from_acceptor,
        });
    }
    Ok(())
}

/// The Wrap token header that an unsealed token's checksum covers, with zero extra and rotation
/// counts.
fn wrap_checksum_header(flags: u8, snd_seq_num: u64) -> Vec<u8> {
    wrap_header(flags, 0, 0, snd_seq_num)
}

/// Build a 16-byte RFC 4121 Wrap token header.
fn wrap_header(flags: u8, ec: u16, rrc: u16, snd_seq_num: u64) -> Vec<u8> {
    let mut header = Vec::with_capacity(GSS_WRAP_HEADER_LEN);
    header.extend_from_slice(&TOK_ID_GSS_WRAP);
    header.push(flags);
    header.push(GSS_WRAP_FILLER);
    header.extend_from_slice(&ec.to_be_bytes());
    header.extend_from_slice(&rrc.to_be_bytes());
    header.extend_from_slice(&snd_seq_num.to_be_bytes());
    header
}

/// Rotate `bytes` right by `count` positions, modulo its length.
fn rotate_right(bytes: &[u8], count: usize) -> Vec<u8> {
    let mut out = bytes.to_vec();
    if let Some(shift) = count.checked_rem(bytes.len()) {
        out.rotate_right(shift);
    }
    out
}

/// Rotate `bytes` left by `count` positions, modulo its length.
fn rotate_left(bytes: &[u8], count: usize) -> Vec<u8> {
    let mut out = bytes.to_vec();
    if let Some(shift) = count.checked_rem(bytes.len()) {
        out.rotate_left(shift);
    }
    out
}

use crate::error::Spnego as Error;

/// Enforce DER BIT STRING content rules at both reqFlags boundaries.
///
/// # Errors
/// Returns `InvalidReqFlags` for missing count bytes or invalid padding.
fn validate_req_flags(bytes: &[u8]) -> Result<(), Error> {
    let Some((&unused, bits)) = bytes.split_first() else {
        return Err(Error::InvalidReqFlags);
    };
    (unused <= 7
        && (unused == 0
            || bits
                .last()
                .is_some_and(|last| last & (1_u8 << unused).wrapping_sub(1) == 0)))
    .ok_or(Error::InvalidReqFlags)
}

/// Map an AP-REP processing error onto the SPNEGO error type.
fn ap_rep_error(error: error::ApRep) -> Error {
    match error {
        error::ApRep::Decode { target, message } => Error::Decode { target, message },
        error::ApRep::Encode { target, message } => Error::Encode { target, message },
        error::ApRep::InvalidMessage {
            field,
            expected,
            actual,
        } => Error::InvalidMessage {
            field,
            expected,
            actual,
        },
        error::ApRep::UnsupportedEtype(etype) => Error::UnsupportedEtype(etype),
        error::ApRep::KeyEtypeMismatch {
            key_etype,
            encrypted_data_etype,
        } => Error::ApRepKeyEtypeMismatch {
            key_etype,
            encrypted_data_etype,
        },
        error::ApRep::Random(source) => Error::Random(source),
        error::ApRep::Crypto(source) => Error::Crypto(source),
    }
}

/// Convert an ASN.1 INTEGER field to `u32`.
///
/// # Errors
///
/// Returns [`Error::IntegerOutOfRange`] when the value is negative or above `u32::MAX`.
fn integer_to_u32(field: &'static str, value: &Integer) -> Result<u32, Error> {
    value
        .to_string()
        .parse::<u32>()
        .map_err(|_out_of_range| Error::IntegerOutOfRange {
            field,
            value: value.to_string(),
        })
}

/// Copy an ASN.1 encryption key into the crate's key type.
fn encryption_key_from_rasn(value: &rasn_kerberos::EncryptionKey) -> EncryptionKey {
    EncryptionKey {
        etype: value.r#type,
        value: value.value.as_ref().to_vec(),
    }
}

/// Map an AP-REQ construction error onto the SPNEGO error type. Variants without a SPNEGO
/// counterpart become [`Error::Client`] with their typed source.
fn client_error_to_spnego(error: error::Client) -> Error {
    if let error::Client::Decode { target, message } = error {
        return Error::Decode { target, message };
    }
    if let error::Client::Encode { target, message } = error {
        return Error::Encode { target, message };
    }
    if let error::Client::InvalidString(source) = error {
        return Error::InvalidKerberosString(source.to_string());
    }
    if let error::Client::InvalidKerberosString(message) = error {
        return Error::InvalidKerberosString(message);
    }
    if let error::Client::UnsupportedEtype(etype) = error {
        return Error::UnsupportedEtype(etype);
    }
    if let error::Client::Crypto(source) = error {
        return Error::Crypto(source);
    }
    if let error::Client::Random(source) = error {
        return Error::Random(source);
    }
    if matches!(error, error::Client::TimeOverflow) {
        return Error::TimeOverflow;
    }
    Error::Client(Box::new(error))
}

/// The current time split into whole seconds and microseconds, as a Kerberos authenticator carries
/// it.
///
/// # Errors
///
/// Returns [`Error::TimeOverflow`] when the clock is before the Unix epoch.
fn current_time() -> Result<(SystemTime, u32), Error> {
    let now = SystemTime::now();
    let elapsed = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_before_epoch| Error::TimeOverflow)?;
    let timestamp = UNIX_EPOCH
        .checked_add(Duration::from_secs(elapsed.as_secs()))
        .ok_or(Error::TimeOverflow)?;
    Ok((timestamp, elapsed.subsec_micros()))
}

/// Generate a random 30-bit initial sequence number, as gokrb5 does.
///
/// # Errors
///
/// Returns [`Error::Random`] when the system random source fails.
fn random_sequence_number<F>(fill: F) -> Result<u32, Error>
where
    F: FnOnce(&mut [u8]) -> Result<(), getrandom::Error>,
{
    let mut bytes = [0; 4];
    fill(&mut bytes)?;
    Ok(u32::from_be_bytes(bytes) & 0x3fff_ffff)
}

/// Deterministic entropy fixtures for initial sequence range enforcement.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod sequence_tests;

/// Convert a Kerberos time to `SystemTime`.
///
/// # Errors
///
/// Returns [`Error::TimeOverflow`] for fractions or times outside the `SystemTime` range.
fn system_time_from_kerberos_time(time: &rasn_kerberos::KerberosTime) -> Result<SystemTime, Error> {
    use crate::client::time::from_kerberos;

    from_kerberos(time).ok_or(Error::TimeOverflow)
}

/// Decode the `NegotiationToken` CHOICE from its outer element.
///
/// # Errors
///
/// Returns [`Error::UnexpectedTag`] for a tag other than `[0]` or `[1]`, and the errors of the
/// `NegTokenInit` or `NegTokenResp` decoder.
fn decode_negotiation_choice(choice: Tlv<'_>) -> Result<NegotiationToken, Error> {
    match choice.tag() {
        TAG_CONTEXT_0 => Ok(NegotiationToken::Init(decode_neg_token_init(
            choice.value(),
        )?)),
        TAG_CONTEXT_1 => Ok(NegotiationToken::Resp(decode_neg_token_resp(
            choice.value(),
        )?)),
        actual => Err(Error::UnexpectedTag {
            expected: TAG_CONTEXT_0,
            actual,
        }),
    }
}

/// Decode the content of a `NegTokenInit` choice.
///
/// # Errors
///
/// Returns DER errors ([`Error::TruncatedDer`], [`Error::HighTagNumber`],
/// [`Error::IndefiniteLength`], [`Error::LengthExceedsInput`], [`Error::TrailingData`]) for
/// malformed input, [`Error::UnexpectedTag`] for an unknown field, [`Error::InvalidOidEncoding`] or
/// [`Error::InvalidOid`] for a malformed mechanism OID, and [`Error::MissingMechTypes`] when the
/// mechanism list is absent or empty.
fn decode_neg_token_init(bytes: &[u8]) -> Result<NegTokenInit, Error> {
    let sequence = read_single_tlv(bytes, TAG_SEQUENCE)?;
    let mut fields = DerReader::new(sequence.value());
    let mut offered_mechs = None;
    let mut previous_tag = None;
    let mut req_flags = None;
    let mut mech_token = None;
    let mut mech_list_mic = None;

    while !fields.remaining().is_empty() {
        let field = fields.read_tlv()?;
        if previous_tag.is_some_and(|previous| previous >= field.tag()) {
            return Err(Error::InvalidFieldOrder);
        }
        previous_tag = Some(field.tag());
        match field.tag() {
            TAG_CONTEXT_0 => {
                let mech_list = read_single_tlv(field.value(), TAG_SEQUENCE)?;
                let mut oid_reader = DerReader::new(mech_list.value());
                let mut oids = Vec::new();
                while !oid_reader.remaining().is_empty() {
                    oids.push(decode_oid_tlv(oid_reader.read_tlv()?)?);
                }
                offered_mechs = Some(oids);
            }
            TAG_CONTEXT_1 => {
                req_flags = Some(
                    read_single_tlv(field.value(), TAG_BIT_STRING)?
                        .value()
                        .to_vec(),
                );
            }
            TAG_CONTEXT_2 => {
                mech_token = Some(
                    read_single_tlv(field.value(), TAG_OCTET_STRING)?
                        .value()
                        .to_vec(),
                );
            }
            TAG_CONTEXT_3 => {
                mech_list_mic = Some(
                    read_single_tlv(field.value(), TAG_OCTET_STRING)?
                        .value()
                        .to_vec(),
                );
            }
            0xa4..=0xbe => {}
            actual => {
                return Err(Error::UnexpectedTag {
                    expected: TAG_CONTEXT_0,
                    actual,
                });
            }
        }
    }

    if let Some(flags) = &req_flags {
        validate_req_flags(flags)?;
    }
    let mech_types = offered_mechs
        .filter(|oids| !oids.is_empty())
        .ok_or(Error::MissingMechTypes)?;
    Ok(NegTokenInit {
        mech_types,
        req_flags,
        mech_token: mech_token.map(Zeroizing::new),
        mech_list_mic: mech_list_mic.map(Zeroizing::new),
    })
}

/// Decode the content of a `NegTokenResp` choice.
///
/// # Errors
///
/// Returns DER errors ([`Error::TruncatedDer`], [`Error::HighTagNumber`],
/// [`Error::IndefiniteLength`], [`Error::LengthExceedsInput`], [`Error::TrailingData`]) for
/// malformed input, [`Error::UnexpectedTag`] for an unknown field, [`Error::InvalidInteger`] or
/// [`Error::InvalidNegState`] for a bad negotiation state, and [`Error::InvalidOidEncoding`] or
/// [`Error::InvalidOid`] for a malformed mechanism OID.
fn decode_neg_token_resp(bytes: &[u8]) -> Result<NegTokenResp, Error> {
    let sequence = read_single_tlv(bytes, TAG_SEQUENCE)?;
    let mut fields = DerReader::new(sequence.value());
    let mut neg_state = None;
    let mut previous_tag = None;
    let mut supported_mech = None;
    let mut response_token = None;
    let mut mech_list_mic = None;

    while !fields.remaining().is_empty() {
        let field = fields.read_tlv()?;
        if previous_tag.is_some_and(|previous| previous >= field.tag()) {
            return Err(Error::InvalidFieldOrder);
        }
        previous_tag = Some(field.tag());
        match field.tag() {
            TAG_CONTEXT_0 => {
                let enumerated = read_single_tlv(field.value(), TAG_ENUMERATED)?;
                neg_state = Some(NegState::from_value(decode_u32(enumerated.value())?)?);
            }
            TAG_CONTEXT_1 => {
                supported_mech = Some(decode_oid_tlv(read_single_tlv(
                    field.value(),
                    TAG_OBJECT_IDENTIFIER,
                )?)?);
            }
            TAG_CONTEXT_2 => {
                response_token = Some(
                    read_single_tlv(field.value(), TAG_OCTET_STRING)?
                        .value()
                        .to_vec(),
                );
            }
            TAG_CONTEXT_3 => {
                mech_list_mic = Some(
                    read_single_tlv(field.value(), TAG_OCTET_STRING)?
                        .value()
                        .to_vec(),
                );
            }
            0xa4..=0xbe => {}
            actual => {
                return Err(Error::UnexpectedTag {
                    expected: TAG_CONTEXT_0,
                    actual,
                });
            }
        }
    }

    Ok(NegTokenResp {
        neg_state,
        supported_mech,
        response_token: response_token.map(Zeroizing::new),
        mech_list_mic: mech_list_mic.map(Zeroizing::new),
    })
}

/// Require at least one offered mechanism to be Kerberos.
///
/// # Errors
///
/// Returns [`Error::MissingMechTypes`] for an empty list, and [`Error::UnsupportedMechanism`] with
/// the first listed OID when none is Kerberos 5.
fn ensure_kerberos_mechanism(mech_types: &[ObjectIdentifier]) -> Result<(), Error> {
    let Some(first) = mech_types.first() else {
        return Err(Error::MissingMechTypes);
    };

    if mech_types
        .iter()
        .any(ObjectIdentifier::is_kerberos_mechanism)
    {
        Ok(())
    } else {
        Err(Error::UnsupportedMechanism(first.clone()))
    }
}

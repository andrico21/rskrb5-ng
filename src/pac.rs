//! Microsoft Privilege Attribute Certificate (PAC) parsing.
//!
//! This module covers the PAC surface that gokrb5 consumes on the service
//! path: the PAC container, `KERB_VALIDATION_INFO`, client information,
//! UPN/DNS information, PAC signatures, and AES server checksum verification.

use alloc::fmt;
use core::time::Duration;
use std::{
    collections::HashSet,
    time::{SystemTime, UNIX_EPOCH},
};

use compcol::{
    Algorithm, lznt1::Lznt1, vec::decompress_to_vec_capped, xpress::Xpress,
    xpress_huffman::XpressHuffman,
};
use zeroize::{Zeroize as _, Zeroizing};

use crate::{
    crypto::{KerberosEtype, selection},
    keytab::EncryptionKey,
};

#[cfg(feature = "messages")]
mod authorization;
mod credential_secrets;
mod ndr;
mod reader;
/// Redacted, erased validation-info session keys.
pub mod session_key;

#[cfg(test)]
/// PAC mutation regression tests.
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "pac/mutation_tests.rs"]
mod mutation_tests;

use self::{
    ndr::{
        RpcUnicodeStringDescriptor, ensure_zero_trailing, read_counted_supplemental_credentials,
        read_deferred_claims_arrays, read_deferred_domain_group_memberships,
        read_deferred_group_memberships, read_deferred_rpc_unicode_strings, read_deferred_sid,
        read_deferred_sid_and_attributes, read_deferred_u8_array, read_deferred_unicode_string,
        read_ndr_u16, read_ndr_u32, read_ndr_wrapper,
    },
    reader::Reader,
};

/// `AD-IF-RELEVANT` authorization-data type.
pub const AD_IF_RELEVANT: i32 = 1;
/// Microsoft `AD-WIN2K-PAC` authorization-data type.
pub const AD_WIN2K_PAC: i32 = 128;

/// `KERB_VALIDATION_INFO` PAC buffer type.
pub const INFO_TYPE_KERB_VALIDATION_INFO: u32 = 1;
/// PAC credentials buffer type.
pub const INFO_TYPE_CREDENTIALS: u32 = 2;
/// PAC server checksum buffer type.
pub const INFO_TYPE_PAC_SERVER_SIGNATURE_DATA: u32 = 6;
/// PAC KDC checksum buffer type.
pub const INFO_TYPE_PAC_KDC_SIGNATURE_DATA: u32 = 7;
/// PAC client info buffer type.
pub const INFO_TYPE_PAC_CLIENT_INFO: u32 = 10;
/// PAC S4U delegation info buffer type.
pub const INFO_TYPE_S4U_DELEGATION_INFO: u32 = 11;
/// PAC UPN/DNS info buffer type.
pub const INFO_TYPE_UPN_DNS_INFO: u32 = 12;
/// PAC client claims info buffer type.
pub const INFO_TYPE_PAC_CLIENT_CLAIMS_INFO: u32 = 13;
/// PAC device info buffer type.
pub const INFO_TYPE_PAC_DEVICE_INFO: u32 = 14;
/// PAC device claims info buffer type.
pub const INFO_TYPE_PAC_DEVICE_CLAIMS_INFO: u32 = 15;

/// Microsoft unsigned HMAC-MD5 PAC checksum type.
pub const CHECKSUM_HMAC_MD5_UNSIGNED: u32 = 0xffff_ff76;
/// Kerberos AES128 HMAC-SHA1-96 checksum type.
pub const CHECKSUM_HMAC_SHA1_96_AES128: u32 = 15;
/// Kerberos AES256 HMAC-SHA1-96 checksum type.
pub const CHECKSUM_HMAC_SHA1_96_AES256: u32 = 16;
/// Kerberos AES128 SHA2 checksum type.
pub const CHECKSUM_HMAC_SHA256_128_AES128: u32 = 19;
/// Kerberos AES256 SHA2 checksum type.
pub const CHECKSUM_HMAC_SHA384_192_AES256: u32 = 20;

/// Claims data is not compressed.
pub const CLAIMS_COMPRESSION_FORMAT_NONE: u16 = 0;
/// Claims data uses LZNT1 compression.
pub const CLAIMS_COMPRESSION_FORMAT_LZNT1: u16 = 2;
/// Claims data uses XPRESS compression.
pub const CLAIMS_COMPRESSION_FORMAT_XPRESS: u16 = 3;
/// Claims data uses XPRESS Huffman compression.
pub const CLAIMS_COMPRESSION_FORMAT_XPRESS_HUFF: u16 = 4;

/// Claims originated in Active Directory.
pub const CLAIMS_SOURCE_TYPE_AD: u16 = 1;

/// Signed 64-bit integer claim value type.
pub const CLAIM_TYPE_ID_INT64: u16 = 1;
/// Unsigned 64-bit integer claim value type.
pub const CLAIM_TYPE_ID_UINT64: u16 = 2;
/// UTF-16 string claim value type.
pub const CLAIM_TYPE_ID_STRING: u16 = 3;
/// Boolean claim value type.
pub const CLAIM_TYPE_ID_BOOLEAN: u16 = 6;

/// Byte length of the PAC header (`cBuffers` and `Version`).
const PAC_HEADER_LEN: usize = 8;
/// Byte length of one `PAC_INFO_BUFFER` table entry.
const PAC_INFO_BUFFER_LEN: usize = 16;
/// Byte length of the `SignatureType` field that precedes a PAC signature.
const PAC_SIGNATURE_TYPE_LEN: usize = 4;
/// Key usage of the PAC server checksum (MS-PAC 2.8.1).
const PAC_SERVER_CHECKSUM_KEY_USAGE: u32 = 17;
/// Key usage of the encrypted `PAC_CREDENTIAL_DATA` (MS-PAC 2.6.1).
const PAC_CREDENTIALS_KEY_USAGE: u32 = 16;
/// Windows `FILETIME` ticks (100 ns intervals) per second.
const WINDOWS_TICKS_PER_SECOND: u64 = 10_000_000;
/// Nanoseconds per Windows `FILETIME` tick.
const NANOS_PER_WINDOWS_TICK: u64 = 100;
/// Seconds from 1601-01-01 (the `FILETIME` epoch) to 1970-01-01 UTC.
const WINDOWS_TO_UNIX_SECONDS: u64 = 11_644_473_600;

/// NTLM supplemental credential LM OWF numeric mask.
pub const NTLM_SUPPLEMENTAL_CRED_LMOWF: u32 = 1;
/// NTLM supplemental credential NT OWF numeric mask.
pub const NTLM_SUPPLEMENTAL_CRED_NTOWF: u32 = 2;

/// Parsed PAC container and selected processed buffers.
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub struct Pac {
    /// Number of PAC info buffers.
    c_buffers: u32,
    /// PAC version; parsing accepts only zero.
    version: u32,
    /// PAC info buffer table.
    buffers: Vec<InfoBuffer>,
    /// Original PAC bytes.
    data: Zeroizing<Vec<u8>>,
    /// PAC bytes with server and KDC signature bytes zeroed.
    zero_signature_data: Zeroizing<Vec<u8>>,
    /// Parsed `KERB_VALIDATION_INFO`, if present and processed.
    kerb_validation_info: Option<KerbValidationInfo>,
    /// Parsed server checksum, if present and processed.
    server_checksum: Option<SignatureData>,
    /// Parsed KDC checksum, if present and processed.
    kdc_checksum: Option<SignatureData>,
    /// Parsed credentials info, if present and processed.
    ///
    /// The encrypted nested credential data still requires the AS reply key.
    credentials_info: Option<CredentialsInfo>,
    /// Parsed client info, if present and processed.
    client_info: Option<ClientInfo>,
    /// Parsed UPN/DNS info, if present and processed.
    upn_dns_info: Option<UpnDnsInfo>,
    /// Parsed S4U delegation info, if present and processed.
    s4u_delegation_info: Option<S4UDelegationInfo>,
    /// Parsed device info, if present and processed.
    device_info: Option<DeviceInfo>,
    /// Parsed client claims info, if present and processed.
    client_claims_info: Option<ClaimsInfo>,
    /// Parsed device claims info, if present and processed.
    device_claims_info: Option<ClaimsInfo>,
}

impl Pac {
    /// Return the buffer count.
    #[inline]
    #[must_use]
    pub const fn c_buffers(&self) -> u32 {
        self.c_buffers
    }
    /// Return the PAC version.
    #[inline]
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }
    /// Borrow the buffer descriptors.
    #[inline]
    #[must_use]
    pub fn buffers(&self) -> &[InfoBuffer] {
        &self.buffers
    }
    /// Borrow raw PAC bytes; callers must erase copies.
    #[inline]
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }
    /// Borrow the signature-cleared PAC bytes.
    #[inline]
    #[must_use]
    pub fn zero_signature_data(&self) -> &[u8] {
        &self.zero_signature_data
    }
    /// Borrow parsed validation information.
    #[inline]
    #[must_use]
    pub const fn kerb_validation_info(&self) -> Option<&KerbValidationInfo> {
        self.kerb_validation_info.as_ref()
    }
    /// Borrow the server signature.
    #[inline]
    #[must_use]
    pub const fn server_checksum(&self) -> Option<&SignatureData> {
        self.server_checksum.as_ref()
    }
    /// Borrow the KDC signature.
    #[inline]
    #[must_use]
    pub const fn kdc_checksum(&self) -> Option<&SignatureData> {
        self.kdc_checksum.as_ref()
    }
    /// Borrow encrypted credentials.
    #[inline]
    #[must_use]
    pub const fn credentials_info(&self) -> Option<&CredentialsInfo> {
        self.credentials_info.as_ref()
    }
    /// Borrow client metadata.
    #[inline]
    #[must_use]
    pub const fn client_info(&self) -> Option<&ClientInfo> {
        self.client_info.as_ref()
    }
    /// Borrow UPN/DNS metadata.
    #[inline]
    #[must_use]
    pub const fn upn_dns_info(&self) -> Option<&UpnDnsInfo> {
        self.upn_dns_info.as_ref()
    }
    /// Borrow delegation metadata.
    #[inline]
    #[must_use]
    pub const fn s4u_delegation_info(&self) -> Option<&S4UDelegationInfo> {
        self.s4u_delegation_info.as_ref()
    }
    /// Borrow device metadata.
    #[inline]
    #[must_use]
    pub const fn device_info(&self) -> Option<&DeviceInfo> {
        self.device_info.as_ref()
    }
    /// Borrow client claims.
    #[inline]
    #[must_use]
    pub const fn client_claims_info(&self) -> Option<&ClaimsInfo> {
        self.client_claims_info.as_ref()
    }
    /// Borrow device claims.
    #[inline]
    #[must_use]
    pub const fn device_claims_info(&self) -> Option<&ClaimsInfo> {
        self.device_claims_info.as_ref()
    }
    /// Parse the PAC header and info buffer table.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`] or [`Error::TooShort`] when the header or buffer table is
    /// cut short, [`Error::LengthOverflow`] when the table size overflows `usize`, and
    /// [`Error::BufferOffsetNotAligned`] or [`Error::BufferOutOfBounds`] for an invalid buffer
    /// entry. Returns [`Error::InvalidPacVersion`] when the format version is nonzero.
    #[inline]
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        let c_buffers = reader.read_u32()?;
        let version = reader.read_u32()?;
        (version == 0).ok_or(Error::InvalidPacVersion(version))?;
        let buffer_count =
            usize::try_from(c_buffers).map_err(|_out_of_range| Error::LengthOverflow)?;
        let table_len = buffer_count
            .checked_mul(PAC_INFO_BUFFER_LEN)
            .ok_or(Error::LengthOverflow)?;
        let minimum = PAC_HEADER_LEN
            .checked_add(table_len)
            .ok_or(Error::LengthOverflow)?;
        if bytes.len() < minimum {
            return Err(Error::TooShort {
                target: "PAC info buffer table",
                minimum,
                actual: bytes.len(),
            });
        }

        let mut buffers = Vec::with_capacity(buffer_count);
        for _ in 0..c_buffers {
            buffers.push(InfoBuffer {
                ul_type: reader.read_u32()?,
                cb_buffer_size: reader.read_u32()?,
                offset: reader.read_u64()?,
            });
        }

        for buffer in &buffers {
            buffer.validate(bytes.len())?;
        }

        Ok(Self {
            c_buffers,
            version,
            buffers,
            data: Zeroizing::new(bytes.to_vec()),
            zero_signature_data: Zeroizing::new(bytes.to_vec()),
            kerb_validation_info: None,
            server_checksum: None,
            kdc_checksum: None,
            credentials_info: None,
            client_info: None,
            upn_dns_info: None,
            s4u_delegation_info: None,
            device_info: None,
            client_claims_info: None,
            device_claims_info: None,
        })
    }

    /// Parse the PAC header and process recognized PAC info buffers.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Pac::parse`] and [`Pac::process_buffers`].
    #[inline]
    pub fn parse_and_process(bytes: &[u8]) -> Result<Self, Error> {
        let mut pac = Self::parse(bytes)?;
        pac.process_buffers()?;
        Ok(pac)
    }

    /// Process recognized PAC info buffers.
    ///
    /// Unknown and currently unsupported PAC buffers are left in the raw buffer
    /// table and skipped here.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] when a recognized buffer lies outside the PAC or fails to parse, or
    /// when a signature buffer cannot be zeroed in place.
    #[inline]
    pub fn process_buffers(&mut self) -> Result<(), Error> {
        for buffer in &self.buffers {
            let bytes = buffer.slice(&self.data)?;
            match buffer.ul_type {
                INFO_TYPE_KERB_VALIDATION_INFO if self.kerb_validation_info.is_none() => {
                    self.kerb_validation_info = Some(KerbValidationInfo::parse(bytes)?);
                }
                INFO_TYPE_PAC_SERVER_SIGNATURE_DATA if self.server_checksum.is_none() => {
                    let checksum = SignatureData::parse(bytes)?;
                    buffer.copy_zeroed_signature(&mut self.zero_signature_data, &checksum)?;
                    self.server_checksum = Some(checksum);
                }
                INFO_TYPE_PAC_KDC_SIGNATURE_DATA if self.kdc_checksum.is_none() => {
                    let checksum = SignatureData::parse(bytes)?;
                    buffer.copy_zeroed_signature(&mut self.zero_signature_data, &checksum)?;
                    self.kdc_checksum = Some(checksum);
                }
                INFO_TYPE_CREDENTIALS if self.credentials_info.is_none() => {
                    self.credentials_info = Some(CredentialsInfo::parse(bytes)?);
                }
                INFO_TYPE_PAC_CLIENT_INFO if self.client_info.is_none() => {
                    self.client_info = Some(ClientInfo::parse(bytes)?);
                }
                INFO_TYPE_UPN_DNS_INFO if self.upn_dns_info.is_none() => {
                    self.upn_dns_info = Some(UpnDnsInfo::parse(bytes)?);
                }
                INFO_TYPE_S4U_DELEGATION_INFO if self.s4u_delegation_info.is_none() => {
                    self.s4u_delegation_info = Some(S4UDelegationInfo::parse(bytes)?);
                }
                INFO_TYPE_PAC_DEVICE_INFO if self.device_info.is_none() => {
                    self.device_info = Some(DeviceInfo::parse(bytes)?);
                }
                INFO_TYPE_PAC_CLIENT_CLAIMS_INFO if self.client_claims_info.is_none() => {
                    self.client_claims_info = Some(ClaimsInfo::parse(bytes)?);
                }
                INFO_TYPE_PAC_DEVICE_CLAIMS_INFO if self.device_claims_info.is_none() => {
                    self.device_claims_info = Some(ClaimsInfo::parse(bytes)?);
                }
                _ => {}
            }
        }

        Ok(())
    }

    /// Return AD credential attributes derived from `KERB_VALIDATION_INFO`, when present.
    #[inline]
    pub fn ad_credentials(&self) -> Option<AdCredentials> {
        self.kerb_validation_info
            .as_ref()
            .map(KerbValidationInfo::ad_credentials)
    }

    /// Verify required service-side PAC buffers and the server checksum.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MissingRequiredBuffer`] when a required service buffer is absent,
    /// [`Error::UnsupportedChecksumType`] for an unknown server checksum type, and
    /// [`Error::ServerChecksumVerificationFailed`] when the server checksum does not verify.
    #[inline]
    pub fn verify(&self, key: &EncryptionKey) -> Result<(), Error> {
        self.require_service_buffers()?;
        if !self.verify_server_checksum(key)? {
            return Err(Error::ServerChecksumVerificationFailed);
        }
        Ok(())
    }

    /// Verify the server checksum over the zero-signature PAC bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MissingRequiredBuffer`] when the server checksum buffer is absent and
    /// [`Error::UnsupportedChecksumType`] for an unknown checksum type.
    #[inline]
    pub fn verify_server_checksum(&self, key: &EncryptionKey) -> Result<bool, Error> {
        selection::reject_enctype(key.etype())?;
        let checksum = self
            .server_checksum
            .as_ref()
            .ok_or(Error::MissingRequiredBuffer("ServerChecksum"))?;
        if let Ok(id) = i32::try_from(checksum.signature_type) {
            selection::reject_checksum(id)?;
        }
        let etype = kerberos_etype_for_checksum_type(checksum.signature_type)
            .ok_or(Error::UnsupportedChecksumType(checksum.signature_type))?;
        if key.etype() != etype.etype_id() {
            return Ok(false);
        }
        Ok(etype.verify_checksum(
            key.value(),
            &self.zero_signature_data,
            &checksum.signature,
            PAC_SERVER_CHECKSUM_KEY_USAGE,
        ))
    }

    #[must_use]
    /// Return an info buffer by type.
    #[inline]
    pub fn buffer(&self, ul_type: u32) -> Option<&InfoBuffer> {
        self.buffers.iter().find(|buffer| buffer.ul_type == ul_type)
    }

    /// Return the raw bytes for an info buffer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BufferOffsetNotAligned`], [`Error::LengthOverflow`] or
    /// [`Error::BufferOutOfBounds`] when `buffer` does not describe a range inside the PAC.
    #[inline]
    pub fn buffer_bytes(&self, buffer: &InfoBuffer) -> Result<&[u8], Error> {
        buffer.slice(&self.data)
    }

    /// Checks that every buffer the service path needs was processed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MissingRequiredBuffer`] naming the first absent buffer.
    const fn require_service_buffers(&self) -> Result<(), Error> {
        if self.kerb_validation_info.is_none() {
            return Err(Error::MissingRequiredBuffer("KerbValidationInfo"));
        }
        if self.server_checksum.is_none() {
            return Err(Error::MissingRequiredBuffer("ServerChecksum"));
        }
        if self.kdc_checksum.is_none() {
            return Err(Error::MissingRequiredBuffer("KDCChecksum"));
        }
        if self.client_info.is_none() {
            return Err(Error::MissingRequiredBuffer("ClientInfo"));
        }
        Ok(())
    }
}

/// Extract and process the first `AD-WIN2K-PAC` entry from Kerberos
/// authorization data.
///
/// Traversal permits at most eight `AD-IF-RELEVANT` wrappers and charges every
/// visited entry's payload against one inclusive 1 MiB budget. Nested payloads
/// are charged again at each decoded level; siblings share the same budget.
/// Admission occurs before DER decoding or PAC processing. The first PAC still
/// ends the search; this helper does not validate authorization restrictions.
///
/// # Errors
///
/// Returns [`Error::DerDecode`] when nested `AD-IF-RELEVANT` data does not decode, and the
/// errors of [`Pac::parse_and_process`] for the first PAC found. Returns
/// [`Error::AuthorizationDataDepthLimit`] or [`Error::AuthorizationDataByteLimit`]
/// before exceeding the local traversal limits.
#[cfg(feature = "messages")]
#[inline]
pub fn find_pac_in_authorization_data(
    authorization_data: &rasn_kerberos::AuthorizationData,
) -> Result<Option<Pac>, Error> {
    authorization::find(authorization_data, 0, &mut 0x0010_0000)
}

/// PAC info buffer table entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct InfoBuffer {
    /// Type of the PAC data at `offset`.
    pub ul_type: u32,
    /// Size of the PAC data at `offset`.
    pub cb_buffer_size: u32,
    /// Offset from the beginning of the PAC to the data.
    pub offset: u64,
}

impl InfoBuffer {
    /// Returns the buffer offset and length as `usize` values.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LengthOverflow`] when either value does not fit in
    /// `usize`.
    fn offset_and_len(&self) -> Result<(usize, usize), Error> {
        let offset = usize::try_from(self.offset).map_err(|_out_of_range| Error::LengthOverflow)?;
        let len =
            usize::try_from(self.cb_buffer_size).map_err(|_out_of_range| Error::LengthOverflow)?;
        Ok((offset, len))
    }

    /// Error describing this buffer as lying outside `total_len` bytes.
    const fn out_of_bounds(&self, total_len: usize) -> Error {
        Error::BufferOutOfBounds {
            ul_type: self.ul_type,
            offset: self.offset,
            len: self.cb_buffer_size,
            total_len,
        }
    }

    /// Checks that the buffer is eight-byte aligned and lies inside a PAC of
    /// `total_len` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BufferOffsetNotAligned`] for an unaligned offset,
    /// [`Error::LengthOverflow`] when the range does not fit in `usize`, and
    /// [`Error::BufferOutOfBounds`] when it ends past `total_len`.
    fn validate(&self, total_len: usize) -> Result<(), Error> {
        if !self.offset.is_multiple_of(8) {
            return Err(Error::BufferOffsetNotAligned {
                ul_type: self.ul_type,
                offset: self.offset,
            });
        }
        let (offset, len) = self.offset_and_len()?;
        let in_bounds = offset.checked_add(len).is_some_and(|end| end <= total_len);
        if !in_bounds {
            return Err(self.out_of_bounds(total_len));
        }
        Ok(())
    }

    /// Returns this buffer's bytes within the PAC `data`.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`InfoBuffer::validate`].
    fn slice<'data>(&self, data: &'data [u8]) -> Result<&'data [u8], Error> {
        self.validate(data.len())?;
        let (offset, len) = self.offset_and_len()?;
        let end = offset.checked_add(len).ok_or(Error::LengthOverflow)?;
        data.get(offset..end)
            .ok_or_else(|| self.out_of_bounds(data.len()))
    }

    /// Copies the zeroed signature buffer over this buffer's range in
    /// `zero_signature_data`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LengthOverflow`] when the range does not fit in
    /// `usize`, and [`Error::BufferOutOfBounds`] when it ends past
    /// `zero_signature_data` or its length differs from the signature buffer.
    fn copy_zeroed_signature(
        &self,
        zero_signature_data: &mut [u8],
        signature: &SignatureData,
    ) -> Result<(), Error> {
        let (offset, len) = self.offset_and_len()?;
        let end = offset.checked_add(len).ok_or(Error::LengthOverflow)?;
        let total_len = zero_signature_data.len();
        let Some(target) = zero_signature_data
            .get_mut(offset..end)
            .filter(|target| target.len() == signature.zeroed_data.len())
        else {
            return Err(self.out_of_bounds(total_len));
        };
        target.copy_from_slice(&signature.zeroed_data);
        Ok(())
    }
}

/// PAC signature data.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct SignatureData {
    /// PAC checksum type.
    pub signature_type: u32,
    /// Checksum bytes.
    pub signature: Vec<u8>,
    /// Optional RODC identifier.
    pub rodc_identifier: Option<u16>,
    /// Original signature buffer with only checksum bytes zeroed.
    pub zeroed_data: Vec<u8>,
}

impl SignatureData {
    /// Parse PAC signature data.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`] when the buffer is cut short and
    /// [`Error::UnsupportedChecksumType`] for an unknown checksum type.
    #[inline]
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        let signature_type = reader.read_u32()?;
        let signature_len = checksum_signature_len(signature_type)
            .ok_or(Error::UnsupportedChecksumType(signature_type))?;
        let signature = reader.read_bytes(signature_len)?.to_vec();
        let rodc_identifier = if reader.remaining() >= 2 {
            Some(reader.read_u16()?)
        } else {
            None
        };

        let mut zeroed_data = bytes.to_vec();
        let signature_end = PAC_SIGNATURE_TYPE_LEN
            .checked_add(signature_len)
            .ok_or(Error::LengthOverflow)?;
        zeroed_data
            .get_mut(PAC_SIGNATURE_TYPE_LEN..signature_end)
            .ok_or(Error::OutOfBounds {
                target: "PAC_SIGNATURE_DATA.Signature",
                offset: PAC_SIGNATURE_TYPE_LEN,
                len: signature_len,
                total_len: bytes.len(),
            })?
            .fill(0);

        Ok(Self {
            signature_type,
            signature,
            rodc_identifier,
            zeroed_data,
        })
    }
}

/// PAC client info.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ClientInfo {
    /// TGT authentication time.
    pub client_id: FileTime,
    /// Client account name length in bytes.
    pub name_length: u16,
    /// Client account name.
    pub name: String,
}

impl ClientInfo {
    /// Parse PAC client info.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`] when the buffer is cut short, and
    /// [`Error::InvalidUtf16Length`] or [`Error::InvalidUtf16`] for a malformed name.
    #[inline]
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        let client_id = reader.read_filetime()?;
        let name_length = reader.read_u16()?;
        let name_bytes = reader.read_bytes(name_length.into())?;
        let name = utf16le_bytes_to_string(name_bytes, "ClientInfo.Name")?;
        Ok(Self {
            client_id,
            name_length,
            name,
        })
    }
}

/// PAC UPN/DNS info.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct UpnDnsInfo {
    /// UPN length in bytes.
    pub upn_length: u16,
    /// UPN offset from the start of this buffer.
    pub upn_offset: u16,
    /// DNS domain name length in bytes.
    pub dns_domain_name_length: u16,
    /// DNS domain name offset from the start of this buffer.
    pub dns_domain_name_offset: u16,
    /// UPN/DNS flags.
    pub flags: u32,
    /// User principal name.
    pub upn: String,
    /// DNS domain name.
    pub dns_domain: String,
}

impl UpnDnsInfo {
    /// Parse PAC UPN/DNS info.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`] when the fixed header is cut short,
    /// [`Error::LengthOverflow`] or [`Error::OutOfBounds`] when a name lies outside the buffer,
    /// and [`Error::InvalidUtf16Length`] or [`Error::InvalidUtf16`] for a malformed name.
    #[inline]
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        let upn_length = reader.read_u16()?;
        let upn_offset = reader.read_u16()?;
        let dns_domain_name_length = reader.read_u16()?;
        let dns_domain_name_offset = reader.read_u16()?;
        let flags = reader.read_u32()?;

        let upn = utf16le_bytes_to_string(
            checked_slice(
                bytes,
                upn_offset.into(),
                upn_length.into(),
                "UPN_DNS_INFO.UPN",
            )?,
            "UPN_DNS_INFO.UPN",
        )?;
        let dns_domain = utf16le_bytes_to_string(
            checked_slice(
                bytes,
                dns_domain_name_offset.into(),
                dns_domain_name_length.into(),
                "UPN_DNS_INFO.DNSDomain",
            )?,
            "UPN_DNS_INFO.DNSDomain",
        )?;

        Ok(Self {
            upn_length,
            upn_offset,
            dns_domain_name_length,
            dns_domain_name_offset,
            flags,
            upn,
            dns_domain,
        })
    }
}

/// PAC credentials info.
///
/// This PAC buffer is not NDR-wrapped. The nested credential data is encrypted
/// with key usage 16 and normally requires the AS reply key, so service-side PAC
/// processing records the encrypted bytes without decrypting them.
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub struct CredentialsInfo {
    /// Credentials info version. The Microsoft format requires zero.
    version: u32,
    /// Kerberos encryption type used for the encrypted credential data.
    encryption_type: u32,
    /// Encrypted NDR-encoded `CredentialData`.
    encrypted_credential_data: Zeroizing<Vec<u8>>,
}

impl CredentialsInfo {
    /// Return the credential format version.
    #[inline]
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Return the credential encryption type.
    #[inline]
    #[must_use]
    pub const fn encryption_type(&self) -> u32 {
        self.encryption_type
    }

    /// Borrow the encrypted credential bytes; callers own erasure of any copies.
    #[inline]
    #[must_use]
    pub fn encrypted_credential_data(&self) -> &[u8] {
        &self.encrypted_credential_data
    }

    /// Erase the previous credential bytes before adopting their replacement.
    #[inline]
    pub fn set_encrypted_credential_data(&mut self, value: Zeroizing<Vec<u8>>) {
        self.encrypted_credential_data.as_mut_slice().zeroize();
        #[cfg(test)]
        credential_secrets::observe_bytes(&self.encrypted_credential_data);
        self.encrypted_credential_data = value;
    }
    /// Parse PAC credentials info without decrypting the nested credential data.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`] when the header is cut short and
    /// [`Error::InvalidCredentialsInfoVersion`] for a non-zero version.
    #[inline]
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        let version = reader.read_u32()?;
        if version != 0 {
            return Err(Error::InvalidCredentialsInfoVersion(version));
        }
        let encryption_type = reader.read_u32()?;
        let encrypted_credential_data =
            Zeroizing::new(reader.read_bytes(reader.remaining())?.to_vec());

        Ok(Self {
            version,
            encryption_type,
            encrypted_credential_data,
        })
    }

    /// Decrypt and parse the nested PAC credential data.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LengthOverflow`] when the encryption type does not fit in `i32`,
    /// [`Error::CredentialKeyTypeMismatch`] when `key` has another type,
    /// [`Error::UnsupportedEncryptionType`] for an unknown type, [`Error::Crypto`] when
    /// decryption fails, and the errors of [`CredentialData::parse`].
    #[inline]
    pub fn decrypt_credential_data(&self, key: &EncryptionKey) -> Result<CredentialData, Error> {
        let encryption_type =
            i32::try_from(self.encryption_type).map_err(|_out_of_range| Error::LengthOverflow)?;
        if key.etype() != encryption_type {
            return Err(Error::CredentialKeyTypeMismatch {
                expected: encryption_type,
                actual: key.etype(),
            });
        }
        let etype = selection::enctype(encryption_type)?
            .ok_or(Error::UnsupportedEncryptionType(encryption_type))?;
        let plaintext = Zeroizing::new(etype.decrypt_message(
            key.value(),
            &self.encrypted_credential_data,
            PAC_CREDENTIALS_KEY_USAGE,
        )?);
        CredentialData::parse(&plaintext)
    }
}

/// Decrypted PAC credential data.
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub struct CredentialData {
    /// Number of supplemental credentials.
    credential_count: u32,
    /// Supplemental credentials.
    credentials: Vec<SecpkgSupplementalCredential>,
}

impl CredentialData {
    /// Return the number of supplemental packages.
    #[inline]
    #[must_use]
    pub const fn credential_count(&self) -> u32 {
        self.credential_count
    }
    /// Borrow supplemental package owners.
    #[inline]
    #[must_use]
    pub fn credentials(&self) -> &[SecpkgSupplementalCredential] {
        &self.credentials
    }
    /// Borrow package owners for their erasing setters, without exposing raw storage.
    #[inline]
    pub fn credentials_mut(&mut self) -> &mut [SecpkgSupplementalCredential] {
        &mut self.credentials
    }
    /// Parse NDR-encoded PAC credential data.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] when the NDR encoding is malformed: a bad wrapper
    /// ([`Error::TooShort`], [`Error::InvalidNdrHeader`], [`Error::InvalidNdrObjectLength`]),
    /// truncated data ([`Error::Truncated`]), a null or inconsistent pointer, count, SID or
    /// string, or non-zero trailing bytes ([`Error::TrailingNdrBytesAfter`]).
    #[inline]
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        read_ndr_wrapper(&mut reader, "CredentialData")?;

        let max_count = read_ndr_u32(&mut reader)?;
        let credential_count = read_ndr_u32(&mut reader)?;
        (max_count == credential_count).ok_or(Error::CountMismatch {
            target: "CredentialData.Credentials",
            expected: credential_count,
            actual: max_count,
        })?;
        let credentials = read_counted_supplemental_credentials(&mut reader, credential_count)?;
        ensure_zero_trailing(&mut reader, "CredentialData")?;

        Ok(Self {
            credential_count,
            credentials,
        })
    }
}

/// Supplemental credential package entry.
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub struct SecpkgSupplementalCredential {
    /// Supplemental credential package name.
    package_name: RpcUnicodeString,
    /// Credential byte length.
    credential_size: u32,
    /// Package-specific credential bytes.
    credentials: Zeroizing<Vec<u8>>,
}

impl SecpkgSupplementalCredential {
    /// Borrow the package name.
    #[inline]
    #[must_use]
    pub const fn package_name(&self) -> &RpcUnicodeString {
        &self.package_name
    }

    /// Return the encoded credential size.
    #[inline]
    #[must_use]
    pub const fn credential_size(&self) -> u32 {
        self.credential_size
    }

    /// Borrow credential bytes; callers must erase any copies.
    #[inline]
    #[must_use]
    pub fn credentials(&self) -> &[u8] {
        &self.credentials
    }

    /// Erase the previous credential and adopt a replacement with its wire size.
    /// # Errors
    /// Returns [`Error::LengthOverflow`] if the replacement exceeds the wire size range.
    #[inline]
    pub fn set_credentials(&mut self, value: Zeroizing<Vec<u8>>) -> Result<(), Error> {
        let length = u32::try_from(value.len()).map_err(|_too_long| Error::LengthOverflow)?;
        self.credentials.as_mut_slice().zeroize();
        #[cfg(test)]
        credential_secrets::observe_bytes(&self.credentials);
        self.credentials = value;
        self.credential_size = length;
        Ok(())
    }
}

/// NTLM supplemental credential data.
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub struct NtlmSupplementalCredential {
    /// NTLM supplemental credential version. The Microsoft format requires zero.
    version: u32,
    /// NTLM supplemental credential flags.
    flags: u32,
    /// LM one-way function, if present and valid.
    lm_password: Option<Zeroizing<[u8; 16]>>,
    /// NT one-way function, if present and valid.
    nt_password: Option<Zeroizing<[u8; 16]>>,
}

impl NtlmSupplementalCredential {
    /// Return the format version.
    #[must_use]
    #[inline]
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Return the validity flags.
    #[must_use]
    #[inline]
    pub const fn flags(&self) -> u32 {
        self.flags
    }

    /// Borrow the LM hash; callers must erase any copies they create.
    #[must_use]
    #[inline]
    pub fn lm_password(&self) -> Option<&[u8; 16]> {
        self.lm_password.as_deref()
    }

    /// Borrow the NT hash; callers must erase any copies they create.
    #[must_use]
    #[inline]
    pub fn nt_password(&self) -> Option<&[u8; 16]> {
        self.nt_password.as_deref()
    }

    /// Erase the previous LM hash before replacing it and updating its validity flag.
    #[inline]
    pub fn set_lm_password(&mut self, value: Option<Zeroizing<[u8; 16]>>) {
        if let Some(previous) = &mut self.lm_password {
            previous.zeroize();
        }
        #[cfg(test)]
        credential_secrets::observe_replacement(self.lm_password.as_ref());
        self.flags &= !NTLM_SUPPLEMENTAL_CRED_LMOWF;
        if value.is_some() {
            self.flags |= NTLM_SUPPLEMENTAL_CRED_LMOWF;
        }
        self.lm_password = value;
    }

    /// Erase the previous NT hash before replacing it and updating its validity flag.
    #[inline]
    pub fn set_nt_password(&mut self, value: Option<Zeroizing<[u8; 16]>>) {
        if let Some(previous) = &mut self.nt_password {
            previous.zeroize();
        }
        #[cfg(test)]
        credential_secrets::observe_replacement(self.nt_password.as_ref());
        self.flags &= !NTLM_SUPPLEMENTAL_CRED_NTOWF;
        if value.is_some() {
            self.flags |= NTLM_SUPPLEMENTAL_CRED_NTOWF;
        }
        self.nt_password = value;
    }
    /// Parse package-specific NTLM supplemental credential bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`] when the buffer is cut short and
    /// [`Error::InvalidNtlmSupplementalCredentialVersion`] for a non-zero version.
    #[inline]
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        let version = reader.read_u32()?;
        if version != 0 {
            return Err(Error::InvalidNtlmSupplementalCredentialVersion(version));
        }
        let flags = reader.read_u32()?;
        (flags & (NTLM_SUPPLEMENTAL_CRED_LMOWF | NTLM_SUPPLEMENTAL_CRED_NTOWF) != 0)
            .ok_or(Error::MissingNtlmValidityFlag)?;
        let lm_slot = Zeroizing::new(reader.read_array()?);
        let nt_slot = Zeroizing::new(reader.read_array()?);
        let lm_password =
            ntlm_supplemental_flag_set(flags, NTLM_SUPPLEMENTAL_CRED_LMOWF).then_some(lm_slot);
        let nt_password =
            ntlm_supplemental_flag_set(flags, NTLM_SUPPLEMENTAL_CRED_NTOWF).then_some(nt_slot);

        Ok(Self {
            version,
            flags,
            lm_password,
            nt_password,
        })
    }

    #[must_use]
    /// Whether the LM OWF flag is set.
    #[inline]
    pub const fn has_lm_password(&self) -> bool {
        ntlm_supplemental_flag_set(self.flags, NTLM_SUPPLEMENTAL_CRED_LMOWF)
    }

    #[must_use]
    /// Whether the NT OWF flag is set.
    #[inline]
    pub const fn has_nt_password(&self) -> bool {
        ntlm_supplemental_flag_set(self.flags, NTLM_SUPPLEMENTAL_CRED_NTOWF)
    }
}

/// PAC S4U delegation information.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct S4UDelegationInfo {
    /// Principal to which the application can forward the ticket.
    pub s4u2proxy_target: RpcUnicodeString,
    /// Number of transited services.
    pub transited_list_size: u32,
    /// Delegated services transited by the client and subsequent services.
    pub s4u_transited_services: Vec<RpcUnicodeString>,
}

impl S4UDelegationInfo {
    /// Parse NDR-encoded S4U delegation information.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] when the NDR encoding is malformed: a bad wrapper
    /// ([`Error::TooShort`], [`Error::InvalidNdrHeader`], [`Error::InvalidNdrObjectLength`]),
    /// truncated data ([`Error::Truncated`]), a null or inconsistent pointer, count, SID or
    /// string, or non-zero trailing bytes ([`Error::TrailingNdrBytesAfter`]).
    #[inline]
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        read_ndr_wrapper(&mut reader, "S4UDelegationInfo")?;

        let s4u2proxy_target_descriptor = RpcUnicodeStringDescriptor::read(&mut reader)?;
        let transited_list_size = read_ndr_u32(&mut reader)?;
        let s4u_transited_services_ref = read_ndr_u32(&mut reader)?;

        let s4u2proxy_target = read_deferred_unicode_string(
            &mut reader,
            s4u2proxy_target_descriptor,
            "S4U2proxyTarget",
        )?;
        let s4u_transited_services = read_deferred_rpc_unicode_strings(
            &mut reader,
            s4u_transited_services_ref,
            transited_list_size,
            "S4UTransitedServices",
        )?;
        ensure_zero_trailing(&mut reader, "S4UDelegationInfo")?;

        Ok(Self {
            s4u2proxy_target,
            transited_list_size,
            s4u_transited_services,
        })
    }
}

/// PAC device information.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct DeviceInfo {
    /// Device account RID.
    pub user_id: u32,
    /// Device primary group RID.
    pub primary_group_id: u32,
    /// Domain SID for the device account.
    pub account_domain_id: Option<Sid>,
    /// Number of account-domain groups.
    pub account_group_count: u32,
    /// Account-domain group memberships.
    pub account_group_ids: Vec<GroupMembership>,
    /// Number of extra SIDs.
    pub sid_count: u32,
    /// Extra SIDs for groups outside the account domain.
    pub extra_sids: Vec<SidAndAttributes>,
    /// Number of domain group sets.
    pub domain_group_count: u32,
    /// Domain group memberships.
    pub domain_group: Vec<DomainGroupMembership>,
}

impl DeviceInfo {
    /// Parse NDR-encoded PAC device information.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] when the NDR encoding is malformed: a bad wrapper
    /// ([`Error::TooShort`], [`Error::InvalidNdrHeader`], [`Error::InvalidNdrObjectLength`]),
    /// truncated data ([`Error::Truncated`]), a null or inconsistent pointer, count, SID or
    /// string, or non-zero trailing bytes ([`Error::TrailingNdrBytesAfter`]).
    #[inline]
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        read_ndr_wrapper(&mut reader, "DeviceInfo")?;

        let user_id = read_ndr_u32(&mut reader)?;
        let primary_group_id = read_ndr_u32(&mut reader)?;
        let account_domain_id_ref = read_ndr_u32(&mut reader)?;
        let account_group_count = read_ndr_u32(&mut reader)?;
        let account_group_ids_ref = read_ndr_u32(&mut reader)?;
        let sid_count = read_ndr_u32(&mut reader)?;
        let extra_sids_ref = read_ndr_u32(&mut reader)?;
        let domain_group_count = read_ndr_u32(&mut reader)?;
        let domain_group_ref = read_ndr_u32(&mut reader)?;

        let account_domain_id = read_deferred_sid(
            &mut reader,
            account_domain_id_ref,
            "DeviceInfo.AccountDomainID",
        )?;
        let account_group_ids = read_deferred_group_memberships(
            &mut reader,
            account_group_ids_ref,
            account_group_count,
            "DeviceInfo.AccountGroupIDs",
        )?;
        let extra_sids = read_deferred_sid_and_attributes(
            &mut reader,
            extra_sids_ref,
            sid_count,
            "DeviceInfo.ExtraSIDs",
        )?;
        let domain_group = read_deferred_domain_group_memberships(
            &mut reader,
            domain_group_ref,
            domain_group_count,
            "DeviceInfo.DomainGroup",
        )?;
        ensure_zero_trailing(&mut reader, "DeviceInfo")?;

        Ok(Self {
            user_id,
            primary_group_id,
            account_domain_id,
            account_group_count,
            account_group_ids,
            sid_count,
            extra_sids,
            domain_group_count,
            domain_group,
        })
    }

    #[must_use]
    /// Return SIDs for account-domain groups, extra SIDs, and domain groups.
    #[inline]
    pub fn group_membership_sids(&self) -> Vec<String> {
        let mut sids = Vec::new();
        let mut seen = HashSet::new();
        if let Some(account_domain_sid) = &self.account_domain_id {
            for group in &self.account_group_ids {
                let sid = format!("{account_domain_sid}-{}", group.relative_id);
                if seen.insert(sid.clone()) {
                    sids.push(sid);
                }
            }
        }
        for extra_sid in &self.extra_sids {
            let sid = extra_sid.sid.to_string();
            if seen.insert(sid.clone()) {
                sids.push(sid);
            }
        }
        for domain_group in &self.domain_group {
            for group in &domain_group.group_ids {
                let sid = format!("{}-{}", domain_group.domain_id, group.relative_id);
                if seen.insert(sid.clone()) {
                    sids.push(sid);
                }
            }
        }
        sids
    }
}

/// PAC client or device claims info.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ClaimsInfo {
    /// Claims metadata, including compression and raw nested claims bytes.
    pub metadata: ClaimsSetMetadata,
    /// Decoded claims set.
    pub claims_set: ClaimsSet,
}

impl ClaimsInfo {
    /// Creates a `ClaimsInfo` from its required fields.
    #[must_use]
    #[inline]
    pub const fn new(metadata: ClaimsSetMetadata, claims_set: ClaimsSet) -> Self {
        Self {
            metadata,
            claims_set,
        }
    }

    /// Parse PAC client or device claims info.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`ClaimsSetMetadata::parse`] and
    /// [`ClaimsSetMetadata::claims_set`].
    #[inline]
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let metadata = ClaimsSetMetadata::parse(bytes)?;
        let claims_set = metadata.claims_set()?;
        Ok(Self {
            metadata,
            claims_set,
        })
    }
}

/// Claims set metadata wrapping a nested claims set byte stream.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ClaimsSetMetadata {
    /// Encoded claims set byte length.
    pub claims_set_size: u32,
    /// Encoded claims set bytes.
    pub claims_set_bytes: Vec<u8>,
    /// Compression format for `claims_set_bytes`.
    pub compression_format: u16,
    /// Uncompressed claims set byte length.
    pub uncompressed_claims_set_size: u32,
    /// Reserved field type.
    pub reserved_type: u16,
    /// Reserved field byte length.
    pub reserved_field_size: u32,
    /// Reserved field bytes.
    pub reserved_field: Vec<u8>,
}

impl ClaimsSetMetadata {
    /// Parse an NDR-encoded `ClaimsSetMetadata` value.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] when the NDR encoding is malformed: a bad wrapper
    /// ([`Error::TooShort`], [`Error::InvalidNdrHeader`], [`Error::InvalidNdrObjectLength`]),
    /// truncated data ([`Error::Truncated`]), a null or inconsistent pointer, count, SID or
    /// string, or non-zero trailing bytes ([`Error::TrailingNdrBytesAfter`]).
    #[inline]
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        read_ndr_wrapper(&mut reader, "ClaimsSetMetadata")?;

        let claims_set_size = read_ndr_u32(&mut reader)?;
        let claims_set_bytes_ref = read_ndr_u32(&mut reader)?;
        let compression_format = read_ndr_u16(&mut reader)?;
        let uncompressed_claims_set_size = read_ndr_u32(&mut reader)?;
        let reserved_type = read_ndr_u16(&mut reader)?;
        let reserved_field_size = read_ndr_u32(&mut reader)?;
        let reserved_field_ref = read_ndr_u32(&mut reader)?;

        let claims_set_bytes = read_deferred_u8_array(
            &mut reader,
            claims_set_bytes_ref,
            claims_set_size,
            "ClaimsSetMetadata.ClaimsSetBytes",
        )?;
        let reserved_field = read_deferred_u8_array(
            &mut reader,
            reserved_field_ref,
            reserved_field_size,
            "ClaimsSetMetadata.ReservedField",
        )?;
        ensure_zero_trailing(&mut reader, "ClaimsSetMetadata")?;

        Ok(Self {
            claims_set_size,
            claims_set_bytes,
            compression_format,
            uncompressed_claims_set_size,
            reserved_type,
            reserved_field_size,
            reserved_field,
        })
    }

    /// Decode the nested claims set bytes, decompressing when required.
    ///
    /// Output is limited to 1 MiB independently of producer metadata, including
    /// uncompressed copies. PAC processing handles at most one client and one
    /// device claims buffer, so their combined decoded output is at most 2 MiB.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedClaimsCompressionFormat`] for an unknown format,
    /// [`Error::ClaimsDecompression`] when decompression fails, [`Error::LengthOverflow`] when
    /// the declared size does not fit in `usize`, and [`Error::ClaimsDecompressedSizeMismatch`]
    /// when the output size differs from `uncompressed_claims_set_size`.
    #[inline]
    pub fn decoded_claims_set_bytes(&self) -> Result<Vec<u8>, Error> {
        (self.uncompressed_claims_set_size <= 0x0010_0000
            && self.claims_set_bytes.len() <= 0x0010_0000)
            .ok_or(Error::ClaimsOutputLimit)?;
        match self.compression_format {
            CLAIMS_COMPRESSION_FORMAT_NONE => {
                let expected = usize::try_from(self.uncompressed_claims_set_size)
                    .map_err(|_out_of_range| Error::LengthOverflow)?;
                let actual = self.claims_set_bytes.len();
                (actual == expected).ok_or(Error::ClaimsDecompressedSizeMismatch {
                    compression_format: self.compression_format,
                    expected,
                    actual,
                })?;
                Ok(self.claims_set_bytes.clone())
            }
            CLAIMS_COMPRESSION_FORMAT_LZNT1 => decompress_claims_set_bytes::<Lznt1>(
                self.compression_format,
                &self.claims_set_bytes,
                self.uncompressed_claims_set_size,
            ),
            CLAIMS_COMPRESSION_FORMAT_XPRESS => {
                let mut framed = Vec::with_capacity(self.claims_set_bytes.len().saturating_add(8));
                framed
                    .extend_from_slice(&u64::from(self.uncompressed_claims_set_size).to_le_bytes());
                framed.extend_from_slice(&self.claims_set_bytes);
                decompress_claims_set_bytes::<Xpress>(
                    self.compression_format,
                    &framed,
                    self.uncompressed_claims_set_size,
                )
            }
            CLAIMS_COMPRESSION_FORMAT_XPRESS_HUFF => {
                let mut framed = Vec::with_capacity(self.claims_set_bytes.len().saturating_add(4));
                framed.extend_from_slice(&self.uncompressed_claims_set_size.to_le_bytes());
                framed.extend_from_slice(&self.claims_set_bytes);
                decompress_claims_set_bytes::<XpressHuffman>(
                    self.compression_format,
                    &framed,
                    self.uncompressed_claims_set_size,
                )
            }
            compression_format => Err(Error::UnsupportedClaimsCompressionFormat(
                compression_format,
            )),
        }
    }

    /// Decode the nested claims set.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`ClaimsSetMetadata::decoded_claims_set_bytes`] and
    /// [`ClaimsSet::parse`].
    #[inline]
    pub fn claims_set(&self) -> Result<ClaimsSet, Error> {
        ClaimsSet::parse(&self.decoded_claims_set_bytes()?)
    }
}

/// Decoded PAC claims set.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ClaimsSet {
    /// Number of claims arrays.
    pub claims_array_count: u32,
    /// Claims arrays.
    pub claims_arrays: Vec<ClaimsArray>,
    /// Reserved field type.
    pub reserved_type: u16,
    /// Reserved field byte length.
    pub reserved_field_size: u32,
    /// Reserved field bytes.
    pub reserved_field: Vec<u8>,
}

impl ClaimsSet {
    /// Parse an NDR-encoded claims set.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] when the NDR encoding is malformed: a bad wrapper
    /// ([`Error::TooShort`], [`Error::InvalidNdrHeader`], [`Error::InvalidNdrObjectLength`]),
    /// truncated data ([`Error::Truncated`]), a null or inconsistent pointer, count, SID or
    /// string, or non-zero trailing bytes ([`Error::TrailingNdrBytesAfter`]), plus
    /// [`Error::UnsupportedClaimType`] or [`Error::InvalidClaimUnionTag`] for a malformed claim
    /// entry.
    #[inline]
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        read_ndr_wrapper(&mut reader, "ClaimsSet")?;

        let claims_array_count = read_ndr_u32(&mut reader)?;
        let claims_arrays_ref = read_ndr_u32(&mut reader)?;
        let reserved_type = read_ndr_u16(&mut reader)?;
        let reserved_field_size = read_ndr_u32(&mut reader)?;
        let reserved_field_ref = read_ndr_u32(&mut reader)?;

        let claims_arrays = read_deferred_claims_arrays(
            &mut reader,
            claims_arrays_ref,
            claims_array_count,
            "ClaimsSet.ClaimsArrays",
        )?;
        let reserved_field = read_deferred_u8_array(
            &mut reader,
            reserved_field_ref,
            reserved_field_size,
            "ClaimsSet.ReservedField",
        )?;
        ensure_zero_trailing(&mut reader, "ClaimsSet")?;

        Ok(Self {
            claims_array_count,
            claims_arrays,
            reserved_type,
            reserved_field_size,
            reserved_field,
        })
    }
}

/// Claims from a single source.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ClaimsArray {
    /// Claims source type.
    pub claims_source_type: u16,
    /// Number of claim entries.
    pub claims_count: u32,
    /// Claim entries.
    pub claim_entries: Vec<ClaimEntry>,
}

/// A single decoded claim entry.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ClaimEntry {
    /// Claim identifier URI.
    pub id: String,
    /// Claim value type.
    pub claim_type: u16,
    /// Claim values.
    pub values: ClaimValues,
}

/// Typed claim values.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ClaimValues {
    /// Signed 64-bit integer values.
    Int64(Vec<i64>),
    /// Unsigned 64-bit integer values.
    UInt64(Vec<u64>),
    /// UTF-16 string values.
    String(Vec<String>),
    /// Boolean values.
    Boolean(Vec<bool>),
}

impl ClaimValues {
    #[must_use]
    /// Number of values.
    #[inline]
    pub const fn len(&self) -> usize {
        match self {
            Self::Int64(values) => values.len(),
            Self::UInt64(values) => values.len(),
            Self::String(values) => values.len(),
            Self::Boolean(values) => values.len(),
        }
    }

    #[must_use]
    /// Whether the claim carries no values.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Microsoft FILETIME, expressed as 100ns ticks since 1601-01-01 UTC.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct FileTime {
    /// 100 ns intervals since 1601-01-01 UTC.
    ticks: u64,
}

impl FileTime {
    #[must_use]
    /// Build from raw Windows FILETIME ticks.
    #[inline]
    pub const fn from_ticks(ticks: u64) -> Self {
        Self { ticks }
    }

    #[must_use]
    /// Raw Windows FILETIME ticks.
    #[inline]
    pub const fn ticks(self) -> u64 {
        self.ticks
    }

    #[must_use]
    /// Convert to `SystemTime`.
    ///
    /// Every `FILETIME` is representable on Unix platforms. A platform whose
    /// `SystemTime` cannot represent the instant gets the Unix epoch instead.
    #[inline]
    pub fn system_time(self) -> SystemTime {
        let unix_epoch_ticks = WINDOWS_TO_UNIX_SECONDS.saturating_mul(WINDOWS_TICKS_PER_SECOND);
        let converted = self.ticks.checked_sub(unix_epoch_ticks).map_or_else(
            || {
                let before_epoch = unix_epoch_ticks.saturating_sub(self.ticks);
                UNIX_EPOCH.checked_sub(filetime_tick_duration(before_epoch))
            },
            |after_epoch| UNIX_EPOCH.checked_add(filetime_tick_duration(after_epoch)),
        );
        converted.unwrap_or(UNIX_EPOCH)
    }
}

/// RPC Unicode string decoded from NDR.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct RpcUnicodeString {
    /// String length in bytes.
    pub length: u16,
    /// Maximum string length in bytes.
    pub maximum_length: u16,
    /// Decoded string value.
    pub value: String,
}

/// PAC group membership entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct GroupMembership {
    /// Relative identifier.
    pub relative_id: u32,
    /// Group attributes.
    pub attributes: u32,
}

impl GroupMembership {
    /// Creates a `GroupMembership` from its required fields.
    #[must_use]
    #[inline]
    pub const fn new(relative_id: u32, attributes: u32) -> Self {
        Self {
            relative_id,
            attributes,
        }
    }
}

/// Windows SID.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Sid {
    /// SID revision.
    pub revision: u8,
    /// Identifier authority bytes.
    pub identifier_authority: [u8; 6],
    /// SID sub-authorities.
    pub sub_authorities: Vec<u32>,
}

impl fmt::Display for Sid {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut authority = 0_u64;
        for byte in self.identifier_authority {
            authority = (authority << 8_u32) | u64::from(byte);
        }
        if authority > u64::from(u32::MAX) {
            write!(f, "S-{}-0x", self.revision)?;
            for byte in self.identifier_authority {
                write!(f, "{byte:02x}")?;
            }
        } else {
            write!(f, "S-{}-{authority}", self.revision)?;
        }
        for sub_authority in &self.sub_authorities {
            write!(f, "-{sub_authority}")?;
        }
        Ok(())
    }
}

/// SID with attributes.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct SidAndAttributes {
    /// SID.
    pub sid: Sid,
    /// SID attributes.
    pub attributes: u32,
}

/// Device domain group memberships.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct DomainGroupMembership {
    /// Domain SID.
    pub domain_id: Sid,
    /// Number of group memberships in `group_ids`.
    pub group_count: u32,
    /// Groups within `domain_id`.
    pub group_ids: Vec<GroupMembership>,
}

/// AD credential attributes derived from PAC `KERB_VALIDATION_INFO`.
///
/// This mirrors the AD credential summary gokrb5 exposes to service callers,
/// while preserving optional PAC fields as Rust options.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct AdCredentials {
    /// Effective user name.
    pub effective_name: String,
    /// Full user name.
    pub full_name: String,
    /// User RID.
    pub user_id: u32,
    /// Primary group RID.
    pub primary_group_id: u32,
    /// Logon time.
    pub logon_time: SystemTime,
    /// Logoff time.
    pub logoff_time: SystemTime,
    /// Password last set time.
    pub password_last_set: SystemTime,
    /// Group membership SIDs.
    pub group_membership_sids: Vec<String>,
    /// Logon domain name.
    pub logon_domain_name: String,
    /// Logon domain SID, when present.
    pub logon_domain_id: Option<String>,
    /// Logon server name.
    pub logon_server: String,
}

/// Parsed `KERB_VALIDATION_INFO`.
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub struct KerbValidationInfo {
    /// User logon time.
    logon_time: FileTime,
    /// User logoff time.
    logoff_time: FileTime,
    /// Kickoff time.
    kickoff_time: FileTime,
    /// Password last set time.
    password_last_set: FileTime,
    /// Password can change time.
    password_can_change: FileTime,
    /// Password must change time.
    password_must_change: FileTime,
    /// Effective user name.
    effective_name: RpcUnicodeString,
    /// Full user name.
    full_name: RpcUnicodeString,
    /// Logon script.
    logon_script: RpcUnicodeString,
    /// Profile path.
    profile_path: RpcUnicodeString,
    /// Home directory.
    home_directory: RpcUnicodeString,
    /// Home directory drive.
    home_directory_drive: RpcUnicodeString,
    /// Logon count.
    logon_count: u16,
    /// Bad password count.
    bad_password_count: u16,
    /// User RID.
    user_id: u32,
    /// Primary group RID.
    primary_group_id: u32,
    /// Group count.
    group_count: u32,
    /// Group memberships.
    group_ids: Vec<GroupMembership>,
    /// User flags.
    user_flags: u32,
    /// User session key bytes.
    user_session_key: session_key::SessionKey,
    /// Logon server.
    logon_server: RpcUnicodeString,
    /// Logon domain name.
    logon_domain_name: RpcUnicodeString,
    /// Logon domain SID.
    logon_domain_id: Option<Sid>,
    /// Reserved values.
    reserved1: [u32; 2],
    /// User account control flags.
    user_account_control: u32,
    /// Sub-authentication status.
    sub_auth_status: u32,
    /// Last successful interactive logon.
    last_successful_ilogon: FileTime,
    /// Last failed interactive logon.
    last_failed_ilogon: FileTime,
    /// Failed interactive logon count.
    failed_ilogon_count: u32,
    /// Reserved value.
    reserved3: u32,
    /// Extra SID count.
    sid_count: u32,
    /// Extra SIDs.
    extra_sids: Vec<SidAndAttributes>,
    /// Resource group domain SID.
    resource_group_domain_sid: Option<Sid>,
    /// Resource group count.
    resource_group_count: u32,
    /// Resource groups.
    resource_group_ids: Vec<GroupMembership>,
}

impl KerbValidationInfo {
    /// Mutably borrow group metadata without exposing credential storage.
    #[inline]
    #[must_use]
    pub const fn group_ids_mut(&mut self) -> &mut Vec<GroupMembership> {
        &mut self.group_ids
    }
    /// Return user logon time.
    #[inline]
    #[must_use]
    pub const fn logon_time(&self) -> FileTime {
        self.logon_time
    }
    /// Return user logoff time.
    #[inline]
    #[must_use]
    pub const fn logoff_time(&self) -> FileTime {
        self.logoff_time
    }
    /// Return kickoff time.
    #[inline]
    #[must_use]
    pub const fn kickoff_time(&self) -> FileTime {
        self.kickoff_time
    }
    /// Return password last-set time.
    #[inline]
    #[must_use]
    pub const fn password_last_set(&self) -> FileTime {
        self.password_last_set
    }
    /// Return earliest password-change time.
    #[inline]
    #[must_use]
    pub const fn password_can_change(&self) -> FileTime {
        self.password_can_change
    }
    /// Return mandatory password-change time.
    #[inline]
    #[must_use]
    pub const fn password_must_change(&self) -> FileTime {
        self.password_must_change
    }
    /// Borrow the effective user name.
    #[inline]
    #[must_use]
    pub const fn effective_name(&self) -> &RpcUnicodeString {
        &self.effective_name
    }
    /// Borrow the full user name.
    #[inline]
    #[must_use]
    pub const fn full_name(&self) -> &RpcUnicodeString {
        &self.full_name
    }
    /// Borrow the logon script.
    #[inline]
    #[must_use]
    pub const fn logon_script(&self) -> &RpcUnicodeString {
        &self.logon_script
    }
    /// Borrow the profile path.
    #[inline]
    #[must_use]
    pub const fn profile_path(&self) -> &RpcUnicodeString {
        &self.profile_path
    }
    /// Borrow the home directory.
    #[inline]
    #[must_use]
    pub const fn home_directory(&self) -> &RpcUnicodeString {
        &self.home_directory
    }
    /// Borrow the home drive.
    #[inline]
    #[must_use]
    pub const fn home_directory_drive(&self) -> &RpcUnicodeString {
        &self.home_directory_drive
    }
    /// Return the logon count.
    #[inline]
    #[must_use]
    pub const fn logon_count(&self) -> u16 {
        self.logon_count
    }
    /// Return the bad-password count.
    #[inline]
    #[must_use]
    pub const fn bad_password_count(&self) -> u16 {
        self.bad_password_count
    }
    /// Return the user RID.
    #[inline]
    #[must_use]
    pub const fn user_id(&self) -> u32 {
        self.user_id
    }
    /// Return the primary group RID.
    #[inline]
    #[must_use]
    pub const fn primary_group_id(&self) -> u32 {
        self.primary_group_id
    }
    /// Return the group count.
    #[inline]
    #[must_use]
    pub const fn group_count(&self) -> u32 {
        self.group_count
    }
    /// Borrow group memberships.
    #[inline]
    #[must_use]
    pub fn group_ids(&self) -> &[GroupMembership] {
        &self.group_ids
    }
    /// Return user flags.
    #[inline]
    #[must_use]
    pub const fn user_flags(&self) -> u32 {
        self.user_flags
    }
    /// Borrow the logon server.
    #[inline]
    #[must_use]
    pub const fn logon_server(&self) -> &RpcUnicodeString {
        &self.logon_server
    }
    /// Borrow the logon domain name.
    #[inline]
    #[must_use]
    pub const fn logon_domain_name(&self) -> &RpcUnicodeString {
        &self.logon_domain_name
    }
    /// Borrow the domain SID.
    #[inline]
    #[must_use]
    pub const fn logon_domain_id(&self) -> Option<&Sid> {
        self.logon_domain_id.as_ref()
    }
    /// Return reserved values.
    #[inline]
    #[must_use]
    pub const fn reserved1(&self) -> [u32; 2] {
        self.reserved1
    }
    /// Return account-control flags.
    #[inline]
    #[must_use]
    pub const fn user_account_control(&self) -> u32 {
        self.user_account_control
    }
    /// Return sub-authentication status.
    #[inline]
    #[must_use]
    pub const fn sub_auth_status(&self) -> u32 {
        self.sub_auth_status
    }
    /// Return the last successful interactive logon time.
    #[inline]
    #[must_use]
    pub const fn last_successful_ilogon(&self) -> FileTime {
        self.last_successful_ilogon
    }
    /// Return the last failed interactive logon time.
    #[inline]
    #[must_use]
    pub const fn last_failed_ilogon(&self) -> FileTime {
        self.last_failed_ilogon
    }
    /// Return the failed interactive-logon count.
    #[inline]
    #[must_use]
    pub const fn failed_ilogon_count(&self) -> u32 {
        self.failed_ilogon_count
    }
    /// Return the reserved scalar.
    #[inline]
    #[must_use]
    pub const fn reserved3(&self) -> u32 {
        self.reserved3
    }
    /// Return the extra SID count.
    #[inline]
    #[must_use]
    pub const fn sid_count(&self) -> u32 {
        self.sid_count
    }
    /// Borrow extra SIDs.
    #[inline]
    #[must_use]
    pub fn extra_sids(&self) -> &[SidAndAttributes] {
        &self.extra_sids
    }
    /// Borrow the resource domain SID.
    #[inline]
    #[must_use]
    pub const fn resource_group_domain_sid(&self) -> Option<&Sid> {
        self.resource_group_domain_sid.as_ref()
    }
    /// Return resource group count.
    #[inline]
    #[must_use]
    pub const fn resource_group_count(&self) -> u32 {
        self.resource_group_count
    }
    /// Borrow resource groups.
    #[inline]
    #[must_use]
    pub fn resource_group_ids(&self) -> &[GroupMembership] {
        &self.resource_group_ids
    }
    /// Borrow the session-key owner; callers must erase any copies they create.
    #[inline]
    #[must_use]
    pub const fn user_session_key(&self) -> &session_key::SessionKey {
        &self.user_session_key
    }

    /// Replace the session key, erasing the previous owner's live bytes on drop.
    #[inline]
    pub fn set_user_session_key(&mut self, value: session_key::SessionKey) {
        self.user_session_key = value;
    }

    /// Parse NDR-encoded `KERB_VALIDATION_INFO`.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] when the NDR encoding is malformed: a bad wrapper
    /// ([`Error::TooShort`], [`Error::InvalidNdrHeader`], [`Error::InvalidNdrObjectLength`]),
    /// truncated data ([`Error::Truncated`]), a null or inconsistent pointer, count, SID or
    /// string, or non-zero trailing bytes ([`Error::TrailingNdrBytes`]).
    #[inline]
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        read_ndr_wrapper(&mut reader, "KERB_VALIDATION_INFO")?;
        let info = Self::read_fields(&mut reader)?;
        reader.align(4)?;
        if reader.remaining_bytes().iter().any(|byte| *byte != 0) {
            return Err(Error::TrailingNdrBytes {
                remaining: reader.remaining(),
            });
        }
        Ok(info)
    }

    /// Reads the fixed fields and the deferred pointers after the NDR wrapper.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`] when the buffer ends early, and the
    /// errors of the deferred string, SID and group readers.
    fn read_fields(reader: &mut Reader<'_>) -> Result<Self, Error> {
        let logon_time = reader.read_filetime()?;
        let logoff_time = reader.read_filetime()?;
        let kickoff_time = reader.read_filetime()?;
        let password_last_set = reader.read_filetime()?;
        let password_can_change = reader.read_filetime()?;
        let password_must_change = reader.read_filetime()?;

        let effective_name_desc = RpcUnicodeStringDescriptor::read(reader)?;
        let full_name_desc = RpcUnicodeStringDescriptor::read(reader)?;
        let logon_script_desc = RpcUnicodeStringDescriptor::read(reader)?;
        let profile_path_desc = RpcUnicodeStringDescriptor::read(reader)?;
        let home_directory_desc = RpcUnicodeStringDescriptor::read(reader)?;
        let home_directory_drive_desc = RpcUnicodeStringDescriptor::read(reader)?;

        let logon_count = reader.read_u16()?;
        let bad_password_count = reader.read_u16()?;
        let user_id = reader.read_u32()?;
        let primary_group_id = reader.read_u32()?;
        let group_count = reader.read_u32()?;
        let group_ids_ref = reader.read_u32()?;
        let user_flags = reader.read_u32()?;
        let user_session_key = session_key::SessionKey::new(Zeroizing::new(reader.read_array()?));

        let logon_server_desc = RpcUnicodeStringDescriptor::read(reader)?;
        let logon_domain_name_desc = RpcUnicodeStringDescriptor::read(reader)?;
        let logon_domain_id_ref = reader.read_u32()?;
        let reserved1 = [reader.read_u32()?, reader.read_u32()?];
        let user_account_control = reader.read_u32()?;
        let sub_auth_status = reader.read_u32()?;
        let last_successful_ilogon = reader.read_filetime()?;
        let last_failed_ilogon = reader.read_filetime()?;
        let failed_ilogon_count = reader.read_u32()?;
        let reserved3 = reader.read_u32()?;
        let sid_count = reader.read_u32()?;
        let extra_sids_ref = reader.read_u32()?;
        let resource_group_domain_sid_ref = reader.read_u32()?;
        let resource_group_count = reader.read_u32()?;
        let resource_group_ids_ref = reader.read_u32()?;

        let effective_name =
            read_deferred_unicode_string(reader, effective_name_desc, "EffectiveName")?;
        let full_name = read_deferred_unicode_string(reader, full_name_desc, "FullName")?;
        let logon_script = read_deferred_unicode_string(reader, logon_script_desc, "LogonScript")?;
        let profile_path = read_deferred_unicode_string(reader, profile_path_desc, "ProfilePath")?;
        let home_directory =
            read_deferred_unicode_string(reader, home_directory_desc, "HomeDirectory")?;
        let home_directory_drive =
            read_deferred_unicode_string(reader, home_directory_drive_desc, "HomeDirectoryDrive")?;
        let group_ids =
            read_deferred_group_memberships(reader, group_ids_ref, group_count, "GroupIDs")?;
        let logon_server = read_deferred_unicode_string(reader, logon_server_desc, "LogonServer")?;
        let logon_domain_name =
            read_deferred_unicode_string(reader, logon_domain_name_desc, "LogonDomainName")?;
        let logon_domain_id = read_deferred_sid(reader, logon_domain_id_ref, "LogonDomainID")?;
        let extra_sids =
            read_deferred_sid_and_attributes(reader, extra_sids_ref, sid_count, "ExtraSIDs")?;
        let resource_group_domain_sid = read_deferred_sid(
            reader,
            resource_group_domain_sid_ref,
            "ResourceGroupDomainSID",
        )?;
        let resource_group_ids = read_deferred_group_memberships(
            reader,
            resource_group_ids_ref,
            resource_group_count,
            "ResourceGroupIDs",
        )?;

        Ok(Self {
            logon_time,
            logoff_time,
            kickoff_time,
            password_last_set,
            password_can_change,
            password_must_change,
            effective_name,
            full_name,
            logon_script,
            profile_path,
            home_directory,
            home_directory_drive,
            logon_count,
            bad_password_count,
            user_id,
            primary_group_id,
            group_count,
            group_ids,
            user_flags,
            user_session_key,
            logon_server,
            logon_domain_name,
            logon_domain_id,
            reserved1,
            user_account_control,
            sub_auth_status,
            last_successful_ilogon,
            last_failed_ilogon,
            failed_ilogon_count,
            reserved3,
            sid_count,
            extra_sids,
            resource_group_domain_sid,
            resource_group_count,
            resource_group_ids,
        })
    }

    #[must_use]
    /// Return SIDs for domain groups, extra SIDs, and resource groups.
    #[inline]
    pub fn group_membership_sids(&self) -> Vec<String> {
        let mut sids = Vec::new();
        let mut seen = HashSet::new();
        if let Some(domain_sid) = &self.logon_domain_id {
            for group in &self.group_ids {
                let sid = format!("{domain_sid}-{}", group.relative_id);
                if seen.insert(sid.clone()) {
                    sids.push(sid);
                }
            }
        }
        for extra_sid in &self.extra_sids {
            let sid = extra_sid.sid.to_string();
            if seen.insert(sid.clone()) {
                sids.push(sid);
            }
        }
        if let Some(resource_domain_sid) = &self.resource_group_domain_sid {
            for group in &self.resource_group_ids {
                let sid = format!("{resource_domain_sid}-{}", group.relative_id);
                if seen.insert(sid.clone()) {
                    sids.push(sid);
                }
            }
        }
        sids
    }

    /// Return a gokrb5-style AD credential summary.
    #[inline]
    pub fn ad_credentials(&self) -> AdCredentials {
        AdCredentials {
            effective_name: self.effective_name.value.clone(),
            full_name: self.full_name.value.clone(),
            user_id: self.user_id,
            primary_group_id: self.primary_group_id,
            logon_time: self.logon_time.system_time(),
            logoff_time: self.logoff_time.system_time(),
            password_last_set: self.password_last_set.system_time(),
            group_membership_sids: self.group_membership_sids(),
            logon_domain_name: self.logon_domain_name.value.clone(),
            logon_domain_id: self.logon_domain_id.as_ref().map(ToString::to_string),
            logon_server: self.logon_server.value.clone(),
        }
    }
}

/// Decompresses `bytes` with algorithm `A`, requiring exactly
/// `uncompressed_size` output bytes.
///
/// # Errors
///
/// Returns [`Error::ClaimsDecompression`] when decompression fails,
/// [`Error::LengthOverflow`] when `uncompressed_size` does not fit in `usize`,
/// and [`Error::ClaimsDecompressedSizeMismatch`] for any other output length.
fn decompress_claims_set_bytes<A>(
    compression_format: u16,
    bytes: &[u8],
    uncompressed_size: u32,
) -> Result<Vec<u8>, Error>
where
    A: Algorithm,
{
    let decoded =
        decompress_to_vec_capped::<A>(bytes, u64::from(uncompressed_size)).map_err(|error| {
            Error::ClaimsDecompression {
                compression_format,
                message: error.to_string(),
            }
        })?;
    let actual = decoded.len();
    let expected =
        usize::try_from(uncompressed_size).map_err(|_out_of_range| Error::LengthOverflow)?;
    if actual != expected {
        return Err(Error::ClaimsDecompressedSizeMismatch {
            compression_format,
            expected,
            actual,
        });
    }
    Ok(decoded)
}

/// Signature byte length of a PAC checksum type, or `None` when unknown.
const fn checksum_signature_len(signature_type: u32) -> Option<usize> {
    match signature_type {
        CHECKSUM_HMAC_MD5_UNSIGNED | CHECKSUM_HMAC_SHA256_128_AES128 => Some(16),
        CHECKSUM_HMAC_SHA1_96_AES128 | CHECKSUM_HMAC_SHA1_96_AES256 => Some(12),
        CHECKSUM_HMAC_SHA384_192_AES256 => Some(24),
        _ => None,
    }
}

/// Converts a count of `FILETIME` ticks into a [`Duration`].
const fn filetime_tick_duration(ticks: u64) -> Duration {
    let seconds = ticks.div_euclid(WINDOWS_TICKS_PER_SECOND);
    // Below 10^7 ticks, so the nanosecond product stays below 10^9.
    let sub_second_ticks = ticks.rem_euclid(WINDOWS_TICKS_PER_SECOND);
    Duration::from_secs(seconds).saturating_add(Duration::from_nanos(
        sub_second_ticks.saturating_mul(NANOS_PER_WINDOWS_TICK),
    ))
}

/// Mapping between PAC wire checksums and Kerberos enctypes.
mod checksum_mapping;
use checksum_mapping::kerberos_etype_for_checksum_type;

/// Whether the numeric NTLM validity mask is set; reserved bits are ignored.
const fn ntlm_supplemental_flag_set(flags: u32, flag: u32) -> bool {
    flags & flag != 0
}

/// Returns `bytes[offset..offset + len]` of the named `target`.
///
/// # Errors
///
/// Returns [`Error::LengthOverflow`] when the end offset overflows `usize` and
/// [`Error::OutOfBounds`] when the range ends past `bytes`.
fn checked_slice<'bytes>(
    bytes: &'bytes [u8],
    offset: usize,
    len: usize,
    target: &'static str,
) -> Result<&'bytes [u8], Error> {
    let end = offset.checked_add(len).ok_or(Error::LengthOverflow)?;
    bytes.get(offset..end).ok_or(Error::OutOfBounds {
        target,
        offset,
        len,
        total_len: bytes.len(),
    })
}

/// Decodes UTF-16LE `bytes` of the named `target`.
///
/// # Errors
///
/// Returns [`Error::InvalidUtf16Length`] for an odd byte length and
/// [`Error::InvalidUtf16`] for invalid UTF-16.
fn utf16le_bytes_to_string(bytes: &[u8], target: &'static str) -> Result<String, Error> {
    if !bytes.len().is_multiple_of(2) {
        return Err(Error::InvalidUtf16Length {
            target,
            bytes: bytes.len(),
        });
    }

    String::from_utf16le(bytes).map_err(|error| Error::InvalidUtf16 {
        target,
        message: error.to_string(),
    })
}

use crate::error::Pac as Error;

// `PAC_ATTRIBUTES_INFO` and `PAC_REQUESTOR` (MS-PAC 2.14 and 2.15), included into `pac`.
//
// MIT krb5 1.22.2 only names the buffer types (`KRB5_PAC_ATTRIBUTES_INFO` 17 and
// `KRB5_PAC_REQUESTOR` 18, `src/include/krb5/krb5.hin` lines 8170-8171) and never
// decodes them; the layouts follow MS-PAC and the Samba IDL (`krb5pac.idl`).

/// Most flag bits `PAC_ATTRIBUTES_INFO` may declare; Windows and Samba declare two.
const MAX_FLAG_BITS: u32 = 1024;
/// MS-PAC `PAC_WAS_REQUESTED`: the client asked for the PAC.
const PAC_WAS_REQUESTED: u32 = 0x1;
/// MS-PAC `PAC_WAS_GIVEN_IMPLICITLY`: the KDC included the PAC without a request.
const PAC_WAS_GIVEN_IMPLICITLY: u32 = 0x2;
/// Most sub-authorities of a SID (MS-DTYP 2.4.2).
const MAX_SUB_AUTHORITIES: u8 = 15;

/// `PAC_ATTRIBUTES_INFO`: how the PAC came to be in the ticket (MS-PAC 2.14).
///
/// This is claim metadata of the KDC, not authorization: read it from a
/// [`Verified`] only.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct AttributesInfo {
    /// Number of meaningful bits in `flags`.
    flags_length: u32,
    /// The flag words, least significant word first.
    flags: Vec<u32>,
}

impl AttributesInfo {
    /// The number of meaningful flag bits the buffer declares.
    #[inline]
    #[must_use]
    pub const fn flags_length(&self) -> u32 {
        self.flags_length
    }

    /// The first flag word (`PAC_WAS_REQUESTED` is bit 0, `PAC_WAS_GIVEN_IMPLICITLY` bit 1).
    #[inline]
    #[must_use]
    pub fn flags(&self) -> u32 {
        self.flags.first().copied().unwrap_or_default()
    }

    /// Whether the client asked for the PAC (`PA-PAC-REQUEST`, MS-KILE 3.3.5.7.4).
    #[inline]
    #[must_use]
    pub fn was_requested(&self) -> bool {
        self.flags() & PAC_WAS_REQUESTED != 0
    }

    /// Whether the KDC added the PAC without the client asking for it.
    #[inline]
    #[must_use]
    pub fn was_given_implicitly(&self) -> bool {
        self.flags() & PAC_WAS_GIVEN_IMPLICITLY != 0
    }

    /// Parse a `PAC_ATTRIBUTES_INFO` buffer: a bit count and the words that hold the bits.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`] for a short buffer, [`Error::UnreasonableNdrCount`]
    /// when more than 1024 flag bits are declared, and
    /// [`Error::TrailingNdrBytesAfter`] when non-zero bytes follow the flags.
    #[inline]
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        let flags_length = reader.read_u32()?;
        if flags_length > MAX_FLAG_BITS {
            return Err(Error::UnreasonableNdrCount {
                target: "PAC_ATTRIBUTES_INFO.FlagsLength",
                count: flags_length,
            });
        }
        let words = flags_length.div_ceil(32);
        let mut flags = Vec::new();
        for _ in 0..words {
            flags.push(reader.read_u32()?);
        }
        ensure_zero_trailing(&mut reader, "PAC_ATTRIBUTES_INFO")?;
        Ok(Self {
            flags_length,
            flags,
        })
    }
}

/// `PAC_REQUESTOR`: the SID of the account that requested the ticket (MS-PAC 2.15).
///
/// It is claim metadata of the KDC, not authorization: read it from a
/// [`Verified`] only.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct RequestorSid {
    /// The requestor's SID.
    sid: Sid,
}

impl RequestorSid {
    /// Borrow the SID.
    #[inline]
    #[must_use]
    pub const fn sid(&self) -> &Sid {
        &self.sid
    }

    /// Parse a `PAC_REQUESTOR` buffer: one plain (not NDR-wrapped) `SID`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidSidRevision`] for a revision other than one,
    /// [`Error::InvalidSidSubAuthorityCount`] for more than 15 sub-authorities,
    /// [`Error::Truncated`] for a short buffer and
    /// [`Error::TrailingNdrBytesAfter`] when non-zero bytes follow the SID.
    #[inline]
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        let revision = reader.read_u8()?;
        let count = reader.read_u8()?;
        if revision != 1 {
            return Err(Error::InvalidSidRevision(revision));
        }
        if count > MAX_SUB_AUTHORITIES {
            return Err(Error::InvalidSidSubAuthorityCount {
                target: "PAC_REQUESTOR",
                max_count: u32::from(MAX_SUB_AUTHORITIES),
                actual_count: count,
            });
        }
        let identifier_authority: [u8; 6] = reader.read_array()?;
        let mut sub_authorities = Vec::new();
        for _ in 0..count {
            sub_authorities.push(reader.read_u32()?);
        }
        ensure_zero_trailing(&mut reader, "PAC_REQUESTOR")?;
        Ok(Self {
            sid: Sid {
                revision,
                identifier_authority,
                sub_authorities,
            },
        })
    }
}

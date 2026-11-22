// `PA-PAC-REQUEST`, included into `pac` (feature `messages`).
//
// MS-KILE 2.2.2 `KERB-PA-PAC-REQUEST` (padata type 128) lets a client ask a KDC to include or to
// leave out the PAC. MIT krb5 1.22.2 sends none and a KDC of its own ignores it
// (`src/include/krb5/krb5.hin:1830` only names the type); Active Directory honours it, and Samba
// reports the outcome in `PAC_ATTRIBUTES_INFO`.

/// The `PA-PAC-REQUEST` padata type.
pub const PA_PAC_REQUEST: i32 = 128;

/// `KERB-PA-PAC-REQUEST`: whether the client wants the PAC in its tickets.
///
/// ```text
/// KERB-PA-PAC-REQUEST ::= SEQUENCE { include-pac[0] BOOLEAN }
/// ```
#[derive(AsnType, Clone, Copy, Debug, Decode, Encode, Eq, PartialEq)]
#[non_exhaustive]
pub struct Request {
    /// Whether the KDC should include the PAC.
    #[rasn(tag(explicit(0)))]
    include_pac: bool,
}

impl Request {
    /// Ask the KDC to include the PAC.
    #[inline]
    #[must_use]
    pub const fn include() -> Self {
        Self { include_pac: true }
    }

    /// Ask the KDC to leave the PAC out.
    #[inline]
    #[must_use]
    pub const fn exclude() -> Self {
        Self { include_pac: false }
    }

    /// Whether the client wants the PAC.
    #[inline]
    #[must_use]
    pub const fn include_pac(self) -> bool {
        self.include_pac
    }

    /// Decode a DER `KERB-PA-PAC-REQUEST`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DerDecode`] when `bytes` is not exactly one `KERB-PA-PAC-REQUEST`.
    #[inline]
    pub fn decode_der(bytes: &[u8]) -> Result<Self, Error> {
        decode_complete::<Self>(bytes).map_err(Error::DerDecode)
    }

    /// Encode the request as DER.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DerEncode`] when the encoder fails.
    #[inline]
    pub fn encode_der(self) -> Result<Vec<u8>, Error> {
        der_encode(&self).map_err(|source| Error::DerEncode(source.to_string()))
    }

    /// The `PA-DATA` element that carries this request in an AS-REQ.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DerEncode`] when the encoder fails.
    #[inline]
    pub fn padata(self) -> Result<rasn_kerberos::PaData, Error> {
        Ok(rasn_kerberos::PaData {
            r#type: PA_PAC_REQUEST,
            value: self.encode_der()?.into(),
        })
    }
}

use super::Error;

/// GSS-API object identifier.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ObjectIdentifier(Vec<u32>);

impl ObjectIdentifier {
    #[must_use]
    /// Kerberos 5 mechanism OID: `1.2.840.113554.1.2.2`.
    #[inline]
    pub fn krb5() -> Self {
        Self(vec![1, 2, 840, 113_554, 1, 2, 2])
    }

    #[must_use]
    /// Microsoft legacy Kerberos mechanism OID: `1.2.840.48018.1.2.2`.
    #[inline]
    pub fn ms_legacy_krb5() -> Self {
        Self(vec![1, 2, 840, 48_018, 1, 2, 2])
    }

    #[must_use]
    /// SPNEGO mechanism OID: `1.3.6.1.5.5.2`.
    #[inline]
    pub fn spnego() -> Self {
        Self(vec![1, 3, 6, 1, 5, 5, 2])
    }

    #[must_use]
    /// `NegoEx` pseudo-mechanism OID (MS-NEGOEX 1.9, MIT `NEGOEX_OID`): `1.3.6.1.4.1.311.2.2.30`.
    #[inline]
    pub fn negoex() -> Self {
        Self(vec![1, 3, 6, 1, 4, 1, 311, 2, 2, 30])
    }

    /// The DER content octets (no tag, no length), the form of
    /// [`GssMechanism::oid`](crate::extensions::GssMechanism::oid).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidOid`] when the arcs are invalid.
    #[inline]
    pub fn to_der_content(&self) -> Result<Vec<u8>, Error> {
        let element = super::der::encode_oid(self)?;
        Ok(
            super::der::read_single_tlv(&element, super::TAG_OBJECT_IDENTIFIER)?
                .value()
                .to_vec(),
        )
    }

    /// An object identifier from DER content octets.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidOidEncoding`] for empty, truncated or nonminimal
    /// content or an arc wider than 32 bits, and [`Error::InvalidOid`] for invalid arcs.
    #[inline]
    pub fn from_der_content(content: &[u8]) -> Result<Self, Error> {
        super::der::decode_oid_value(content)
    }

    /// Construct an object identifier from arcs.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidOid`] when there are fewer than two arcs, the
    /// first arc exceeds 2, or the second arc is 40 or more under a first arc
    /// of 0 or 1.
    #[inline]
    pub fn from_arcs(arcs: Vec<u32>) -> Result<Self, Error> {
        validate_arcs(&arcs)?;
        Ok(Self(arcs))
    }

    /// An object identifier of arcs the crate knows to be valid.
    #[must_use]
    pub(crate) fn from_static(arcs: &[u32]) -> Self {
        Self(arcs.to_vec())
    }

    #[must_use]
    /// OID arcs.
    #[inline]
    pub fn arcs(&self) -> &[u32] {
        &self.0
    }

    #[must_use]
    /// Whether this OID is one of the Kerberos mechanism OIDs accepted by
    /// gokrb5's SPNEGO verifier.
    #[inline]
    pub fn is_kerberos_mechanism(&self) -> bool {
        self == &Self::krb5() || self == &Self::ms_legacy_krb5()
    }
}

/// Check the X.660 constraints on the first two arcs of an object identifier.
///
/// # Errors
///
/// Returns [`Error::InvalidOid`] when there are fewer than two arcs, the first
/// arc exceeds 2, or the second arc is 40 or more under a first arc of 0 or 1.
pub(super) const fn validate_arcs(arcs: &[u32]) -> Result<(), Error> {
    let [first, second, ..] = *arcs else {
        return Err(Error::InvalidOid);
    };
    if first > 2 || (first < 2 && second >= 40) {
        return Err(Error::InvalidOid);
    }
    Ok(())
}

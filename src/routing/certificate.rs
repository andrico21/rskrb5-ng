/// The user identity of a certificate `S4U2Self` request.
///
/// MS-SFU 2.2.2 `S4UUserID`, MIT 1.22.2 `krb5_get_credentials_for_user` with a
/// subject certificate: the user's DER X.509 certificate, the user's realm,
/// and optionally the requested user name (empty: the KDC names the user from
/// the certificate).
///
/// This type parses nothing: the KDC maps the certificate to a user and the
/// crate binds the issued ticket to the user name the KDC returns under the
/// request checksum. A certificate parser checks the bytes before they are sent
/// through [`CertificateInspector`] (the seam the `pkinit` leaf can implement).
///
/// # Security
///
/// The certificate is public data; its `Debug` form shows only its size.
#[derive(Clone, Eq, PartialEq)]
pub struct CertificateIdentity {
    /// DER X.509 certificate of the user.
    certificate: Vec<u8>,
    /// Realm of the user, which the request is sent to first.
    realm: String,
    /// Requested user name components; empty lets the KDC choose.
    name: Vec<String>,
}

impl CertificateIdentity {
    /// Largest accepted certificate, in bytes.
    pub const MAX_CERTIFICATE_BYTES: usize = 0x0001_0000;

    /// An identity for the user of `certificate` in `realm`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CertificateSize`] for an empty certificate or one past
    /// [`Self::MAX_CERTIFICATE_BYTES`], and [`Error::EmptyRealm`] for an empty
    /// realm.
    #[inline]
    pub fn new<R>(certificate: Vec<u8>, realm: R) -> Result<Self, Error>
    where
        R: Into<String>,
    {
        if certificate.is_empty() || certificate.len() > Self::MAX_CERTIFICATE_BYTES {
            return Err(Error::CertificateSize {
                max: Self::MAX_CERTIFICATE_BYTES,
            });
        }
        let user_realm = realm.into();
        if user_realm.is_empty() {
            return Err(Error::EmptyRealm);
        }
        Ok(Self {
            certificate,
            realm: user_realm,
            name: Vec::new(),
        })
    }

    /// Request this user name instead of letting the KDC choose one.
    #[inline]
    #[must_use]
    pub fn with_name<I, S>(mut self, components: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.name = components.into_iter().map(Into::into).collect();
        self
    }

    /// Check the certificate with `inspector` before it is sent.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CertificateRejected`] carrying the inspector's refusal.
    #[inline]
    pub fn inspected(self, inspector: &dyn CertificateInspector) -> Result<Self, Error> {
        inspector
            .inspect(&self.certificate)
            .map_err(Error::CertificateRejected)?;
        Ok(self)
    }

    /// The DER certificate.
    #[inline]
    #[must_use]
    pub fn certificate(&self) -> &[u8] {
        &self.certificate
    }

    /// The user's realm.
    #[inline]
    #[must_use]
    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// The requested user name components; empty when the KDC chooses.
    #[inline]
    #[must_use]
    pub fn name(&self) -> &[String] {
        &self.name
    }
}

impl fmt::Debug for CertificateIdentity {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f
            .debug_struct("CertificateIdentity")
            .field(
                "certificate",
                &format_args!("{} bytes", self.certificate.len()),
            )
            .field("realm", &self.realm)
            .field("name", &self.name)
            .finish()
    }
}

/// Parse and validate the certificate of a certificate `S4U2Self` request before it
/// is sent: the seam a certificate parser (the `pkinit` leaf's) implements.
pub trait CertificateInspector: Send + Sync {
    /// Accept or refuse the DER certificate.
    ///
    /// # Errors
    ///
    /// Returns the refusal, which the caller receives as
    /// [`Error::CertificateRejected`].
    fn inspect(&self, certificate: &[u8]) -> Result<(), ProviderError>;
}

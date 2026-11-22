// The verified PAC and the checks it passed, included into `pac`.

/// Which checks a [`Verified`] PAC passed.
///
/// A signature whose requirement was [`SignatureRequirement::IfPresent`] and whose inputs were not
/// supplied did not verify: the PAC is verified, that signature is not.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct VerifiedChecks {
    /// One bit per check, in the order of [`VerifiedChecks::from_results`].
    bits: u8,
}

impl VerifiedChecks {
    /// Bit of the server signature.
    const SERVER: u8 = 1;
    /// Bit of the KDC signature.
    const KDC: u8 = 2;
    /// Bit of the ticket signature.
    const TICKET: u8 = 4;
    /// Bit of the full checksum.
    const FULL: u8 = 8;
    /// Bit of the client binding.
    const CLIENT: u8 = 16;

    /// Pack the results of `[server, kdc, ticket, full, client]`.
    pub(super) fn from_results(results: [bool; 5]) -> Self {
        let masks = [
            Self::SERVER,
            Self::KDC,
            Self::TICKET,
            Self::FULL,
            Self::CLIENT,
        ];
        let bits = results
            .into_iter()
            .zip(masks)
            .filter(|(passed, _)| *passed)
            .fold(0, |bits, (_, mask)| bits | mask);
        Self { bits }
    }

    /// The server signature verified under the service key.
    #[inline]
    #[must_use]
    pub const fn server(self) -> bool {
        self.bits & Self::SERVER != 0
    }

    /// The KDC signature verified under the KDC key.
    #[inline]
    #[must_use]
    pub const fn kdc(self) -> bool {
        self.bits & Self::KDC != 0
    }

    /// The ticket signature verified under the KDC key.
    #[inline]
    #[must_use]
    pub const fn ticket(self) -> bool {
        self.bits & Self::TICKET != 0
    }

    /// The full checksum (KB5020805) verified under the KDC key.
    #[inline]
    #[must_use]
    pub const fn full(self) -> bool {
        self.bits & Self::FULL != 0
    }

    /// The client info named the ticket's client and authentication time.
    #[inline]
    #[must_use]
    pub const fn client(self) -> bool {
        self.bits & Self::CLIENT != 0
    }
}

/// A PAC that passed [`Pac::verify_ext`] under an explicit policy.
///
/// Only verification constructs it, and it has no mutator: the data it shows was checked.
/// [`Verified::checks`] says which signatures that included.
///
/// ```compile_fail
/// // A verified PAC cannot be assembled from parts.
/// use rskrb5_ng::pac::{Pac, Verified};
/// fn forge(pac: Pac) -> Verified {
///     Verified { pac }
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Verified {
    /// The verified PAC.
    pac: Pac,
    /// The checks it passed.
    checks: VerifiedChecks,
}

impl Verified {
    /// The checks this PAC passed.
    #[inline]
    #[must_use]
    pub const fn checks(&self) -> VerifiedChecks {
        self.checks
    }

    /// Borrow the verified PAC container.
    #[inline]
    #[must_use]
    pub const fn pac(&self) -> &Pac {
        &self.pac
    }

    /// Borrow the validation info, when the KDC sent it.
    #[inline]
    #[must_use]
    pub const fn kerb_validation_info(&self) -> Option<&KerbValidationInfo> {
        self.pac.kerb_validation_info()
    }

    /// The AD credential summary of the validation info, when present.
    #[inline]
    #[must_use]
    pub fn ad_credentials(&self) -> Option<AdCredentials> {
        self.pac.ad_credentials()
    }

    /// Borrow the client info.
    #[inline]
    #[must_use]
    pub const fn client_info(&self) -> Option<&ClientInfo> {
        self.pac.client_info()
    }

    /// Borrow the UPN and DNS info.
    #[inline]
    #[must_use]
    pub const fn upn_dns_info(&self) -> Option<&UpnDnsInfo> {
        self.pac.upn_dns_info()
    }

    /// Borrow the delegation info.
    #[inline]
    #[must_use]
    pub const fn s4u_delegation_info(&self) -> Option<&S4UDelegationInfo> {
        self.pac.s4u_delegation_info()
    }

    /// Borrow the device info.
    #[inline]
    #[must_use]
    pub const fn device_info(&self) -> Option<&DeviceInfo> {
        self.pac.device_info()
    }

    /// Borrow the client claims; a zero-length claims buffer is no claims.
    #[inline]
    #[must_use]
    pub const fn client_claims_info(&self) -> Option<&ClaimsInfo> {
        self.pac.client_claims_info()
    }

    /// Borrow the device claims.
    #[inline]
    #[must_use]
    pub const fn device_claims_info(&self) -> Option<&ClaimsInfo> {
        self.pac.device_claims_info()
    }

    /// Borrow the encrypted credentials.
    #[inline]
    #[must_use]
    pub const fn credentials_info(&self) -> Option<&CredentialsInfo> {
        self.pac.credentials_info()
    }

    /// Borrow the PAC attributes (how the PAC came to be in the ticket).
    #[inline]
    #[must_use]
    pub const fn attributes_info(&self) -> Option<&AttributesInfo> {
        self.pac.attributes_info()
    }

    /// Borrow the requestor SID.
    #[inline]
    #[must_use]
    pub const fn requestor_sid(&self) -> Option<&RequestorSid> {
        self.pac.requestor_sid()
    }
}

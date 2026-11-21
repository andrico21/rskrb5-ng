//! MS-SFU 2.2.2 `PA-S4U-X509-USER`: the checksummed user identity of an
//! `S4U2Self` request, by name or by certificate (MIT 1.22.2
//! `src/lib/krb5/krb/s4u_creds.c:193-397`).
//!
//! The request element names the user and the TGS-REQ nonce under a keyed
//! checksum of the request's authenticator subkey (key usage 26); the KDC
//! answers with the same element naming the user it found, under key usage 27
//! when the request set `USE_REPLY_KEY_USAGE`.

use rasn::{
    AsnType, Decode, Decoder as _, Encode, Encoder as _, der,
    types::{BitString, OctetString},
};

use crate::{
    crypto::{CryptoPolicy, Use, selection},
    error::{Client as Error, Crypto},
};

/// `PA-S4U-X509-USER` padata type.
pub const PA_S4U_X509_USER: i32 = 130;
/// Key usage of the request checksum (`KRB5_KEYUSAGE_PA_S4U_X509_USER_REQUEST`).
pub const REQUEST_USAGE: u32 = 26;
/// Key usage of the reply checksum (`KRB5_KEYUSAGE_PA_S4U_X509_USER_REPLY`).
pub const REPLY_USAGE: u32 = 27;
/// `S4UUserID` option: the KDC checksums its reply with [`REPLY_USAGE`].
pub const USE_REPLY_KEY_USAGE: u32 = 0x2000_0000;

/// MS-SFU `S4UUserID`.
#[derive(AsnType, Clone, Debug, Decode, Encode, Eq, PartialEq)]
#[non_exhaustive]
pub struct UserId {
    /// The nonce of the TGS-REQ body.
    #[rasn(tag(explicit(0)))]
    pub nonce: u32,
    /// The user's name; absent when the KDC names the user from the certificate.
    #[rasn(tag(explicit(1)))]
    pub cname: Option<rasn_kerberos::PrincipalName>,
    /// The user's realm.
    #[rasn(tag(explicit(2)))]
    pub crealm: rasn_kerberos::Realm,
    /// The user's DER X.509 certificate.
    #[rasn(tag(explicit(3)))]
    pub subject_certificate: Option<OctetString>,
    /// `KERB-S4U-OPTIONS` flags.
    #[rasn(tag(explicit(4)))]
    pub options: Option<BitString>,
}

/// MS-SFU `PA-S4U-X509-USER`.
#[derive(AsnType, Clone, Debug, Decode, Encode, Eq, PartialEq)]
#[non_exhaustive]
pub struct PaS4uX509User {
    /// The user identity.
    #[rasn(tag(explicit(0)))]
    pub user_id: UserId,
    /// The keyed checksum over the DER `user_id`.
    #[rasn(tag(explicit(1)))]
    pub checksum: rasn_kerberos::Checksum,
}

impl UserId {
    /// An identity for `crealm` with `nonce`, the options set to
    /// [`USE_REPLY_KEY_USAGE`] as MIT does (`s4u_creds.c:471`).
    #[must_use]
    #[inline]
    pub fn new(
        nonce: u32,
        cname: Option<rasn_kerberos::PrincipalName>,
        crealm: rasn_kerberos::Realm,
        subject_certificate: Option<Vec<u8>>,
    ) -> Self {
        Self {
            nonce,
            cname,
            crealm,
            subject_certificate: subject_certificate.map(OctetString::from),
            options: Some(BitString::from_slice(&USE_REPLY_KEY_USAGE.to_be_bytes())),
        }
    }

    /// Whether the KDC checksums its reply with [`REPLY_USAGE`].
    #[must_use]
    #[inline]
    pub fn uses_reply_usage(&self) -> bool {
        self.options.as_ref().is_some_and(|bits| {
            let raw = bits.as_raw_slice();
            raw.first().is_some_and(|first| first & 0x20 != 0)
        })
    }
}

impl PaS4uX509User {
    /// Decode a DER `PA-S4U-X509-USER`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Decode`] when `bytes` is not one.
    #[inline]
    pub fn decode_der(bytes: &[u8]) -> Result<Self, Error> {
        der::decode(bytes).map_err(|error| Error::Decode {
            target: "PA-S4U-X509-USER",
            message: error.to_string(),
        })
    }

    /// Encode as DER.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Encode`] when the encoder fails.
    #[inline]
    pub fn encode_der(&self) -> Result<Vec<u8>, Error> {
        der::encode(self).map_err(|error| Error::Encode {
            target: "PA-S4U-X509-USER",
            message: error.to_string(),
        })
    }

    /// The outgoing admission of the element (`client::crypto_policy::padata`):
    /// it decodes, and its checksum is a keyed checksum of an enctype the policy
    /// permits for a session key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Decode`], the typed refusal of an unkeyed checksum, or
    /// [`Error::Encode`] for a checksum type of no implemented enctype.
    #[inline]
    pub fn admit(policy: &CryptoPolicy, bytes: &[u8]) -> Result<(), Error> {
        let element = Self::decode_der(bytes)?;
        let etype = selection::checksum(element.checksum.r#type)
            .map_err(Crypto::from)?
            .ok_or_else(|| Error::Encode {
                target: "PA-DATA",
                message: format!(
                    "PA-S4U-X509-USER checksum type {} is not supported",
                    element.checksum.r#type
                ),
            })?;
        policy.check_use(etype.etype_id(), Use::SessionKey)?;
        Ok(())
    }
}

//! The RFC 8636 key derivation and the RFC 4556 `octetstring2key` (MIT 1.22.2
//! `pkinit_crypto_openssl.c:2569-2640,2717-2861`).

use rasn::{der as rasn_der, types::OctetString};
use rasn_kerberos::{KerberosString, PrincipalName};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;

use super::asn1::{
    AlgorithmIdentifier, KDF_SHA1, KDF_SHA256, KDF_SHA512, Krb5PrincipalName, OtherInfo,
    PkinitSuppPubInfo, oid,
};
use crate::{
    client::principal::Principal,
    crypto::{KerberosEtype, prf},
    error::Pkinit as Error,
    keytab::EncryptionKey,
};

/// The KDF of an RFC 8636 `id-pkinit-kdf` OID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Kdf {
    /// `id-pkinit-kdf-ah-sha1`.
    Sha1,
    /// `id-pkinit-kdf-ah-sha256`.
    Sha256,
    /// `id-pkinit-kdf-ah-sha512`.
    Sha512,
}

impl Kdf {
    /// The KDFs this client offers, in MIT's order (`pkinit_constants.c:49-54` `supported_kdf_alg_ids`).
    pub(super) const OFFERED: [Self; 3] = [Self::Sha256, Self::Sha1, Self::Sha512];

    /// The OID arcs.
    pub(super) const fn arcs(self) -> &'static [u32] {
        match self {
            Self::Sha1 => KDF_SHA1,
            Self::Sha256 => KDF_SHA256,
            Self::Sha512 => KDF_SHA512,
        }
    }

    /// The KDF of `arcs`, if this client offered it.
    pub(super) fn from_arcs(arcs: &[u32]) -> Option<Self> {
        Self::OFFERED.into_iter().find(|kdf| kdf.arcs() == arcs)
    }
}

/// The inputs both derivations share.
pub(super) struct Inputs<'input> {
    /// The agreed secret `Z`.
    pub secret: &'input [u8],
    /// The reply key's enctype.
    pub etype: i32,
    /// The request's client (`partyUInfo`).
    pub client: &'input Principal,
    /// The request's server (`partyVInfo`).
    pub server: &'input Principal,
    /// The DER AS-REQ as sent.
    pub as_req: &'input [u8],
    /// The DER PA-PK-AS-REP as received.
    pub pk_as_rep: &'input [u8],
}

/// The enctype and its random-to-key seed length.
///
/// # Errors
/// Returns [`Error::UnsupportedAlgorithm`] for an unimplemented enctype.
fn etype_of(etype: i32) -> Result<(KerberosEtype, usize), Error> {
    let kind = KerberosEtype::from_etype_id(etype).ok_or_else(|| Error::UnsupportedAlgorithm {
        algorithm: format!("enctype {etype}"),
    })?;
    Ok((kind, prf::seed_len(kind)))
}

/// The key of `seed` for `etype`.
///
/// # Errors
/// Returns the random-to-key errors.
fn to_key(kind: KerberosEtype, etype: i32, seed: &[u8]) -> Result<EncryptionKey, Error> {
    let key = prf::random_to_key(kind, seed).map_err(Error::Crypto)?;
    Ok(EncryptionKey::new(etype, key.to_vec()))
}

/// RFC 4556 section 3.2.3.1 `octetstring2key`: SHA-1 over a counter byte and
/// `Z`, concatenated to the seed length.
///
/// # Errors
/// Returns [`Error::UnsupportedAlgorithm`] for an unimplemented enctype.
pub(super) fn octetstring2key(secret: &[u8], etype: i32) -> Result<EncryptionKey, Error> {
    let (kind, length) = etype_of(etype)?;
    let mut seed = Zeroizing::new(Vec::with_capacity(length.saturating_add(20)));
    let mut counter = 0_u8;
    while seed.len() < length {
        let block = Sha1::new()
            .chain_update([counter])
            .chain_update(secret)
            .finalize();
        seed.extend_from_slice(&block);
        counter = counter.wrapping_add(1);
    }
    seed.truncate(length);
    to_key(kind, etype, &seed)
}

/// The DER `KRB5PrincipalName` of `principal`; the anonymous client is always
/// `WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS` (MIT `pkinit_kdf`).
///
/// # Errors
/// Returns [`Error::Malformed`] for a name that is not a Kerberos string.
fn party(principal: &Principal) -> Result<OctetString, Error> {
    let anonymous = principal.components == ["WELLKNOWN", "ANONYMOUS"];
    let realm = if anonymous {
        "WELLKNOWN:ANONYMOUS"
    } else {
        principal.realm.as_str()
    };
    let malformed = |_detail| Error::Malformed {
        structure: "KRB5PrincipalName",
        reason: "a name is not a Kerberos string",
    };
    let string = |value: &str| KerberosString::try_from(value.to_owned()).map_err(malformed);
    let name = Krb5PrincipalName {
        realm: string(realm)?,
        principal_name: PrincipalName {
            r#type: principal.name_type,
            string: principal
                .components
                .iter()
                .map(|component| string(component))
                .collect::<Result<_, _>>()?,
        },
    };
    encode("KRB5PrincipalName", &name).map(OctetString::from)
}

/// DER-encode `value`.
///
/// # Errors
/// Returns [`Error::Malformed`] when encoding fails.
pub(super) fn encode<T>(structure: &'static str, value: &T) -> Result<Vec<u8>, Error>
where
    T: rasn::Encode,
{
    rasn_der::encode(value).map_err(|_detail| Error::Malformed {
        structure,
        reason: "cannot be encoded",
    })
}

/// RFC 8636 section 6: `SP 800-56A` single-step KDF over `OtherInfo` with the
/// chosen hash, then random-to-key.
///
/// # Errors
/// Returns the encoding and key errors.
pub(super) fn derive(kdf: Kdf, inputs: &Inputs<'_>) -> Result<EncryptionKey, Error> {
    let (kind, length) = etype_of(inputs.etype)?;
    let supp = PkinitSuppPubInfo {
        enctype: inputs.etype,
        as_req: inputs.as_req.to_vec().into(),
        pk_as_rep: inputs.pk_as_rep.to_vec().into(),
    };
    let info = encode(
        "OtherInfo",
        &OtherInfo {
            algorithm_id: AlgorithmIdentifier {
                algorithm: oid(kdf.arcs()),
                parameters: None,
            },
            party_u_info: party(inputs.client)?,
            party_v_info: party(inputs.server)?,
            supp_pub_info: encode("PkinitSuppPubInfo", &supp)?.into(),
        },
    )?;
    let mut seed = Zeroizing::new(Vec::with_capacity(length.saturating_add(64)));
    let mut counter = 1_u32;
    while seed.len() < length {
        let prefix = counter.to_be_bytes();
        match kdf {
            Kdf::Sha1 => seed.extend_from_slice(&hash::<Sha1>(prefix, inputs.secret, &info)),
            Kdf::Sha256 => seed.extend_from_slice(&hash::<Sha256>(prefix, inputs.secret, &info)),
            Kdf::Sha512 => seed.extend_from_slice(&hash::<Sha512>(prefix, inputs.secret, &info)),
        }
        counter = counter.checked_add(1).ok_or(Error::Malformed {
            structure: "KDF",
            reason: "the counter overflows",
        })?;
    }
    seed.truncate(length);
    to_key(kind, inputs.etype, &seed)
}

/// `H(counter || Z || OtherInfo)` in a zeroizing owner.
fn hash<D>(counter: [u8; 4], secret: &[u8], info: &[u8]) -> Zeroizing<Vec<u8>>
where
    D: Digest,
{
    Zeroizing::new(
        D::new()
            .chain_update(counter)
            .chain_update(secret)
            .chain_update(info)
            .finalize()
            .to_vec(),
    )
}

//! The bounded certificate path validator and the KDC identity checks.
//!
//! The validator works over `x509-cert` (no third-party path validator exists
//! on the `der` 0.8 generation; see `docs/dependency-admission.md#x509-cert`);
//! the identity checks are MIT 1.22.2 `pkinit_clnt.c:344-492`
//! (`verify_kdc_san`, `verify_kdc_eku`).
//!
//! Rules, each a refusal:
//! - a path has at most [`MAX_CHAIN_LENGTH`] certificates and ends at a
//!   configured anchor; at most [`MAX_CERTIFICATES`] candidates and a bounded
//!   number of signature checks are spent on building it;
//! - every certificate is valid at the time of the check;
//! - every issuer below the anchor is a CA (`basicConstraints cA`), allows
//!   `keyCertSign` when it carries a key usage, and honours its path length;
//! - the issuer name of each certificate is the subject of the next, byte for
//!   byte, and its signature verifies under the next one's key;
//! - an unknown critical extension fails the certificate;
//! - a certificate listed by a valid CRL of its issuer is revoked; with CRL
//!   checking required, a certificate whose issuer has no current CRL fails.

use core::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use der::{
    Decode as _, Encode as _,
    oid::{AssociatedOid as _, ObjectIdentifier},
};
use rasn::der as rasn_der;
use rasn_kerberos::KerberosString;
use x509_cert::{
    Certificate,
    crl::CertificateList,
    ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAltName, name::GeneralName},
};

use super::{
    super::{CertificatePolicy, EkuChecking, MAX_CERTIFICATES, MAX_CHAIN_LENGTH},
    asn1::Krb5PrincipalName,
    keys::{self, Hash, Kind},
};
use crate::error::Pkinit as Error;

/// `id-pkinit-san` (RFC 4556 section 3.2.2).
const PKINIT_SAN: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.2.2");
/// `id-pkinit-KPKdc` (RFC 4556 section 3.2.4).
const KP_KDC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.2.3.5");
/// `id-kp-serverAuth` (RFC 5280).
const KP_SERVER_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");
/// The most signature checks one path search may spend.
const MAX_SIGNATURE_CHECKS: usize = 128;

/// A decoded certificate that re-encodes to exactly the bytes received (so
/// the signed `tbsCertificate` is the received one).
pub(super) struct Parsed {
    /// The certificate.
    pub certificate: Certificate,
}

/// Decode `der` strictly.
///
/// # Errors
/// Returns [`Error::Malformed`] for a certificate that is not canonical DER.
pub(super) fn parse(der: &[u8]) -> Result<Parsed, Error> {
    let malformed = |_detail| Error::Malformed {
        structure: "certificate",
        reason: "not a canonical DER X.509 certificate",
    };
    let certificate = Certificate::from_der(der).map_err(malformed)?;
    if certificate.to_der().map_err(malformed)? != der {
        return Err(Error::Malformed {
            structure: "certificate",
            reason: "not a canonical DER X.509 certificate",
        });
    }
    Ok(Parsed { certificate })
}

/// Check `issuer`'s signature on `subject`.
///
/// # Errors
/// Returns the signature errors.
fn signed_by(subject: &Certificate, issuer: &Certificate) -> Result<(), Error> {
    let algorithm = keys::signature_algorithm(&subject.signature_algorithm().oid)?;
    let tbs = subject
        .tbs_certificate()
        .to_der()
        .map_err(|_detail| Error::Malformed {
            structure: "certificate",
            reason: "the tbsCertificate cannot be encoded",
        })?;
    let signature = subject.signature().as_bytes().ok_or(Error::Malformed {
        structure: "certificate",
        reason: "the signature has unused bits",
    })?;
    keys::verify(
        issuer.tbs_certificate().subject_public_key_info(),
        algorithm,
        &tbs,
        signature,
        "certificate",
    )
}

/// Validity at `now` and the critical extensions.
///
/// # Errors
/// Returns [`Error::Certificate`].
fn usable(certificate: &Certificate, now: SystemTime) -> Result<(), Error> {
    let validity = certificate.tbs_certificate().validity();
    let at = since_epoch(now);
    if at < validity.not_before.to_unix_duration() || at > validity.not_after.to_unix_duration() {
        return Err(Error::Certificate {
            reason: "a certificate is outside its validity period",
        });
    }
    let known = [
        BasicConstraints::OID,
        KeyUsage::OID,
        ExtendedKeyUsage::OID,
        SubjectAltName::OID,
    ];
    let unknown = certificate
        .tbs_certificate()
        .extensions()
        .map_or(&[][..], Vec::as_slice)
        .iter()
        .any(|extension| extension.critical && !known.contains(&extension.extn_id));
    if unknown {
        return Err(Error::Certificate {
            reason: "a certificate carries an unknown critical extension",
        });
    }
    Ok(())
}

/// The time since the Unix epoch (zero before it).
fn since_epoch(now: SystemTime) -> Duration {
    now.duration_since(UNIX_EPOCH).unwrap_or_default()
}

/// Whether `issuer` may sign certificates `below` levels under it.
fn may_issue(issuer: &Certificate, below: usize) -> bool {
    let tbs = issuer.tbs_certificate();
    let constraints = tbs.get_extension::<BasicConstraints>().ok().flatten();
    let usage = tbs.get_extension::<KeyUsage>().ok().flatten();
    let ca = constraints.as_ref().is_some_and(|(_, value)| value.ca);
    let length = constraints
        .as_ref()
        .and_then(|(_, value)| value.path_len_constraint)
        .is_none_or(|limit| below <= usize::from(limit));
    let signs = usage.is_none_or(|(_, value)| value.key_cert_sign());
    ca && length && signs
}

/// The search state.
struct Search<'input> {
    /// Candidate intermediates.
    candidates: &'input [Parsed],
    /// The anchors.
    anchors: &'input [Parsed],
    /// The time of the check.
    now: SystemTime,
    /// Signature checks left.
    budget: usize,
}

impl Search<'_> {
    /// A path from `certificate` (at `depth`, with `below` CA levels under its
    /// issuer) to an anchor, issuers first-found.
    ///
    /// # Errors
    /// Returns the first hard failure; `Ok(None)` means no path.
    fn path(
        &mut self,
        certificate: &Certificate,
        depth: usize,
    ) -> Result<Option<Vec<Certificate>>, Error> {
        usable(certificate, self.now)?;
        if depth >= MAX_CHAIN_LENGTH {
            return Ok(None);
        }
        let issuer = certificate.tbs_certificate().issuer();
        let below = depth.saturating_sub(1);
        for anchor in self.anchors {
            if anchor.certificate.tbs_certificate().subject() == issuer
                && self.spend()
                && signed_by(certificate, &anchor.certificate).is_ok()
            {
                usable(&anchor.certificate, self.now)?;
                return Ok(Some(vec![anchor.certificate.clone()]));
            }
        }
        for candidate in self.candidates {
            let parent = &candidate.certificate;
            if parent.tbs_certificate().subject() != issuer
                || parent == certificate
                || !may_issue(parent, below)
                || !self.spend()
                || signed_by(certificate, parent).is_err()
            {
                continue;
            }
            if let Some(mut rest) = self.path(parent, depth.saturating_add(1))? {
                rest.insert(0, parent.clone());
                return Ok(Some(rest));
            }
        }
        Ok(None)
    }

    /// Take one signature check from the budget.
    const fn spend(&mut self) -> bool {
        let left = self.budget > 0;
        self.budget = self.budget.saturating_sub(1);
        left
    }
}

/// Validate `leaf` against `anchors` through `candidates`, then apply `crls`.
///
/// # Errors
/// Returns [`Error::Certificate`] without a path, [`Error::Revoked`] and
/// [`Error::RevocationUnknown`].
pub(super) fn validate(
    leaf: &Certificate,
    (candidates, anchors, crls): (&[Parsed], &[Parsed], &[CertificateList]),
    require_crl: bool,
    now: SystemTime,
) -> Result<(), Error> {
    if candidates.len().saturating_add(anchors.len()) > MAX_CERTIFICATES {
        return Err(Error::Certificate {
            reason: "too many candidate certificates",
        });
    }
    if anchors.iter().any(|anchor| anchor.certificate == *leaf) {
        return usable(leaf, now);
    }
    let mut search = Search {
        candidates,
        anchors,
        now,
        budget: MAX_SIGNATURE_CHECKS,
    };
    let issuers = search.path(leaf, 1)?.ok_or(Error::Certificate {
        reason: "no path to a configured anchor",
    })?;
    let mut subject = leaf;
    for issuer in &issuers {
        revocation(subject, issuer, crls, (require_crl, now))?;
        subject = issuer;
    }
    Ok(())
}

/// The revocation status of `subject` from the CRLs of `issuer`.
///
/// # Errors
/// Returns [`Error::Revoked`] when listed and [`Error::RevocationUnknown`]
/// when CRL checking is required and no current CRL of `issuer` exists, or
/// when the only CRLs of `issuer` are stale (OpenSSL fails then too).
fn revocation(
    subject: &Certificate,
    issuer: &Certificate,
    crls: &[CertificateList],
    (required, now): (bool, SystemTime),
) -> Result<(), Error> {
    let mut stale = false;
    let mut current = false;
    for crl in crls {
        let list = &crl.tbs_cert_list;
        if list.issuer != *issuer.tbs_certificate().subject() || !crl_signed_by(crl, issuer) {
            continue;
        }
        let at = since_epoch(now);
        let fresh = list.this_update.to_unix_duration() <= at
            && list
                .next_update
                .is_none_or(|next| at <= next.to_unix_duration());
        if !fresh {
            stale = true;
            continue;
        }
        current = true;
        let serial = subject.tbs_certificate().serial_number();
        if list
            .revoked_certificates
            .as_deref()
            .unwrap_or_default()
            .iter()
            .any(|entry| entry.serial_number == *serial)
        {
            return Err(Error::Revoked);
        }
    }
    if !current && (required || stale) {
        return Err(Error::RevocationUnknown);
    }
    Ok(())
}

/// Whether `issuer` signed `crl`.
fn crl_signed_by(crl: &CertificateList, issuer: &Certificate) -> bool {
    let Ok(algorithm) = keys::signature_algorithm(&crl.signature_algorithm.oid) else {
        return false;
    };
    let (Ok(tbs), Some(signature)) = (crl.tbs_cert_list.to_der(), crl.signature.as_bytes()) else {
        return false;
    };
    keys::verify(
        issuer.tbs_certificate().subject_public_key_info(),
        algorithm,
        &tbs,
        signature,
        "CRL",
    )
    .is_ok()
}

/// Whether a SAN names the KDC: `krbtgt/REALM@REALM` in an `id-pkinit-san`,
/// or a configured hostname in a dNSName (MIT `verify_kdc_san`).
fn names_kdc(name: &GeneralName, realm: &str, policy: &CertificatePolicy) -> bool {
    if let GeneralName::OtherName(other) = name {
        return other.type_id == PKINIT_SAN
            && other
                .value
                .to_der()
                .ok()
                .and_then(|der| rasn_der::decode::<Krb5PrincipalName>(&der).ok())
                .is_some_and(|principal| {
                    let components: Vec<&[u8]> = principal
                        .principal_name
                        .string
                        .iter()
                        .map(KerberosString::as_bytes)
                        .collect();
                    principal.realm.as_bytes() == realm.as_bytes()
                        && components == [b"krbtgt".as_slice(), realm.as_bytes()]
                });
    }
    if let GeneralName::DnsName(host) = name {
        return policy
            .kdc_hostnames()
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(host.as_str()));
    }
    false
}

/// The KDC identity checks (MIT `verify_kdc_san`, `verify_kdc_eku`).
///
/// The certificate must name the KDC ([`names_kdc`]) and carry the EKU the
/// policy asks for and the `digitalSignature` key usage.
///
/// # Errors
/// Returns [`Error::KdcName`] and [`Error::KeyPurpose`].
pub(super) fn kdc_identity(
    certificate: &Certificate,
    realm: &str,
    policy: &CertificatePolicy,
) -> Result<(), Error> {
    let tbs = certificate.tbs_certificate();
    let alternatives = tbs
        .get_extension::<SubjectAltName>()
        .ok()
        .flatten()
        .map_or_else(Vec::new, |(_, value)| value.0);
    if !alternatives
        .iter()
        .any(|name| names_kdc(name, realm, policy))
    {
        return Err(Error::KdcName {
            realm: realm.to_owned(),
        });
    }
    let accepted: &[ObjectIdentifier] = match policy.eku_checking() {
        EkuChecking::None => return Ok(()),
        EkuChecking::KpKdc => &[KP_KDC],
        EkuChecking::KpServerAuth => &[KP_KDC, KP_SERVER_AUTH],
    };
    let purposes = tbs
        .get_extension::<ExtendedKeyUsage>()
        .ok()
        .flatten()
        .map_or_else(Vec::new, |(_, value)| value.0);
    let signs = tbs
        .get_extension::<KeyUsage>()
        .ok()
        .flatten()
        .is_some_and(|(_, value)| value.digital_signature());
    if purposes.iter().any(|purpose| accepted.contains(purpose)) && signs {
        Ok(())
    } else {
        Err(Error::KeyPurpose)
    }
}

/// The scheme and hash of a CMS signer (`signatureAlgorithm` and `digestAlgorithm`).
///
/// # Errors
/// Returns [`Error::UnsupportedAlgorithm`] and [`Error::Malformed`] for a
/// signature algorithm whose hash differs from the digest algorithm.
pub(super) fn signer_algorithm(
    signature: &ObjectIdentifier,
    digest: &ObjectIdentifier,
) -> Result<(Kind, Hash), Error> {
    let hash = Hash::from_oid(digest).ok_or_else(|| Error::UnsupportedAlgorithm {
        algorithm: digest.to_string(),
    })?;
    if *signature == keys::RSA_ENCRYPTION {
        return Ok((Kind::Rsa, hash));
    }
    let (kind, named) = keys::signature_algorithm(signature)?;
    if named != hash {
        return Err(Error::Malformed {
            structure: "SignerInfo",
            reason: "the signature and digest algorithms disagree",
        });
    }
    Ok((kind, hash))
}

/// Decode DER CRLs strictly.
///
/// # Errors
/// Returns [`Error::Malformed`].
pub(super) fn parse_crls(crls: &[Vec<u8>]) -> Result<Vec<CertificateList>, Error> {
    crls.iter()
        .map(|der| {
            CertificateList::from_der(der).map_err(|_detail| Error::Malformed {
                structure: "CRL",
                reason: "not a DER X.509 CRL",
            })
        })
        .collect()
}

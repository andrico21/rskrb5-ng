//! What a rule is matched against: the matching data of one certificate.
//!
//! MIT 1.22.2 `get_matching_data`, `pkinit_crypto_openssl.c:4850-4891`.

use der::{Decode as _, Encode as _, oid::ObjectIdentifier};
use rasn::der as rasn_der;
use rasn_kerberos::KerberosString;
use x509_cert::{
    Certificate,
    ext::pkix::{ExtendedKeyUsage, KeyUsage, SubjectAltName, name::GeneralName},
};

use super::{asn1::Krb5PrincipalName, matching_name};
use crate::error::Pkinit as Error;

/// `id-pkinit-KPClientAuth` (RFC 4556 section 3.2.2): the `pkinit` keyword.
const KP_CLIENT_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.2.3.4");
/// `id-ms-kp-sc-logon`: the `msScLogin` keyword.
const KP_MS_SC_LOGON: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.20.2.2");
/// `id-kp-clientAuth`: the `clientAuth` keyword.
const KP_CLIENT_AUTH_TLS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2");
/// `id-kp-emailProtection`: the `emailProtection` keyword.
const KP_EMAIL_PROTECTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.4");
/// `id-pkinit-san` (RFC 4556 section 3.2.2).
const PKINIT_SAN: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.2.2");
/// The Microsoft user principal name `otherName`.
const MS_UPN: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.20.2.3");

/// The extended key usage bits of `<EKU>`, in the order of MIT's keyword table.
pub(super) const EKU_KEYWORDS: [(&str, u8); 4] = [
    ("pkinit", 1),
    ("msScLogin", 2),
    ("clientAuth", 4),
    ("emailProtection", 8),
];
/// The key usage bits of `<KU>`.
pub(super) const KU_KEYWORDS: [(&str, u8); 2] = [("digitalSignature", 1), ("keyEncipherment", 2)];

/// The data of one certificate that the rules read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Facts {
    /// The subject, rendered by [`matching_name::render`].
    pub subject: String,
    /// The issuer, rendered likewise.
    pub issuer: String,
    /// The `id-pkinit-san` principals (`krb5_unparse_name` form), then the UPNs.
    pub sans: Vec<String>,
    /// The `<EKU>` bits present.
    pub eku: u8,
    /// The `<KU>` bits present.
    pub ku: u8,
}

/// The `krb5_unparse_name` quoting of one component or realm.
fn quoted(text: &[u8], out: &mut String) {
    for byte in text {
        match byte {
            b'@' | b'/' | b'\\' => {
                out.push('\\');
                out.push(char::from(*byte));
            }
            b'\t' => out.push_str("\\t"),
            b'\n' => out.push_str("\\n"),
            0x08 => out.push_str("\\b"),
            0 => out.push_str("\\0"),
            other => out.push(char::from(*other)),
        }
    }
}

/// `principal` as `krb5_unparse_name` prints it.
fn unparse(principal: &Krb5PrincipalName) -> String {
    let mut out = String::new();
    for (index, component) in principal.principal_name.string.iter().enumerate() {
        if index > 0 {
            out.push('/');
        }
        quoted(KerberosString::as_bytes(component), &mut out);
    }
    out.push('@');
    quoted(principal.realm.as_bytes(), &mut out);
    out
}

/// The PKINIT principals, then the UPNs, of the SAN extension (MIT
/// `crypto_retrieve_X509_sans`: an undecodable PKINIT SAN is skipped, a UPN
/// with an embedded NUL is skipped).
fn alternative_names(certificate: &Certificate) -> Vec<String> {
    let names = certificate
        .tbs_certificate()
        .get_extension::<SubjectAltName>()
        .ok()
        .flatten()
        .map_or_else(Vec::new, |(_, value)| value.0);
    let mut principals = Vec::new();
    let mut upns = Vec::new();
    for name in &names {
        let GeneralName::OtherName(other) = name else {
            continue;
        };
        let oid = other.type_id;
        if oid == PKINIT_SAN {
            let decoded = other
                .value
                .to_der()
                .ok()
                .and_then(|der| rasn_der::decode::<Krb5PrincipalName>(&der).ok());
            if let Some(principal) = decoded {
                principals.push(unparse(&principal));
            }
        }
        if oid == MS_UPN && !other.value.value().contains(&0) {
            upns.push(
                other
                    .value
                    .value()
                    .iter()
                    .map(|byte| char::from(*byte))
                    .collect::<String>(),
            );
        }
    }
    principals.extend(upns);
    principals
}

/// The bits of `table` whose keyword OID is in `present`.
fn usage_bits(present: &[ObjectIdentifier], oids: &[(ObjectIdentifier, u8)]) -> u8 {
    oids.iter()
        .filter(|(oid, _)| present.contains(oid))
        .fold(0, |bits, (_, bit)| bits | bit)
}

impl Facts {
    /// The matching data of the DER certificate `der`.
    ///
    /// # Errors
    /// Returns [`Error::Malformed`] for bytes that are not a certificate or a
    /// name OpenSSL cannot print.
    pub(super) fn from_der(der: &[u8]) -> Result<Self, Error> {
        let certificate = Certificate::from_der(der).map_err(|_detail| Error::Malformed {
            structure: "certificate",
            reason: "not a DER X.509 certificate",
        })?;
        let tbs = certificate.tbs_certificate();
        let purposes = tbs
            .get_extension::<ExtendedKeyUsage>()
            .ok()
            .flatten()
            .map_or_else(Vec::new, |(_, value)| value.0);
        let eku = usage_bits(
            &purposes,
            &[
                (KP_CLIENT_AUTH, 1),
                (KP_MS_SC_LOGON, 2),
                (KP_CLIENT_AUTH_TLS, 4),
                (KP_EMAIL_PROTECTION, 8),
            ],
        );
        // Without a KeyUsage extension no bit is set (MIT :4750-4758).
        let ku = tbs
            .get_extension::<KeyUsage>()
            .ok()
            .flatten()
            .map_or(0, |(_, usage)| {
                u8::from(usage.digital_signature()) | (u8::from(usage.key_encipherment()) << 1_u8)
            });
        Ok(Self {
            subject: matching_name::render(tbs.subject())?,
            issuer: matching_name::render(tbs.issuer())?,
            sans: alternative_names(&certificate),
            eku,
            ku,
        })
    }
}

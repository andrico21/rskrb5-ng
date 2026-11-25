//! The `pkinit_*` relations: their typed values, the refused selectors, the
//! 2048-bit floor, and the behaviour without the leaf.

use core::error::Error;

use rskrb5_ng::{
    Config,
    config::ConfigDiagnostic,
    error::Pkinit,
    preauth::pkinit::{
        CertificatePolicy, ConfiguredIdentities, DhGroup, EkuChecking, Identity, KdcTrust,
    },
};

/// A boxed test failure.
type TestError = Box<dyn Error>;

/// The realm.
const REALM: &str = "TEST.RSKRB5";

/// A profile with `lines` in the realm.
fn config(lines: &str) -> Result<Config, TestError> {
    Ok(Config::parse(&format!(
        "[libdefaults]\n default_realm = {REALM}\n[realms]\n {REALM} = {{\n kdc = 127.0.0.1:1\n{lines}\n }}\n"
    ))?)
}

/// The path of a fixture.
fn fixture(name: &str) -> String {
    format!(
        "{}/tests/pkinit/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    )
}

/// `pkinit_dh_min_bits` maps like MIT's, with a 2048-bit floor.
#[test]
fn dh_min_bits_maps_like_mit_with_a_2048_floor() -> Result<(), TestError> {
    // Given MIT's parse_dh_min_bits values, when each is mapped, then the
    // group matches MIT's and 1024 or fewer bits are refused.
    for (value, group) in [
        ("2048", DhGroup::Modp2048),
        ("1536", DhGroup::Modp2048),
        ("3072", DhGroup::Modp4096),
        ("4096", DhGroup::Modp4096),
        ("P-256", DhGroup::P256),
        ("p-384", DhGroup::P384),
        ("P-521", DhGroup::P521),
    ] {
        assert_eq!(DhGroup::from_min_bits(value)?, group, "{value}");
    }
    assert!(matches!(
        DhGroup::from_min_bits("1024"),
        Err(Pkinit::DhGroupTooSmall { bits: 1024 })
    ));
    assert!(matches!(
        DhGroup::from_min_bits("8192"),
        Err(Pkinit::InvalidDhGroup { value: _ })
    ));
    Ok(())
}

/// The realm `pkinit_*` relations shape the certificate policy.
#[test]
fn realm_relations_shape_the_certificate_policy() -> Result<(), TestError> {
    // Given the client-side pkinit relations of a realm.
    let profile = config(
        " pkinit_eku_checking = kpServerAuth\n pkinit_kdc_hostname = kdc.test.rskrb5\n pkinit_require_crl_checking = true\n pkinit_dh_min_bits = P-384",
    )?;
    // When the policy is read, then every relation takes effect.
    let policy = CertificatePolicy::from_config(&profile, REALM)?;
    assert_eq!(policy.eku_checking(), EkuChecking::KpServerAuth, "eku");
    assert_eq!(policy.kdc_hostnames(), ["kdc.test.rskrb5"], "hostnames");
    assert!(policy.crl_checking(), "crl");
    assert_eq!(policy.group(), DhGroup::P384, "group");
    // And the relations are no longer reported as deferred.
    assert!(
        !profile.diagnostics().iter().any(|item| matches!(
            item,
            ConfigDiagnostic::NotYetEffective { relation, package: _ } if relation.starts_with("pkinit_")
        )),
        "{:?}",
        profile.diagnostics()
    );
    Ok(())
}

/// Refused identity locations are typed errors.
#[test]
fn refused_identity_locations_are_typed_errors() -> Result<(), TestError> {
    for location in ["PKCS11:module_name=/usr/lib/p11.so", "PKCS12:/tmp/user.p12"] {
        let profile = config(&format!(" pkinit_identities = {location}"))?;
        assert!(
            matches!(
                ConfiguredIdentities::from_config(&profile, REALM),
                Err(Pkinit::UnsupportedLocation {
                    relation: "pkinit_identities",
                    location: _
                })
            ),
            "{location}"
        );
    }
    Ok(())
}

/// Without the leaf a configured `pkinit_cert_match` rule is reported as
/// unavailable and refused, never skipped.
#[cfg(not(feature = "pkinit"))]
#[test]
fn certificate_rules_are_unavailable_without_the_leaf() -> Result<(), TestError> {
    // Given identities and a pkinit_cert_match rule in a build without the leaf.
    let profile = config(&format!(
        " pkinit_identities = FILE:{}\n pkinit_cert_match = <EKU>pkinit",
        fixture("client.pem")
    ))?;
    // Then the relation is reported as unavailable and reading the identities fails typed.
    assert!(
        profile.diagnostics().iter().any(|item| matches!(
            item,
            ConfigDiagnostic::FeatureUnavailable {
                relation: "pkinit_cert_match",
                feature: "pkinit"
            }
        )),
        "{:?}",
        profile.diagnostics()
    );
    assert!(matches!(
        ConfiguredIdentities::from_config(&profile, REALM),
        Err(Pkinit::Unavailable)
    ));
    Ok(())
}

/// A rule whose keyword is unknown is refused when the profile is read.
#[test]
fn certificate_rules_with_an_unknown_keyword_are_refused_by_the_profile() {
    // MIT 1.22.2 knows the `&&` and `||` prefixes only: `+` and `-` start no rule.
    for rule in ["<ISSUERS>x", "+<EKU>pkinit", "-<EKU>pkinit", "<DNS>x"] {
        let profile = config(&format!(" pkinit_cert_match = {rule}"));
        assert!(profile.is_err(), "{rule}: {profile:?}");
    }
}

/// FILE identities pair a certificate with its key.
#[test]
fn file_identities_pair_certificate_and_key() -> Result<(), TestError> {
    let certificate = fixture("client.pem");
    let key = fixture("client.key");
    let profile = config(&format!(
        " pkinit_identities = FILE:{certificate},{key}\n pkinit_identities = FILE:{certificate}"
    ))?;
    let identities = ConfiguredIdentities::from_config(&profile, REALM)?;
    assert_eq!(identities.files().len(), 2, "both locations");
    assert_eq!(
        identities
            .files()
            .first()
            .and_then(|(_, path)| path.clone()),
        Some(key.into()),
        "the key path after the comma"
    );
    Ok(())
}

/// A realm without anchors is a typed error.
#[test]
fn missing_anchors_are_a_typed_error() -> Result<(), TestError> {
    let profile = config(" pkinit_eku_checking = kpKDC")?;
    assert!(matches!(
        KdcTrust::from_config(&profile, REALM),
        Err(Pkinit::NoAnchors { realm: _ })
    ));
    Ok(())
}

/// Anchors, pool certificates and CRLs load from files.
#[cfg(feature = "pkinit")]
#[test]
fn anchors_pool_and_crls_load_from_files() -> Result<(), TestError> {
    let profile = config(&format!(
        " pkinit_anchors = FILE:{}\n pkinit_pool = FILE:{}\n pkinit_revoke = FILE:{}",
        fixture("ca-ec.pem"),
        fixture("ca-rsa.pem"),
        fixture("crl-ec.pem")
    ))?;
    let trust = KdcTrust::from_config(&profile, REALM)?;
    assert_eq!(trust.anchors().len(), 1, "anchors");
    assert_eq!(trust.intermediates().len(), 1, "pool");
    assert_eq!(trust.crls().len(), 1, "crls");
    let identity = Identity::from_files(
        fixture("client.pem").as_ref(),
        Some(fixture("client-pkcs8.key").as_ref()),
    )?;
    assert_eq!(identity.certificates().len(), 1, "chain");
    let mismatched = Identity::from_files(
        fixture("kdc.pem").as_ref(),
        Some(fixture("client.key").as_ref()),
    );
    assert!(
        matches!(mismatched, Err(Pkinit::Identity { reason: _ })),
        "{mismatched:?}"
    );
    Ok(())
}

/// Without the leaf every PKINIT operation is unavailable.
#[cfg(not(feature = "pkinit"))]
#[test]
fn without_the_leaf_every_operation_is_unavailable() -> Result<(), TestError> {
    // Given a build without the leaf and a realm that configures anchors.
    let profile = config(&format!(" pkinit_anchors = FILE:{}", fixture("ca-ec.pem")))?;
    // Then the relation is reported as unavailable and loading fails typed.
    assert!(
        profile.diagnostics().iter().any(|item| matches!(
            item,
            ConfigDiagnostic::FeatureUnavailable {
                relation: "pkinit_anchors",
                feature: "pkinit"
            }
        )),
        "{:?}",
        profile.diagnostics()
    );
    assert!(matches!(
        KdcTrust::from_config(&profile, REALM),
        Err(Pkinit::Unavailable)
    ));
    assert!(matches!(
        Identity::from_pem(b"", b""),
        Err(Pkinit::Unavailable)
    ));
    Ok(())
}

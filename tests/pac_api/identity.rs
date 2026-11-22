//! The mutable, serializable identity attribute set derived from a verified PAC.

use core::error::Error;

use rskrb5_ng::{
    keytab::Keytab,
    pac::{IdentityAttributes, Pac, Verification, VerificationPolicy},
};

use super::{pac_ad_win2k, vector};

/// The gokrb5 `AD_WIN2K` PAC verified under the sysHTTP key of its fixture keytab.
fn verified_gokrb5_pac() -> Result<IdentityAttributes, Box<dyn Error>> {
    let keytab = Keytab::parse(&vector(pac_ad_win2k::SYSHTTP_KEYTAB)?)?;
    let (key, _entry) = keytab.find_key(&["sysHTTP"], "TEST.GOKRB5", 2, 18)?;
    let pac = Pac::parse_and_process(&vector(pac_ad_win2k::PAC_AD_WIN2K)?)?;
    let request = Verification::new(VerificationPolicy::acceptor().with_client_binding(false))
        .with_server_key(key);
    Ok(IdentityAttributes::from_verified(
        &pac.verify_ext(&request)?,
    ))
}

/// A verified AD PAC yields its AD identity, and what was verified is recorded with it.
#[test]
fn a_verified_pac_yields_its_ad_identity_attributes() -> Result<(), Box<dyn Error>> {
    // Given the gokrb5 AD PAC verified under the service key.
    let attributes = verified_gokrb5_pac()?;
    // When its attributes are read.
    // Then they carry the AD identity of testuser1 and the one signature that was verified.
    assert_eq!(
        attributes.get("ad:effective-name"),
        Some(["testuser1".to_owned()].as_slice())
    );
    assert_eq!(
        attributes.get("ad:full-name"),
        Some(["Test1 User1".to_owned()].as_slice())
    );
    assert_eq!(
        attributes.get("ad:user-id"),
        Some(["1105".to_owned()].as_slice())
    );
    assert_eq!(
        attributes.get("ad:primary-group-id"),
        Some(["513".to_owned()].as_slice())
    );
    assert_eq!(
        attributes.get("pac:client-name"),
        Some(["testuser1".to_owned()].as_slice())
    );
    assert_eq!(
        attributes.get("pac:verified"),
        Some(["server".to_owned()].as_slice())
    );
    assert!(
        attributes
            .get("ad:group-sid")
            .is_some_and(|groups| !groups.is_empty())
    );
    Ok(())
}

/// Attributes are added, replaced and removed like gokrb5's credential attributes.
#[test]
fn attributes_are_mutable() {
    // Given an empty set.
    let mut attributes = IdentityAttributes::new();
    assert!(attributes.is_empty());
    // When values are added, replaced and removed.
    attributes.add("role", "admin");
    attributes.add("role", "audit");
    attributes.set("team", vec!["core".to_owned()]);
    let removed = attributes.remove("team");
    let absent = attributes.remove("team");
    // Then the set follows.
    assert_eq!(
        attributes.get("role"),
        Some(["admin".to_owned(), "audit".to_owned()].as_slice())
    );
    assert!(removed && !absent);
    attributes.set("role", Vec::new());
    assert!(attributes.is_empty() && attributes.get("role").is_none());
    attributes.add("x", "1");
    assert_eq!(attributes.len(), 1);
}

/// The set round-trips through JSON as an object of name to values.
#[cfg(feature = "serde")]
#[test]
fn attributes_serialize_to_json_and_back() -> Result<(), Box<dyn Error>> {
    // Given the attributes of a verified PAC.
    let attributes = verified_gokrb5_pac()?;
    // When they are serialized and read again.
    let json = serde_json::to_string(&attributes)?;
    let again: IdentityAttributes = serde_json::from_str(&json)?;
    // Then the object form holds the names and the round trip is exact.
    assert!(json.starts_with('{') && json.contains("\"ad:effective-name\":[\"testuser1\"]"));
    assert_eq!(again, attributes);
    Ok(())
}

/// No credential, hash or key leaves the PAC through the attribute set.
#[test]
fn attributes_hold_no_secret_material() -> Result<(), Box<dyn Error>> {
    // Given the attributes of a verified PAC.
    let attributes = verified_gokrb5_pac()?;
    // When their names are listed.
    let names: Vec<&str> = attributes.names().collect();
    // Then only identity names appear.
    assert!(names.iter().all(|name| {
        ["pac:", "ad:", "upn:", "claim:"]
            .iter()
            .any(|prefix| name.starts_with(prefix))
    }));
    assert!(
        !names
            .iter()
            .any(|name| name.contains("key") || name.contains("hash"))
    );
    Ok(())
}

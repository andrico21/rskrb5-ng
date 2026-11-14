use core::error::Error;
use std::time::SystemTime;

use rskrb5_ng::{
    client::options::{AsReq, TgsReq},
    config::{Config, LibDefaults},
    crypto::{CryptoPolicy, KerberosEtype, selection},
    error::{Config as ConfigError, Policy, RejectedFeature},
    keytab::{Keytab, Principal},
};

use super::client::policy_cause;

/// Numeric dispatch distinguishes permanently forbidden IDs from unknown capabilities.
#[test]
fn numeric_selection_is_typed() -> Result<(), Box<dyn Error>> {
    // Given every prohibited enctype and a genuinely unknown ID.
    for (id, expected) in [
        (1_i32, RejectedFeature::SingleDes),
        (2_i32, RejectedFeature::SingleDes),
        (3_i32, RejectedFeature::SingleDes),
        (4_i32, RejectedFeature::SingleDes),
        (8_i32, RejectedFeature::SingleDes),
        (24_i32, RejectedFeature::Rc4Export),
        (6_i32, RejectedFeature::WeakCrypto),
    ] {
        // When an application selects rather than probes a capability.
        let failure = KerberosEtype::try_from(id)
            .err()
            .ok_or("D2 selection accepted")?;
        // Then the machine-readable reason survives.
        assert!(
            matches!(failure, Policy::RejectedFeature { feature, reason: _ } if feature == expected)
        );
    }
    assert!(
        selection::enctype(999)?.is_none(),
        "unknown capability remains absent"
    );
    Ok(())
}

/// Every historical unkeyed or weak negotiable checksum is permanently refused.
#[test]
fn checksum_selection_is_typed() -> Result<(), Box<dyn Error>> {
    // Given CRC32, MD4/DES, DES-MAC, MD5/DES, raw SHA1 and other legacy checksums.
    for id in [
        1_i32, 2_i32, 3_i32, 4_i32, 5_i32, 6_i32, 7_i32, 8_i32, 9_i32, 10_i32, 14_i32,
    ] {
        // When selecting integrity for use.
        let failure = selection::checksum(id)
            .err()
            .ok_or("weak checksum selected")?;
        // Then the selected checksum ID is retained in the typed rejection.
        assert!(
            matches!(failure, Policy::RejectedFeature { feature: RejectedFeature::UnauthenticatedChecksum { id: actual }, reason: _ } if actual == id)
        );
    }
    assert_eq!(
        selection::checksum(-138)?
            .ok_or("keyed RC4 checksum")?
            .etype_id(),
        23_i32
    );
    assert_eq!(
        selection::checksum(15)?.ok_or("AES checksum")?.etype_id(),
        17_i32
    );
    Ok(())
}

/// Explicit checksum configuration is selection, unlike an opaque checksum container.
#[test]
fn textual_checksum_selection_is_typed() -> Result<(), Box<dyn Error>> {
    // Given numeric and named weak checksums in safe_checksum_type.
    for (token, id) in [
        ("1", 1_i32),
        ("crc32", 1_i32),
        ("rsa-md4", 2_i32),
        ("rsa-md5", 7_i32),
        ("rsa-md5-des", 8_i32),
        ("md4", 2_i32),
        ("MD5", 7_i32),
        ("sha", 9_i32),
        ("SHA1", 14_i32),
    ] {
        // When configuring authenticated integrity.
        let failure = Config::parse(&format!("[libdefaults]\nsafe_checksum_type = {token}"))
            .err()
            .ok_or("weak config accepted")?;
        // Then configuration retains the typed policy cause.
        assert!(
            matches!(failure, ConfigError::Policy(Policy::RejectedFeature { feature: RejectedFeature::UnauthenticatedChecksum { id: actual }, reason: _ }) if actual == id)
        );
    }
    Ok(())
}

/// Raw key generation rejects D2 selection before password derivation.
#[test]
fn raw_keytab_selection_is_typed() -> Result<(), Box<dyn Error>> {
    // Given an empty keytab and a caller-selected prohibited enctype.
    for (id, feature) in [
        (1_i32, RejectedFeature::SingleDes),
        (2_i32, RejectedFeature::SingleDes),
        (3_i32, RejectedFeature::SingleDes),
        (24_i32, RejectedFeature::Rc4Export),
        (6_i32, RejectedFeature::WeakCrypto),
    ] {
        let mut keys = Keytab::new();
        // When creating a password-derived entry.
        let failure = keys
            .add_entry_from_password(
                Principal::new("EXAMPLE.COM", 1, ["alice"]),
                b"password".to_vec().into(),
                SystemTime::UNIX_EPOCH,
                1,
                id,
            )
            .err()
            .ok_or("D2 key generated")?;
        // Then the cause is policy and the keytab stays unchanged.
        let cause = failure
            .source()
            .and_then(Error::source)
            .and_then(|source| source.downcast_ref::<Policy>())
            .ok_or("typed policy cause")?;
        assert!(
            matches!(cause, Policy::RejectedFeature { feature: actual, reason: _ } if *actual == feature)
        );
        assert!(
            keys.entries().is_empty(),
            "rejection leaves no generated key"
        );
    }
    Ok(())
}

/// Serde configuration rejects algorithm selection while opaque key data remains representable.
#[cfg(feature = "serde")]
#[test]
fn serde_config_cannot_select_d2() -> Result<(), Box<dyn Error>> {
    // Given serialized default configuration with one prohibited field at a time.
    for (field, value, feature) in [
        (
            "allow_weak_crypto",
            serde_json::json!(true),
            RejectedFeature::WeakCrypto,
        ),
        (
            "safe_checksum_type",
            serde_json::json!(7_i32),
            RejectedFeature::UnauthenticatedChecksum { id: 7_i32 },
        ),
        (
            "default_tkt_enctypes",
            serde_json::json!(["des-cbc-crc"]),
            RejectedFeature::SingleDes,
        ),
        (
            "default_tgs_enctypes",
            serde_json::json!(["rc4-hmac-exp"]),
            RejectedFeature::Rc4Export,
        ),
        (
            "permitted_enctypes",
            serde_json::json!(["des-cbc-md5"]),
            RejectedFeature::SingleDes,
        ),
    ] {
        let mut serialized = serde_json::to_value(LibDefaults::new())?;
        drop(
            serialized
                .as_object_mut()
                .ok_or("object")?
                .insert(field.to_owned(), value),
        );
        // When generic serde constructs a selecting config value.
        let failure = serde_json::from_value::<LibDefaults>(serialized)
            .err()
            .ok_or("serde selected D2")?;
        // Then serde's error envelope reports the permanent policy refusal.
        assert!(failure.to_string().contains(&feature.to_string()));
    }
    Ok(())
}

/// A mutated request list is rejected when a client builds a request, not after use.
#[test]
fn policy_snapshot_rejects_mutated_request_selection() -> Result<(), Box<dyn Error>> {
    // Given request lists bypassing the text parser and permitted-list setter.
    for field in ["ticket", "service"] {
        let mut defaults = LibDefaults::new();
        match field {
            "ticket" => defaults.default_tkt_enctypes = vec!["des-cbc-md5".to_owned()],
            _ => defaults.default_tgs_enctypes = vec!["rc4-hmac-exp".to_owned()],
        }
        // When a client builds either request from this configuration.
        for admission in [
            AsReq::from_libdefaults(SystemTime::UNIX_EPOCH, 42, &defaults).err(),
            TgsReq::from_libdefaults(SystemTime::UNIX_EPOCH, 42, &defaults).err(),
        ] {
            let failure = admission.ok_or("D2 request survived client admission")?;
            // Then the selection retains its typed rejection.
            assert!(matches!(
                policy_cause(&failure),
                Some(Policy::RejectedFeature {
                    feature: _,
                    reason: _
                })
            ));
        }
        // The acceptor snapshot reads the permitted list only.
        drop(CryptoPolicy::from_libdefaults(&defaults)?);
    }
    Ok(())
}

use core::error::Error;

use rskrb5_ng::{
    config::{Config, ConfigDiagnostic, protocol},
    error::{Config as ConfigError, Policy, RejectedFeature},
};

/// Removed protocols and conversion are rejected in both configuration scopes.
#[test]
fn enabling_protocol_relations_are_typed() -> Result<(), Box<dyn Error>> {
    // Given relations that actively select removed mechanisms.
    for (key, value, expected) in [
        ("krb4_get_tickets", "yes", RejectedFeature::KerberosV4),
        ("krb4_convert", "true", RejectedFeature::V4Conversion),
        ("v4_instance_convert", "host", RejectedFeature::V4Conversion),
        ("v4_name_convert", "{", RejectedFeature::V4Conversion),
        ("v4_realm", "EXAMPLE.COM", RejectedFeature::V4Conversion),
        ("pkinit_win2k", "true", RejectedFeature::Draft9Pkinit),
        ("pkinit_rsa_only", "true", RejectedFeature::RsaPkinit),
        ("flag_RSA_PROTOCOL", "yes", RejectedFeature::RsaPkinit),
        (
            "kpasswd_protocol",
            "unprotected",
            RejectedFeature::UnprotectedPasswordChange,
        ),
    ] {
        for section in ["libdefaults", "realms", "login", "appdefaults"] {
            let relation = format!("{key} = {value}\n{}", if value == "{" { "}" } else { "" });
            let text = if section == "libdefaults" {
                format!("[libdefaults]\n{relation}")
            } else if section == "realms" {
                format!("[realms]\nEXAMPLE.COM = {{\n{relation}\n}}")
            } else {
                format!("[{section}]\n{relation}")
            };
            // When parsing an enabling selection.
            let failure = Config::parse(&text)
                .err()
                .ok_or("removed protocol accepted")?;
            // Then configuration retains the exact permanent feature identity.
            assert!(
                matches!(failure, ConfigError::Policy(Policy::RejectedFeature { feature, reason: _ }) if feature == expected),
                "{key}: {failure:?}"
            );
        }
    }
    Ok(())
}

/// Direct relation selection uses the same typed boundary as profile parsing.
#[test]
fn relation_api_rejects_removed_modes() -> Result<(), Box<dyn Error>> {
    // Given one explicit selector for each remaining feature.
    for (key, value, expected) in [
        ("krb4_get_tickets", "true", RejectedFeature::KerberosV4),
        ("krb4_convert", "true", RejectedFeature::V4Conversion),
        ("pkinit_rsa_only", "true", RejectedFeature::RsaPkinit),
        ("pkinit_draft9", "true", RejectedFeature::Draft9Pkinit),
        (
            "kpasswd_protocol",
            "cleartext",
            RejectedFeature::UnprotectedPasswordChange,
        ),
    ] {
        // When an application selects the protocol relation directly.
        let failure = protocol::relation(key, value)
            .err()
            .ok_or("removed selector accepted")?;
        // Then the exact feature survives without crypto or transport.
        assert!(
            matches!(failure, ConfigError::Policy(Policy::RejectedFeature { feature, reason: _ }) if feature == expected)
        );
    }
    Ok(())
}

/// Serde may not silently discard removed-mode selectors as unknown keys.
#[cfg(feature = "serde")]
#[test]
fn serde_protocol_relations_are_rejected() -> Result<(), Box<dyn Error>> {
    use rskrb5_ng::config::LibDefaults;
    // Given serialized defaults with a legacy selector injected.
    for (key, expected) in [
        ("krb4_get_tickets", RejectedFeature::KerberosV4),
        ("krb4_convert", RejectedFeature::V4Conversion),
        ("pkinit_rsa_only", RejectedFeature::RsaPkinit),
        ("pkinit_draft9", RejectedFeature::Draft9Pkinit),
        (
            "kpasswd_unprotected",
            RejectedFeature::UnprotectedPasswordChange,
        ),
    ] {
        let mut value = serde_json::to_value(LibDefaults::new())?;
        drop(
            value
                .as_object_mut()
                .ok_or("object")?
                .insert(key.to_owned(), true.into()),
        );
        // When serde constructs configuration, not an opaque protocol record.
        let failure = serde_json::from_value::<LibDefaults>(value)
            .err()
            .ok_or("serde enabled removed protocol")?;
        // Then serde's native envelope identifies the rejected feature.
        assert!(failure.to_string().contains(&expected.to_string()));
    }
    Ok(())
}

/// Explicit draft-9 PA data is rejected by the actual outgoing AS builder.
#[cfg(feature = "messages")]
#[test]
fn draft9_api_selection_is_rejected() -> Result<(), Box<dyn Error>> {
    use std::time::SystemTime;

    use rskrb5_ng::client::{build_tgt_as_req, options::AsReq, principal::Principal};
    // Given application-selected draft-9 PA types, not KDC advertisements.
    for id in [14_i32, 15_i32] {
        let options =
            AsReq::new(SystemTime::UNIX_EPOCH, 1).with_padata(vec![rasn_kerberos::PaData {
                r#type: id,
                value: Vec::new().into(),
            }]);
        // When building an outgoing exchange.
        let failure = build_tgt_as_req(Principal::user("EXAMPLE.COM", "alice"), options)
            .err()
            .ok_or("draft9 selected")?;
        // Then the builder rejects before DER construction or network effects.
        let mut cause: &(dyn Error + 'static) = &failure;
        while let Some(source) = cause.source() {
            cause = source;
        }
        assert!(matches!(
            cause.downcast_ref::<Policy>(),
            Some(Policy::RejectedFeature {
                feature: RejectedFeature::Draft9Pkinit,
                reason: _
            })
        ));
    }
    Ok(())
}

/// Disabled legacy switches and RSA certificate metadata do not select removed modes.
#[test]
fn disabled_relations_and_certificate_paths_are_accepted() -> Result<(), Box<dyn Error>> {
    // Given disabled protocol/conversion switches and a certificate filename.
    for value in ["false", "no", "0", "f", "n"] {
        let text = format!(
            "[libdefaults]\nkrb4_get_tickets = {value}\nkrb4_convert = {value}\nv4_name_convert = {value}\npkinit_win2k = {value}\npkinit_rsa_only = {value}\npkinit_anchors = FILE:/rsa-root.pem\n[realms]\nEXAMPLE.COM = {{\ndefault_domain = example.com\nv4_realm = {value}\n}}"
        );
        // When parsing non-enabling relations.
        let config = Config::parse(&text)?;
        // Then the unrelated default_domain remains parsed.
        assert_eq!(
            config.realms.first().ok_or("realm")?.default_domain,
            "example.com"
        );
    }
    Ok(())
}

/// MIT's historical preference list never makes draft-9 usable.
#[test]
fn draft9_preferences_are_ignored_with_diagnostics() -> Result<(), Box<dyn Error>> {
    // Given MIT's preference order containing removed draft types.
    let text = "[libdefaults]\npreferred_preauth_types = 17,16,15,14";
    // When parsing preferences, not explicitly selecting an exchange mechanism.
    let config = Config::parse(text)?;
    // Then only current types remain and every ignored ID is observable.
    assert_eq!(config.libdefaults.preferred_preauth_types, [17_i32, 16_i32]);
    assert_eq!(config.libdefaults.diagnostics().len(), 3);
    assert!(matches!(
        config.libdefaults.diagnostics().as_ref(),
        [
            ConfigDiagnostic::IgnoredPreauthType { id: 15_i32 },
            ConfigDiagnostic::IgnoredPreauthType { id: 14_i32 },
            ConfigDiagnostic::NotYetEffective {
                relation: "preferred_preauth_types",
                package: "plan 2 WP-04"
            }
        ]
    ));
    Ok(())
}

/// Unknown password protocol versions cannot become an unprotected fallback.
#[test]
fn password_versions_fail_closed() -> Result<(), Box<dyn Error>> {
    use rskrb5_ng::crypto::selection;
    // Given unknown/legacy framing selections, including version zero.
    for version in [0_u16, 2_u16, 0xffff_u16] {
        // When an application explicitly selects its framing version.
        let failure = selection::password_change_version(version)
            .err()
            .ok_or("weak version selected")?;
        // Then no protocol downgrade is available.
        assert!(matches!(
            failure,
            Policy::RejectedFeature {
                feature: RejectedFeature::UnprotectedPasswordChange,
                reason: _
            }
        ));
    }
    selection::password_change_version(1)?;
    selection::password_change_version(0xff80)?;
    Ok(())
}

/// Even the raw kpasswd encoder cannot send a NULL-enctype password payload.
#[cfg(feature = "messages")]
#[test]
fn null_password_payload_is_rejected() -> Result<(), Box<dyn Error>> {
    use rskrb5_ng::kadmin::Request;
    // Given a historical request fixture relabelled as unencrypted by a caller.
    let bytes = hex::decode(include_str!("../fixtures/kpasswd-request.hex").trim())?;
    let (ap_req, mut krb_priv) = Request::parse(&bytes)?.into_parts();
    krb_priv.enc_part.etype = 0_i32;
    let request = Request::new(ap_req, krb_priv);
    // When encoding the caller-selected unprotected payload.
    let failure = request
        .encode()
        .err()
        .ok_or("NULL password request encoded")?;
    // Then no frame is emitted and the protection failure is typed.
    let mut cause: &(dyn Error + 'static) = &failure;
    while let Some(source) = cause.source() {
        cause = source;
    }
    assert!(matches!(
        cause.downcast_ref::<Policy>(),
        Some(Policy::RejectedFeature {
            feature: RejectedFeature::UnprotectedPasswordChange,
            reason: _
        })
    ));
    Ok(())
}

/// Advertised draft-9 mechanisms are ignored, never selected or hard-rejected.
#[cfg(feature = "messages")]
#[test]
fn draft9_advertisements_are_ignored() -> Result<(), Box<dyn Error>> {
    use std::time::SystemTime;

    use rskrb5_ng::client::{
        KdcError, PreauthKeyInfo, principal::Principal, select_preauth_key_info,
    };
    // Given opaque draft-9 advertisements beside an implemented AES hint.
    let mut reply = KdcError::new(
        SystemTime::UNIX_EPOCH,
        0,
        25,
        Principal::tgt_service("EXAMPLE.COM"),
    );
    reply.set_method_data(
        [14_i32, 15_i32]
            .into_iter()
            .map(|id| rasn_kerberos::PaData {
                r#type: id,
                value: vec![0xff].into(),
            })
            .collect(),
    );
    reply.set_preauth_key_info(vec![PreauthKeyInfo::new(17)]);
    // When choosing from the available enctype hints.
    let selected = select_preauth_key_info(&reply, &[17_i32])?;
    // Then opaque removed advertisements do not obstruct current mechanisms.
    assert_eq!(selected.etype, 17_i32);
    Ok(())
}

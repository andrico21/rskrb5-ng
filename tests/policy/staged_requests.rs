use core::error::Error;
use std::time::SystemTime;

use rskrb5_ng::{
    Config,
    client::{
        self, Tokio,
        options::{AsReq, TgsReq},
        principal::Principal,
        transport::KdcProtocol,
    },
    config::{LibDefaults, ParseMode, Toggle},
    crypto::CryptoPolicy,
    error::{self, Policy, RejectedFeature},
    kdc_req,
    keytab::{EncryptionKey, Keytab},
};

use super::client::{policy_cause, session};

/// Both request builders reject mixed staged selections with a named cause.
#[test]
fn staged_options_reject_mixed_lists_by_name() -> Result<(), Box<dyn Error>> {
    let mut defaults = Config::parse("[libdefaults]\npermitted_enctypes = aes128-cts")?.libdefaults;
    defaults.default_tkt_enctypes = vec!["aes128-cts".to_owned(), "aes256-cts".to_owned()];
    defaults.default_tgs_enctypes = defaults.default_tkt_enctypes.clone();
    let as_error = AsReq::from_libdefaults(SystemTime::UNIX_EPOCH, 42, &defaults)
        .err()
        .ok_or("mixed AS list narrowed")?;
    let tgs_error = TgsReq::from_libdefaults(SystemTime::UNIX_EPOCH, 42, &defaults)
        .err()
        .ok_or("mixed TGS list narrowed")?;
    for failure in [as_error, tgs_error] {
        assert!(failure.to_string().contains("aes256-cts-hmac-sha1-96"));
    }
    Ok(())
}

/// Staged mixed AES lists fail by name instead of being intersected with permission.
#[test]
fn staged_mixed_requests_reject_excluded_aes() -> Result<(), Box<dyn Error>> {
    for key in ["default_tkt_enctypes", "default_tgs_enctypes"] {
        let mut defaults =
            Config::parse("[libdefaults]\npermitted_enctypes = aes128-cts")?.libdefaults;
        let names = vec!["aes128-cts".to_owned(), "aes256-cts".to_owned()];
        match key {
            "default_tkt_enctypes" => defaults.default_tkt_enctypes = names,
            _ => defaults.default_tgs_enctypes = names,
        }
        let failure = match key {
            "default_tkt_enctypes" => {
                AsReq::from_libdefaults(SystemTime::UNIX_EPOCH, 42, &defaults).err()
            }
            _ => TgsReq::from_libdefaults(SystemTime::UNIX_EPOCH, 42, &defaults).err(),
        }
        .ok_or("mixed excluded request admitted")?;
        assert!(
            matches!(failure, error::Client::Config(error::Config::EnctypeNotPermitted { key: actual, enctype }) if actual == key && enctype == "aes256-cts-hmac-sha1-96")
        );
        // The permitted list alone admits an acceptor snapshot.
        drop(CryptoPolicy::from_libdefaults(&defaults)?);
    }
    Ok(())
}

/// Disabled tokens in staged requests retain their original spelling at admission.
#[test]
fn staged_requests_preserve_disabled_token() -> Result<(), Box<dyn Error>> {
    for key in ["default_tkt_enctypes", "default_tgs_enctypes"] {
        let mut defaults = LibDefaults::new();
        let names = vec!["aes128-cts".to_owned(), "+RC4-HMAC".to_owned()];
        match key {
            "default_tkt_enctypes" => defaults.default_tkt_enctypes = names,
            _ => defaults.default_tgs_enctypes = names,
        }
        for option_error in [
            AsReq::from_libdefaults(SystemTime::UNIX_EPOCH, 42, &defaults)
                .err()
                .ok_or("disabled AS admitted")?,
            TgsReq::from_libdefaults(SystemTime::UNIX_EPOCH, 42, &defaults)
                .err()
                .ok_or("disabled TGS admitted")?,
        ] {
            assert!(
                matches!(option_error, error::Client::Config(error::Config::DisabledEnctype { token }) if token == "+RC4-HMAC")
            );
        }
    }
    Ok(())
}

/// Parsed implicit defaults and allowed staged ordering survive request encoding.
#[test]
fn staged_allowed_requests_preserve_wire_order() -> Result<(), Box<dyn Error>> {
    for text in ["[libdefaults]\npermitted_enctypes = aes128-cts", ""] {
        let mut defaults = Config::parse(text)?.libdefaults;
        let expected = if text.is_empty() {
            defaults.default_tkt_enctypes = vec!["aes128-cts".to_owned(), "aes256-cts".to_owned()];
            vec![17_i32, 18_i32]
        } else {
            vec![17_i32]
        };
        let request = client::build_tgt_as_req(
            Principal::user("EXAMPLE.COM", "alice"),
            AsReq::from_libdefaults(SystemTime::UNIX_EPOCH, 42, &defaults)?,
        )?;
        assert_eq!(
            kdc_req::decode_as_req(request.der())?.0.req_body.etype,
            expected
        );
        defaults.default_tgs_enctypes = defaults.default_tkt_enctypes.clone();
        let mut tgt = session(17, 17)?;
        tgt.set_session_key(EncryptionKey::new(17, vec![0; 16]));
        let service = client::build_tgs_req_with_confounder(
            &tgt,
            Principal::new("EXAMPLE.COM", 2, ["HTTP", "other"]),
            TgsReq::from_libdefaults(SystemTime::UNIX_EPOCH, 42, &defaults)?,
            SystemTime::UNIX_EPOCH,
            0,
            &[0; 16],
        )?;
        assert_eq!(
            kdc_req::decode_tgs_req(service.der())?.0.req_body.etype,
            expected
        );
    }
    Ok(())
}

/// Staged secure unsupported names obey the selected parsing mode.
#[test]
fn staged_requests_honor_strict_mode() -> Result<(), Box<dyn Error>> {
    let mut defaults = LibDefaults::new();
    defaults.default_tkt_enctypes = vec!["aes128-cts".to_owned(), "camellia".to_owned()];
    drop(AsReq::from_libdefaults(
        SystemTime::UNIX_EPOCH,
        42,
        &defaults,
    )?);
    defaults.enctype_parse_mode = ParseMode::Strict;
    let failure = AsReq::from_libdefaults(SystemTime::UNIX_EPOCH, 42, &defaults)
        .err()
        .ok_or("strict unsupported request admitted")?;
    assert!(
        matches!(failure, error::Client::Config(error::Config::UnsupportedSecureEnctype { token, until: _ }) if token == "camellia")
    );
    Ok(())
}

/// Client and both option admissions preserve the permanent policy source.
#[test]
fn staged_admission_preserves_rejected_feature_causes() -> Result<(), Box<dyn Error>> {
    for expected in [
        RejectedFeature::SingleDes,
        RejectedFeature::WeakCrypto,
        RejectedFeature::UnauthenticatedChecksum { id: 1_i32 },
    ] {
        let mut config = Config::new();
        match expected {
            RejectedFeature::SingleDes => {
                config.libdefaults.permitted_enctypes = vec!["des-cbc-crc".to_owned()];
            }
            RejectedFeature::WeakCrypto => config.libdefaults.allow_weak_crypto = Toggle::Enabled,
            RejectedFeature::UnauthenticatedChecksum { id } => {
                config.libdefaults.safe_checksum_type = id;
            }
            RejectedFeature::KerberosV4
            | RejectedFeature::V4Conversion
            | RejectedFeature::RsaPkinit
            | RejectedFeature::Draft9Pkinit
            | RejectedFeature::Rc4Export
            | RejectedFeature::UnprotectedPasswordChange => return Err("unhandled fixture".into()),
            _ => return Err("unknown fixture".into()),
        }
        let as_options = AsReq::from_libdefaults(SystemTime::UNIX_EPOCH, 42, &config.libdefaults);
        let tgs_options = TgsReq::from_libdefaults(SystemTime::UNIX_EPOCH, 42, &config.libdefaults);
        let as_error = as_options.err().ok_or("prohibited AS admitted")?;
        let tgs_error = tgs_options.err().ok_or("prohibited TGS admitted")?;
        let mut kerberos = Tokio::with_keytab(
            config,
            KdcProtocol::Tcp,
            Principal::user("EXAMPLE.COM", "alice"),
            Keytab::new(),
        );
        let client_error = kerberos
            .cache_service_ticket(session(18, 18)?)
            .err()
            .ok_or("prohibited client admitted")?;
        for failure in [&as_error, &tgs_error, &client_error] {
            assert!(
                matches!(policy_cause(failure), Some(Policy::RejectedFeature { feature, reason: _ }) if *feature == expected)
            );
        }
    }
    Ok(())
}

/// Valid configured client admission still accepts a matching credential.
#[test]
fn staged_client_accepts_allowed_policy() -> Result<(), Box<dyn Error>> {
    let mut kerberos = Tokio::with_keytab(
        Config::new(),
        KdcProtocol::Tcp,
        Principal::user("EXAMPLE.COM", "alice"),
        Keytab::new(),
    );
    kerberos.cache_service_ticket(session(18, 18)?)?;
    assert_eq!(kerberos.cached_service_ticket_count(), 1);
    Ok(())
}

/// The configured client keeps the named request-list cause on every staged key.
#[test]
fn staged_client_rejects_mixed_lists_by_name() -> Result<(), Box<dyn Error>> {
    for key in ["default_tkt_enctypes", "default_tgs_enctypes"] {
        let mut config = Config::parse("[libdefaults]\npermitted_enctypes = aes128-cts")?;
        let names = vec!["aes128-cts".to_owned(), "aes256-cts".to_owned()];
        match key {
            "default_tkt_enctypes" => config.libdefaults.default_tkt_enctypes = names,
            _ => config.libdefaults.default_tgs_enctypes = names,
        }
        let mut kerberos = Tokio::with_keytab(
            config,
            KdcProtocol::Tcp,
            Principal::user("EXAMPLE.COM", "alice"),
            Keytab::new(),
        );
        let failure = kerberos
            .cache_service_ticket(session(17, 17)?)
            .err()
            .ok_or("mixed client list admitted")?;
        assert!(
            matches!(failure, error::Client::Config(error::Config::EnctypeNotPermitted { key: actual, enctype }) if actual == key && enctype == "aes256-cts-hmac-sha1-96")
        );
    }
    Ok(())
}

/// A mutated request list is rejected when a client builds a request, not after use.
#[test]
fn client_admission_rejects_mutated_request_selection() -> Result<(), Box<dyn Error>> {
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
    }
    Ok(())
}

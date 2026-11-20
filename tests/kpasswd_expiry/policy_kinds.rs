//! The same `[libdefaults]` refusal yields the same `Error` variant and policy cause
//! on the AS, TGS and kpasswd result paths (plan-1 residual, MIT-admin-1).

use std::time::UNIX_EPOCH;

use rskrb5_ng::{
    client::{
        self,
        options::{AsReq, TgsReq},
        principal::Principal,
    },
    config::{Config, Toggle},
    error::{Client, Crypto, Policy, RejectedFeature},
    keytab::EncryptionKey,
};

use super::{KdcProtocol, TestError, Tokio, runtime, support};

/// How a path reported the refusal: its variant and, when typed, its policy cause.
#[derive(Debug, Eq, PartialEq)]
enum Refusal {
    /// `Error::Crypto` carrying a typed `RejectedFeature`.
    TypedPolicy(RejectedFeature),
    /// `Error::Config`, whatever its cause.
    Config,
    /// Anything else.
    Other(String),
}

/// Classify the failure of a path that must refuse before any I/O.
fn classify<T>(result: Result<T, Client>) -> Refusal {
    match result {
        Ok(_) => Refusal::Other("the path accepted the configuration".to_owned()),
        Err(Client::Crypto(Crypto::Policy(Policy::RejectedFeature { feature, reason: _ }))) => {
            Refusal::TypedPolicy(feature)
        }
        Err(Client::Config(_)) => Refusal::Config,
        Err(other) => Refusal::Other(other.to_string()),
    }
}

/// The three paths report each refusing configuration the same way.
#[test]
fn the_same_libdefaults_refusal_has_one_kind_on_every_path() -> Result<(), TestError> {
    let cases: [(&str, Config, Refusal); 4] = [
        (
            "allow_weak_crypto",
            {
                let mut config = Config::new();
                config.libdefaults.allow_weak_crypto = Toggle::Enabled;
                config
            },
            Refusal::TypedPolicy(RejectedFeature::WeakCrypto),
        ),
        (
            "single DES in permitted_enctypes",
            {
                let mut config = Config::new();
                config.libdefaults.permitted_enctypes = vec!["des-cbc-crc".to_owned()];
                config
            },
            Refusal::TypedPolicy(RejectedFeature::SingleDes),
        ),
        (
            "unauthenticated safe_checksum_type",
            {
                let mut config = Config::new();
                config.libdefaults.safe_checksum_type = 1;
                config
            },
            Refusal::TypedPolicy(RejectedFeature::UnauthenticatedChecksum { id: 1 }),
        ),
        (
            "unknown enctype name",
            {
                let mut config = Config::new();
                config.libdefaults.permitted_enctypes = vec!["no-such-enctype".to_owned()];
                config
            },
            Refusal::Config,
        ),
    ];
    let (built, options) = support::built_request()?;
    let as_request = client::build_tgt_as_req(
        Principal::user("TEST.GOKRB5", "testuser1"),
        AsReq::new(UNIX_EPOCH, 42).with_etypes(vec![18_i32]),
    )
    .map_err(|error| format!("AS-REQ: {error}"))?;
    let session = support::tgt(&Principal::user("TEST.GOKRB5", "testuser1"))?;
    let tgs_request = client::build_tgs_req_with_confounder(
        &session,
        Principal::new("TEST.GOKRB5", 2, ["host", "example.test"]),
        TgsReq::new(UNIX_EPOCH, 43).with_etypes(vec![18_i32]),
        UNIX_EPOCH,
        1,
        &[0x21; 16],
    )
    .map_err(|error| format!("TGS-REQ: {error}"))?;
    let key = EncryptionKey::new(18, vec![0x11; 32]);
    let transport = Tokio::new();
    runtime()?.block_on(async {
        for (label, config, expected) in cases {
            let as_path = classify(
                transport
                    .exchange_as_req_with_config(&config, KdcProtocol::Tcp, &as_request, &key)
                    .await,
            );
            let tgs_path = classify(
                transport
                    .exchange_tgs_req_with_config(&config, KdcProtocol::Tcp, &tgs_request, &key)
                    .await,
            );
            let kpasswd_path = classify(
                transport
                    .exchange_kpasswd_result_with_config(
                        &config,
                        KdcProtocol::Tcp,
                        "TEST.GOKRB5",
                        &built,
                        &options,
                    )
                    .await,
            );
            assert_eq!(as_path, expected, "AS path, {label}");
            assert_eq!(tgs_path, expected, "TGS path, {label}");
            assert_eq!(kpasswd_path, expected, "kpasswd path, {label}");
        }
        Ok(())
    })
}

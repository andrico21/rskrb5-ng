//! `spake_preauth_groups` with and without the leaf, the policy, and the
//! outgoing PA-SPAKE admission.

use core::error::Error;

use rskrb5_ng::config::{Config, ConfigDiagnostic, ParseMode};

/// The relation is effective with the leaf; without it, it is reported as
/// `FeatureUnavailable` (strict mode refuses it) and never deferred to WP-07.
#[test]
fn spake_preauth_groups() -> Result<(), Box<dyn Error>> {
    let text = "[libdefaults]\n spake_preauth_groups = P-256 edwards25519\n";
    let config = Config::parse(text)?;
    let unavailable = ConfigDiagnostic::FeatureUnavailable {
        relation: "spake_preauth_groups",
        feature: "spake",
    };
    let strict = Config::parse_with_mode(text, ParseMode::Strict);
    if cfg!(feature = "spake") {
        assert!(
            config.diagnostics().is_empty(),
            "the leaf is compiled in: {:?}",
            config.diagnostics()
        );
        drop(strict?);
    } else {
        assert_eq!(
            config.diagnostics(),
            [unavailable],
            "missing FeatureUnavailable"
        );
        assert!(
            strict.is_err(),
            "strict mode admitted an unavailable relation"
        );
    }
    Ok(())
}

/// The policy keeps the profile's order, drops repeats, and is usable only with the leaf.
#[test]
fn policy_follows_the_profile() -> Result<(), Box<dyn Error>> {
    use rskrb5_ng::preauth::spake::{AVAILABLE, Group, Policy};

    let config =
        Config::parse("[libdefaults]\n spake_preauth_groups = P-521, edwards25519 p-521\n")?;
    let policy = Policy::from_libdefaults(&config.libdefaults);
    assert_eq!(policy.groups(), [Group::P521, Group::Edwards25519]);
    assert_eq!(policy.is_usable(), AVAILABLE);
    assert_eq!(policy.permitted(4), AVAILABLE.then_some(Group::P521));
    assert_eq!(policy.permitted(2), None);
    assert_eq!(Policy::default().groups(), [Group::Edwards25519]);
    assert!(!Policy::new([]).is_usable());
    assert_eq!(Group::from_name("P-384").map(Group::id), Some(3_i32));
    Ok(())
}

/// Outgoing admission: a support message is admitted; a response is admitted
/// only when its factor enctype is permitted as a reply key; a KDC-side message
/// (challenge) and garbage never leave the client.
#[test]
fn outgoing_spake_is_admitted_exactly() -> Result<(), Box<dyn Error>> {
    use std::time::UNIX_EPOCH;

    use rasn_kerberos::PaData;
    use rskrb5_ng::{
        client::{self, KdcTransport, build_tgt_as_req, options::AsReq, principal::Principal},
        error::{Client as ClientError, Crypto, Policy},
        keytab::EncryptionKey,
        preauth::spake::PA_SPAKE,
    };

    /// Counts the requests that reach it and answers none.
    struct Counting(usize);
    impl KdcTransport for Counting {
        fn send(&mut self, _realm: &str, _request: &[u8]) -> Result<Vec<u8>, ClientError> {
            self.0 = self.0.saturating_add(1);
            Err(ClientError::Transport("admitted request".to_owned()))
        }
    }

    let support = hex::decode("a0093007a0053003020101")?;
    // [2] SPAKEResponse { [0] pubkey (32 bytes), [1] EncryptedData { [0] etype, [2] cipher } }.
    let response = |etype: u8| {
        let mut bytes = hex::decode("a2373035a0220420")?;
        bytes.extend([0x11_u8; 32]);
        bytes.extend(hex::decode("a10f300da0030201")?);
        bytes.push(etype);
        bytes.extend(hex::decode("a2060404deadbeef")?);
        Ok::<_, hex::FromHexError>(bytes)
    };
    let challenge = hex::decode(
        "a1363034a003020101a122042018f511e750c97b592acd30db7d9e5fca660389102e6bf610c1bfbed4616c8362a20930073005a003020101",
    )?;
    for (value, admitted, rc4_refused) in [
        (support, true, false),
        (response(0x12)?, true, false),
        (response(0x17)?, false, true),
        (challenge, false, false),
        (vec![0x47_u8; 8], false, false),
    ] {
        let mut transport = Counting(0);
        let result = build_tgt_as_req(
            Principal::user("TEST.RSKRB5", "spakeuser"),
            AsReq::new(UNIX_EPOCH, 7).with_padata(vec![PaData {
                r#type: PA_SPAKE,
                value: value.clone().into(),
            }]),
        )
        .and_then(|request| {
            client::exchange_as_req(
                &mut transport,
                &request,
                &EncryptionKey::new(18, vec![0; 32]),
            )
        });
        assert_eq!(
            transport.0,
            usize::from(admitted),
            "{}: {result:?}",
            hex::encode(&value)
        );
        if rc4_refused {
            let refused = matches!(
                &result,
                Err(ClientError::Crypto(Crypto::Policy(
                    Policy::EnctypeNotPermitted {
                        etype: 23_i32,
                        usage: _
                    }
                )))
            );
            assert!(refused, "{result:?}");
        }
    }
    Ok(())
}

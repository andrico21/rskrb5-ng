use core::error::Error;

use rasn::{
    der,
    types::{GeneralString, Integer},
};

use super::{PreauthKeyInfo, Principal, derive_password_reply_key};
use crate::{
    config::LibDefaults,
    crypto::{CryptoPolicy, pbkdf2_observation, s2k::Family},
    error,
};

/// Explicit prohibited profiles fail before the real password primitive seam.
#[test]
fn forbidden_profiles_never_enter_pbkdf2() -> Result<(), Box<dyn Error>> {
    // Given a caller-selected prohibited enctype rather than a peer advertisement.
    let principal = Principal::user("EXAMPLE.COM", "alice");
    for (id, expected) in [
        (1_i32, error::RejectedFeature::SingleDes),
        (2_i32, error::RejectedFeature::SingleDes),
        (3_i32, error::RejectedFeature::SingleDes),
        (24_i32, error::RejectedFeature::Rc4Export),
        (6_i32, error::RejectedFeature::WeakCrypto),
    ] {
        let info = PreauthKeyInfo::new(id);
        let _prior = pbkdf2_observation::take();
        // When explicit password derivation selects that profile.
        let failure = derive_password_reply_key(&principal, b"password", &info)
            .err()
            .ok_or("prohibited derivation accepted")?;
        // Then no primitive ran and the permanent feature identity survives.
        assert_eq!(pbkdf2_observation::take(), 0);
        assert!(
            matches!(failure, error::Client::Crypto(error::Crypto::Policy(error::Policy::RejectedFeature { feature, reason: _ })) if feature == expected)
        );
    }
    Ok(())
}

/// Unauthenticated low-work hints must fail before entering real PBKDF2.
#[test]
fn low_peer_counts_never_enter_pbkdf2() -> Result<(), Box<dyn Error>> {
    // Given low ETYPE-INFO2 work factors in both AES families and key sizes.
    let principal = Principal::user("EXAMPLE.COM", "alice");
    for id in [17_i32, 18_i32, 19_i32, 20_i32] {
        let info = PreauthKeyInfo::new(id).with_s2kparams(Some(1_u32.to_be_bytes().to_vec()));
        let _prior = pbkdf2_observation::take();
        // When the public peer-hint derivation boundary is used.
        let result = derive_password_reply_key(&principal, b"password", &info);
        let calls = pbkdf2_observation::take();
        // Then no derivation occurred, even on the failure path.
        assert_eq!(
            calls, 0,
            "etype {id} entered PBKDF2 before rejecting weak work factor"
        );
        let failure = result.err().ok_or("low count accepted")?;
        assert!(
            matches!(failure, error::Client::Crypto(error::Crypto::Policy(error::Policy::S2kIterationsTooLow { etype, minimum: _, actual: 1 })) if etype == id)
        );
    }
    Ok(())
}

/// Encoded KDC INFO2 challenges enforce floors before constructing encrypted timestamps.
#[test]
fn info2_challenge_checks_before_timestamp_derivation() -> Result<(), Box<dyn Error>> {
    use std::time::SystemTime;

    use super::{options::AsReq, preauth::password_preauth_request};
    // Given real DER METHOD-DATA for both AES families at count one.
    for (id, family) in [(17_i32, Family::AesSha1), (20_i32, Family::AesSha2)] {
        let principal = Principal::user("EXAMPLE.COM", "alice");
        let service = Principal::tgt_service("EXAMPLE.COM");
        let now = SystemTime::now();
        let options = AsReq::new(now, 42).with_etypes(vec![id]);
        let hints = rasn_kerberos::EtypeInfo2::from([rasn_kerberos::EtypeInfo2Entry {
            etype: id,
            salt: None,
            s2kparams: Some(1_u32.to_be_bytes().to_vec().into()),
        }]);
        let method = rasn_kerberos::MethodData::from([rasn_kerberos::PaData {
            r#type: 19,
            value: der::encode(&hints)?.into(),
        }]);
        let error = rasn_kerberos::KrbError {
            pvno: Integer::from(5_i32),
            msg_type: Integer::from(30_i32),
            ctime: None,
            cusec: None,
            stime: super::kerberos_time_from_system_time(SystemTime::UNIX_EPOCH)?,
            susec: Integer::from(0_i32),
            error_code: 25,
            crealm: None,
            cname: None,
            realm: GeneralString::try_from("EXAMPLE.COM")?,
            sname: super::principal_to_rasn(&service)?,
            e_text: None,
            e_data: Some(der::encode(&method)?.into()),
        };
        let bytes = der::encode(&error)?;
        let _prior = pbkdf2_observation::take();
        // When the real preauth path decodes and selects the peer hint.
        let failure = password_preauth_request(
            principal.clone(),
            service.clone(),
            b"password",
            options.clone(),
            &bytes,
        )
        .err()
        .ok_or("weak challenge accepted")?;
        // Then no PBKDF2 occurred; only an application override can allow it.
        assert_eq!(pbkdf2_observation::take(), 0);
        assert!(matches!(
            failure,
            error::Client::Crypto(error::Crypto::Policy(error::Policy::S2kIterationsTooLow {
                etype: _,
                minimum: _,
                actual: 1
            }))
        ));
        let defaults = LibDefaults::new().with_min_s2k_iterations(family, 1)?;
        let mut allowed = options;
        allowed.set_crypto_policy(Ok(CryptoPolicy::from_libdefaults(&defaults)?));
        let (request, key) =
            password_preauth_request(principal, service, b"password", allowed, &bytes)?;
        assert_eq!(pbkdf2_observation::take(), 1);
        assert_eq!(key.etype(), id);
        assert!(
            request
                .message
                .0
                .padata
                .as_ref()
                .is_some_and(|padata| padata.iter().any(|entry| entry.r#type == 2_i32))
        );
    }
    Ok(())
}

/// Inclusive minima and explicit trusted overrides enter the real primitive exactly once.
#[test]
fn accepted_minima_and_overrides_enter_pbkdf2() -> Result<(), Box<dyn Error>> {
    // Given both AES sizes/families and absent or explicitly encoded RFC defaults.
    let principal = Principal::user("EXAMPLE.COM", "alice");
    for (id, minimum, family) in [
        (17_i32, 4096_u32, Family::AesSha1),
        (18_i32, 4096_u32, Family::AesSha1),
        (19_i32, 0x8000_u32, Family::AesSha2),
        (20_i32, 0x8000_u32, Family::AesSha2),
    ] {
        for params in [None, Some(minimum.to_be_bytes().to_vec())] {
            let info = PreauthKeyInfo::new(id).with_s2kparams(params);
            let _prior = pbkdf2_observation::take();
            // When deriving with the default policy at its inclusive floor.
            let key = derive_password_reply_key(&principal, b"password", &info)?;
            // Then exactly one actual PBKDF2 call occurred and a real key was produced.
            assert_eq!(pbkdf2_observation::take(), 1);
            assert_eq!(key.etype(), id);
        }
        let defaults = LibDefaults::new().with_min_s2k_iterations(family, 1)?;
        let policy = CryptoPolicy::from_libdefaults(&defaults)?;
        let info = PreauthKeyInfo::new(id).with_s2kparams(Some(1_u32.to_be_bytes().to_vec()));
        let key = super::password_derivation::derive(&policy, &principal, b"password", &info)?;
        assert_eq!(pbkdf2_observation::take(), 1);
        assert_eq!(key.etype(), id);
    }
    Ok(())
}

/// Near-floor, zero, malformed and above-ceiling inputs do no password work.
#[test]
fn invalid_counts_and_upper_bound_enter_no_pbkdf2() -> Result<(), Box<dyn Error>> {
    // Given each AES family and hostile count encodings.
    let principal = Principal::user("EXAMPLE.COM", "alice");
    for (id, below) in [(17_i32, 4095_u32), (20_i32, 0x7fff_u32)] {
        for bytes in [
            below.to_be_bytes().to_vec(),
            0_u32.to_be_bytes().to_vec(),
            0x0100_0001_u32.to_be_bytes().to_vec(),
            vec![1_u8; 3],
        ] {
            let info = PreauthKeyInfo::new(id).with_s2kparams(Some(bytes));
            let _prior = pbkdf2_observation::take();
            // When the real boundary parses the peer's parameters.
            let failure = derive_password_reply_key(&principal, b"password", &info)
                .err()
                .ok_or("invalid count accepted")?;
            // Then all errors occur before the primitive.
            assert_eq!(pbkdf2_observation::take(), 0);
            assert!(matches!(failure, error::Client::Crypto(_)));
        }
    }
    let defaults = LibDefaults::new().with_min_s2k_iterations(Family::AesSha2, 1)?;
    let policy = CryptoPolicy::from_libdefaults(&defaults)?;
    let failure = policy
        .check_s2k_params(20, "01000001")
        .err()
        .ok_or("override bypassed maximum")?;
    assert!(matches!(
        failure,
        error::Crypto::IterationCountTooHigh {
            maximum: 0x0100_0000,
            actual: 0x0100_0001
        }
    ));
    policy.check_s2k_params(20, "01000000")?;
    assert_eq!(pbkdf2_observation::take(), 0);
    Ok(())
}

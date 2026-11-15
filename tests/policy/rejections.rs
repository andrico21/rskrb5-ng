use core::error::Error;

use rskrb5_ng::error::{self, Policy, RejectedFeature, RejectionReason};

/// Every catalogue entry survives conversion into the crate-wide error.
#[test]
fn catalogue_converts_without_losing_feature() -> Result<(), Box<dyn Error>> {
    // Given the complete nine-feature catalogue from todo 14 step 5.
    let first = RejectedFeature::SingleDes;
    let features = [
        first,
        RejectedFeature::KerberosV4,
        RejectedFeature::V4Conversion,
        RejectedFeature::RsaPkinit,
        RejectedFeature::Draft9Pkinit,
        RejectedFeature::Rc4Export,
        RejectedFeature::UnauthenticatedChecksum { id: 7_i32 },
        RejectedFeature::UnprotectedPasswordChange,
        RejectedFeature::WeakCrypto,
    ];
    for feature in features {
        let reason = RejectionReason::InsecureByDesign;
        let policy = Policy::RejectedFeature { feature, reason };
        // When propagated into Any by From, with an explicit construction control.
        let converted = error::Any::from(policy);
        let explicit = error::Any::Policy(policy);
        assert_policy_source(&converted, policy)?;
        // Then both retain the exact typed policy as their source.
        assert_eq!(
            converted
                .source()
                .and_then(|cause| cause.downcast_ref::<Policy>()),
            Some(&policy)
        );
        assert_eq!(
            explicit
                .source()
                .and_then(|cause| cause.downcast_ref::<Policy>()),
            Some(&policy)
        );
    }
    Ok(())
}

/// Policy errors can reach every domain without becoming strings.
#[test]
fn policy_converts_into_domains() -> Result<(), Box<dyn Error>> {
    // Given a permanent refusal with no external cause.
    let reason = RejectionReason::RemovedAndInsecure;
    let policy = Policy::RejectedFeature {
        feature: RejectedFeature::SingleDes,
        reason,
    };
    // When converted through the base domains.
    let errors: [Box<dyn Error>; 5] = [
        Box::new(error::Config::from(policy)),
        Box::new(error::Crypto::from(policy)),
        Box::new(error::Ccache::from(policy)),
        Box::new(error::Keytab::from(policy)),
        Box::new(error::Pac::from(policy)),
    ];
    // Then source traversal reaches the same policy, and the policy has no cause.
    for error in errors {
        assert_policy_source(error.as_ref(), policy)?;
    }
    assert!(policy.source().is_none());
    let config = error::Config::Policy(policy);
    let crypto = error::Crypto::Policy(policy);
    let ccache = error::Ccache::Policy(policy);
    assert_policy_source(&config, policy)?;
    assert_policy_source(&crypto, policy)?;
    assert_policy_source(&ccache, policy)?;
    Ok(())
}

/// Protocol domains preserve the common rejection through their existing causes.
#[cfg(feature = "messages")]
#[test]
fn policy_converts_into_message_domains() -> Result<(), Box<dyn Error>> {
    // Given a refusal to use unauthenticated integrity.
    let reason = RejectionReason::MissingAuthentication;
    let policy = Policy::RejectedFeature {
        feature: RejectedFeature::UnauthenticatedChecksum { id: 1_i32 },
        reason,
    };
    // When propagated into each message domain.
    let errors: [Box<dyn Error>; 13] = [
        Box::new(error::Client::from(policy)),
        Box::new(error::Service::from(policy)),
        Box::new(error::ApRep::from(policy)),
        Box::new(error::ApReq::from(policy)),
        Box::new(error::Kadmin::from(policy)),
        Box::new(error::KdcRep::from(policy)),
        Box::new(error::KdcReq::from(policy)),
        Box::new(error::KrbCred::from(policy)),
        Box::new(error::KrbErrorCodec::from(policy)),
        Box::new(error::KrbPriv::from(policy)),
        Box::new(error::KrbSafe::from(policy)),
        Box::new(error::Messages::from(policy)),
        Box::new(error::Ticket::from(policy)),
    ];
    // Then none of the conversions erase the cause.
    for error in errors {
        assert_policy_source(error.as_ref(), policy)?;
    }
    let kadmin = error::Kadmin::Policy(policy);
    let codec = error::KrbErrorCodec::Policy(policy);
    let messages = error::Messages::Policy(policy);
    assert_policy_source(&kadmin, policy)?;
    assert_policy_source(&codec, policy)?;
    assert_policy_source(&messages, policy)?;
    Ok(())
}

/// Negotiation wrappers retain policy errors as typed sources.
#[cfg(feature = "spnego")]
#[test]
fn policy_converts_into_negotiation_domains() -> Result<(), Box<dyn Error>> {
    // Given an export-cipher refusal.
    let policy = Policy::RejectedFeature {
        feature: RejectedFeature::Rc4Export,
        reason: RejectionReason::InsecureByDesign,
    };
    // When converted into negotiation errors.
    let spnego = error::Spnego::from(policy);
    // Then source traversal reaches policy.
    assert_policy_source(&spnego, policy)?;
    #[cfg(feature = "http")]
    assert_policy_source(&error::Http::from(policy), policy)?;
    Ok(())
}

/// Every feature and reason renders its own text, and the rejection message carries both.
///
/// The wording is not pinned: the text of a feature or reason must be present, differ
/// from every sibling and keep the checksum id, and the message must contain the two texts.
#[test]
fn rejection_display_is_present_distinct_and_composed() {
    // Given the nine-feature catalogue and the three reasons.
    let features = [
        RejectedFeature::SingleDes,
        RejectedFeature::KerberosV4,
        RejectedFeature::V4Conversion,
        RejectedFeature::RsaPkinit,
        RejectedFeature::Draft9Pkinit,
        RejectedFeature::Rc4Export,
        RejectedFeature::UnauthenticatedChecksum { id: 4242_i32 },
        RejectedFeature::UnprotectedPasswordChange,
        RejectedFeature::WeakCrypto,
    ];
    let reasons = [
        RejectionReason::RemovedAndInsecure,
        RejectionReason::InsecureByDesign,
        RejectionReason::MissingAuthentication,
    ];
    // When each is rendered on its own.
    let feature_texts = features.map(|feature| feature.to_string());
    let reason_texts = reasons.map(|reason| reason.to_string());
    // Then every text is present and no two siblings share one.
    for texts in [feature_texts.as_slice(), reason_texts.as_slice()] {
        let mut distinct = texts.to_vec();
        distinct.sort();
        distinct.dedup();
        assert_eq!(distinct.len(), texts.len());
        assert!(texts.iter().all(|text| !text.is_empty()));
    }
    // And the checksum feature keeps its identifier.
    assert!(feature_texts.iter().any(|text| text.contains("4242")));
    // And the rejection message contains the text of its feature and of its reason.
    for (feature, feature_text) in features.into_iter().zip(&feature_texts) {
        for (reason, reason_text) in reasons.into_iter().zip(&reason_texts) {
            let message = Policy::RejectedFeature { feature, reason }.to_string();
            assert!(message.contains(feature_text.as_str()));
            assert!(message.ends_with(reason_text.as_str()));
        }
    }
}

/// Inspect only causal structure, not human-readable formatting.
fn assert_policy_source(error: &dyn Error, policy: Policy) -> Result<(), Box<dyn Error>> {
    let mut source = error.source();
    while let Some(cause) = source {
        if let Some(actual) = cause.downcast_ref::<Policy>() {
            assert_eq!(*actual, policy);
            return Ok(());
        }
        source = cause.source();
    }
    Err("policy cause was erased".into())
}

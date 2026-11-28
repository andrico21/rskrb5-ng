//! Name attributes of the initiator, from the ticket's verified PAC.
//!
//! RFC 6680 `gss_inquire_name` and `gss_get_name_attribute` over the PAC MIT
//! 1.22.2 exposes as `urn:mspac:` attributes (`pac.c:880-1060`,
//! `naming_exts.c:253-380`): the whole PAC under `urn:mspac:`, each buffer
//! under its name or `urn:mspac:<type>`. Only a PAC whose KDC signature
//! verified is reported authenticated; an unverified PAC is never shown.

use rskrb5_ng::{
    crypto::CryptoPolicy,
    error::Gss,
    gss::{
        Acceptor, AcceptorOptions, Credential, EstablishedContext, InitStep, Initiator,
        InitiatorOptions, MemoryTransferLedger, TransferKey,
    },
    pac::VerificationPolicy,
    service::Validator,
};

use super::{
    context::{Context as _, TestError},
    support::{
        AES256_SHA1, cache_of, establish, kdc_key, keytab, refused, sequenced, target,
        ticket_with_indicators, ticket_with_pac,
    },
};

/// The acceptor's context of a ticket whose PAC carries `buffers`; with
/// `kdc` the acceptor holds the KDC key and verifies the KDC signature.
fn accepted(buffers: &[(u32, &[u8])], kdc: bool) -> Result<EstablishedContext, TestError> {
    let ticket = ticket_with_pac(AES256_SHA1, &[], Some(buffers))?;
    let credential = Credential::from_ccache(cache_of(&ticket)?)?;
    let mut init = Initiator::new(target()?, InitiatorOptions::new());
    let InitStep::Continue(token) = init.init_sec_context(&credential, None)? else {
        return Err("a mutual initiator waits".into());
    };
    let keys = keytab();
    let mut validator = Validator::new(&keys).with_crypto_policy(CryptoPolicy::default());
    if kdc {
        validator = validator
            .with_pac_kdc_key(kdc_key())
            .with_pac_policy(VerificationPolicy::kdc());
    }
    let mut accept = Acceptor::from_validator(validator, AcceptorOptions::new());
    Ok(accept.accept_sec_context(&token)?.into_context())
}

/// The acceptor lists the PAC and its buffers as `urn:mspac:` attributes and
/// returns their bytes, authenticated when the KDC signature verified.
#[test]
fn the_source_name_carries_the_verified_pac_attributes() -> Result<(), TestError> {
    let context = accepted(&[(1000, b"opaque buffer")], true)?;
    let names = context.source_attributes();
    for expected in [
        "urn:mspac:",
        "urn:mspac:server-checksum",
        "urn:mspac:privsvr-checksum",
        "urn:mspac:client-info",
        "urn:mspac:1000",
    ] {
        assert!(
            names.iter().any(|name| name == expected),
            "{expected}: {names:?}"
        );
    }
    let buffer = context.source_attribute("urn:mspac:1000")?;
    assert_eq!(buffer.value(), b"opaque buffer");
    assert!(buffer.authenticated());
    assert!(buffer.complete());
    // MIT matches the attribute name case-insensitively.
    assert_eq!(
        context.source_attribute("URN:MSPAC:1000")?.value(),
        b"opaque buffer"
    );
    let whole = context.source_attribute("urn:mspac:")?;
    let pac = context.pac().context("a verified PAC")?;
    assert_eq!(whole.value(), pac.pac().data());
    Ok(())
}

/// Without the KDC key the PAC passed the server signature only: its
/// attributes are shown, but not as authenticated.
#[test]
fn a_pac_without_a_verified_kdc_signature_is_not_authenticated() -> Result<(), TestError> {
    let context = accepted(&[(1000, b"x")], false)?;
    assert!(!context.source_attribute("urn:mspac:1000")?.authenticated());
    Ok(())
}

/// Unknown attributes, absent buffers, attributes of another namespace and a
/// context without a PAC report no attribute.
#[test]
fn unknown_attributes_are_unavailable() -> Result<(), TestError> {
    let context = accepted(&[], true)?;
    for name in [
        "urn:mspac:logon-info",
        "urn:mspac:77",
        "urn:other:x",
        "urn:mspac:0",
        "urn:mspac:x1",
    ] {
        assert!(
            matches!(
                context.source_attribute(name),
                Err(Gss::NameAttributeUnavailable(_))
            ),
            "{name}"
        );
    }
    let plain = establish(sequenced())?;
    assert_eq!(plain.acceptor.source_attributes(), Vec::<String>::new());
    assert_eq!(plain.initiator.source_attributes(), Vec::<String>::new());
    refused(plain.acceptor.source_attribute("urn:mspac:"))?;
    Ok(())
}

/// With PAC extraction off, the acceptor's context exposes no PAC and no PAC
/// attribute, although the PAC was verified (gokrb5 `DecodePAC(false)`).
#[test]
fn pac_decode_disabled_exposes_no_attributes() -> Result<(), TestError> {
    let ticket = ticket_with_pac(AES256_SHA1, &[], Some(&[(1000, b"opaque buffer")]))?;
    let credential = Credential::from_ccache(cache_of(&ticket)?)?;
    let mut init = Initiator::new(target()?, InitiatorOptions::new());
    let InitStep::Continue(token) = init.init_sec_context(&credential, None)? else {
        return Err("a mutual initiator waits".into());
    };
    let keys = keytab();
    let validator = Validator::new(&keys).with_pac_extraction(false);
    let mut accept = Acceptor::from_validator(validator, AcceptorOptions::new());
    let context = accept.accept_sec_context(&token)?.into_context();
    assert!(context.pac().is_none());
    assert_eq!(context.source_attributes(), Vec::<String>::new());
    refused(context.source_attribute("urn:mspac:"))?;
    Ok(())
}

/// The acceptor's context of a ticket whose verified CAMMAC carries `indicators`.
fn accepted_with_indicators(indicators: &[&str]) -> Result<EstablishedContext, TestError> {
    let ticket = ticket_with_indicators(indicators)?;
    let credential = Credential::from_ccache(cache_of(&ticket)?)?;
    let mut init = Initiator::new(target()?, InitiatorOptions::new());
    let InitStep::Continue(token) = init.init_sec_context(&credential, None)? else {
        return Err("a mutual initiator waits".into());
    };
    let keys = keytab();
    let mut accept = Acceptor::from_validator(Validator::new(&keys), AcceptorOptions::new());
    Ok(accept.accept_sec_context(&token)?.into_context())
}

/// The verified indicators are the authenticated, complete values of the
/// `auth-indicators` attribute, every one of them in order (MIT
/// `ai_authdata.c:113-117,153-186`).
#[test]
fn verified_cammac_exposes_all_auth_indicators() -> Result<(), TestError> {
    let context = accepted_with_indicators(&["otp", "pkinit", "hardened"])?;
    assert_eq!(context.source_attributes(), ["auth-indicators"]);
    let attribute = context.source_attribute("auth-indicators")?;
    assert_eq!(attribute.value(), b"otp");
    assert_eq!(
        attribute.values(),
        [b"otp".to_vec(), b"pkinit".to_vec(), b"hardened".to_vec()]
    );
    assert!(attribute.authenticated());
    assert!(attribute.complete());
    // MIT matches this attribute name exactly.
    refused(context.source_attribute("AUTH-INDICATORS"))?;
    // A ticket without indicators has no such attribute.
    let plain = accepted_with_indicators(&[])?;
    assert_eq!(plain.source_attributes(), Vec::<String>::new());
    refused(plain.source_attribute("auth-indicators"))?;
    Ok(())
}

/// An acceptor context keeps its verified indicators through an authenticated
/// export and import.
#[test]
fn indicator_attributes_survive_context_transfer() -> Result<(), TestError> {
    let context = accepted_with_indicators(&["otp", "pkinit"])?;
    let key = TransferKey::new([0x24; 32]);
    let blob = context.export(&key)?;
    let mut ledger = MemoryTransferLedger::new();
    let imported = EstablishedContext::import(&blob, &key, &mut ledger)?;
    let attribute = imported.source_attribute("auth-indicators")?;
    assert_eq!(attribute.values(), [b"otp".to_vec(), b"pkinit".to_vec()]);
    assert!(attribute.authenticated());
    Ok(())
}

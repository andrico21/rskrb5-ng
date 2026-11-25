//! AD-CAMMAC and authentication indicators in the acceptor (RFC 7751, RFC 8129).
//!
//! The rule under test is MIT 1.22.2's: the acceptor verifies the CAMMAC's
//! service verifier, a checksum with key usage 64 under the key that decrypted
//! the ticket over the DER of the CAMMAC's elements (`cammac_util.c:36-59`,
//! `authdata.c:586-606`, `rd_req_dec.c:643-648`), and takes indicators only
//! from a verified CAMMAC of the ticket (`authdata.c:659-665`). Stricter than
//! MIT, a CAMMAC whose verifier does not verify refuses the ticket instead of
//! being skipped (`authdata.c:555-558`).

use rasn::der;
use rasn_kerberos::AuthorizationData;
use rskrb5_ng::{
    error::Service as Error,
    keytab::{EncryptionKey, Keytab},
    service::Validator,
};

use super::support::{ap_req, keytab, session_key};
use crate::{
    cammac_fixture::{AD_CAMMAC, cammac, element, indicators, wrapped},
    context::TestError,
};

/// The validation time of the fixture.
const NOW: u64 = 1_893_553_447;

/// The service key that encrypts the fixture ticket.
fn service_key(keytab: &Keytab) -> Result<EncryptionKey, TestError> {
    let (key, _) = keytab.find_key(&["HTTP", "host.test.gokrb5"], "TEST.GOKRB5", 1, 18)?;
    Ok(key.clone())
}

/// Validate the fixture AP-REQ carrying `ticket` and `authenticator` data.
fn validate(
    ticket: Option<AuthorizationData>,
    authenticator: Option<AuthorizationData>,
) -> Result<Result<rskrb5_ng::service::ValidatedApReq, Error>, TestError> {
    let keytab = keytab()?;
    let now = std::time::UNIX_EPOCH
        .checked_add(core::time::Duration::from_secs(NOW))
        .ok_or("time is representable")?;
    let bytes = ap_req(ticket, authenticator)?;
    Ok(Validator::new(&keytab)
        .with_now(now)
        .validate_ap_req(&bytes))
}

/// A CAMMAC the service cannot verify refuses the ticket: elements changed
/// after the MAC, a flipped MAC, a MAC under another key, no service verifier,
/// an undecodable CAMMAC, and an undecodable indicator list inside a verified
/// CAMMAC.
#[test]
fn tampered_cammac_is_refused() -> Result<(), TestError> {
    let key = service_key(&keytab()?)?;
    let good = cammac(vec![indicators(&["otp"])?], &key)?;

    let mut extended = good.clone();
    extended.elements.push(indicators(&["pkinit"])?);
    let mut flipped = good.clone();
    let mut mac = flipped
        .svc_verifier
        .as_ref()
        .ok_or("a service verifier")?
        .mac
        .checksum
        .to_vec();
    *mac.first_mut().ok_or("a MAC byte")? ^= 0x01;
    if let Some(verifier) = flipped.svc_verifier.as_mut() {
        verifier.mac.checksum = mac.into();
    }
    let session_keyed = cammac(vec![indicators(&["otp"])?], &session_key())?;
    let mut unverified = good.clone();
    unverified.svc_verifier = None;
    let malformed_list = cammac(vec![element(97, vec![0x04, 0x00])], &key)?;

    for (label, data) in [
        ("extended", wrapped(&extended)?),
        ("flipped", wrapped(&flipped)?),
        ("session key", wrapped(&session_keyed)?),
        ("no verifier", wrapped(&unverified)?),
        ("indicator list", wrapped(&malformed_list)?),
        (
            "undecodable",
            vec![element(
                1,
                der::encode(&vec![element(AD_CAMMAC, vec![0x30, 0x03, 0x02])])?,
            )],
        ),
    ] {
        let refused = validate(Some(data), None)?;
        assert!(
            matches!(refused, Err(Error::AuthorizationData(_))),
            "{label}: {refused:?}"
        );
    }
    Ok(())
}

/// An authenticator is client-controlled: a CAMMAC in it is refused even
/// when its verifier is right (it may be copied from another ticket), and an
/// indicator element outside a CAMMAC is no CAMMAC-protected indicator.
#[test]
fn authenticator_indicators_are_not_authenticated() -> Result<(), TestError> {
    let key = service_key(&keytab()?)?;
    let copied = wrapped(&cammac(vec![indicators(&["otp"])?], &key)?)?;
    let in_authenticator = validate(None, Some(copied))?;
    assert!(
        matches!(
            in_authenticator,
            Err(Error::UnsupportedAuthorizationData { kind: AD_CAMMAC })
        ),
        "{in_authenticator:?}"
    );
    // A bare indicator element is refused where it is critical,
    let bare = validate(Some(vec![indicators(&["otp"])?]), None)?;
    assert!(
        matches!(bare, Err(Error::UnsupportedAuthorizationData { kind: 97 })),
        "{bare:?}"
    );
    // and never taken for an indicator where it is optional, in the ticket or
    // in the authenticator.
    let optional = vec![element(1, der::encode(&vec![indicators(&["otp"])?])?)];
    for (ticket, authenticator) in [(Some(optional.clone()), None), (None, Some(optional))] {
        assert!(
            validate(ticket, authenticator)??
                .auth_indicators()
                .is_empty()
        );
    }
    Ok(())
}

/// Every indicator of every verified CAMMAC of the ticket is collected once,
/// in order, inside AD-IF-RELEVANT as MIT issues it or as a mandatory element.
#[test]
fn verified_cammacs_yield_their_indicators() -> Result<(), TestError> {
    let key = service_key(&keytab()?)?;
    let mut data = wrapped(&cammac(vec![indicators(&["otp"])?], &key)?)?;
    let second = cammac(vec![indicators(&["pkinit", "hardened"])?], &key)?;
    data.push(element(AD_CAMMAC, der::encode(&second)?));
    let accepted = validate(Some(data), None)??;
    assert_eq!(accepted.auth_indicators(), ["otp", "pkinit", "hardened"]);
    // A ticket without a CAMMAC has none.
    assert!(validate(None, None)??.auth_indicators().is_empty());
    Ok(())
}

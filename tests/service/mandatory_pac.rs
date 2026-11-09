//! Mandatory-container PAC discovery must agree with authorization policy.

use rasn::der;
use rskrb5_ng::{
    error::{Pac as PacError, Service},
    pac,
    service::Validator,
    ticket::decrypt_ticket_enc_part,
};

use super::{
    KDC_REP_TICKET_USAGE_FOR_TEST, PAC_TICKET_CONFOUNDER, TestError, ap_req_with_pac,
    authorization_element, encrypt_message, syshttp_keytab, timestamp,
};

/// Rewrap the signed fixture PAC without changing its contents or checksum.
fn mandatory_request(corrupt: bool) -> Result<Vec<u8>, TestError> {
    let keytab = syshttp_keytab()?;
    let (key, _) = keytab.find_key(&["sysHTTP"], "TEST.GOKRB5", 2, 18)?;
    let mut request: rasn_kerberos::ApReq = der::decode(&ap_req_with_pac()?)?;
    let mut ticket = decrypt_ticket_enc_part(&request.ticket, key)?;
    let data = ticket.authorization_data.as_mut().ok_or("ticket has PAC")?;
    let wrapper = data.first_mut().ok_or("PAC wrapper exists")?;
    let mut nested: rasn_kerberos::AuthorizationData = der::decode(wrapper.data.as_ref())?;
    if corrupt {
        nested.first_mut().ok_or("PAC exists")?.data = vec![0_u8].into();
    }
    ticket.authorization_data = Some(authorization_element(8, der::encode(&nested)?));
    request.ticket.enc_part.cipher = encrypt_message(
        key,
        &der::encode(&ticket)?,
        KDC_REP_TICKET_USAGE_FOR_TEST,
        PAC_TICKET_CONFOUNDER,
    )?
    .into();
    Ok(der::encode(&request)?)
}

/// A recognized mandatory wrapper returns its verified PAC rather than silently dropping it.
#[test]
fn mandatory_wrapper_returns_verified_pac() -> Result<(), TestError> {
    // Given a signed PAC inside the mandatory container understood by policy.
    let keytab = syshttp_keytab()?;
    let request = mandatory_request(false)?;
    let mut validator = Validator::new(&keytab).with_now(timestamp(1_893_553_447)?);
    // When the real acceptor processes the request.
    let accepted = validator.validate_ap_req(&request)?;
    // Then discovery and policy agree on its presence.
    assert_eq!(
        accepted
            .pac()
            .ok_or("verified mandatory PAC missing")?
            .c_buffers(),
        5
    );
    Ok(())
}

/// Malformed PAC data cannot hide inside a recognized mandatory container.
#[test]
fn mandatory_wrapper_rejects_invalid_pac() -> Result<(), TestError> {
    // Given a valid ticket carrying a malformed mandatory PAC.
    let keytab = syshttp_keytab()?;
    let request = mandatory_request(true)?;
    let mut validator = Validator::new(&keytab).with_now(timestamp(1_893_553_447)?);
    // When the real acceptor processes the request.
    let result = validator.validate_ap_req(&request);
    // Then PAC verification is not bypassed by its container.
    assert!(matches!(result, Err(Service::Pac(_))));
    assert_eq!(validator.replay_cache_mut().len(), 0);
    Ok(())
}

/// A bad signature under the mandatory wrapper fails the public discovery/verification path.
#[test]
fn mandatory_wrapper_exposes_bad_signature() -> Result<(), TestError> {
    // Given a structurally valid PAC with a corrupted server signature.
    let mut bytes = super::decode_hex(super::pac_ad_win2k::PAC_AD_WIN2K)?;
    let parsed = pac::Pac::parse(&bytes)?;
    let signature = parsed
        .buffer(pac::INFO_TYPE_PAC_SERVER_SIGNATURE_DATA)
        .ok_or("server signature exists")?;
    let offset = usize::try_from(signature.offset)?
        .checked_add(4)
        .ok_or("offset fits")?;
    *bytes.get_mut(offset).ok_or("signature byte exists")? ^= 1;
    let nested = authorization_element(pac::AD_WIN2K_PAC, bytes);
    let wrapped = authorization_element(8, der::encode(&nested)?);
    let keytab = syshttp_keytab()?;
    let (key, _) = keytab.find_key(&["sysHTTP"], "TEST.GOKRB5", 2, 18)?;
    // When the PAC is discovered and authenticated.
    let result = pac::find_pac_in_authorization_data(&wrapped)?
        .ok_or("mandatory PAC missing")?
        .verify(key);
    // Then the signature failure remains visible.
    assert!(matches!(
        result,
        Err(PacError::ServerChecksumVerificationFailed)
    ));
    Ok(())
}

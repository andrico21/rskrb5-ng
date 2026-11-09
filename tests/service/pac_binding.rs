//! PAC client metadata must describe the enclosing ticket.

use super::{
    AP_REQ_AUTHENTICATOR_USAGE_FOR_TEST, EncryptionKey, KDC_REP_TICKET_USAGE_FOR_TEST,
    PAC_AUTHENTICATOR_CONFOUNDER, PAC_TICKET_CONFOUNDER, TestError, VALID_SESSION_KEY, Validator,
    ap_req_with_pac, decode_hex, decrypt_ap_req_authenticator, decrypt_ticket_enc_part, der,
    encrypt_message, kerberos_time, principal, syshttp_keytab, timestamp,
};

/// Reissue a ticket and matching authenticator while retaining the signed PAC verbatim.
fn request_with_client(name: &str, auth_time: u64) -> Result<Vec<u8>, TestError> {
    let keytab = syshttp_keytab()?;
    let (key, _) = keytab.find_key(&["sysHTTP"], "TEST.GOKRB5", 2, 18)?;
    let mut request: rasn_kerberos::ApReq = der::decode(&ap_req_with_pac()?)?;
    let mut ticket = decrypt_ticket_enc_part(&request.ticket, key)?;
    ticket.cname = principal([name])?;
    ticket.auth_time = kerberos_time(auth_time)?;
    request.ticket.enc_part.cipher = encrypt_message(
        key,
        &der::encode(&ticket)?,
        KDC_REP_TICKET_USAGE_FOR_TEST,
        PAC_TICKET_CONFOUNDER,
    )?
    .into();
    let session_key = EncryptionKey::new(18, decode_hex(VALID_SESSION_KEY)?);
    let mut authenticator =
        decrypt_ap_req_authenticator(&request, &session_key, AP_REQ_AUTHENTICATOR_USAGE_FOR_TEST)?;
    authenticator.cname = ticket.cname;
    request.authenticator.cipher = encrypt_message(
        &session_key,
        &der::encode(&authenticator)?,
        AP_REQ_AUTHENTICATOR_USAGE_FOR_TEST,
        PAC_AUTHENTICATOR_CONFOUNDER,
    )?
    .into();
    Ok(der::encode(&request)?)
}

/// A valid signature does not authorize a PAC belonging to another client.
#[test]
fn pac_binding_rejects_different_name() -> Result<(), TestError> {
    for name in ["testuser2", "TESTUSER1", "testuser1/extra"] {
        // Given a signed testuser1 PAC but matching ticket/authenticator for testuser2.
        let keytab = syshttp_keytab()?;
        let request = request_with_client(name, 1_494_085_991)?;
        let mut validator = Validator::new(&keytab).with_now(timestamp(1_893_553_447)?);
        // When the real acceptor processes the request.
        let result = validator.validate_ap_req(&request);
        // Then no authenticated result or replay admission is produced.
        assert!(matches!(result, Err(super::Error::PacClientMismatch)));
        assert_eq!(validator.replay_cache_mut().len(), 0);
    }
    Ok(())
}

/// The original synthetic fixture's mismatched authentication time must fail closed.
#[test]
fn pac_binding_rejects_different_authtime() -> Result<(), TestError> {
    for auth_time in [1_893_553_445, 1_494_085_990, 1_494_085_992] {
        // Given the original 2030 ticket authtime and the unchanged 2017 PAC timestamp.
        let keytab = syshttp_keytab()?;
        let request = request_with_client("testuser1", auth_time)?;
        let mut validator = Validator::new(&keytab).with_now(timestamp(1_893_553_447)?);
        // When the real acceptor processes the request.
        let result = validator.validate_ap_req(&request);
        // Then a valid signature cannot bypass the time binding.
        assert!(matches!(result, Err(super::Error::PacClientMismatch)));
        assert_eq!(validator.replay_cache_mut().len(), 0);
    }
    Ok(())
}

/// Exact name and authtime agreement permits returning the verified PAC.
#[test]
fn pac_binding_accepts_matching_client() -> Result<(), TestError> {
    // Given a ticket bound to both fields of the signed PAC client info.
    let keytab = syshttp_keytab()?;
    let request = request_with_client("testuser1", 1_494_085_991)?;
    let mut validator = Validator::new(&keytab).with_now(timestamp(1_893_553_447)?);
    // When the request is validated.
    let accepted = validator.validate_ap_req(&request)?;
    // Then the verified PAC describes the accepted ticket client.
    let info = accepted
        .pac()
        .as_ref()
        .ok_or("PAC present")?
        .client_info()
        .ok_or("client info present")?;
    assert_eq!(info.name, "testuser1");
    assert_eq!(info.client_id.system_time(), timestamp(1_494_085_991)?);
    Ok(())
}

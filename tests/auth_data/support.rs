//! Fixtures: the gokrb5 service keytab and AP-REQ re-encrypted with chosen authorization data.

use rasn::der;
use rasn_kerberos::{AuthorizationData, AuthorizationDataValue};
use rskrb5_ng::{
    ap_req::decrypt_ap_req_authenticator,
    crypto::AesSha1Etype,
    keytab::{EncryptionKey, Keytab},
    ticket::decrypt_ticket_enc_part,
};

use crate::context::{Context as _, TestError};

/// The gokrb5 service keytab of `tests/service.rs`.
const HTTP_KEYTAB: &str = concat!(
    "0502000000440002000b544553542e474f4b5242350004485454500010686f73742e746573742e676f6b",
    "72623500000001590dc4dc010011001057a7754c70c4d85c155c718c2f1292b0000000540002000b",
    "544553542e474f4b5242350004485454500010686f73742e746573742e676f6b72623500000001590d",
    "c4dc01001200209cad00bbc72d703258e911dc18e6d5487cf737bf67fd111f0c2463ad6033bf51",
    "000000440002000b544553542e474f4b5242350004485454500010686f73742e746573742e676f6b",
    "72623500000001590dc4dc020011001057a7754c70c4d85c155c718c2f1292b0000000540002000b",
    "544553542e474f4b5242350004485454500010686f73742e746573742e676f6b72623500000001590d",
    "c4dc02001200209cad00bbc72d703258e911dc18e6d5487cf737bf67fd111f0c2463ad6033bf51",
);

/// The session key of the gokrb5 fixture ticket and authenticator.
const SESSION_KEY: &str = "8845cbaccbf11cb9f467fd577ba51c70d73de6554980a05395bf319e18bdda07";

/// The gokrb5 AP-REQ fixture.
const AP_REQ: &[u8] = include_bytes!("../fixtures/valid_ap_req.der");

/// The ticket-encryption key usage.
const TICKET_USAGE: u32 = 2;
/// The authenticator key usage.
const AUTHENTICATOR_USAGE: u32 = 11;

/// The session key of the fixture.
pub(super) fn session_key() -> EncryptionKey {
    EncryptionKey::new(18_i32, hex::decode(SESSION_KEY).unwrap_or_default())
}

/// The service keytab.
pub(super) fn keytab() -> Result<Keytab, TestError> {
    Keytab::parse(&hex::decode(HTTP_KEYTAB)?).context("keytab parses")
}

/// One authorization data element.
pub(super) fn element(kind: i32, data: &[u8]) -> AuthorizationDataValue {
    AuthorizationDataValue {
        r#type: kind,
        data: data.to_vec().into(),
    }
}

/// An authorization data list holding one element whose payload is the DER of `inner`.
pub(super) fn wrapping(
    kind: i32,
    inner: &impl rasn::Encode,
) -> Result<AuthorizationData, TestError> {
    Ok(vec![element(kind, &der::encode(inner)?)])
}

/// Encrypt `plaintext` under `key` with a fixed confounder.
fn seal(
    key: &EncryptionKey,
    plaintext: &[u8],
    usage: u32,
    confounder: u8,
) -> Result<Vec<u8>, TestError> {
    let etype = AesSha1Etype::from_etype_id(key.etype()).context("AES-SHA1 etype")?;
    Ok(etype.encrypt_message_with_confounder(key.value(), plaintext, usage, &[confounder; 16])?)
}

/// The fixture AP-REQ with its ticket and authenticator re-encrypted around the given authorization data.
pub(super) fn ap_req(
    ticket_data: Option<AuthorizationData>,
    authenticator_data: Option<AuthorizationData>,
) -> Result<Vec<u8>, TestError> {
    let keytab = keytab()?;
    let (service_key, _) = keytab.find_key(&["HTTP", "host.test.gokrb5"], "TEST.GOKRB5", 1, 18)?;
    let mut request: rasn_kerberos::ApReq =
        der::decode(AP_REQ).map_err(|cause| cause.to_string())?;
    let mut ticket = decrypt_ticket_enc_part(&request.ticket, service_key)?;
    ticket.authorization_data = ticket_data;
    request.ticket.enc_part.cipher =
        seal(service_key, &der::encode(&ticket)?, TICKET_USAGE, 0x10)?.into();
    let session = session_key();
    let mut authenticator = decrypt_ap_req_authenticator(&request, &session, AUTHENTICATOR_USAGE)?;
    authenticator.authorization_data = authenticator_data;
    request.authenticator.cipher = seal(
        &session,
        &der::encode(&authenticator)?,
        AUTHENTICATOR_USAGE,
        0x20,
    )?
    .into();
    Ok(der::encode(&request)?)
}

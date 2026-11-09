//! Signed PAC service-request fixtures.

use super::{
    super::context::Context as _, AP_REQ_AUTHENTICATOR_USAGE_FOR_TEST, EncryptionKey,
    KDC_REP_TICKET_USAGE_FOR_TEST, PAC_AUTHENTICATOR_CONFOUNDER, PAC_TICKET_CONFOUNDER, TestError,
    VALID_SESSION_KEY, decode_hex, der, encrypt_message, encryption_key, kerberos_time,
    pac_ad_win2k, pac_authorization_data, principal, realm, syshttp_keytab, zero_kerberos_flags,
};

pub(super) fn ap_req_with_pac() -> Result<Vec<u8>, TestError> {
    ap_req_with_pac_bytes(decode_hex(pac_ad_win2k::PAC_AD_WIN2K)?)
}

pub(super) fn ap_req_with_pac_bytes(pac_bytes: Vec<u8>) -> Result<Vec<u8>, TestError> {
    let keytab = syshttp_keytab()?;
    let (service_key, _) = keytab
        .find_key(&["sysHTTP"], "TEST.GOKRB5", 2, 18)
        .context("sysHTTP service key exists")?;
    let session_key = EncryptionKey::new(18, decode_hex(VALID_SESSION_KEY)?);
    let client = principal(["testuser1"])?;
    let service = principal(["sysHTTP"])?;
    let pac_authorization_data = pac_authorization_data(pac_bytes)?;
    let auth_time = kerberos_time(1_494_085_991)?;
    let ctime = kerberos_time(1_893_553_447)?;

    let enc_ticket = rasn_kerberos::EncTicketPart {
        flags: rasn_kerberos::TicketFlags(zero_kerberos_flags()),
        key: encryption_key(&session_key),
        crealm: realm("TEST.GOKRB5")?,
        cname: client.clone(),
        transited: rasn_kerberos::TransitedEncoding {
            r#type: 1,
            contents: Vec::new().into(),
        },
        auth_time,
        start_time: Some(kerberos_time(1_893_553_445)?),
        end_time: kerberos_time(1_893_639_845)?,
        renew_till: None,
        caddr: None,
        authorization_data: Some(pac_authorization_data),
    };
    let ticket_cipher = encrypt_message(
        service_key,
        &der::encode(&enc_ticket).context("EncTicketPart encodes")?,
        KDC_REP_TICKET_USAGE_FOR_TEST,
        PAC_TICKET_CONFOUNDER,
    )?;

    let authenticator = rasn_kerberos::Authenticator {
        authenticator_vno: 5_i32.into(),
        crealm: realm("TEST.GOKRB5")?,
        cname: client,
        cksum: None,
        cusec: 123_456_i32.into(),
        ctime,
        subkey: None,
        seq_number: Some(42),
        authorization_data: None,
    };
    let authenticator_cipher = encrypt_message(
        &session_key,
        &der::encode(&authenticator).context("Authenticator encodes")?,
        AP_REQ_AUTHENTICATOR_USAGE_FOR_TEST,
        PAC_AUTHENTICATOR_CONFOUNDER,
    )?;

    let ap_req = rasn_kerberos::ApReq {
        pvno: 5_i32.into(),
        msg_type: 14_i32.into(),
        ap_options: rasn_kerberos::ApOptions(zero_kerberos_flags()),
        ticket: rasn_kerberos::Ticket {
            tkt_vno: 5_i32.into(),
            realm: realm("TEST.GOKRB5")?,
            sname: service,
            enc_part: rasn_kerberos::EncryptedData {
                etype: service_key.etype(),
                kvno: Some(2),
                cipher: ticket_cipher.into(),
            },
        },
        authenticator: rasn_kerberos::EncryptedData {
            etype: session_key.etype(),
            kvno: None,
            cipher: authenticator_cipher.into(),
        },
    };

    der::encode(&ap_req).context("AP-REQ encodes")
}

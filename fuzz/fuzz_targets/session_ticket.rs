//! Deterministic, encrypted session tickets shared by reply fuzz harnesses.

use rskrb5_ng::{Principal, ap_req, keytab::EncryptionKey, ticket};

/// Encrypt the fixture's ticket body with the advertised session key and service.
pub(super) fn encoded(service: &Principal, session_key: &EncryptionKey) -> Option<Vec<u8>> {
    let template = ap_req::decode(include_bytes!("../fixtures/valid_ap_req.der")).ok()?;
    let ticket_key = EncryptionKey::new(
        18,
        vec![
            0x9c, 0xad, 0x00, 0xbb, 0xc7, 0x2d, 0x70, 0x32, 0x58, 0xe9, 0x11, 0xdc, 0x18, 0xe6,
            0xd5, 0x48, 0x7c, 0xf7, 0x37, 0xbf, 0x67, 0xfd, 0x11, 0x1f, 0x0c, 0x24, 0x63, 0xad,
            0x60, 0x33, 0xbf, 0x51,
        ],
    );
    let mut body = ticket::decrypt_ticket_enc_part(&template.ticket, &ticket_key).ok()?;
    body.key.r#type = session_key.etype;
    body.key.value = session_key.value.clone().into();
    let mut name = template.ticket.sname;
    name.r#type = service.name_type;
    name.string = service
        .components
        .iter()
        .map(|part| part.as_str().try_into())
        .collect::<Result<_, _>>()
        .ok()?;
    ticket::encode_build_ticket_with_confounder(
        service.realm.as_str().try_into().ok()?,
        name,
        &body,
        &ticket_key,
        template.ticket.enc_part.kvno,
        &[0; 16],
    )
    .ok()
}

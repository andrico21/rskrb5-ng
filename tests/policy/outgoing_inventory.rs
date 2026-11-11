use core::error::Error;

use rasn::{der, types::Integer};
use rasn_kerberos::{ApOptions, ApReq, EncryptedData, KdcReq, KdcReqBody, PaData, Ticket};
use rskrb5_ng::{
    Config, client,
    crypto::{CryptoPolicy, Use},
    error::{Client as ClientError, Policy},
    keytab::EncryptionKey,
};

use super::{CountingTransport, bind, policy_cause, requests};

/// Walk every visible encryption selection; exhaustive patterns make schema growth a build error.
fn inventory(message: &KdcReq) -> Result<Vec<(i32, Use)>, Box<dyn Error>> {
    let KdcReq {
        pvno: _,
        msg_type: _,
        padata,
        req_body,
    } = message;
    let KdcReqBody {
        kdc_options: _,
        cname: _,
        realm: _,
        sname: _,
        from: _,
        till: _,
        rtime: _,
        nonce: _,
        etype,
        addresses: _,
        enc_authorization_data,
        additional_tickets,
    } = req_body;
    let mut fields: Vec<_> = etype.iter().map(|&id| (id, Use::RequestList)).collect();
    if let Some(encrypted) = enc_authorization_data {
        fields.push((enctype(encrypted), Use::SessionKey));
    }
    for ticket in additional_tickets.as_deref().unwrap_or_default() {
        fields.push((ticket_enctype(ticket), Use::TicketKey));
    }
    for PaData { r#type, value } in padata.as_deref().unwrap_or_default() {
        match *r#type {
            1_i32 => {
                let ApReq {
                    pvno: _,
                    msg_type: _,
                    ap_options: _,
                    ticket,
                    authenticator,
                } = der::decode(value)?;
                fields.push((ticket_enctype(&ticket), Use::TicketKey));
                fields.push((enctype(&authenticator), Use::SessionKey));
            }
            2_i32 => fields.push((enctype(&der::decode(value)?), Use::ReplyKey)),
            _ => return Err("fixture contains an unclassified PA envelope".into()),
        }
    }
    Ok(fields)
}

/// Account for every field of the opaque encryption envelope.
const fn enctype(data: &EncryptedData) -> i32 {
    let EncryptedData {
        etype,
        kvno: _,
        cipher: _,
    } = data;
    *etype
}

/// Account for every visible field of a ticket without decrypting its ciphertext.
const fn ticket_enctype(ticket: &Ticket) -> i32 {
    let Ticket {
        tkt_vno: _,
        realm: _,
        sname: _,
        enc_part,
    } = ticket;
    enctype(enc_part)
}

/// Populate all encrypted paths simultaneously, using distinct type-safe dependency fields.
fn populated() -> Result<KdcReq, Box<dyn Error>> {
    let (request, _) = requests(17)?;
    let mut message = request.message().0.clone();
    let encrypted = message
        .req_body
        .enc_authorization_data
        .clone()
        .ok_or("body absent")?;
    let ticket = Ticket {
        tkt_vno: Integer::from(5_i32),
        realm: message.req_body.realm.clone(),
        sname: message.req_body.sname.clone().ok_or("service absent")?,
        enc_part: encrypted.clone(),
    };
    let ap = ApReq {
        pvno: Integer::from(5_i32),
        msg_type: Integer::from(14_i32),
        ap_options: ApOptions::reserved(),
        ticket: ticket.clone(),
        authenticator: encrypted.clone(),
    };
    message.req_body.additional_tickets = Some(vec![ticket]);
    message.padata = Some(vec![
        PaData {
            r#type: 1,
            value: der::encode(&ap)?.into(),
        },
        PaData {
            r#type: 2,
            value: der::encode(&encrypted)?.into(),
        },
    ]);
    Ok(message)
}

/// Every inventoried path must independently refuse an excluded enctype, not only the first path.
#[test]
fn outgoing_encryption_inventory_is_guarded() -> Result<(), Box<dyn Error>> {
    let config = Config::parse("[libdefaults]\npermitted_enctypes = aes128-cts")?;
    let policy = CryptoPolicy::from_libdefaults(&config.libdefaults)?;
    let baseline = populated()?;
    let paths = inventory(&baseline)?;
    assert_eq!(
        paths,
        vec![
            (17_i32, Use::RequestList),
            (17_i32, Use::SessionKey),
            (17_i32, Use::TicketKey),
            (17_i32, Use::TicketKey),
            (17_i32, Use::SessionKey),
            (17_i32, Use::ReplyKey),
        ]
    );
    for index in 0_usize..=paths.len() {
        let mut message = baseline.clone();
        let key = EncryptionKey::new(if index == paths.len() { 18 } else { 17 }, vec![0; 16]);
        match index {
            0 => message.req_body.etype = vec![17_i32, 18_i32],
            1 => {
                message
                    .req_body
                    .enc_authorization_data
                    .as_mut()
                    .ok_or("body absent")?
                    .etype = 18_i32;
            }
            2 => {
                let tickets = message
                    .req_body
                    .additional_tickets
                    .as_mut()
                    .ok_or("tickets absent")?;
                let mut excluded = tickets.first().ok_or("ticket absent")?.clone();
                excluded.enc_part.etype = 18_i32;
                tickets.push(excluded);
            }
            3 | 4 => {
                let data = message.padata.as_mut().ok_or("padata absent")?;
                let mut ap: ApReq = der::decode(&data.first().ok_or("AP absent")?.value)?;
                if index == 3 {
                    ap.ticket.enc_part.etype = 18_i32;
                } else {
                    ap.authenticator.etype = 18_i32;
                }
                data.push(PaData {
                    r#type: 1,
                    value: der::encode(&ap)?.into(),
                });
            }
            5 => message
                .padata
                .as_mut()
                .ok_or("padata absent")?
                .push(PaData {
                    r#type: 2,
                    value: der::encode(&EncryptedData {
                        etype: 18,
                        kvno: None,
                        cipher: vec![0x47; 32].into(),
                    })?
                    .into(),
                }),
            _ => {}
        }
        let usage = paths.get(index).map_or(Use::ReplyKey, |&(_, usage)| usage);
        let (mut as_request, mut tgs_request) = bind(&message)?;
        as_request.set_crypto_policy(policy.clone());
        tgs_request.set_crypto_policy(policy.clone());
        let mut transport = CountingTransport(0);
        for result in [
            client::exchange_as_req(&mut transport, &as_request, &key),
            client::exchange_tgs_req(&mut transport, &tgs_request, &key),
        ] {
            let error = result.err().ok_or("excluded inventory field admitted")?;
            assert_eq!(
                policy_cause(&error),
                Some(&Policy::EnctypeNotPermitted {
                    etype: 18_i32,
                    usage
                })
            );
        }
        assert_eq!(transport.0, 0, "inventory path {index} reached transport");
    }
    Ok(())
}

/// Unsupported credential PA envelopes cannot bypass admission as opaque informational data.
#[test]
fn outgoing_unsupported_credential_padata_is_rejected() -> Result<(), Box<dyn Error>> {
    let kinds: [i32; 33] = [
        5_i32, 6, 7, 8, 9, 11, 12, 13, 16, 17, 19, 22, 23, 30, 31, 41, 130, 134, 135, 136, 138,
        141, 142, 143, 144, 145, 146, 147, 148, 151, 152, 153, 165,
    ];
    for kind in kinds {
        let mut message = populated()?;
        message
            .padata
            .as_mut()
            .ok_or("padata absent")?
            .push(PaData {
                r#type: kind,
                value: vec![0x47; 32].into(),
            });
        let (as_request, tgs_request) = bind(&message)?;
        let mut transport = CountingTransport(0);
        for result in [
            client::exchange_as_req(
                &mut transport,
                &as_request,
                &EncryptionKey::new(17, vec![0; 16]),
            ),
            client::exchange_tgs_req(
                &mut transport,
                &tgs_request,
                &EncryptionKey::new(17, vec![0; 16]),
            ),
        ] {
            assert!(
                matches!(
                    result,
                    Err(ClientError::Encode {
                        target: "PA-DATA",
                        message: _
                    })
                ),
                "unsupported PA type {kind} admitted"
            );
        }
        assert_eq!(transport.0, 0);
    }
    Ok(())
}

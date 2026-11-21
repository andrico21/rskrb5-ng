use core::error::Error;

use rasn::{der, types::Integer};
use rasn_kerberos::{ApOptions, ApReq, EncryptedData, KdcReq, KdcReqBody, PaData, Ticket};
use rskrb5_ng::{
    Config, client,
    crypto::{CryptoPolicy, Use},
    error::{Client as ClientError, Policy, RejectedFeature},
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

/// PA types whose refusal names the class: the enctype hints a KDC or peer sends.
const PEER_HINTS: [i32; 4] = [11, 19, 23, 165];

/// The one PA type that only embeds an element of the other encoding.
const EMBEDDING_WRAPPER: i32 = 22;

/// PA types this client neither builds nor can policy-check: credential mechanisms, the halves a KDC
/// sends, FAST armor, authentication sets, and obsolete or vendor ids.
const UNSUPPORTED: [i32; 23] = [
    5, 6, 7, 8, 9, 12, 13, 17, 30, 31, 41, 130, 134, 135, 141, 143, 144, 145, 146, 147, 148, 152,
    153,
];

/// PA types with their own decoder: a payload that is not their element is refused.
///
/// The refusal happens before the transport. 136 (PA-FX-FAST) and 138 (PA-ENCRYPTED-CHALLENGE)
/// are admitted by FAST (todo 7); PA-SPAKE (151) is admitted checked: only a support message or a
/// response leaves the client; PA-OTP-REQUEST (142, todo 10) is admitted checked: the one OTP type a
/// client sends (141 and 144 are KDC halves and stay refused); PA-PK-AS-REQ (16) is admitted checked
/// by PKINIT (todo 8): only a DER PA-PK-AS-REQ leaves the client.
const DECODED: [i32; 7] = [1, 2, 16, 136, 138, 142, 151];

/// The permanently refused draft-9 PKINIT types, refused by the selection layer before the arms.
const DRAFT9_PKINIT: [i32; 2] = [14, 15];

/// Every outgoing PA type from 0 to 255 is refused or admitted exactly as the inventory says.
///
/// The refusal names the class where one is known (peer-only enctype hint, embedding wrapper);
/// the rest of the refused set shares one message that makes no claim about the mechanism. Every
/// other type, those next to the refused ones included, reaches the transport.
#[test]
fn outgoing_padata_types_are_refused_or_admitted_exactly() -> Result<(), Box<dyn Error>> {
    for kind in 0_i32..=255_i32 {
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
        let mut admitted = 0_usize;
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
            let expected = if PEER_HINTS.contains(&kind) {
                Some(format!(
                    "outgoing PA type {kind} is a peer-only enctype hint"
                ))
            } else if kind == EMBEDDING_WRAPPER {
                Some(format!(
                    "outgoing PA type {kind} embeds data that cannot be policy-checked"
                ))
            } else if UNSUPPORTED.contains(&kind) {
                Some(format!("outgoing PA type {kind} is not supported"))
            } else {
                None
            };
            let actual = match &result {
                Err(ClientError::Encode {
                    target: "PA-DATA",
                    message: text,
                }) => Some(text.as_str()),
                _ => None,
            };
            if let Some(text) = &expected {
                assert_eq!(actual, Some(text.as_str()), "PA type {kind}");
            } else if DRAFT9_PKINIT.contains(&kind) {
                let error = result.err().ok_or("draft-9 PKINIT admitted")?;
                assert!(
                    matches!(
                        policy_cause(&error),
                        Some(Policy::RejectedFeature {
                            feature: RejectedFeature::Draft9Pkinit,
                            reason: _
                        })
                    ),
                    "PA type {kind}: {error}"
                );
            } else if DECODED.contains(&kind) {
                assert_eq!(actual, None, "PA type {kind} has no refusal arm");
                assert!(
                    result.is_err(),
                    "PA type {kind}: a garbage element was admitted"
                );
            } else {
                assert_eq!(actual, None, "PA type {kind} is not refused by the arms");
                assert!(
                    matches!(&result, Err(ClientError::Transport(text)) if text == "admitted request"),
                    "PA type {kind}: expected the transport to be reached, got {result:?}"
                );
                admitted += 1;
            }
        }
        assert_eq!(transport.0, admitted, "PA type {kind}: transport sends");
    }
    Ok(())
}

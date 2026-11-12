//! Functional service-acquisition replacement through the public client path.

use core::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use rasn::{der, types::Integer};
use rasn_kerberos::{
    ApReq, EncKdcRepPart, EncTgsRepPart, EncryptedData, KdcRep, KerberosFlags, KerberosTime,
    TgsRep, TgsReq, Ticket, TicketFlags,
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpListener,
    runtime::Builder,
    time::timeout,
};

use super::TestError;
use crate::{
    Config, ap_req,
    client::{AsRepSession, Principal, Tokio, principal_to_rasn, transport::KdcProtocol},
    crypto::AesSha1Etype,
    keytab::EncryptionKey,
    ticket,
};

/// A bounded TGS peer seals a fresh key under the actual request authenticator subkey.
/// # Cancel safety
/// Cancellation drops this fixture's socket; no shared state survives it.
async fn answer_service(listener: TcpListener) -> Result<(), TestError> {
    let (mut socket, _) = listener.accept().await?;
    let length = usize::try_from(socket.read_u32().await?)?;
    let _bounded = u16::try_from(length)?;
    let mut bytes = vec![0; length];
    let _: usize = socket.read_exact(&mut bytes).await?;
    let request: TgsReq = der::decode(&bytes)?;
    let authenticator: ApReq = der::decode(
        request
            .0
            .padata
            .as_ref()
            .and_then(|data| data.iter().find(|value| value.r#type == 1))
            .ok_or("AP request")?
            .value
            .as_ref(),
    )?;
    let auth = ap_req::decrypt_ap_req_authenticator(
        &authenticator,
        &EncryptionKey::new(18, vec![0x41; 32]),
        7,
    )?;
    let (key, usage) = match auth.subkey {
        Some(key) => (EncryptionKey::new(key.r#type, key.value.to_vec()), 9),
        None => (EncryptionKey::new(18, vec![0x41; 32]), 8),
    };
    let body = request.0.req_body;
    let service = body.sname.ok_or("service name")?;
    let seconds = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
    let now = KerberosTime(
        chrono::DateTime::from_timestamp(seconds, 0)
            .ok_or("time")?
            .fixed_offset(),
    );
    let part = EncTgsRepPart(EncKdcRepPart {
        key: rasn_kerberos::EncryptionKey {
            r#type: 18,
            value: vec![0x63; 32].into(),
        },
        last_req: vec![],
        nonce: body.nonce,
        key_expiration: None,
        flags: TicketFlags(KerberosFlags::from_slice(&[0; 4])),
        auth_time: now.clone(),
        start_time: Some(now),
        end_time: body.till,
        renew_till: None,
        srealm: body.realm.clone(),
        sname: service.clone(),
        caddr: None,
        encrypted_pa_data: None,
    });
    let cipher = AesSha1Etype::from_etype_id(18)
        .ok_or("AES")?
        .encrypt_message_with_confounder(key.value(), &der::encode(&part)?, usage, &[0; 16])?;
    let reply = TgsRep(KdcRep {
        pvno: Integer::from(5_i32),
        msg_type: Integer::from(13_i32),
        padata: None,
        crealm: body.realm.clone(),
        cname: principal_to_rasn(&Principal::user("EXAMPLE.COM", "alice"))?,
        ticket: Ticket {
            tkt_vno: Integer::from(5_i32),
            realm: body.realm,
            sname: service,
            enc_part: EncryptedData {
                etype: 18,
                kvno: None,
                cipher: vec![0x74; 16].into(),
            },
        },
        enc_part: EncryptedData {
            etype: 18,
            kvno: None,
            cipher: cipher.into(),
        },
    });
    let encoded = der::encode(&reply)?;
    socket.write_u32(u32::try_from(encoded.len())?).await?;
    socket.write_all(&encoded).await?;
    Ok(())
}

/// Public acquisition replaces an expired retained service session with the authenticated reply.
/// This is functional replacement, not a live observation of dependency-owned ticket erasure.
#[test]
fn service_acquisition_replaces_expired_cached_session() -> Result<(), TestError> {
    Builder::new_current_thread().enable_all().build()?.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let config = Config::parse(&format!("[libdefaults]\n dns_lookup_kdc = false\n[realms]\n EXAMPLE.COM = {{\n kdc = {}\n }}\n", listener.local_addr()?))?;
        let principal = Principal::user("EXAMPLE.COM", "alice");
        let service = Principal::new("EXAMPLE.COM", 2, ["HTTP", "host.example.com"]);
        let tgt_service = Principal::tgt_service("EXAMPLE.COM");
        let wire_ticket = Ticket {
            tkt_vno: Integer::from(5_i32), realm: "EXAMPLE.COM".try_into()?,
            sname: principal_to_rasn(&tgt_service)?,
            enc_part: EncryptedData { etype: 18, kvno: None, cipher: vec![0x52; 16].into() },
        };
        let now = SystemTime::now();
        let tgt = AsRepSession::new(principal.clone(), tgt_service,
            EncryptionKey::new(18, vec![0x41; 32]), ticket::encode(&wire_ticket)?.into(),
            [0; 4], now, now.checked_add(Duration::from_hours(10)).ok_or("end time")?);
        let mut client = Tokio::from_tgt_session(config, KdcProtocol::Tcp, tgt);
        let old_ticket = Ticket {
            sname: principal_to_rasn(&service)?,
            ..wire_ticket
        };
        let old = AsRepSession::new(principal, service.clone(), EncryptionKey::new(18, vec![0x31; 32]),
            ticket::encode(&old_ticket)?.into(), [0; 4], UNIX_EPOCH, UNIX_EPOCH);
        drop(client.service_tickets.insert(crate::client::service_cache_key(&service), old));
        let (issued, ()) = timeout(Duration::from_secs(10), async {
            tokio::try_join!(async { client.get_service_ticket(service.clone()).await.map_err(|err| TestError::from(format!("service acquisition: {err} ({err:?})"))) }, answer_service(listener))
        }).await??;
        assert_eq!(issued.session_key().value().as_ref(), &[0x63; 32]);
        let replacement = client.cached_service_ticket(service);
        assert!(replacement.is_some(), "authenticated replacement was not cached");
        let cached = replacement.ok_or("replacement not cached")?;
        assert_eq!(cached.session_key().value().as_ref(), &[0x63; 32]);
        assert_eq!(cached.ticket(), issued.ticket());
        Ok(())
    })
}

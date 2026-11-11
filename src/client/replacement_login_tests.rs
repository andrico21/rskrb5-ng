//! Live first-party key erasure across successful login replacement.

use core::{error::Error, time::Duration};
use std::time::{SystemTime, UNIX_EPOCH};

use rasn::{der, types::Integer};
use rasn_kerberos::{
    AsRep, AsReq, EncAsRepPart, EncKdcRepPart, EncryptedData, KdcRep, KerberosFlags, KerberosTime,
    Ticket, TicketFlags,
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpListener,
    runtime::Builder,
    time::timeout,
};

use crate::{
    Config,
    client::{
        AsRepSession, PreauthKeyInfo, Principal, Tokio, derive_password_reply_key,
        transport::KdcProtocol,
    },
    crypto::AesSha1Etype,
    keytab::{EncryptionKey, key_bytes::EVENTS},
};

type TestError = Box<dyn Error + Send + Sync>;

/// A bounded loopback AS peer supplies a real encrypted replacement session.
/// # Cancel safety
/// Cancellation abandons only this fixture's socket.
async fn answer(listener: TcpListener) -> Result<(), TestError> {
    let (mut socket, _) = listener.accept().await?;
    let length = usize::try_from(socket.read_u32().await?)?;
    let _bounded = u16::try_from(length)?;
    let mut bytes = vec![0; length];
    let _: usize = socket.read_exact(&mut bytes).await?;
    let request: AsReq = der::decode(&bytes)?;
    let body = request.0.req_body;
    let name = body.cname.ok_or("client name")?;
    let service = body.sname.ok_or("service name")?;
    let principal = Principal::user("EXAMPLE.COM", "alice");
    let key =
        derive_password_reply_key(&principal, b"retained-password", &PreauthKeyInfo::new(18))?;
    let seconds = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
    let now = KerberosTime(
        chrono::DateTime::from_timestamp(seconds, 0)
            .ok_or("fixture time")?
            .fixed_offset(),
    );
    let part = EncAsRepPart(EncKdcRepPart {
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
        .encrypt_message_with_confounder(key.value(), &der::encode(&part)?, 3, &[0; 16])?;
    let reply = AsRep(KdcRep {
        pvno: Integer::from(5_i32),
        msg_type: Integer::from(11_i32),
        padata: None,
        crealm: body.realm.clone(),
        cname: name,
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

/// Both login entry points erase the displaced first-party cached service key.
#[test]
fn login_replacement_erases_live_cached_key() -> Result<(), TestError> {
    Builder::new_current_thread().enable_all().build()?.block_on(async {
        for affirm in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let config = Config::parse(&format!("[libdefaults]\n dns_lookup_kdc = false\n[realms]\n EXAMPLE.COM = {{\n kdc = {}\n }}\n", listener.local_addr()?))?;
            let principal = Principal::user("EXAMPLE.COM", "alice");
            let mut client = Tokio::with_password(config, KdcProtocol::Tcp, principal.clone(), b"retained-password").with_fast_negotiation(false);
            let old = AsRepSession::new(principal, Principal::tgt_service("EXAMPLE.COM"), EncryptionKey::new(17, vec![0x41; 16]), vec![0x52; 16].into(), [0; 4], UNIX_EPOCH, UNIX_EPOCH);
            client.tgt = Some(old.clone());
            drop(client.tgt_sessions.insert("EXAMPLE.COM".to_owned(), old.clone()));
            drop(client.service_tickets.insert(("EXAMPLE.COM".to_owned(), vec!["old".to_owned()]), old));
            EVENTS.with_borrow_mut(Vec::clear);
            let operation = Box::pin(async {
                if affirm { client.affirm_login().await } else { client.login().await }
            });
            let (session, ()) = timeout(Duration::from_secs(10), async { tokio::try_join!(async { operation.await.map_err(|error| TestError::from(error.to_string())) }, answer(listener)) }).await??;
            assert_eq!(session.session_key().value().as_ref(), &[0x63; 32]);
            EVENTS.with_borrow(|events| {
                assert_eq!(events.iter().filter(|(length, _)| *length == 16).count(), if affirm { 4 } else { 3 });
                assert!(events.iter().all(|(_, erased)| *erased), "live key wipe omitted");
            });
            assert_eq!(client.cached_service_ticket_count(), 0);
        }
        Ok(())
    })
}

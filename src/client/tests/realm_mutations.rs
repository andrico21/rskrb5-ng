//! Deterministic realm-cache selection across a ticket start boundary.

use core::{error::Error, time::Duration};
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::DateTime;
use rasn::{der, types::Integer};
use rasn_kerberos::{
    EncKdcRepPart, EncTgsRepPart, EncryptedData, KdcRep, KerberosFlags, KerberosString,
    KerberosTime, PrincipalName, TgsRep, TicketFlags,
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpListener,
    task::JoinSet,
    time::timeout,
};

use crate::{
    client::{self, AsRepSession, Principal, transport::KdcProtocol},
    crypto::AesSha1Etype,
    kadmin::Request,
    keytab::EncryptionKey,
    ticket,
};

/// Fixture failures can cross the loopback peer task boundary.
type TestError = Box<dyn Error + Send + Sync>;

/// A framed renewal reply authenticates the new session key and server identity.
async fn answer_renewal(listener: TcpListener, session: AsRepSession) -> Result<(), TestError> {
    let (mut stream, _) = timeout(Duration::from_secs(10), listener.accept()).await??;
    let mut mark = [0; 4];
    let _: usize = timeout(Duration::from_secs(10), stream.read_exact(&mut mark)).await??;
    let mut bytes = vec![0; usize::try_from(u32::from_be_bytes(mark))?];
    let _: usize = timeout(Duration::from_secs(10), stream.read_exact(&mut bytes)).await??;
    let request: rasn_kerberos::TgsReq = der::decode(&bytes)?;
    let time = |value: SystemTime| -> Result<KerberosTime, TestError> {
        let seconds = i64::try_from(value.duration_since(UNIX_EPOCH)?.as_secs())?;
        Ok(KerberosTime(
            DateTime::from_timestamp(seconds, 0)
                .ok_or("time")?
                .fixed_offset(),
        ))
    };
    let server = PrincipalName {
        r#type: 2,
        string: session
            .service
            .components
            .iter()
            .map(|value| KerberosString::try_from(value.as_str()))
            .collect::<Result<_, _>>()?,
    };
    let part = EncTgsRepPart(EncKdcRepPart {
        key: rasn_kerberos::EncryptionKey {
            r#type: 18,
            value: vec![0x66; 32].into(),
        },
        last_req: vec![],
        nonce: request.0.req_body.nonce,
        key_expiration: None,
        flags: TicketFlags(KerberosFlags::from_slice(&[0; 4])),
        auth_time: time(session.auth_time)?,
        start_time: Some(time(session.start_time)?),
        end_time: time(session.end_time)?,
        renew_till: None,
        srealm: KerberosString::try_from(session.service.realm.as_str())?,
        sname: server,
        caddr: None,
        encrypted_pa_data: None,
    });
    let cipher = AesSha1Etype::from_etype_id(18)
        .ok_or("AES")?
        .encrypt_message_with_confounder(
            session.session_key.value(),
            &der::encode(&part)?,
            8,
            &[0; 16],
        )?;
    let reply = TgsRep(KdcRep {
        pvno: Integer::from(5_i32),
        msg_type: Integer::from(13_i32),
        padata: None,
        crealm: KerberosString::try_from(session.client.realm.as_str())?,
        cname: PrincipalName {
            r#type: 1,
            string: vec![KerberosString::try_from("client")?],
        },
        ticket: ticket::decode(&session.ticket)?,
        enc_part: EncryptedData {
            etype: 18,
            kvno: None,
            cipher: cipher.into(),
        },
    });
    let encoded = der::encode(&reply)?;
    timeout(
        Duration::from_secs(10),
        stream.write_all(&u32::try_from(encoded.len())?.to_be_bytes()),
    )
    .await??;
    timeout(Duration::from_secs(10), stream.write_all(&encoded)).await??;
    Ok(())
}

/// Clock-controlled acquisition renews foreign entries but does not renew home entries.
#[tokio::test]
async fn realm_selection_across_start_boundary() -> Result<(), TestError> {
    for foreign in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let now = UNIX_EPOCH
            + Duration::from_secs(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs());
        let destination = if foreign {
            "OTHER.TEST"
        } else {
            "EXAMPLE.TEST"
        };
        let mut session = super::session_with_key(EncryptionKey::new(18, vec![0x11; 32]))?;
        session.auth_time = now;
        session.start_time = now;
        session.end_time = now + Duration::from_secs(60);
        session.renew_till = Some(now + Duration::from_secs(120));
        session.ticket_flags = client::KDC_OPTION_RENEWABLE.to_be_bytes();
        session.service = Principal::new("EXAMPLE.TEST", 2, ["krbtgt", destination]);
        let mut wire = Request::parse(&hex::decode(
            include_str!("../../../tests/fixtures/kpasswd-request.hex").trim(),
        )?)?
        .ap_req()
        .ticket
        .clone();
        wire.realm = KerberosString::try_from("EXAMPLE.TEST")?;
        wire.sname = PrincipalName {
            r#type: 2,
            string: vec![
                KerberosString::try_from("krbtgt")?,
                KerberosString::try_from(destination)?,
            ],
        };
        session.ticket = ticket::encode(&wire)?.into();
        let config = crate::Config::parse(&format!(
            "[libdefaults]\ndns_lookup_kdc = false\n[realms]\nEXAMPLE.TEST = {{\nkdc = {address}\n}}\nOTHER.TEST = {{\nkdc = {address}\n}}\n"
        ))?;
        let mut client = client::Tokio::new(config, KdcProtocol::Tcp, session.client.clone(), None);
        drop(
            client
                .tgt_sessions
                .insert(destination.to_owned(), session.clone()),
        );
        let mut peers = JoinSet::new();
        drop(peers.spawn(answer_renewal(listener, session)));
        let mut first = true;
        let result = timeout(
            Duration::from_secs(10),
            client.get_service_ticket_with_clock(
                Principal::new(destination, 2, ["HTTP", "host"]),
                || {
                    let instant = if first {
                        now - Duration::from_secs(1)
                    } else {
                        now
                    };
                    first = false;
                    instant
                },
            ),
        )
        .await?;
        drop(result);
        peers.abort_all();
        while let Some(outcome) = timeout(Duration::from_secs(10), peers.join_next()).await? {
            match outcome {
                Ok(delivery) => delivery?,
                Err(error) if error.is_cancelled() => {}
                Err(error) => return Err(error.into()),
            }
        }
        let cached = client.tgt_sessions.get(destination).ok_or("realm cache")?;
        assert_eq!(cached.session_key.value().as_slice() == [0x66; 32], foreign);
        assert!(
            client.tgt.is_none(),
            "foreign renewal must not replace the primary TGT"
        );
    }
    Ok(())
}

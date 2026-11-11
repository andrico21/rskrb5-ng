use core::{error::Error, future::poll_fn, net::SocketAddr, pin::pin, task::Poll, time::Duration};
use std::time::SystemTime;

use rasn::der;
use rasn_kerberos::EncryptedData;
use rskrb5_ng::{
    Config,
    client::{
        self, AsRepSession, BuiltAsReq, BuiltTgsReq,
        options::AsReq,
        principal::Principal,
        transport::{KdcProtocol, Tokio},
    },
    crypto::{CryptoPolicy, Use},
    error::{Client as ClientError, Policy, RejectedFeature, RejectionReason},
    kdc_req,
    keytab::EncryptionKey,
};
use tokio::{io::ReadBuf, net::UdpSocket, runtime::Builder, time::timeout};

use super::{client::policy_cause, exchange_admission::CountingTransport};

/// Encode the same opaque authorization envelope into both public built-request forms.
fn requests(etype: i32) -> Result<(BuiltAsReq, BuiltTgsReq), Box<dyn Error>> {
    let original = client::build_tgt_as_req(
        Principal::user("EXAMPLE.COM", "alice"),
        AsReq::new(SystemTime::UNIX_EPOCH, 42).with_etypes(vec![17_i32]),
    )?;
    let mut body = original.message().0.req_body.clone();
    body.enc_authorization_data = Some(EncryptedData {
        etype,
        kvno: None,
        cipher: vec![0x47; 32].into(),
    });
    bind(&kdc_req::build_as_req(body, None).0)
}

/// Bind a custom wire message without substituting an ordinary builder's fields.
fn bind(message: &rasn_kerberos::KdcReq) -> Result<(BuiltAsReq, BuiltTgsReq), Box<dyn Error>> {
    let original = client::build_tgt_as_req(
        Principal::user("EXAMPLE.COM", "alice"),
        AsReq::new(SystemTime::UNIX_EPOCH, 42).with_etypes(vec![17_i32]),
    )?;
    let as_message = kdc_req::build_as_req(message.req_body.clone(), message.padata.clone());
    let tgs_message = kdc_req::build_tgs_req(message.req_body.clone(), message.padata.clone());
    let as_der = der::encode(&as_message)?;
    let tgs_der = der::encode(&tgs_message)?;
    Ok((
        BuiltAsReq::new(
            as_message,
            as_der.into(),
            original.client().clone(),
            original.service().clone(),
            original.nonce(),
        ),
        BuiltTgsReq::new(
            tgs_message,
            tgs_der.into(),
            original.client().clone(),
            original.service().clone(),
            "EXAMPLE.COM".to_owned(),
            original.nonce(),
        ),
    ))
}

/// Exhaustive dependency-field and behavioral coverage of outgoing encryption envelopes.
#[path = "outgoing_inventory.rs"]
mod inventory;

/// Distinguish runtime exclusion from permanent rejection at the body boundary.
fn expected(etype: i32) -> Option<Policy> {
    match etype {
        17_i32 => None,
        1_i32 => Some(Policy::RejectedFeature {
            feature: RejectedFeature::SingleDes,
            reason: RejectionReason::RemovedAndInsecure,
        }),
        _ => Some(Policy::EnctypeNotPermitted {
            etype,
            usage: Use::SessionKey,
        }),
    }
}

/// Matching DER and permitted outer selections cannot hide excluded body encryption.
#[test]
fn checked_exchanges_admit_body_authorization_enctype() -> Result<(), Box<dyn Error>> {
    let config = Config::parse("[libdefaults]\npermitted_enctypes = aes128-cts")?;
    let policy = CryptoPolicy::from_libdefaults(&config.libdefaults)?;
    let key = EncryptionKey::new(17, vec![0; 16]);
    for etype in [18_i32, 1_i32, 17_i32] {
        let (mut as_request, mut tgs_request) = requests(etype)?;
        as_request.set_crypto_policy(policy.clone());
        tgs_request.set_crypto_policy(policy.clone());
        let mut transport = CountingTransport(0);
        let outcomes = [
            client::exchange_as_req(&mut transport, &as_request, &key),
            client::exchange_tgs_req(&mut transport, &tgs_request, &key),
        ];
        assert_eq!(transport.0, if etype == 17_i32 { 2 } else { 0 });
        for outcome in outcomes {
            let error = outcome.err().ok_or("counting transport must fail")?;
            assert_eq!(policy_cause(&error).copied(), expected(etype));
            if etype == 17_i32 {
                assert!(matches!(error, ClientError::Transport(_)));
            }
        }
    }
    Ok(())
}

/// Either a received packet or the completed client exchange.
enum Event {
    Packet(SocketAddr),
    Outcome(Result<(), ClientError>),
}

/// Count actual UDP requests and answer with malformed DER to finish permitted exchanges.
/// # Cancel safety
/// cancel-safe: no shared state; dropping the exchange closes its socket.
async fn counted<F>(socket: &UdpSocket, exchange: F) -> Result<(ClientError, usize), Box<dyn Error>>
where
    F: Future<Output = Result<AsRepSession, ClientError>>,
{
    let mut pending = pin!(exchange);
    let mut buffer = [0_u8; 4096];
    let mut sends = 0_usize;
    let outcome = timeout(Duration::from_secs(5), async {
        loop {
            let event = poll_fn(|context| {
                let mut read = ReadBuf::new(&mut buffer);
                if let Poll::Ready(received) = socket.poll_recv_from(context, &mut read) {
                    return Poll::Ready(received.map(Event::Packet));
                }
                pending
                    .as_mut()
                    .poll(context)
                    .map(|outcome| Ok(Event::Outcome(outcome.map(drop))))
            })
            .await?;
            match event {
                Event::Packet(peer) => {
                    sends = sends.saturating_add(1);
                    let _: usize = socket.send_to(&[0xff], peer).await?;
                }
                Event::Outcome(result) => return Ok::<_, Box<dyn Error>>(result),
            }
        }
    })
    .await??;
    Ok((outcome.err().ok_or("malformed reply must fail")?, sends))
}

/// Both explicit and configured Tokio paths enforce the effective policy before any send.
#[test]
fn tokio_exchanges_admit_body_authorization_enctype() -> Result<(), Box<dyn Error>> {
    let runtime = Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let addr = socket.local_addr()?;
        let config = Config::parse(&format!(
            "[libdefaults]\npermitted_enctypes = aes128-cts\ndns_lookup_kdc = false\n\
             [realms]\nEXAMPLE.COM = {{\n kdc = {addr}\n}}"
        ))?;
        let policy = CryptoPolicy::from_libdefaults(&config.libdefaults)?;
        let transport = Tokio::new();
        let key = EncryptionKey::new(17, vec![0; 16]);
        for etype in [18_i32, 1_i32, 17_i32] {
            let (mut as_request, mut tgs_request) = requests(etype)?;
            as_request.set_crypto_policy(policy.clone());
            tgs_request.set_crypto_policy(policy.clone());
            let explicit_as = counted(
                &socket,
                transport.exchange_as_req(KdcProtocol::Udp, addr, &as_request, &key),
            )
            .await?;
            let explicit_tgs = counted(
                &socket,
                transport.exchange_tgs_req(KdcProtocol::Udp, addr, &tgs_request, &key),
            )
            .await?;
            as_request.set_crypto_policy(CryptoPolicy::default());
            tgs_request.set_crypto_policy(CryptoPolicy::default());
            let configured_as = counted(
                &socket,
                transport.exchange_as_req_with_config(&config, KdcProtocol::Udp, &as_request, &key),
            )
            .await?;
            let configured_tgs = counted(
                &socket,
                transport.exchange_tgs_req_with_config(
                    &config,
                    KdcProtocol::Udp,
                    &tgs_request,
                    &key,
                ),
            )
            .await?;
            for (error, sends) in [explicit_as, explicit_tgs, configured_as, configured_tgs] {
                assert_eq!(sends, usize::from(etype == 17_i32));
                assert_eq!(policy_cause(&error).copied(), expected(etype));
            }
        }
        Ok(())
    })
}

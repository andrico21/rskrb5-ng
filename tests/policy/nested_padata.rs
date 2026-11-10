use core::error::Error;
use std::time::SystemTime;

use rasn_kerberos::PaData;
use rskrb5_ng::{
    Config,
    client::{
        self,
        options::{AsReq, TgsReq},
        principal::Principal,
        transport::{KdcProtocol, Tokio},
    },
    crypto::{CryptoPolicy, Use},
    error::{Client as ClientError, Policy},
    kdc_req,
    keytab::EncryptionKey,
};
use tokio::runtime::Builder;

use super::{
    client::{policy_cause, session},
    exchange_admission::CountingTransport,
};

/// Generate real encrypted PA credentials independently of the admitting policy.
fn credential(kind: i32, ticket_etype: i32, key_etype: i32) -> Result<PaData, Box<dyn Error>> {
    let key = EncryptionKey::new(key_etype, vec![0; if key_etype == 17 { 16 } else { 32 }]);
    if kind == client::PA_ENC_TIMESTAMP {
        return Ok(client::pa_enc_timestamp_with_confounder(
            &key,
            SystemTime::UNIX_EPOCH,
            0,
            &[0; 16],
            None,
        )?);
    }
    let mut tgt = session(key_etype, ticket_etype)?;
    tgt.set_session_key(key);
    let request = client::build_tgs_req_with_confounder(
        &tgt,
        Principal::new("EXAMPLE.COM", 2, ["HTTP", "other"]),
        TgsReq::new(SystemTime::UNIX_EPOCH, 42).with_etypes(vec![17_i32]),
        SystemTime::UNIX_EPOCH,
        0,
        &[0; 16],
    )?;
    Ok(request
        .message()
        .0
        .padata
        .as_ref()
        .and_then(|data| data.first())
        .ok_or("generated PA-TGS-REQ missing")?
        .clone())
}

/// Narrow policy to AES128 independently of the outer request and reply key.
fn config() -> Result<Config, Box<dyn Error>> {
    Ok(Config::parse(
        "[libdefaults]\npermitted_enctypes = aes128-cts\ndns_lookup_kdc = false",
    )?)
}

/// Matching wire fixtures separate from the admission assertions.
#[path = "nested_padata_requests.rs"]
mod fixtures;
use fixtures::requests;

/// Every visible encryption selection is rejected before the synchronous send boundary.
#[test]
fn checked_exchanges_reject_nested_padata_enctypes() -> Result<(), Box<dyn Error>> {
    for (kind, ticket_etype, key_etype, usage) in [
        (1_i32, 18_i32, 17_i32, Use::TicketKey),
        (1_i32, 17_i32, 18_i32, Use::SessionKey),
        (2_i32, 17_i32, 18_i32, Use::ReplyKey),
    ] {
        for prefix in [vec![], vec![credential(kind, 17, 17)?]] {
            let mut data = prefix;
            data.push(credential(kind, ticket_etype, key_etype)?);
            let (as_request, tgs_request) = requests(data)?;
            let key = EncryptionKey::new(17, vec![0; 16]);
            let mut transport = CountingTransport(0);
            for result in [
                client::exchange_as_req(&mut transport, &as_request, &key),
                client::exchange_tgs_req(&mut transport, &tgs_request, &key),
            ] {
                let error = result.err().ok_or("excluded PA credential accepted")?;
                assert_eq!(transport.0, 0, "excluded PA credential reached transport");
                assert_eq!(
                    policy_cause(&error),
                    Some(&Policy::EnctypeNotPermitted {
                        etype: 18_i32,
                        usage
                    })
                );
            }
        }
    }
    Ok(())
}

/// Explicit and configured Tokio exchanges use their effective policy before endpoint lookup.
#[test]
fn tokio_exchanges_reject_nested_padata_enctypes() -> Result<(), Box<dyn Error>> {
    let runtime = Builder::new_current_thread().enable_all().build()?;
    let transport = Tokio::new();
    let configured = config()?;
    let key = EncryptionKey::new(17, vec![0; 16]);
    for (kind, ticket_etype, key_etype, usage) in [
        (1_i32, 18_i32, 17_i32, Use::TicketKey),
        (1_i32, 17_i32, 18_i32, Use::SessionKey),
        (2_i32, 17_i32, 18_i32, Use::ReplyKey),
    ] {
        let (mut as_request, mut tgs_request) =
            requests(vec![credential(kind, ticket_etype, key_etype)?])?;
        let explicit_as = runtime.block_on(transport.exchange_as_req(
            KdcProtocol::Tcp,
            "invalid endpoint",
            &as_request,
            &key,
        ));
        let explicit_tgs = runtime.block_on(transport.exchange_tgs_req(
            KdcProtocol::Tcp,
            "invalid endpoint",
            &tgs_request,
            &key,
        ));
        as_request.set_crypto_policy(CryptoPolicy::default());
        tgs_request.set_crypto_policy(CryptoPolicy::default());
        let configured_as = runtime.block_on(transport.exchange_as_req_with_config(
            &configured,
            KdcProtocol::Tcp,
            &as_request,
            &key,
        ));
        let configured_tgs = runtime.block_on(transport.exchange_tgs_req_with_config(
            &configured,
            KdcProtocol::Tcp,
            &tgs_request,
            &key,
        ));
        for result in [explicit_as, explicit_tgs, configured_as, configured_tgs] {
            let error = result.err().ok_or("excluded PA credential accepted")?;
            assert_eq!(
                policy_cause(&error),
                Some(&Policy::EnctypeNotPermitted {
                    etype: 18_i32,
                    usage
                })
            );
        }
    }
    Ok(())
}

/// Permitted credentials, cookies and unknown informational PA payloads remain transmissible.
#[test]
fn checked_exchanges_preserve_permitted_padata() -> Result<(), Box<dyn Error>> {
    let data = vec![
        credential(1, 17, 17)?,
        credential(2, 17, 17)?,
        PaData {
            r#type: client::PA_FX_COOKIE,
            value: vec![0xff].into(),
        },
        PaData {
            r#type: 999,
            value: vec![0xff].into(),
        },
    ];
    let (as_request, tgs_request) = requests(data.clone())?;
    assert_eq!(
        kdc_req::decode_as_req(as_request.der())?.0.padata,
        Some(data.clone())
    );
    assert_eq!(
        kdc_req::decode_tgs_req(tgs_request.der())?.0.padata,
        Some(data)
    );
    let key = EncryptionKey::new(17, vec![0; 16]);
    let mut transport = CountingTransport(0);
    for result in [
        client::exchange_as_req(&mut transport, &as_request, &key),
        client::exchange_tgs_req(&mut transport, &tgs_request, &key),
    ] {
        assert!(matches!(result, Err(ClientError::Transport(_))));
    }
    assert_eq!(transport.0, 2);
    Ok(())
}

/// Explicit option credentials must fail before replacement or any request encryption.
#[test]
fn builders_reject_nested_padata_before_crypto() -> Result<(), Box<dyn Error>> {
    let configured = config()?;
    let mut tgt = session(17, 17)?;
    tgt.set_session_key(EncryptionKey::new(17, vec![0; 16]));
    for (kind, ticket_etype, key_etype, usage) in [
        (1_i32, 18_i32, 17_i32, Use::TicketKey),
        (1_i32, 17_i32, 18_i32, Use::SessionKey),
        (2_i32, 17_i32, 18_i32, Use::ReplyKey),
    ] {
        let data = vec![credential(kind, ticket_etype, key_etype)?];
        let as_options =
            AsReq::from_libdefaults(SystemTime::UNIX_EPOCH, 42, &configured.libdefaults)?
                .with_padata(data.clone());
        let tgs_options =
            TgsReq::from_libdefaults(SystemTime::UNIX_EPOCH, 42, &configured.libdefaults)?
                .with_padata(data);
        let as_result =
            client::build_tgt_as_req(Principal::user("EXAMPLE.COM", "alice"), as_options.clone());
        let preauth_result = client::build_preauthenticated_tgt_as_req(
            Principal::user("EXAMPLE.COM", "alice"),
            as_options,
            &EncryptionKey::new(17, vec![]),
            None,
        );
        let tgs_result = client::build_tgs_req_with_confounder(
            &tgt,
            Principal::new("EXAMPLE.COM", 2, ["HTTP", "other"]),
            tgs_options,
            SystemTime::UNIX_EPOCH,
            0,
            &[],
        );
        for error in [as_result.err(), preauth_result.err(), tgs_result.err()] {
            let refusal = error.ok_or("excluded PA option accepted")?;
            assert_eq!(
                policy_cause(&refusal),
                Some(&Policy::EnctypeNotPermitted {
                    etype: 18_i32,
                    usage
                })
            );
        }
    }
    Ok(())
}

/// Known credential envelopes require complete DER, unlike opaque informational payloads.
#[test]
fn builders_reject_malformed_nested_padata() -> Result<(), Box<dyn Error>> {
    for kind in [1_i32, 2_i32] {
        let valid = credential(kind, 17, 17)?;
        let mut trailing = valid.value.to_vec();
        trailing.extend_from_slice(&[0x05, 0x00]);
        for value in [vec![0xff], trailing] {
            let result = client::build_tgt_as_req(
                Principal::user("EXAMPLE.COM", "alice"),
                AsReq::new(SystemTime::UNIX_EPOCH, 42).with_padata(vec![PaData {
                    r#type: kind,
                    value: value.into(),
                }]),
            );
            assert!(matches!(
                result,
                Err(ClientError::Decode {
                    target: _,
                    message: _
                })
            ));
        }
    }
    Ok(())
}

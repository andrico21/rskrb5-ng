use core::error::Error;
use std::time::SystemTime;

use rasn::der;
use rasn_kerberos::{KdcReq, PaData};
use rskrb5_ng::{
    Config,
    client::{
        self, BuiltAsReq, BuiltTgsReq,
        options::AsReq,
        principal::Principal,
        transport::{KdcProtocol, Tokio},
    },
    crypto::{CryptoPolicy, Use},
    error::{Client as ClientError, Policy},
    kdc_req,
    keytab::EncryptionKey,
};
use tokio::runtime::Builder;

use super::client::{policy_cause, session};

/// Count the real exchange boundary without supplying network capability.
pub(super) struct CountingTransport(pub usize);
impl client::KdcTransport for CountingTransport {
    fn send(&mut self, _realm: &str, _request: &[u8]) -> Result<Vec<u8>, ClientError> {
        self.0 = self.0.saturating_add(1);
        Err(ClientError::Transport("admitted request".to_owned()))
    }
}

/// Construct matching AS and TGS wrappers with independently selectable wire fields.
fn requests(wire: &KdcReq) -> Result<(BuiltAsReq, BuiltTgsReq), Box<dyn Error>> {
    let config = Config::parse("[libdefaults]\npermitted_enctypes = aes128-cts")?;
    let original = client::build_tgt_as_req(
        Principal::user("EXAMPLE.COM", "alice"),
        AsReq::from_libdefaults(SystemTime::UNIX_EPOCH, 42, &config.libdefaults),
    )?;
    let mut as_request = BuiltAsReq::new(
        original.message().clone(),
        der::encode(&kdc_req::build_as_req(
            wire.req_body.clone(),
            wire.padata.clone(),
        ))?
        .into(),
        original.client().clone(),
        original.service().clone(),
        original.nonce(),
    );
    as_request.set_crypto_policy(CryptoPolicy::from_libdefaults(&config.libdefaults)?);
    let mut tgs_request = BuiltTgsReq::new(
        kdc_req::build_tgs_req(
            original.message().0.req_body.clone(),
            original.message().0.padata.clone(),
        ),
        der::encode(&kdc_req::build_tgs_req(
            wire.req_body.clone(),
            wire.padata.clone(),
        ))?
        .into(),
        original.client().clone(),
        original.service().clone(),
        "EXAMPLE.COM".to_owned(),
        original.nonce(),
    );
    tgs_request.set_crypto_policy(CryptoPolicy::from_libdefaults(&config.libdefaults)?);
    Ok((as_request, tgs_request))
}

/// An allowed request body, independent of any exchange validation.
fn allowed_message() -> Result<KdcReq, Box<dyn Error>> {
    let config = Config::parse("[libdefaults]\npermitted_enctypes = aes128-cts")?;
    Ok(client::build_tgt_as_req(
        Principal::user("EXAMPLE.COM", "alice"),
        AsReq::from_libdefaults(SystemTime::UNIX_EPOCH, 42, &config.libdefaults),
    )?
    .message()
    .0
    .clone())
}

/// Constructor-supplied wire-only enctypes and PA selections cannot reach transport.
#[test]
fn checked_exchanges_reject_wire_only_selections() -> Result<(), Box<dyn Error>> {
    for (etype, pa_type) in [(18_i32, 0_i32), (17_i32, 14_i32), (17_i32, 15_i32)] {
        let mut wire = allowed_message()?;
        wire.req_body.etype = vec![etype];
        if pa_type != 0_i32 {
            wire.padata = Some(vec![PaData {
                r#type: pa_type,
                value: vec![0_u8].into(),
            }]);
        }
        let (as_request, tgs_request) = requests(&wire)?;
        let key = EncryptionKey::new(17, vec![0; 16]);
        let mut transport = CountingTransport(0);
        let as_result = client::exchange_as_req(&mut transport, &as_request, &key);
        let tgs_result = client::exchange_tgs_req(&mut transport, &tgs_request, &key);
        assert_eq!(
            transport.0, 0,
            "wire-only selections must be rejected before send"
        );
        assert!(matches!(
            as_result,
            Err(ClientError::Encode {
                target: "AS-REQ",
                message: _
            })
        ));
        assert!(matches!(
            tgs_result,
            Err(ClientError::Encode {
                target: "TGS-REQ",
                message: _
            })
        ));
    }
    Ok(())
}

/// Replacing authorized metadata cannot leave a broader encoded request usable.
#[test]
fn checked_exchanges_reject_stale_der_after_set_message() -> Result<(), Box<dyn Error>> {
    let mut wire = allowed_message()?;
    wire.req_body.etype = vec![17_i32, 18_i32];
    let (mut as_request, mut tgs_request) = requests(&wire)?;
    as_request.set_message(kdc_req::build_as_req(
        wire.req_body.clone(),
        wire.padata.clone(),
    ));
    tgs_request.set_message(kdc_req::build_tgs_req(wire.req_body, wire.padata));
    let allowed = allowed_message()?;
    as_request.set_message(kdc_req::build_as_req(
        allowed.req_body.clone(),
        allowed.padata.clone(),
    ));
    tgs_request.set_message(kdc_req::build_tgs_req(allowed.req_body, allowed.padata));
    let mut transport = CountingTransport(0);
    let key = EncryptionKey::new(17, vec![0; 16]);
    let as_result = client::exchange_as_req(&mut transport, &as_request, &key);
    let tgs_result = client::exchange_tgs_req(&mut transport, &tgs_request, &key);
    assert_eq!(transport.0, 0);
    assert!(matches!(
        as_result,
        Err(ClientError::Encode {
            target: "AS-REQ",
            message: _
        })
    ));
    assert!(matches!(
        tgs_result,
        Err(ClientError::Encode {
            target: "TGS-REQ",
            message: _
        })
    ));
    Ok(())
}

/// Matching authorized bytes remain admitted, so refusal is not an unconditional stub.
#[test]
fn checked_exchanges_send_matching_allowed_requests() -> Result<(), Box<dyn Error>> {
    let (as_request, tgs_request) = requests(&allowed_message()?)?;
    let mut transport = CountingTransport(0);
    let key = EncryptionKey::new(17, vec![0; 16]);
    assert!(matches!(
        client::exchange_as_req(&mut transport, &as_request, &key),
        Err(ClientError::Transport(_))
    ));
    assert!(matches!(
        client::exchange_tgs_req(&mut transport, &tgs_request, &key),
        Err(ClientError::Transport(_))
    ));
    assert_eq!(transport.0, 2);
    Ok(())
}

/// All async admission entrypoints reject wire-only policy violations before endpoint lookup.
#[test]
fn tokio_exchanges_reject_wire_only_selections() -> Result<(), Box<dyn Error>> {
    let runtime = Builder::new_current_thread().enable_all().build()?;
    let config =
        Config::parse("[libdefaults]\npermitted_enctypes = aes128-cts\ndns_lookup_kdc = false")?;
    let key = EncryptionKey::new(17, vec![0; 16]);
    let transport = Tokio::new();
    for (etype, pa_type) in [(18_i32, 0_i32), (17_i32, 14_i32), (17_i32, 15_i32)] {
        let mut wire = allowed_message()?;
        wire.req_body.etype = vec![etype];
        if pa_type != 0_i32 {
            wire.padata = Some(vec![PaData {
                r#type: pa_type,
                value: vec![0_u8].into(),
            }]);
        }
        let (as_request, tgs_request) = requests(&wire)?;
        let as_result = runtime.block_on(transport.exchange_as_req(
            KdcProtocol::Tcp,
            "invalid endpoint",
            &as_request,
            &key,
        ));
        let tgs_result = runtime.block_on(transport.exchange_tgs_req(
            KdcProtocol::Tcp,
            "invalid endpoint",
            &tgs_request,
            &key,
        ));
        let configured_as = runtime.block_on(transport.exchange_as_req_with_config(
            &config,
            KdcProtocol::Tcp,
            &as_request,
            &key,
        ));
        let configured_tgs = runtime.block_on(transport.exchange_tgs_req_with_config(
            &config,
            KdcProtocol::Tcp,
            &tgs_request,
            &key,
        ));
        for result in [as_result, tgs_result, configured_as, configured_tgs] {
            assert!(
                matches!(
                    result,
                    Err(ClientError::Encode {
                        target: _,
                        message: _
                    })
                ),
                "wire mismatch must precede endpoint errors"
            );
        }
    }
    Ok(())
}

/// Matching DER does not bypass policy on the first or a later additional ticket.
#[test]
fn checked_tgs_rejects_each_additional_ticket() -> Result<(), Box<dyn Error>> {
    let runtime = Builder::new_current_thread().enable_all().build()?;
    let config =
        Config::parse("[libdefaults]\npermitted_enctypes = aes128-cts\ndns_lookup_kdc = false")?;
    let tokio_transport = Tokio::new();
    let key = EncryptionKey::new(17, vec![0; 16]);
    for ticket_types in [vec![18_i32], vec![17_i32, 18_i32], vec![17_i32, 17_i32]] {
        let mut wire = allowed_message()?;
        wire.req_body.additional_tickets = Some(
            ticket_types
                .iter()
                .map(|&etype| Ok(der::decode(session(17, etype)?.ticket())?))
                .collect::<Result<Vec<_>, Box<dyn Error>>>()?,
        );
        let (_, mut request) = requests(&wire)?;
        request.set_message(kdc_req::build_tgs_req(wire.req_body, wire.padata));
        let mut transport = CountingTransport(0);
        let result = client::exchange_tgs_req(
            &mut transport,
            &request,
            &EncryptionKey::new(17, vec![0; 16]),
        );
        let error = result.err().ok_or("transport always returns an error")?;
        if ticket_types.contains(&18_i32) {
            assert_eq!(transport.0, 0);
            assert!(matches!(
                policy_cause(&error),
                Some(Policy::EnctypeNotPermitted {
                    etype: 18_i32,
                    usage: Use::TicketKey
                })
            ));
            let explicit = runtime.block_on(tokio_transport.exchange_tgs_req(
                KdcProtocol::Tcp,
                "invalid endpoint",
                &request,
                &key,
            ));
            request.set_crypto_policy(CryptoPolicy::default());
            let configured = runtime.block_on(tokio_transport.exchange_tgs_req_with_config(
                &config,
                KdcProtocol::Tcp,
                &request,
                &key,
            ));
            for outcome in [explicit, configured] {
                let refusal = outcome
                    .err()
                    .ok_or("forbidden additional ticket accepted")?;
                assert!(matches!(
                    policy_cause(&refusal),
                    Some(Policy::EnctypeNotPermitted {
                        etype: 18_i32,
                        usage: Use::TicketKey
                    })
                ));
            }
        } else {
            assert_eq!(transport.0, 1);
            assert!(matches!(error, ClientError::Transport(_)));
        }
    }
    Ok(())
}

use core::error::Error;
use std::time::SystemTime;

use rasn::der;
use rasn_kerberos::Ticket;
use rskrb5_ng::{
    Config,
    client::{self, options::TgsReq, principal::Principal},
    crypto::Use,
    error::{Client as ClientError, Policy},
    kdc_req,
    keytab::EncryptionKey,
};

use super::{
    client::{policy_cause, session},
    exchange_admission::CountingTransport,
};

/// Ordinary TGS builders reject excluded first and later tickets, retaining allowed controls.
#[test]
fn tgs_builder_checks_every_additional_ticket() -> Result<(), Box<dyn Error>> {
    let config = Config::parse("[libdefaults]\npermitted_enctypes = aes128-cts")?;
    let mut tgt = session(17, 17)?;
    tgt.set_session_key(EncryptionKey::new(17, vec![0; 16]));
    for etypes in [
        vec![18_i32],
        vec![17_i32, 18_i32],
        vec![17_i32, 23_i32],
        vec![17_i32, 16_i32],
        vec![17_i32, 1_i32],
        vec![17_i32, 17_i32],
    ] {
        let tickets = etypes
            .iter()
            .map(|&etype| Ok(der::decode::<Ticket>(session(17, etype)?.ticket())?))
            .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
        let options = TgsReq::from_libdefaults(SystemTime::UNIX_EPOCH, 42, &config.libdefaults)
            .with_additional_tickets(tickets.clone());
        let result = client::build_tgs_req_with_confounder(
            &tgt,
            Principal::new("EXAMPLE.COM", 2, ["HTTP", "other"]),
            options,
            SystemTime::UNIX_EPOCH,
            0,
            &[0; 16],
        );
        let mut transport = CountingTransport(0);
        if etypes.iter().all(|&etype| etype == 17_i32) {
            let request = result?;
            let decoded = kdc_req::decode_tgs_req(request.der())?;
            assert_eq!(decoded.0.req_body.additional_tickets, Some(tickets));
            assert!(matches!(
                client::exchange_tgs_req(&mut transport, &request, tgt.session_key()),
                Err(ClientError::Transport(_))
            ));
            assert_eq!(transport.0, 1);
        } else {
            assert_eq!(transport.0, 0, "forbidden ticket must not be sent");
            let error = result.err().ok_or("forbidden additional ticket accepted")?;
            assert!(
                policy_cause(&error).is_some(),
                "must preserve the policy cause"
            );
        }
    }
    Ok(())
}

/// S4U explicit evidence cannot authorize an excluded option ticket appended after it.
#[test]
fn s4u_proxy_checks_option_ticket_after_evidence() -> Result<(), Box<dyn Error>> {
    let config = Config::parse("[libdefaults]\npermitted_enctypes = aes128-cts")?;
    let mut evidence = session(17, 17)?;
    evidence.set_session_key(EncryptionKey::new(17, vec![0; 16]));
    let mut tgt = evidence.clone();
    tgt.set_client(evidence.service().clone());
    for etype in [18_i32, 17_i32] {
        let extra: Ticket = der::decode(session(17, etype)?.ticket())?;
        let options = TgsReq::from_libdefaults(SystemTime::UNIX_EPOCH, 42, &config.libdefaults)
            .with_additional_tickets(vec![extra.clone()]);
        let result = client::build_s4u2proxy_req_with_confounder(
            &tgt,
            &evidence,
            Principal::new("EXAMPLE.COM", 2, ["HTTP", "backend"]),
            options,
            SystemTime::UNIX_EPOCH,
            0,
            &[0; 16],
        );
        if etype == 17_i32 {
            let decoded = kdc_req::decode_tgs_req(result?.der())?;
            assert_eq!(
                decoded.0.req_body.additional_tickets,
                Some(vec![der::decode(evidence.ticket())?, extra])
            );
        } else {
            let error = result.err().ok_or("forbidden S4U extra accepted")?;
            assert!(matches!(
                policy_cause(&error),
                Some(Policy::EnctypeNotPermitted {
                    etype: 18_i32,
                    usage: Use::TicketKey
                })
            ));
        }
    }
    Ok(())
}

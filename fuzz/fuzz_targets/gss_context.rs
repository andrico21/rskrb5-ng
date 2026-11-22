//! Fuzz the GSS-API Kerberos acceptor and the SPNEGO negotiation over it.
//!
//! The low two bits of the first input byte select the entry point: a raw
//! context token for the GSS acceptor, a SPNEGO token for the SPNEGO acceptor
//! over it, or a structured mode that encrypts a fuzzed DER `Authenticator`
//! (its RFC 4121 checksum, delegation option, extensions and `AD-AP-OPTIONS`
//! authorization data) under the session key of the fixture's service ticket,
//! so the checks behind decryption run, and hands the AP-REQ to the GSS
//! acceptor directly or inside a SPNEGO `NegTokenInit`. Bit 3 gives the
//! acceptor channel bindings and bit 4 makes them required. None may panic.

#![no_main]

use core::time::Duration;
use std::time::SystemTime;

use libfuzzer_sys::fuzz_target;
use rskrb5_ng::{
    ap_req,
    gss::{self, AcceptorOptions, ChannelBindings},
    keytab::{EncryptionKey, Keytab},
    service::Validator,
    spnego::{self, Krb5MechToken, NegTokenInit, Token},
    ticket,
};

/// The keytab of the fixture's `HTTP/host.test.gokrb5` service.
const HTTP_KEYTAB: &[u8] = include_bytes!("../fixtures/http.keytab");

/// An AP-REQ for [`HTTP_KEYTAB`]; its ticket carries the session key.
const VALID_AP_REQ: &[u8] = include_bytes!("../fixtures/valid_ap_req.der");

/// The time at which [`VALID_AP_REQ`] is fresh.
const NOW: Duration = Duration::from_secs(1_893_553_447);

/// The confounder of every encryption.
const CONFOUNDER: [u8; 16] = [0; 16];

/// The acceptor options of the selector bits.
fn options(selector: u8) -> AcceptorOptions {
    let mut options = AcceptorOptions::new();
    if selector & 0x08 != 0
        && let Ok(bindings) = ChannelBindings::tls_server_end_point(&[7; 32])
    {
        options = options
            .with_channel_bindings(bindings)
            .require_channel_bindings(selector & 0x10 != 0);
    }
    options
}

/// The krb5 AP-REQ token of the fixture's ticket with the fuzzed DER
/// authenticator encrypted under its session key, and the authenticator time.
fn structured(input: &[u8], keytab: &Keytab) -> Option<(Vec<u8>, SystemTime)> {
    let authenticator = ap_req::decode_authenticator(input).ok()?;
    let template = ap_req::decode(VALID_AP_REQ).ok()?;
    let entry = keytab.entries().first()?;
    let part = ticket::decrypt_ticket_enc_part(&template.ticket, entry.key()).ok()?;
    let session_key = EncryptionKey::new(part.key.r#type, part.key.value.to_vec());
    let usage = ap_req::authenticator_usage_for_ticket(&template.ticket);
    let request = ap_req::build_ap_req_with_confounder(
        template.ticket,
        ap_req::ap_options_from_bits(0x2000_0000),
        &authenticator,
        &session_key,
        usage,
        None,
        &CONFOUNDER,
    )
    .ok()?;
    let token = Krb5MechToken::ap_req(ap_req::encode(&request).ok()?)
        .encode()
        .ok()?;
    let seconds = u64::try_from(authenticator.ctime.0.timestamp()).ok()?;
    Some((token, SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(seconds))?))
}

fuzz_target!(|data: &[u8]| {
    let Some((selector, input)) = data.split_first() else {
        return;
    };
    let Ok(keytab) = Keytab::parse(HTTP_KEYTAB) else {
        return;
    };
    let Some(fixed) = SystemTime::UNIX_EPOCH.checked_add(NOW) else {
        return;
    };
    let (token, now) = if selector & 0x02 == 0 {
        (input.to_vec(), fixed)
    } else {
        let Some(built) = structured(input, &keytab) else {
            return;
        };
        built
    };
    let mut acceptor =
        gss::Acceptor::from_validator(Validator::new(&keytab).with_now(now), options(*selector));
    if selector & 0x01 == 0 {
        if let Ok(accepted) = acceptor.accept_sec_context(&token) {
            drop(accepted.context().inquire());
        }
        return;
    }
    let wrapped = if selector & 0x02 == 0 {
        Some(token)
    } else {
        Token::Init(NegTokenInit::krb5(token)).encode().ok()
    };
    if let Some(bytes) = wrapped {
        let mut negotiation = spnego::Acceptor::new(acceptor);
        drop(negotiation.accept_sec_context(&bytes));
    }
});

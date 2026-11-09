//! Fuzz SPNEGO decoding and the service-side Negotiate acceptance.
//!
//! The first input byte selects the entry point and the rest is its input:
//! the `Negotiate` header parser, the GSS/SPNEGO token, `NegotiationToken`,
//! `NegTokenInit` and `NegTokenResp` decoders, header acceptance against a
//! service validator holding a synthetic test keytab, a raw AP-REQ wrapped
//! into a well-formed header (and validated bare), an AP-REQ followed by an
//! AP-REP the accepted context verifies, and a structured mode that encrypts a fuzzed
//! `EncTicketPart` and Authenticator under the keytab and session keys so the
//! acceptance checks behind decryption are reached. None may panic.

#![no_main]

use core::time::Duration;
use std::time::SystemTime;

use libfuzzer_sys::fuzz_target;
use rskrb5_ng::{
    ap_req,
    keytab::{EncryptionKey, Keytab},
    service::{ApRepOptions, Validator},
    spnego::{self, Krb5MechToken, NegTokenInit, NegTokenResp, NegotiationToken, Token},
    ticket,
};

/// The synthetic `HTTP/host.test.gokrb5` keytab of the service tests.
const HTTP_KEYTAB: &[u8] = include_bytes!("../fixtures/http.keytab");

/// An AP-REQ for [`HTTP_KEYTAB`]; its ticket supplies the realm and sname of
/// the structured mode.
const VALID_AP_REQ: &[u8] = include_bytes!("../fixtures/valid_ap_req.der");

/// The time at which [`VALID_AP_REQ`] is fresh.
const NOW: Duration = Duration::from_secs(1_893_553_447);

/// A fixed confounder, so every run encrypts the same bytes.
const CONFOUNDER: [u8; 16] = [0x11; 16];

/// Split `input` into a part whose length is the first two bytes (big
/// endian) and the rest; `None` when the input is too short.
fn split_prefixed(input: &[u8]) -> Option<(&[u8], &[u8])> {
    let (length, rest) = input.split_first_chunk::<2>()?;
    rest.split_at_checked(usize::from(u16::from_be_bytes(*length)))
}

/// A Negotiate header carrying `ap_req` as a SPNEGO `NegTokenInit`.
fn negotiate_header_for(ap_req: Vec<u8>) -> Option<String> {
    let mech_token = Krb5MechToken::ap_req(ap_req).encode().ok()?;
    spnego::negotiate_header(&Token::Init(NegTokenInit::krb5(mech_token))).ok()
}

/// Accept `header` at `now`, then exercise the accepted context with `ap_rep`.
fn accept(header: &str, now: SystemTime, ap_rep: &[u8]) {
    let Ok(keytab) = Keytab::parse(HTTP_KEYTAB) else {
        return;
    };
    let mut validator = Validator::new(&keytab)
        .with_now(now)
        .without_shared_replay_cache();
    if let Ok(accepted) = spnego::accept_sec_context_header(&mut validator, header) {
        drop(
            accepted.ap_rep_response_header_with_confounder(&CONFOUNDER, &ApRepOptions::default()),
        );
        drop(accepted.ap_req.verify_ap_rep(ap_rep));
    }
}

/// Validate `request` as a bare AP-REQ, outside SPNEGO, at `now`, then verify
/// the AP-REP `reply` against the validated request.
fn validate(request: &[u8], now: SystemTime, reply: &[u8]) {
    if let Ok(keytab) = Keytab::parse(HTTP_KEYTAB) {
        let mut validator = Validator::new(&keytab)
            .with_now(now)
            .without_shared_replay_cache();
        if let Ok(validated) = validator.validate_ap_req(request) {
            drop(validated.verify_ap_rep(reply));
        }
    }
}

/// The fixed validation time.
fn fixed_now() -> Option<SystemTime> {
    SystemTime::UNIX_EPOCH.checked_add(NOW)
}

/// Encrypt a fuzzed `EncTicketPart` under the keytab key and a fuzzed
/// Authenticator under its session key, then accept the resulting AP-REQ at
/// the authenticator's own time.
fn structured(input: &[u8]) -> Option<()> {
    let (enc_ticket_part, authenticator_der) = split_prefixed(input)?;
    let enc_part = ticket::decode_enc_ticket_part(enc_ticket_part).ok()?;
    let authenticator = ap_req::decode_authenticator(authenticator_der).ok()?;
    let template = ap_req::decode(VALID_AP_REQ).ok()?;
    let keytab = Keytab::parse(HTTP_KEYTAB).ok()?;
    let entry = keytab.entries().first()?;
    let ticket = ticket::build_ticket_with_confounder(
        template.ticket.realm,
        template.ticket.sname,
        &enc_part,
        entry.key(),
        Some(entry.kvno()),
        &CONFOUNDER,
    )
    .ok()?;
    let session_key = EncryptionKey::new(enc_part.key.r#type, enc_part.key.value.to_vec());
    let usage = ap_req::authenticator_usage_for_ticket(&ticket);
    let ap_req = ap_req::build_ap_req_with_confounder(
        ticket,
        ap_req::ap_options_from_bits(0),
        &authenticator,
        &session_key,
        usage,
        None,
        &CONFOUNDER,
    )
    .ok()?;
    let header = negotiate_header_for(ap_req::encode(&ap_req).ok()?)?;
    let seconds = u64::try_from(authenticator.ctime.0.timestamp()).ok()?;
    let now = SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(seconds))?;
    accept(&header, now, &[]);
    Some(())
}

fuzz_target!(|data: &[u8]| {
    let Some((selector, input)) = data.split_first() else {
        return;
    };
    match selector & 0x07 {
        0 => {
            if let Ok(token) = spnego::parse_negotiate_header(&String::from_utf8_lossy(input)) {
                drop(token.krb5_ap_req());
            }
        }
        1 => {
            if let Ok(token) = Token::decode(input) {
                drop(token.krb5_ap_req());
                drop(token.encode());
            }
        }
        2 => {
            if let Ok(token) = NegotiationToken::decode(input) {
                drop(token.encode());
            }
        }
        3 => {
            if let Ok(token) = NegTokenInit::decode(input) {
                drop(token.krb5_ap_req());
            }
        }
        4 => drop(NegTokenResp::decode(input)),
        5 => {
            if let Some(now) = fixed_now() {
                accept(&String::from_utf8_lossy(input), now, &[]);
            }
        }
        6 => {
            if let Some((ap_req, ap_rep)) = split_prefixed(input)
                && let Some(now) = fixed_now()
            {
                validate(ap_req, now, ap_rep);
                if let Some(header) = negotiate_header_for(ap_req.to_vec()) {
                    accept(&header, now, ap_rep);
                }
            }
        }
        _ => structured(input).unwrap_or_default(),
    }
});

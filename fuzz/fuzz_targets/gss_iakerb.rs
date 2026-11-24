//! Fuzz the IAKERB proxy token and both ends of an IAKERB exchange.
//!
//! The low two bits of the first input byte select the entry point: the token
//! codec (`Token::decode`, with a re-encode that must decode to the same
//! token), the acceptor on raw bytes after a valid relayed request, the
//! initiator on a fuzzed answer to its first request, or the acceptor on an
//! AP-REQ whose authenticator checksum carries the fuzzed bytes as its
//! `IAKERB-FINISHED` extension (after a realm-discovery exchange, so the
//! transcript is not empty, and without one). Fixed contexts and the valid
//! first request are asserted before the arbitrary input is processed. None
//! may panic.

#![no_main]

use core::time::Duration;
use std::time::SystemTime;

use libfuzzer_sys::fuzz_target;
use rskrb5_ng::{
    Config, ap_req,
    gss::{
        self, AcceptorOptions, CredStore, Credential, CredentialUsage, InitStep, InitiatorOptions,
        Name, NameType,
        iakerb::{AcceptStep, Context, KdcRelay, RelayFailure, RelayPolicy, token::Token},
    },
    keytab::{EncryptionKey, Keytab},
    service::Validator,
    spnego::Krb5MechToken,
    ticket,
};

/// The keytab of the fixture's `HTTP/host.test.gokrb5` service.
const HTTP_KEYTAB: &[u8] = include_bytes!("../fixtures/http.keytab");

/// An AP-REQ for [`HTTP_KEYTAB`]; its ticket carries the session key.
const VALID_AP_REQ: &[u8] = include_bytes!("../fixtures/valid_ap_req.der");

/// The time at which [`VALID_AP_REQ`] is fresh.
const NOW: Duration = Duration::from_secs(1_893_553_447);

/// The AES256 service key [`VALID_AP_REQ`]'s ticket is encrypted in.
const TICKET_KEY: [u8; 32] = [
    0x9c, 0xad, 0x00, 0xbb, 0xc7, 0x2d, 0x70, 0x32, 0x58, 0xe9, 0x11, 0xdc, 0x18, 0xe6, 0xd5, 0x48,
    0x7c, 0xf7, 0x37, 0xbf, 0x67, 0xfd, 0x11, 0x1f, 0x0c, 0x24, 0x63, 0xad, 0x60, 0x33, 0xbf, 0x51,
];

/// The realm of the fixture.
const REALM: &str = "TEST.GOKRB5";

/// The subkey of the structured authenticators.
const SUBKEY: [u8; 32] = [0x77; 32];

/// A relay that answers every request with a `KRB-ERROR`-tagged message.
struct Fixed;

impl KdcRelay for Fixed {
    fn relay(&mut self, _realm: &str, _request: &[u8]) -> Result<Vec<u8>, RelayFailure> {
        Ok(vec![0x7e, 0x00])
    }
}

/// The initiator credential: a password for `testuser1`.
fn credential() -> Option<Credential> {
    let name = Name::import(b"testuser1@TEST.GOKRB5", NameType::User).ok()?;
    let store = CredStore::new().with("password", "passwordvalue").ok()?;
    Credential::acquire_cred_from(Some(&name), CredentialUsage::Initiate, &store).ok()
}

/// A fresh initiator and its first token, a relay request for [`REALM`].
fn initiator(credential: &Credential) -> Option<(Context, Vec<u8>)> {
    let config = Config::parse(
        "[libdefaults]\n default_realm = TEST.GOKRB5\n dns_lookup_kdc = false\n dns_lookup_realm = false\n",
    )
    .ok()?;
    let target = Name::import(b"HTTP@host.test.gokrb5", NameType::HostbasedService).ok()?;
    let mut context = Context::initiator(&config, target, InitiatorOptions::new()).ok()?;
    let InitStep::Continue(first) = context.init_sec_context(credential, None).ok()? else {
        return None;
    };
    Some((context, first))
}

/// A DER element of `tag` holding `value`.
fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if let Ok(short) = u8::try_from(value.len())
        && short < 0x80
    {
        out.push(short);
    } else {
        let digits = value.len().to_be_bytes();
        let skip = digits.iter().take_while(|digit| **digit == 0).count();
        let tail = digits.get(skip..).unwrap_or_default();
        out.push(0x80 | u8::try_from(tail.len()).unwrap_or(0));
        out.extend_from_slice(tail);
    }
    out.extend_from_slice(value);
    out
}

/// A DER INTEGER of the non-negative `value`.
fn int(value: u32) -> Vec<u8> {
    let digits = value.to_be_bytes();
    let skip = digits
        .iter()
        .take_while(|digit| **digit == 0)
        .count()
        .min(3);
    let mut body = digits.get(skip..).unwrap_or_default().to_vec();
    if body.first().is_some_and(|first| first & 0x80 != 0) {
        body.insert(0, 0);
    }
    tlv(0x02, &body)
}

/// The DER `Authenticator` of `testuser1@TEST.GOKRB5` at the fixture's time,
/// with an RFC 4121 checksum of `checksum` and the subkey [`SUBKEY`].
fn authenticator(checksum: &[u8]) -> Vec<u8> {
    let field = |number: u8, inner: Vec<u8>| tlv(0xa0 | number, &inner);
    let name = tlv(
        0x30,
        &[
            field(0, int(1)),
            field(1, tlv(0x30, &tlv(0x1b, b"testuser1"))),
        ]
        .concat(),
    );
    let sum = tlv(
        0x30,
        &[field(0, int(0x8003)), field(1, tlv(0x04, checksum))].concat(),
    );
    let key = tlv(
        0x30,
        &[field(0, int(18)), field(1, tlv(0x04, &SUBKEY))].concat(),
    );
    tlv(
        0x62,
        &tlv(
            0x30,
            &[
                field(0, int(5)),
                field(1, tlv(0x1b, REALM.as_bytes())),
                field(2, name),
                field(3, sum),
                field(4, int(0)),
                field(5, tlv(0x18, b"20300102030407Z")),
                field(6, key),
                field(7, int(1)),
            ]
            .concat(),
        ),
    )
}

/// An AP-REQ token of the fixture's ticket whose authenticator checksum holds
/// `finished` as the `IAKERB-FINISHED` extension.
fn ap_req_token(finished: &[u8]) -> Option<Vec<u8>> {
    let template = ap_req::decode(VALID_AP_REQ).ok()?;
    let ticket_key = EncryptionKey::new(18, TICKET_KEY.to_vec());
    let part = ticket::decrypt_ticket_enc_part(&template.ticket, &ticket_key).ok()?;
    let session = EncryptionKey::new(part.key.r#type, part.key.value.to_vec());
    let usage = ap_req::authenticator_usage_for_ticket(&template.ticket);
    let mut checksum = 16_u32.to_le_bytes().to_vec();
    checksum.extend_from_slice(&[0; 16]);
    checksum.extend_from_slice(&0x32_u32.to_le_bytes());
    checksum.extend_from_slice(&2_u32.to_be_bytes());
    checksum.extend_from_slice(&u32::try_from(finished.len()).ok()?.to_be_bytes());
    checksum.extend_from_slice(finished);
    let authenticator = ap_req::decode_authenticator(&authenticator(&checksum)).ok()?;
    let request = ap_req::build_ap_req_with_confounder(
        template.ticket,
        ap_req::ap_options_from_bits(0x2000_0000),
        &authenticator,
        &session,
        usage,
        None,
        &[0; 16],
    )
    .ok()?;
    let mut token = Krb5MechToken::ap_req(ap_req::encode(&request).ok()?);
    token.set_oid(Context::mechanism());
    token.encode().ok()
}

/// The token codec: a decoded token re-encodes to one that decodes to it.
///
/// # Panics
///
/// Panics when a decoded token is not an IAKERB token or a round trip changes it.
fn codec(input: &[u8]) {
    if let Ok(token) = Token::decode(input) {
        assert!(
            Token::is_iakerb(input),
            "a decoded token is an IAKERB token"
        );
        if let Ok(again) = token.encode() {
            assert_eq!(
                Token::decode(&again).ok(),
                Some(token),
                "a token round trips"
            );
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((selector, input)) = data.split_first() else {
        return;
    };
    codec(input);
    let (Some(credential), Ok(keytab), Some(fixed)) = (
        credential(),
        Keytab::parse(HTTP_KEYTAB),
        SystemTime::UNIX_EPOCH.checked_add(NOW),
    ) else {
        return;
    };
    let (Some((mut initiating, first)), Ok(policy)) =
        (initiator(&credential), RelayPolicy::new(REALM))
    else {
        return;
    };
    let mut acceptor = gss::Acceptor::from_validator(
        Validator::new(&keytab).with_now(fixed),
        AcceptorOptions::new(),
    );
    let mut context = Context::acceptor(policy);
    if selector & 0x03 != 0 {
        let relayed = context.accept_sec_context(&mut acceptor, &mut Fixed, &first);
        assert!(
            matches!(relayed, Ok(AcceptStep::Continue(_))),
            "the first request relays"
        );
    }
    match selector & 0x03 {
        0 => {}
        1 => drop(context.accept_sec_context(&mut acceptor, &mut Fixed, input)),
        2 => {
            drop(initiating.init_sec_context(&credential, Some(input)));
            let wrapped = Token::new(REALM, None, input.to_vec()).encode();
            if let Ok(token) = wrapped {
                drop(initiating.init_sec_context(&credential, Some(&token)));
            }
        }
        _ => {
            let Ok(discovery) = Token::new("", None, Vec::new()).encode() else {
                return;
            };
            if selector & 0x04 != 0 {
                drop(context.accept_sec_context(&mut acceptor, &mut Fixed, &discovery));
            }
            if let Some(token) = ap_req_token(input) {
                drop(context.accept_sec_context(&mut acceptor, &mut Fixed, &token));
            }
        }
    }
});

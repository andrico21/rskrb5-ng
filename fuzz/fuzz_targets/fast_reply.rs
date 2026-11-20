//! Fuzz the replies to an armored AS request (RFC 6113 FAST).
//!
//! An armored exchange is started through the stepwise engine with a fixed
//! armor ticket; the first input byte selects how the rest reaches it:
//! mode 0 feeds the bytes as the KDC's reply (the outer AS-REP or KRB-ERROR,
//! its METHOD-DATA and `PA-FX-FAST-REPLY` decoders); modes 1, 2 and 3 encrypt the
//! bytes as the `KrbFastResponse` under the conversation's armor key and wrap
//! them in a KRB-ERROR (1) or an AS-REP (2, 3), so the decoders behind decryption run
//! (`KrbFastResponse`, `PA-FX-ERROR`, the cookie bound, `KrbFastFinished` and
//! its ticket checksum). None may panic, and no reply may complete the
//! exchange unless its finished message verified.

#![no_main]

mod session_ticket;

use core::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use libfuzzer_sys::fuzz_target;
use rskrb5_ng::{
    Principal, ap_req,
    client::{
        AsRepSession,
        options::AsReq,
        stepwise::{ExchangeStep, InitCreds, InitCredsOptions, StepInput},
    },
    crypto::{KerberosEtype, prf},
    kdc_req,
    keytab::{EncryptionKey, Entry, Keytab, Principal as KeytabPrincipal},
    preauth::fast::{ArmorSource, Exchange, Policy},
};

/// The realm.
const REALM: &str = "FAST.TEST";
/// The request nonce.
const NONCE: u32 = 0x0102_0304;

/// The session key of the armor ticket.
const SESSION_KEY: [u8; 32] = [0x33; 32];

/// The first TLV of `bytes`: its tag, its content and what follows it.
fn read_tlv(bytes: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, after_tag) = bytes.split_first()?;
    let (&first, after_first) = after_tag.split_first()?;
    let (length, body) = if first < 0x80 {
        (usize::from(first), after_first)
    } else {
        let count = usize::from(first & 0x7f);
        let digits = after_first.get(..count)?;
        let length = digits.iter().try_fold(0_usize, |acc, byte| {
            acc.checked_mul(256)?.checked_add(usize::from(*byte))
        })?;
        (length, after_first.get(count..)?)
    };
    Some((tag, body.get(..length)?, body.get(length..)?))
}

/// The armor key of the armored request `message`, recovered as the KDC
/// would: the subkey of the armor AP-REQ's authenticator combined with the
/// armor ticket's session key (RFC 6113 section 5.4.1.1).
fn armor_key(message: &[u8]) -> Option<EncryptionKey> {
    let request = kdc_req::decode_as_req(message).ok()?;
    let fast = request.0.padata?.into_iter().next()?;
    let (_, armored, _) = read_tlv(&fast.value)?;
    let (_, sequence, _) = read_tlv(armored)?;
    let (_, armor, _) = read_tlv(sequence)?;
    let (_, armor_fields, _) = read_tlv(armor)?;
    let (_, _, value_field) = read_tlv(armor_fields)?;
    let (_, octets, _) = read_tlv(value_field)?;
    let (_, ap_req, _) = read_tlv(octets)?;
    let session = EncryptionKey::new(18, SESSION_KEY.to_vec());
    let decoded = ap_req::decode(ap_req).ok()?;
    let subkey = ap_req::decrypt_ap_req_authenticator(&decoded, &session, 11)
        .ok()?
        .subkey?;
    let etype = KerberosEtype::from_etype_id(18)?;
    let combined = prf::krb_fx_cf2(
        &prf::CfInput::new(prf::Key::new(etype, subkey.value.as_ref()), b"subkeyarmor"),
        &prf::CfInput::new(prf::Key::new(etype, &SESSION_KEY), b"ticketarmor"),
    )
    .ok()?;
    Some(EncryptionKey::new(18, combined.to_vec()))
}

/// A DER element with a definite length.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let length = content.len();
    if length < 0x80 {
        out.push(u8::try_from(length).unwrap_or_default());
    } else {
        let bytes = length.to_be_bytes();
        let start = bytes
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(bytes.len());
        let significant = bytes.get(start..).unwrap_or_default();
        out.push(0x80 | u8::try_from(significant.len()).unwrap_or_default());
        out.extend_from_slice(significant);
    }
    out.extend_from_slice(content);
    out
}

/// A DER INTEGER of a small non-negative value.
fn integer(value: u32) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let start = bytes.iter().position(|byte| *byte != 0).unwrap_or(3);
    let mut content = bytes.get(start..).unwrap_or_default().to_vec();
    if content.first().is_some_and(|byte| *byte >= 0x80) {
        content.insert(0, 0);
    }
    tlv(0x02, &content)
}

/// `[n] EXPLICIT` around `content`.
fn field(number: u8, content: &[u8]) -> Vec<u8> {
    tlv(0xa0 | number, content)
}

/// A `GeneralString`.
fn string(text: &str) -> Vec<u8> {
    tlv(0x1b, text.as_bytes())
}

/// The armor TGT: the fixture ticket under fixed keys.
fn armor_ticket() -> Option<AsRepSession> {
    let session = EncryptionKey::new(18, SESSION_KEY.to_vec());
    let service = Principal::tgt_service(REALM);
    let ticket = session_ticket::encoded(&service, &session)?;
    Some(AsRepSession::new(
        Principal::new(REALM, 3, ["host", "armor.fast.test"]),
        service,
        session,
        ticket.into(),
        [0x40, 0x60, 0, 0],
        UNIX_EPOCH,
        SystemTime::now().checked_add(Duration::from_secs(3600))?,
    ))
}

/// `data` as a `KrbFastResponse` sealed in `key`, in a `PA-FX-FAST-REPLY` padata.
fn sealed_padata(key: &EncryptionKey, data: &[u8]) -> Option<Vec<u8>> {
    let etype = KerberosEtype::from_etype_id(key.etype())?;
    let cipher = etype
        .encrypt_message_with_confounder(key.value(), data, 52, &vec![0x5a; etype.confounder_len()])
        .ok()?;
    let encrypted = tlv(
        0x30,
        &[field(0, &integer(18)), field(2, &tlv(0x04, &cipher))].concat(),
    );
    let reply = field(0, &tlv(0x30, &field(0, &encrypted)));
    Some(tlv(
        0x30,
        &tlv(
            0x30,
            &[field(1, &integer(136)), field(2, &tlv(0x04, &reply))].concat(),
        ),
    ))
}

/// A KRB-ERROR `PREAUTH_REQUIRED` whose e-data is `method_data`.
fn error(method_data: &[u8]) -> Vec<u8> {
    let sname = tlv(
        0x30,
        &[
            field(0, &integer(2)),
            field(1, &tlv(0x30, &[string("krbtgt"), string(REALM)].concat())),
        ]
        .concat(),
    );
    tlv(
        0x7e,
        &tlv(
            0x30,
            &[
                field(0, &integer(5)),
                field(1, &integer(30)),
                field(4, &tlv(0x18, b"20300101000000Z")),
                field(5, &integer(0)),
                field(6, &integer(25)),
                field(9, &string(REALM)),
                field(10, &sname),
                field(12, &tlv(0x04, method_data)),
            ]
            .concat(),
        ),
    )
}

/// An AS-REP carrying `padata`, the armor ticket and an opaque encrypted part.
fn as_rep(padata: &[u8], ticket: &[u8]) -> Vec<u8> {
    let cname = tlv(
        0x30,
        &[
            field(0, &integer(1)),
            field(1, &tlv(0x30, &string("alice"))),
        ]
        .concat(),
    );
    let enc_part = tlv(
        0x30,
        &[field(0, &integer(18)), field(2, &tlv(0x04, &[0x47; 64]))].concat(),
    );
    tlv(
        0x6b,
        &tlv(
            0x30,
            &[
                field(0, &integer(5)),
                field(1, &integer(11)),
                field(2, padata),
                field(3, &string(REALM)),
                field(4, &cname),
                field(5, ticket),
                field(6, &enc_part),
            ]
            .concat(),
        ),
    )
}

/// The armored exchange after its first request, the armor key and the armor ticket.
fn start() -> Option<(InitCreds<'static>, EncryptionKey, Vec<u8>)> {
    let armor = armor_ticket()?;
    let ticket = armor.ticket().to_vec();
    let mut keys = Keytab::new();
    keys.entries_mut().push(Entry::new(
        KeytabPrincipal::new(REALM, 1, vec!["alice".to_owned()]),
        0,
        1,
        EncryptionKey::new(18, vec![0x22; 32]),
        1,
    ));
    let options =
        InitCredsOptions::new(AsReq::new(SystemTime::now(), NONCE).with_etypes(vec![18_i32]));
    let mut exchange =
        InitCreds::with_keytab(Principal::user(REALM, "alice"), keys, options).with_armor(
            Exchange::new(Policy::Required, ArmorSource::Ticket(Box::new(armor))),
        );
    let Ok(ExchangeStep::Outbound(outbound)) = exchange.step(StepInput::Start) else {
        return None;
    };
    let key = armor_key(outbound.message())?;
    Some((exchange, key, ticket))
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let started = start();
    assert!(
        started.is_some(),
        "the armored request and its armor key must build"
    );
    let Some((mut exchange, armor_key, ticket)) = started else {
        return;
    };
    let reply = match selector & 0x03 {
        0 => Some(rest.to_vec()),
        1 => sealed_padata(&armor_key, rest).map(|padata| error(&padata)),
        _ => sealed_padata(&armor_key, rest).map(|padata| as_rep(&padata, &ticket)),
    };
    let Some(bytes) = reply else {
        return;
    };
    let completed = matches!(
        exchange.step(StepInput::Reply(&bytes)),
        Ok(ExchangeStep::Complete(_))
    );
    assert!(!completed, "a fuzzed reply completed the armored exchange");
});

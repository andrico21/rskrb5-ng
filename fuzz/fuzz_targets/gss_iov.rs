//! Fuzz the IOV, AEAD and legacy per-message token parsers of an established
//! GSS-API context.
//!
//! Each run establishes a context pair in process (a service ticket sealed
//! under a fixed AES256 service key, the session key of the selected
//! enctype). The low two bits of the first byte select the context: AES256-SHA1,
//! AES256-SHA384, a DCE-style AES256-SHA1 context, or an opted-in DES3 or RC4
//! context (bit 2). The rest is either an IOV array (`kind byte, length byte,
//! bytes` records) handed to `unwrap_iov` and `verify_mic_iov`, or, with bit 3,
//! a mutation list applied to tokens the initiator produced (`wrap_iov` with and
//! without a TRAILER, `wrap_aead`, `wrap`, `get_mic`) before the acceptor opens
//! them. None may panic.

#![no_main]

use core::time::Duration;
use std::time::UNIX_EPOCH;

use libfuzzer_sys::fuzz_target;
use rskrb5_ng::{
    Principal, ap_req,
    client::TgsRepSession,
    config::Config,
    crypto::CryptoPolicy,
    gss::{
        Acceptor, AcceptorOptions, ContextFlags, Credential, EstablishedContext, InitStep,
        Initiator, InitiatorOptions, IovBuffer, IovKind, Name, NameType,
    },
    keytab::{EncryptionKey, Keytab},
    service::Validator,
    ticket,
};

/// The keytab of the fixture's `HTTP/host.test.gokrb5` service.
const HTTP_KEYTAB: &[u8] = include_bytes!("../fixtures/http.keytab");

/// The fixture AP-REQ whose ticket body is re-sealed with the session key.
const VALID_AP_REQ: &[u8] = include_bytes!("../fixtures/valid_ap_req.der");

/// The AES256 key of the fixture ticket (an entry of [`HTTP_KEYTAB`]).
const TICKET_KEY: [u8; 32] = [
    0x9c, 0xad, 0x00, 0xbb, 0xc7, 0x2d, 0x70, 0x32, 0x58, 0xe9, 0x11, 0xdc, 0x18, 0xe6, 0xd5, 0x48,
    0x7c, 0xf7, 0x37, 0xbf, 0x67, 0xfd, 0x11, 0x1f, 0x0c, 0x24, 0x63, 0xad, 0x60, 0x33, 0xbf, 0x51,
];

/// The ticket's start, 2024-01-01T00:00:00Z.
const START: u64 = 1_704_067_200;

/// The ticket's end, 2099-01-01T00:00:00Z.
const END: u64 = 4_070_908_800;

/// A DER `Authenticator` whose `ctime` is the `GeneralizedTime` `stamp`: the
/// only way to make a ticket time without naming the `ASN.1` crate.
fn authenticator(stamp: &[u8; 15]) -> Vec<u8> {
    let mut inner = vec![
        0xa0, 0x03, 0x02, 0x01, 0x05, 0xa1, 0x03, 0x1b, 0x01, 0x52, 0xa2, 0x0e, 0x30, 0x0c, 0xa0,
        0x03, 0x02, 0x01, 0x01, 0xa1, 0x05, 0x30, 0x03, 0x1b, 0x01, 0x61, 0xa4, 0x03, 0x02, 0x01,
        0x00, 0xa5, 0x11, 0x18, 0x0f,
    ];
    inner.extend_from_slice(stamp);
    let mut out = vec![0x62, 0x34, 0x30, 0x32];
    out.extend_from_slice(&inner);
    out
}

/// A context pair with a session key of `etype`, requesting `flags`.
fn pair(etype: i32, flags: ContextFlags) -> Option<(EstablishedContext, EstablishedContext)> {
    let start = ap_req::decode_authenticator(&authenticator(b"20240101000000Z"))
        .ok()?
        .ctime;
    let end = ap_req::decode_authenticator(&authenticator(b"20990101000000Z"))
        .ok()?
        .ctime;
    let template = ap_req::decode(VALID_AP_REQ).ok()?;
    let ticket_key = EncryptionKey::new(18, TICKET_KEY.to_vec());
    let mut body = ticket::decrypt_ticket_enc_part(&template.ticket, &ticket_key).ok()?;
    let length: usize = match etype {
        16_i32 => 24,
        23_i32 => 16,
        _ => 32,
    };
    let fill: u8 = if etype == 16_i32 { 0x5b } else { 0x5a };
    let session = EncryptionKey::new(etype, vec![fill; length]);
    body.key.r#type = etype;
    body.key.value = session.value().to_vec().into();
    body.auth_time = start;
    body.start_time = None;
    body.end_time = end;
    body.renew_till = None;
    let client = Principal::user("TEST.GOKRB5", "testuser1");
    let service = Principal::new("TEST.GOKRB5", 3, ["HTTP", "host.test.gokrb5"]);
    let sname = template.ticket.sname.clone();
    let der = ticket::encode_build_ticket_with_confounder(
        template.ticket.realm.clone(),
        sname,
        &body,
        &ticket_key,
        template.ticket.enc_part.kvno,
        &[0; 16],
    )
    .ok()?;
    let session_ticket = TgsRepSession::new(
        client,
        service,
        session,
        der.into(),
        [0; 4],
        UNIX_EPOCH.checked_add(Duration::from_secs(START))?,
        UNIX_EPOCH.checked_add(Duration::from_secs(END))?,
    );
    let credential = Credential::from_service_ticket(&session_ticket);
    let config = Config::parse(
        "[libdefaults]\n allow_des3 = true\n allow_rc4 = true\n \
         permitted_enctypes = aes256-cts-hmac-sha1-96 aes256-cts-hmac-sha384-192 des3-cbc-sha1 arcfour-hmac\n",
    )
    .ok()?;
    let policy = CryptoPolicy::from_libdefaults(&config.libdefaults).ok()?;
    let target = Name::import(b"HTTP@host.test.gokrb5", NameType::HostbasedService).ok()?;
    let mut init = Initiator::new(
        target,
        InitiatorOptions::new()
            .with_flags(flags)
            .with_crypto_policy(policy.clone()),
    );
    let keys = Keytab::parse(HTTP_KEYTAB).ok()?;
    let mut accept = Acceptor::from_validator(
        Validator::new(&keys).with_crypto_policy(policy),
        AcceptorOptions::new(),
    );
    let InitStep::Continue(first) = init.init_sec_context(&credential, None).ok()? else {
        return None;
    };
    let mut accepted = accept.accept_sec_context(&first).ok()?;
    let reply = accepted.output_token()?.to_vec();
    if let InitStep::Complete(Some(third)) =
        init.init_sec_context(&credential, Some(&reply)).ok()?
    {
        accepted.complete_dce(&third).ok()?;
    }
    Some((init.into_established().ok()?, accepted.into_context()))
}

/// The IOV kinds a kind byte selects.
const KINDS: [IovKind; 9] = [
    IovKind::Empty,
    IovKind::Data,
    IovKind::Header,
    IovKind::MechParams,
    IovKind::Trailer,
    IovKind::Padding,
    IovKind::Stream,
    IovKind::SignOnly,
    IovKind::MicToken,
];

/// An IOV array of `kind, length, bytes` records.
fn buffers(mut input: &[u8]) -> Vec<IovBuffer> {
    let mut out = Vec::new();
    while let [kind, length, rest @ ..] = input {
        let take = usize::from(*length).min(rest.len());
        let (value, tail) = rest.split_at(take);
        let chosen = KINDS
            .get(
                usize::from(*kind)
                    .checked_rem(KINDS.len())
                    .unwrap_or_default(),
            )
            .copied()
            .unwrap_or(IovKind::Data);
        out.push(IovBuffer::new(chosen, value.to_vec()));
        input = tail;
    }
    out
}

/// `bytes` with every `position, mask` pair of `mutations` applied.
fn mutated(bytes: &[u8], mutations: &[u8]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    for [position, mask] in mutations.as_chunks::<2>().0 {
        let at = usize::from(*position).checked_rem(out.len());
        if let Some(byte) = at.and_then(|index| out.get_mut(index)) {
            *byte ^= mask;
        }
    }
    out
}

fuzz_target!(|data: &[u8]| {
    let Some((selector, input)) = data.split_first() else {
        return;
    };
    let base = ContextFlags::MUTUAL | ContextFlags::SEQUENCE | ContextFlags::REPLAY;
    let (etype, flags) = match (selector & 0x04 != 0, selector & 0x03) {
        (true, 0 | 2) => (16, base),
        (true, _) => (23, base),
        (false, 0) => (18, base),
        (false, 1) => (20, base),
        (false, _) => (18, base | ContextFlags::DCE_STYLE),
    };
    let Some((mut initiator, mut acceptor)) = pair(etype, flags) else {
        return;
    };
    if selector & 0x08 == 0 {
        let mut array = buffers(input);
        drop(acceptor.unwrap_iov(&mut array));
        drop(acceptor.verify_mic_iov(&array));
        drop(acceptor.unwrap_aead(input, b"associated"));
        drop(acceptor.unwrap(input));
        drop(acceptor.verify_mic(b"message", input));
        return;
    }
    let mut detached = vec![
        IovBuffer::empty(IovKind::Header),
        IovBuffer::new(IovKind::SignOnly, b"associated".to_vec()),
        IovBuffer::new(IovKind::Data, b"protected data".to_vec()),
        IovBuffer::empty(IovKind::Padding),
        IovBuffer::empty(IovKind::Trailer),
    ];
    if initiator
        .wrap_iov(&mut detached, selector & 0x10 != 0)
        .is_ok()
    {
        let mut opened: Vec<IovBuffer> = detached
            .iter()
            .map(|buffer| IovBuffer::new(buffer.kind(), mutated(buffer.value(), input)))
            .collect();
        drop(acceptor.unwrap_iov(&mut opened));
    }
    let mut rotated = vec![
        IovBuffer::empty(IovKind::Header),
        IovBuffer::new(IovKind::Data, b"rotated".to_vec()),
    ];
    if initiator
        .wrap_iov(&mut rotated, selector & 0x20 != 0)
        .is_ok()
    {
        let mut opened: Vec<IovBuffer> = rotated
            .iter()
            .map(|buffer| IovBuffer::new(buffer.kind(), mutated(buffer.value(), input)))
            .collect();
        drop(acceptor.unwrap_iov(&mut opened));
    }
    if let Ok(token) = initiator.wrap_aead(b"associated", b"aead", selector & 0x40 != 0) {
        drop(acceptor.unwrap_aead(&mutated(&token, input), b"associated"));
    }
    if let Ok(token) = initiator.wrap(b"wrapped", selector & 0x80 != 0) {
        drop(acceptor.unwrap(&mutated(&token, input)));
    }
    if let Ok(token) = initiator.get_mic(b"signed") {
        drop(acceptor.verify_mic(b"signed", &mutated(&token, input)));
    }
});

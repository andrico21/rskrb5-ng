//! The RFC 6560 messages.
//!
//! MIT vectors, the challenge's flags and bounds, and the `PA-OTP-REQUEST` the
//! client builds.

use rasn::{der, types::BitString};
use rasn_kerberos::otp::{
    OtpFlags, OtpFormat as WireFormat, OtpTokenInfo, PaOtpChallenge, PaOtpEncRequest, PaOtpRequest,
};
use rskrb5_ng::{
    crypto::KerberosEtype,
    error::Otp,
    keytab::EncryptionKey,
    preauth::otp::{Challenge, Format, KEY_USAGE_PA_OTP_REQUEST, PinMode, Policy, Response, Token},
};

use super::{kdc::TestError, vectors};

/// The armor key of the request tests.
fn armor() -> EncryptionKey {
    EncryptionKey::new(18, vec![0x42; 32])
}

/// MIT's hex dump as bytes.
fn bytes(hex: &str) -> Result<Vec<u8>, TestError> {
    hex.split_whitespace()
        .map(|byte| Ok(u8::from_str_radix(byte, 16)?))
        .collect()
}

/// A 32-bit flags string with `bits` set (RFC 6560 bit numbers, bit 0 first).
fn flags(bits: &[usize]) -> OtpFlags {
    let mut value = BitString::repeat(false, 32);
    for &bit in bits {
        value.set(bit, true);
    }
    OtpFlags(value)
}

/// A token info with `bits` set and nothing else.
fn token(bits: &[usize]) -> OtpTokenInfo {
    OtpTokenInfo::new(flags(bits))
}

/// The DER of a challenge with these tokens.
fn challenge(tokens: Vec<OtpTokenInfo>) -> Result<Vec<u8>, TestError> {
    Ok(der::encode(&PaOtpChallenge::new(
        vec![0x11; 36].into(),
        tokens,
    ))?)
}

/// Decode `value` under the default policy.
fn decode(value: &[u8]) -> Result<Challenge, Otp> {
    Challenge::decode(value, &Policy::default())
}

/// The refusal of `value` under `policy`.
fn refused(value: &[u8], policy: &Policy) -> Result<Otp, TestError> {
    Challenge::decode(value, policy)
        .err()
        .ok_or_else(|| "a bad challenge was accepted".into())
}

/// The dependency's shapes encode MIT's bytes exactly: the vectors are not
/// merely decodable, they are what MIT's encoder produces.
#[test]
fn mit_encodings_round_trip_through_the_message_types() -> Result<(), TestError> {
    for hex in [vectors::TOKENINFO_MINIMAL, vectors::TOKENINFO_MAXIMAL] {
        let wire = bytes(hex)?;
        let info: OtpTokenInfo = der::decode(&wire)?;
        assert_eq!(der::encode(&info)?, wire);
    }
    for hex in [vectors::CHALLENGE_MINIMAL, vectors::CHALLENGE_MAXIMAL] {
        let wire = bytes(hex)?;
        let parsed: PaOtpChallenge = der::decode(&wire)?;
        assert_eq!(der::encode(&parsed)?, wire);
    }
    for hex in [vectors::REQUEST_MINIMAL, vectors::REQUEST_MAXIMAL] {
        let wire = bytes(hex)?;
        let parsed: PaOtpRequest = der::decode(&wire)?;
        assert_eq!(der::encode(&parsed)?, wire);
    }
    let wire = bytes(vectors::ENC_REQUEST)?;
    let parsed: PaOtpEncRequest = der::decode(&wire)?;
    assert_eq!(parsed.nonce.as_ref(), b"krb5data");
    assert_eq!(der::encode(&parsed)?, wire);
    Ok(())
}

/// MIT's minimal challenge: one token with no flags and nothing else.
#[test]
fn mit_minimal_challenge_decodes() -> Result<(), TestError> {
    let parsed = decode(&bytes(vectors::CHALLENGE_MINIMAL)?)?;
    assert_eq!(parsed.service(), None);
    assert_eq!(parsed.unsupported(), 0);
    let [only] = parsed.tokens() else {
        return Err("expected one token".into());
    };
    assert_eq!(only.vendor(), None);
    assert_eq!(only.challenge(), None);
    assert_eq!(only.length(), None);
    assert_eq!(only.format(), None);
    assert_eq!(only.token_id(), None);
    assert_eq!(only.alg_id(), None);
    assert_eq!(only.pin(), PinMode::Unspecified);
    Ok(())
}

/// MIT's maximal challenge: the second token needs flags, hashing and an
/// iteration count this client does not support, so only the first remains and the
/// drop is counted (MIT `preauth_otp.c:869-897`).
#[test]
fn mit_maximal_challenge_drops_the_unsupported_token() -> Result<(), TestError> {
    let parsed = decode(&bytes(vectors::CHALLENGE_MAXIMAL)?)?;
    assert_eq!(parsed.service(), Some("testservice"));
    assert_eq!(parsed.tokens().len(), 1);
    assert_eq!(parsed.unsupported(), 1);
    Ok(())
}

/// The flags this client supports (MIT `preauth_otp.c:872-874`) and every other
/// bit, one at a time: an unsupported token alone leaves nothing to answer.
#[test]
fn flags_select_the_supported_tokens() -> Result<(), TestError> {
    for (bits, mode) in [
        (vec![3_usize], PinMode::Collect),
        (vec![3, 6], PinMode::CollectSeparately),
        (vec![6], PinMode::CollectSeparately),
        (vec![4], PinMode::DoNotCollect),
        (vec![], PinMode::Unspecified),
    ] {
        let parsed = decode(&challenge(vec![token(&bits)])?)?;
        assert_eq!(parsed.tokens().len(), 1, "{bits:?}");
        assert_eq!(parsed.tokens().first().map(Token::pin), Some(mode));
    }
    for unsupported in [0_usize, 1, 2, 5, 7, 8, 31] {
        let found = refused(&challenge(vec![token(&[unsupported])])?, &Policy::default())?;
        assert!(
            matches!(found, Otp::NoSupportedTokens { dropped: 1 }),
            "bit {unsupported}: {found}"
        );
    }
    let mixed = decode(&challenge(vec![token(&[5]), token(&[]), token(&[1])])?)?;
    assert_eq!((mixed.tokens().len(), mixed.unsupported()), (1, 2));
    Ok(())
}

/// Malformed flags: both PIN flags together (RFC 6560 section 4.1), and a BIT
/// STRING that is shorter than 32 bits or longer than the bound.
#[test]
fn malformed_flags_are_refused() -> Result<(), TestError> {
    let both = refused(&challenge(vec![token(&[3, 4])])?, &Policy::default())?;
    assert!(matches!(both, Otp::ConflictingPinFlags), "{both}");
    for length in [0_usize, 8, 31, 65, 4096] {
        let mut info = token(&[]);
        info.flags = OtpFlags(BitString::repeat(false, length));
        let found = refused(&challenge(vec![info])?, &Policy::default())?;
        assert!(
            matches!(found, Otp::Malformed { message: _ }),
            "{length} bits: {found}"
        );
    }
    Ok(())
}

/// Token fields that MIT filters (an unprintable vendor or challenge, base64,
/// hashing, an iteration count) drop the token; every other field is kept.
#[test]
fn token_fields_filter_and_report() -> Result<(), TestError> {
    let mut full = token(&[3]);
    full.otp_vendor = Some("Example Corp".to_owned());
    full.otp_challenge = Some(b"c0ffee".to_vec().into());
    full.otp_length = Some(6_i32);
    full.otp_format = Some(WireFormat::hexadecimal());
    full.otp_token_id = Some(b"id-1".to_vec().into());
    full.otp_alg_id = Some("urn:ietf:params:xml:ns:keyprov:pskc:hotp".to_owned());
    let parsed = decode(&challenge(vec![full])?)?;
    let [only] = parsed.tokens() else {
        return Err("expected one token".into());
    };
    assert_eq!(only.vendor(), Some("Example Corp"));
    assert_eq!(only.challenge(), Some("c0ffee"));
    assert_eq!(only.length(), Some(6));
    assert_eq!(only.format(), Some(Format::Hexadecimal));
    assert_eq!(only.token_id(), Some(&b"id-1"[..]));
    assert_eq!(
        only.alg_id(),
        Some("urn:ietf:params:xml:ns:keyprov:pskc:hotp")
    );
    let edits: [fn(&mut OtpTokenInfo); 7] = [
        |info| info.otp_vendor = Some("bad\u{7}vendor".to_owned()),
        |info| info.otp_vendor = Some("b\u{e4}d".to_owned()),
        |info| info.otp_challenge = Some(b"bad\x01".to_vec().into()),
        |info| info.otp_format = Some(WireFormat::base64()),
        |info| info.otp_format = Some(WireFormat(9_i32.into())),
        |info| info.iteration_count = Some(1_000_i32),
        |info| info.supported_hash_alg = Some(Vec::new()),
    ];
    let mut dropped = Vec::new();
    for edit in edits {
        let mut info = token(&[]);
        edit(&mut info);
        dropped.push(info);
    }
    let count = dropped.len();
    dropped.push(token(&[]));
    let mixed = decode(&challenge(dropped)?)?;
    assert_eq!((mixed.tokens().len(), mixed.unsupported()), (1, count));
    Ok(())
}

/// The one-field-too-long refusals of `bounded`.
fn too_long(value: &[u8], policy: &Policy, field: &str, limit: usize) -> Result<bool, TestError> {
    Ok(matches!(
        refused(value, policy)?,
        Otp::FieldTooLong { field: found, limit: bound } if found == field && bound == limit
    ))
}

/// Structure and size bounds: nothing unbounded is built from the KDC's bytes.
#[test]
fn challenges_are_bounded() -> Result<(), TestError> {
    let policy = Policy::default()
        .with_max_tokens(3)
        .with_max_field_bytes(16)
        .with_max_challenge_bytes(512);
    let sized = |tokens: Vec<OtpTokenInfo>| {
        der::encode(&PaOtpChallenge::new(vec![0x11; 16].into(), tokens))
    };
    assert_eq!(
        Challenge::decode(&sized(vec![token(&[]); 3])?, &policy)?
            .tokens()
            .len(),
        3
    );
    let four = refused(&sized(vec![token(&[]); 4])?, &policy)?;
    assert!(matches!(four, Otp::TooManyTokens { limit: 3 }), "{four}");
    let none = refused(&sized(Vec::new())?, &policy)?;
    assert!(matches!(none, Otp::Malformed { message: _ }), "{none}");
    let mut vendor = token(&[]);
    vendor.otp_vendor = Some("v".repeat(17));
    assert!(too_long(&sized(vec![vendor])?, &policy, "otp-vendor", 16)?);
    let mut challenge_field = token(&[]);
    challenge_field.otp_challenge = Some(vec![b'c'; 17].into());
    assert!(too_long(
        &sized(vec![challenge_field])?,
        &policy,
        "otp-challenge",
        16
    )?);
    let mut wide = PaOtpChallenge::new(vec![0x11; 17].into(), vec![token(&[])]);
    assert!(too_long(&der::encode(&wide)?, &policy, "nonce", 16)?);
    wide.nonce = Vec::new().into();
    let empty = refused(&der::encode(&wide)?, &policy)?;
    assert!(matches!(empty, Otp::Malformed { message: _ }), "{empty}");
    let large = refused(&[0x30; 513], &policy)?;
    assert!(
        matches!(large, Otp::ChallengeTooLarge { limit: 512 }),
        "{large}"
    );
    Ok(())
}

/// Garbage, truncation and trailing bytes are refused without a panic; a
/// negative length and an empty challenge violate RFC 6560's ranges.
#[test]
fn malformed_challenges_are_refused() -> Result<(), TestError> {
    let good = challenge(vec![token(&[])])?;
    assert_eq!(decode(&good)?.tokens().len(), 1);
    let mut trailing = good.clone();
    trailing.push(0);
    let cut = good.get(..good.len() - 1).ok_or("empty")?.to_vec();
    for bad in [Vec::new(), vec![0x30], cut, trailing, vec![0xff; 40]] {
        let found = refused(&bad, &Policy::default())?;
        assert!(matches!(found, Otp::Malformed { message: _ }), "{found}");
    }
    let mut negative = token(&[]);
    negative.otp_length = Some(-1_i32);
    let mut empty = token(&[]);
    empty.otp_challenge = Some(Vec::new().into());
    for info in [negative, empty] {
        let found = refused(&challenge(vec![info])?, &Policy::default())?;
        assert!(matches!(found, Otp::Malformed { message: _ }), "{found}");
    }
    Ok(())
}

/// The decoded `PA-OTP-REQUEST` of `response` for the token `info`.
fn request(info: OtpTokenInfo, response: &Response) -> Result<PaOtpRequest, TestError> {
    let parsed = decode(&challenge(vec![info])?)?;
    let padata = parsed.request(response, &armor(), &Policy::default())?;
    assert_eq!(padata.r#type, 142_i32);
    Ok(der::decode(&padata.value)?)
}

/// The request names the token it answers, carries the value, encrypts the
/// KDC's nonce in the armor key (usage 45) and has no hashing fields (MIT
/// `preauth_otp.c:606-673`).
#[test]
fn request_carries_the_token_and_the_encrypted_nonce() -> Result<(), TestError> {
    let mut info = token(&[]);
    info.otp_vendor = Some("Example Corp".to_owned());
    info.otp_format = Some(WireFormat::decimal());
    info.otp_length = Some(6_i32);
    info.otp_token_id = Some(b"id-1".to_vec().into());
    info.otp_alg_id = Some("urn:alg".to_owned());
    let sent = request(info, &Response::new(0, b"123456".to_vec()))?;
    assert_eq!(sent.flags, flags(&[]));
    assert_eq!(sent.nonce, None);
    assert_eq!(sent.hash_alg, None);
    assert_eq!(sent.iteration_count, None);
    assert_eq!(sent.otp_value.as_deref(), Some(&b"123456"[..]));
    assert_eq!(sent.otp_pin, None);
    assert_eq!(sent.otp_vendor.as_deref(), Some("Example Corp"));
    assert_eq!(sent.otp_format, Some(WireFormat::decimal()));
    assert_eq!(sent.otp_token_id.as_deref(), Some(&b"id-1"[..]));
    assert_eq!(sent.otp_alg_id.as_deref(), Some("urn:alg"));
    let key = armor();
    let cipher = KerberosEtype::from_etype_id(18).ok_or("etype")?;
    assert_eq!(sent.enc_data.etype, 18_i32);
    let plain =
        cipher.decrypt_message(key.value(), &sent.enc_data.cipher, KEY_USAGE_PA_OTP_REQUEST)?;
    let sealed: PaOtpEncRequest = der::decode(&plain)?;
    assert_eq!(sealed.nonce.as_ref(), &[0x11; 36][..]);
    Ok(())
}

/// The value the KDC receives for `response` to a token with these flag bits.
fn value_sent(
    bits: &[usize],
    response: &Response,
) -> Result<(Option<Vec<u8>>, Option<String>), TestError> {
    let sent = request(token(bits), response)?;
    Ok((sent.otp_value.map(|bytes| bytes.to_vec()), sent.otp_pin))
}

/// The refusal of `response` by a token with these flag bits.
fn pin_refused(bits: &[usize], response: &Response) -> Result<Otp, TestError> {
    decode(&challenge(vec![token(bits)])?)?
        .request(response, &armor(), &Policy::default())
        .err()
        .ok_or_else(|| "accepted".into())
}

/// Each PIN mode: a separate PIN goes in `otp-pin`, a collected one is prefixed to
/// the value, a refused one is never sent, and a required one must be given.
#[test]
fn pin_modes_decide_where_the_pin_goes() -> Result<(), TestError> {
    let with_pin = || Response::new(0, b"123456".to_vec()).with_pin("4242".to_owned());
    let plain = || Response::new(0, b"123456".to_vec());
    let separate = value_sent(&[3, 6], &with_pin())?;
    assert_eq!(
        separate,
        (Some(b"123456".to_vec()), Some("4242".to_owned()))
    );
    let combined = (Some(b"4242123456".to_vec()), None);
    assert_eq!(value_sent(&[3], &with_pin())?, combined);
    assert_eq!(value_sent(&[], &with_pin())?, combined);
    assert_eq!(
        value_sent(&[3], &plain())?,
        (Some(b"123456".to_vec()), None)
    );
    assert!(matches!(
        pin_refused(&[4], &with_pin())?,
        Otp::PinNotCollected
    ));
    assert!(matches!(pin_refused(&[3, 6], &plain())?, Otp::PinRequired));
    Ok(())
}

/// The refusal of `response` by `challenge` under `policy`.
fn answer_refused(
    challenge: &Challenge,
    response: &Response,
    policy: &Policy,
) -> Result<Otp, TestError> {
    challenge
        .request(response, &armor(), policy)
        .err()
        .ok_or_else(|| "accepted".into())
}

/// The responder's answer is checked before anything is built: the token, the
/// value's length and format (MIT `otpvalue_matches_tokeninfo`), and the bounds.
#[test]
fn answers_are_validated_before_a_request_is_built() -> Result<(), TestError> {
    let policy = Policy::default().with_max_value_bytes(8);
    let mut info = token(&[]);
    info.otp_length = Some(6_i32);
    info.otp_format = Some(WireFormat::decimal());
    let parsed = decode(&challenge(vec![info, token(&[])])?)?;
    let unknown = answer_refused(&parsed, &Response::new(2, b"123456".to_vec()), &policy)?;
    assert!(matches!(unknown, Otp::UnknownToken { index: 2, count: 2 }));
    for (value, reason) in [
        (&b"12345"[..], "the length differs from the token's"),
        (b"12345a", "the format is not the token's"),
        (b"", "the value is empty"),
    ] {
        let found = answer_refused(&parsed, &Response::new(0, value.to_vec()), &policy)?;
        assert!(
            matches!(&found, Otp::ValueRejected { reason: why } if *why == reason),
            "{found}"
        );
    }
    let long_value = answer_refused(&parsed, &Response::new(1, b"123456789".to_vec()), &policy)?;
    assert!(
        matches!(long_value, Otp::ValueTooLong { limit: 8 }),
        "{long_value}"
    );
    let long_pin = Response::new(1, b"1".to_vec()).with_pin("123456789".to_owned());
    let found = answer_refused(&parsed, &long_pin, &policy)?;
    assert!(matches!(found, Otp::ValueTooLong { limit: 8 }), "{found}");
    let fine = parsed.request(&Response::new(1, b"anything".to_vec()), &armor(), &policy)?;
    assert_eq!(fine.r#type, 142_i32);
    let weak = EncryptionKey::new(1, vec![0; 8]);
    let sealed = parsed
        .request(&Response::new(1, b"1".to_vec()), &weak, &policy)
        .err()
        .ok_or("DES armor accepted")?;
    assert!(matches!(sealed, Otp::Seal(_)), "{sealed}");
    Ok(())
}

/// The OTP value and the PIN never appear in `Debug` output.
#[test]
fn responses_are_redacted() -> Result<(), TestError> {
    let response = Response::new(0, b"s3cr3t-value".to_vec()).with_pin("s3cr3t-pin".to_owned());
    let sent = request(token(&[3, 6]), &response)?;
    assert_eq!(sent.otp_pin.as_deref(), Some("s3cr3t-pin"));
    let text = format!("{response:?}");
    for secret in ["s3cr3t-value", "s3cr3t-pin"] {
        assert!(!text.contains(secret), "{text}");
    }
    assert!(text.contains("REDACTED"), "{text}");
    Ok(())
}

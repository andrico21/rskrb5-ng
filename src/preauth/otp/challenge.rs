//! Decoding `PA-OTP-CHALLENGE` (RFC 6560 section 4.1; MIT `preauth_otp.c:869-921`).

use rasn::types::BitString;
use rasn_kerberos::otp::{OtpTokenInfo, PaOtpChallenge};

use super::{Challenge, Format, PinMode, Policy, Token};
use crate::{der::decode_complete, error::Otp as Error};

/// RFC 6560 flag bit number of `collect-pin`.
const COLLECT_PIN: usize = 3;
/// `do-not-collect-pin`.
const DO_NOT_COLLECT_PIN: usize = 4;
/// `separate-pin-required`.
const SEPARATE_PIN: usize = 6;
/// The shortest flags string (`KerberosFlags` is at least 32 bits).
const MIN_FLAG_BITS: usize = 32;
/// The longest flags string read.
const MAX_FLAG_BITS: usize = 64;

/// Decode `value` under `policy` (see [`Challenge::decode`]).
///
/// # Errors
/// Returns the size, structure and flag violations of the challenge.
pub(super) fn decode(value: &[u8], policy: &Policy) -> Result<Challenge, Error> {
    if value.len() > policy.challenge_bytes {
        return Err(Error::ChallengeTooLarge {
            limit: policy.challenge_bytes,
        });
    }
    let wire: PaOtpChallenge = decode_complete(value).map_err(|error| Error::Malformed {
        message: format!("PA-OTP-CHALLENGE: {error}"),
    })?;
    bound("nonce", wire.nonce.len(), policy)?;
    if wire.nonce.is_empty() || wire.otp_token_info.is_empty() {
        return Err(Error::Malformed {
            message: "the nonce or the token list is empty".to_owned(),
        });
    }
    if wire.otp_token_info.len() > policy.token_count {
        return Err(Error::TooManyTokens {
            limit: policy.token_count,
        });
    }
    if let Some(service) = &wire.otp_service {
        bound("otp-service", service.len(), policy)?;
    }
    let mut tokens = Vec::new();
    let mut unsupported = 0_usize;
    for info in wire.otp_token_info {
        match token(info, policy)? {
            Some(usable) => tokens.push(usable),
            None => unsupported = unsupported.saturating_add(1),
        }
    }
    if tokens.is_empty() {
        return Err(Error::NoSupportedTokens {
            dropped: unsupported,
        });
    }
    Ok(Challenge {
        service: wire.otp_service,
        tokens,
        unsupported,
        nonce: wire.nonce.to_vec(),
    })
}

/// Refuse a field longer than the policy's bound.
///
/// # Errors
/// Returns [`Error::FieldTooLong`].
const fn bound(field: &'static str, length: usize, policy: &Policy) -> Result<(), Error> {
    if length > policy.field_bytes {
        return Err(Error::FieldTooLong {
            field,
            limit: policy.field_bytes,
        });
    }
    Ok(())
}

/// Whether every byte is printable ASCII (MIT `is_printable_string`).
fn printable(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| (0x20..=0x7e).contains(byte))
}

/// The PIN flags of a token; `None` when another bit is set.
///
/// # Errors
/// Returns [`Error::Malformed`] for a string of the wrong size and
/// [`Error::ConflictingPinFlags`].
fn pin_mode(flags: &BitString) -> Result<Option<PinMode>, Error> {
    if !(MIN_FLAG_BITS..=MAX_FLAG_BITS).contains(&flags.len()) {
        return Err(Error::Malformed {
            message: format!("the flags have {} bits", flags.len()),
        });
    }
    let set = |bit: usize| flags.get(bit).is_some_and(|value| *value);
    let (collect, refuse, separate) =
        (set(COLLECT_PIN), set(DO_NOT_COLLECT_PIN), set(SEPARATE_PIN));
    if collect && refuse {
        return Err(Error::ConflictingPinFlags);
    }
    let known = [COLLECT_PIN, DO_NOT_COLLECT_PIN, SEPARATE_PIN];
    if flags.iter_ones().any(|bit| !known.contains(&bit)) {
        return Ok(None);
    }
    Ok(Some(if refuse {
        PinMode::DoNotCollect
    } else if separate {
        PinMode::CollectSeparately
    } else if collect {
        PinMode::Collect
    } else {
        PinMode::Unspecified
    }))
}

/// A token that needs a feature this client lacks.
struct Unsupported;

/// The format of a token.
///
/// # Errors
/// Returns [`Unsupported`] for base64 and for values this client does not know.
fn format(info: &OtpTokenInfo) -> Result<Option<Format>, Unsupported> {
    let Some(wire) = &info.otp_format else {
        return Ok(None);
    };
    match i64::try_from(&wire.0) {
        Ok(0) => Ok(Some(Format::Decimal)),
        Ok(1) => Ok(Some(Format::Hexadecimal)),
        Ok(2) => Ok(Some(Format::Alphanumeric)),
        Ok(3) => Ok(Some(Format::Binary)),
        Ok(_) | Err(_) => Err(Unsupported),
    }
}

/// One token info: bounded, validated, and `None` when this client cannot answer it
/// (MIT `is_tokeninfo_supported`).
///
/// # Errors
/// Returns the size, range and flag violations of the token info.
fn token(info: OtpTokenInfo, policy: &Policy) -> Result<Option<Token>, Error> {
    let pins = pin_mode(&info.flags.0)?;
    if let Some(vendor) = &info.otp_vendor {
        bound("otp-vendor", vendor.len(), policy)?;
    }
    if let Some(challenge) = &info.otp_challenge {
        bound("otp-challenge", challenge.len(), policy)?;
        if challenge.is_empty() {
            return Err(Error::Malformed {
                message: "otp-challenge is empty".to_owned(),
            });
        }
    }
    if let Some(id) = &info.otp_token_id {
        bound("otp-tokenID", id.len(), policy)?;
    }
    if let Some(alg) = &info.otp_alg_id {
        bound("otp-algID", alg.len(), policy)?;
    }
    let length = info
        .otp_length
        .map(usize::try_from)
        .transpose()
        .map_err(|_negative| Error::Malformed {
            message: "otp-length is negative".to_owned(),
        })?;
    let supported = info.supported_hash_alg.is_none()
        && info.iteration_count.is_none()
        && info
            .otp_vendor
            .as_deref()
            .is_none_or(|vendor| printable(vendor.as_bytes()))
        && info.otp_challenge.as_deref().is_none_or(printable);
    let (Some(pin), Ok(format), true) = (pins, format(&info), supported) else {
        return Ok(None);
    };
    Ok(Some(Token {
        vendor: info.otp_vendor,
        challenge: info
            .otp_challenge
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned()),
        length,
        format,
        id: info.otp_token_id.map(|bytes| bytes.to_vec()),
        alg_id: info.otp_alg_id,
        pin,
    }))
}

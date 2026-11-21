//! Building `PA-OTP-REQUEST` (RFC 6560 section 4.2; MIT `preauth_otp.c:606-673,1113-1127`).

use rasn::{
    AsnType, Encode,
    types::{BitString, OctetString, Utf8String},
};
use rasn_kerberos::{
    EncryptedData, PaData,
    otp::{OtpFlags, OtpFormat as WireFormat, PaOtpEncRequest},
};
use zeroize::Zeroizing;

use super::{
    Challenge, Format, KEY_USAGE_PA_OTP_REQUEST, PA_OTP_REQUEST, PinMode, Policy, Response, Token,
};
use crate::{
    error::Otp as Error,
    keytab::EncryptionKey,
    preauth::fast::keys::{encode, seal},
};

/// The `PA-OTP-REQUEST` this client sends: the fields of MIT's `make_request`, with
/// no hashing (`nonce`, `hashAlg`, `iterationCount`) and no token state
/// (`otp-challenge`, `otp-time`, `otp-counter`), which are optional.
#[derive(AsnType, Encode)]
struct PaOtpRequest {
    /// `flags [0]`: none of `nextOTP` and `combine` applies to a supported token.
    #[rasn(tag(0))]
    flags: OtpFlags,
    /// `encData [2]`: the KDC's nonce in the armor key, usage 45.
    #[rasn(tag(2))]
    enc_data: EncryptedData,
    /// `otp-value [5]`.
    #[rasn(tag(5))]
    otp_value: OctetString,
    /// `otp-pin [6]`.
    #[rasn(tag(6))]
    otp_pin: Option<Utf8String>,
    /// `otp-format [10]`.
    #[rasn(tag(10))]
    otp_format: Option<WireFormat>,
    /// `otp-tokenID [11]`.
    #[rasn(tag(11))]
    otp_token_id: Option<OctetString>,
    /// `otp-algID [12]`.
    #[rasn(tag(12))]
    otp_alg_id: Option<Utf8String>,
    /// `otp-vendor [13]`.
    #[rasn(tag(13))]
    otp_vendor: Option<Utf8String>,
}

/// The `PA-OTP-REQUEST` of `challenge` for `response` (see [`Challenge::request`]).
///
/// # Errors
/// Returns the answer's refusals and [`Error::Seal`].
pub(super) fn build(
    challenge: &Challenge,
    response: &Response,
    armor_key: &EncryptionKey,
    policy: &Policy,
) -> Result<PaData, Error> {
    let token = challenge
        .tokens
        .get(response.token)
        .ok_or(Error::UnknownToken {
            index: response.token,
            count: challenge.tokens.len(),
        })?;
    check_value(token, &response.value, policy)?;
    let (value, separate) = place_pin(token, response, policy)?;
    let nonce = encode(
        "PA-OTP-ENC-REQUEST",
        &PaOtpEncRequest::new(challenge.nonce.clone().into()),
    )?;
    let request = PaOtpRequest {
        flags: OtpFlags(BitString::repeat(false, 32)),
        enc_data: seal(armor_key, KEY_USAGE_PA_OTP_REQUEST, &nonce)?,
        otp_value: value.to_vec().into(),
        otp_pin: separate,
        otp_format: token.format.map(wire_format),
        otp_token_id: token.id.clone().map(Into::into),
        otp_alg_id: token.alg_id.clone(),
        otp_vendor: token.vendor.clone(),
    };
    let der = encode("PA-OTP-REQUEST", &request)?;
    Ok(PaData {
        r#type: PA_OTP_REQUEST,
        value: der.to_vec().into(),
    })
}

/// The wire value of a format.
fn wire_format(format: Format) -> WireFormat {
    match format {
        Format::Decimal => WireFormat::decimal(),
        Format::Hexadecimal => WireFormat::hexadecimal(),
        Format::Alphanumeric => WireFormat::alphanumeric(),
        Format::Binary => WireFormat::binary(),
    }
}

/// The value must fit the token: not empty, within the policy, of the token's
/// length and format (MIT `otpvalue_matches_tokeninfo`).
///
/// # Errors
/// Returns [`Error::ValueRejected`] or [`Error::ValueTooLong`].
fn check_value(token: &Token, value: &[u8], policy: &Policy) -> Result<(), Error> {
    let rejected = |reason| Err(Error::ValueRejected { reason });
    if value.is_empty() {
        return rejected("the value is empty");
    }
    if value.len() > policy.value_bytes {
        return Err(Error::ValueTooLong {
            limit: policy.value_bytes,
        });
    }
    if token.length.is_some_and(|length| length != value.len()) {
        return rejected("the length differs from the token's");
    }
    let matches = match token.format {
        Some(Format::Decimal) => value.iter().all(u8::is_ascii_digit),
        Some(Format::Hexadecimal) => value.iter().all(u8::is_ascii_hexdigit),
        Some(Format::Alphanumeric) => value.iter().all(u8::is_ascii_alphanumeric),
        Some(Format::Binary) | None => true,
    };
    if matches {
        Ok(())
    } else {
        rejected("the format is not the token's")
    }
}

/// The value to send and the separate PIN, by the token's PIN mode.
///
/// A separate PIN travels in `otp-pin`, a collected one is prefixed to the value
/// (RFC 6560 section 3.3, MIT `preauth_otp.c:643-664`), a refused one is an error.
///
/// # Errors
/// Returns [`Error::ValueTooLong`], [`Error::PinNotCollected`] and
/// [`Error::PinRequired`].
fn place_pin(
    token: &Token,
    response: &Response,
    policy: &Policy,
) -> Result<(Zeroizing<Vec<u8>>, Option<String>), Error> {
    let answered = response.pin.as_ref().map(|secret| secret.as_str());
    if answered.is_some_and(|text| text.len() > policy.value_bytes) {
        return Err(Error::ValueTooLong {
            limit: policy.value_bytes,
        });
    }
    match (token.pin, answered) {
        (PinMode::DoNotCollect, Some(_text)) => Err(Error::PinNotCollected),
        (PinMode::CollectSeparately, None) => Err(Error::PinRequired),
        (PinMode::CollectSeparately, Some(text)) => {
            Ok((response.value.clone(), Some(text.to_owned())))
        }
        (_, Some(text)) => {
            let mut combined = Zeroizing::new(text.as_bytes().to_vec());
            combined.extend_from_slice(&response.value);
            Ok((combined, None))
        }
        (_, None) => Ok((response.value.clone(), None)),
    }
}

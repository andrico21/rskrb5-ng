//! OTP preauthentication inside FAST (RFC 6560, MIT 1.22.2 `preauth_otp.c`).
//!
//! The KDC offers `PA-OTP-CHALLENGE` in an armored `PREAUTH_REQUIRED`; the user
//! chooses a token and types its value (and a PIN, when the token takes one); the
//! client answers with a `PA-OTP-REQUEST` that carries the KDC's nonce encrypted in
//! the FAST armor key and the value, and the reply key becomes the armor key
//! (RFC 6560 section 3.6, MIT `preauth_otp.c:1113-1127`).
//! [`Challenge`] is the decoded, bounded and filtered challenge, [`Response`]
//! the user's answer, [`Responder`] the callback that produces it and
//! [`Policy`] the bounds. Install the policy on a stepwise exchange with
//! `InitCreds::with_otp`; the exchange then asks through `Prompt::Otp` and
//! `Answer::Otp`, or through [`Responders`] under `stepwise::drive`.
//!
//! The gap analysis names `OtpChallenge`, `OtpResponse`, `OtpResponder` and
//! `OtpPolicy`; the strict lint profile (`module_name_repetitions`) refuses the
//! repeated prefix, so they are `otp::Challenge`, `otp::Response`, `otp::Responder`
//! and `otp::Policy` (the same reason as `spake::Client`). The exchange-level entry
//! is `InitCreds::with_otp`.
//!
//! # Supported tokens
//!
//! Like MIT, only tokens with the `collect-pin`, `do-not-collect-pin` and
//! `separate-pin-required` flags are answered, with the OTP value in
//! `otp-value`; a token that needs `nextOTP`, `combine`, `must-encrypt-nonce`,
//! `check-digit`, hashing (`supportedHashAlg`, `iterationCount`) or base64
//! values, or whose vendor or challenge is not printable ASCII, is dropped and
//! counted ([`Challenge::unsupported`]). A PIN-change message
//! (`PA-OTP-PIN-CHANGE`) is not handled, as in MIT.
//!
//! # Security
//!
//! - OTP is never sent unarmored: the exchange refuses a challenge without a FAST
//!   armor key ([`Otp::ArmorRequired`]) and, with an OTP policy installed
//!   and no armor, sends nothing at all.
//! - The user selects the token: the engine never picks among several tokens
//!   (MIT `prompt_for_tokeninfo`), and the answer is checked against the token's
//!   length, format and PIN mode before a request is built.
//! - The OTP value and the PIN live in zeroizing owners, are redacted from `Debug`
//!   and are never cached: the exchange drops them as soon as the request is built.
//!   The DER request, the padata copy of it and the armored request hold the value
//!   as bytes that are erased only where the type is [`zeroize::Zeroizing`]; the
//!   `rasn` containers that wrap the bytes are freed without erasure (a residual
//!   copy, see the parity register).
//! - Challenge size, token count and every field are bounded by [`Policy`]; the
//!   user's value and PIN are bounded too.
//! - An OTP value is tried once: a refusal ends the exchange with the KDC's error,
//!   so a script cannot lock the account by retrying.
//!

use core::fmt;
use std::time::SystemTime;

use rasn_kerberos::PaData;
use zeroize::Zeroizing;

use crate::{
    client::stepwise::{Answer, Prompt, Responder as PromptResponder},
    error::Otp,
    extensions::ProviderError,
    keytab::EncryptionKey,
};

/// The challenge decoder.
mod challenge;
/// The request builder.
mod request;

/// `PA-OTP-CHALLENGE` (RFC 6560 section 4.1).
pub const PA_OTP_CHALLENGE: i32 = 141;
/// `PA-OTP-REQUEST` (RFC 6560 section 4.2).
pub const PA_OTP_REQUEST: i32 = 142;
/// `KEY_USAGE_OTP_REQUEST` (RFC 6560 section 4.2, MIT `KRB5_KEYUSAGE_PA_OTP_REQUEST`).
pub const KEY_USAGE_PA_OTP_REQUEST: u32 = 45;

/// The bounds of one OTP exchange; see the [module](self) docs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Policy {
    /// The longest `PA-OTP-CHALLENGE` value decoded.
    challenge_bytes: usize,
    /// The most token infos in one challenge.
    token_count: usize,
    /// The longest nonce, vendor, challenge, token id and algorithm id.
    field_bytes: usize,
    /// The longest OTP value and PIN a user may answer.
    value_bytes: usize,
}

impl Default for Policy {
    #[inline]
    fn default() -> Self {
        Self {
            challenge_bytes: 16 * 1024,
            token_count: 16,
            field_bytes: 1024,
            value_bytes: 1024,
        }
    }
}

impl Policy {
    /// Decode at most `bytes` of challenge (default 16 KiB).
    #[inline]
    #[must_use]
    pub const fn with_max_challenge_bytes(mut self, bytes: usize) -> Self {
        self.challenge_bytes = bytes;
        self
    }

    /// Accept at most `tokens` token infos (default 16).
    #[inline]
    #[must_use]
    pub const fn with_max_tokens(mut self, tokens: usize) -> Self {
        self.token_count = tokens;
        self
    }

    /// Accept challenge fields of at most `bytes` (default 1024).
    #[inline]
    #[must_use]
    pub const fn with_max_field_bytes(mut self, bytes: usize) -> Self {
        self.field_bytes = bytes;
        self
    }

    /// Accept an OTP value and a PIN of at most `bytes` each (default 1024, MIT's
    /// prompt buffer).
    #[inline]
    #[must_use]
    pub const fn with_max_value_bytes(mut self, bytes: usize) -> Self {
        self.value_bytes = bytes;
        self
    }

    /// The challenge size bound.
    #[inline]
    #[must_use]
    pub const fn max_challenge_bytes(&self) -> usize {
        self.challenge_bytes
    }

    /// The token count bound.
    #[inline]
    #[must_use]
    pub const fn max_tokens(&self) -> usize {
        self.token_count
    }

    /// The field size bound.
    #[inline]
    #[must_use]
    pub const fn max_field_bytes(&self) -> usize {
        self.field_bytes
    }

    /// The value and PIN size bound.
    #[inline]
    #[must_use]
    pub const fn max_value_bytes(&self) -> usize {
        self.value_bytes
    }
}

/// The format of an OTP value (RFC 6560 `OTPFormat`); base64 tokens are not supported.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Format {
    /// Decimal digits.
    Decimal,
    /// Hexadecimal digits.
    Hexadecimal,
    /// Letters and digits.
    Alphanumeric,
    /// Raw octets.
    Binary,
}

/// What a token does with a PIN (the `collect-pin`, `do-not-collect-pin` and
/// `separate-pin-required` flags).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PinMode {
    /// The KDC says nothing; a PIN, if answered, is prefixed to the value.
    Unspecified,
    /// A PIN is collected and prefixed to the value (an answer without one means
    /// the responder combined them already).
    Collect,
    /// The PIN is required and travels in its own field.
    CollectSeparately,
    /// The token takes no PIN; an answer with one is refused.
    DoNotCollect,
}

/// One token the user can answer with.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Token {
    /// `otp-vendor`.
    vendor: Option<String>,
    /// `otp-challenge`, printable.
    challenge: Option<String>,
    /// `otp-length`.
    length: Option<usize>,
    /// `otp-format`.
    format: Option<Format>,
    /// `otp-tokenID`.
    id: Option<Vec<u8>>,
    /// `otp-algID`.
    alg_id: Option<String>,
    /// The PIN flags.
    pin: PinMode,
}

impl Token {
    /// The token's vendor, printable ASCII.
    #[inline]
    #[must_use]
    pub fn vendor(&self) -> Option<&str> {
        self.vendor.as_deref()
    }

    /// The challenge the user's token must answer, printable ASCII.
    #[inline]
    #[must_use]
    pub fn challenge(&self) -> Option<&str> {
        self.challenge.as_deref()
    }

    /// The length of the value the KDC expects.
    #[inline]
    #[must_use]
    pub const fn length(&self) -> Option<usize> {
        self.length
    }

    /// The format of the value the KDC expects.
    #[inline]
    #[must_use]
    pub const fn format(&self) -> Option<Format> {
        self.format
    }

    /// The token identifier.
    #[inline]
    #[must_use]
    pub fn token_id(&self) -> Option<&[u8]> {
        self.id.as_deref()
    }

    /// The algorithm identifier (a URI).
    #[inline]
    #[must_use]
    pub fn alg_id(&self) -> Option<&str> {
        self.alg_id.as_deref()
    }

    /// How the token handles a PIN.
    #[inline]
    #[must_use]
    pub const fn pin(&self) -> PinMode {
        self.pin
    }
}

/// A decoded, bounded `PA-OTP-CHALLENGE` with the tokens this client can answer.
#[derive(Clone, Eq, PartialEq)]
pub struct Challenge {
    /// `otp-service`.
    service: Option<String>,
    /// The usable tokens, in the KDC's order.
    tokens: Vec<Token>,
    /// How many token infos were dropped as unsupported.
    unsupported: usize,
    /// The KDC's nonce.
    nonce: Vec<u8>,
}

impl Challenge {
    /// Decode `value`, the `PA-OTP-CHALLENGE` of an armored `PREAUTH_REQUIRED`,
    /// under `policy`: the size, the token count and every field are bounded, token
    /// infos this client cannot answer are dropped (and counted), and an RFC 6560
    /// violation is refused.
    ///
    /// # Errors
    ///
    /// Returns [`Otp::ChallengeTooLarge`], [`Otp::TooManyTokens`],
    /// [`Otp::FieldTooLong`], [`Otp::Malformed`] for a value that is not a
    /// challenge, [`Otp::ConflictingPinFlags`] and [`Otp::NoSupportedTokens`]
    /// when no token remains.
    #[inline]
    pub fn decode(value: &[u8], policy: &Policy) -> Result<Self, Otp> {
        challenge::decode(value, policy)
    }

    /// The `PA-OTP-REQUEST` that answers this challenge with `response`: it names the
    /// chosen token, carries the OTP value and, for a token with a separate PIN, the
    /// PIN, and encrypts the KDC's nonce in `armor_key` (usage
    /// [`KEY_USAGE_PA_OTP_REQUEST`]). The reply key of the exchange is the armor key.
    ///
    /// # Errors
    ///
    /// Returns [`Otp::UnknownToken`] for an index outside [`Challenge::tokens`],
    /// [`Otp::ValueTooLong`] and [`Otp::ValueRejected`] for a value or PIN the
    /// policy or the token refuses, [`Otp::PinRequired`] and
    /// [`Otp::PinNotCollected`], and [`Otp::Seal`] when the armor key cannot
    /// encrypt.
    #[inline]
    pub fn request(
        &self,
        response: &Response,
        armor_key: &EncryptionKey,
        policy: &Policy,
    ) -> Result<PaData, Otp> {
        request::build(self, response, armor_key, policy)
    }

    /// The purpose of the authentication, if the KDC names one.
    #[inline]
    #[must_use]
    pub fn service(&self) -> Option<&str> {
        self.service.as_deref()
    }

    /// The tokens the user can choose from; [`Response::new`] names one by its
    /// index here.
    #[inline]
    #[must_use]
    pub fn tokens(&self) -> &[Token] {
        &self.tokens
    }

    /// How many token infos of the KDC were dropped as unsupported.
    #[inline]
    #[must_use]
    pub const fn unsupported(&self) -> usize {
        self.unsupported
    }
}

impl fmt::Debug for Challenge {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Challenge")
            .field("service", &self.service)
            .field("tokens", &self.tokens)
            .field("unsupported", &self.unsupported)
            .finish_non_exhaustive()
    }
}

/// The user's answer: the chosen token, its value and, if it takes one, a PIN.
/// The value and the PIN are erased when the answer is dropped and are redacted
/// from `Debug`.
pub struct Response {
    /// The index into [`Challenge::tokens`].
    token: usize,
    /// The OTP value, exactly as the token produced it.
    value: Zeroizing<Vec<u8>>,
    /// The PIN.
    pin: Option<Zeroizing<String>>,
}

impl Response {
    /// Answer with `value` from the token at `token` of [`Challenge::tokens`].
    #[inline]
    #[must_use]
    pub fn new(token: usize, value: Vec<u8>) -> Self {
        Self {
            token,
            value: Zeroizing::new(value),
            pin: None,
        }
    }

    /// Add the token's PIN.
    #[inline]
    #[must_use]
    pub fn with_pin(mut self, pin: String) -> Self {
        self.pin = Some(Zeroizing::new(pin));
        self
    }

    /// The chosen token's index.
    #[inline]
    #[must_use]
    pub const fn token(&self) -> usize {
        self.token
    }
}

impl fmt::Debug for Response {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Response")
            .field("token", &self.token)
            .field("value", &"[REDACTED]")
            .field("pin", &self.pin.as_ref().map(|_pin| "[REDACTED]"))
            .finish()
    }
}

/// The user side of OTP: choose a token and read its value.
pub trait Responder {
    /// Show `challenge` to the user and return the token they chose, its value
    /// and PIN. Nothing is chosen for the user, also with one token.
    ///
    /// # Errors
    ///
    /// Returns the caller's failure; the driver reports it as
    /// `error::Client::Responder` and abandons the exchange.
    fn select(&mut self, challenge: &Challenge) -> Result<Response, ProviderError>;
}

/// A stepwise `Responder` that answers `Prompt::Otp` with a [`Responder`] and every
/// other prompt with the wrapped one.
#[derive(Debug)]
pub struct Responders<R, O> {
    /// The responder of the other prompts.
    inner: R,
    /// The OTP responder.
    otp: O,
}

impl<R, O> Responders<R, O> {
    /// Route OTP prompts to `otp` and every other prompt to `inner`.
    #[inline]
    #[must_use]
    pub const fn new(inner: R, otp: O) -> Self {
        Self { inner, otp }
    }

    /// The OTP responder.
    #[inline]
    #[must_use]
    pub const fn otp(&self) -> &O {
        &self.otp
    }
}

impl<R: PromptResponder, O: Responder> PromptResponder for Responders<R, O> {
    #[inline]
    fn respond(&mut self, prompt: &Prompt) -> Result<Answer, ProviderError> {
        match prompt {
            Prompt::Otp {
                client: _,
                challenge,
            } => self.otp.select(challenge).map(Answer::Otp),
            Prompt::Password { client: _ } => self.inner.respond(prompt),
        }
    }

    #[inline]
    fn password_expiry(&mut self, expires: SystemTime) {
        self.inner.password_expiry(expires);
    }
}

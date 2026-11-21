//! The result code and result text of a kpasswd reply (MIT `chpw.c:245-275,372-510`).

/// The length of the Active Directory policy structure (MIT `AD_POLICY_INFO_LENGTH`).
const AD_POLICY_INFO_LENGTH: usize = 30;
/// 100-nanosecond intervals in a day (MIT `AD_POLICY_TIME_TO_DAYS`).
const AD_POLICY_TIME_TO_DAYS: u64 = 86_400 * 10_000_000;
/// `AD_POLICY_COMPLEX`: the password must include numbers or symbols.
const AD_POLICY_COMPLEX: u32 = 1;

/// An RFC 3244 result code, with Microsoft's extension.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ResultCode {
    /// The password was changed.
    Success,
    /// The request was malformed.
    Malformed,
    /// The server failed.
    HardError,
    /// The server could not authenticate the request.
    AuthError,
    /// The new password was rejected, usually by policy: the user may try another.
    SoftError,
    /// The client is not allowed to make this change.
    AccessDenied,
    /// The protocol version is not supported.
    BadVersion,
    /// The change needs a ticket obtained with a password (the initial flag).
    InitialFlagNeeded,
    /// A code outside RFC 3244.
    Other(u16),
}

impl From<u16> for ResultCode {
    #[inline]
    fn from(code: u16) -> Self {
        match code {
            0 => Self::Success,
            1 => Self::Malformed,
            2 => Self::HardError,
            3 => Self::AuthError,
            4 => Self::SoftError,
            5 => Self::AccessDenied,
            6 => Self::BadVersion,
            7 => Self::InitialFlagNeeded,
            other => Self::Other(other),
        }
    }
}

impl ResultCode {
    /// MIT's description of the code (`krb5_chpw_result_code_string`).
    #[inline]
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::Success => "Success",
            Self::Malformed => "Malformed request error",
            Self::HardError => "Server error",
            Self::AuthError => "Authentication error",
            Self::SoftError => "Password change rejected",
            Self::AccessDenied => "Access denied",
            Self::BadVersion => "Wrong protocol version",
            Self::InitialFlagNeeded => "Initial password required",
            Self::Other(_) => "Password change failed",
        }
    }
}

/// The Active Directory password policy in the result text of a rejection.
///
/// A packed 30-byte structure that starts with two zero bytes, so that the text looks
/// empty to a reader that expects UTF-8.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct AdPasswordPolicy {
    /// The minimum number of characters.
    min_length: u32,
    /// The number of previous passwords the new one must differ from.
    history: u32,
    /// The password properties; bit 0 requires complexity.
    properties: u32,
    /// The maximum password age, in 100-nanosecond intervals.
    expire: u64,
    /// The minimum password age, in 100-nanosecond intervals.
    min_age: u64,
}

impl AdPasswordPolicy {
    /// A policy from its fields.
    #[inline]
    #[must_use]
    pub const fn new(
        min_length: u32,
        history: u32,
        properties: u32,
        expire: u64,
        min_age: u64,
    ) -> Self {
        Self {
            min_length,
            history,
            properties,
            expire,
            min_age,
        }
    }

    /// The minimum number of characters.
    #[inline]
    #[must_use]
    pub const fn min_length(&self) -> u32 {
        self.min_length
    }

    /// The number of previous passwords the new one must differ from.
    #[inline]
    #[must_use]
    pub const fn history(&self) -> u32 {
        self.history
    }

    /// The raw password properties.
    #[inline]
    #[must_use]
    pub const fn properties(&self) -> u32 {
        self.properties
    }

    /// The maximum password age, in 100-nanosecond intervals.
    #[inline]
    #[must_use]
    pub const fn expire(&self) -> u64 {
        self.expire
    }

    /// The minimum password age, in 100-nanosecond intervals.
    #[inline]
    #[must_use]
    pub const fn min_age(&self) -> u64 {
        self.min_age
    }

    /// Whether the password must include numbers or symbols.
    #[inline]
    #[must_use]
    pub const fn requires_complexity(&self) -> bool {
        self.properties & AD_POLICY_COMPLEX != 0
    }

    /// Read the structure from result text; `None` unless it is exactly 30 bytes that
    /// start with two zero bytes (MIT `decode_ad_policy_info`).
    fn parse(text: &[u8]) -> Option<Self> {
        let fields: &[u8; AD_POLICY_INFO_LENGTH] = text.try_into().ok()?;
        let [0, 0, rest @ ..] = fields else {
            return None;
        };
        let (min_length, after_length) = rest.split_first_chunk::<4>()?;
        let (history, after_history) = after_length.split_first_chunk::<4>()?;
        let (properties, after_properties) = after_history.split_first_chunk::<4>()?;
        let (expire, min_age) = after_properties.split_first_chunk::<8>()?;
        Some(Self::new(
            u32::from_be_bytes(*min_length),
            u32::from_be_bytes(*history),
            u32::from_be_bytes(*properties),
            u64::from_be_bytes(*expire),
            u64::from_be_bytes(min_age.try_into().ok()?),
        ))
    }

    /// MIT's sentences for the policy; empty when the policy asks for nothing.
    fn sentences(&self) -> String {
        let mut text = String::new();
        let mut sentence = |part: &str| {
            if !text.is_empty() {
                text.push_str("  ");
            }
            text.push_str(part);
        };
        if self.requires_complexity() {
            sentence(
                "The password must include numbers or symbols.  Don't include any part of your name in the password.",
            );
        }
        if self.min_length > 0 {
            let plural = if self.min_length == 1 { "" } else { "s" };
            sentence(&format!(
                "The password must contain at least {} character{plural}.",
                self.min_length
            ));
        }
        if self.history > 0 {
            sentence(&if self.history == 1 {
                "The password must be different from the previous password.".to_owned()
            } else {
                format!(
                    "The password must be different from the previous {} passwords.",
                    self.history
                )
            });
        }
        if self.min_age > 0 {
            let days = self.min_age.div_euclid(AD_POLICY_TIME_TO_DAYS).max(1);
            sentence(&if days == 1 {
                "The password can only be changed once a day.".to_owned()
            } else {
                format!("The password can only be changed every {days} days.")
            });
        }
        text
    }
}

/// The message of a result text (MIT `krb5_chpw_message`): the sentences of an Active
/// Directory policy; else the text when it is valid UTF-8 without NUL; else generic advice.
pub(super) fn message(text: &[u8]) -> String {
    if let Some(policy) = AdPasswordPolicy::parse(text) {
        let sentences = policy.sentences();
        if !sentences.is_empty() {
            return sentences;
        }
    }
    match str::from_utf8(text) {
        Ok(printable) if !printable.is_empty() && !printable.contains('\0') => printable.to_owned(),
        _ => "Try a more complex password, or contact your administrator.".to_owned(),
    }
}

/// The Active Directory policy in a result text, if it carries one.
pub(super) fn ad_policy(text: &[u8]) -> Option<AdPasswordPolicy> {
    AdPasswordPolicy::parse(text)
}

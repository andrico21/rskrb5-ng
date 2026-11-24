/// A decoded kadm5 result: what a successful call of a [`Procedure`] returns.
///
/// [`RemoteAdminClient`] decodes each result through [`Response::decode`];
/// it is public so results can be decoded and tested on their own.
#[non_exhaustive]
pub enum Response {
    /// `generic_ret`: the call succeeded.
    Done,
    /// `gprinc_ret`.
    Principal(Box<PrincipalRecord>),
    /// `gpol_ret`.
    Policy(Box<PolicyRecord>),
    /// `gprincs_ret` or `gpols_ret`: names.
    Names(Vec<String>),
    /// `chrand_ret`: the new random keys.
    Keys(Vec<EncryptionKey>),
    /// `getprivs_ret`.
    Privileges(Privileges),
    /// `gstrings_ret`.
    Strings(Vec<StringAttribute>),
    /// `getpkeys_ret`: keys with their versions and salts.
    KeyData(Vec<KeyData>),
}

impl fmt::Debug for Response {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Done => f.write_str("Done"),
            Self::Principal(record) => f.debug_tuple("Principal").field(record).finish(),
            Self::Policy(record) => f.debug_tuple("Policy").field(record).finish(),
            Self::Names(names) => f.debug_tuple("Names").field(names).finish(),
            Self::Keys(keys) => f.debug_tuple("Keys").field(keys).finish(),
            Self::Privileges(privileges) => f.debug_tuple("Privileges").field(privileges).finish(),
            Self::Strings(strings) => f.debug_tuple("Strings").field(strings).finish(),
            Self::KeyData(keys) => f.debug_tuple("KeyData").field(keys).finish(),
        }
    }
}

impl Response {
    /// Decode the result of `procedure` under API `version` (`kadm_rpc_xdr.c`).
    ///
    /// The result is the version and code, then on success the procedure's
    /// payload, with no byte left over.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Server`] for a non-zero code, [`Error::Malformed`] for
    /// a layout violation, a principal name that does not parse, disagreeing
    /// counts or trailing bytes, and [`Error::TooLarge`] for a string, list or
    /// key above its bound; a count is checked against the bytes before
    /// anything is allocated.
    #[inline]
    pub fn decode(procedure: Procedure, version: ApiVersion, bytes: &[u8]) -> Result<Self, Error> {
        wire::decode_response(procedure, version, bytes)
    }
}

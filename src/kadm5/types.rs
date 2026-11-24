/// The first two components of the admin service, `kadmin/admin`
/// (`KADM5_ADMIN_SERVICE`, `admin.h:64`).
pub const ADMIN_SERVICE: [&str; 2] = ["kadmin", "admin"];

/// kadmind's port when `admin_server` names none (`DEFAULT_KADM5_PORT`).
pub const DEFAULT_PORT: u16 = 749;

/// The kadm5 RPC program, `KADM` 2112 version 2 (`kadm_rpc.h`).
pub const PROGRAM: Program = Program::new(2112, 2);

/// The kadm5 API version a connection speaks (`admin.h:185-188`).
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum ApiVersion {
    /// `KADM5_API_VERSION_2`.
    V2,
    /// `KADM5_API_VERSION_3`: the policy lockout fields.
    V3,
    /// `KADM5_API_VERSION_4`: the policy attributes, lifetimes, key/salt
    /// list and TL data.
    #[default]
    V4,
}

impl ApiVersion {
    /// The version on the wire: `KADM5_API_VERSION_MASK | n`.
    #[inline]
    #[must_use]
    pub const fn wire(self) -> u32 {
        match self {
            Self::V2 => 0x1234_5702,
            Self::V3 => 0x1234_5703,
            Self::V4 => 0x1234_5704,
        }
    }

    /// The next older version, if there is one.
    const fn older(self) -> Option<Self> {
        match self {
            Self::V4 => Some(Self::V3),
            Self::V3 => Some(Self::V2),
            Self::V2 => None,
        }
    }
}

/// A kadm5 remote procedure (`kadm_rpc.h`; 17, `SETV4KEY`, was removed in 1.18).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum Procedure {
    /// `CREATE_PRINCIPAL` (1).
    CreatePrincipal,
    /// `DELETE_PRINCIPAL` (2).
    DeletePrincipal,
    /// `MODIFY_PRINCIPAL` (3).
    ModifyPrincipal,
    /// `RENAME_PRINCIPAL` (4).
    RenamePrincipal,
    /// `GET_PRINCIPAL` (5).
    GetPrincipal,
    /// `CHPASS_PRINCIPAL` (6).
    ChangePassword,
    /// `CHRAND_PRINCIPAL` (7).
    RandomizeKeys,
    /// `CREATE_POLICY` (8).
    CreatePolicy,
    /// `DELETE_POLICY` (9).
    DeletePolicy,
    /// `MODIFY_POLICY` (10).
    ModifyPolicy,
    /// `GET_POLICY` (11).
    GetPolicy,
    /// `GET_PRIVS` (12).
    GetPrivileges,
    /// `INIT` (13): the API version negotiation.
    Init,
    /// `GET_PRINCS` (14).
    GetPrincipals,
    /// `GET_POLS` (15).
    GetPolicies,
    /// `SETKEY_PRINCIPAL` (16).
    SetKeys,
    /// `CREATE_PRINCIPAL3` (18): with key/salt tuples.
    CreatePrincipal3,
    /// `CHPASS_PRINCIPAL3` (19): with key/salt tuples and keep-old.
    ChangePassword3,
    /// `CHRAND_PRINCIPAL3` (20): with key/salt tuples and keep-old.
    RandomizeKeys3,
    /// `SETKEY_PRINCIPAL3` (21): with key/salt tuples and keep-old.
    SetKeys3,
    /// `PURGEKEYS` (22).
    PurgeKeys,
    /// `GET_STRINGS` (23).
    GetStrings,
    /// `SET_STRING` (24).
    SetString,
    /// `SETKEY_PRINCIPAL4` (25): key data with versions and salts.
    SetKeys4,
    /// `EXTRACT_KEYS` (26): `kadm5_get_principal_keys`.
    ExtractKeys,
    /// `CREATE_ALIAS` (27).
    CreateAlias,
}

impl Procedure {
    /// The procedure number.
    #[inline]
    #[must_use]
    pub const fn number(self) -> u32 {
        match self {
            Self::CreatePrincipal => 1,
            Self::DeletePrincipal => 2,
            Self::ModifyPrincipal => 3,
            Self::RenamePrincipal => 4,
            Self::GetPrincipal => 5,
            Self::ChangePassword => 6,
            Self::RandomizeKeys => 7,
            Self::CreatePolicy => 8,
            Self::DeletePolicy => 9,
            Self::ModifyPolicy => 10,
            Self::GetPolicy => 11,
            Self::GetPrivileges => 12,
            Self::Init => 13,
            Self::GetPrincipals => 14,
            Self::GetPolicies => 15,
            Self::SetKeys => 16,
            Self::CreatePrincipal3 => 18,
            Self::ChangePassword3 => 19,
            Self::RandomizeKeys3 => 20,
            Self::SetKeys3 => 21,
            Self::PurgeKeys => 22,
            Self::GetStrings => 23,
            Self::SetString => 24,
            Self::SetKeys4 => 25,
            Self::ExtractKeys => 26,
            Self::CreateAlias => 27,
        }
    }

    /// MIT's name of the procedure's client function.
    #[inline]
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::CreatePrincipal => "kadm5_create_principal",
            Self::DeletePrincipal => "kadm5_delete_principal",
            Self::ModifyPrincipal => "kadm5_modify_principal",
            Self::RenamePrincipal => "kadm5_rename_principal",
            Self::GetPrincipal => "kadm5_get_principal",
            Self::ChangePassword => "kadm5_chpass_principal",
            Self::RandomizeKeys => "kadm5_randkey_principal",
            Self::CreatePolicy => "kadm5_create_policy",
            Self::DeletePolicy => "kadm5_delete_policy",
            Self::ModifyPolicy => "kadm5_modify_policy",
            Self::GetPolicy => "kadm5_get_policy",
            Self::GetPrivileges => "kadm5_get_privs",
            Self::Init => "kadm5_init",
            Self::GetPrincipals => "kadm5_get_principals",
            Self::GetPolicies => "kadm5_get_policies",
            Self::SetKeys => "kadm5_setkey_principal",
            Self::CreatePrincipal3 => "kadm5_create_principal_3",
            Self::ChangePassword3 => "kadm5_chpass_principal_3",
            Self::RandomizeKeys3 => "kadm5_randkey_principal_3",
            Self::SetKeys3 => "kadm5_setkey_principal_3",
            Self::PurgeKeys => "kadm5_purgekeys",
            Self::GetStrings => "kadm5_get_strings",
            Self::SetString => "kadm5_set_string",
            Self::SetKeys4 => "kadm5_setkey_principal_4",
            Self::ExtractKeys => "kadm5_get_principal_keys",
            Self::CreateAlias => "kadm5_create_alias",
        }
    }

    /// Whether the procedure changes the database: its outcome is unknown when
    /// it may have been delivered and has no authenticated answer.
    #[inline]
    #[must_use]
    pub const fn is_mutation(self) -> bool {
        !matches!(
            self,
            Self::GetPrincipal
                | Self::GetPolicy
                | Self::GetPrivileges
                | Self::Init
                | Self::GetPrincipals
                | Self::GetPolicies
                | Self::GetStrings
                | Self::ExtractKeys
        )
    }
}

/// The fields of a principal record a call reads or sets (`admin.h:88-116`).
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub struct PrincipalMask(u32);

impl PrincipalMask {
    /// `KADM5_PRINCIPAL`.
    pub const PRINCIPAL: Self = Self(0x01);

    /// `KADM5_PRINC_EXPIRE_TIME`.
    pub const PRINC_EXPIRE_TIME: Self = Self(0x02);

    /// `KADM5_PW_EXPIRATION`.
    pub const PW_EXPIRATION: Self = Self(0x04);

    /// `KADM5_LAST_PWD_CHANGE`.
    pub const LAST_PWD_CHANGE: Self = Self(0x08);

    /// `KADM5_ATTRIBUTES`.
    pub const ATTRIBUTES: Self = Self(0x10);

    /// `KADM5_MAX_LIFE`.
    pub const MAX_LIFE: Self = Self(0x20);

    /// `KADM5_MOD_TIME`.
    pub const MOD_TIME: Self = Self(0x40);

    /// `KADM5_MOD_NAME`.
    pub const MOD_NAME: Self = Self(0x80);

    /// `KADM5_KVNO`.
    pub const KVNO: Self = Self(0x100);

    /// `KADM5_MKVNO`.
    pub const MKVNO: Self = Self(0x200);

    /// `KADM5_AUX_ATTRIBUTES`.
    pub const AUX_ATTRIBUTES: Self = Self(0x400);

    /// `KADM5_POLICY`.
    pub const POLICY: Self = Self(0x800);

    /// `KADM5_POLICY_CLR`.
    pub const POLICY_CLR: Self = Self(0x1000);

    /// `KADM5_MAX_RLIFE`.
    pub const MAX_RLIFE: Self = Self(0x2000);

    /// `KADM5_LAST_SUCCESS`.
    pub const LAST_SUCCESS: Self = Self(0x4000);

    /// `KADM5_LAST_FAILED`.
    pub const LAST_FAILED: Self = Self(0x8000);

    /// `KADM5_FAIL_AUTH_COUNT`.
    pub const FAIL_AUTH_COUNT: Self = Self(0x1_0000);

    /// `KADM5_KEY_DATA`.
    pub const KEY_DATA: Self = Self(0x2_0000);

    /// `KADM5_TL_DATA`.
    pub const TL_DATA: Self = Self(0x4_0000);

    /// `KADM5_KEY_HIST`.
    pub const KEY_HIST: Self = Self(0x40_0000);

    /// `KADM5_PRINCIPAL_NORMAL_MASK`: every field `get_principal` returns
    /// by default.
    pub const NORMAL: Self = Self(0x41_ffff);

    /// The bits.
    #[inline]
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// A mask of the given bits.
    #[inline]
    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Whether every bit of `other` is set.
    #[inline]
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// This mask without the bits of `other`.
    #[inline]
    #[must_use]
    pub const fn without(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }
}

impl BitOr for PrincipalMask {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

/// The fields of a policy record a call sets (`admin.h:99,120-133`).
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub struct PolicyMask(u32);

impl PolicyMask {
    /// `KADM5_POLICY`: the name.
    pub const POLICY: Self = Self(0x800);

    /// `KADM5_PW_MAX_LIFE`.
    pub const PW_MAX_LIFE: Self = Self(0x4000);

    /// `KADM5_PW_MIN_LIFE`.
    pub const PW_MIN_LIFE: Self = Self(0x8000);

    /// `KADM5_PW_MIN_LENGTH`.
    pub const PW_MIN_LENGTH: Self = Self(0x1_0000);

    /// `KADM5_PW_MIN_CLASSES`.
    pub const PW_MIN_CLASSES: Self = Self(0x2_0000);

    /// `KADM5_PW_HISTORY_NUM`.
    pub const PW_HISTORY_NUM: Self = Self(0x4_0000);

    /// `KADM5_PW_MAX_FAILURE`.
    pub const PW_MAX_FAILURE: Self = Self(0x10_0000);

    /// `KADM5_PW_FAILURE_COUNT_INTERVAL`.
    pub const PW_FAILURE_COUNT_INTERVAL: Self = Self(0x20_0000);

    /// `KADM5_PW_LOCKOUT_DURATION`.
    pub const PW_LOCKOUT_DURATION: Self = Self(0x40_0000);

    /// `KADM5_POLICY_ATTRIBUTES`.
    pub const ATTRIBUTES: Self = Self(0x80_0000);

    /// `KADM5_POLICY_MAX_LIFE`.
    pub const MAX_LIFE: Self = Self(0x100_0000);

    /// `KADM5_POLICY_MAX_RLIFE`.
    pub const MAX_RLIFE: Self = Self(0x200_0000);

    /// `KADM5_POLICY_ALLOWED_KEYSALTS`.
    pub const ALLOWED_KEYSALTS: Self = Self(0x400_0000);

    /// `KADM5_POLICY_TL_DATA`.
    pub const TL_DATA: Self = Self(0x800_0000);

    /// The bits.
    #[inline]
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// A mask of the given bits.
    #[inline]
    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Whether every bit of `other` is set.
    #[inline]
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// This mask without the bits of `other`.
    #[inline]
    #[must_use]
    pub const fn without(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }
}

impl BitOr for PolicyMask {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

/// The caller's privileges (`KADM5_PRIV_*`, `admin.h:171-174`).
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub struct Privileges(u32);

impl Privileges {
    /// `KADM5_PRIV_GET`.
    pub const GET: Self = Self(0x01);

    /// `KADM5_PRIV_ADD`.
    pub const ADD: Self = Self(0x02);

    /// `KADM5_PRIV_MODIFY`.
    pub const MODIFY: Self = Self(0x04);

    /// `KADM5_PRIV_DELETE`.
    pub const DELETE: Self = Self(0x08);

    /// The bits.
    #[inline]
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// A mask of the given bits.
    #[inline]
    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Whether every bit of `other` is set.
    #[inline]
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// This mask without the bits of `other`.
    #[inline]
    #[must_use]
    pub const fn without(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }
}

impl BitOr for Privileges {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

/// A key's salt type (`KRB5_KDB_SALTTYPE_*`, MIT `kdb.h`).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum SaltType {
    /// `normal` (0): the principal's default salt.
    Normal,
    /// `v4` (1): the Kerberos V4 empty salt, always refused.
    V4,
    /// `norealm` (2).
    NoRealm,
    /// `onlyrealm` (3).
    OnlyRealm,
    /// `special` (4).
    Special,
    /// `afs3` (5): the AFS DES salt, always refused.
    Afs3,
    /// Another number.
    Other(i32),
}

impl SaltType {
    /// The number on the wire.
    #[inline]
    #[must_use]
    pub const fn wire(self) -> i32 {
        match self {
            Self::Normal => 0,
            Self::V4 => 1,
            Self::NoRealm => 2,
            Self::OnlyRealm => 3,
            Self::Special => 4,
            Self::Afs3 => 5,
            Self::Other(number) => number,
        }
    }
}

/// A key/salt tuple: the enctype and salt type of a key to make
/// (`krb5_key_salt_tuple`).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub struct KeySaltTuple {
    /// The enctype.
    enctype: i32,
    /// The salt type.
    salt: SaltType,
}

impl KeySaltTuple {
    /// The tuple of `enctype` and `salt`.
    #[inline]
    #[must_use]
    pub const fn new(enctype: i32, salt: SaltType) -> Self {
        Self { enctype, salt }
    }

    /// The enctype.
    #[inline]
    #[must_use]
    pub const fn enctype(&self) -> i32 {
        self.enctype
    }

    /// The salt type.
    #[inline]
    #[must_use]
    pub const fn salt_type(&self) -> SaltType {
        self.salt
    }
}

/// The key options of a password change, a key randomization or a key set.
///
/// They say whether to keep the old keys and which key/salt tuples to make
/// (none: kadmind's).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct KeyOptions {
    /// Keep the old keys.
    keep_old: bool,
    /// The tuples.
    keysalts: Vec<KeySaltTuple>,
}

impl KeyOptions {
    /// Replace the old keys; kadmind's key/salt tuples.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            keep_old: false,
            keysalts: Vec::new(),
        }
    }

    /// Keep the old keys beside the new ones.
    #[inline]
    #[must_use]
    pub const fn keep_old(mut self, keep: bool) -> Self {
        self.keep_old = keep;
        self
    }

    /// Make keys of `keysalts`.
    #[inline]
    #[must_use]
    pub fn with_keysalts(mut self, keysalts: Vec<KeySaltTuple>) -> Self {
        self.keysalts = keysalts;
        self
    }

    /// Whether the old keys are kept.
    #[inline]
    #[must_use]
    pub const fn keeps_old(&self) -> bool {
        self.keep_old
    }

    /// The tuples.
    #[inline]
    #[must_use]
    pub fn keysalts(&self) -> &[KeySaltTuple] {
        &self.keysalts
    }

    /// Whether the options need the `*3` procedures.
    const fn is_extended(&self) -> bool {
        self.keep_old || !self.keysalts.is_empty()
    }
}

/// A key with its version and salt (`kadm5_key_data`).
///
/// [`RemoteAdminClient::set_key_data`] sends these and
/// [`RemoteAdminClient::get_principal_keys`] returns them.
///
/// The key and salt are erased when dropped and never shown by `Debug`.
#[derive(Clone)]
#[non_exhaustive]
pub struct KeyData {
    /// The key version.
    kvno: u32,
    /// The key.
    key: EncryptionKey,
    /// The salt type.
    salt_type: i16,
    /// The salt.
    salt: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for KeyData {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyData")
            .field("kvno", &self.kvno)
            .field("key", &self.key)
            .field("salt_type", &self.salt_type)
            .field("salt_len", &self.salt.len())
            .finish()
    }
}

impl KeyData {
    /// Key `key` at version `kvno`, with the normal salt.
    #[inline]
    #[must_use]
    pub fn new(kvno: u32, key: EncryptionKey) -> Self {
        Self {
            kvno,
            key,
            salt_type: 0,
            salt: Zeroizing::new(Vec::new()),
        }
    }

    /// The salt of type `salt_type` with the bytes `salt`.
    #[inline]
    #[must_use]
    pub fn with_salt(mut self, salt_type: i16, salt: Vec<u8>) -> Self {
        self.salt_type = salt_type;
        self.salt = Zeroizing::new(salt);
        self
    }

    /// The key version.
    #[inline]
    #[must_use]
    pub const fn kvno(&self) -> u32 {
        self.kvno
    }

    /// The key.
    #[inline]
    #[must_use]
    pub const fn key(&self) -> &EncryptionKey {
        &self.key
    }

    /// The salt type.
    #[inline]
    #[must_use]
    pub const fn salt_type(&self) -> i16 {
        self.salt_type
    }

    /// The salt bytes.
    #[inline]
    #[must_use]
    pub fn salt(&self) -> &[u8] {
        &self.salt
    }
}

/// A principal's string attribute (`krb5_string_attr`).
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct StringAttribute {
    /// The key.
    key: String,
    /// The value.
    value: String,
}

impl StringAttribute {
    /// The key.
    #[inline]
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// The value.
    #[inline]
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

/// A tagged data entry of a record (`krb5_tl_data`).
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct TlData {
    /// The type.
    kind: i16,
    /// The contents.
    contents: Vec<u8>,
}

impl TlData {
    /// An entry of type `kind` holding `contents`.
    #[inline]
    #[must_use]
    pub const fn new(kind: i16, contents: Vec<u8>) -> Self {
        Self { kind, contents }
    }

    /// The type.
    #[inline]
    #[must_use]
    pub const fn kind(&self) -> i16 {
        self.kind
    }

    /// The contents.
    #[inline]
    #[must_use]
    pub fn contents(&self) -> &[u8] {
        &self.contents
    }
}

/// What a principal record says about one of its keys: never the key itself
/// (`xdr_krb5_key_data_nocontents`, `kadm_rpc_xdr.c`).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub struct KeyInfo {
    /// The key-data version: 1 without, 2 with a salt type.
    version: i16,
    /// The key version.
    kvno: u16,
    /// The enctype.
    enctype: i16,
    /// The salt type.
    salt_type: i16,
}

impl KeyInfo {
    /// The key-data version.
    #[inline]
    #[must_use]
    pub const fn version(self) -> i16 {
        self.version
    }

    /// The key version.
    #[inline]
    #[must_use]
    pub const fn kvno(self) -> u16 {
        self.kvno
    }

    /// The enctype.
    #[inline]
    #[must_use]
    pub const fn enctype(self) -> i16 {
        self.enctype
    }

    /// The salt type.
    #[inline]
    #[must_use]
    pub const fn salt_type(self) -> i16 {
        self.salt_type
    }
}

/// How a [`RemoteAdminClient`] connects and calls.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Options {
    /// The realm administered.
    realm: String,
    /// The `RPCSEC_GSS` service.
    protection: Protection,
    /// The newest API version offered.
    api_version: ApiVersion,
    /// How long a connection attempt or a call may take.
    timeout: Duration,
    /// The policy key/salt tuples and keys pass.
    crypto_policy: CryptoPolicy,
    /// The GSS initiator options; the flags are always MIT's.
    initiator: InitiatorOptions,
}

impl Options {
    /// Administer `realm` with the defaults.
    ///
    /// They are privacy, API v4 first, MIT's one-hour call timeout
    /// (`client_init.c` `CLSET_TIMEOUT`) and the secure default encryption
    /// policy.
    #[inline]
    #[must_use]
    pub fn new(realm: &str) -> Self {
        Self {
            realm: realm.to_owned(),
            protection: Protection::Privacy,
            api_version: ApiVersion::V4,
            timeout: Duration::from_hours(1),
            crypto_policy: CryptoPolicy::default(),
            initiator: InitiatorOptions::new(),
        }
    }

    /// The defaults with `config`'s encryption policy and GSS initiator relations.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Client`] when the configured policy is invalid.
    #[inline]
    pub fn from_config(config: &Config, realm: &str) -> Result<Self, Error> {
        let policy = CryptoPolicy::from_libdefaults(&config.libdefaults)
            .map_err(|error| Error::Client(ClientError::from(error)))?;
        Ok(Self::new(realm)
            .with_crypto_policy(policy)
            .with_initiator_options(InitiatorOptions::from_config(config)))
    }

    /// Use `protection`.
    #[inline]
    #[must_use]
    pub const fn with_protection(mut self, protection: Protection) -> Self {
        self.protection = protection;
        self
    }

    /// Offer `version` first.
    #[inline]
    #[must_use]
    pub const fn with_api_version(mut self, version: ApiVersion) -> Self {
        self.api_version = version;
        self
    }

    /// Bound each connection attempt and each call by `timeout`.
    #[inline]
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Check key/salt tuples and keys against `policy`.
    #[inline]
    #[must_use]
    pub fn with_crypto_policy(mut self, policy: CryptoPolicy) -> Self {
        self.crypto_policy = policy;
        self
    }

    /// Use `options` for the GSS initiator (channel bindings, the enctype
    /// policy of the context); its flags are replaced by MIT's.
    #[inline]
    #[must_use]
    pub fn with_initiator_options(mut self, options: InitiatorOptions) -> Self {
        self.initiator = options;
        self
    }

    /// The realm.
    #[inline]
    #[must_use]
    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// The `RPCSEC_GSS` service.
    #[inline]
    #[must_use]
    pub const fn protection(&self) -> Protection {
        self.protection
    }

    /// The timeout of a connection attempt or a call.
    #[inline]
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }
}

/// The administration server of a realm.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct AdminServer {
    /// The host name or address.
    host: String,
    /// The port.
    port: u16,
}

impl AdminServer {
    /// The host name or address.
    #[inline]
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port.
    #[inline]
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }
}

/// The administration server of `realm`.
///
/// It is the first `[realms] <realm> admin_server` value, `host`, `host:port`
/// or `[address]:port`, port 749 when it names none (MIT
/// `kadm5_get_config_params`, `alt_prof.c` `parse_admin_server_port`). No DNS
/// lookup is made: MIT's kadm5 client makes none.
///
/// # Errors
///
/// Returns [`Error::NoAdminServer`] without a value and
/// [`Error::BadAdminServer`] for a value with an empty host, an unclosed
/// bracket or a port that is not a number from 1 to 65535 (MIT's `atoi` would
/// take 0).
#[inline]
pub fn admin_server(config: &Config, realm: &str) -> Result<AdminServer, Error> {
    connect::admin_server(config, realm)
}

/// The admin service principal of `realm`, `kadmin/admin@<realm>`.
#[inline]
#[must_use]
pub fn service_principal(realm: &str) -> Principal {
    Principal::new(realm, 1, ADMIN_SERVICE)
}

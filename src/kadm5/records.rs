/// A principal's database record (`kadm5_principal_ent_rec`, `admin.h:190-213`).
///
/// [`RemoteAdminClient::get_principal`] returns one; for
/// [`RemoteAdminClient::create_principal`] and
/// [`RemoteAdminClient::modify_principal`] the `with_*` setters mark the
/// fields they set in the record's mask, and the call adds or removes
/// `KADM5_PRINCIPAL` as kadmind requires (`svr_principal.c:313,569`). Key data
/// carries no key bytes: kadmind never sends them here.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct PrincipalRecord {
    /// The principal.
    principal: Principal,
    /// When the principal expires.
    princ_expire_time: i32,
    /// When the password last changed.
    last_pwd_change: i32,
    /// When the password expires.
    pw_expiration: i32,
    /// The maximum ticket life.
    max_life: i32,
    /// Who last modified the record.
    mod_name: Option<Principal>,
    /// When the record was last modified.
    mod_date: i32,
    /// The `KRB5_KDB_*` attributes.
    attributes: i32,
    /// The current key version.
    kvno: u32,
    /// The master key version.
    mkvno: u32,
    /// The policy.
    policy: Option<String>,
    /// The `KADM5_POLICY` auxiliary attributes.
    aux_attributes: i32,
    /// The maximum renewable life.
    max_renewable_life: i32,
    /// The last successful authentication.
    last_success: i32,
    /// The last failed authentication.
    last_failed: i32,
    /// The failed authentication count.
    fail_auth_count: u32,
    /// What the record says about its keys.
    key_data: Vec<KeyInfo>,
    /// The tagged data.
    tl_data: Vec<TlData>,
    /// The fields set or returned.
    mask: PrincipalMask,
}

impl PrincipalRecord {
    /// A record of `principal` with no other field set.
    #[inline]
    #[must_use]
    pub const fn new(principal: Principal) -> Self {
        Self {
            principal,
            princ_expire_time: 0,
            last_pwd_change: 0,
            pw_expiration: 0,
            max_life: 0,
            mod_name: None,
            mod_date: 0,
            attributes: 0,
            kvno: 0,
            mkvno: 0,
            policy: None,
            aux_attributes: 0,
            max_renewable_life: 0,
            last_success: 0,
            last_failed: 0,
            fail_auth_count: 0,
            key_data: Vec::new(),
            tl_data: Vec::new(),
            mask: PrincipalMask(0),
        }
    }

    /// Set the expiry of the principal (seconds since the epoch, 0 for never).
    #[inline]
    #[must_use]
    pub const fn with_princ_expire_time(mut self, time: i32) -> Self {
        self.princ_expire_time = time;
        self.mask = PrincipalMask(self.mask.0 | PrincipalMask::PRINC_EXPIRE_TIME.0);
        self
    }

    /// Set the password expiry.
    #[inline]
    #[must_use]
    pub const fn with_pw_expiration(mut self, time: i32) -> Self {
        self.pw_expiration = time;
        self.mask = PrincipalMask(self.mask.0 | PrincipalMask::PW_EXPIRATION.0);
        self
    }

    /// Set the maximum ticket life in seconds.
    #[inline]
    #[must_use]
    pub const fn with_max_life(mut self, seconds: i32) -> Self {
        self.max_life = seconds;
        self.mask = PrincipalMask(self.mask.0 | PrincipalMask::MAX_LIFE.0);
        self
    }

    /// Set the maximum renewable life in seconds.
    #[inline]
    #[must_use]
    pub const fn with_max_renewable_life(mut self, seconds: i32) -> Self {
        self.max_renewable_life = seconds;
        self.mask = PrincipalMask(self.mask.0 | PrincipalMask::MAX_RLIFE.0);
        self
    }

    /// Set the `KRB5_KDB_*` attributes.
    #[inline]
    #[must_use]
    pub const fn with_attributes(mut self, attributes: i32) -> Self {
        self.attributes = attributes;
        self.mask = PrincipalMask(self.mask.0 | PrincipalMask::ATTRIBUTES.0);
        self
    }

    /// Set the key version.
    #[inline]
    #[must_use]
    pub const fn with_kvno(mut self, kvno: u32) -> Self {
        self.kvno = kvno;
        self.mask = PrincipalMask(self.mask.0 | PrincipalMask::KVNO.0);
        self
    }

    /// Set the policy.
    #[inline]
    #[must_use]
    pub fn with_policy(mut self, policy: &str) -> Self {
        self.policy = Some(policy.to_owned());
        self.mask = self.mask | PrincipalMask::POLICY;
        self
    }

    /// Remove the policy (`KADM5_POLICY_CLR`).
    #[inline]
    #[must_use]
    pub fn clear_policy(mut self) -> Self {
        self.policy = None;
        self.mask = self.mask | PrincipalMask::POLICY_CLR;
        self
    }

    /// Set the failed authentication count (kadmind accepts only 0).
    #[inline]
    #[must_use]
    pub const fn with_fail_auth_count(mut self, count: u32) -> Self {
        self.fail_auth_count = count;
        self.mask = PrincipalMask(self.mask.0 | PrincipalMask::FAIL_AUTH_COUNT.0);
        self
    }

    /// Set the tagged data.
    #[inline]
    #[must_use]
    pub fn with_tl_data(mut self, entries: Vec<TlData>) -> Self {
        self.tl_data = entries;
        self.mask = self.mask | PrincipalMask::TL_DATA;
        self
    }

    /// The principal.
    #[inline]
    #[must_use]
    pub const fn principal(&self) -> &Principal {
        &self.principal
    }

    /// When the principal expires (seconds since the epoch, 0 for never).
    #[inline]
    #[must_use]
    pub const fn princ_expire_time(&self) -> i32 {
        self.princ_expire_time
    }

    /// When the password last changed.
    #[inline]
    #[must_use]
    pub const fn last_pwd_change(&self) -> i32 {
        self.last_pwd_change
    }

    /// When the password expires.
    #[inline]
    #[must_use]
    pub const fn pw_expiration(&self) -> i32 {
        self.pw_expiration
    }

    /// The maximum ticket life in seconds.
    #[inline]
    #[must_use]
    pub const fn max_life(&self) -> i32 {
        self.max_life
    }

    /// Who last modified the record.
    #[inline]
    #[must_use]
    pub const fn mod_name(&self) -> Option<&Principal> {
        self.mod_name.as_ref()
    }

    /// When the record was last modified.
    #[inline]
    #[must_use]
    pub const fn mod_date(&self) -> i32 {
        self.mod_date
    }

    /// The `KRB5_KDB_*` attributes.
    #[inline]
    #[must_use]
    pub const fn attributes(&self) -> i32 {
        self.attributes
    }

    /// The current key version.
    #[inline]
    #[must_use]
    pub const fn kvno(&self) -> u32 {
        self.kvno
    }

    /// The master key version.
    #[inline]
    #[must_use]
    pub const fn mkvno(&self) -> u32 {
        self.mkvno
    }

    /// The policy.
    #[inline]
    #[must_use]
    pub fn policy(&self) -> Option<&str> {
        self.policy.as_deref()
    }

    /// The auxiliary attributes (`KADM5_POLICY` 0x800 when a policy applies).
    #[inline]
    #[must_use]
    pub const fn aux_attributes(&self) -> i32 {
        self.aux_attributes
    }

    /// The maximum renewable life in seconds.
    #[inline]
    #[must_use]
    pub const fn max_renewable_life(&self) -> i32 {
        self.max_renewable_life
    }

    /// The last successful authentication.
    #[inline]
    #[must_use]
    pub const fn last_success(&self) -> i32 {
        self.last_success
    }

    /// The last failed authentication.
    #[inline]
    #[must_use]
    pub const fn last_failed(&self) -> i32 {
        self.last_failed
    }

    /// The failed authentication count.
    #[inline]
    #[must_use]
    pub const fn fail_auth_count(&self) -> u32 {
        self.fail_auth_count
    }

    /// What the record says about its keys.
    #[inline]
    #[must_use]
    pub fn key_data(&self) -> &[KeyInfo] {
        &self.key_data
    }

    /// The tagged data.
    #[inline]
    #[must_use]
    pub fn tl_data(&self) -> &[TlData] {
        &self.tl_data
    }

    /// The fields set (for a create or modify) or asked for (from a get).
    #[inline]
    #[must_use]
    pub const fn mask(&self) -> PrincipalMask {
        self.mask
    }
}

/// A password policy (`kadm5_policy_ent_rec`, `admin.h:215-236`).
///
/// The `with_*` setters mark the fields they set; a create adds
/// `KADM5_POLICY` and a modify removes it, as kadmind requires
/// (`svr_policy.c:74,269`). Under API v2 the v3 and v4 fields are neither
/// sent nor received, under v3 the v4 fields (`kadm_rpc_xdr.c`
/// `_xdr_kadm5_policy_ent_rec`).
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct PolicyRecord {
    /// The policy name.
    name: String,
    /// The minimum password life.
    pw_min_life: i32,
    /// The maximum password life.
    pw_max_life: i32,
    /// The minimum password length.
    pw_min_length: i32,
    /// The minimum number of character classes.
    pw_min_classes: i32,
    /// The number of old passwords kept.
    pw_history_num: i32,
    /// The reference count, no longer used.
    policy_refcnt: i32,
    /// Failures before lockout (v3).
    pw_max_fail: u32,
    /// The failure count interval (v3).
    pw_failcnt_interval: i32,
    /// The lockout duration (v3).
    pw_lockout_duration: i32,
    /// The attributes (v4).
    attributes: i32,
    /// The maximum ticket life (v4).
    max_life: i32,
    /// The maximum renewable life (v4).
    max_renewable_life: i32,
    /// The allowed key/salt tuples (v4).
    allowed_keysalts: Option<String>,
    /// The tagged data (v4).
    tl_data: Vec<TlData>,
    /// The fields set.
    mask: PolicyMask,
}

impl PolicyRecord {
    /// A policy named `name` with no field set.
    #[inline]
    #[must_use]
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            pw_min_life: 0,
            pw_max_life: 0,
            pw_min_length: 0,
            pw_min_classes: 0,
            pw_history_num: 0,
            policy_refcnt: 0,
            pw_max_fail: 0,
            pw_failcnt_interval: 0,
            pw_lockout_duration: 0,
            attributes: 0,
            max_life: 0,
            max_renewable_life: 0,
            allowed_keysalts: None,
            tl_data: Vec::new(),
            mask: PolicyMask(0),
        }
    }

    /// Set the minimum password life in seconds.
    #[inline]
    #[must_use]
    pub const fn with_pw_min_life(mut self, value: i32) -> Self {
        self.pw_min_life = value;
        self.mask = PolicyMask(self.mask.0 | PolicyMask::PW_MIN_LIFE.0);
        self
    }

    /// The minimum password life in seconds.
    #[inline]
    #[must_use]
    pub const fn pw_min_life(&self) -> i32 {
        self.pw_min_life
    }

    /// Set the maximum password life in seconds.
    #[inline]
    #[must_use]
    pub const fn with_pw_max_life(mut self, value: i32) -> Self {
        self.pw_max_life = value;
        self.mask = PolicyMask(self.mask.0 | PolicyMask::PW_MAX_LIFE.0);
        self
    }

    /// The maximum password life in seconds.
    #[inline]
    #[must_use]
    pub const fn pw_max_life(&self) -> i32 {
        self.pw_max_life
    }

    /// Set the minimum password length.
    #[inline]
    #[must_use]
    pub const fn with_pw_min_length(mut self, value: i32) -> Self {
        self.pw_min_length = value;
        self.mask = PolicyMask(self.mask.0 | PolicyMask::PW_MIN_LENGTH.0);
        self
    }

    /// The minimum password length.
    #[inline]
    #[must_use]
    pub const fn pw_min_length(&self) -> i32 {
        self.pw_min_length
    }

    /// Set the minimum number of character classes.
    #[inline]
    #[must_use]
    pub const fn with_pw_min_classes(mut self, value: i32) -> Self {
        self.pw_min_classes = value;
        self.mask = PolicyMask(self.mask.0 | PolicyMask::PW_MIN_CLASSES.0);
        self
    }

    /// The minimum number of character classes.
    #[inline]
    #[must_use]
    pub const fn pw_min_classes(&self) -> i32 {
        self.pw_min_classes
    }

    /// Set the number of old passwords kept.
    #[inline]
    #[must_use]
    pub const fn with_pw_history_num(mut self, value: i32) -> Self {
        self.pw_history_num = value;
        self.mask = PolicyMask(self.mask.0 | PolicyMask::PW_HISTORY_NUM.0);
        self
    }

    /// The number of old passwords kept.
    #[inline]
    #[must_use]
    pub const fn pw_history_num(&self) -> i32 {
        self.pw_history_num
    }

    /// Set the failures before lockout (v3).
    #[inline]
    #[must_use]
    pub const fn with_pw_max_fail(mut self, value: u32) -> Self {
        self.pw_max_fail = value;
        self.mask = PolicyMask(self.mask.0 | PolicyMask::PW_MAX_FAILURE.0);
        self
    }

    /// The failures before lockout (v3).
    #[inline]
    #[must_use]
    pub const fn pw_max_fail(&self) -> u32 {
        self.pw_max_fail
    }

    /// Set the failure count interval in seconds (v3).
    #[inline]
    #[must_use]
    pub const fn with_pw_failcnt_interval(mut self, value: i32) -> Self {
        self.pw_failcnt_interval = value;
        self.mask = PolicyMask(self.mask.0 | PolicyMask::PW_FAILURE_COUNT_INTERVAL.0);
        self
    }

    /// The failure count interval in seconds (v3).
    #[inline]
    #[must_use]
    pub const fn pw_failcnt_interval(&self) -> i32 {
        self.pw_failcnt_interval
    }

    /// Set the lockout duration in seconds (v3).
    #[inline]
    #[must_use]
    pub const fn with_pw_lockout_duration(mut self, value: i32) -> Self {
        self.pw_lockout_duration = value;
        self.mask = PolicyMask(self.mask.0 | PolicyMask::PW_LOCKOUT_DURATION.0);
        self
    }

    /// The lockout duration in seconds (v3).
    #[inline]
    #[must_use]
    pub const fn pw_lockout_duration(&self) -> i32 {
        self.pw_lockout_duration
    }

    /// Set the policy attributes (v4).
    #[inline]
    #[must_use]
    pub const fn with_attributes(mut self, value: i32) -> Self {
        self.attributes = value;
        self.mask = PolicyMask(self.mask.0 | PolicyMask::ATTRIBUTES.0);
        self
    }

    /// The policy attributes (v4).
    #[inline]
    #[must_use]
    pub const fn attributes(&self) -> i32 {
        self.attributes
    }

    /// Set the maximum ticket life in seconds (v4).
    #[inline]
    #[must_use]
    pub const fn with_max_life(mut self, value: i32) -> Self {
        self.max_life = value;
        self.mask = PolicyMask(self.mask.0 | PolicyMask::MAX_LIFE.0);
        self
    }

    /// The maximum ticket life in seconds (v4).
    #[inline]
    #[must_use]
    pub const fn max_life(&self) -> i32 {
        self.max_life
    }

    /// Set the maximum renewable life in seconds (v4).
    #[inline]
    #[must_use]
    pub const fn with_max_renewable_life(mut self, value: i32) -> Self {
        self.max_renewable_life = value;
        self.mask = PolicyMask(self.mask.0 | PolicyMask::MAX_RLIFE.0);
        self
    }

    /// The maximum renewable life in seconds (v4).
    #[inline]
    #[must_use]
    pub const fn max_renewable_life(&self) -> i32 {
        self.max_renewable_life
    }

    /// Set the allowed key/salt tuples, MIT's string form (v4).
    #[inline]
    #[must_use]
    pub fn with_allowed_keysalts(mut self, keysalts: &str) -> Self {
        self.allowed_keysalts = Some(keysalts.to_owned());
        self.mask = self.mask | PolicyMask::ALLOWED_KEYSALTS;
        self
    }

    /// Set the tagged data (v4).
    #[inline]
    #[must_use]
    pub fn with_tl_data(mut self, entries: Vec<TlData>) -> Self {
        self.tl_data = entries;
        self.mask = self.mask | PolicyMask::TL_DATA;
        self
    }

    /// The policy name.
    #[inline]
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The reference count kadmind reports (no longer used).
    #[inline]
    #[must_use]
    pub const fn policy_refcnt(&self) -> i32 {
        self.policy_refcnt
    }

    /// The allowed key/salt tuples (v4).
    #[inline]
    #[must_use]
    pub fn allowed_keysalts(&self) -> Option<&str> {
        self.allowed_keysalts.as_deref()
    }

    /// The tagged data (v4).
    #[inline]
    #[must_use]
    pub fn tl_data(&self) -> &[TlData] {
        &self.tl_data
    }

    /// The fields set.
    #[inline]
    #[must_use]
    pub const fn mask(&self) -> PolicyMask {
        self.mask
    }
}

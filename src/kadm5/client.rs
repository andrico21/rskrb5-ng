/// A connection to kadmind with an established `RPCSEC_GSS` context and a
/// negotiated API version.
///
/// Calls are made one at a time. A failure after a call was sent closes the
/// connection; a mutation then reports
/// [`crate::error::Kadm5::OutcomeUnknown`] and is never repeated.
///
/// # Cancel safety
///
/// NOT cancel-safe once a call was sent: dropping its future leaves the
/// outcome unknown and the client refuses every later call with
/// [`crate::error::Kadm5::Interrupted`] before sending anything; make a new
/// client and check the server's state.
#[non_exhaustive]
pub struct RemoteAdminClient<S> {
    /// The connection.
    stream: S,
    /// The `RPCSEC_GSS` context.
    rpc: RpcClient,
    /// The negotiated API version.
    version: ApiVersion,
    /// The options.
    options: Options,
    /// The procedure of a call that did not finish.
    interrupted: Option<Procedure>,
}

impl<S> fmt::Debug for RemoteAdminClient<S> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteAdminClient")
            .field("rpc", &self.rpc)
            .field("version", &self.version)
            .field("options", &self.options)
            .field("interrupted", &self.interrupted)
            .finish_non_exhaustive()
    }
}

/// Refuse key/salt tuples the policy or D2 refuses.
///
/// # Errors
///
/// Returns the policy errors of the check, or the call errors.
fn check_keysalts(policy: &CryptoPolicy, tuples: &[KeySaltTuple]) -> Result<(), Error> {
    for tuple in tuples {
        check_salt(tuple.salt.wire())?;
        policy.check_use(tuple.enctype, Use::CheckedLowLevel)?;
    }
    Ok(())
}

/// Refuse the Kerberos V4 (1) and AFS3 (5) salts: Kerberos V4 legacy, DES only.
///
/// # Errors
///
/// Returns the policy errors of the check, or the call errors.
const fn check_salt(salt: i32) -> Result<(), Error> {
    if salt == SaltType::V4.wire() || salt == SaltType::Afs3.wire() {
        return Err(Error::Policy(PolicyError::RejectedFeature {
            feature: RejectedFeature::KerberosV4,
            reason: RejectionReason::RemovedAndInsecure,
        }));
    }
    Ok(())
}

/// Refuse keys of enctypes the policy refuses.
///
/// # Errors
///
/// Returns the policy errors of the check, or the call errors.
fn check_keys<'key, I>(policy: &CryptoPolicy, keys: I) -> Result<(), Error>
where
    I: IntoIterator<Item = &'key EncryptionKey>,
{
    for key in keys {
        policy.check_use(key.etype(), Use::CheckedLowLevel)?;
    }
    Ok(())
}

/// The password bytes of `password`, if any.
fn password_bytes(password: Option<&Password>) -> Option<&[u8]> {
    password.map(Password::as_bytes)
}

impl RemoteAdminClient<TcpStream> {
    /// Connect to the admin server of the options' realm.
    ///
    /// The server is the one `config` names (`[realms] <realm> admin_server`,
    /// see [`admin_server`]); then the `RPCSEC_GSS` context for
    /// `kadmin/admin@<realm>` is created with `credential` and the API version
    /// negotiated.
    ///
    /// `credential` must hold a live service ticket for `kadmin/admin@<realm>`
    /// (`Credential::from_service_ticket` of an AS or TGS exchange, or a
    /// credential cache that holds one); MIT's `kadm5_init_with_password`
    /// gets it by an AS exchange for that service.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`admin_server`], [`Error::Connect`] when no
    /// address accepts a connection within the timeout, and the errors of
    /// [`Self::over_stream`].
    ///
    /// # Cancel safety
    ///
    /// Cancel-safe: nothing on the server changes before the client exists.
    #[inline]
    pub async fn connect(
        config: &Config,
        credential: &Credential,
        options: Options,
    ) -> Result<Self, Error> {
        let server = connect::admin_server(config, &options.realm)?;
        let stream = connect::tcp(&server, &options).await?;
        connect::over_stream(stream, credential, options).await
    }
}

impl<S> RemoteAdminClient<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Create the `RPCSEC_GSS` context on `stream` and negotiate the API version.
    ///
    /// The client offers v4 (or the options' version), then the next older
    /// one while the server answers `KADM5_NEW_SERVER_API_VERSION`.
    ///
    /// # Errors
    ///
    /// Returns the RPC errors of the context creation
    /// ([`crate::error::Rpc::AuthenticationRejected`] for a server that will
    /// not take `RPCSEC_GSS`: the client never falls back to another flavor),
    /// the GSS errors of the context, and [`Error::Server`] when the server
    /// refuses every version.
    ///
    /// # Cancel safety
    ///
    /// Cancel-safe: nothing on the server changes before the client exists.
    #[inline]
    pub async fn over_stream(
        stream: S,
        credential: &Credential,
        options: Options,
    ) -> Result<Self, Error> {
        connect::over_stream(stream, credential, options).await
    }

    /// The negotiated API version.
    #[inline]
    #[must_use]
    pub const fn api_version(&self) -> ApiVersion {
        self.version
    }

    /// `kadm5_get_privs`: the caller's privileges.
    ///
    /// # Errors
    ///
    /// Returns the call errors.
    #[inline]
    pub async fn get_privileges(&mut self) -> Result<Privileges, Error> {
        let arguments = wire::begin(self.version).finish();
        match call::run(self, Procedure::GetPrivileges, &arguments).await? {
            Response::Privileges(privileges) => Ok(privileges),
            Response::Done
            | Response::Principal(_)
            | Response::Policy(_)
            | Response::Names(_)
            | Response::Keys(_)
            | Response::Strings(_)
            | Response::KeyData(_) => Err(Error::Malformed("an unexpected result")),
        }
    }

    /// `kadm5_create_principal`, or `kadm5_create_principal_3` with tuples.
    ///
    /// It creates `record`'s principal with the fields it sets, `password`
    /// (none: random keys when the record's attributes ask for them) and,
    /// when given, keys of `keysalts`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Policy`] for a refused tuple and
    /// [`Error::InvalidArgument`] for a password holding a NUL, before
    /// anything is sent, then the call errors.
    #[inline]
    pub async fn create_principal(
        &mut self,
        record: &PrincipalRecord,
        password: Option<&Password>,
        keysalts: &[KeySaltTuple],
    ) -> Result<(), Error> {
        check_keysalts(&self.options.crypto_policy, keysalts)?;
        let mask = record.mask | PrincipalMask::PRINCIPAL;
        let mut head = wire::principal_record(wire::begin(self.version), record, mask)?;
        let procedure = if keysalts.is_empty() {
            Procedure::CreatePrincipal
        } else {
            head = wire::keysalts(head, keysalts)?;
            Procedure::CreatePrincipal3
        };
        let arguments = wire::text(head, "password", password_bytes(password))?.finish();
        self.done(procedure, &arguments).await
    }

    /// `kadm5_delete_principal`.
    ///
    /// # Errors
    ///
    /// Returns the call errors.
    #[inline]
    pub async fn delete_principal(&mut self, principal: &Principal) -> Result<(), Error> {
        let arguments = wire::principal(wire::begin(self.version), principal)?.finish();
        self.done(Procedure::DeletePrincipal, &arguments).await
    }

    /// `kadm5_modify_principal`: set the fields `record` sets.
    ///
    /// # Errors
    ///
    /// Returns the call errors.
    #[inline]
    pub async fn modify_principal(&mut self, record: &PrincipalRecord) -> Result<(), Error> {
        let mask = record.mask.without(PrincipalMask::PRINCIPAL);
        let arguments = wire::principal_record(wire::begin(self.version), record, mask)?.finish();
        self.done(Procedure::ModifyPrincipal, &arguments).await
    }

    /// `kadm5_rename_principal`.
    ///
    /// # Errors
    ///
    /// Returns the call errors.
    #[inline]
    pub async fn rename_principal(
        &mut self,
        from: &Principal,
        to: &Principal,
    ) -> Result<(), Error> {
        let arguments =
            wire::principal(wire::principal(wire::begin(self.version), from)?, to)?.finish();
        self.done(Procedure::RenamePrincipal, &arguments).await
    }

    /// `kadm5_get_principal`: the record of `principal`, with the fields of `mask`.
    ///
    /// # Errors
    ///
    /// Returns the call errors.
    #[inline]
    pub async fn get_principal(
        &mut self,
        principal: &Principal,
        mask: PrincipalMask,
    ) -> Result<PrincipalRecord, Error> {
        let arguments = wire::principal(wire::begin(self.version), principal)?
            .i32(i32::from_be_bytes(mask.bits().to_be_bytes()))
            .finish();
        match call::run(self, Procedure::GetPrincipal, &arguments).await? {
            Response::Principal(mut record) => {
                record.mask = mask;
                Ok(*record)
            }
            Response::Done
            | Response::Policy(_)
            | Response::Names(_)
            | Response::Keys(_)
            | Response::Privileges(_)
            | Response::Strings(_)
            | Response::KeyData(_) => Err(Error::Malformed("an unexpected result")),
        }
    }

    /// `kadm5_get_principals`: the names matching `expression` (a glob;
    /// none for all).
    ///
    /// # Errors
    ///
    /// Returns the call errors.
    #[inline]
    pub async fn list_principals(
        &mut self,
        expression: Option<&str>,
    ) -> Result<Vec<String>, Error> {
        self.names(Procedure::GetPrincipals, expression).await
    }

    /// `kadm5_chpass_principal` (`kadm5_chpass_principal_3` with options):
    /// set `principal`'s password.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Policy`] for a refused tuple, before anything is
    /// sent, then the call errors.
    #[inline]
    pub async fn change_password(
        &mut self,
        principal: &Principal,
        password: &Password,
        options: &KeyOptions,
    ) -> Result<(), Error> {
        check_keysalts(&self.options.crypto_policy, &options.keysalts)?;
        let mut head = wire::principal(wire::begin(self.version), principal)?;
        let procedure = if options.is_extended() {
            head = wire::keysalts(head.bool(options.keep_old), &options.keysalts)?;
            Procedure::ChangePassword3
        } else {
            Procedure::ChangePassword
        };
        let arguments = wire::text(head, "password", Some(password.as_bytes()))?.finish();
        self.done(procedure, &arguments).await
    }

    /// `kadm5_randkey_principal` (`kadm5_randkey_principal_3` with options):
    /// give `principal` random keys and return them.
    ///
    /// # Security
    ///
    /// The keys are erased when dropped and never shown by `Debug`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Policy`] for a refused tuple, before anything is
    /// sent, then the call errors.
    #[inline]
    pub async fn randomize_keys(
        &mut self,
        principal: &Principal,
        options: &KeyOptions,
    ) -> Result<Vec<EncryptionKey>, Error> {
        check_keysalts(&self.options.crypto_policy, &options.keysalts)?;
        let mut arguments = wire::principal(wire::begin(self.version), principal)?;
        let procedure = if options.is_extended() {
            arguments = wire::keysalts(arguments.bool(options.keep_old), &options.keysalts)?;
            Procedure::RandomizeKeys3
        } else {
            Procedure::RandomizeKeys
        };
        match call::run(self, procedure, &arguments.finish()).await? {
            Response::Keys(keys) => Ok(keys),
            Response::Done
            | Response::Principal(_)
            | Response::Policy(_)
            | Response::Names(_)
            | Response::Privileges(_)
            | Response::Strings(_)
            | Response::KeyData(_) => Err(Error::Malformed("an unexpected result")),
        }
    }

    /// `kadm5_setkey_principal`: set `principal`'s keys to `keys`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] without keys and [`Error::Policy`]
    /// for a refused enctype, before anything is sent, then the call errors.
    #[inline]
    pub async fn set_keys(
        &mut self,
        principal: &Principal,
        keys: &[EncryptionKey],
    ) -> Result<(), Error> {
        if keys.is_empty() {
            return Err(Error::InvalidArgument("no keys to set"));
        }
        check_keys(&self.options.crypto_policy, keys)?;
        let arguments =
            wire::keyblocks(wire::principal(wire::begin(self.version), principal)?, keys)?.finish();
        self.done(Procedure::SetKeys, &arguments).await
    }

    /// `kadm5_setkey_principal_3`: set `principal`'s keys to `keys`, made for
    /// the options' tuples, keeping the old keys if the options say so.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::set_keys`] and [`Error::Policy`] for a
    /// refused tuple.
    #[inline]
    pub async fn set_keys_for_keysalts(
        &mut self,
        principal: &Principal,
        options: &KeyOptions,
        keys: &[EncryptionKey],
    ) -> Result<(), Error> {
        if keys.is_empty() {
            return Err(Error::InvalidArgument("no keys to set"));
        }
        check_keysalts(&self.options.crypto_policy, &options.keysalts)?;
        check_keys(&self.options.crypto_policy, keys)?;
        let head = wire::principal(wire::begin(self.version), principal)?.bool(options.keep_old);
        let arguments =
            wire::keyblocks(wire::keysalts(head, &options.keysalts)?, keys)?.finish();
        self.done(Procedure::SetKeys3, &arguments).await
    }

    /// `kadm5_setkey_principal_4`: set `principal`'s keys to `keys`, each with
    /// its version and salt.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] without keys (MIT `EINVAL`) and
    /// [`Error::Policy`] for a refused enctype or salt, before anything is
    /// sent, then the call errors.
    #[inline]
    pub async fn set_key_data(
        &mut self,
        principal: &Principal,
        keep_old: bool,
        keys: &[KeyData],
    ) -> Result<(), Error> {
        if keys.is_empty() {
            return Err(Error::InvalidArgument("no key data to set"));
        }
        for entry in keys {
            check_salt(i32::from(entry.salt_type))?;
        }
        check_keys(&self.options.crypto_policy, keys.iter().map(KeyData::key))?;
        let head = wire::principal(wire::begin(self.version), principal)?.bool(keep_old);
        let arguments = wire::key_data(head, keys)?.finish();
        self.done(Procedure::SetKeys4, &arguments).await
    }

    /// `kadm5_purgekeys`: remove `principal`'s keys older than `keep_kvno`.
    ///
    /// # Errors
    ///
    /// Returns the call errors.
    #[inline]
    pub async fn purge_keys(&mut self, principal: &Principal, keep_kvno: i32) -> Result<(), Error> {
        let arguments = wire::principal(wire::begin(self.version), principal)?
            .i32(keep_kvno)
            .finish();
        self.done(Procedure::PurgeKeys, &arguments).await
    }

    /// `kadm5_get_strings`: `principal`'s string attributes.
    ///
    /// # Errors
    ///
    /// Returns the call errors.
    #[inline]
    pub async fn get_strings(
        &mut self,
        principal: &Principal,
    ) -> Result<Vec<StringAttribute>, Error> {
        let arguments = wire::principal(wire::begin(self.version), principal)?.finish();
        match call::run(self, Procedure::GetStrings, &arguments).await? {
            Response::Strings(strings) => Ok(strings),
            Response::Done
            | Response::Principal(_)
            | Response::Policy(_)
            | Response::Names(_)
            | Response::Keys(_)
            | Response::Privileges(_)
            | Response::KeyData(_) => Err(Error::Malformed("an unexpected result")),
        }
    }

    /// `kadm5_set_string`: set `principal`'s attribute `key` to `value`, or
    /// remove it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] for a key or value holding a NUL,
    /// before anything is sent, then the call errors.
    #[inline]
    pub async fn set_string(
        &mut self,
        principal: &Principal,
        key: &str,
        value: Option<&str>,
    ) -> Result<(), Error> {
        let head = wire::text(
            wire::principal(wire::begin(self.version), principal)?,
            "attribute key",
            Some(key.as_bytes()),
        )?;
        let arguments = wire::text(head, "attribute value", value.map(str::as_bytes))?.finish();
        self.done(Procedure::SetString, &arguments).await
    }

    /// `kadm5_get_principal_keys`: `principal`'s keys of version `kvno` (0
    /// for all), which needs kadmind's `extract-keys` privilege.
    ///
    /// # Security
    ///
    /// The keys are erased when dropped and never shown by `Debug`.
    ///
    /// # Errors
    ///
    /// Returns the call errors.
    #[inline]
    pub async fn get_principal_keys(
        &mut self,
        principal: &Principal,
        kvno: u32,
    ) -> Result<Vec<KeyData>, Error> {
        let arguments = wire::principal(wire::begin(self.version), principal)?
            .u32(kvno)
            .finish();
        match call::run(self, Procedure::ExtractKeys, &arguments).await? {
            Response::KeyData(keys) => Ok(keys),
            Response::Done
            | Response::Principal(_)
            | Response::Policy(_)
            | Response::Names(_)
            | Response::Keys(_)
            | Response::Privileges(_)
            | Response::Strings(_) => Err(Error::Malformed("an unexpected result")),
        }
    }

    /// `kadm5_create_alias`: make `alias` name `target`.
    ///
    /// # Errors
    ///
    /// Returns the call errors.
    #[inline]
    pub async fn create_alias(
        &mut self,
        alias: &Principal,
        target: &Principal,
    ) -> Result<(), Error> {
        let arguments =
            wire::principal(wire::principal(wire::begin(self.version), alias)?, target)?.finish();
        self.done(Procedure::CreateAlias, &arguments).await
    }

    /// `kadm5_create_policy`: create `policy` with the fields it sets.
    ///
    /// # Errors
    ///
    /// Returns the call errors.
    #[inline]
    pub async fn create_policy(&mut self, policy: &PolicyRecord) -> Result<(), Error> {
        let mask = (policy.mask | PolicyMask::POLICY).bits();
        let arguments =
            wire::policy_record(wire::begin(self.version), policy, self.version, mask)?.finish();
        self.done(Procedure::CreatePolicy, &arguments).await
    }

    /// `kadm5_delete_policy`.
    ///
    /// # Errors
    ///
    /// Returns the call errors.
    #[inline]
    pub async fn delete_policy(&mut self, name: &str) -> Result<(), Error> {
        let arguments =
            wire::text(wire::begin(self.version), "policy", Some(name.as_bytes()))?.finish();
        self.done(Procedure::DeletePolicy, &arguments).await
    }

    /// `kadm5_modify_policy`: set the fields `policy` sets.
    ///
    /// # Errors
    ///
    /// Returns the call errors.
    #[inline]
    pub async fn modify_policy(&mut self, policy: &PolicyRecord) -> Result<(), Error> {
        let mask = policy.mask.without(PolicyMask::POLICY).bits();
        let arguments =
            wire::policy_record(wire::begin(self.version), policy, self.version, mask)?.finish();
        self.done(Procedure::ModifyPolicy, &arguments).await
    }

    /// `kadm5_get_policy`.
    ///
    /// # Errors
    ///
    /// Returns the call errors.
    #[inline]
    pub async fn get_policy(&mut self, name: &str) -> Result<PolicyRecord, Error> {
        let arguments =
            wire::text(wire::begin(self.version), "policy", Some(name.as_bytes()))?.finish();
        match call::run(self, Procedure::GetPolicy, &arguments).await? {
            Response::Policy(record) => Ok(*record),
            Response::Done
            | Response::Principal(_)
            | Response::Names(_)
            | Response::Keys(_)
            | Response::Privileges(_)
            | Response::Strings(_)
            | Response::KeyData(_) => Err(Error::Malformed("an unexpected result")),
        }
    }

    /// `kadm5_get_policies`: the policy names matching `expression` (none for all).
    ///
    /// # Errors
    ///
    /// Returns the call errors.
    #[inline]
    pub async fn list_policies(&mut self, expression: Option<&str>) -> Result<Vec<String>, Error> {
        self.names(Procedure::GetPolicies, expression).await
    }

    /// Destroy the `RPCSEC_GSS` context (`RPCSEC_GSS_DESTROY`) and close the connection.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Interrupted`] after an unfinished call and the RPC errors.
    #[inline]
    pub async fn destroy(mut self) -> Result<(), Error> {
        call::destroy(&mut self).await
    }

    /// A call answered by `generic_ret`.
    ///
    /// # Errors
    ///
    /// Returns the policy errors of the check, or the call errors.
    async fn done(&mut self, procedure: Procedure, arguments: &[u8]) -> Result<(), Error> {
        match call::run(self, procedure, arguments).await? {
            Response::Done => Ok(()),
            Response::Principal(_)
            | Response::Policy(_)
            | Response::Names(_)
            | Response::Keys(_)
            | Response::Privileges(_)
            | Response::Strings(_)
            | Response::KeyData(_) => Err(Error::Malformed("an unexpected result")),
        }
    }

    /// A call answered by a name list.
    ///
    /// # Errors
    ///
    /// Returns the policy errors of the check, or the call errors.
    async fn names(
        &mut self,
        procedure: Procedure,
        expression: Option<&str>,
    ) -> Result<Vec<String>, Error> {
        let arguments = wire::text(
            wire::begin(self.version),
            "expression",
            expression.map(str::as_bytes),
        )?
        .finish();
        match call::run(self, procedure, &arguments).await? {
            Response::Names(names) => Ok(names),
            Response::Done
            | Response::Principal(_)
            | Response::Policy(_)
            | Response::Keys(_)
            | Response::Privileges(_)
            | Response::Strings(_)
            | Response::KeyData(_) => Err(Error::Malformed("an unexpected result")),
        }
    }
}

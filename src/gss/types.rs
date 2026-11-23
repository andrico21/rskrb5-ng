/// A GSS-API name type the Kerberos mechanism imports (MIT `import_name.c:126-345`).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum NameType {
    /// `GSS_C_NT_HOSTBASED_SERVICE`: `service@host`, or `service` for any host.
    HostbasedService,
    /// `GSS_C_NT_USER_NAME`: a principal string.
    User,
    /// `GSS_C_NT_MACHINE_UID_NAME`: a binary user id of the host's byte order.
    MachineUid,
    /// `GSS_C_NT_STRING_UID_NAME`: a decimal user id.
    StringUid,
    /// `GSS_C_NT_ANONYMOUS`: the anonymous principal.
    Anonymous,
    /// `GSS_C_NT_EXPORT_NAME`: an RFC 2743 section 3.2 exported name.
    Export,
    /// `GSS_C_NT_COMPOSITE_EXPORT`: an RFC 6680 composite exported name.
    CompositeExport,
    /// `GSS_KRB5_NT_PRINCIPAL_NAME`: a Kerberos principal string.
    Principal,
    /// `GSS_KRB5_NT_ENTERPRISE_NAME`: an enterprise principal (RFC 6806).
    Enterprise,
    /// `GSS_KRB5_NT_X509_CERT`: a DER certificate, for `S4U2Self` by certificate.
    X509Cert,
}

impl NameType {
    /// The object identifier of this name type (MIT `gssapi_generic.c:42-122`,
    /// `gssapi_krb5.c:146-156`).
    #[inline]
    #[must_use]
    pub fn oid(self) -> ObjectIdentifier {
        name::oid(self)
    }

    /// The name type of an object identifier; the RFC 2743 host-based OID
    /// (`1.3.6.1.5.6.2`) is the same type as the GSS-API v1 one.
    #[inline]
    #[must_use]
    pub fn from_oid(oid: &ObjectIdentifier) -> Option<Self> {
        name::from_oid(oid)
    }
}

/// How a [`Name`] names its principal.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum NameKind {
    /// A principal (user, service, enterprise or anonymous).
    Principal,
    /// A host-based service; the host may be empty (any host).
    Hostbased,
    /// A certificate, with no principal of its own.
    Certificate(Vec<u8>),
}

/// A Kerberos mechanism name (MIT `krb5_gss_name_t`).
///
/// A name without a realm names its principal in the realm the client resolves
/// later (host-based names) or in the default realm [`Self::with_default_realm`]
/// supplies; this module never reads the default realm from an ambient profile.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub struct Name {
    /// The principal; the realm may be empty.
    principal: Principal,
    /// The type the name was imported as.
    imported_as: NameType,
    /// Host-based, certificate or plain.
    kind: NameKind,
    /// The unread attribute block of a composite exported name (RFC 6680).
    attributes: Option<Vec<u8>>,
}

impl Name {
    /// Import a name of `name_type` from `bytes`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BadName`] for a malformed name or exported-name token,
    /// [`Error::NameTooLong`] above 4 KiB (64 KiB for a certificate), and
    /// [`Error::BadNameType`] for the user-id types, which need
    /// [`Self::import_uid`].
    #[inline]
    pub fn import(bytes: &[u8], name_type: NameType) -> Result<Self, Error> {
        name::import(bytes, name_type)
    }

    /// Import a [`NameType::MachineUid`] or [`NameType::StringUid`] name, with
    /// `resolve` mapping the user id to the account's principal string.
    ///
    /// MIT reads the password database (`import_name.c:249-262`); this module
    /// asks the caller instead, so it reads no ambient account data.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BadName`] for a malformed id, [`Error::UnresolvedUid`]
    /// when `resolve` knows no account, [`Error::BadNameType`] for another
    /// type, and the errors of [`Self::import`] for the resolved string.
    #[inline]
    pub fn import_uid<F>(bytes: &[u8], name_type: NameType, resolve: F) -> Result<Self, Error>
    where
        F: FnOnce(u32) -> Option<String>,
    {
        name::import_uid(bytes, name_type, resolve)
    }

    /// The name of `principal`, as a Kerberos principal name.
    #[inline]
    #[must_use]
    pub fn from_principal(principal: &Principal) -> Self {
        Self {
            principal: principal.clone(),
            imported_as: NameType::Principal,
            kind: NameKind::Principal,
            attributes: None,
        }
    }

    /// Fill an empty realm with `realm`, except for host-based and certificate
    /// names, whose realm the client resolves.
    #[inline]
    #[must_use]
    pub fn with_default_realm(mut self, realm: &str) -> Self {
        if self.principal.realm.is_empty() && self.kind == NameKind::Principal {
            realm.clone_into(&mut self.principal.realm);
        }
        self
    }

    /// The principal string in MIT's quoting and its display type: anonymous
    /// for the anonymous principal, otherwise the Kerberos principal type
    /// (MIT `disp_name.c:28-78`).
    #[inline]
    #[must_use]
    pub fn display(&self) -> (String, NameType) {
        name::display(self)
    }

    /// The RFC 2743 section 3.2 exported name (MIT `export_name.c:28-88`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::BadName`] for a certificate name, which has no
    /// principal string, and [`Error::NameTooLong`] for a name above 4 KiB.
    #[inline]
    pub fn export(&self) -> Result<Vec<u8>, Error> {
        name::export(self)
    }

    /// Whether both names name the same principal: realm and components, the
    /// name type and the imported form ignored (MIT `compare_name.c`,
    /// `krb5_principal_compare`); certificate names compare their certificates.
    #[inline]
    #[must_use]
    pub fn compare(&self, other: &Self) -> bool {
        self.principal.realm == other.principal.realm
            && self.principal.components == other.principal.components
            && self.certificate() == other.certificate()
    }

    /// `gss_inquire_mechs_for_name`: the mechanisms that take this name: krb5,
    /// or none for a certificate name, which only `S4U2Self` takes.
    #[inline]
    #[must_use]
    pub fn inquire_mechs(&self) -> Vec<ObjectIdentifier> {
        if self.certificate().is_some() {
            Vec::new()
        } else {
            vec![ObjectIdentifier::krb5()]
        }
    }

    /// The mechanism name of this name; MIT duplicates the name (`canon_name.c`).
    #[inline]
    #[must_use]
    pub fn canonicalize(&self) -> Self {
        self.clone()
    }

    /// The principal; its realm may be empty.
    #[inline]
    #[must_use]
    pub const fn principal(&self) -> &Principal {
        &self.principal
    }

    /// The type the name was imported as.
    #[inline]
    #[must_use]
    pub const fn name_type(&self) -> NameType {
        self.imported_as
    }

    /// Whether this is the anonymous principal.
    #[inline]
    #[must_use]
    pub fn is_anonymous(&self) -> bool {
        name::is_anonymous(&self.principal)
    }

    /// Whether this is a host-based service name.
    #[inline]
    #[must_use]
    pub fn is_hostbased(&self) -> bool {
        self.kind == NameKind::Hostbased
    }

    /// The certificate of a [`NameType::X509Cert`] name.
    #[inline]
    #[must_use]
    pub fn certificate(&self) -> Option<&[u8]> {
        match &self.kind {
            NameKind::Certificate(bytes) => Some(bytes),
            NameKind::Principal | NameKind::Hostbased => None,
        }
    }

    /// The unread attribute block of a composite exported name (RFC 6680).
    #[inline]
    #[must_use]
    pub fn composite_attributes(&self) -> Option<&[u8]> {
        self.attributes.as_deref()
    }
}

/// GSS-API context flags (RFC 2744 section 5.19 and MIT's extensions in
/// `gssapi.hin:137-146` and `gssapi_ext.h:229-231,605`).
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct ContextFlags(u32);

impl ContextFlags {
    /// `GSS_C_DELEG_FLAG`: credentials are delegated.
    pub const DELEG: Self = Self(1);
    /// `GSS_C_MUTUAL_FLAG`: the acceptor authenticates itself.
    pub const MUTUAL: Self = Self(2);
    /// `GSS_C_REPLAY_FLAG`: replayed per-message tokens are detected.
    pub const REPLAY: Self = Self(4);
    /// `GSS_C_SEQUENCE_FLAG`: out-of-sequence per-message tokens are detected.
    pub const SEQUENCE: Self = Self(8);
    /// `GSS_C_CONF_FLAG`: confidentiality is available.
    pub const CONF: Self = Self(0x10);
    /// `GSS_C_INTEG_FLAG`: integrity is available.
    pub const INTEG: Self = Self(0x20);
    /// `GSS_C_ANON_FLAG`: the initiator is anonymous.
    pub const ANON: Self = Self(0x40);
    /// `GSS_C_PROT_READY_FLAG`: protection is available.
    pub const PROT_READY: Self = Self(0x80);
    /// `GSS_C_TRANS_FLAG`: the context can be exported.
    pub const TRANS: Self = Self(0x100);
    /// `GSS_C_CHANNEL_BOUND_FLAG`: on the acceptor, matching channel bindings
    /// were present; on the initiator, a request for strict channel binding
    /// (MS-KILE `KERB_AP_OPTIONS_CBT`).
    pub const CHANNEL_BOUND: Self = Self(0x800);
    /// `GSS_C_DCE_STYLE`: three-leg DCE-style establishment.
    pub const DCE_STYLE: Self = Self(0x1000);
    /// `GSS_C_IDENTIFY_FLAG`: identification only.
    pub const IDENTIFY: Self = Self(0x2000);
    /// `GSS_C_EXTENDED_ERROR_FLAG`: extended errors.
    pub const EXTENDED_ERROR: Self = Self(0x4000);
    /// `GSS_C_DELEG_POLICY_FLAG`: delegate only to `OK-AS-DELEGATE` services.
    pub const DELEG_POLICY: Self = Self(0x8000);

    /// No flag.
    #[inline]
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// The flags of a bit mask, unknown bits kept.
    #[inline]
    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// The bit mask.
    #[inline]
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Whether every flag of `other` is set.
    #[inline]
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// The flags of either.
    #[inline]
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// The flags of both.
    #[inline]
    #[must_use]
    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// The flags of `self` that are not in `other`.
    #[inline]
    #[must_use]
    pub const fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }
}

impl BitOr for ContextFlags {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

/// RFC 2744 channel bindings: two addresses and application data, hashed into
/// the authenticator checksum as RFC 4121 section 4.1.1.2 lays them out.
///
/// The caller supplies the channel's value, for example a TLS exporter output
/// or a server certificate hash; this module never reads it from a socket.
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub struct ChannelBindings {
    /// The initiator's address type (`GSS_C_AF_*`).
    initiator_address_type: u32,
    /// The initiator's address, at most 255 bytes.
    initiator_address: Vec<u8>,
    /// The acceptor's address type (`GSS_C_AF_*`).
    acceptor_address_type: u32,
    /// The acceptor's address, at most 255 bytes.
    acceptor_address: Vec<u8>,
    /// The application data, at most 64 KiB.
    application_data: Vec<u8>,
}

impl fmt::Debug for ChannelBindings {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChannelBindings")
            .field("initiator_address_type", &self.initiator_address_type)
            .field("acceptor_address_type", &self.acceptor_address_type)
            .field("application_data_len", &self.application_data.len())
            .finish_non_exhaustive()
    }
}

impl ChannelBindings {
    /// Bindings of `application_data` with no addresses (`GSS_C_AF_NULLADDR`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::BindingTooLong`] above 64 KiB.
    #[inline]
    pub fn new(application_data: Vec<u8>) -> Result<Self, Error> {
        bindings::check("application data", &application_data, bindings::MAX_DATA)?;
        Ok(Self {
            initiator_address_type: 0,
            initiator_address: Vec::new(),
            acceptor_address_type: 0,
            acceptor_address: Vec::new(),
            application_data,
        })
    }

    /// RFC 5929 `tls-server-end-point` bindings of a server certificate hash.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BindingTooLong`] above 64 KiB.
    #[inline]
    pub fn tls_server_end_point(certificate_hash: &[u8]) -> Result<Self, Error> {
        Self::new([&b"tls-server-end-point:"[..], certificate_hash].concat())
    }

    /// RFC 9266 `tls-exporter` bindings of a TLS 1.3 exporter output.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BindingTooLong`] above 64 KiB.
    #[inline]
    pub fn tls_exporter(exporter_output: &[u8]) -> Result<Self, Error> {
        Self::new([&b"tls-exporter:"[..], exporter_output].concat())
    }

    /// Set the initiator's address.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BindingTooLong`] above 255 bytes.
    #[inline]
    pub fn with_initiator_address(
        mut self,
        address_type: u32,
        address: Vec<u8>,
    ) -> Result<Self, Error> {
        bindings::check("initiator address", &address, bindings::MAX_ADDRESS)?;
        self.initiator_address_type = address_type;
        self.initiator_address = address;
        Ok(self)
    }

    /// Set the acceptor's address.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BindingTooLong`] above 255 bytes.
    #[inline]
    pub fn with_acceptor_address(
        mut self,
        address_type: u32,
        address: Vec<u8>,
    ) -> Result<Self, Error> {
        bindings::check("acceptor address", &address, bindings::MAX_ADDRESS)?;
        self.acceptor_address_type = address_type;
        self.acceptor_address = address;
        Ok(self)
    }

    /// The application data.
    #[inline]
    #[must_use]
    pub fn application_data(&self) -> &[u8] {
        &self.application_data
    }

    /// The MD5 digest the authenticator checksum carries (RFC 4121 section
    /// 4.1.1.2; MIT `util_cksum.c:30-76`). The acceptor reads an all-zero digest
    /// as "no bindings", whatever bindings it holds.
    #[inline]
    #[must_use]
    pub fn digest(&self) -> [u8; 16] {
        bindings::digest(self)
    }
}

/// The context key [`EstablishedContext::pseudo_random`] derives from (RFC
/// 4401 section 2; MIT `prf.c:62-75`).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum PrfKey {
    /// `GSS_C_PRF_KEY_FULL`: the acceptor subkey when the acceptor sent one,
    /// else the partial key.
    Full,
    /// `GSS_C_PRF_KEY_PARTIAL`: the initiator subkey, else the ticket session
    /// key.
    Partial,
}

/// The type of an [`IovBuffer`] (`GSS_IOV_BUFFER_TYPE_*`, MIT
/// `gssapi_ext.h:262-270`).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum IovKind {
    /// `GSS_IOV_BUFFER_TYPE_EMPTY`: ignored.
    Empty,
    /// `GSS_IOV_BUFFER_TYPE_DATA`: message data, sealed under confidentiality.
    Data,
    /// `GSS_IOV_BUFFER_TYPE_HEADER`: the token header.
    Header,
    /// `GSS_IOV_BUFFER_TYPE_MECH_PARAMS`: ignored by the krb5 mechanism.
    MechParams,
    /// `GSS_IOV_BUFFER_TYPE_TRAILER`: the token trailer.
    Trailer,
    /// `GSS_IOV_BUFFER_TYPE_PADDING`: padding, always empty for RFC 4121 tokens.
    Padding,
    /// `GSS_IOV_BUFFER_TYPE_STREAM`: a whole wrap token to unwrap.
    Stream,
    /// `GSS_IOV_BUFFER_TYPE_SIGN_ONLY`: data that is authenticated, never sealed.
    SignOnly,
    /// `GSS_IOV_BUFFER_TYPE_MIC_TOKEN`: the MIC token of `get_mic_iov`.
    MicToken,
}

impl IovKind {
    /// The `GSS_IOV_BUFFER_TYPE_*` number.
    #[inline]
    #[must_use]
    pub const fn code(self) -> u32 {
        match self {
            Self::Empty => 0,
            Self::Data => 1,
            Self::Header => 2,
            Self::MechParams => 3,
            Self::Trailer => 7,
            Self::Padding => 9,
            Self::Stream => 10,
            Self::SignOnly => 11,
            Self::MicToken => 12,
        }
    }

    /// The kind of a `GSS_IOV_BUFFER_TYPE_*` number, the flag bits
    /// (`GSS_IOV_BUFFER_FLAG_MASK`) ignored.
    #[inline]
    #[must_use]
    pub const fn from_code(code: u32) -> Option<Self> {
        Some(match code & 0xffff {
            0 => Self::Empty,
            1 => Self::Data,
            2 => Self::Header,
            3 => Self::MechParams,
            7 => Self::Trailer,
            9 => Self::Padding,
            10 => Self::Stream,
            11 => Self::SignOnly,
            12 => Self::MicToken,
            _ => return None,
        })
    }
}

/// One buffer of an IOV array (`gss_iov_buffer_desc`).
///
/// The mechanism replaces the value of the header, trailer, padding and MIC
/// buffers it fills, and seals or opens data buffers in place; every buffer
/// owns its bytes (MIT's `GSS_IOV_BUFFER_FLAG_ALLOCATE` is implied). Values
/// are erased when dropped and never shown by `Debug`.
#[derive(Clone, Eq, PartialEq)]
pub struct IovBuffer {
    /// The buffer type.
    kind: IovKind,
    /// The bytes.
    value: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for IovBuffer {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IovBuffer")
            .field("kind", &self.kind)
            .field("len", &self.value.len())
            .finish()
    }
}

impl IovBuffer {
    /// A buffer of `kind` holding `value`.
    #[inline]
    #[must_use]
    pub fn new(kind: IovKind, value: Vec<u8>) -> Self {
        Self {
            kind,
            value: Zeroizing::new(value),
        }
    }

    /// An empty buffer of `kind`, for the mechanism to fill.
    #[inline]
    #[must_use]
    pub fn empty(kind: IovKind) -> Self {
        Self::new(kind, Vec::new())
    }

    /// The buffer type.
    #[inline]
    #[must_use]
    pub const fn kind(&self) -> IovKind {
        self.kind
    }

    /// The bytes.
    #[inline]
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// The bytes, erased when the owner drops.
    #[inline]
    #[must_use]
    pub fn into_value(self) -> Zeroizing<Vec<u8>> {
        self.value
    }
}

/// The value of a name attribute (`gss_get_name_attribute`, RFC 6680).
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub struct NameAttribute {
    /// The value.
    value: Vec<u8>,
    /// Whether the value is authenticated: the PAC's KDC signature verified.
    authenticated: bool,
    /// Whether the value is complete.
    complete: bool,
}

impl fmt::Debug for NameAttribute {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NameAttribute")
            .field("value_len", &self.value.len())
            .field("authenticated", &self.authenticated)
            .field("complete", &self.complete)
            .finish()
    }
}

impl NameAttribute {
    /// The value: the bytes of the PAC or of one PAC buffer.
    #[inline]
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Whether the value is authenticated: only when the PAC's KDC signature
    /// verified, not merely its server signature.
    #[inline]
    #[must_use]
    pub const fn authenticated(&self) -> bool {
        self.authenticated
    }

    /// Whether the value is complete (always, for PAC attributes).
    #[inline]
    #[must_use]
    pub const fn complete(&self) -> bool {
        self.complete
    }
}

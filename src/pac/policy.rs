// The explicit policy and the inputs of PAC verification (MS-PAC 2.8, MIT `krb5_pac_verify_ext`).
// Included into `pac` by `src/pac.rs` so the types live at `pac::`.

/// What a policy demands of one PAC signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SignatureRequirement {
    /// The signature buffer must be present and must verify under a key the caller supplies;
    /// a missing buffer, a missing key and a mismatch are each an error.
    Required,
    /// A present signature is verified when its inputs (key, ticket bytes) are supplied and is
    /// left unverified, and reported as such, when they are not; a mismatch is an error.
    IfPresent,
}

/// Whether a ticket's server is one whose tickets carry a ticket signature and a full checksum.
///
/// MS-PAC 2.8.3 and MIT `k5_pac_should_have_ticket_signature`
/// (`src/lib/krb5/krb/pac.c:584-593`): tickets for the ticket-granting service and for
/// `kadmin/changepw` carry neither.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TicketKind {
    /// An ordinary service ticket: ticket signature and full checksum are expected.
    Service,
    /// A ticket for `krbtgt/*` or `kadmin/changepw`: neither is expected.
    NoTicketSignature,
}

impl TicketKind {
    /// Classify a ticket by the components of its server principal.
    #[inline]
    #[must_use]
    pub fn of_server<S>(components: &[S]) -> Self
    where
        S: AsRef<str>,
    {
        match components {
            [first, _] if first.as_ref() == "krbtgt" => Self::NoTicketSignature,
            [first, second] if first.as_ref() == "kadmin" && second.as_ref() == "changepw" => {
                Self::NoTicketSignature
            }
            _ => Self::Service,
        }
    }

    /// Whether the ticket signature and the full checksum are expected.
    #[inline]
    #[must_use]
    pub const fn expects_ticket_signature(self) -> bool {
        matches!(self, Self::Service)
    }
}

/// The caller's choice of which PAC signatures, buffers and identity checks a PAC must pass.
///
/// A PAC is authorization data only after [`Pac::verify_ext`] accepted it under a policy;
/// parsing, or the presence of a KDC checksum, proves nothing.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct VerificationPolicy {
    /// The server signature, keyed with the service key.
    server: SignatureRequirement,
    /// The KDC signature over the server signature, keyed with the KDC (`krbtgt`) key.
    kdc: SignatureRequirement,
    /// The ticket signature over the ticket, keyed with the KDC key.
    ticket: SignatureRequirement,
    /// The full checksum over the PAC, keyed with the KDC key (KB5020805).
    full: SignatureRequirement,
    /// Whether the client info must be present and equal the ticket's client.
    client_binding: bool,
    /// Buffer types that must be present.
    required_buffers: Vec<u32>,
}

impl VerificationPolicy {
    /// The secure default of a service that holds only its own key: the server signature must
    /// verify, a KDC, ticket or full signature is verified when the caller adds the KDC key, and
    /// the server checksum, KDC checksum and client info buffers must be present and the client
    /// info must name the ticket's client.
    ///
    /// No buffer MIT krb5 does not always send is required: a default MIT PAC has no
    /// `KERB_VALIDATION_INFO` (FU-SVC-P01).
    #[inline]
    #[must_use]
    pub fn acceptor() -> Self {
        Self {
            server: SignatureRequirement::Required,
            kdc: SignatureRequirement::IfPresent,
            ticket: SignatureRequirement::IfPresent,
            full: SignatureRequirement::IfPresent,
            client_binding: true,
            required_buffers: vec![
                INFO_TYPE_PAC_SERVER_SIGNATURE_DATA,
                INFO_TYPE_PAC_KDC_SIGNATURE_DATA,
                INFO_TYPE_PAC_CLIENT_INFO,
            ],
        }
    }

    /// The policy of a party that holds the service and the KDC key: every signature must verify.
    #[inline]
    #[must_use]
    pub fn kdc() -> Self {
        Self::acceptor()
            .with_kdc(SignatureRequirement::Required)
            .with_ticket(SignatureRequirement::Required)
            .with_full(SignatureRequirement::Required)
    }

    /// Set the demand on the server signature.
    #[inline]
    #[must_use]
    pub const fn with_server(mut self, requirement: SignatureRequirement) -> Self {
        self.server = requirement;
        self
    }

    /// Set the demand on the KDC signature.
    #[inline]
    #[must_use]
    pub const fn with_kdc(mut self, requirement: SignatureRequirement) -> Self {
        self.kdc = requirement;
        self
    }

    /// Set the demand on the ticket signature (only for [`TicketKind::Service`] tickets).
    #[inline]
    #[must_use]
    pub const fn with_ticket(mut self, requirement: SignatureRequirement) -> Self {
        self.ticket = requirement;
        self
    }

    /// Set the demand on the full checksum (only for [`TicketKind::Service`] tickets).
    #[inline]
    #[must_use]
    pub const fn with_full(mut self, requirement: SignatureRequirement) -> Self {
        self.full = requirement;
        self
    }

    /// Require or stop requiring that the client info names the ticket's client (MIT
    /// `krb5_pac_verify_ext` with a `NULL` principal skips it).
    #[inline]
    #[must_use]
    pub const fn with_client_binding(mut self, required: bool) -> Self {
        self.client_binding = required;
        self
    }

    /// Additionally require a buffer type to be present.
    #[inline]
    #[must_use]
    pub fn require_buffer(mut self, ul_type: u32) -> Self {
        if !self.required_buffers.contains(&ul_type) {
            self.required_buffers.push(ul_type);
        }
        self
    }

    /// The demand on the server signature.
    #[inline]
    #[must_use]
    pub const fn server(&self) -> SignatureRequirement {
        self.server
    }

    /// The demand on the KDC signature.
    #[inline]
    #[must_use]
    pub const fn kdc_requirement(&self) -> SignatureRequirement {
        self.kdc
    }

    /// The demand on the ticket signature.
    #[inline]
    #[must_use]
    pub const fn ticket(&self) -> SignatureRequirement {
        self.ticket
    }

    /// The demand on the full checksum.
    #[inline]
    #[must_use]
    pub const fn full(&self) -> SignatureRequirement {
        self.full
    }

    /// Whether the client info must name the ticket's client.
    #[inline]
    #[must_use]
    pub const fn client_binding(&self) -> bool {
        self.client_binding
    }

    /// The buffer types that must be present.
    #[inline]
    #[must_use]
    pub fn required_buffers(&self) -> &[u32] {
        &self.required_buffers
    }
}

impl Default for VerificationPolicy {
    #[inline]
    fn default() -> Self {
        Self::acceptor()
    }
}

/// The client a PAC must describe: its realm-less name and the ticket's authentication time.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ClientBinding {
    /// The name the PAC's client info must carry.
    name: String,
    /// The `FILETIME` ticks of the ticket's authentication time.
    auth_ticks: Option<u64>,
}

impl ClientBinding {
    /// Bind to a client name and the ticket's authentication time.
    ///
    /// `name` is the name as the PAC spells it (MIT `krb5_unparse_name_flags` with
    /// `KRB5_PRINCIPAL_UNPARSE_DISPLAY`, realm-less unless `name` carries `@REALM`). The time
    /// must equal the PAC's `ClientId` to the tick; a time outside the `FILETIME` range never
    /// matches.
    #[inline]
    #[must_use]
    pub fn new<N>(name: N, auth_time: SystemTime) -> Self
    where
        N: Into<String>,
    {
        let auth_ticks = auth_time
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|elapsed| {
                elapsed
                    .as_secs()
                    .checked_add(WINDOWS_TO_UNIX_SECONDS)?
                    .checked_mul(WINDOWS_TICKS_PER_SECOND)?
                    .checked_add(u64::from(elapsed.subsec_nanos().div_euclid(100)))
            });
        Self {
            name: name.into(),
            auth_ticks,
        }
    }

    /// The name the PAC must carry.
    #[inline]
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether `client_id_ticks` is this binding's authentication time.
    pub(super) fn matches_ticks(&self, client_id_ticks: u64) -> bool {
        self.auth_ticks == Some(client_id_ticks)
    }
}

/// The keys and ticket data a PAC is verified against, with the policy that judges them.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Verification<'keys> {
    /// What must pass.
    policy: VerificationPolicy,
    /// The service key: server signature.
    server_key: Option<&'keys EncryptionKey>,
    /// The KDC key: KDC, ticket and full signatures.
    kdc_key: Option<&'keys EncryptionKey>,
    /// The client the PAC must describe.
    client: Option<ClientBinding>,
    /// The ticket re-encoded with its PAC replaced by one zero byte.
    ticket_signature_input: Option<&'keys [u8]>,
    /// The kind of ticket that carries the PAC.
    ticket_kind: TicketKind,
}

impl<'keys> Verification<'keys> {
    /// Start a verification under `policy`; add the keys and the client binding it needs.
    #[inline]
    #[must_use]
    pub const fn new(policy: VerificationPolicy) -> Self {
        Self {
            policy,
            server_key: None,
            kdc_key: None,
            client: None,
            ticket_signature_input: None,
            ticket_kind: TicketKind::Service,
        }
    }

    /// Supply the key of the service the ticket is for (the server signature key).
    #[inline]
    #[must_use]
    pub const fn with_server_key(mut self, key: &'keys EncryptionKey) -> Self {
        self.server_key = Some(key);
        self
    }

    /// Supply the KDC key (`krbtgt`), which signs the KDC signature, the ticket signature and the
    /// full checksum.
    #[inline]
    #[must_use]
    pub const fn with_kdc_key(mut self, key: &'keys EncryptionKey) -> Self {
        self.kdc_key = Some(key);
        self
    }

    /// Supply the client the PAC must describe.
    #[inline]
    #[must_use]
    pub fn with_client(mut self, client: ClientBinding) -> Self {
        self.client = Some(client);
        self
    }

    /// Supply the bytes the ticket signature covers, from [`ticket_signature_input`].
    #[inline]
    #[must_use]
    pub const fn with_ticket_signature_input(mut self, input: &'keys [u8]) -> Self {
        self.ticket_signature_input = Some(input);
        self
    }

    /// Set the kind of the ticket (default [`TicketKind::Service`]).
    #[inline]
    #[must_use]
    pub const fn with_ticket_kind(mut self, kind: TicketKind) -> Self {
        self.ticket_kind = kind;
        self
    }

    /// The policy.
    pub(super) const fn policy(&self) -> &VerificationPolicy {
        &self.policy
    }

    /// The service key.
    pub(super) const fn server_key(&self) -> Option<&'keys EncryptionKey> {
        self.server_key
    }

    /// The KDC key.
    pub(super) const fn kdc_key(&self) -> Option<&'keys EncryptionKey> {
        self.kdc_key
    }

    /// The client binding.
    pub(super) const fn client(&self) -> Option<&ClientBinding> {
        self.client.as_ref()
    }

    /// The ticket signature input.
    pub(super) const fn ticket_signature_input(&self) -> Option<&'keys [u8]> {
        self.ticket_signature_input
    }

    /// The kind of the ticket.
    pub(super) const fn ticket_kind(&self) -> TicketKind {
        self.ticket_kind
    }
}

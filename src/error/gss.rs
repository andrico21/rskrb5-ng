/// GSS-API Kerberos V5 mechanism error ([`crate::gss`]).
///
/// The variants name the RFC 2743 major status they correspond to where one
/// applies; the wrapped domain errors carry the Kerberos-level cause.
#[cfg(feature = "spnego")]
#[derive(thiserror::Error)]
#[non_exhaustive]
pub enum Gss {
    /// A name could not be imported or used (`GSS_S_BAD_NAME`).
    #[error("bad name: {0}")]
    BadName(&'static str),
    /// A name, exported-name token or name component exceeds its bound (`GSS_S_BAD_NAME`).
    #[error("name is {actual} bytes, above the {maximum}-byte limit")]
    NameTooLong {
        /// The bound.
        maximum: usize,
        /// The length offered.
        actual: usize,
    },
    /// The name type is not one the Kerberos mechanism imports (`GSS_S_BAD_NAMETYPE`).
    #[error("unsupported name type {0:?}")]
    BadNameType(ObjectIdentifier),
    /// The caller's resolver knows no local account for a numeric user id (`G_NOUSER`).
    #[error("user id {0} has no local account")]
    UnresolvedUid(u32),
    /// The initiator's channel bindings differ from the acceptor's (`GSS_S_BAD_BINDINGS`).
    #[error("channel bindings do not match")]
    BadBindings,
    /// The acceptor requires channel bindings and the initiator sent none
    /// (`GSS_S_BAD_BINDINGS`).
    #[error("the acceptor requires channel bindings and the initiator sent none")]
    MissingBindings,
    /// A channel-binding field exceeds its bound.
    #[error("channel-binding {field} is {actual} bytes, above the {maximum}-byte limit")]
    BindingTooLong {
        /// The field.
        field: &'static str,
        /// The bound.
        maximum: usize,
        /// The length offered.
        actual: usize,
    },
    /// The RFC 4121 authenticator checksum is malformed (`GSS_S_DEFECTIVE_CREDENTIAL`).
    #[error("malformed GSS authenticator checksum: {0}")]
    DefectiveChecksum(&'static str),
    /// A context-establishment token is malformed (`GSS_S_DEFECTIVE_TOKEN`).
    #[error("defective token: {0}")]
    DefectiveToken(&'static str),
    /// A token exceeds its bound (`GSS_S_DEFECTIVE_TOKEN`).
    #[error("token is {actual} bytes, above the {maximum}-byte limit")]
    TokenTooLarge {
        /// The bound.
        maximum: usize,
        /// The length offered.
        actual: usize,
    },
    /// A per-message token was seen before (`GSS_S_DUPLICATE_TOKEN`).
    #[error("duplicate per-message token, sequence number {0}")]
    DuplicateToken(u64),
    /// A per-message token is older than the replay window (`GSS_S_OLD_TOKEN`).
    #[error("per-message token older than the replay window, sequence number {0}")]
    OldToken(u64),
    /// A per-message token arrived after a later one (`GSS_S_UNSEQ_TOKEN`).
    #[error("per-message token out of sequence, sequence number {0}")]
    UnsequencedToken(u64),
    /// A per-message token skipped earlier sequence numbers (`GSS_S_GAP_TOKEN`).
    #[error("per-message token after a gap, sequence number {0}")]
    GapToken(u64),
    /// The context or its ticket expired (`GSS_S_CONTEXT_EXPIRED`).
    #[error("the security context has expired")]
    ContextExpired,
    /// A step was called that the context does not expect (`GSS_S_NO_CONTEXT`).
    #[error("the context does not expect this step: {0}")]
    UnexpectedStep(&'static str),
    /// The credential cannot be used this way (`GSS_S_NO_CRED`).
    #[error("the credential cannot be used to {0}")]
    WrongCredentialUsage(&'static str),
    /// The credential holds nothing usable for the request (`GSS_S_NO_CRED`).
    #[error("no usable credential: {0}")]
    NoCredential(&'static str),
    /// A credential-store key is not one this mechanism knows (`GSS_S_CRED_UNAVAIL`).
    #[error("unsupported credential-store key {0}")]
    UnsupportedCredStoreKey(String),
    /// A credential-store key is given twice.
    #[error("credential-store key {0} is given twice")]
    DuplicateCredStoreKey(String),
    /// The replay cache cannot be used: replay detection cannot be switched
    /// off, and only in-memory replay caches (`memory:`) are implemented.
    #[error("replay cache {0} is not available")]
    UnsupportedReplayCache(String),
    /// The target credential cache already holds tickets (`GSS_S_DUPLICATE_ELEMENT`).
    #[error("the credential cache already holds tickets")]
    DuplicateElement,
    /// The context did not negotiate the protection asked for (`GSS_S_UNAVAILABLE`).
    #[error("the context did not negotiate {0}")]
    NotNegotiated(&'static str),
    /// Per-message tokens of DES3 and RC4 contexts use the RFC 1964/4757 formats,
    /// which this module does not implement (`GSS_S_UNAVAILABLE`).
    #[error("per-message tokens of encryption type {0} use the RFC 1964/4757 formats")]
    LegacyTokenFormat(i32),
    /// The delegated credential could not be read.
    #[error("the delegated credential could not be read: {0}")]
    DelegatedCredential(#[source] KrbCred),
    /// SPNEGO or RFC 4121 token processing failed.
    #[error("token error: {0}")]
    Spnego(#[from] Spnego),
    /// AP-REQ validation failed.
    #[error("acceptor error: {0}")]
    Service(#[from] Service),
    /// An AP-REQ could not be built or decoded.
    #[error("AP-REQ error: {0}")]
    ApReq(#[from] ApReq),
    /// An AP-REP could not be built, decoded or decrypted.
    #[error("AP-REP error: {0}")]
    ApRep(#[from] ApRep),
    /// A ticket could not be decoded.
    #[error("ticket error: {0}")]
    Ticket(#[from] Ticket),
    /// The runtime policy refuses an encryption type.
    #[error("policy error: {0}")]
    Policy(#[from] Policy),
    /// AP-REQ construction or ticket acquisition failed.
    #[error("initiator error: {0}")]
    Client(#[from] Client),
    /// A credential cache could not be read or written.
    #[error("credential cache error: {0}")]
    Ccache(#[from] Ccache),
    /// A keytab could not be read.
    #[error("keytab error: {0}")]
    Keytab(#[from] Keytab),
    /// A cryptographic operation failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] Crypto),
    /// The system random source failed.
    #[error("random source error: {0}")]
    Random(#[from] getrandom::Error),
}

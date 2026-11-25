/// Crate-level error type.
#[derive(thiserror::Error)]
#[non_exhaustive]
pub enum Any {
    /// A requested cryptographic feature violates permanent policy.
    #[error("policy error: {0}")]
    Policy(#[from] Policy),
    /// Hex fixture data failed to decode.
    #[cfg(feature = "evaluation")]
    #[error("fixture hex decode failed: {0}")]
    Hex(#[from] hex::FromHexError),
    /// Keytab parsing or serialization failed.
    #[error("keytab error: {0}")]
    Keytab(#[from] Keytab),
    /// krb5.conf parsing failed.
    #[error("config error: {0}")]
    Config(#[from] Config),
    /// Credential cache parsing or serialization failed.
    #[error("ccache error: {0}")]
    CCache(#[from] Ccache),
    /// Kerberos cryptographic operation failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] Crypto),
    /// Extension registration, provider output or profile-module resolution failed.
    #[error("extension error: {0}")]
    Extensions(#[from] Extensions),
    /// A trace destination or sink failed.
    #[error("trace error: {0}")]
    Trace(#[from] Trace),
    /// PAC parsing or verification failed.
    #[error("PAC error: {0}")]
    Pac(#[from] Pac),
    /// Realm-path, transited-encoding or certificate-identity handling failed.
    #[error("routing error: {0}")]
    Routing(#[from] Routing),
    /// A DER element is not canonical or exceeds its budget.
    #[error("DER error: {0}")]
    Der(#[from] Der),
    /// A replay store or replay-cache name failed.
    #[error("replay store error: {0}")]
    Replay(#[from] Replay),
    /// Local authorization or name translation failed.
    #[error("local authorization error: {0}")]
    LocalAuth(#[from] LocalAuth),
    /// Kerberos message helper processing failed.
    #[cfg(feature = "messages")]
    #[error("message helper error: {0}")]
    Messages(#[from] Messages),
    /// HTTP Negotiate processing failed.
    #[cfg(feature = "http")]
    #[error("HTTP Negotiate error: {0}")]
    Http(#[from] Http),
    /// An HTTP exchange failed.
    #[cfg(feature = "http")]
    #[error("HTTP exchange error: {0}")]
    HttpExchange(#[from] HttpExchange),
    /// The HTTP Negotiate client failed.
    #[cfg(feature = "http")]
    #[error("HTTP client error: {0}")]
    HttpClient(#[from] HttpClient),
    /// The HTTP session manager refused a session.
    #[cfg(feature = "http")]
    #[error("HTTP session error: {0}")]
    HttpSession(#[from] HttpSession),
    /// The cookie jar refused a cookie.
    #[cfg(feature = "http")]
    #[error("HTTP cookie error: {0}")]
    HttpCookie(#[from] HttpCookie),
    /// AS exchange client processing failed.
    #[cfg(feature = "messages")]
    #[error("client error: {0}")]
    Client(#[from] Client),
    /// AP-REQ message processing failed.
    #[cfg(feature = "messages")]
    #[error("AP-REQ error: {0}")]
    ApReq(#[from] ApReq),
    /// AP-REP message processing failed.
    #[cfg(feature = "messages")]
    #[error("AP-REP error: {0}")]
    ApRep(#[from] ApRep),
    /// kadmin message processing failed.
    #[cfg(feature = "messages")]
    #[error("kadmin error: {0}")]
    Kadmin(#[from] Kadmin),
    /// KDC request message processing failed.
    #[cfg(feature = "messages")]
    #[error("KDC request error: {0}")]
    KdcReq(#[from] KdcReq),
    /// KDC reply message processing failed.
    #[cfg(feature = "messages")]
    #[error("KDC reply error: {0}")]
    KdcRep(#[from] KdcRep),
    /// KRB-ERROR message processing failed.
    #[cfg(feature = "messages")]
    #[error("KRB-ERROR error: {0}")]
    Krb(#[from] KrbErrorCodec),
    /// Authorization-data helper processing failed.
    #[cfg(feature = "messages")]
    #[error("authorization data helper error: {0}")]
    AuthData(#[from] AuthData),
    /// An authenticated message operation failed.
    #[cfg(feature = "messages")]
    #[error("authenticated message error: {0}")]
    AuthMessage(#[from] AuthMessage),
    /// KRB-PRIV processing failed.
    #[cfg(feature = "messages")]
    #[error("KRB-PRIV error: {0}")]
    KrbPriv(#[from] KrbPriv),
    /// KRB-CRED processing failed.
    #[cfg(feature = "messages")]
    #[error("KRB-CRED error: {0}")]
    KrbCred(#[from] KrbCred),
    /// KRB-SAFE processing failed.
    #[cfg(feature = "messages")]
    #[error("KRB-SAFE error: {0}")]
    KrbSafe(#[from] KrbSafe),
    /// AP-REQ service validation failed.
    #[cfg(feature = "messages")]
    #[error("service validation error: {0}")]
    Service(#[from] Service),
    /// SPNEGO/GSSAPI token processing failed.
    #[cfg(feature = "spnego")]
    #[error("SPNEGO error: {0}")]
    Spnego(#[from] Spnego),
    /// GSS-API Kerberos mechanism processing failed.
    #[cfg(feature = "spnego")]
    #[error("GSS-API error: {0}")]
    Gss(#[from] Gss),
    /// IAKERB relay or context processing failed.
    #[cfg(feature = "spnego")]
    #[error("IAKERB error: {0}")]
    Iakerb(#[from] Iakerb),
    /// `NegoEx` negotiation failed.
    #[cfg(feature = "spnego")]
    #[error("NegoEx error: {0}")]
    Negoex(#[from] Negoex),
    /// ONC RPC or `RPCSEC_GSS` processing failed.
    #[cfg(feature = "spnego")]
    #[error("RPC error: {0}")]
    Rpc(#[from] Rpc),
    /// Remote kadm5 administration failed.
    #[cfg(all(feature = "spnego", feature = "tokio"))]
    #[error("kadm5 error: {0}")]
    Kadm5(#[from] Kadm5),
    /// Ticket message processing failed.
    #[cfg(feature = "messages")]
    #[error("Ticket error: {0}")]
    Ticket(#[from] Ticket),
}

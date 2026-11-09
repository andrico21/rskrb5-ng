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
    /// PAC parsing or verification failed.
    #[error("PAC error: {0}")]
    Pac(#[from] Pac),
    /// Kerberos message helper processing failed.
    #[cfg(feature = "messages")]
    #[error("message helper error: {0}")]
    Messages(#[from] Messages),
    /// HTTP Negotiate processing failed.
    #[cfg(feature = "http")]
    #[error("HTTP Negotiate error: {0}")]
    Http(#[from] Http),
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
    /// Ticket message processing failed.
    #[cfg(feature = "messages")]
    #[error("Ticket error: {0}")]
    Ticket(#[from] Ticket),
}

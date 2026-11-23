/// IAKERB error ([`crate::gss::iakerb`]).
///
/// The variants separate the three things an IAKERB exchange can fail on: the
/// token (its framing, header and order), the relay policy (a realm, a
/// request, a round or a byte count the acceptor refuses) and the context (the
/// transcript checksum and the underlying Kerberos exchanges).
#[cfg(feature = "spnego")]
#[derive(thiserror::Error)]
#[non_exhaustive]
pub enum Iakerb {
    /// The bytes are not an IAKERB proxy token: not a GSS-framed token of the
    /// IAKERB mechanism, or not token id `05 01` (`G_BAD_TOK_HEADER`).
    #[error("not an IAKERB token: {0}")]
    NotIakerb(&'static str),
    /// An IAKERB token or its `IAKERB-HEADER` is malformed (`GSS_S_DEFECTIVE_TOKEN`).
    #[error("malformed IAKERB token: {0}")]
    BadToken(&'static str),
    /// A token exceeds its bound (`GSS_S_DEFECTIVE_TOKEN`).
    #[error("IAKERB token is {actual} bytes, above the {maximum}-byte limit")]
    TokenTooLarge {
        /// The bound.
        maximum: usize,
        /// The length offered.
        actual: usize,
    },
    /// A token arrived that the context does not expect now (`GSS_S_DEFECTIVE_TOKEN`,
    /// MIT `G_WRONG_TOKID`).
    #[error("the IAKERB context does not expect this step: {0}")]
    UnexpectedStep(&'static str),
    /// The relay policy does not name the realm the initiator asked the
    /// acceptor to contact.
    #[error("the relay policy does not permit realm {0}")]
    RealmNotPermitted(String),
    /// The relay policy refuses the request: it is not a well-formed AS-REQ or
    /// TGS-REQ for the realm named in the token header.
    #[error("the relay refuses this request: {0}")]
    RequestRefused(&'static str),
    /// The exchange needs more relay rounds than the bound (MIT `IAKERB_MAX_HOPS`).
    #[error("the exchange needs more than {maximum} relay rounds")]
    RoundLimit {
        /// The bound.
        maximum: usize,
    },
    /// The transcript of the exchange exceeds its bound.
    #[error("the IAKERB transcript exceeds {maximum} bytes")]
    TranscriptTooLarge {
        /// The bound.
        maximum: usize,
    },
    /// The relay policy is malformed.
    #[error("invalid relay policy: {0}")]
    InvalidPolicy(&'static str),
    /// The application's [`crate::gss::iakerb::KdcRelay`] failed.
    #[error("the KDC relay failed: {0}")]
    RelayFailed(String),
    /// The acceptor's reply is not a KDC reply or error.
    #[error("the relay returned something other than a KDC reply: {0}")]
    BadRelayReply(&'static str),
    /// The acceptor reported that it could not find a KDC for the realm
    /// (`KRB_AP_ERR_IAKERB_KDC_NOT_FOUND`).
    #[error("the IAKERB acceptor found no KDC for the realm")]
    KdcNotFound,
    /// The acceptor reported that the KDC did not answer
    /// (`KRB_AP_ERR_IAKERB_KDC_NO_RESPONSE`).
    #[error("the KDC did not answer the IAKERB acceptor")]
    KdcNoResponse,
    /// The KDC asked for input the IAKERB initiator cannot supply (a prompt
    /// other than the credential's password).
    #[error("the KDC asked for input the IAKERB initiator cannot supply")]
    UnsupportedPrompt,
    /// The AP-REQ after an IAKERB exchange carries no `IAKERB-FINISHED`
    /// (`GSS_S_BAD_SIG`).
    #[error("the AP-REQ carries no IAKERB-FINISHED checksum")]
    MissingFinished,
    /// The `IAKERB-FINISHED` checksum does not cover the transcript under the
    /// initiator's subkey (`GSS_S_BAD_SIG`).
    #[error("the IAKERB-FINISHED checksum does not match the transcript")]
    BadFinished,
    /// An `IAKERB-FINISHED` arrived although no IAKERB token was exchanged
    /// (`KRB5KRB_AP_ERR_MSG_TYPE`).
    #[error("an IAKERB-FINISHED arrived without an IAKERB exchange")]
    UnexpectedFinished,
    /// The initiator asked to delegate its credentials, which IAKERB
    /// contexts of this crate do not carry.
    #[error("delegation is not supported over IAKERB")]
    DelegationUnsupported,
    /// A GSS-API Kerberos mechanism step failed.
    #[error("GSS-API error: {0}")]
    Gss(#[from] Gss),
    /// The AS or TGS exchange failed.
    #[error("exchange error: {0}")]
    Client(#[from] Client),
    /// The AP-REQ did not validate.
    #[error("acceptor error: {0}")]
    Service(#[from] Service),
    /// The system random source failed.
    #[error("random source error: {0}")]
    Random(#[from] getrandom::Error),
}

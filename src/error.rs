//! Typed errors grouped by Kerberos domain.
#[cfg(feature = "messages")]
use core::error::Error as StdError;
use core::{str::Utf8Error, time::Duration};
#[cfg(feature = "messages")]
use std::time::SystemTime;
use std::{env, io, path::PathBuf, time::SystemTimeError};

#[cfg(feature = "http")]
use http_types::{
    Response as HttpResponse,
    header::{InvalidHeaderValue, ToStrError},
};
#[cfg(feature = "messages")]
use rasn::types::Integer;

#[cfg(feature = "messages")]
use crate::client::KdcError;
#[cfg(feature = "tokio")]
use crate::client::transport::KdcProtocol;
#[cfg(feature = "spnego")]
use crate::gss::negoex::{AuthScheme, MessageType, ProviderFailure};
#[cfg(feature = "http")]
use crate::http::ClientNegotiateResponse;
#[cfg(feature = "spnego")]
use crate::spnego::oid::ObjectIdentifier;
use crate::{
    ccache::keyring::Fault as KeyringFault,
    config::parameters::Failure as ExpansionFailure,
    extensions::{Interface, ProviderError},
};
include!("error/any.rs");
include!("error/auth_message.rs");
include!("error/auth_data.rs");
include!("error/der.rs");
include!("error/gss.rs");
include!("error/http_client.rs");
include!("error/iakerb.rs");
include!("error/kadm5.rs");
include!("error/negoex.rs");
include!("error/policy.rs");
include!("error/replay.rs");
mod credential_debug;
#[cfg(feature = "messages")]
/// AP-REP helper error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ApRep {
    /// ASN.1 DER decode failed.
    #[error("failed to decode {target}: {message}")]
    Decode {
        /// Decoded type name.
        target: &'static str,
        /// Decoder error text.
        message: String,
    },
    /// ASN.1 DER encode failed.
    #[error("failed to encode {target}: {message}")]
    Encode {
        /// Encoded type name.
        target: &'static str,
        /// Encoder error text.
        message: String,
    },
    /// Message field did not contain the expected value.
    #[error("invalid {field}: expected {expected}, got {actual}")]
    InvalidMessage {
        /// Field name.
        field: &'static str,
        /// Expected value.
        expected: i32,
        /// Actual value.
        actual: String,
    },
    /// The encrypted data etype is not implemented yet.
    #[error("unsupported encryption type: {0}")]
    UnsupportedEtype(i32),
    /// A key did not match the encrypted AP-REP data etype.
    #[error(
        "key etype {key_etype} does not match AP-REP encrypted data etype {encrypted_data_etype}"
    )]
    KeyEtypeMismatch {
        /// Reply key encryption type.
        key_etype: i32,
        /// AP-REP encrypted data encryption type.
        encrypted_data_etype: i32,
    },
    /// Random byte generation failed.
    #[error("random byte generation failed: {0}")]
    Random(#[from] getrandom::Error),
    /// Crypto operation failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] Crypto),
}
#[cfg(feature = "messages")]
/// AP-REQ helper error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ApReq {
    /// ASN.1 DER decode failed.
    #[error("failed to decode {target}: {message}")]
    Decode {
        /// Decoded type name.
        target: &'static str,
        /// Decoder error text.
        message: String,
    },
    /// ASN.1 DER encode failed.
    #[error("failed to encode {target}: {message}")]
    Encode {
        /// Encoded type name.
        target: &'static str,
        /// Encoder error text.
        message: String,
    },
    /// Message field did not contain the expected value.
    #[error("invalid {field}: expected {expected}, got {actual}")]
    InvalidMessage {
        /// Field name.
        field: &'static str,
        /// Expected value.
        expected: i32,
        /// Actual value.
        actual: String,
    },
    /// The encrypted data etype is not implemented yet.
    #[error("unsupported encryption type: {0}")]
    UnsupportedEtype(i32),
    /// A key did not match the encrypted AP-REQ authenticator etype.
    #[error(
        "key etype {key_etype} does not match AP-REQ authenticator etype {encrypted_data_etype}"
    )]
    KeyEtypeMismatch {
        /// Reply key encryption type.
        key_etype: i32,
        /// AP-REQ authenticator encryption type.
        encrypted_data_etype: i32,
    },
    /// Random byte generation failed.
    #[error("random byte generation failed: {0}")]
    Random(#[from] getrandom::Error),
    /// Crypto operation failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] Crypto),
}
/// Credential cache parsing and serialization error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Ccache {
    /// Version one has no field for a nonzero principal name type.
    #[error("credential cache version one cannot represent principal name type {0}")]
    UnrepresentableNameType(i32),
    /// A configured name could not be expanded from available facts.
    #[error("credential name expansion failed: {0}")]
    Expansion(#[from] ExpansionFailure),
    /// A requested cryptographic feature violates permanent policy.
    #[error("policy error: {0}")]
    Policy(#[from] Policy),
    /// UID tokens require Linux procfs process identities.
    #[error("credential path process identity is unavailable (UID tokens require Linux procfs)")]
    IdentityUnavailable,
    /// File loading or saving failed.
    #[error("credential cache file could not be read or written: {0}")]
    Io(#[from] io::Error),
    /// The default cache name could not be read from `KRB5CCNAME`.
    #[error("default credential cache name could not be read from KRB5CCNAME: {0}")]
    DefaultCacheName(#[source] env::VarError),
    /// A cache name was empty or did not include a path.
    #[error("invalid credential cache name")]
    InvalidCacheName,
    /// The cache name uses a cache type this module cannot parse.
    #[error("unsupported credential cache type: {cache_type}")]
    UnsupportedCacheType {
        /// Cache type prefix before the first colon.
        cache_type: String,
    },
    /// The Windows `API:` cache (MIT Kerberos for Windows CCAPI) is omitted by owner decision
    /// D13; see `docs/security-policy.md#windows-api-ccache`.
    #[error(
        "the Windows API: credential cache is omitted by owner decision D13 (docs/security-policy.md#windows-api-ccache)"
    )]
    UnsupportedWindowsApi,
    /// Input is too short to contain the `ccache` header.
    #[error("credential cache is too short: {actual} bytes")]
    TooShort {
        /// Actual input length.
        actual: usize,
    },
    /// The credential cache does not start with the required first byte.
    #[error("invalid credential cache first byte: {0}")]
    InvalidFirstByte(u8),
    /// Unsupported ccache version.
    #[error("invalid credential cache version: {0}")]
    InvalidVersion(u8),
    /// A read would exceed the input length.
    #[error(
        "credential cache data is truncated at offset {offset}; need {needed} bytes, have {remaining}"
    )]
    Truncated {
        /// Offset where the read started.
        offset: usize,
        /// Bytes needed.
        needed: usize,
        /// Bytes remaining from offset.
        remaining: usize,
    },
    /// A signed length was negative where the field cannot be negative.
    #[error("negative credential cache length: {0}")]
    NegativeLength(i32),
    /// A length cannot fit in the target integer type.
    #[error("credential cache length overflow")]
    LengthOverflow,
    /// Principal strings must be valid UTF-8.
    #[error("invalid credential cache string: {0}")]
    InvalidString(#[from] Utf8Error),
    /// A v4 header field is malformed.
    #[error("invalid credential cache header field tag {tag} with length {length}")]
    InvalidHeaderField {
        /// Field tag.
        tag: u16,
        /// Field value length.
        length: usize,
    },
    /// The v4 header length did not match parsed fields.
    #[error("invalid credential cache header length")]
    InvalidHeaderLength,
    /// The named cache does not exist or holds no default principal yet
    /// (MIT `KRB5_FCC_NOFILE`).
    #[error("credential cache {name} does not exist or is not initialized")]
    CacheNotFound {
        /// The full cache name.
        name: String,
    },
    /// A cache named for a collection operation is not a member of the
    /// collection, such as a `DIR` subsidiary outside the collection directory.
    #[error("credential cache {name} is not a member of collection {collection}")]
    OutsideCollection {
        /// The full cache name.
        name: String,
        /// The collection.
        collection: String,
    },
    /// The configured `ccache_type` is not a cache format version (1 to 4).
    #[error("ccache_type {0} is not a credential cache format version (1 to 4)")]
    InvalidCacheType(i32),
    /// The Linux kernel keyring cache type failed (`KEYRING:`, `ccache-keyring`).
    #[error("kernel keyring cache error: {0}")]
    Keyring(#[from] KeyringFault),
    /// Cache selection failed in a selector or host-realm mapper.
    #[error("credential cache selection failed: {0}")]
    Selection(#[source] Extensions),
    /// The KCM daemon client failed.
    #[error("KCM credential cache failed: {0}")]
    Kcm(#[from] Kcm),
    /// The cache type needs an operating system service this platform lacks.
    #[error("credential cache type {cache_type} is not supported on {platform}")]
    UnsupportedPlatform {
        /// The cache type prefix.
        cache_type: &'static str,
        /// The platform.
        platform: &'static str,
    },
}
#[cfg(feature = "messages")]
/// Kerberos client exchange error.
#[derive(thiserror::Error)]
#[non_exhaustive]
pub enum Client {
    /// ASN.1 DER decode failed.
    #[error("failed to decode {target}: {message}")]
    Decode {
        /// Decoded type name.
        target: &'static str,
        /// Decoder error text.
        message: String,
    },
    /// ASN.1 DER encode failed.
    #[error("failed to encode {target}: {message}")]
    Encode {
        /// Encoded type name.
        target: &'static str,
        /// Encoder error text.
        message: String,
    },
    /// ASN.1 string value was not valid UTF-8.
    #[error("invalid Kerberos string: {0}")]
    InvalidString(#[from] Utf8Error),
    /// A Kerberos string value could not be constructed.
    #[error("invalid Kerberos string value: {0}")]
    InvalidKerberosString(String),
    /// A human-readable Kerberos principal name was invalid.
    #[error("invalid Kerberos principal name {value:?}: {reason}")]
    InvalidPrincipalName {
        /// Input principal string.
        value: String,
        /// Validation failure.
        reason: &'static str,
    },
    /// Message field did not contain the expected value.
    #[error("invalid {field}: expected {expected}, got {actual}")]
    InvalidMessage {
        /// Field name.
        field: &'static str,
        /// Expected value.
        expected: i32,
        /// Actual value.
        actual: String,
    },
    /// Message integer field could not be represented as `u32`.
    #[error("invalid {field}: expected unsigned 32-bit integer, got {actual}")]
    InvalidUnsignedInteger {
        /// Field name.
        field: &'static str,
        /// Actual value.
        actual: String,
    },
    /// No ticket encryption types were requested.
    #[error("ticket request must request at least one encryption type")]
    EmptyEtypes,
    /// The encrypted data etype is not implemented yet.
    #[error("unsupported encryption type: {0}")]
    UnsupportedEtype(i32),
    /// A KDC reply used an enctype outside the request's requested list.
    #[error("KDC reply enctype {0} was not requested")]
    EnctypeNotRequested(i32),
    /// A KDC reply used an enctype outside the configured permitted list.
    #[error("KDC reply enctype {0} is not permitted by configuration")]
    EnctypeNotPermitted(i32),
    /// A key did not match the encrypted KDC reply data etype.
    #[error(
        "key etype {key_etype} does not match KDC-REP encrypted data etype {encrypted_data_etype}"
    )]
    KeyEtypeMismatch {
        /// Reply key encryption type.
        key_etype: i32,
        /// KDC-REP encrypted data encryption type.
        encrypted_data_etype: i32,
    },
    /// A key did not match the encrypted AP-REP data etype.
    #[error(
        "key etype {key_etype} does not match AP-REP encrypted data etype {encrypted_data_etype}"
    )]
    ApRepKeyEtypeMismatch {
        /// Reply key encryption type.
        key_etype: i32,
        /// AP-REP encrypted data encryption type.
        encrypted_data_etype: i32,
    },
    /// A key did not match the encrypted AP-REQ authenticator etype.
    #[error(
        "key etype {key_etype} does not match AP-REQ authenticator etype {encrypted_data_etype}"
    )]
    ApReqKeyEtypeMismatch {
        /// Reply key encryption type.
        key_etype: i32,
        /// AP-REQ authenticator encryption type.
        encrypted_data_etype: i32,
    },
    /// A key did not match the encrypted ticket data etype.
    #[error(
        "key etype {key_etype} does not match Ticket encrypted data etype {encrypted_data_etype}"
    )]
    TicketKeyEtypeMismatch {
        /// Service key encryption type.
        key_etype: i32,
        /// Ticket encrypted data encryption type.
        encrypted_data_etype: i32,
    },
    /// A successful kpasswd reply did not contain AP-REP.
    #[error("kpasswd reply does not contain AP-REP")]
    MissingKpasswdApRep,
    /// An authenticated kpasswd response violated its contextual control policy.
    #[error("invalid kpasswd response control: {0}")]
    KpasswdReplyControl(&'static str),
    /// Delivery or reply validation failed after entering a mutation exchange.
    #[error("password mutation outcome is unknown: {0}")]
    KpasswdOutcomeUnknown(#[source] Box<Self>),
    /// An earlier password change may have reached the server and its outcome was never
    /// confirmed: it is not replayed until the caller verifies it and acknowledges it.
    #[error("an earlier password change may have reached the server; verify its outcome first")]
    PasswordChangePending,
    /// A kpasswd AP-REP did not echo the AP-REQ authenticator timestamp.
    #[error("kpasswd AP-REP timestamp mismatch: expected {expected:?}, got {actual:?}")]
    KpasswdApRepTimestampMismatch {
        /// Timestamp supplied by the AP-REQ authenticator.
        expected: SystemTime,
        /// Timestamp supplied by AP-REP.
        actual: SystemTime,
    },
    /// The KDC-REP client principal did not match the KDC-REQ.
    #[error("KDC-REP client {actual} does not match requested client {expected}")]
    PrincipalMismatch {
        /// Expected request client.
        expected: String,
        /// Actual reply client.
        actual: String,
    },
    /// The KDC-REP service principal did not match the KDC-REQ.
    #[error("KDC-REP service {actual} does not match requested service {expected}")]
    ServicePrincipalMismatch {
        /// Expected request service.
        expected: String,
        /// Actual reply service.
        actual: String,
    },
    /// Authenticated reply times violate ordering or the requested bounds.
    #[error("KDC reply violates requested ticket time constraints")]
    ReplyTimeConstraint,
    /// Authenticated reply grants ticket capabilities not requested by the client.
    #[error("KDC reply violates requested ticket flag constraints")]
    ReplyFlagConstraint,
    /// The KDC-REP nonce did not match the KDC-REQ nonce.
    #[error("KDC-REP nonce {actual} does not match KDC-REQ nonce {expected}")]
    NonceMismatch {
        /// Expected request nonce.
        expected: u32,
        /// Actual reply nonce.
        actual: u32,
    },
    /// The AS-REP did not include the encrypted padata required by FAST negotiation.
    #[error("KDC did not respond appropriately to FAST negotiation")]
    InvalidFastNegotiationResponse,
    /// The FAST negotiation checksum of an AS-REP or TGS-REP used a checksum
    /// type other than the one its reply key requires (RFC 6806 section 11).
    #[error("unsupported Kerberos checksum type: {0}")]
    UnsupportedChecksumType(i32),
    /// The AS-REP FAST negotiation checksum was invalid.
    #[error("KDC FAST negotiation response checksum invalid")]
    FastNegotiationChecksumMismatch,
    /// A TGS referral chain exceeded the configured limit.
    #[error("TGS referral depth exceeded maximum {max}")]
    MaxReferralDepth {
        /// Maximum number of referrals followed.
        max: usize,
    },
    /// The KDC's `PA-S4U-X509-USER` reply does not match the request: a
    /// missing element, another nonce, an invalid checksum or no user name
    /// (MIT 1.22.2 `KRB5_KDCREP_MODIFIED`, `s4u_creds.c:272-397`).
    #[error("the S4U2Self reply identity does not match the request")]
    S4uReplyModified,
    /// `verify_init_creds` found no key to verify with (no `host/*` principal
    /// or no key for the named server) and `verify_ap_req_nofail` is not
    /// `false` (MIT 1.22.2 `vfy_increds.c:296-314`).
    #[error("no host key to verify the initial credentials with")]
    VerifyInitCredsNoHostKey,
    /// The host keytab refused the AP-REQ of `verify_init_creds`: the
    /// credentials did not come from the KDC that shares the host key.
    #[error("the host keytab refused the initial credentials: {0}")]
    VerifyInitCredsRejected(#[source] Box<Service>),
    /// The configured cross-realm path cannot be used (WP-11).
    #[error("routing error: {0}")]
    Routing(#[from] Routing),
    /// A TGS referral named a realm the exchange already visited (MIT 1.22.2
    /// `get_creds.c:612-614`).
    #[error("cross-realm referral loop through {realm}")]
    ReferralLoop {
        /// The realm referred to a second time.
        realm: String,
    },
    /// A TGS referral reply did not contain a usable `krbtgt/<realm>` service.
    #[error("invalid TGS referral ticket service: {service}")]
    InvalidReferralTicket {
        /// Referral ticket service name.
        service: String,
    },
    /// An inserted session belongs to a different client realm or component sequence.
    #[cfg(feature = "tokio")]
    #[error("cached session client does not match the configured client identity")]
    CacheClientMismatch,
    /// A renewal helper expected a `krbtgt/<realm>` TGT session.
    #[error("expected a TGT session, got service {service}")]
    InvalidTgtSession {
        /// Actual session service name.
        service: String,
    },
    /// Explicit renewal requires a valid renewable ticket with a live renewal horizon.
    #[cfg(feature = "tokio")]
    #[error("cached ticket is not eligible for renewal")]
    TicketNotRenewable,
    /// Blocking Negotiate requires a live runtime outside an entered Tokio context.
    #[cfg(all(feature = "tokio", feature = "spnego"))]
    #[error(
        "blocking Negotiate runtime is unavailable; use the async Negotiate client inside Tokio"
    )]
    BlockingRuntimeUnavailable,
    /// A high-level client operation needs password/keytab credentials.
    #[cfg(feature = "tokio")]
    #[error("no password or keytab credentials are configured")]
    NoClientCredentials,
    /// A configured credential-cache load needs `default_ccache_name`.
    #[cfg(feature = "tokio")]
    #[error("config.libdefaults.default_ccache_name is not configured")]
    NoDefaultCCacheName,
    /// The default client keytab name could not be read from `KRB5_CLIENT_KTNAME`.
    #[cfg(feature = "tokio")]
    #[error("default client keytab name could not be read from KRB5_CLIENT_KTNAME: {0}")]
    DefaultClientKeytabName(#[source] env::VarError),
    /// A high-level client operation needs a non-empty client principal name.
    #[cfg(feature = "tokio")]
    #[error("client principal name is not configured")]
    MissingClientName,
    /// A high-level client operation needs a non-empty client realm.
    #[cfg(feature = "tokio")]
    #[error("client principal realm is not configured")]
    MissingClientRealm,
    /// KDC DNS lookup is disabled and no configured KDC exists for the realm.
    #[cfg(feature = "tokio")]
    #[error("no configured KDC exists for realm {realm}")]
    NoConfiguredKdc {
        /// Realm missing a configured KDC.
        realm: String,
    },
    /// A high-level client operation needs a current TGT.
    #[cfg(feature = "tokio")]
    #[error("no TGT session is available")]
    NoTgtSession,
    /// S4U processing requires frontend keys to authenticate the delegated user.
    #[error("S4U delegated identity requires frontend service keys")]
    DelegationKeyRequired,
    /// The decrypted evidence or self ticket names a different delegated user.
    #[error("S4U ticket client differs from the requested delegated identity")]
    DelegationPrincipalMismatch,
    /// SPNEGO/GSSAPI token processing failed.
    #[cfg(feature = "spnego")]
    #[error("SPNEGO error: {0}")]
    Spnego(#[from] Spnego),
    /// Crypto operation failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] Crypto),
    /// Keytab operation failed.
    #[error("keytab error: {0}")]
    Keytab(#[from] Keytab),
    /// Configuration parsing or lookup failed.
    #[error("config error: {0}")]
    Config(#[from] Config),
    /// Credential cache operation failed.
    #[error("ccache error: {0}")]
    CCache(#[from] Ccache),
    /// kadmin protocol processing failed.
    #[error("kadmin error: {0}")]
    Kadmin(#[from] Kadmin),
    /// Kerberos message helper failed.
    #[error("message error: {0}")]
    Message(#[from] Messages),
    /// Random byte generation failed.
    #[error("random byte generation failed: {0}")]
    Random(#[from] getrandom::Error),
    /// A Kerberos time could not be represented as a `SystemTime`.
    #[error("Kerberos time overflows SystemTime")]
    TimeOverflow,
    /// The KDC returned an application-level error.
    #[error("KDC returned error code {}", .0.error_code())]
    Kdc(Box<KdcError>),
    /// No supported preauthentication encryption type was available.
    #[error("no supported preauthentication encryption type for requested list {requested:?}")]
    NoSupportedPreauthEtype {
        /// Requested encryption type ids.
        requested: Vec<i32>,
    },
    /// Tokio transport I/O failed.
    #[cfg(feature = "tokio")]
    #[error("KDC transport I/O failed: {0}")]
    Io(#[from] io::Error),
    /// A configured KDC endpoint could not be parsed.
    #[cfg(feature = "tokio")]
    #[error("invalid KDC endpoint: {0}")]
    InvalidKdcEndpoint(String),
    /// DNS resolver construction failed.
    #[cfg(feature = "tokio")]
    #[error("DNS resolver configuration failed: {0}")]
    DnsResolverConfig(String),
    /// Host acquisition found no host name the caller's policy approves: every
    /// canonical form of `host` other than the host itself was refused.
    #[cfg(feature = "tokio")]
    #[error("no approved canonical name for host {host}")]
    HostNameNotApproved {
        /// The requested host, folded to lower case.
        host: String,
    },
    /// A registered server locator or host-realm mapper failed or gave a
    /// refused answer.
    #[cfg(feature = "tokio")]
    #[error("server location extension failed: {0}")]
    Locate(#[source] Box<Extensions>),
    /// A DNS SRV lookup failed (not merely found no record, except for the last
    /// resort lookups of the KDC and `_kerberos-adm` services), or, with
    /// [`Tokio::with_dns_server`], the lookup of an SRV target failed for another
    /// reason than the name having no address data.
    ///
    /// [`Tokio::with_dns_server`]: crate::client::transport::Tokio::with_dns_server
    #[cfg(feature = "tokio")]
    #[error("DNS SRV lookup failed for {realm} over {protocol:?}: {message}")]
    DnsSrvLookup {
        /// Realm being discovered.
        realm: String,
        /// Protocol of the failed discovery, which picks the SRV label: `Udp`
        /// and `Auto` query `_udp`, `Tcp` queries `_tcp`. It is not always the
        /// requested protocol: a KDC request with `Auto` reports its second pass
        /// (see [`Tokio::send_to_realm`]), and the `_kerberos-adm._tcp` fallback
        /// of a kpasswd call reports `Tcp`, the label it queried, whatever
        /// protocol was requested (the failure of that fallback's targets is a
        /// [`Client::KdcEndpointFailures`] of the requested protocol).
        ///
        /// [`Tokio::send_to_realm`]: crate::client::transport::Tokio::send_to_realm
        protocol: KdcProtocol,
        /// The resolver's error for the SRV lookup, or for the lookup of one
        /// SRV target (`target <name>: <error>`).
        message: String,
    },
    /// A root SRV target declares the service named in `service` unavailable.
    #[cfg(feature = "tokio")]
    #[error("DNS service {service} is unavailable for {realm}")]
    DnsServiceUnavailable {
        /// Queried service label.
        service: String,
        /// Realm being discovered.
        realm: String,
    },
    /// No KDC endpoints were discovered for a realm.
    #[cfg(feature = "tokio")]
    #[error("no KDC endpoints discovered for {realm} over {protocol:?}")]
    NoKdcEndpoints {
        /// Realm being discovered.
        realm: String,
        /// Protocol of the failed discovery: the requested one, except that a
        /// KDC request with `Auto` reports its second pass (see
        /// [`Tokio::send_to_realm`]).
        ///
        /// [`Tokio::send_to_realm`]: crate::client::transport::Tokio::send_to_realm
        protocol: KdcProtocol,
    },
    /// Every endpoint of the last pass that ran failed, or, with
    /// [`Tokio::with_dns_server`], discovery found no endpoint and none of the
    /// targets of at least one published record set resolved (MIT:
    /// `KRB5_KDC_UNREACH`).
    ///
    /// [`Tokio::with_dns_server`]: crate::client::transport::Tokio::with_dns_server
    #[cfg(feature = "tokio")]
    #[error("all KDC endpoints for {realm} over {protocol:?} failed: {failures:?}")]
    KdcEndpointFailures {
        /// Realm being contacted.
        realm: String,
        /// Protocol of that pass or of the failed discovery: the requested one,
        /// except with `Auto`, where a KDC request reports its second pass (see
        /// [`Tokio::send_to_realm`]) and a kpasswd request its last pass (see
        /// [`Tokio::send_to_kpasswd_realm`]); `Auto` itself is reported only for
        /// a kpasswd discovery failure.
        ///
        /// [`Tokio::send_to_realm`]: crate::client::transport::Tokio::send_to_realm
        /// [`Tokio::send_to_kpasswd_realm`]: crate::client::transport::Tokio::send_to_kpasswd_realm
        protocol: KdcProtocol,
        /// One `authority: error` entry per endpoint of that pass, in the order
        /// tried; for a discovery failure, one entry per published record set
        /// none of whose targets resolved (`target <name>: <reason>` joined by
        /// `; `), the UDP set first.
        failures: Vec<String>,
    },
    /// Tokio transport exchange timed out.
    #[cfg(feature = "tokio")]
    #[error("KDC transport timed out after {0:?}")]
    TransportTimeout(Duration),
    /// UDP cannot carry the encoded request as one datagram.
    #[cfg(feature = "tokio")]
    #[error("KDC UDP request length {actual} exceeds datagram limit {limit}")]
    UdpRequestTooLarge {
        /// Encoded request byte length.
        actual: usize,
        /// Maximum UDP payload length.
        limit: usize,
    },
    /// UDP response exceeded the configured acceptance limit.
    #[cfg(feature = "tokio")]
    #[error("KDC UDP response exceeds configured limit {limit}")]
    UdpResponseTooLarge {
        /// Maximum accepted response byte length.
        limit: usize,
    },
    /// KDC TCP frame has the RFC 4120 reserved high bit set.
    #[cfg(feature = "tokio")]
    #[error("KDC TCP frame has its reserved high bit set")]
    TcpReservedBitSet,
    /// TCP request length could not fit the service's length prefix.
    #[cfg(feature = "tokio")]
    #[error("TCP request length {actual} exceeds the service framing limit")]
    TcpRequestTooLarge {
        /// Encoded request byte length.
        actual: usize,
    },
    /// TCP response length exceeded the configured limit.
    #[cfg(feature = "tokio")]
    #[error("KDC TCP response length {actual} exceeds configured limit {limit}")]
    TcpResponseTooLarge {
        /// Response length from the TCP frame header.
        actual: u32,
        /// Maximum accepted response body length.
        limit: usize,
    },
    /// KDC returned no bytes.
    #[cfg(feature = "tokio")]
    #[error("KDC returned an empty response")]
    EmptyKdcResponse,
    /// KDC transport failed.
    #[error("KDC transport failed: {0}")]
    Transport(String),
    /// A stepwise exchange received an input it does not expect now.
    #[error("the exchange expected {expected}")]
    UnexpectedStepInput {
        /// What the exchange expected.
        expected: &'static str,
    },
    /// A stepwise exchange exceeded its round-trip bound (MIT `KRB5_GET_IN_TKT_LOOP`).
    #[error("the exchange exceeded {limit} KDC round trips")]
    ExchangeLoop {
        /// The bound.
        limit: usize,
    },
    /// The exchange's responder failed to answer a prompt.
    #[error("the responder failed to answer a prompt")]
    Responder(#[source] ProviderError),
    /// A registered preauthentication mechanism failed or its output was refused.
    #[error("a registered preauthentication mechanism failed")]
    Preauth(#[source] Extensions),
    /// The FAST armor failed to wrap a request or unwrap a reply.
    #[error("the FAST armor failed")]
    Armor(#[source] ProviderError),
    /// SPAKE preauthentication failed (RFC 9588); there is no fallback to
    /// another mechanism after it (MIT `disable_fallback`).
    #[error("SPAKE preauthentication failed")]
    Spake(#[from] Spake),
    /// OTP preauthentication failed or was refused before a request was sent
    /// (RFC 6560); there is no retry of an OTP value.
    #[error("OTP preauthentication failed")]
    Otp(#[from] Otp),
    /// PKINIT or anonymous PKINIT failed (RFC 4556, RFC 6112).
    ///
    /// There is no fallback to another mechanism after it (MIT
    /// `disable_fallback`).
    #[error("PKINIT preauthentication failed")]
    Pkinit(#[from] Pkinit),
    /// Encrypted timestamp is disabled for the client realm
    /// (`[realms] disable_encrypted_timestamp`), and the KDC offered no other
    /// usable mechanism.
    #[error("encrypted timestamp is disabled for realm {realm}")]
    EncryptedTimestampDisabled {
        /// The client realm.
        realm: String,
    },
    /// `noaddresses = false` needs request addresses, and interface addresses
    /// are not enumerated: configure `extra_addresses`.
    #[error("noaddresses = false requires extra_addresses; interface addresses are not enumerated")]
    NoRequestAddresses,
    /// The MS-KKDCP KDC proxy failed.
    #[error("the KDC proxy failed: {0}")]
    KdcProxy(#[from] KdcProxy),
}
/// Configuration parsing error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Config {
    /// Strict parsing rejects unrecognized sections.
    #[error("unknown configuration section: {section}")]
    UnknownSection {
        /// Section name as written in the profile.
        section: String,
    },
    /// Strict parsing rejects unrecognized relation paths.
    #[error("unknown configuration relation path: {}", path.join("/"))]
    UnknownRelation {
        /// Selected profile path.
        path: Vec<String>,
    },
    /// Strict parsing rejects removed preauthentication preferences.
    #[error("ignored preauthentication preference: {id}")]
    IgnoredPreauthType {
        /// Removed preference identifier.
        id: i32,
    },
    /// Strict parsing rejects configuration intended only for server processes.
    #[error("server-only configuration section: {section}")]
    ServerOnly {
        /// Canonical section name.
        section: &'static str,
    },
    /// An unsupported relation requires stricter behavior or strict parsing.
    #[error("relation {relation} is not yet effective; requires {package}")]
    NotYetEffective {
        /// Selected relation.
        relation: &'static str,
        /// Work package owning its runtime consumer.
        package: &'static str,
    },
    /// A relation's consumer needs a leaf Cargo feature this build lacks
    /// (strict mode).
    #[error("relation {relation} needs the `{feature}` Cargo feature")]
    FeatureUnavailable {
        /// Selected relation.
        relation: &'static str,
        /// The leaf feature.
        feature: &'static str,
    },
    /// A relation names behaviour this library excludes permanently by an
    /// owner decision (strict mode).
    #[error("relation {relation} is out of scope ({decision})")]
    OutOfScope {
        /// Selected relation.
        relation: &'static str,
        /// The owner decision that excludes it: `D1`, `D2` or `D1/D3`.
        decision: &'static str,
    },
    /// A local-address list contains a malformed IP address.
    #[error("invalid extra address: {0}")]
    InvalidAddress(String),
    /// Dynamic profile and plugin providers are not loaded by this crate.
    #[error("dynamic configuration modules are unsupported")]
    UnsupportedDynamicModule,
    /// An enctype expression contains a name or operator outside MIT's vocabulary.
    #[error("unknown enctype expression token: {token}")]
    UnknownEnctype {
        /// Original token with its prefix and spelling intact.
        token: String,
    },
    /// An explicit positive legacy term lacks its family's runtime permission.
    #[error("disabled enctype expression token: {token}")]
    DisabledEnctype {
        /// Original token with its prefix and spelling intact.
        token: String,
    },
    /// An explicit positive insecure term is permanently forbidden.
    #[error("enctype expression token {token}: {source}")]
    RejectedEnctype {
        /// Original token with its prefix and spelling intact.
        token: String,
        /// Permanent typed policy refusal, retained as a causal error.
        source: Policy,
    },
    /// Strict mode rejects a secure encryption type that is not implemented yet.
    #[error("unsupported secure enctype expression token {token}; unavailable until {until}")]
    UnsupportedSecureEnctype {
        /// Original token with its prefix and spelling intact.
        token: String,
        /// Work package implementing this encryption type.
        until: &'static str,
    },
    /// The resolved expression cannot permit any encryption type.
    #[error("enctype expression resolves to an empty list")]
    EmptyEnctypeExpression,
    /// Input exceeds the expression parser's allocation budget.
    #[error("enctype expression exceeds {maximum} bytes")]
    EnctypeExpressionTooLarge {
        /// Maximum accepted UTF-8 byte length.
        maximum: usize,
    },
    /// A requested cryptographic feature violates permanent policy.
    #[error("policy error: {0}")]
    Policy(#[from] Policy),
    /// A named top-level configuration file could not be resolved or read.
    #[error("configuration file {path} could not be read: {source}")]
    File {
        /// The path requested by the caller.
        path: PathBuf,
        /// The causal filesystem error.
        source: io::Error,
    },
    /// File loading failed.
    #[error("configuration file could not be read: {0}")]
    Io(#[from] io::Error),
    /// The default config path list could not be read from `KRB5_CONFIG`.
    #[error("default configuration path list is not set in KRB5_CONFIG")]
    DefaultConfigName,
    /// A config path list contained no usable paths.
    #[error("configuration path list is empty")]
    EmptyConfigPathList,
    /// No environment or platform-default config file exists.
    #[error("no default Kerberos configuration file found")]
    NoDefault,
    /// A section line was syntactically invalid.
    #[error("invalid {section} section line {line}: {text}")]
    InvalidLine {
        /// Section name.
        section: &'static str,
        /// One-based line number.
        line: usize,
        /// Line text after comment stripping.
        text: String,
    },
    /// A boolean value was invalid.
    #[error("invalid boolean value: {0}")]
    InvalidBoolean(String),
    /// A duration value was invalid.
    #[error("invalid time duration value: {0}")]
    InvalidDuration(String),
    /// `default_rcache_name` is not a MIT replay-cache name of a known type.
    #[error("invalid replay cache name: {0}")]
    InvalidReplayCacheName(String),
    /// A duration value overflowed.
    #[error("time duration overflow: {0}")]
    DurationOverflow(String),
    /// An integer value was invalid.
    #[error("invalid integer for {key} on line {line}: {value}")]
    InvalidInteger {
        /// Line number.
        line: usize,
        /// Config key.
        key: String,
        /// Config value.
        value: String,
    },
    /// The realms section has invalid brace structure.
    #[error("invalid realms section: {0}")]
    InvalidRealmsSection(String),
    /// The requested realm is absent.
    #[error("realm not configured: {0}")]
    NoRealm(String),
    /// The requested realm has no configured KDCs.
    #[error("realm has no configured KDCs: {0}")]
    NoKdc(String),
    /// The requested realm has no configured password-change servers.
    #[error("realm has no configured kpasswd servers: {0}")]
    NoKpasswdServer(String),
    /// Include or subsection nesting reached past [`crate::config::MAX_INCLUDE_DEPTH`].
    #[error("include or subsection nesting reached depth {depth}, past the limit of {limit}")]
    IncludeTooDeep {
        /// The depth the parser reached.
        depth: usize,
        /// The documented limit.
        limit: usize,
    },
    /// More files were included than [`crate::config::MAX_INCLUDE_FILES`] allows.
    #[error("configuration included {count} files, past the limit of {limit}")]
    IncludeTooMany {
        /// The number of files the parser reached.
        count: usize,
        /// The documented limit.
        limit: usize,
    },
    /// Included files carried more bytes than [`crate::config::MAX_INCLUDE_BYTES`] allows.
    #[error("included configuration reached {bytes} bytes, past the limit of {limit}")]
    IncludeTooLarge {
        /// The number of included bytes the parser read. A single file that
        /// overshoots the limit is read only up to the limit plus one byte, so
        /// this is the limit plus one in that case.
        bytes: usize,
        /// The documented limit.
        limit: usize,
    },
    /// An include chain returned to a file or directory it is already reading.
    #[error("include cycle: {path} is already being read")]
    IncludeCycle {
        /// The file or directory the cycle returned to.
        path: PathBuf,
    },
    /// An `include` directive named a file that could not be read, or that is
    /// not UTF-8 text.
    #[error("include file {path} could not be read: {source}")]
    IncludeFile {
        /// The file the directive named.
        path: PathBuf,
        /// Why it could not be used.
        source: io::Error,
    },
    /// An `includedir` directive, or a directory handed to
    /// `Config::load_paths`, named a directory that could not be listed.
    #[error("includedir {path} could not be listed: {source}")]
    IncludeDir {
        /// The directory the directive named.
        path: PathBuf,
        /// Why it could not be listed.
        source: io::Error,
    },
    /// An explicit request enctype list names an enctype outside the explicit
    /// `permitted_enctypes` allowlist.
    #[error("[libdefaults] {key} lists {enctype}, which permitted_enctypes does not permit")]
    EnctypeNotPermitted {
        /// Request-list key: `default_tkt_enctypes` or `default_tgs_enctypes`.
        key: &'static str,
        /// The configured enctype name.
        enctype: String,
    },
}
/// Errors produced by Kerberos cryptographic operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum Crypto {
    /// A requested cryptographic feature violates permanent policy.
    #[error("policy error: {0}")]
    Policy(#[from] Policy),
    /// AES key material length did not match the selected encryption type.
    #[error("invalid key length: expected {expected} bytes, got {actual}")]
    InvalidKeyLength {
        /// Expected key length.
        expected: usize,
        /// Actual key length.
        actual: usize,
    },
    /// Confounder length did not match the selected encryption type.
    #[error("invalid confounder length: expected {expected} bytes, got {actual}")]
    InvalidConfounderLength {
        /// Expected confounder length.
        expected: usize,
        /// Actual confounder length.
        actual: usize,
    },
    /// Ciphertext was too short for the requested operation.
    #[error("ciphertext too short: expected at least {minimum} bytes, got {actual}")]
    CiphertextTooShort {
        /// Minimum accepted byte length.
        minimum: usize,
        /// Actual byte length.
        actual: usize,
    },
    /// Decrypted plaintext was too short to remove a confounder.
    #[error("plaintext too short: expected at least {minimum} bytes, got {actual}")]
    PlaintextTooShort {
        /// Minimum accepted byte length.
        minimum: usize,
        /// Actual byte length.
        actual: usize,
    },
    /// Message integrity verification failed.
    #[error("integrity verification failed")]
    IntegrityCheckFailed,
    /// String-to-key parameters were not four bytes of hex.
    #[error("invalid s2kparams length: expected 8 hex characters, got {0}")]
    InvalidS2kParamsLength(usize),
    /// String-to-key parameter hex was invalid.
    #[error("invalid s2kparams hex byte: {0}")]
    InvalidS2kParamsHex(char),
    /// RFC3962's zero iteration value means 2^32 iterations and is not run.
    #[error("s2kparams iteration count zero is not supported")]
    UnsupportedIterationCountZero,
    /// The peer's password-derivation work factor exceeds the local resource policy.
    #[error("s2kparams iteration count {actual} exceeds maximum {maximum}")]
    IterationCountTooHigh {
        /// Inclusive local work ceiling.
        maximum: u32,
        /// Requested iteration count.
        actual: u32,
    },
    /// RC4-HMAC string-to-key requires a UTF-8 password byte string.
    #[error("RC4-HMAC string-to-key secret must be valid UTF-8")]
    InvalidStringToKeySecret,
    /// DES3 string-to-key parameters are required to be empty.
    #[error("DES3 string-to-key parameters must be empty")]
    NonEmptyDes3S2kParams,
    /// DES3 random-to-key seed material length did not match RFC3961.
    #[error("invalid random-to-key seed length: expected {expected} bytes, got {actual}")]
    InvalidSeedLength {
        /// Expected seed length.
        expected: usize,
        /// Actual seed length.
        actual: usize,
    },
    /// The n-fold input was empty.
    #[error("n-fold input must not be empty")]
    EmptyNfoldInput,
    /// The n-fold usage constant was empty.
    #[error("key usage constant must not be empty")]
    EmptyUsage,
    /// An RFC3961 derivation constant exceeds the cipher block size.
    #[error("derivation constant length {actual} exceeds maximum {maximum}")]
    DerivationConstantTooLong {
        /// Cipher block size in bytes.
        maximum: usize,
        /// Supplied constant length in bytes.
        actual: usize,
    },
    /// The n-fold output size was not a positive whole number of bytes.
    #[error("invalid n-fold output bit count: {0}")]
    InvalidNfoldOutputBits(usize),
    /// Data encryption needs at least one plaintext byte.
    #[error("plaintext must not be empty")]
    EmptyPlaintext,
    /// CBC ciphertext was not an exact multiple of the selected block size.
    #[error("ciphertext length {actual} is not a multiple of {block_size}")]
    InvalidCiphertextBlockSize {
        /// Required block size.
        block_size: usize,
        /// Actual ciphertext length.
        actual: usize,
    },
    /// A PRF+ output request exceeds what its counter or the local bound allows.
    #[error("PRF+ output of {requested} bytes exceeds the maximum of {maximum}")]
    PrfOutputTooLong {
        /// Largest accepted output length in bytes.
        maximum: usize,
        /// Requested output length in bytes.
        requested: usize,
    },
}
/// Extension registration, provider output and profile-module errors.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Extensions {
    /// A provider id is empty, too long or uses a byte outside `[A-Za-z0-9_.-]`.
    #[error("invalid {interface} extension id {id}")]
    InvalidId {
        /// The interface.
        interface: Interface,
        /// The refused id.
        id: String,
    },
    /// The interface already has a provider with this id.
    #[error("{interface} extension {id} is already registered")]
    DuplicateId {
        /// The interface.
        interface: Interface,
        /// The duplicate id.
        id: String,
    },
    /// The interface already holds its maximum number of providers.
    #[error("more than {limit} {interface} extensions")]
    TooManyProviders {
        /// The interface.
        interface: Interface,
        /// The bound.
        limit: usize,
    },
    /// A provider's registration data breaks the interface's rules.
    #[error("{interface} extension {id} cannot be registered: {reason}")]
    InvalidRegistration {
        /// The interface.
        interface: Interface,
        /// The provider id.
        id: String,
        /// Which rule.
        reason: &'static str,
    },
    /// A store prefix is built in or held by another provider.
    ///
    /// Prefixes are compared without regard to ASCII letter case.
    #[error("store extension {id} cannot claim the taken prefix {prefix}")]
    PrefixTaken {
        /// The provider id.
        id: String,
        /// The claimed prefix.
        prefix: String,
    },
    /// A provider failed.
    #[error("{interface} extension {id} failed")]
    CallFailed {
        /// The interface.
        interface: Interface,
        /// The provider id.
        id: String,
        /// The provider's error.
        source: ProviderError,
    },
    /// A provider's output breaks the interface's shape.
    #[error("{interface} extension {id} returned malformed output: {reason}")]
    MalformedOutput {
        /// The interface.
        interface: Interface,
        /// The provider id.
        id: String,
        /// Which rule.
        reason: &'static str,
    },
    /// A provider's output exceeds a bound.
    #[error("{interface} extension {id} output exceeds its bound of {limit}")]
    OutputTooLarge {
        /// The interface.
        interface: Interface,
        /// The provider id.
        id: String,
        /// The bound.
        limit: usize,
    },
    /// A preauthentication session ran out of rounds.
    #[error("client preauthentication exceeded {limit} rounds")]
    TooManyRounds {
        /// The bound.
        limit: usize,
    },
    /// The permanent or runtime enctype policy refused a mechanism's PA-DATA.
    #[error("clpreauth extension {id} output refused: {source}")]
    PolicyRefused {
        /// The mechanism id.
        id: String,
        /// The policy refusal.
        source: Policy,
    },
    /// The configuration a profile names is invalid, or `module` is unresolved.
    #[error("config error: {0}")]
    Config(#[from] Config),
}
#[cfg(feature = "messages")]
/// RFC 6113 FAST armor and encrypted-challenge failures. The stepwise AS
/// exchange reports them as [`Client::Armor`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Fast {
    /// FAST is required and no armor ticket for the realm is available.
    #[error("FAST is required but no armor ticket for realm {realm} is available")]
    ArmorUnavailable {
        /// The realm of the request.
        realm: String,
    },
    /// The armor ticket is not the ticket-granting ticket of the request's realm.
    #[error("the armor ticket is for {actual}, not the TGS of realm {realm}")]
    ArmorTicket {
        /// The realm of the request.
        realm: String,
        /// The armor ticket's service.
        actual: String,
    },
    /// The anonymous-armor provider failed.
    #[error("the anonymous armor provider failed")]
    AnonymousArmor(#[source] ProviderError),
    /// A reply to an armored request carries no PA-FX-FAST.
    #[error("the KDC reply to an armored request is not armored")]
    Unarmored,
    /// An armored request was answered by a KRB-ERROR without PA-FX-FAST.
    #[error("the KDC answered an armored request with unarmored error {code}")]
    UnarmoredError {
        /// The unauthenticated error code.
        code: i32,
    },
    /// The armored AS-REP carries no `KrbFastFinished`.
    #[error("the armored KDC reply has no KrbFastFinished")]
    MissingFinished,
    /// The finished ticket checksum does not verify.
    #[error("the FAST ticket checksum does not verify: the ticket was modified")]
    TicketChecksum,
    /// A FAST checksum is not the armor key's mandatory checksum type.
    #[error("the FAST checksum has type {actual}, not the armor key's type {expected}")]
    ChecksumType {
        /// The armor key's mandatory checksum type.
        expected: i32,
        /// The received type.
        actual: i32,
    },
    /// The `KrbFastResponse` answers another request.
    #[error("the FAST response nonce {actual} does not match the request nonce {expected}")]
    NonceMismatch {
        /// The request nonce.
        expected: u32,
        /// The response nonce.
        actual: u32,
    },
    /// A FAST structure breaks an RFC 6113 rule.
    #[error("malformed FAST {structure}: {reason}")]
    Malformed {
        /// The structure.
        structure: &'static str,
        /// The broken rule.
        reason: &'static str,
    },
    /// A KDC cookie exceeds the bound.
    #[error("the KDC cookie exceeds {limit} bytes")]
    CookieTooLarge {
        /// The bound in bytes.
        limit: usize,
    },
    /// The armored exchange exceeded its round bound.
    #[error("the FAST exchange exceeded {limit} rounds")]
    TooManyRounds {
        /// The bound.
        limit: usize,
    },
    /// The reply to an encrypted challenge lacks what RFC 6113 section 5.4.6 requires.
    #[error("the KDC reply to the encrypted challenge lacks {what}")]
    ChallengeReply {
        /// The missing or invalid element.
        what: &'static str,
    },
    /// The exchange ran without armor where armor is required.
    #[error("the exchange ran without FAST armor")]
    NotArmored,
    /// A DER encoding or decoding failed.
    #[error("failed to {action} {target}: {message}")]
    Codec {
        /// `encode` or `decode`.
        action: &'static str,
        /// The structure.
        target: &'static str,
        /// The codec's message.
        message: String,
    },
    /// A FAST key has an enctype this library does not implement.
    #[error("FAST key enctype {0} is not implemented")]
    UnsupportedEtype(i32),
    /// A key, checksum or cipher operation failed, or policy refused its enctype.
    #[error("FAST cryptography failed: {0}")]
    Crypto(#[from] Crypto),
    /// The OS random source failed.
    #[error("random generation failed: {0}")]
    Random(#[from] getrandom::Error),
}
/// Trace destination and sink errors.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Trace {
    /// A trace destination (`KRB5_TRACE` or a caller's path) is not usable as given.
    #[error("trace destination refused: {reason}")]
    InvalidDestination {
        /// Why the destination was refused.
        reason: &'static str,
    },
    /// The trace file could not be opened for appending.
    #[error("cannot open the trace file {path}: {source}")]
    Open {
        /// The destination path.
        path: PathBuf,
        /// The operating system's failure.
        #[source]
        source: io::Error,
    },
    /// A sink could not write an event.
    #[error("trace output failed: {0}")]
    Write(#[from] io::Error),
    /// A sink declined an event.
    #[error("the trace sink refused the event")]
    Refused,
}
#[cfg(feature = "http")]
/// HTTP Negotiate adapter error.
#[derive(thiserror::Error)]
#[non_exhaustive]
pub enum Http {
    /// The request did not contain an Authorization header.
    #[error("missing HTTP Authorization header")]
    MissingAuthorization,
    /// The response did not contain a WWW-Authenticate header.
    #[error("missing HTTP WWW-Authenticate header")]
    MissingWwwAuthenticate,
    /// No Negotiate challenge was present in WWW-Authenticate headers.
    #[error("missing HTTP Negotiate challenge")]
    MissingNegotiateChallenge,
    /// The request or response header could not be represented as a string.
    #[error("invalid HTTP header value: {0}")]
    InvalidHeader(#[from] ToStrError),
    /// A response header value could not be constructed.
    #[error("invalid HTTP response header value: {0}")]
    InvalidHeaderValue(#[from] InvalidHeaderValue),
    /// SPNEGO/GSSAPI token processing failed.
    #[error("SPNEGO error: {0}")]
    Spnego(#[from] Spnego),
    /// Tokio client processing failed while building an HTTP request.
    #[cfg(feature = "tokio")]
    #[error("client error: {0}")]
    Client(#[from] Client),
    /// Keytab loading failed while constructing HTTP middleware.
    #[cfg(feature = "tower")]
    #[error("keytab error: {0}")]
    Keytab(#[from] Keytab),
}
#[cfg(feature = "messages")]
/// kadmin message parsing errors.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum Kadmin {
    /// A requested cryptographic feature violates permanent policy.
    #[error("policy error: {0}")]
    Policy(#[from] Policy),
    /// The frame is too short to contain the kpasswd header.
    #[error("kadmin reply frame is too short: {actual} bytes")]
    FrameTooShort {
        /// Actual byte length.
        actual: usize,
    },
    /// The declared kpasswd frame length is shorter than the fixed header or
    /// differs from the supplied frame length because it has trailing bytes.
    #[error("invalid kadmin reply message length: {0}")]
    InvalidMessageLength(u16),
    /// Kerberos message field did not contain the expected value.
    #[error("invalid {field}: expected {expected}, got {actual}")]
    InvalidKerberosMessage {
        /// Field name.
        field: &'static str,
        /// Expected value.
        expected: i32,
        /// Actual value.
        actual: String,
    },
    /// The frame prefix length exceeds the supplied byte slice.
    #[error("truncated kadmin reply frame: expected {expected} bytes, got {actual}")]
    TruncatedFrame {
        /// Expected frame byte length.
        expected: usize,
        /// Actual supplied byte length.
        actual: usize,
    },
    /// The reply protocol version is not supported.
    #[error("invalid kadmin reply protocol version: {0}")]
    InvalidReplyVersion(u16),
    /// The request protocol version is not supported.
    #[error("invalid kadmin request protocol version: {0:#06x}")]
    InvalidRequestVersion(u16),
    /// The AP-REQ length points outside the frame body.
    #[error("invalid kadmin AP-REQ length {ap_req_length} for body length {body_length}")]
    InvalidApReqLength {
        /// AP-REQ byte length from the frame header.
        ap_req_length: u16,
        /// Available frame body byte length.
        body_length: usize,
    },
    /// The AP-REP length points outside the frame body.
    #[error("invalid kadmin AP-REP length {ap_rep_length} for body length {body_length}")]
    InvalidApRepLength {
        /// AP-REP byte length from the frame header.
        ap_rep_length: u16,
        /// Available frame body byte length.
        body_length: usize,
    },
    /// The response data is too short to hold a result code.
    #[error("kadmin response data is too short: {actual} bytes")]
    ResponseTooShort {
        /// Actual response byte length.
        actual: usize,
    },
    /// A KRB-ERROR reply did not include kpasswd response data.
    #[error("kadmin reply does not contain response data")]
    MissingReplyResult,
    /// A KRB-ERROR reply carried a success result without authenticated
    /// provenance.
    #[error("kadmin success result is not authenticated")]
    UnauthenticatedSuccess,
    /// A non-error reply did not include a KRB-PRIV section.
    #[error("kadmin reply does not contain KRB-PRIV")]
    MissingKrbPriv,
    /// A failure reply did not include a KRB-ERROR section.
    #[error("kadmin reply does not contain KRB-ERROR")]
    MissingKrb,
    /// A successful reply did not include an AP-REP section.
    #[error("kadmin reply does not contain AP-REP")]
    MissingApRep,
    /// A KRB-ERROR reply included AP-REP and/or KRB-PRIV payload fields.
    #[error("kadmin error reply cannot include AP-REP or KRB-PRIV")]
    InvalidErrorReplyPayload,
    /// The encrypted data etype is not implemented yet.
    #[error("unsupported encryption type: {0}")]
    UnsupportedEtype(i32),
    /// The supplied key etype did not match the encrypted KRB-PRIV etype.
    #[error(
        "key etype {key_etype} does not match KRB-PRIV encrypted data etype {encrypted_data_etype}"
    )]
    KeyEtypeMismatch {
        /// Supplied key encryption type.
        key_etype: i32,
        /// KRB-PRIV encrypted data encryption type.
        encrypted_data_etype: i32,
    },
    /// Cryptographic decrypt or integrity verification failed.
    #[error("kadmin crypto operation failed: {0}")]
    Crypto(#[from] Crypto),
    /// The operating system randomness source failed.
    #[error("kadmin random source failed: {0}")]
    Random(#[from] getrandom::Error),
    /// kpasswd returned a non-success result code.
    #[error("kpasswd failed with code {code}: {text}")]
    PasswordChangeFailed {
        /// kpasswd result code.
        code: u16,
        /// kpasswd result text.
        text: String,
        /// kpasswd result text as received, before lossy UTF-8 conversion.
        text_raw: Vec<u8>,
    },
    /// An unsigned kpasswd refusal is diagnostic data, not a confirmed outcome.
    #[error("unauthenticated kpasswd rejection with code {code}")]
    UnauthenticatedRejection {
        /// Unauthenticated kpasswd result code.
        code: u16,
        /// Unauthenticated result bytes, retained verbatim for diagnostics.
        text_raw: Vec<u8>,
    },
    /// DER decoding failed for a framed Kerberos message.
    #[error("{target} decode failed: {message}")]
    Decode {
        /// Kerberos message being decoded.
        target: &'static str,
        /// Decoder error.
        message: String,
    },
    /// DER encoding failed for a framed Kerberos message.
    #[error("{target} encode failed: {message}")]
    Encode {
        /// Kerberos message being encoded.
        target: &'static str,
        /// Encoder error.
        message: String,
    },
    /// A Kerberos string value could not be constructed.
    #[error("invalid Kerberos string value: {0}")]
    InvalidKerberosString(String),
    /// Encoded AP-REQ is too large for the two-byte kpasswd length field.
    #[error("encoded AP-REQ is too large: {actual} bytes")]
    ApReqTooLarge {
        /// Encoded AP-REQ byte length.
        actual: usize,
    },
    /// Encoded kadmin frame is too large for the two-byte length prefix.
    #[error("encoded kadmin frame is too large: {actual} bytes")]
    FrameTooLarge {
        /// Encoded frame byte length.
        actual: usize,
    },
}
/// Which half of a KCM exchange failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum KcmStage {
    /// Connecting to the daemon socket.
    Connect,
    /// Sending the request frame.
    Write,
    /// Receiving the reply frame.
    Read,
}

/// Why a KCM daemon socket or peer was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum KcmRefusal {
    /// The path is a symbolic link, not the socket itself.
    Symlink,
    /// The path is not a Unix domain socket.
    NotASocket,
    /// The socket file belongs to a user that is neither root, this process's
    /// effective user, nor an explicitly trusted user.
    UntrustedOwner {
        /// The owning user id.
        uid: u32,
    },
    /// The connected peer runs as a user that is neither root, this
    /// process's effective user, nor an explicitly trusted user.
    UntrustedPeer {
        /// The peer's user id.
        uid: u32,
    },
    /// This process's effective user id cannot be read on this platform, so
    /// only root-owned sockets and explicitly trusted users are accepted.
    IdentityUnavailable,
}

/// KCM credential-cache daemon client error (MIT `KRB5_KCM_*` and the daemon's
/// status codes).
///
/// Reply bytes are never copied into an error: only lengths, opcodes and
/// status codes.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Kcm {
    /// No daemon is configured (`kcm_socket = -`) or none listens on the
    /// socket (MIT `KRB5_KCM_NO_SERVER`).
    #[error("no KCM server found")]
    NoServer,
    /// The daemon socket or peer failed the trust check.
    #[error("KCM socket refused: {0:?}")]
    Untrusted(KcmRefusal),
    /// A socket operation failed.
    #[error("KCM {stage:?} failed: {source}")]
    Io {
        /// The failed half of the exchange.
        stage: KcmStage,
        /// The operating-system error.
        #[source]
        source: io::Error,
    },
    /// The daemon announced a reply larger than the cap (MIT
    /// `KRB5_KCM_REPLY_TOO_BIG`); nothing was allocated for it.
    #[error("KCM reply of {length} bytes exceeds the limit of {limit} bytes")]
    ReplyTooBig {
        /// The announced length.
        length: u32,
        /// The enforced limit.
        limit: usize,
    },
    /// The request does not fit the four-byte frame length or the request limit.
    #[error("KCM request of {length} bytes is too large")]
    RequestTooBig {
        /// The request length.
        length: usize,
    },
    /// A reply that cannot be parsed (MIT `KRB5_KCM_MALFORMED_REPLY`).
    #[error("malformed KCM reply to opcode {opcode}: {what}")]
    MalformedReply {
        /// The request opcode.
        opcode: u16,
        /// What was wrong.
        what: &'static str,
    },
    /// The daemon answered with a nonzero status code.
    #[error("KCM daemon refused opcode {opcode} with status {code}")]
    Daemon {
        /// The request opcode.
        opcode: u16,
        /// The status code, an MIT `krb5_error_code`.
        code: i32,
    },
    /// A mutating request was sent but its reply never arrived: the daemon
    /// may or may not have applied it.
    #[error("outcome unknown: KCM opcode {opcode} was sent and no reply arrived")]
    OutcomeUnknown {
        /// The request opcode.
        opcode: u16,
        /// Why the reply is missing.
        #[source]
        cause: Box<Self>,
    },
    /// The connection failed earlier and cannot carry another request.
    #[error("KCM connection is unusable after an earlier failure")]
    Broken,
    /// A request holds a value the wire encoding cannot represent (a length
    /// that does not fit its field).
    #[error("KCM request cannot be encoded: a length does not fit its field")]
    Unencodable,
    /// More entries than this client enumerates.
    #[error("KCM list holds more than {limit} entries")]
    TooManyEntries {
        /// The limit.
        limit: usize,
    },
    /// A KCM transport is installed already: the first installation wins.
    #[error("a KCM transport is installed already")]
    TransportInstalled,
    /// The configuration names a Mach service (`kcm_mach_service`) and the
    /// process has no Mach transport: no installed transport and no
    /// transport factory, for example because the platform companion crate was
    /// never asked to install its transport.
    #[error("no Mach transport is installed to reach the KCM service {service}")]
    NoMachTransport {
        /// The configured service name.
        service: String,
    },
}

#[cfg(feature = "messages")]
/// MS-KKDCP KDC proxy failures (`transport::kkdcp`, `transport::proxy`).
///
/// A KDC proxy transport reports a failure before the request could reach the
/// proxy as [`Self::NotDelivered`] and any later one as [`Self::MaybeDelivered`]
/// (or one of the response variants), so a password change through the proxy
/// keeps its outcome-unknown classification.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KdcProxy {
    /// The realm names an `https://` server and no KDC proxy transport is
    /// available: none was set and the `kkdcp-rustls` feature is not compiled in.
    #[error("no KDC proxy transport is available for {url}")]
    Unavailable {
        /// The proxy URL.
        url: String,
    },
    /// A configured `https://` server is not a URL this crate sends to.
    #[error("invalid KDC proxy URL: {reason}")]
    InvalidUrl {
        /// What is wrong, without the URL text.
        reason: &'static str,
    },
    /// A KDC-PROXY-MESSAGE does not decode, or its framing is wrong.
    #[error("malformed KDC-PROXY-MESSAGE: {reason}")]
    Malformed {
        /// What is wrong, without message bytes.
        reason: &'static str,
    },
    /// A message or a proxy response is longer than its bound.
    #[error("KDC proxy message of {actual} bytes exceeds {limit}")]
    TooLarge {
        /// The length seen, or the bound plus one when the length is unknown.
        actual: usize,
        /// The bound.
        limit: usize,
    },
    /// The realm sets no `http_anchors` and the transport has no configured
    /// roots: there is no implicit trust store.
    #[error("no trust anchors for the KDC proxy of realm {realm}")]
    NoAnchors {
        /// The realm.
        realm: String,
    },
    /// An `http_anchors` value cannot be loaded.
    #[error("cannot load KDC proxy trust anchor {anchor}: {reason}")]
    Anchor {
        /// The anchor value as configured.
        anchor: String,
        /// What is wrong.
        reason: &'static str,
    },
    /// The proxy answered with an HTTP status other than 200; a redirect is
    /// never followed.
    #[error("the KDC proxy answered HTTP status {status}")]
    Status {
        /// The HTTP status code.
        status: u16,
    },
    /// The request failed before any byte of it could reach the proxy (name
    /// resolution, connect, TLS handshake or certificate verification).
    #[error("the KDC proxy request was not delivered")]
    NotDelivered(#[source] Box<dyn StdError + Send + Sync>),
    /// The request failed after it may have reached the proxy.
    #[error("the KDC proxy request may have been delivered")]
    MaybeDelivered(#[source] Box<dyn StdError + Send + Sync>),
}

#[cfg(feature = "messages")]
/// KDC reply helper error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KdcRep {
    /// ASN.1 DER decode failed.
    #[error("failed to decode {target}: {message}")]
    Decode {
        /// Decoded type name.
        target: &'static str,
        /// Decoder error text.
        message: String,
    },
    /// ASN.1 DER encode failed.
    #[error("failed to encode {target}: {message}")]
    Encode {
        /// Encoded type name.
        target: &'static str,
        /// Encoder error text.
        message: String,
    },
    /// Message field did not contain the expected value.
    #[error("invalid {field}: expected {expected}, got {actual}")]
    InvalidMessage {
        /// Field name.
        field: &'static str,
        /// Expected value.
        expected: i32,
        /// Actual value.
        actual: String,
    },
    /// The encrypted data etype is not implemented yet.
    #[error("unsupported encryption type: {0}")]
    UnsupportedEtype(i32),
    /// A key did not match the encrypted KDC reply data etype.
    #[error(
        "key etype {key_etype} does not match KDC reply encrypted data etype {encrypted_data_etype}"
    )]
    KeyEtypeMismatch {
        /// Reply key encryption type.
        key_etype: i32,
        /// KDC reply encrypted data encryption type.
        encrypted_data_etype: i32,
    },
    /// A key did not match the encrypted ticket data etype.
    #[error(
        "key etype {key_etype} does not match Ticket encrypted data etype {encrypted_data_etype}"
    )]
    TicketKeyEtypeMismatch {
        /// Key encryption type.
        key_etype: i32,
        /// Ticket encrypted data encryption type.
        encrypted_data_etype: i32,
    },
    /// Random byte generation failed.
    #[error("random byte generation failed: {0}")]
    Random(#[from] getrandom::Error),
    /// Crypto operation failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] Crypto),
}
#[cfg(feature = "messages")]
/// KDC request helper error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KdcReq {
    /// ASN.1 DER decode failed.
    #[error("failed to decode {target}: {message}")]
    Decode {
        /// Decoded type name.
        target: &'static str,
        /// Decoder error text.
        message: String,
    },
    /// ASN.1 DER encode failed.
    #[error("failed to encode {target}: {message}")]
    Encode {
        /// Encoded type name.
        target: &'static str,
        /// Encoder error text.
        message: String,
    },
    /// Message field did not contain the expected value.
    #[error("invalid {field}: expected {expected}, got {actual}")]
    InvalidMessage {
        /// Field name.
        field: &'static str,
        /// Expected value.
        expected: i32,
        /// Actual value.
        actual: String,
    },
    /// The encrypted data etype is not implemented yet.
    #[error("unsupported encryption type: {0}")]
    UnsupportedEtype(i32),
    /// A key did not match the encrypted ticket data etype.
    #[error(
        "key etype {key_etype} does not match Ticket encrypted data etype {encrypted_data_etype}"
    )]
    TicketKeyEtypeMismatch {
        /// Key encryption type.
        key_etype: i32,
        /// Ticket encrypted data encryption type.
        encrypted_data_etype: i32,
    },
    /// Random byte generation failed.
    #[error("random byte generation failed: {0}")]
    Random(#[from] getrandom::Error),
    /// Crypto operation failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] Crypto),
}
/// Keytab parsing and serialization error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Keytab {
    /// Version one has no field for a nonzero principal name type.
    #[error("keytab version one cannot represent principal name type {0}")]
    UnrepresentableNameType(i32),
    /// A configured name could not be expanded from available facts.
    #[error("keytab name expansion failed: {0}")]
    Expansion(#[from] ExpansionFailure),
    /// UID tokens require Linux procfs process identities.
    #[error("credential path process identity is unavailable (UID tokens require Linux procfs)")]
    IdentityUnavailable,
    /// File loading or saving failed.
    #[error("keytab file could not be read or written: {0}")]
    Io(#[from] io::Error),
    /// The default keytab name could not be read from `KRB5_KTNAME`.
    #[error("default keytab name could not be read from KRB5_KTNAME: {0}")]
    DefaultKeytabName(#[source] env::VarError),
    /// A keytab name was empty or did not include a path.
    #[error("invalid keytab name")]
    InvalidKeytabName,
    /// The keytab name uses a keytab type this module cannot parse.
    #[error("unsupported keytab type: {keytab_type}")]
    UnsupportedKeytabType {
        /// Keytab type prefix before the first colon.
        keytab_type: String,
    },
    /// A principal name was empty or contained empty components. A keytab
    /// entry whose principal has no name components or an empty name component
    /// is also reported here.
    #[error("invalid keytab principal name")]
    InvalidPrincipalName,
    /// A keytab entry has a principal with an empty realm. MIT treats such an
    /// entry as the end of the table; this crate rejects it as malformed.
    #[error("keytab principal has an empty realm")]
    EmptyRealm,
    /// A keytab entry has a key of zero length. MIT treats such an entry as
    /// the end of the table; this crate rejects it as malformed.
    #[error("keytab entry has an empty key")]
    EmptyKey,
    /// Input is too short to contain the keytab header.
    #[error("keytab is too short: {actual} bytes")]
    TooShort {
        /// Actual input length.
        actual: usize,
    },
    /// Keytab does not start with the required first byte.
    #[error("invalid keytab first byte: {0}")]
    InvalidFirstByte(u8),
    /// Unsupported keytab version.
    #[error("invalid keytab version: {0}")]
    InvalidVersion(u8),
    /// A read would exceed the input length.
    #[error("keytab data is truncated at offset {offset}; need {needed} bytes, have {remaining}")]
    Truncated {
        /// Offset where the read started.
        offset: usize,
        /// Bytes needed.
        needed: usize,
        /// Bytes remaining from offset.
        remaining: usize,
    },
    /// A signed length was negative where the field cannot be negative.
    #[error("negative keytab length: {0}")]
    NegativeLength(i32),
    /// A length cannot fit in the target integer type.
    #[error("keytab length overflow")]
    LengthOverflow,
    /// A keytab entry timestamp was before the Unix epoch.
    #[error("keytab timestamp is before the Unix epoch: {0}")]
    TimestampBeforeUnixEpoch(#[from] SystemTimeError),
    /// A keytab entry timestamp cannot fit in the file format.
    #[error("keytab timestamp overflow")]
    TimestampOverflow,
    /// Principal strings must be valid UTF-8.
    #[error("invalid keytab string: {0}")]
    InvalidString(#[from] Utf8Error),
    /// The encrypted data etype is not implemented yet.
    #[error("unsupported encryption type: {0}")]
    UnsupportedEtype(i32),
    /// Key derivation failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] Crypto),
    /// Key lookup did not find a matching entry.
    #[error("matching key not found in keytab for {principal}@{realm}, kvno {kvno}, etype {etype}")]
    NoMatchingKey {
        /// Principal components joined by `/`.
        principal: String,
        /// Principal realm.
        realm: String,
        /// Requested kvno, or 0 for latest.
        kvno: u32,
        /// Requested encryption type.
        etype: i32,
    },
}
#[cfg(feature = "messages")]
/// KRB-CRED helper error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KrbCred {
    /// ASN.1 DER decode failed.
    #[error("failed to decode {target}: {message}")]
    Decode {
        /// Decoded type name.
        target: &'static str,
        /// Decoder error text.
        message: String,
    },
    /// ASN.1 DER encode failed.
    #[error("failed to encode {target}: {message}")]
    Encode {
        /// Encoded type name.
        target: &'static str,
        /// Encoder error text.
        message: String,
    },
    /// ASN.1 string value was not valid UTF-8.
    #[error("invalid Kerberos string: {0}")]
    InvalidString(#[from] Utf8Error),
    /// A string could not be encoded as a Kerberos `GeneralString`.
    #[error("invalid Kerberos string: {0}")]
    InvalidKerberosString(String),
    /// Message field did not contain the expected value.
    #[error("invalid {field}: expected {expected}, got {actual}")]
    InvalidMessage {
        /// Field name.
        field: &'static str,
        /// Expected value.
        expected: i32,
        /// Actual value.
        actual: String,
    },
    /// The encrypted data etype is not implemented yet.
    #[error("unsupported encryption type: {0}")]
    UnsupportedEtype(i32),
    /// A key did not match the encrypted KRB-CRED data etype.
    #[error(
        "key etype {key_etype} does not match KRB-CRED encrypted data etype {encrypted_data_etype}"
    )]
    KeyEtypeMismatch {
        /// Reply key encryption type.
        key_etype: i32,
        /// KRB-CRED encrypted data encryption type.
        encrypted_data_etype: i32,
    },
    /// A key did not match the encrypted ticket data etype.
    #[error(
        "key etype {key_etype} does not match Ticket encrypted data etype {encrypted_data_etype}"
    )]
    TicketKeyEtypeMismatch {
        /// Key encryption type.
        key_etype: i32,
        /// Ticket encrypted data encryption type.
        encrypted_data_etype: i32,
    },
    /// The KRB-CRED ticket count and ticket-info count differed.
    #[error("KRB-CRED has {ticket_count} tickets but {info_count} ticket-info entries")]
    TicketInfoCountMismatch {
        /// Ticket count.
        ticket_count: usize,
        /// Ticket-info count.
        info_count: usize,
    },
    /// A field required for ccache conversion was absent.
    #[error("KRB-CRED missing required field {0}")]
    MissingKrbCredInfoField(&'static str),
    /// A Kerberos time could not fit in a ccache timestamp.
    #[error("Kerberos time cannot be represented as a ccache timestamp")]
    TimeOutOfRange,
    /// Ccache authorization data cannot be represented in KRB-CRED info.
    #[error("ccache credential authorization data cannot be represented in KRB-CRED")]
    UnsupportedCredentialAuthData,
    /// Ccache second-ticket data cannot be represented in KRB-CRED info.
    #[error("ccache credential second ticket cannot be represented in KRB-CRED")]
    UnsupportedSecondTicket,
    /// Random byte generation failed.
    #[error("random byte generation failed: {0}")]
    Random(#[from] getrandom::Error),
    /// Crypto operation failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] Crypto),
}
#[cfg(feature = "messages")]
/// KRB-ERROR helper error.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum KrbErrorCodec {
    /// A requested cryptographic feature violates permanent policy.
    #[error("policy error: {0}")]
    Policy(#[from] Policy),
    /// ASN.1 DER decode failed.
    #[error("failed to decode {target}: {message}")]
    Decode {
        /// Decoded type name.
        target: &'static str,
        /// Decoder error text.
        message: String,
    },
    /// ASN.1 DER encode failed.
    #[error("failed to encode {target}: {message}")]
    Encode {
        /// Encoded type name.
        target: &'static str,
        /// Encoder error text.
        message: String,
    },
    /// ASN.1 string value was not valid UTF-8.
    #[error("invalid Kerberos string: {0}")]
    InvalidString(#[from] Utf8Error),
    /// A Kerberos integer could not fit in the expected Rust type.
    #[error("integer field {field} is out of range: {value}")]
    IntegerOutOfRange {
        /// Field name.
        field: &'static str,
        /// Integer value.
        value: String,
    },
    /// Message field did not contain the expected value.
    #[error("invalid {field}: expected {expected}, got {actual}")]
    InvalidMessage {
        /// Field name.
        field: &'static str,
        /// Expected value.
        expected: i32,
        /// Actual value.
        actual: String,
    },
    /// The ASN.1 INTEGER `kvno` cannot be represented as the requested type.
    #[error("encrypted data kvno cannot be represented as {target}: {kvno:?}")]
    KvnoOutOfRange {
        /// Target integer representation.
        target: &'static str,
        /// Original ASN.1 INTEGER value.
        kvno: Integer,
    },
    /// A Kerberos time could not be represented as a `SystemTime`.
    #[error("Kerberos time overflows SystemTime")]
    TimeOverflow,
}
#[cfg(feature = "messages")]
/// KRB-PRIV helper error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KrbPriv {
    /// ASN.1 DER decode failed.
    #[error("failed to decode {target}: {message}")]
    Decode {
        /// Decoded type name.
        target: &'static str,
        /// Decoder error text.
        message: String,
    },
    /// ASN.1 DER encode failed.
    #[error("failed to encode {target}: {message}")]
    Encode {
        /// Encoded type name.
        target: &'static str,
        /// Encoder error text.
        message: String,
    },
    /// Message field did not contain the expected value.
    #[error("invalid {field}: expected {expected}, got {actual}")]
    InvalidMessage {
        /// Field name.
        field: &'static str,
        /// Expected value.
        expected: i32,
        /// Actual value.
        actual: String,
    },
    /// The encrypted data etype is not implemented yet.
    #[error("unsupported encryption type: {0}")]
    UnsupportedEtype(i32),
    /// A key did not match the encrypted KRB-PRIV data etype.
    #[error(
        "key etype {key_etype} does not match KRB-PRIV encrypted data etype {encrypted_data_etype}"
    )]
    KeyEtypeMismatch {
        /// Reply key encryption type.
        key_etype: i32,
        /// KRB-PRIV encrypted data encryption type.
        encrypted_data_etype: i32,
    },
    /// Random byte generation failed.
    #[error("random byte generation failed: {0}")]
    Random(#[from] getrandom::Error),
    /// Crypto operation failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] Crypto),
}
#[cfg(feature = "messages")]
/// KRB-SAFE helper error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KrbSafe {
    /// ASN.1 DER decode failed.
    #[error("failed to decode {target}: {message}")]
    Decode {
        /// Decoded type name.
        target: &'static str,
        /// Decoder error text.
        message: String,
    },
    /// ASN.1 DER encode failed.
    #[error("failed to encode {target}: {message}")]
    Encode {
        /// Encoded type name.
        target: &'static str,
        /// Encoder error text.
        message: String,
    },
    /// Message field did not contain the expected value.
    #[error("invalid {field}: expected {expected}, got {actual}")]
    InvalidMessage {
        /// Field name.
        field: &'static str,
        /// Expected value.
        expected: i32,
        /// Actual value.
        actual: String,
    },
    /// The encryption type is not implemented yet.
    #[error("unsupported encryption type: {0}")]
    UnsupportedEtype(i32),
    /// The checksum type is not implemented yet.
    #[error("unsupported checksum type: {0}")]
    UnsupportedChecksumType(i32),
    /// A key did not match the KRB-SAFE checksum type.
    #[error("key etype {key_etype} does not match KRB-SAFE checksum type {checksum_type}")]
    KeyChecksumTypeMismatch {
        /// Key encryption type.
        key_etype: i32,
        /// KRB-SAFE checksum type.
        checksum_type: i32,
    },
    /// KRB-SAFE checksum verification failed.
    #[error("KRB-SAFE checksum verification failed")]
    ChecksumMismatch,
    /// Crypto operation failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] Crypto),
}
#[cfg(feature = "messages")]
/// Errors from Kerberos message helpers.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum Messages {
    /// A requested cryptographic feature violates permanent policy.
    #[error("policy error: {0}")]
    Policy(#[from] Policy),
    /// ASN.1 DER decode failed.
    #[error("failed to decode {target}: {message}")]
    Decode {
        /// Decoded type name.
        target: &'static str,
        /// Decoder error text.
        message: String,
    },
    /// ASN.1 DER encode failed.
    #[error("failed to encode {target}: {message}")]
    Encode {
        /// Encoded type name.
        target: &'static str,
        /// Encoder error text.
        message: String,
    },
    /// ASN.1 string value was not valid UTF-8.
    #[error("invalid Kerberos string: {0}")]
    InvalidString(#[from] Utf8Error),
    /// A Kerberos integer could not fit in the expected Rust type.
    #[error("integer field {field} is out of range: {value}")]
    IntegerOutOfRange {
        /// Field name.
        field: &'static str,
        /// Integer value.
        value: String,
    },
    /// Message field did not contain the expected value.
    #[error("invalid {field}: expected {expected}, got {actual}")]
    InvalidMessage {
        /// Field name.
        field: &'static str,
        /// Expected value.
        expected: i32,
        /// Actual value.
        actual: String,
    },
    /// The ASN.1 INTEGER `kvno` cannot be represented as the requested type.
    #[error("encrypted data kvno cannot be represented as {target}: {kvno:?}")]
    KvnoOutOfRange {
        /// Target integer representation.
        target: &'static str,
        /// Original ASN.1 INTEGER value.
        kvno: Integer,
    },
    /// A Kerberos time could not be represented as a `SystemTime`.
    #[error("Kerberos time overflows SystemTime")]
    TimeOverflow,
}
/// PAC parsing errors.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Pac {
    /// The PAC format version is not supported by MS-PAC.
    #[error("unsupported PAC version {0}; expected zero")]
    InvalidPacVersion(u32),
    /// Input was too short.
    #[error("{target} is too short: expected at least {minimum} bytes, got {actual}")]
    TooShort {
        /// Parsed target.
        target: &'static str,
        /// Minimum accepted byte length.
        minimum: usize,
        /// Actual byte length.
        actual: usize,
    },
    /// A read exceeded the input length.
    #[error("PAC data is truncated at offset {offset}; need {needed} bytes, have {remaining}")]
    Truncated {
        /// Offset where the read started.
        offset: usize,
        /// Bytes needed.
        needed: usize,
        /// Bytes remaining from offset.
        remaining: usize,
    },
    /// A length or offset overflowed the target integer type.
    #[error("PAC length overflow")]
    LengthOverflow,
    /// A PAC buffer offset was not aligned to eight bytes.
    #[error("PAC buffer {ul_type} offset {offset} is not eight-byte aligned")]
    BufferOffsetNotAligned {
        /// PAC buffer type.
        ul_type: u32,
        /// PAC buffer offset.
        offset: u64,
    },
    /// A PAC buffer range exceeded the PAC byte length.
    #[error(
        "PAC buffer {ul_type} at offset {offset} with length {len} exceeds PAC length {total_len}"
    )]
    BufferOutOfBounds {
        /// PAC buffer type.
        ul_type: u32,
        /// PAC buffer offset.
        offset: u64,
        /// PAC buffer length.
        len: u32,
        /// PAC byte length.
        total_len: usize,
    },
    /// A sub-structure range exceeded its buffer length.
    #[error(
        "{target} range at offset {offset} with length {len} exceeds buffer length {total_len}"
    )]
    OutOfBounds {
        /// Parsed target.
        target: &'static str,
        /// Offset.
        offset: usize,
        /// Length.
        len: usize,
        /// Total buffer length.
        total_len: usize,
    },
    /// A checksum type is recognized neither for parsing nor verification.
    #[error("unsupported PAC checksum type: {0}")]
    UnsupportedChecksumType(u32),
    /// An encryption type is not supported for PAC credential decryption.
    #[error("unsupported PAC encryption type: {0}")]
    UnsupportedEncryptionType(i32),
    /// A claims compression format is not supported.
    #[error("unsupported PAC claims compression format: {0}")]
    UnsupportedClaimsCompressionFormat(u16),
    /// Claims decoding would exceed the independent 1 MiB output ceiling.
    #[error("PAC claims output exceeds the 1 MiB limit")]
    ClaimsOutputLimit,
    /// PAC claims decompression failed.
    #[error("PAC claims decompression failed for format {compression_format}: {message}")]
    ClaimsDecompression {
        /// Claims compression format.
        compression_format: u16,
        /// Decompression error message.
        message: String,
    },
    /// PAC claims decompressed to a length other than the metadata declared.
    #[error(
        "PAC claims decompressed size mismatch for format {compression_format}: expected {expected}, got {actual}"
    )]
    ClaimsDecompressedSizeMismatch {
        /// Claims compression format.
        compression_format: u16,
        /// Expected decompressed byte length.
        expected: usize,
        /// Actual decompressed byte length.
        actual: usize,
    },
    /// A claims value type is not supported.
    #[error("unsupported PAC claim type: {0}")]
    UnsupportedClaimType(u16),
    /// A Boolean ULONG64 claim was neither zero nor one.
    #[error("invalid Boolean claim value: {0}")]
    InvalidBooleanClaim(u64),
    /// A claim union discriminant did not match the entry type.
    #[error("invalid PAC claim union tag: claim type {claim_type}, union tag {union_tag}")]
    InvalidClaimUnionTag {
        /// Claim type field.
        claim_type: u16,
        /// Union tag field.
        union_tag: u16,
    },
    /// A required PAC buffer was absent.
    #[error("PAC Info Buffers do not contain required {0}")]
    MissingRequiredBuffer(&'static str),
    /// PAC credentials info version was not zero.
    #[error("invalid PAC credentials info version: {0}")]
    InvalidCredentialsInfoVersion(u32),
    /// PAC credentials were decrypted with the wrong key type.
    #[error("PAC credentials key type mismatch: expected {expected}, got {actual}")]
    CredentialKeyTypeMismatch {
        /// Required Kerberos encryption type.
        expected: i32,
        /// Provided Kerberos encryption type.
        actual: i32,
    },
    /// NTLM supplemental credential version was not zero.
    #[error("invalid NTLM supplemental credential version: {0}")]
    InvalidNtlmSupplementalCredentialVersion(u32),
    /// Neither LM nor NT hash has a validity flag (MS-PAC 2.6.4).
    #[error("NTLM supplemental credential has no hash validity flag")]
    MissingNtlmValidityFlag,
    /// Validated supplemental credential storage could not be reserved.
    #[error("PAC supplemental credential allocation failed")]
    CredentialAllocation,
    /// The PAC server checksum did not verify.
    #[error("PAC service checksum verification failed")]
    ServerChecksumVerificationFailed,
    /// The PAC KDC signature did not verify under the KDC key.
    #[error("PAC KDC checksum verification failed")]
    KdcChecksumVerificationFailed,
    /// The PAC ticket signature did not verify under the KDC key.
    #[error("PAC ticket checksum verification failed")]
    TicketChecksumVerificationFailed,
    /// The PAC full checksum (KB5020805) did not verify under the KDC key.
    #[error("PAC full checksum verification failed")]
    FullChecksumVerificationFailed,
    /// A signature the policy requires cannot be verified because no key was supplied.
    #[error("no key was supplied to verify the required PAC {0}")]
    MissingVerificationKey(&'static str),
    /// The policy binds the PAC to a client but the request names none.
    #[error("PAC client binding is required but no client was given")]
    MissingClientBinding,
    /// The PAC client info names another client or authentication time than the ticket.
    #[error("PAC client info does not match the ticket client")]
    ClientInfoMismatch,
    /// The policy requires a PAC and the ticket carries none.
    #[error("the ticket carries no PAC but the policy requires one")]
    RequiredPacAbsent,
    /// A PAC declares more info buffers than the 4096 MIT accepts.
    #[error("PAC declares {0} info buffers; at most 4096 are accepted")]
    BufferCountLimit(u32),
    /// A PAC carries two buffers of one interpreted type.
    #[error("PAC carries more than one buffer of type {0}")]
    DuplicateBuffer(u32),
    /// A PAC buffer overlaps the header or table, or another buffer.
    #[error("PAC buffer {ul_type} at offset {offset} overlaps the table or another buffer")]
    BufferOverlap {
        /// PAC buffer type.
        ul_type: u32,
        /// PAC buffer offset.
        offset: u64,
    },
    /// PAC authorization data failed DER decoding.
    #[cfg(feature = "messages")]
    #[error("PAC authorization-data DER decode failed: {0}")]
    DerDecode(String),
    /// The ticket could not be DER-encoded for its PAC ticket signature.
    #[cfg(feature = "messages")]
    #[error("PAC ticket-signature input DER encode failed: {0}")]
    DerEncode(String),
    /// PAC lookup would decode more than eight nested authorization wrappers.
    #[cfg(feature = "messages")]
    #[error("PAC authorization-data depth exceeds eight wrappers")]
    AuthorizationDataDepthLimit,
    /// PAC lookup would visit more than 1 MiB of cumulative payload bytes.
    #[cfg(feature = "messages")]
    #[error("PAC authorization-data byte budget exceeds 1 MiB")]
    AuthorizationDataByteLimit,
    /// The NDR wrapper was not little-endian NDR64-compatible data.
    #[error("invalid NDR header")]
    InvalidNdrHeader,
    /// The NDR wrapper object length exceeded the available bytes.
    #[error("invalid NDR object length {object_len}; only {remaining} bytes remain")]
    InvalidNdrObjectLength {
        /// Declared object length.
        object_len: usize,
        /// Remaining bytes.
        remaining: usize,
    },
    /// An NDR pointer was null where the pointed value was required.
    #[error("missing NDR pointer for {0}")]
    MissingNdrPointer(&'static str),
    /// An NDR count was too large to allocate safely.
    #[error("unreasonable NDR count for {target}: {count}")]
    UnreasonableNdrCount {
        /// Parsed target.
        target: &'static str,
        /// Count value.
        count: u32,
    },
    /// An NDR conformant/varying array described invalid bounds.
    #[error(
        "invalid NDR array bounds for {target}: max={max_count}, offset={offset}, actual={actual_count}"
    )]
    InvalidNdrArrayBounds {
        /// Parsed target.
        target: &'static str,
        /// Maximum element count.
        max_count: u32,
        /// Varying array offset.
        offset: u32,
        /// Actual element count.
        actual_count: u32,
    },
    /// A declared count did not match the transmitted conformant array count.
    #[error("NDR count mismatch for {target}: expected {expected}, got {actual}")]
    CountMismatch {
        /// Parsed target.
        target: &'static str,
        /// Expected count.
        expected: u32,
        /// Actual count.
        actual: u32,
    },
    /// RPC Unicode string length metadata was inconsistent.
    #[error(
        "invalid RPC_UNICODE_STRING for {target}: length {length}, maximum length {maximum_length}"
    )]
    InvalidRpcUnicodeString {
        /// Parsed target.
        target: &'static str,
        /// String length in bytes.
        length: u16,
        /// Maximum string length in bytes.
        maximum_length: u16,
    },
    /// RPC Unicode string data did not contain the declared number of UTF-16 units.
    #[error(
        "invalid RPC_UNICODE_STRING data for {target}: expected {expected_units} UTF-16 units, got {actual_units}"
    )]
    InvalidRpcUnicodeStringData {
        /// Parsed target.
        target: &'static str,
        /// Expected UTF-16 units.
        expected_units: usize,
        /// Actual UTF-16 units.
        actual_units: usize,
    },
    /// UTF-16 input had an odd byte length.
    #[error("invalid UTF-16LE length for {target}: {bytes} bytes")]
    InvalidUtf16Length {
        /// Parsed target.
        target: &'static str,
        /// Byte count.
        bytes: usize,
    },
    /// UTF-16 decoding failed.
    #[error("invalid UTF-16LE data for {target}: {message}")]
    InvalidUtf16 {
        /// Parsed target.
        target: &'static str,
        /// Decode error message.
        message: String,
    },
    /// SID revision was unsupported.
    #[error("unsupported SID revision: {0}")]
    InvalidSidRevision(u8),
    /// SID sub-authority count was inconsistent.
    #[error("invalid SID sub-authority count for {target}: max={max_count}, actual={actual_count}")]
    InvalidSidSubAuthorityCount {
        /// Parsed target.
        target: &'static str,
        /// Maximum transmitted sub-authority count.
        max_count: u32,
        /// Actual SID sub-authority count.
        actual_count: u8,
    },
    /// NDR data remained after all `KERB_VALIDATION_INFO` fields were parsed.
    #[error("trailing NDR bytes after KERB_VALIDATION_INFO: {remaining}")]
    TrailingNdrBytes {
        /// Remaining byte count.
        remaining: usize,
    },
    /// NDR data remained after all fields were parsed.
    #[error("trailing NDR bytes after {target}: {remaining}")]
    TrailingNdrBytesAfter {
        /// Parsed target.
        target: &'static str,
        /// Remaining byte count.
        remaining: usize,
    },
    /// Internal alignment request was invalid.
    #[error("invalid alignment: {0}")]
    InvalidAlignment(usize),
    /// Kerberos cryptographic operation failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] Crypto),
}
#[cfg(feature = "messages")]
/// AP-REQ service validation error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Service {
    /// `KerberosTime` contains fractional seconds forbidden by RFC 4120 section 5.2.3.
    #[error("fractional seconds are not permitted in KerberosTime")]
    FractionalKerberosTime,
    /// Validator skew exceeds the replay cache's immutable policy.
    #[error("validator skew {requested:?} exceeds replay cache maximum {maximum:?}")]
    ReplayCacheSkewExceeded {
        /// Cache-owned maximum skew.
        maximum: Duration,
        /// Validator's requested acceptance skew.
        requested: Duration,
    },
    /// Validation time moved behind the cache's admission high-water mark.
    #[error("replay cache clock moved backwards")]
    ReplayCacheClockRollback,
    /// All replay-cache slots contain live records.
    #[error("replay cache capacity {capacity} exhausted")]
    ReplayCacheCapacityExceeded {
        /// Immutable maximum number of live records.
        capacity: usize,
    },
    /// An authorization-data restriction cannot be safely interpreted.
    #[error("unsupported mandatory authorization data type {kind}")]
    UnsupportedAuthorizationData {
        /// Authorization-data type identifier.
        kind: i32,
    },
    /// Authorization-data wrappers exceed the service's depth or decoded-byte budget.
    #[error("authorization data exceeds the service validation limit")]
    AuthorizationDataLimit,
    /// Cross-realm transit was neither KDC-checked nor explicitly trusted locally.
    #[error("cross-realm transit policy rejected the ticket")]
    TransitPolicyRejected,
    /// ASN.1 DER decode failed.
    #[error("failed to decode {target}: {message}")]
    Decode {
        /// Decoded type name.
        target: &'static str,
        /// Decoder error text.
        message: String,
    },
    /// ASN.1 DER encode failed.
    #[error("failed to encode {target}: {message}")]
    Encode {
        /// Encoded type name.
        target: &'static str,
        /// Encoder error text.
        message: String,
    },
    /// ASN.1 string value was not valid UTF-8.
    #[error("invalid Kerberos string: {0}")]
    InvalidString(#[from] Utf8Error),
    /// A Kerberos integer could not fit in the expected Rust type.
    #[error("integer field {field} is out of range: {value}")]
    IntegerOutOfRange {
        /// Field name.
        field: &'static str,
        /// Integer value.
        value: String,
    },
    /// Message field did not contain the expected value.
    #[error("invalid {field}: expected {expected}, got {actual}")]
    InvalidMessage {
        /// Field name.
        field: &'static str,
        /// Expected value.
        expected: i32,
        /// Actual value.
        actual: String,
    },
    /// The encrypted data etype is not implemented yet.
    #[error("unsupported encryption type: {0}")]
    UnsupportedEtype(i32),
    /// A key did not match the encrypted AP-REP data etype.
    #[error(
        "key etype {key_etype} does not match AP-REP encrypted data etype {encrypted_data_etype}"
    )]
    ApRepKeyEtypeMismatch {
        /// Reply key encryption type.
        key_etype: i32,
        /// AP-REP encrypted data encryption type.
        encrypted_data_etype: i32,
    },
    /// A key did not match the encrypted AP-REQ authenticator etype.
    #[error(
        "key etype {key_etype} does not match AP-REQ authenticator etype {encrypted_data_etype}"
    )]
    ApReqKeyEtypeMismatch {
        /// Reply key encryption type.
        key_etype: i32,
        /// AP-REQ authenticator encryption type.
        encrypted_data_etype: i32,
    },
    /// A key did not match the encrypted ticket data etype.
    #[error(
        "key etype {key_etype} does not match Ticket encrypted data etype {encrypted_data_etype}"
    )]
    TicketKeyEtypeMismatch {
        /// Service key encryption type.
        key_etype: i32,
        /// Ticket encrypted data encryption type.
        encrypted_data_etype: i32,
    },
    /// Keytab lookup failed.
    #[error("keytab error: {0}")]
    Keytab(#[from] Keytab),
    /// Crypto operation failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] Crypto),
    /// Random byte generation failed.
    #[error("random byte generation failed: {0}")]
    Random(#[from] getrandom::Error),
    /// PAC parsing or verification failed.
    #[error("PAC error: {0}")]
    Pac(#[from] Pac),
    /// PAC client name or authentication time does not match the ticket.
    #[error("PAC client metadata does not match ticket client")]
    PacClientMismatch,
    /// Ticket has not become valid or carries the invalid ticket flag.
    #[error("ticket for {service}@{realm} is not yet valid")]
    TicketNotYetValid {
        /// Service principal.
        service: String,
        /// Service realm.
        realm: String,
    },
    /// Ticket has expired.
    #[error("ticket for {service}@{realm} has expired")]
    TicketExpired {
        /// Service principal.
        service: String,
        /// Service realm.
        realm: String,
    },
    /// The ticket is for another service than the named acceptor (MIT
    /// `KRB5KRB_AP_WRONG_PRINC`).
    #[error("ticket for {actual} presented to acceptor {expected}")]
    WrongPrincipal {
        /// The acceptor name (`name@realm`; an empty host or realm matches any).
        expected: String,
        /// The ticket's server principal (`name@realm`).
        actual: String,
    },
    /// Ticket client and authenticator client do not match.
    #[error("authenticator client {authenticator} does not match ticket client {ticket}")]
    ClientPrincipalMismatch {
        /// Ticket client principal (`name@realm`).
        ticket: String,
        /// Authenticator client principal (`name@realm`).
        authenticator: String,
    },
    /// Authenticator timestamp exceeded the accepted clock skew.
    #[error("authenticator clock skew exceeds {max_clock_skew:?}")]
    ClockSkew {
        /// Maximum accepted skew.
        max_clock_skew: Duration,
    },
    /// AP-REQ replay detected.
    #[error("AP-REQ replay detected")]
    Replay,
    /// Shared replay cache lock could not be acquired.
    #[error("shared replay cache lock is poisoned")]
    ReplayCachePoisoned,
    /// AD-KDC-ISSUED or AD-AND-OR authorization data is not valid.
    #[error("authorization data error: {0}")]
    AuthorizationData(#[from] AuthData),
    /// An AD-AND-OR element's conditions are not met.
    #[error("authorization conditions are not satisfied")]
    AuthorizationConditionUnsatisfied,
    /// A replay store failed, so the authenticator is refused (fail closed).
    #[error("replay store error: {0}")]
    ReplayStore(#[from] Replay),
    /// AP-REP did not echo the AP-REQ authenticator timestamp.
    #[error("AP-REP timestamp mismatch: expected {expected:?}, got {actual:?}")]
    ApRepTimestampMismatch {
        /// Expected AP-REQ authenticator timestamp.
        expected: SystemTime,
        /// Timestamp supplied by AP-REP.
        actual: SystemTime,
    },
    /// Ticket client address list did not include the observed client address.
    #[error("client address not accepted for ticket {service}@{realm}")]
    BadClientAddress {
        /// Service principal.
        service: String,
        /// Service realm.
        realm: String,
    },
    /// The service requires client addresses but the ticket is addressless.
    #[error("ticket for {service}@{realm} does not contain required client addresses")]
    RequiredClientAddressMissing {
        /// Service principal.
        service: String,
        /// Service realm.
        realm: String,
    },
    /// A Kerberos time could not be represented as a `SystemTime`.
    #[error("Kerberos time overflows SystemTime")]
    TimeOverflow,
}
#[cfg(feature = "messages")]
/// SPAKE preauthentication error (RFC 9588, `preauth::spake`).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Spake {
    /// No configured SPAKE group is available in this build (MIT: the module
    /// is not enabled without a permitted group).
    #[error("no SPAKE group is permitted and available")]
    NoGroups,
    /// The KDC's challenge names a group the policy does not permit, after the
    /// client already sent its support message (MIT `KRB5KDC_ERR_PREAUTH_FAILED`).
    #[error("SPAKE group {group} is not permitted")]
    GroupNotPermitted {
        /// The group number of the challenge.
        group: i32,
    },
    /// The challenge offers no second factor this client supports (only `SF-NONE`).
    #[error("the SPAKE challenge offers no supported second factor")]
    NoSupportedFactor,
    /// A public key is not a valid, canonically encoded group element, or the
    /// shared element is the identity.
    #[error("invalid SPAKE group element for group {group}")]
    InvalidElement {
        /// The group number.
        group: i32,
    },
    /// A PA-SPAKE value is not a valid DER message or exceeds a bound.
    #[error("malformed PA-SPAKE message: {message}")]
    Malformed {
        /// What is wrong, without message bytes.
        message: String,
    },
    /// The KDC sent a PA-SPAKE message this client does not expect now.
    #[error("unexpected PA-SPAKE message: {message}")]
    Unexpected {
        /// What was received.
        message: &'static str,
    },
    /// A second-factor exchange (`encdata`) was requested; only `SF-NONE` is
    /// supported, as in MIT 1.22.2.
    #[error("SPAKE second-factor rounds are not supported")]
    SecondFactorUnsupported,
    /// The initial reply key cannot feed the SPAKE derivations.
    #[error("SPAKE key derivation failed")]
    Crypto(#[from] Crypto),
    /// The random generator failed.
    #[error("random generator failed")]
    Random(#[from] getrandom::Error),
}
#[cfg(feature = "messages")]
/// OTP preauthentication error (RFC 6560, `preauth::otp`). The stepwise AS
/// exchange reports it as [`Client::Otp`]. No variant carries an OTP value or a PIN.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Otp {
    /// OTP is only ever sent inside FAST, and this exchange has no armor key.
    #[error("OTP needs FAST armor and this exchange has none")]
    ArmorRequired,
    /// The KDC offered `PA-OTP-CHALLENGE` more than once in one reply.
    #[error("the KDC offered PA-OTP-CHALLENGE more than once")]
    RepeatedChallenge,
    /// The `PA-OTP-CHALLENGE` value exceeds the policy's size bound.
    #[error("the PA-OTP-CHALLENGE exceeds {limit} bytes")]
    ChallengeTooLarge {
        /// The bound.
        limit: usize,
    },
    /// The challenge lists more token infos than the policy allows.
    #[error("the PA-OTP-CHALLENGE lists more than {limit} tokens")]
    TooManyTokens {
        /// The bound.
        limit: usize,
    },
    /// A challenge field exceeds the policy's size bound.
    #[error("the {field} of the PA-OTP-CHALLENGE exceeds {limit} bytes")]
    FieldTooLong {
        /// The ASN.1 field name.
        field: &'static str,
        /// The bound.
        limit: usize,
    },
    /// The challenge is not a valid RFC 6560 message.
    #[error("malformed PA-OTP-CHALLENGE: {message}")]
    Malformed {
        /// What is wrong, without message bytes.
        message: String,
    },
    /// A token info sets both `collect-pin` and `do-not-collect-pin`
    /// (RFC 6560 section 4.1: the request is invalid).
    #[error("a token sets both collect-pin and do-not-collect-pin")]
    ConflictingPinFlags,
    /// Every token of the challenge needs a feature this client lacks (MIT
    /// `No supported tokens`).
    #[error("none of the {dropped} offered tokens is supported")]
    NoSupportedTokens {
        /// How many token infos were dropped.
        dropped: usize,
    },
    /// The answer selects a token the challenge does not list.
    #[error("token {index} is not one of the {count} offered tokens")]
    UnknownToken {
        /// The selected index.
        index: usize,
        /// The number of usable tokens.
        count: usize,
    },
    /// The OTP value does not fit the selected token.
    #[error("the OTP value is refused: {reason}")]
    ValueRejected {
        /// Why, without the value.
        reason: &'static str,
    },
    /// The OTP value or the PIN exceeds the policy's size bound.
    #[error("the OTP value or PIN exceeds {limit} bytes")]
    ValueTooLong {
        /// The bound.
        limit: usize,
    },
    /// The token requires a separate PIN and the answer has none.
    #[error("the token requires a separate PIN")]
    PinRequired,
    /// The answer has a PIN for a token that must not collect one.
    #[error("the token collects no PIN")]
    PinNotCollected,
    /// The armor key could not encrypt the nonce.
    #[error("sealing the OTP nonce failed")]
    Seal(#[from] Fast),
}
#[cfg(feature = "messages")]
/// PKINIT error (RFC 4556, RFC 5349, RFC 6112, RFC 8070, RFC 8636; `preauth::pkinit`).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Pkinit {
    /// The `pkinit` leaf feature is not compiled in.
    #[error("PKINIT needs the `pkinit` Cargo feature")]
    Unavailable,
    /// The KDC did not offer PA-PK-AS-REQ.
    #[error("the KDC does not offer PKINIT")]
    NotOffered,
    /// No trust anchor is configured.
    ///
    /// MIT: "No `pkinit_anchors` supplied".
    #[error("no pkinit_anchors are configured for realm {realm}")]
    NoAnchors {
        /// The realm.
        realm: String,
    },
    /// The client identity cannot be used.
    #[error("unusable PKINIT identity: {reason}")]
    Identity {
        /// Why, without key material.
        reason: &'static str,
    },
    /// A configured identity, trust or selector location cannot be honoured.
    #[error("{relation} location {location} is not supported")]
    UnsupportedLocation {
        /// The relation.
        relation: &'static str,
        /// The location type, such as `PKCS11`.
        location: String,
    },
    /// `pkinit_dh_min_bits` asks for a group below the 2048-bit floor.
    #[error("Diffie-Hellman groups of {bits} bits are refused; the floor is 2048")]
    DhGroupTooSmall {
        /// The requested size.
        bits: u32,
    },
    /// `pkinit_dh_min_bits` names no supported group.
    #[error("unknown pkinit_dh_min_bits value {value}")]
    InvalidDhGroup {
        /// The configured value.
        value: String,
    },
    /// A PKINIT structure is malformed or breaks an RFC rule.
    #[error("malformed PKINIT {structure}: {reason}")]
    Malformed {
        /// The structure.
        structure: &'static str,
        /// The broken rule.
        reason: &'static str,
    },
    /// An input exceeds its bound.
    #[error("PKINIT {structure} exceeds {limit} bytes")]
    TooLarge {
        /// The structure.
        structure: &'static str,
        /// The bound in bytes.
        limit: usize,
    },
    /// An algorithm is not supported or not permitted.
    #[error("unsupported PKINIT algorithm {algorithm}")]
    UnsupportedAlgorithm {
        /// The algorithm OID or name.
        algorithm: String,
    },
    /// A signature does not verify (MIT `KRB5KDC_ERR_INVALID_SIG`).
    #[error("the {what} signature does not verify")]
    Signature {
        /// What was signed.
        what: &'static str,
    },
    /// The KDC certificate chain is not acceptable.
    #[error("the KDC certificate is not trusted: {reason}")]
    Certificate {
        /// Why, without certificate contents.
        reason: &'static str,
    },
    /// A KDC certificate is revoked (MIT `KRB5KDC_ERR_REVOKED_CERTIFICATE`).
    #[error("a KDC chain certificate is revoked")]
    Revoked,
    /// No CRL covers a chain certificate while CRL checking is required.
    ///
    /// MIT `KRB5KDC_ERR_REVOCATION_STATUS_UNKNOWN`.
    #[error("the revocation status of a KDC chain certificate is unknown")]
    RevocationUnknown,
    /// The KDC certificate does not name the realm's KDC.
    ///
    /// Neither the realm's TGS nor a configured `pkinit_kdc_hostname` (MIT
    /// `KRB5KDC_ERR_KDC_NAME_MISMATCH`).
    #[error("the KDC certificate does not name the KDC of realm {realm}")]
    KdcName {
        /// The realm.
        realm: String,
    },
    /// The KDC certificate lacks the required key purpose.
    ///
    /// The EKU or the `digitalSignature` key usage (MIT
    /// `KRB5KDC_ERR_INCONSISTENT_KEY_PURPOSE`).
    #[error("the KDC certificate lacks the required key purpose")]
    KeyPurpose,
    /// The KDC's Diffie-Hellman or ECDH public value is invalid.
    #[error("the KDC's key-agreement public value is invalid")]
    PublicValue,
    /// The KDC's signed nonce differs from the request's.
    #[error("the PKINIT reply nonce {actual} does not match the request nonce {expected}")]
    NonceMismatch {
        /// The request nonce.
        expected: u32,
        /// The reply nonce.
        actual: u32,
    },
    /// The anonymous reply fails RFC 6112.
    ///
    /// MIT `KRB5_KDCREP_MODIFIED`, "Reply has wrong form of session key for
    /// anonymous request".
    #[error("the anonymous PKINIT reply is invalid: {reason}")]
    Anonymous {
        /// Why.
        reason: &'static str,
    },
    /// The reply came before a request, or the state is spent.
    #[error("unexpected PKINIT reply: {reason}")]
    Unexpected {
        /// Why.
        reason: &'static str,
    },
    /// An identity provider or signer failed.
    #[error("the PKINIT identity provider or signer failed")]
    Provider(#[source] ProviderError),
    /// A PKINIT file could not be read.
    #[error("cannot read PKINIT file {path}")]
    Io {
        /// The path.
        path: PathBuf,
        /// The cause.
        #[source]
        source: io::Error,
    },
    /// The key derivation or the anonymous key check failed.
    #[error("PKINIT key derivation failed")]
    Crypto(#[from] Crypto),
    /// The random generator failed.
    #[error("random generator failed")]
    Random(#[from] getrandom::Error),
    /// The KDC answered with a permanently rejected mode.
    ///
    /// RSA key transport (`encKeyPack`, D2).
    #[error("PKINIT reply refused by policy: {0}")]
    Policy(#[from] Policy),
}
#[cfg(feature = "spnego")]
/// SPNEGO/GSS token processing error.
#[derive(thiserror::Error)]
#[non_exhaustive]
pub enum Spnego {
    /// Input was absent.
    #[error("input is empty")]
    EmptyInput,
    /// DER input ended before a complete value could be read.
    #[error("truncated DER value")]
    TruncatedDer,
    /// DER used an unsupported high-tag-number form.
    #[error("high-tag-number DER form is not supported")]
    HighTagNumber,
    /// DER used an unsupported indefinite length.
    #[error("indefinite DER length is not supported")]
    IndefiniteLength,
    /// DER length uses redundant octets instead of its shortest representation.
    #[error("nonminimal DER length")]
    NonminimalLength,
    /// Known SPNEGO fields were repeated or appeared out of sequence.
    #[error("duplicate or reordered SPNEGO field")]
    InvalidFieldOrder,
    /// SPNEGO reqFlags to encode is not a canonical named-bit DER BIT STRING of at most 32 bits.
    ///
    /// Only encoding returns this; decoding keeps received `reqFlags` bytes unvalidated.
    #[error("invalid SPNEGO reqFlags BIT STRING")]
    InvalidReqFlags,
    /// DER length exceeds the remaining input.
    #[error("DER length exceeds remaining input")]
    LengthExceedsInput,
    /// DER value used an unexpected tag.
    #[error("unexpected DER tag: expected 0x{expected:02x}, got 0x{actual:02x}")]
    UnexpectedTag {
        /// Expected one-byte tag.
        expected: u8,
        /// Actual one-byte tag.
        actual: u8,
    },
    /// DER contained trailing bytes after the expected value.
    #[error("trailing DER data")]
    TrailingData,
    /// OID arcs were invalid.
    #[error("invalid object identifier")]
    InvalidOid,
    /// OID base-128 encoding was malformed.
    #[error("invalid object identifier encoding")]
    InvalidOidEncoding,
    /// SPNEGO OID did not match `1.3.6.1.5.5.2`.
    #[error("unexpected SPNEGO OID: {0:?}")]
    UnexpectedSpnegoOid(ObjectIdentifier),
    /// The mechanism OID is not a supported Kerberos mechanism.
    #[error("unsupported mechanism OID: {0:?}")]
    UnsupportedMechanism(ObjectIdentifier),
    /// A mechanism switch or continuation needs retained SPNEGO negotiation state.
    #[error("SPNEGO mechanism switching and continuation require negotiation state")]
    NegotiationRequiresState,
    /// Extracting an AP-REQ alone cannot verify a supplied mechanism-list MIC.
    #[error("SPNEGO mechListMIC requires validated Kerberos context keys")]
    MechListMicRequiresState,
    /// A non-first mechanism requires a mechanism-list MIC.
    #[error("SPNEGO mechListMIC is required for a non-first mechanism")]
    MissingMechListMic,
    /// The mechanism-list MIC is malformed or fails context integrity checks.
    #[error("invalid SPNEGO mechListMIC")]
    InvalidMechListMic,
    /// The GSS authenticator omitted its RFC 4121 checksum.
    #[error("GSS authenticator checksum is required")]
    MissingAuthenticatorChecksum,
    /// The GSS authenticator checksum has an invalid type or structure.
    #[error("invalid RFC 4121 authenticator checksum")]
    InvalidAuthenticatorChecksum,
    /// The GSS authenticator omitted its mandatory sequence number.
    #[error("GSS authenticator sequence number is required")]
    MissingAuthenticatorSequence,
    /// Context initiation requested delegation without a delegated-credential input.
    #[error("GSS delegation requires a delegated credential, which this builder does not accept")]
    DelegationRequiresCredential,
    /// KRB5 token ID was unknown.
    #[error("unknown KRB5 token ID: {0:02x?}")]
    UnknownKrb5TokenId([u8; 2]),
    /// KRB5 token omitted its Kerberos message bytes.
    #[error("KRB5 token does not contain a Kerberos message")]
    MissingKerberosMessage,
    /// GSS-API MIC/Wrap token was too short.
    #[error("GSS token too short: expected at least {minimum} bytes, got {actual}")]
    GssTokenTooShort {
        /// Minimum accepted byte length.
        minimum: usize,
        /// Actual byte length.
        actual: usize,
    },
    /// GSS-API MIC/Wrap token ID was not the expected value.
    #[error("invalid GSS token ID: expected {expected:02x?}, got {actual:02x?}")]
    InvalidGssTokenId {
        /// Expected two-byte token id.
        expected: [u8; 2],
        /// Actual two-byte token id.
        actual: [u8; 2],
    },
    /// GSS-API token sender direction did not match the caller's expectation.
    #[error(
        "unexpected GSS token sender: expected_from_acceptor={expected_from_acceptor}, actual_from_acceptor={actual_from_acceptor}"
    )]
    UnexpectedGssTokenSender {
        /// Whether caller expected an acceptor token.
        expected_from_acceptor: bool,
        /// Whether token flags identify an acceptor token.
        actual_from_acceptor: bool,
    },
    /// GSS-API token filler bytes were invalid.
    #[error("invalid GSS token filler")]
    InvalidGssFiller,
    /// GSS-API token has no payload for checksum calculation.
    #[error("GSS token payload has not been set")]
    MissingGssPayload,
    /// GSS-API token has no checksum.
    #[error("GSS token checksum has not been set")]
    MissingGssChecksum,
    /// GSS-API token checksum was already set.
    #[error("GSS token checksum has already been set")]
    GssChecksumAlreadySet,
    /// GSS-API sealed token encrypted body was absent.
    #[error("GSS sealed token encrypted body has not been set")]
    MissingGssEncryptedBody,
    /// GSS-API sealed token encrypted body was already set.
    #[error("GSS sealed token encrypted body has already been set")]
    GssEncryptedBodyAlreadySet,
    /// GSS-API token needs encryption instead of a separate checksum.
    #[error("GSS sealed token must be encrypted, not checksummed")]
    SealedGssTokenNeedsEncryption,
    /// GSS-API token was not sealed.
    #[error("GSS token is not sealed")]
    GssTokenNotSealed,
    /// GSS-API token checksum length did not match the header.
    #[error("invalid GSS checksum length: expected {expected} bytes, got {actual}")]
    InvalidGssChecksumLength {
        /// Expected checksum length.
        expected: usize,
        /// Actual checksum length.
        actual: usize,
    },
    /// GSS-API wrap token EC length exceeded remaining bytes.
    #[error(
        "inconsistent wrap checksum length: token has {token_len} bytes, checksum length is {checksum_len}"
    )]
    InconsistentWrapChecksumLength {
        /// Whole token length.
        token_len: usize,
        /// Claimed checksum length.
        checksum_len: usize,
    },
    /// GSS-API checksum verification failed.
    #[error("GSS token checksum mismatch")]
    GssChecksumMismatch,
    /// GSS-API sealed token decrypted to too few bytes.
    #[error("GSS decrypted token too short: expected at least {minimum} bytes, got {actual}")]
    GssDecryptedTokenTooShort {
        /// Minimum accepted byte length.
        minimum: usize,
        /// Actual byte length.
        actual: usize,
    },
    /// GSS-API sealed token embedded header did not match the clear header.
    #[error("GSS sealed token embedded header mismatch")]
    InvalidGssEncryptedHeader,
    /// `NegTokenInit` omitted the mechanism list.
    #[error("NegTokenInit does not contain any mechanism types")]
    MissingMechTypes,
    /// SPNEGO token omitted the mechanism token.
    #[error("SPNEGO token does not contain a mechanism token")]
    MissingMechToken,
    /// SPNEGO token does not carry an AP-REQ.
    #[error("SPNEGO token does not carry a KRB5 AP-REQ")]
    MissingApReq,
    /// SPNEGO token does not carry an AP-REP.
    #[error("SPNEGO token does not carry a KRB5 AP-REP")]
    MissingApRep,
    /// A negotiation token had the wrong CHOICE variant.
    #[error("expected {expected}, got {actual}")]
    WrongNegotiationToken {
        /// Expected variant.
        expected: &'static str,
        /// Actual variant.
        actual: &'static str,
    },
    /// SPNEGO negotiation state was invalid.
    #[error("invalid SPNEGO negState: {0}")]
    InvalidNegState(u32),
    /// INTEGER/ENUMERATED value was not supported.
    #[error("invalid DER integer value")]
    InvalidInteger,
    /// HTTP header was not a usable `Negotiate` value.
    #[error("invalid Negotiate header")]
    InvalidNegotiateHeader,
    /// HTTP Negotiate header exceeded the parser's byte limit.
    #[error("Negotiate header exceeds {maximum} bytes: got {actual}")]
    NegotiateHeaderTooLong {
        /// Maximum accepted header value length in bytes.
        maximum: usize,
        /// Actual header value length in bytes.
        actual: usize,
    },
    /// Base64 decoding failed.
    #[error("base64 decode error: {0}")]
    Base64(#[source] base64::DecodeError),
    /// ASN.1 DER decode failed.
    #[error("failed to decode {target}: {message}")]
    Decode {
        /// Decoded type name.
        target: &'static str,
        /// Decoder error text.
        message: String,
    },
    /// ASN.1 DER encode failed.
    #[error("failed to encode {target}: {message}")]
    Encode {
        /// Encoded type name.
        target: &'static str,
        /// Encoder error text.
        message: String,
    },
    /// A Kerberos string value could not be constructed.
    #[error("invalid Kerberos string value: {0}")]
    InvalidKerberosString(String),
    /// A Kerberos integer could not fit in the expected Rust type.
    #[error("integer field {field} is out of range: {value}")]
    IntegerOutOfRange {
        /// Field name.
        field: &'static str,
        /// Integer value.
        value: String,
    },
    /// Message field did not contain the expected value.
    #[error("invalid {field}: expected {expected}, got {actual}")]
    InvalidMessage {
        /// Field name.
        field: &'static str,
        /// Expected value.
        expected: i32,
        /// Actual value.
        actual: String,
    },
    /// The encrypted data etype is not implemented yet.
    #[error("unsupported encryption type: {0}")]
    UnsupportedEtype(i32),
    /// A key did not match the encrypted AP-REP data etype.
    #[error(
        "key etype {key_etype} does not match AP-REP encrypted data etype {encrypted_data_etype}"
    )]
    ApRepKeyEtypeMismatch {
        /// Reply key encryption type.
        key_etype: i32,
        /// AP-REP encrypted data encryption type.
        encrypted_data_etype: i32,
    },
    /// Crypto operation failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] Crypto),
    /// Random byte generation failed.
    #[error("random byte generation failed: {0}")]
    Random(#[from] getrandom::Error),
    /// A Kerberos time could not be represented as a `SystemTime`.
    #[error("Kerberos time overflows SystemTime")]
    TimeOverflow,
    /// AP-REP did not echo the AP-REQ authenticator timestamp.
    #[error("AP-REP timestamp mismatch: expected {expected:?}, got {actual:?}")]
    ApRepTimestampMismatch {
        /// Expected AP-REQ authenticator timestamp.
        expected: SystemTime,
        /// Timestamp supplied by AP-REP.
        actual: SystemTime,
    },
    /// Service AP-REQ validation failed.
    #[error("service validation error: {0}")]
    Service(#[from] Service),
    /// Client AP-REQ construction failed.
    #[error("client AP-REQ construction error: {0}")]
    Client(#[source] Box<Client>),
}
#[cfg(feature = "messages")]
/// Ticket helper error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Ticket {
    /// ASN.1 DER decode failed.
    #[error("failed to decode {target}: {message}")]
    Decode {
        /// Decoded type name.
        target: &'static str,
        /// Decoder error text.
        message: String,
    },
    /// ASN.1 DER encode failed.
    #[error("failed to encode {target}: {message}")]
    Encode {
        /// Encoded type name.
        target: &'static str,
        /// Encoder error text.
        message: String,
    },
    /// Message field did not contain the expected value.
    #[error("invalid {field}: expected {expected}, got {actual}")]
    InvalidMessage {
        /// Field name.
        field: &'static str,
        /// Expected value.
        expected: i32,
        /// Actual value.
        actual: String,
    },
    /// The encrypted data etype is not implemented yet.
    #[error("unsupported encryption type: {0}")]
    UnsupportedEtype(i32),
    /// A key did not match the encrypted ticket data etype.
    #[error(
        "key etype {key_etype} does not match Ticket encrypted data etype {encrypted_data_etype}"
    )]
    KeyEtypeMismatch {
        /// Reply key encryption type.
        key_etype: i32,
        /// Ticket encrypted data encryption type.
        encrypted_data_etype: i32,
    },
    /// Random byte generation failed.
    #[error("random byte generation failed: {0}")]
    Random(#[from] getrandom::Error),
    /// Crypto operation failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] Crypto),
}
/// Realm-path, transited-encoding or certificate-identity failure (WP-11).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Routing {
    /// A realm name is empty.
    #[error("empty realm name")]
    EmptyRealm,
    /// A realm has no cross-realm path to itself.
    #[error("no cross-realm path from a realm to itself")]
    SameRealm,
    /// A configured path names a realm twice or an endpoint as an intermediate.
    #[error("realm path loops through {realm}")]
    PathLoop {
        /// The realm the path reaches a second time.
        realm: String,
    },
    /// A path holds more realms than the bound.
    #[error("realm path exceeds {max} realms")]
    PathTooLong {
        /// The bound, endpoints included.
        max: usize,
    },
    /// A transited encoding is longer than the bound.
    #[error("transited encoding exceeds {max} bytes")]
    TransitedTooLong {
        /// The bound in bytes.
        max: usize,
    },
    /// A transited realm name grows past the bound.
    #[error("transited realm name exceeds {max} bytes")]
    TransitedRealmTooLong {
        /// The bound in bytes.
        max: usize,
    },
    /// A transited encoding names more realms than the bound.
    #[error("transited encoding names more than {max} realms")]
    TransitedTooManyRealms {
        /// The bound, expanded realms included.
        max: usize,
    },
    /// A transited encoding is malformed.
    #[error("malformed transited encoding: {reason}")]
    MalformedTransited {
        /// What is wrong with it.
        reason: &'static str,
    },
    /// A certificate identity is empty or larger than the bound.
    #[error("a certificate identity holds 1 to {max} DER bytes")]
    CertificateSize {
        /// The bound in bytes.
        max: usize,
    },
    /// The certificate inspector refused the certificate.
    #[error("the certificate inspector refused the certificate: {0}")]
    CertificateRejected(#[source] ProviderError),
}
/// Local authorization and name translation error (WP-17, `localauth`).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LocalAuth {
    /// A rule value is neither `DEFAULT` nor `RULE:...` (MIT `KRB5_CONFIG_BADFORMAT`).
    #[error("unsupported auth_to_local rule type: {kind}")]
    UnsupportedRuleType {
        /// The text before the first colon, or the whole value.
        kind: String,
    },
    /// A RULE is malformed.
    #[error("malformed auth_to_local rule: {reason}")]
    MalformedRule {
        /// What is wrong, without the rule text.
        reason: &'static str,
    },
    /// A rule or an input exceeds a bound.
    #[error("auth_to_local {what} exceeds the limit of {limit}")]
    LimitExceeded {
        /// What grew past the bound.
        what: &'static str,
        /// The bound.
        limit: usize,
    },
    /// The regular-expression compiler refused a pattern.
    #[error("auth_to_local regular expression rejected: {message}")]
    InvalidRegex {
        /// The compiler's message.
        message: String,
    },
    /// No mapping or rule produced a local name (MIT `KRB5_LNAME_NOTRANS`).
    #[error("no local name for the principal")]
    NoTranslation,
    /// A translation is not a usable local account name.
    #[error("translated local name is not usable: {reason}")]
    InvalidLocalName {
        /// Why: empty, too long or containing NUL.
        reason: &'static str,
    },
}

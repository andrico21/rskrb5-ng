//! Typed errors grouped by Kerberos domain.
use core::str::Utf8Error;
#[cfg(feature = "messages")]
use core::time::Duration;
#[cfg(feature = "messages")]
use std::time::SystemTime;
use std::{env, io, path::PathBuf, time::SystemTimeError};

#[cfg(feature = "http")]
use http_types::header::{InvalidHeaderValue, ToStrError};
#[cfg(feature = "messages")]
use rasn::types::Integer;

#[cfg(feature = "messages")]
use crate::client::KdcError;
#[cfg(feature = "tokio")]
use crate::client::transport::KdcProtocol;
use crate::config::parameters::Failure as ExpansionFailure;
#[cfg(feature = "spnego")]
use crate::spnego::oid::ObjectIdentifier;
include!("error/any.rs");
include!("error/policy.rs");
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
    /// The AS-REP FAST negotiation checksum used an unsupported checksum type.
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
    /// DNS SRV KDC lookup failed.
    #[cfg(feature = "tokio")]
    #[error("DNS SRV lookup failed for {realm} over {protocol:?}: {message}")]
    DnsSrvLookup {
        /// Realm being discovered.
        realm: String,
        /// Requested wire protocol.
        protocol: KdcProtocol,
        /// Resolver error message.
        message: String,
    },
    /// DNS explicitly declares that the requested service is unavailable.
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
        /// Requested wire protocol.
        protocol: KdcProtocol,
    },
    /// All discovered KDC endpoint attempts failed.
    #[cfg(feature = "tokio")]
    #[error("all KDC endpoints for {realm} over {protocol:?} failed: {failures:?}")]
    KdcEndpointFailures {
        /// Realm being contacted.
        realm: String,
        /// Requested wire protocol.
        protocol: KdcProtocol,
        /// Per-endpoint failure messages.
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
}
/// Configuration parsing error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Config {
    /// Strict parsing rejects unrecognized sections.
    #[error("unknown configuration section: {section}")]
    UnknownSection {
        /// Section name.
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
    /// Include nesting reached past [`crate::config::MAX_INCLUDE_DEPTH`].
    #[error("include nesting reached depth {depth}, past the limit of {limit}")]
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
    /// PAC authorization data failed DER decoding.
    #[cfg(feature = "messages")]
    #[error("PAC authorization-data DER decode failed: {0}")]
    DerDecode(String),
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

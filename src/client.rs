//! Kerberos client-side exchange primitives.
//!
//! This module covers the first client slices needed for gokrb5-compatible
//! login flows: deterministic AS-REQ and TGS-REQ construction,
//! PA-ENC-TIMESTAMP and PA-TGS-REQ preauthentication, a KDC transport
//! boundary, encrypted-part validation, Tokio TCP/UDP transport, and
//! `krb5.conf`-driven KDC discovery.
#[cfg(feature = "tokio")]
use alloc::collections::BTreeMap;
#[cfg(feature = "tokio")]
use alloc::fmt;
#[cfg(feature = "tokio")]
use alloc::sync::Arc;
#[cfg(not(feature = "tokio"))]
use core::fmt;
use core::time::Duration;
#[cfg(feature = "tokio")]
use std::env;
#[cfg(feature = "tokio")]
use std::io;
#[cfg(feature = "tokio")]
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rasn::{der, types::Integer};
#[cfg(feature = "tokio")]
use tokio::{sync::Mutex, time::sleep};
use zeroize::Zeroizing;

#[cfg(feature = "tokio")]
use crate::config::Config;
#[cfg(all(feature = "spnego", feature = "tokio"))]
use crate::spnego;
use crate::{
    ap_req, ccache,
    crypto::{CryptoPolicy, KerberosEtype, Rc4HmacEtype, Use, kerb_checksum_hmac_md5, selection},
    error, kdc_rep, kdc_req,
    keytab::{EncryptionKey, Keytab},
    krb_error, messages, ticket,
};
#[cfg(feature = "tokio")]
use crate::{
    config::{credential_names, parameters::DefaultName},
    file_name,
    keytab::configured_keytab,
};
/// Identity-bound cache insertion.
#[cfg(feature = "tokio")]
mod cache_insert;
/// In-memory credential-cache replacement.
#[cfg(feature = "tokio")]
mod cache_update;
/// Redaction and erasure of client credential owners.
mod credential_debug;
/// Shared runtime policy validation before client effects.
mod crypto_policy;

/// Owning password input and erasure.
pub mod password;
/// Peer string-to-key policy regression tests.
#[cfg(test)]
#[path = "client/s2k_tests.rs"]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod s2k_tests;
/// Owning password input, erased on drop; see its explicit constructors.
pub type Password = password::Secret;
/// Password credential rotation eligibility.
#[cfg(feature = "tokio")]
mod password_rotation;
/// TGT refresh scheduling.
#[cfg(feature = "tokio")]
mod refresh_schedule;
/// Cached-session renewal eligibility.
#[cfg(feature = "tokio")]
mod renewal_eligibility;
#[cfg(feature = "tokio")]
use renewal_eligibility::session_renewable_at;
/// Preauthentication challenge request construction.
mod preauth;
/// Authenticated KDC reply time and flag constraints.
mod reply_constraints;
use preauth::{keytab_preauth_request, password_preauth_request};
/// TGT session metadata serialization.
#[cfg(all(feature = "tokio", feature = "serde"))]
mod session_json;
/// Shared Kerberos whole-second conversion boundary.
pub(crate) mod time;
#[cfg(feature = "tokio")]
use refresh_schedule::{session_refresh_delay_at, session_refresh_due_at};
/// Password-change request construction and verification.
pub mod kpasswd;
/// High-level SPNEGO/HTTP Negotiate client wrappers.
#[cfg(all(feature = "tokio", feature = "spnego"))]
pub mod negotiate;
/// AS-REQ and TGS-REQ option builders.
pub mod options;
/// Kerberos principal names used by the client.
pub mod principal;
#[cfg(feature = "tokio")]
/// KDC endpoint discovery and asynchronous transport.
pub mod transport;
#[cfg(feature = "tokio")]
use self::kpasswd::{RequestOptions, build_kpasswd_request, validated_result};
#[cfg(feature = "tokio")]
use self::transport::{KdcEndpoint, KdcProtocol, Tokio as TokioKdcTransport};
use self::{
    options::{ApReq, AsReq, TgsReq},
    principal::Principal,
};
#[cfg(feature = "tokio")]
use crate::kadmin;
/// Kerberos protocol version number carried in every message (RFC 4120).
const KRB5_PVNO: i32 = 5;
/// `KRB_NT_PRINCIPAL` name type: a user or ordinary principal.
const KRB_NT_PRINCIPAL: i32 = 1;
/// `KRB_NT_SRV_INST` name type: a service instance such as `krbtgt/REALM`.
const KRB_NT_SRV_INST: i32 = 2;
/// Ticket lifetime that request options start from: one day.
const DEFAULT_TICKET_LIFETIME: Duration = Duration::from_hours(24);
/// Default ticket enctypes, strongest first: AES-SHA2 then AES-SHA1.
const DEFAULT_TKT_ENCTYPES: &[i32] = &[20, 19, 18, 17];
/// Default TGS-REQ enctypes; the same list as the AS-REQ default.
const DEFAULT_TGS_ENCTYPES: &[i32] = DEFAULT_TKT_ENCTYPES;
/// Environment variable naming the default credential cache.
#[cfg(feature = "tokio")]
const KRB5CCNAME_ENV: &str = "KRB5CCNAME";
/// Environment variable naming the default client keytab.
#[cfg(feature = "tokio")]
const KRB5_CLIENT_KTNAME_ENV: &str = "KRB5_CLIENT_KTNAME";
/// PA-ENC-TIMESTAMP preauthentication type.
pub const PA_ENC_TIMESTAMP: i32 = 2;
/// PA-PW-SALT password salt hint (RFC 4120).
const PA_PW_SALT: i32 = 3;
/// PA-TGS-REQ preauthentication type.
pub const PA_TGS_REQ: i32 = 1;
/// PA-ETYPE-INFO preauthentication hint type.
pub const PA_ETYPE_INFO: i32 = 11;
/// PA-ETYPE-INFO2 preauthentication hint type.
pub const PA_ETYPE_INFO2: i32 = 19;
/// PA-REQ-ENC-PA-REP marker used by modern gokrb5-compatible AS exchanges.
pub const PA_REQ_ENC_PA_REP: i32 = 149;
/// PA-FX-FAST padata type used to signal FAST negotiation support.
pub const PA_FX_FAST: i32 = 136;
/// PA-FX-COOKIE padata type carrying KDC conversation state (RFC 6113 section 5.2).
pub const PA_FX_COOKIE: i32 = 133;
/// PA-AS-FRESHNESS padata type for AS freshness tokens (RFC 8070).
pub const PA_AS_FRESHNESS: i32 = 150;
/// PA-PAC-OPTIONS preauthentication type used by MS-KILE.
pub const PA_PAC_OPTIONS: i32 = 167;
/// PA-FOR-USER padata type used by `S4U2Self`.
pub const PA_FOR_USER: i32 = 129;
/// KDC error code for additional preauthentication required.
pub const KDC_ERR_PREAUTH_REQUIRED: i32 = 25;
/// KDC error code indicating the client should retry over TCP.
pub const KRB_ERR_RESPONSE_TOO_BIG: i32 = 52;
/// Key usage for AS-REQ encrypted timestamp preauthentication.
pub const AS_REQ_PA_ENC_TIMESTAMP_USAGE: u32 = 1;
/// Key usage for AS-REP encrypted parts.
pub const AS_REP_ENCPART_USAGE: u32 = kdc_rep::AS_REP_ENCPART_USAGE;
/// Key usage for PA-REQ-ENC-PA-REP checksums over the original AS-REQ.
pub const AS_REQ_CHECKSUM_USAGE: u32 = 56;
/// Key usage for the TGS-REQ request-body checksum inside the authenticator.
pub const TGS_REQ_AUTHENTICATOR_CHECKSUM_USAGE: u32 = 6;
/// Key usage for the PA-TGS-REQ AP-REQ authenticator.
pub const TGS_REQ_AUTHENTICATOR_USAGE: u32 = 7;
/// Key usage for normal AP-REQ authenticators.
pub const AP_REQ_AUTHENTICATOR_USAGE: u32 = 11;
/// Key usage for AP-REP encrypted parts.
pub const AP_REP_ENCPART_USAGE: u32 = 12;
/// Key usage for TGS-REP encrypted parts when encrypted with the TGT session key.
pub const TGS_REP_ENCPART_SESSION_KEY_USAGE: u32 = kdc_rep::TGS_REP_ENCPART_SESSION_KEY_USAGE;
/// Key usage/message type for PA-FOR-USER checksums.
pub const PA_FOR_USER_CHECKSUM_USAGE: u32 = 17;
/// Raw PAC option mask for `claims`.
pub const PAC_OPTION_CLAIMS: u32 = 0x8000_0000;
/// Raw PAC option mask for `branch-aware`.
pub const PAC_OPTION_BRANCH_AWARE: u32 = 0x4000_0000;
/// Raw PAC option mask for `forward-to-full-DC`.
pub const PAC_OPTION_FORWARD_TO_FULL_DC: u32 = 0x2000_0000;
/// Raw PAC option mask for `resource-based constrained delegation`.
pub const PAC_OPTION_RESOURCE_BASED_CONSTRAINED_DELEGATION: u32 = 0x1000_0000;
/// Ticket flag bit indicating the AS-REP carries encrypted padata.
pub const TICKET_FLAG_ENC_PA_REP: u32 = 0x0001_0000;
/// INVALID ticket flag in RFC 4120 bit-string order.
const TICKET_FLAG_INVALID: u32 = 0x0100_0000;
/// Raw KDC option mask for `renewable` in RFC 4120 bit-string order.
pub const KDC_OPTION_RENEWABLE: u32 = 0x0080_0000;
/// Raw KDC option mask for `canonicalize` in RFC 4120 bit-string order.
pub const KDC_OPTION_CANONICALIZE: u32 = 0x0001_0000;
/// Raw KDC option mask for `cname-in-addl-tkt` in RFC 4120 bit-string order.
pub const KDC_OPTION_CNAME_IN_ADDL_TKT: u32 = 0x0002_0000;
/// Raw KDC option mask for `renew` in RFC 4120 bit-string order.
pub const KDC_OPTION_RENEW: u32 = 0x0000_0002;
/// Encoded AS-REQ plus validation metadata needed when processing the AS-REP.
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub struct BuiltAsReq {
    /// Policy used for the request and all subsequent reply validation.
    pub crypto_policy: CryptoPolicy,
    /// Request clock snapshot and acceptable reply start-time skew.
    pub reply_clock: (SystemTime, Duration),
    /// ASN.1 AS-REQ message.
    pub message: rasn_kerberos::AsReq,
    /// DER-encoded AS-REQ bytes suitable for KDC transport.
    pub der: Zeroizing<Vec<u8>>,
    /// Request client principal.
    pub client: Principal,
    /// Request service principal.
    pub service: Principal,
    /// Request nonce.
    pub nonce: u32,
}
impl BuiltAsReq {
    /// Creates a `BuiltAsReq` from its required fields.
    #[must_use]
    #[inline]
    pub fn new(
        message: rasn_kerberos::AsReq,
        der: Zeroizing<Vec<u8>>,
        client: Principal,
        service: Principal,
        nonce: u32,
    ) -> Self {
        Self {
            crypto_policy: CryptoPolicy::default(),
            reply_clock: (SystemTime::now(), Duration::from_secs(300)),
            message,
            der,
            client,
            service,
            nonce,
        }
    }
}
/// Encoded TGS-REQ plus validation metadata needed when processing the TGS-REP.
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub struct BuiltTgsReq {
    /// Policy used for the request and all subsequent reply validation.
    pub crypto_policy: CryptoPolicy,
    /// Request clock snapshot and acceptable reply start-time skew.
    pub reply_clock: (SystemTime, Duration),
    /// Frontend keys for validating S4U tickets; never encoded on the wire.
    pub delegation_keytab: Option<Keytab>,
    /// ASN.1 TGS-REQ message.
    pub message: rasn_kerberos::TgsReq,
    /// DER-encoded TGS-REQ bytes suitable for KDC transport.
    pub der: Zeroizing<Vec<u8>>,
    /// Expected client principal in the KDC reply.
    ///
    /// This is normally the same principal that authenticated the TGS-REQ, but
    /// `S4U2Self` replies carry the impersonated user as the client.
    pub client: Principal,
    /// Requested service principal.
    pub service: Principal,
    /// Realm contacted for the TGS exchange.
    pub kdc_realm: String,
    /// Request nonce.
    pub nonce: u32,
}
impl BuiltTgsReq {
    /// Creates a `BuiltTgsReq` from its required fields.
    #[must_use]
    #[inline]
    pub fn new(
        message: rasn_kerberos::TgsReq,
        der: Zeroizing<Vec<u8>>,
        client: Principal,
        service: Principal,
        kdc_realm: String,
        nonce: u32,
    ) -> Self {
        Self {
            crypto_policy: CryptoPolicy::default(),
            reply_clock: (SystemTime::now(), Duration::from_secs(300)),
            message,
            der,
            client,
            service,
            kdc_realm,
            nonce,
            delegation_keytab: None,
        }
    }
}
/// The TGS-REQ plus the pieces an implicit-FAST caller needs from it.
///
/// RFC 6113 section 5.4.2 arms a TGS request implicitly when the TGT travels in
/// `PA-TGS-REQ`: the FAST `req-checksum` is keyed over the encoded AP-REQ, and
/// the armor key is `KRB-FX-CF2(subkey, TGT session key, "subkeyarmor",
/// "ticketarmor")` with the subkey this request's authenticator carries. Both
/// are returned here rather than added to [`BuiltTgsReq`], so unarmored callers
/// keep the shape they had.
#[derive(Clone)]
#[non_exhaustive]
pub struct TgsFastRequestParts {
    /// The request as built, with its validation metadata.
    pub request: BuiltTgsReq,
    /// DER of the AP-REQ placed in the outer `PA-TGS-REQ` padata.
    pub ap_req_der: Zeroizing<Vec<u8>>,
    /// The authenticator's subkey. Secret, and zeroized on drop: the implicit
    /// armor key is derived from it, so it must not reach a log.
    pub authenticator_subkey: EncryptionKey,
}
impl fmt::Debug for TgsFastRequestParts {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            request,
            ap_req_der,
            authenticator_subkey,
        } = self;
        f.debug_struct("TgsFastRequestParts")
            .field("request", request)
            .field("ap_req_der_len", &ap_req_der.len())
            .field("authenticator_subkey_etype", &authenticator_subkey.etype)
            .finish_non_exhaustive()
    }
}
/// Built client AP-REQ.
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub struct BuiltApReq {
    /// ASN.1 AP-REQ message.
    pub message: rasn_kerberos::ApReq,
    /// DER-encoded AP-REQ bytes.
    pub der: Zeroizing<Vec<u8>>,
    /// Client principal placed in the authenticator.
    pub client: Principal,
    /// Service principal from the ticket.
    pub service: Principal,
    /// Service-ticket session key used to encrypt the authenticator.
    pub session_key: EncryptionKey,
    /// Authenticator `ctime` without `cusec`.
    pub authenticator_ctime: SystemTime,
    /// Authenticator microsecond field.
    pub authenticator_cusec: u32,
    /// Authenticator timestamp including `cusec`.
    pub authenticator_time: SystemTime,
    /// Optional client sequence number supplied in the authenticator.
    pub sequence_number: Option<u32>,
    /// Optional client-selected subkey supplied in the authenticator.
    pub subkey: Option<EncryptionKey>,
}
/// Successful AS-REP processing result.
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub struct AsRepSession {
    /// Client identity returned by the KDC.
    pub client: Principal,
    /// Service identity returned by the KDC.
    pub service: Principal,
    /// Session key issued by the KDC.
    pub session_key: EncryptionKey,
    /// DER-encoded ticket from the AS-REP.
    pub ticket: Zeroizing<Vec<u8>>,
    /// Ticket flags as raw ccache bytes.
    pub ticket_flags: [u8; 4],
    /// Initial authentication time.
    pub auth_time: SystemTime,
    /// Ticket start time, or auth time when start time is absent.
    pub start_time: SystemTime,
    /// Ticket end time.
    pub end_time: SystemTime,
    /// Renewable-until time, when supplied.
    pub renew_till: Option<SystemTime>,
    /// Session key expiration time, when supplied.
    pub key_expiration: Option<SystemTime>,
}
impl AsRepSession {
    /// Creates a `AsRepSession` from its required fields.
    #[must_use]
    #[inline]
    pub const fn new(
        client: Principal,
        service: Principal,
        session_key: EncryptionKey,
        ticket: Zeroizing<Vec<u8>>,
        ticket_flags: [u8; 4],
        auth_time: SystemTime,
        end_time: SystemTime,
    ) -> Self {
        Self {
            client,
            service,
            session_key,
            ticket,
            ticket_flags,
            auth_time,
            start_time: auth_time,
            end_time,
            renew_till: None,
            key_expiration: None,
        }
    }
    /// Sets `start_time`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_start_time(mut self, value: SystemTime) -> Self {
        self.start_time = value;
        self
    }
    /// Sets `renew_till`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_renew_till(mut self, value: Option<SystemTime>) -> Self {
        self.renew_till = value;
        self
    }
    /// Sets `key_expiration`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_key_expiration(mut self, value: Option<SystemTime>) -> Self {
        self.key_expiration = value;
        self
    }
    /// Convert this AS-REP result into the existing MIT ccache credential shape.
    /// # Errors
    ///
    /// Returns [`Error::TimeOverflow`] when a session time is before the Unix epoch,
    /// has a fractional second, or is after 2106.
    #[inline]
    pub fn to_ccache_credential(&self) -> Result<ccache::Credential, Error> {
        Ok(ccache::Credential {
            client: ccache_principal(&self.client),
            server: ccache_principal(&self.service),
            key: ccache::EncryptionKey {
                etype: self.session_key.etype,
                value: self.session_key.value.clone(),
            },
            times: ccache::CredentialTimes {
                auth_time: system_time_to_u32_seconds(self.auth_time)?,
                start_time: system_time_to_u32_seconds(self.start_time)?,
                end_time: system_time_to_u32_seconds(self.end_time)?,
                renew_till: self
                    .renew_till
                    .map(system_time_to_u32_seconds)
                    .transpose()?
                    .unwrap_or_default(),
            },
            is_skey: false,
            ticket_flags: self.ticket_flags,
            addresses: Vec::new(),
            auth_data: Vec::new(),
            ticket: self.ticket.clone(),
            second_ticket: Zeroizing::default(),
        })
    }
}
/// Successful TGS-REP processing result.
///
/// The ticket/session material is the same shape as an AS-REP result and can
/// be written to the existing ccache credential representation.
pub type TgsRepSession = AsRepSession;
/// Result of a referral-following TGS exchange.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ReferralTgsResult {
    /// Final service ticket.
    pub ticket: TgsRepSession,
    /// Intermediate referral TGTs acquired while reaching the service realm.
    pub referral_tgts: Vec<AsRepSession>,
}
/// Runtime-neutral boundary for KDC request/response transport.
pub trait KdcTransport {
    /// Send an encoded KDC request and return the encoded KDC response.
    /// # Errors
    ///
    /// Returns the transport's error when the request cannot be delivered or no
    /// response arrives.
    fn send(&mut self, realm: &str, request: &[u8]) -> Result<Vec<u8>, Error>;
}
/// Parsed KRB-ERROR returned by a KDC.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct KdcError {
    /// Client time, when present.
    pub ctime: Option<SystemTime>,
    /// Client microseconds, when present.
    pub cusec: Option<u32>,
    /// KDC/server time.
    pub stime: SystemTime,
    /// KDC/server microseconds.
    pub susec: u32,
    /// Kerberos error code.
    pub error_code: i32,
    /// Optional human-readable error text.
    pub text: Option<String>,
    /// Client principal carried by the error, when present.
    pub client: Option<Principal>,
    /// Service principal that issued the error.
    pub service: Principal,
    /// Raw e-data bytes, when present.
    pub e_data: Option<Vec<u8>>,
    /// Parsed METHOD-DATA PA-DATA values for preauthentication errors.
    pub method_data: Vec<rasn_kerberos::PaData>,
    /// Parsed PA-ETYPE-INFO2/PA-ETYPE-INFO key derivation hints.
    pub preauth_key_info: Vec<PreauthKeyInfo>,
}
impl KdcError {
    /// Creates a `KdcError` from its required fields.
    #[must_use]
    #[inline]
    pub const fn new(stime: SystemTime, susec: u32, error_code: i32, service: Principal) -> Self {
        Self {
            ctime: None,
            cusec: None,
            stime,
            susec,
            error_code,
            text: None,
            client: None,
            service,
            e_data: None,
            method_data: Vec::new(),
            preauth_key_info: Vec::new(),
        }
    }
    /// Sets `ctime`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_ctime(mut self, value: Option<SystemTime>) -> Self {
        self.ctime = value;
        self
    }
    /// Sets `cusec`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_cusec(mut self, value: Option<u32>) -> Self {
        self.cusec = value;
        self
    }
    /// Sets `text`, preserving the other fields.
    #[must_use]
    #[inline]
    pub fn with_text(mut self, value: Option<String>) -> Self {
        self.text = value;
        self
    }
    /// Sets `client`, preserving the other fields.
    #[must_use]
    #[inline]
    pub fn with_client(mut self, value: Option<Principal>) -> Self {
        self.client = value;
        self
    }
    /// Sets `e_data`, preserving the other fields.
    #[must_use]
    #[inline]
    pub fn with_e_data(mut self, value: Option<Vec<u8>>) -> Self {
        self.e_data = value;
        self
    }
    /// Sets `method_data`, preserving the other fields.
    #[must_use]
    #[inline]
    pub fn with_method_data(mut self, value: Vec<rasn_kerberos::PaData>) -> Self {
        self.method_data = value;
        self
    }
    /// Sets `preauth_key_info`, preserving the other fields.
    #[must_use]
    #[inline]
    pub fn with_preauth_key_info(mut self, value: Vec<PreauthKeyInfo>) -> Self {
        self.preauth_key_info = value;
        self
    }
}
/// KDC hint for deriving or selecting a preauthentication key.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct PreauthKeyInfo {
    /// Encryption type requested by the KDC.
    pub etype: i32,
    /// Optional password salt.
    pub salt: Option<String>,
    /// Optional string-to-key parameters as raw bytes.
    pub s2kparams: Option<Vec<u8>>,
}
impl PreauthKeyInfo {
    /// Creates a `PreauthKeyInfo` from its required fields.
    #[must_use]
    #[inline]
    pub const fn new(etype: i32) -> Self {
        Self {
            etype,
            salt: None,
            s2kparams: None,
        }
    }
    /// Sets `salt`, preserving the other fields.
    #[must_use]
    #[inline]
    pub fn with_salt(mut self, value: Option<String>) -> Self {
        self.salt = value;
        self
    }
    /// Sets `s2kparams`, preserving the other fields.
    #[must_use]
    #[inline]
    pub fn with_s2kparams(mut self, value: Option<Vec<u8>>) -> Self {
        self.s2kparams = value;
        self
    }
}
/// Long-term credential source used by [`Tokio`].
#[cfg(feature = "tokio")]
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum TokioClientCredentials {
    /// Password credential for AS login.
    Password(Zeroizing<Vec<u8>>),
    /// Keytab credential for AS login.
    Keytab(Keytab),
}
#[cfg(feature = "tokio")]
impl fmt::Debug for TokioClientCredentials {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Password(_) => f.write_str("Password(<redacted>)"),
            Self::Keytab(keytab) => f
                .debug_struct("Keytab")
                .field("entries", &keytab.entries().len())
                .finish(),
        }
    }
}
/// Client configuration and runtime-state diagnostics.
///
/// This is the structured equivalent of gokrb5's client diagnostics output:
/// callers can inspect local credential state, KDC discovery results, and
/// configuration/keytab mismatches without parsing a formatted text block.
#[cfg(feature = "tokio")]
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "PascalCase"))]
#[non_exhaustive]
pub struct TokioClientDiagnostics {
    /// Client principal name.
    pub client: String,
    /// Client realm.
    pub realm: String,
    /// Selected high-level transport protocol.
    pub protocol: String,
    /// Configured credential source: `password`, `keytab`, or `none`.
    pub credential_source: String,
    /// Whether the client currently holds a TGT session.
    pub has_tgt: bool,
    /// Number of cached TGT sessions.
    pub tgt_session_count: usize,
    /// Number of cached service tickets.
    pub service_ticket_cache_count: usize,
    /// Configured default ticket enctype IDs.
    pub default_tkt_enctypes: Vec<i32>,
    /// Configured preferred preauthentication type IDs.
    pub preferred_preauth_types: Vec<i32>,
    /// Key encryption type IDs for the client's realm and ordered components.
    pub keytab_enctypes: Vec<i32>,
    /// UDP KDC endpoints discovered from config or DNS.
    #[cfg_attr(feature = "serde", serde(rename = "UDPKDCs"))]
    pub udp_kdcs: Vec<String>,
    /// TCP KDC endpoints discovered from config or DNS.
    #[cfg_attr(feature = "serde", serde(rename = "TCPKDCs"))]
    pub tcp_kdcs: Vec<String>,
    /// Configuration and discovery errors found by diagnostics.
    pub errors: Vec<String>,
}
#[cfg(feature = "tokio")]
impl TokioClientDiagnostics {
    #[must_use]
    /// Whether diagnostics found no errors.
    #[inline]
    pub const fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }
}
/// Counts of unusable sessions removed from a Tokio client cache.
#[cfg(feature = "tokio")]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "PascalCase"))]
#[non_exhaustive]
pub struct PrunedSessions {
    /// Whether the primary TGT was removed.
    pub primary_tgt: bool,
    /// Number of realm-keyed TGT sessions removed.
    pub tgt_sessions: usize,
    /// Number of service tickets removed.
    pub service_tickets: usize,
}
#[cfg(feature = "tokio")]
impl PrunedSessions {
    /// Sets `primary_tgt`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_primary_tgt(mut self, value: bool) -> Self {
        self.primary_tgt = value;
        self
    }
    /// Sets `tgt_sessions`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_tgt_sessions(mut self, value: usize) -> Self {
        self.tgt_sessions = value;
        self
    }
    /// Sets `service_tickets`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_service_tickets(mut self, value: usize) -> Self {
        self.service_tickets = value;
        self
    }
    #[must_use]
    /// Whether no sessions were removed.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        !self.primary_tgt && self.tgt_sessions == 0 && self.service_tickets == 0
    }
}
#[cfg(feature = "tokio")]
/// Background renewal task ownership.
pub mod auto_renewal;
/// Handle for a background Tokio TGT auto-renewal task.
#[cfg(feature = "tokio")]
pub type TokioClientAutoRenewal = auto_renewal::Handle;
/// High-level Tokio Kerberos client with TGT and service-ticket caching.
#[cfg(feature = "tokio")]
#[derive(Clone, Eq, PartialEq)]
pub struct Tokio {
    /// Deferred typed policy failure from legacy infallible import constructors.
    import_policy_error: Option<error::Policy>,
    /// Kerberos configuration used for realm and KDC lookups.
    config: Config,
    /// Transport protocol policy for KDC exchanges.
    protocol: KdcProtocol,
    /// Tokio KDC transport.
    transport: TokioKdcTransport,
    /// Client principal this client authenticates as.
    client: Principal,
    /// Long-term credential for AS login, if any.
    credentials: Option<TokioClientCredentials>,
    /// Primary TGT session for the client realm.
    tgt: Option<AsRepSession>,
    /// TGT sessions keyed by the realm they are issued for.
    tgt_sessions: BTreeMap<String, AsRepSession>,
    /// Service tickets keyed by `service_cache_key`.
    service_tickets: BTreeMap<(String, Vec<String>), TgsRepSession>,
    /// Send PA-ENC-TIMESTAMP in the first AS-REQ instead of probing.
    assume_preauthentication: bool,
    /// Request FAST negotiation (PA-REQ-ENC-PA-REP) in AS-REQs.
    fast_negotiation: bool,
}
#[cfg(feature = "tokio")]
impl fmt::Debug for Tokio {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            config,
            import_policy_error,
            protocol,
            transport,
            client,
            credentials,
            tgt,
            tgt_sessions,
            service_tickets,
            assume_preauthentication,
            fast_negotiation,
        } = self;
        f.debug_struct("TokioClient")
            .field("import_policy_error", import_policy_error)
            .field("config", config)
            .field("protocol", protocol)
            .field("transport", transport)
            .field("client", client)
            .field("credentials", credentials)
            .field("has_tgt", &tgt.is_some())
            .field("tgt_sessions", &tgt_sessions.len())
            .field("cached_service_tickets", &service_tickets.len())
            .field("assume_preauthentication", assume_preauthentication)
            .field("fast_negotiation", fast_negotiation)
            .finish()
    }
}
#[cfg(feature = "tokio")]
impl Tokio {
    /// Create a password-backed client using KDCs discovered from config.
    #[inline]
    pub fn with_password<P>(
        config: Config,
        protocol: KdcProtocol,
        client: Principal,
        password: P,
    ) -> Self
    where
        P: Into<Vec<u8>>,
    {
        Self::new(
            config,
            protocol,
            client,
            Some(TokioClientCredentials::Password(Zeroizing::new(
                password.into(),
            ))),
        )
    }
    #[must_use]
    /// Create a keytab-backed client using KDCs discovered from config.
    #[inline]
    pub const fn with_keytab(
        config: Config,
        protocol: KdcProtocol,
        client: Principal,
        keytab: Keytab,
    ) -> Self {
        Self::new(
            config,
            protocol,
            client,
            Some(TokioClientCredentials::Keytab(keytab)),
        )
    }
    /// Create a keytab-backed client by loading a file-backed keytab name.
    ///
    /// Bare paths, `FILE:path`, and `WRFILE:path` are supported by the keytab
    /// module. Other keytab stores are rejected explicitly.
    /// # Errors
    ///
    /// Returns [`Error::Keytab`] when the keytab name uses an unsupported store or
    /// the keytab cannot be read or parsed.
    #[inline]
    pub fn with_keytab_name<P>(
        config: Config,
        protocol: KdcProtocol,
        client: Principal,
        keytab_name: P,
    ) -> Result<Self, Error>
    where
        P: AsRef<str>,
    {
        Ok(Self::with_keytab(
            config,
            protocol,
            client,
            Keytab::load_name(keytab_name)?,
        ))
    }
    /// Create a keytab-backed client from `config.libdefaults.default_client_keytab_name`.
    /// # Ambient input
    /// Expands templates using `TMPDIR`, `TEMP`, `APPDATA` and process identity.
    /// Use `with_keytab_name` with a literal name to avoid this discovery.
    /// # Errors
    ///
    /// Returns [`Error::Keytab`] when the configured keytab cannot be loaded.
    #[inline]
    pub fn with_client_keytab_from_config(
        config: Config,
        protocol: KdcProtocol,
        client: Principal,
    ) -> Result<Self, Error> {
        let keytab = configured_keytab(&config.libdefaults, DefaultName::ClientKeytab)?;
        Ok(Self::with_keytab(config, protocol, client, keytab))
    }
    /// Create a keytab-backed client from the default client keytab.
    ///
    /// # Ambient input
    /// Reads `KRB5_CLIENT_KTNAME`; use `with_client_keytab_from_config` to avoid discovery.
    /// The configured fallback expands `TMPDIR`, `TEMP`, `APPDATA` and process identity;
    /// use `with_keytab_name` with a literal name to avoid expansion discovery.
    ///
    /// `KRB5_CLIENT_KTNAME` takes precedence when set. Otherwise this falls
    /// back to `config.libdefaults.default_client_keytab_name`.
    /// # Errors
    ///
    /// Returns [`Error::DefaultClientKeytabName`] when `KRB5_CLIENT_KTNAME` is not
    /// valid Unicode and [`Error::Keytab`] when the keytab cannot be loaded.
    #[inline]
    pub fn with_client_keytab_from_default(
        config: Config,
        protocol: KdcProtocol,
        client: Principal,
    ) -> Result<Self, Error> {
        let keytab = default_client_keytab_name(&config)?;
        Ok(Self::with_keytab(config, protocol, client, keytab))
    }
    /// Create a keytab-backed client by loading the file keytab named by `KRB5_CLIENT_KTNAME`.
    ///
    /// # Ambient input
    /// Reads `KRB5_CLIENT_KTNAME`; use `with_keytab_name` for an explicit name.
    /// # Errors
    ///
    /// Returns [`Error::DefaultClientKeytabName`] when `KRB5_CLIENT_KTNAME` is unset
    /// or not valid Unicode and [`Error::Keytab`] when the keytab cannot be loaded.
    #[inline]
    pub fn with_client_keytab_from_env(
        config: Config,
        protocol: KdcProtocol,
        client: Principal,
    ) -> Result<Self, Error> {
        let keytab_name =
            env::var(KRB5_CLIENT_KTNAME_ENV).map_err(Error::DefaultClientKeytabName)?;
        Self::with_keytab_name(config, protocol, client, keytab_name)
    }
    /// Create a keytab-backed client by loading the file keytab named by `KRB5_KTNAME`.
    ///
    /// # Ambient input
    /// Reads `KRB5_KTNAME`; use `with_keytab_name` for an explicit name.
    /// # Errors
    ///
    /// Returns [`Error::Keytab`] when `KRB5_KTNAME` is unset or invalid or the keytab
    /// cannot be loaded.
    #[inline]
    pub fn with_keytab_from_env(
        config: Config,
        protocol: KdcProtocol,
        client: Principal,
    ) -> Result<Self, Error> {
        Ok(Self::with_keytab(
            config,
            protocol,
            client,
            Keytab::load_from_env()?,
        ))
    }
    #[must_use]
    /// Attach or replace password credentials on an existing client.
    ///
    /// This is useful when starting from a ccache-loaded client and keeping
    /// live credentials available for later refreshes.
    #[inline]
    pub fn with_password_credential<P>(mut self, password: P) -> Self
    where
        P: Into<Vec<u8>>,
    {
        self.credentials = Some(TokioClientCredentials::Password(Zeroizing::new(
            password.into(),
        )));
        self
    }
    #[must_use]
    /// Attach or replace keytab credentials on an existing client.
    ///
    /// This is useful when starting from a ccache-loaded client and keeping
    /// live credentials available for later refreshes.
    #[inline]
    pub fn with_keytab_credential(mut self, keytab: Keytab) -> Self {
        self.credentials = Some(TokioClientCredentials::Keytab(keytab));
        self
    }
    #[must_use]
    /// Create a cache-only client from a ccache.
    ///
    /// Cached TGTs and service tickets are reused and renewed when possible.
    /// Excluded credentials are not admitted. A policy failure is retained and
    /// returned by operational methods before effects; use [`Self::try_from_ccache`]
    /// to receive it immediately.
    /// If no live password or keytab credential is configured, expired
    /// non-renewable entries cannot be re-acquired from the KDC.
    #[inline]
    pub fn from_ccache(config: Config, protocol: KdcProtocol, cache: &ccache::CCache) -> Self {
        let client = client_principal_from_ccache(cache.default_principal());
        let mut kerberos = Self::new(config, protocol, client, None);
        let now = SystemTime::now();
        for credential in cache.entries() {
            if !same_ccache_client_identity(&credential.client, cache.default_principal()) {
                continue;
            }
            let session = ccache_credential_session(credential);
            let insertion = if is_tgt_principal(&session.service) {
                // A TGT whose service names no realm cannot be cached; it is
                // skipped like the other unusable entries.
                kerberos.cache_tgt_session_at(session, now)
            } else {
                kerberos.cache_service_ticket(session)
            };
            if let Err(skipped) = insertion
                && let Some(policy) = crypto_policy::cause(&skipped)
            {
                kerberos.import_policy_error = Some(policy);
            }
        }
        kerberos
    }
    /// Import a ccache and report policy rejection immediately.
    /// # Errors
    /// Returns typed policy refusal for excluded credentials or invalid configuration.
    #[inline]
    pub fn try_from_ccache(
        config: Config,
        protocol: KdcProtocol,
        cache: &ccache::CCache,
    ) -> Result<Self, Error> {
        let policy = crypto_policy::configured(&config.libdefaults)?;
        for credential in cache.entries() {
            if same_ccache_client_identity(&credential.client, cache.default_principal()) {
                crypto_policy::session(
                    &policy,
                    &ccache_credential_session(credential),
                    Use::ImportedCredential,
                )?;
            }
        }
        let client = Self::from_ccache(config, protocol, cache);
        crypto_policy::ready(&client)?;
        Ok(client)
    }
    /// Create a cache-only client by loading a ccache name.
    ///
    /// Bare paths, `FILE:path`, `WRFILE:path`, and MIT `DIR:` collection names
    /// are supported by the ccache module. Other credential cache stores are
    /// rejected explicitly.
    /// # Errors
    ///
    /// Returns [`Error::CCache`] when the cache name uses an unsupported store or
    /// the cache cannot be read or parsed.
    #[inline]
    pub fn from_ccache_name<P>(
        config: Config,
        protocol: KdcProtocol,
        cache_name: P,
    ) -> Result<Self, Error>
    where
        P: AsRef<str>,
    {
        let cache = ccache::CCache::load_name(cache_name)?;
        Self::try_from_ccache(config, protocol, &cache)
    }
    /// Create a cache-only client from `config.libdefaults.default_ccache_name`.
    /// # Ambient input
    /// Expands templates using `TMPDIR`, `TEMP`, `APPDATA` and process identity.
    /// Use `from_ccache_name` with a literal name to avoid this discovery.
    /// # Errors
    ///
    /// Returns [`Error::NoDefaultCCacheName`] when `default_ccache_name` is empty
    /// and [`Error::CCache`] when the cache cannot be loaded.
    #[inline]
    pub fn from_default_ccache_name(config: Config, protocol: KdcProtocol) -> Result<Self, Error> {
        let cache_name = configured_default_ccache_name(&config)?;
        let cache = ccache::CCache::load(ccache::CCache::resolved_file_path(&cache_name)?)?;
        Self::try_from_ccache(config, protocol, &cache)
    }
    /// Create a cache-only client from the default credential cache.
    ///
    /// # Ambient input
    /// Reads `KRB5CCNAME`; use `from_default_ccache_name` to use only configuration.
    /// The configured fallback expands `TMPDIR`, `TEMP`, `APPDATA` and process identity;
    /// use `from_ccache_name` with a literal name to avoid expansion discovery.
    ///
    /// `KRB5CCNAME` takes precedence when set. Otherwise this falls back to
    /// `config.libdefaults.default_ccache_name`.
    /// # Errors
    ///
    /// Returns [`Error::CCache`] when `KRB5CCNAME` is not valid Unicode or the cache
    /// cannot be loaded, and [`Error::NoDefaultCCacheName`] when no cache is named.
    #[inline]
    pub fn from_default_ccache(config: Config, protocol: KdcProtocol) -> Result<Self, Error> {
        let cache_name = default_ccache_name(&config)?;
        let cache = ccache::CCache::load(ccache::CCache::resolved_file_path(&cache_name)?)?;
        Self::try_from_ccache(config, protocol, &cache)
    }
    /// Create a cache-only client by loading the file ccache named by `KRB5CCNAME`.
    ///
    /// # Ambient input
    /// Reads `KRB5CCNAME`; use `from_ccache_name` for an explicit name.
    /// # Errors
    ///
    /// Returns [`Error::CCache`] when `KRB5CCNAME` is unset or invalid or the cache
    /// cannot be loaded.
    #[inline]
    pub fn from_ccache_env(config: Config, protocol: KdcProtocol) -> Result<Self, Error> {
        let cache = ccache::CCache::load_from_env()?;
        Self::try_from_ccache(config, protocol, &cache)
    }
    #[must_use]
    /// Create a cache-only client from a known TGT session.
    /// Excluded credentials are not admitted; operational methods return the
    /// retained policy failure before use.
    #[inline]
    pub fn from_tgt_session(config: Config, protocol: KdcProtocol, tgt: AsRepSession) -> Self {
        let mut kerberos = Self::new(config, protocol, tgt.client.clone(), None);
        // A TGT whose service names no realm cannot be cached; the client then
        // starts without a session, as before.
        if let Err(skipped) = kerberos.cache_tgt_session(tgt) {
            kerberos.import_policy_error = crypto_policy::cause(&skipped);
        }
        kerberos
    }
    /// Export current TGT and service-ticket state to a fresh MIT ccache.
    /// # Errors
    ///
    /// Returns [`Error::TimeOverflow`] when a session time does not fit the ccache
    /// time format.
    #[inline]
    pub fn to_ccache(&self) -> Result<ccache::CCache, Error> {
        let mut cache = ccache::CCache::new(ccache_principal(&self.client));
        for credential in self.ccache_credentials()? {
            drop(cache.upsert_credential(credential));
        }
        Ok(cache)
    }
    /// Replace this client's non-configuration entries in an existing ccache.
    ///
    /// X-CACHECONF metadata and entries for other clients are preserved. The
    /// ccache default principal is set to this client's principal.
    /// # Errors
    ///
    /// Returns [`Error::TimeOverflow`] when a session time does not fit the ccache
    /// time format.
    #[inline]
    pub fn update_ccache(&self, cache: &mut ccache::CCache) -> Result<(), Error> {
        cache_update::update(self, cache)
    }
    /// Save current TGT and service-ticket state to a fresh ccache file.
    /// # Errors
    ///
    /// Returns [`Error::TimeOverflow`] when a session time does not fit the ccache
    /// time format and [`Error::CCache`] when the file cannot be written.
    #[inline]
    pub fn save_ccache<P>(&self, path: P) -> Result<(), Error>
    where
        P: AsRef<Path>,
    {
        self.to_ccache()?.save(path)?;
        Ok(())
    }
    /// Save current TGT and service-ticket state to a fresh ccache name.
    /// # Errors
    ///
    /// Returns [`Error::TimeOverflow`] when a session time does not fit the ccache
    /// time format and [`Error::CCache`] when the name uses an unsupported store or
    /// the cache cannot be written.
    #[inline]
    pub fn save_ccache_name<P>(&self, cache_name: P) -> Result<(), Error>
    where
        P: AsRef<str>,
    {
        self.to_ccache()?.save_name(cache_name)?;
        Ok(())
    }
    /// Save current TGT and service-ticket state to `config.libdefaults.default_ccache_name`.
    /// # Ambient input
    /// Expands templates using `TMPDIR`, `TEMP`, `APPDATA` and process identity.
    /// Use `save_ccache` with a literal path to avoid this discovery.
    /// # Errors
    ///
    /// Returns [`Error::NoDefaultCCacheName`] when `default_ccache_name` is empty,
    /// and the errors of [`Self::save_ccache_name`].
    #[inline]
    pub fn save_default_ccache_name(&self) -> Result<(), Error> {
        self.to_ccache()?
            .save_resolved_name(&configured_default_ccache_name(&self.config)?)?;
        Ok(())
    }
    /// Save current TGT and service-ticket state to the default credential cache.
    ///
    /// # Ambient input
    /// Reads `KRB5CCNAME`, which overrides the configured name when set; invalid
    /// Unicode is an error. Use [`Self::save_ccache_name`] for an explicit name
    /// or [`Self::save_default_ccache_name`] to use only configuration.
    /// Configured templates read `TMPDIR`, `TEMP`, `APPDATA` and process identity;
    /// use `save_ccache` with a literal path to avoid expansion discovery.
    ///
    /// `KRB5CCNAME` takes precedence when set. Otherwise this falls back to
    /// `config.libdefaults.default_ccache_name`.
    /// # Errors
    ///
    /// Returns [`Error::CCache`] when `KRB5CCNAME` is not valid Unicode,
    /// [`Error::NoDefaultCCacheName`] when no cache is named, and the errors of
    /// [`Self::save_ccache_name`].
    #[inline]
    pub fn save_default_ccache(&self) -> Result<(), Error> {
        self.to_ccache()?
            .save_resolved_name(&default_ccache_name(&self.config)?)?;
        Ok(())
    }
    /// Load an existing ccache when present, update this client's entries, and save it.
    ///
    /// Missing files are created. Existing X-CACHECONF metadata and entries for
    /// other clients are preserved.
    /// # Errors
    ///
    /// Returns [`Error::CCache`] when an existing file cannot be read or parsed or the
    /// file cannot be written, and [`Error::TimeOverflow`] when a session time does
    /// not fit the ccache time format.
    #[inline]
    pub fn update_ccache_file<P>(&self, path: P) -> Result<(), Error>
    where
        P: AsRef<Path>,
    {
        let cache_path = path.as_ref();
        let mut cache = match ccache::CCache::load(cache_path) {
            Ok(cache) => cache,
            Err(error::Ccache::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                ccache::CCache::new(ccache_principal(&self.client))
            }
            Err(error) => return Err(error.into()),
        };
        self.update_ccache(&mut cache)?;
        cache.save(cache_path)?;
        Ok(())
    }
    /// Load an existing ccache name, update this client's entries, and save it.
    ///
    /// Missing files are created. Existing X-CACHECONF metadata and entries for
    /// other clients are preserved.
    /// # Errors
    ///
    /// Returns [`Error::CCache`] when the name is not a file-backed cache, and the
    /// errors of [`Self::update_ccache_file`].
    #[inline]
    pub fn update_ccache_name<P>(&self, cache_name: P) -> Result<(), Error>
    where
        P: AsRef<str>,
    {
        let path = ccache::CCache::file_path_from_cache_name(cache_name.as_ref())?;
        self.update_ccache_file(path)
    }
    /// Update the ccache named by `config.libdefaults.default_ccache_name`.
    /// # Ambient input
    /// Expands templates using `TMPDIR`, `TEMP`, `APPDATA` and process identity.
    /// Use `update_ccache_file` with a literal path to avoid this discovery.
    /// # Errors
    ///
    /// Returns [`Error::NoDefaultCCacheName`] when `default_ccache_name` is empty,
    /// and the errors of [`Self::update_ccache_name`].
    #[inline]
    pub fn update_default_ccache_name(&self) -> Result<(), Error> {
        self.update_ccache_file(ccache::CCache::resolved_file_path(
            &configured_default_ccache_name(&self.config)?,
        )?)
    }
    /// Update the default credential cache.
    ///
    /// # Ambient input
    /// Reads `KRB5CCNAME`, which overrides the configured name when set; invalid
    /// Unicode is an error. Use [`Self::update_ccache_name`] for an explicit name
    /// or [`Self::update_default_ccache_name`] to use only configuration.
    /// Configured templates read `TMPDIR`, `TEMP`, `APPDATA` and process identity;
    /// use `update_ccache_file` with a literal path to avoid expansion discovery.
    ///
    /// `KRB5CCNAME` takes precedence when set. Otherwise this falls back to
    /// `config.libdefaults.default_ccache_name`.
    /// # Errors
    ///
    /// Returns [`Error::CCache`] when `KRB5CCNAME` is not valid Unicode,
    /// [`Error::NoDefaultCCacheName`] when no cache is named, and the errors of
    /// [`Self::update_ccache_name`].
    #[inline]
    pub fn update_default_ccache(&self) -> Result<(), Error> {
        self.update_ccache_file(ccache::CCache::resolved_file_path(&default_ccache_name(
            &self.config,
        )?)?)
    }
    /// Build a client with empty caches, the default transport and FAST
    /// negotiation enabled.
    const fn new(
        config: Config,
        protocol: KdcProtocol,
        client: Principal,
        credentials: Option<TokioClientCredentials>,
    ) -> Self {
        Self {
            import_policy_error: None,
            config,
            protocol,
            transport: TokioKdcTransport::new(),
            client,
            credentials,
            tgt: None,
            tgt_sessions: BTreeMap::new(),
            service_tickets: BTreeMap::new(),
            assume_preauthentication: false,
            fast_negotiation: true,
        }
    }
    #[must_use]
    /// Override the transport used for KDC exchanges.
    #[inline]
    pub const fn with_transport(mut self, transport: TokioKdcTransport) -> Self {
        self.transport = transport;
        self
    }
    #[must_use]
    /// Configure whether AS login sends PA-ENC-TIMESTAMP in the first AS-REQ.
    #[inline]
    pub const fn with_assume_preauthentication(mut self, assume_preauthentication: bool) -> Self {
        self.assume_preauthentication = assume_preauthentication;
        self
    }
    #[must_use]
    /// Configure whether AS login advertises PA-REQ-ENC-PA-REP.
    #[inline]
    pub const fn with_fast_negotiation(mut self, fast_negotiation: bool) -> Self {
        self.fast_negotiation = fast_negotiation;
        self
    }
    /// Spawn a background task that refreshes the primary TGT before expiry.
    ///
    /// Dropping or aborting the returned handle cancels the task. The client is
    /// shared explicitly so callers control the synchronization boundary.
    #[inline]
    pub fn spawn_auto_renewal(client: Arc<Mutex<Self>>) -> TokioClientAutoRenewal {
        Self::spawn_auto_renewal_with_retry(client, Duration::from_secs(60))
    }
    /// Spawn a background TGT refresh task with a custom retry delay for errors.
    #[inline]
    pub fn spawn_auto_renewal_with_retry(
        client: Arc<Mutex<Self>>,
        retry_delay: Duration,
    ) -> TokioClientAutoRenewal {
        let paced_retry_delay = retry_delay.max(Duration::from_millis(1));
        let handle = tokio::spawn(async move {
            loop {
                let delay = {
                    let guard = client.lock().await;
                    guard.tgt.as_ref().map_or(Duration::ZERO, |tgt| {
                        session_refresh_delay_at(tgt, SystemTime::now())
                    })
                };
                if !delay.is_zero() {
                    sleep(delay).await;
                }
                let mut guard = client.lock().await;
                if guard.credentials.is_none() && guard.tgt.is_none() {
                    return;
                }
                // A refresh that leaves the TGT due made no progress (for
                // example a cache-only, non-renewable ticket); pace that case
                // too instead of spinning for the rest of the refresh band.
                let refreshed = guard.refresh_tgt_if_needed().await.map(|_| ());
                let still_due = guard
                    .tgt
                    .as_ref()
                    .is_none_or(|tgt| session_refresh_due_at(tgt, SystemTime::now()));
                if refreshed.is_err() || still_due {
                    drop(guard);
                    sleep(paced_retry_delay).await;
                }
            }
        });
        TokioClientAutoRenewal::new(handle)
    }
    #[must_use]
    /// Parsed Kerberos configuration.
    #[inline]
    pub const fn config(&self) -> &Config {
        &self.config
    }
    #[must_use]
    /// Selected KDC wire protocol.
    #[inline]
    pub const fn protocol(&self) -> KdcProtocol {
        self.protocol
    }
    #[must_use]
    /// Client principal.
    #[inline]
    pub const fn client_principal(&self) -> &Principal {
        &self.client
    }
    /// Validate that the client has enough local state for KDC operations.
    /// # Errors
    ///
    /// Returns [`Error::MissingClientName`] for an empty client name or name
    /// component, [`Error::MissingClientRealm`] for an empty realm,
    /// [`Error::NoClientCredentials`] when neither a credential nor a TGT is
    /// available, and [`Error::NoConfiguredKdc`] when DNS KDC lookup is off and the
    /// realm has no configured KDC.
    #[inline]
    pub fn validate_configuration(&self) -> Result<(), Error> {
        if self.client.components.is_empty() || self.client.components.iter().any(String::is_empty)
        {
            return Err(Error::MissingClientName);
        }
        if self.client.realm.is_empty() {
            return Err(Error::MissingClientRealm);
        }
        if self.credentials.is_none() && self.tgt.is_none() {
            return Err(Error::NoClientCredentials);
        }
        if !self.config.libdefaults.dns_lookup_kdc.is_enabled() {
            let realm_entry =
                self.config
                    .realm(&self.client.realm)
                    .ok_or_else(|| Error::NoConfiguredKdc {
                        realm: self.client.realm.clone(),
                    })?;
            if realm_entry.kdc.is_empty() {
                return Err(Error::NoConfiguredKdc {
                    realm: self.client.realm.clone(),
                });
            }
        }
        Ok(())
    }
    #[must_use]
    /// Whether the client has enough local state for KDC operations.
    #[inline]
    pub fn is_configured(&self) -> bool {
        self.validate_configuration().is_ok()
    }
    /// Run structured client diagnostics.
    /// # Cancel safety
    ///
    /// cancel-safe: the diagnostics only read client state and perform lookups, so
    /// dropping the future discards the partial report and changes nothing.
    #[inline]
    pub async fn diagnostics(&self) -> TokioClientDiagnostics {
        let mut errors = Vec::new();
        if let Err(error) = self.validate_configuration() {
            errors.push(error.to_string());
        }
        let keytab_enctypes = match self.credentials.as_ref() {
            Some(TokioClientCredentials::Keytab(keytab)) => {
                let enctypes = keytab_client_enctypes(keytab, &self.client);
                record_keytab_enctype_diagnostics(
                    &mut errors,
                    &enctypes,
                    &self.config.libdefaults.default_tkt_enctype_ids(),
                    "default_tkt_enctypes",
                );
                enctypes
            }
            _ => Vec::new(),
        };
        let udp_kdcs = self
            .diagnostic_kdc_endpoints(KdcProtocol::Udp, &mut errors)
            .await;
        let tcp_kdcs = self
            .diagnostic_kdc_endpoints(KdcProtocol::Tcp, &mut errors)
            .await;
        TokioClientDiagnostics {
            client: self.client.name(),
            realm: self.client.realm.clone(),
            protocol: protocol_label(self.protocol).to_owned(),
            credential_source: credential_source(self.credentials.as_ref()).to_owned(),
            has_tgt: self.tgt.is_some(),
            tgt_session_count: self.tgt_sessions.len(),
            service_ticket_cache_count: self.service_tickets.len(),
            default_tkt_enctypes: self.config.libdefaults.default_tkt_enctype_ids(),
            preferred_preauth_types: self.config.libdefaults.preferred_preauth_types.clone(),
            keytab_enctypes,
            udp_kdcs,
            tcp_kdcs,
            errors,
        }
    }
    /// Run diagnostics and return pretty-printed JSON.
    /// # Errors
    ///
    /// Returns the `serde_json` error if the report cannot be serialized.
    /// # Cancel safety
    ///
    /// cancel-safe: the diagnostics only read client state and perform lookups, so
    /// dropping the future discards the partial report and changes nothing.
    #[cfg(feature = "serde")]
    #[inline]
    pub async fn diagnostics_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.diagnostics().await)
    }
    #[must_use]
    /// Whether AS login sends PA-ENC-TIMESTAMP in the first AS-REQ.
    #[inline]
    pub const fn assume_preauthentication(&self) -> bool {
        self.assume_preauthentication
    }
    #[must_use]
    /// Whether AS login advertises PA-REQ-ENC-PA-REP.
    #[inline]
    pub const fn fast_negotiation(&self) -> bool {
        self.fast_negotiation
    }
    #[must_use]
    /// Current TGT session, when logged in or loaded from cache.
    #[inline]
    pub const fn tgt_session(&self) -> Option<&AsRepSession> {
        self.tgt.as_ref()
    }
    #[must_use]
    /// Whether the primary TGT is missing, expired, or inside the refresh window.
    #[inline]
    pub fn tgt_refresh_due(&self) -> bool {
        self.tgt
            .as_ref()
            .is_none_or(|tgt| session_refresh_due_at(tgt, SystemTime::now()))
    }
    #[must_use]
    /// Number of cached TGT sessions keyed by target realm.
    #[inline]
    pub fn tgt_session_count(&self) -> usize {
        self.tgt_sessions.len()
    }
    #[must_use]
    /// Cached TGT session for a target realm, when present.
    #[inline]
    pub fn tgt_session_for_realm(&self, realm: &str) -> Option<&AsRepSession> {
        self.tgt_sessions.get(realm)
    }
    /// Remove a cached TGT session for a target realm.
    #[inline]
    pub fn remove_tgt_session_for_realm(&mut self, realm: &str) -> Option<AsRepSession> {
        let removed = self.tgt_sessions.remove(realm);
        if realm == self.client.realm {
            let primary = self.tgt.take();
            return removed.or(primary);
        }
        removed
    }
    #[must_use]
    /// Number of cached service tickets.
    #[inline]
    pub fn cached_service_ticket_count(&self) -> usize {
        self.service_tickets.len()
    }
    /// Clear cached service tickets without dropping the TGT.
    #[inline]
    pub fn clear_service_ticket_cache(&mut self) {
        self.service_tickets.clear();
    }
    #[must_use]
    /// Return a currently valid cached service ticket without contacting a KDC.
    #[inline]
    pub fn cached_service_ticket(&self, service: Principal) -> Option<TgsRepSession> {
        crypto_policy::ready(self).ok()?;
        let resolved = self.resolve_service_principal(service);
        let key = service_cache_key(&resolved);
        let mut ticket = self.service_tickets.get(&key)?.clone();
        crypto_policy::session(
            &crypto_policy::configured(&self.config.libdefaults).ok()?,
            &ticket,
            Use::SessionKey,
        )
        .ok()?;
        if !session_valid_at(&ticket, SystemTime::now()) {
            return None;
        }
        ticket.service = resolved;
        Some(ticket)
    }
    /// Remove a cached service ticket without dropping the TGT.
    #[inline]
    pub fn remove_cached_service_ticket(&mut self, service: Principal) -> Option<TgsRepSession> {
        let resolved = self.resolve_service_principal(service);
        let key = service_cache_key(&resolved);
        self.service_tickets.remove(&key)
    }
    /// Drop unusable TGT and service-ticket sessions, including expired renewable tickets.
    #[inline]
    pub fn prune_unusable_sessions(&mut self) -> PrunedSessions {
        self.prune_unusable_sessions_at(SystemTime::now())
    }
    /// Drop sessions that are not valid at `now`.
    fn prune_unusable_sessions_at(&mut self, now: SystemTime) -> PrunedSessions {
        let primary_tgt = self
            .tgt
            .as_ref()
            .is_some_and(|tgt| !session_valid_at(tgt, now));
        if primary_tgt {
            self.tgt = None;
        }
        let tgt_session_count = self.tgt_sessions.len();
        self.tgt_sessions
            .retain(|_, session| session_valid_at(session, now));
        let service_ticket_count = self.service_tickets.len();
        self.service_tickets
            .retain(|_, session| session_valid_at(session, now));
        PrunedSessions {
            primary_tgt,
            // `retain` never grows a map, so these differences cannot underflow.
            tgt_sessions: tgt_session_count.saturating_sub(self.tgt_sessions.len()),
            service_tickets: service_ticket_count.saturating_sub(self.service_tickets.len()),
        }
    }
    /// Drop live credentials, the TGT session, and all cached service tickets.
    #[inline]
    pub fn destroy(&mut self) {
        self.credentials = None;
        self.tgt = None;
        self.tgt_sessions.clear();
        self.service_tickets.clear();
    }
    /// Return public TGT session metadata as pretty-printed JSON.
    /// # Errors
    ///
    /// Returns the `serde_json` error if the sessions cannot be serialized.
    #[cfg(feature = "serde")]
    #[inline]
    pub fn sessions_json(&self) -> Result<String, serde_json::Error> {
        session_json::render(self)
    }
    /// Return public service-ticket cache metadata as pretty-printed JSON.
    /// # Errors
    ///
    /// Returns the `serde_json` error if the tickets cannot be serialized.
    #[cfg(feature = "serde")]
    #[inline]
    pub fn service_ticket_cache_json(&self) -> Result<String, serde_json::Error> {
        let tickets = self
            .service_tickets
            .values()
            .map(service_ticket_json_entry)
            .collect::<Vec<_>>();
        serde_json::to_string_pretty(&tickets)
    }
    /// Cache a service ticket, retaining the better entry for the same service.
    ///
    /// A currently valid session wins over an invalid one. If both have the same
    /// validity, the later end time wins; ties retain the cached session. Thus a
    /// shorter-lived valid candidate does not replace a longer-lived valid entry.
    /// To force replacement, first call [`Self::remove_cached_service_ticket`]
    /// for the service, then insert the candidate. Removal and insertion are
    /// separate operations; a rejected insertion does not restore a removed ticket.
    ///
    /// Client realm and ordered components must match; advisory name type is ignored.
    /// Rejection leaves the cache unchanged.
    /// # Errors
    /// Returns [`Error::CacheClientMismatch`] for another client identity.
    #[inline]
    pub fn cache_service_ticket(&mut self, ticket: TgsRepSession) -> Result<(), Error> {
        cache_insert::service_ticket(self, ticket)
    }
    /// Cache a TGT session, retaining the better entry for the same target realm.
    ///
    /// A currently valid session wins over an invalid one. If both have the same
    /// validity, the later end time wins; ties retain the cached session. Thus a
    /// shorter-lived valid candidate does not replace a longer-lived valid entry.
    /// To force replacement, first call [`Self::remove_tgt_session_for_realm`],
    /// then insert the candidate. For the client's home realm, removal clears
    /// both the realm-keyed entry and primary TGT. These are separate operations;
    /// a rejected insertion does not restore a removed TGT.
    ///
    /// Client realm and ordered components must match; advisory name type is ignored.
    /// Rejection leaves both the primary and realm-keyed caches unchanged.
    /// # Errors
    ///
    /// Returns [`Error::InvalidTgtSession`] when the session's service is not a
    /// `krbtgt/<realm>` principal, or [`Error::CacheClientMismatch`] for another client identity.
    #[inline]
    pub fn cache_tgt_session(&mut self, tgt: AsRepSession) -> Result<(), Error> {
        self.cache_tgt_session_at(tgt, SystemTime::now())
    }
    /// Cache a TGT session at `now`, keeping the better of it and any cached session
    /// for the same realm; a session for the client realm also becomes the primary TGT.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidTgtSession`] when the session's service is not a
    /// `krbtgt/<realm>` principal.
    fn cache_tgt_session_at(&mut self, tgt: AsRepSession, now: SystemTime) -> Result<(), Error> {
        cache_insert::tgt_session_at(self, tgt, now)
    }
    /// Ensure this client has a valid TGT, reusing an existing TGT when possible.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: the client's TGT and ticket caches are replaced only after an
    /// exchange completes, so dropping the future leaves the previous session in
    /// place and the call can be repeated.
    /// # Errors
    ///
    /// Returns [`Error::NoClientCredentials`] when a new login is needed but no
    /// password or keytab is configured, and any AS exchange error of [`Self::login`].
    #[inline]
    pub async fn affirm_login(&mut self) -> Result<&AsRepSession, Error> {
        crypto_policy::ready(self)?;
        if let Some(tgt) = self.tgt.clone() {
            let now = SystemTime::now();
            if session_valid_at(&tgt, now) {
                return self.tgt.as_ref().ok_or(Error::NoTgtSession);
            }
        }
        self.login().await
    }
    /// Perform AS login with the configured long-term credential.
    /// # Errors
    ///
    /// Returns [`Error::NoClientCredentials`] when no credential is configured and
    /// the cached TGT is not valid, and any AS exchange,
    /// transport or validation error.
    /// # Cancel safety
    ///
    /// cancel-safe: the client's TGT and ticket caches are updated only after an
    /// exchange completes, so dropping the future leaves the previous sessions in
    /// place and the call can be repeated. No server-side state is committed.
    #[inline]
    pub async fn login(&mut self) -> Result<&AsRepSession, Error> {
        crypto_policy::ready(self)?;
        let Some(credentials) = self.credentials.clone() else {
            let Some(tgt) = self.tgt.clone() else {
                return Err(Error::NoClientCredentials);
            };
            let now = SystemTime::now();
            if session_valid_at(&tgt, now) {
                return self.tgt.as_ref().ok_or(Error::NoTgtSession);
            }
            return Err(Error::NoClientCredentials);
        };
        let options = self.as_req_options()?;
        let session = match credentials {
            TokioClientCredentials::Password(password) => {
                self.transport
                    .login_tgt_with_password_config(
                        &self.config,
                        self.protocol,
                        self.client.clone(),
                        &password,
                        options,
                    )
                    .await?
            }
            TokioClientCredentials::Keytab(keytab) => {
                self.transport
                    .login_tgt_with_keytab_config(
                        &self.config,
                        self.protocol,
                        self.client.clone(),
                        &keytab,
                        options,
                    )
                    .await?
            }
        };
        self.tgt_sessions.clear();
        self.tgt = None;
        self.cache_tgt_session(session)?;
        self.service_tickets.clear();
        self.tgt.as_ref().ok_or(Error::NoTgtSession)
    }
    /// Renew the current TGT explicitly.
    /// # Errors
    ///
    /// Returns [`Error::NoTgtSession`] when no client-realm TGT is cached or the
    /// renewal does not yield one, and the errors of
    /// [`Self::renew_tgt_session_for_realm`].
    /// # Cancel safety
    ///
    /// cancel-safe: the client's TGT and ticket caches are updated only after an
    /// exchange completes, so dropping the future leaves the previous sessions in
    /// place and the call can be repeated. No server-side state is committed.
    #[inline]
    pub async fn renew_tgt(&mut self) -> Result<&AsRepSession, Error> {
        let realm = self.client.realm.clone();
        drop(self.renew_tgt_session_for_realm(&realm).await?);
        self.tgt.as_ref().ok_or(Error::NoTgtSession)
    }
    /// Renew a cached TGT session for a target realm.
    /// # Errors
    ///
    /// Returns [`Error::NoTgtSession`] when no TGT is cached for `realm`,
    /// [`Error::TicketNotRenewable`] for an unflagged, invalid, expired or future ticket,
    /// [`Error::InvalidTgtSession`] when the renewed ticket is not a TGT,
    /// [`Error::Random`] when the nonce cannot be generated, and any TGS exchange,
    /// transport or validation error.
    /// # Cancel safety
    ///
    /// cancel-safe: the client's TGT and ticket caches are updated only after an
    /// exchange completes, so dropping the future leaves the previous sessions in
    /// place and the call can be repeated. No server-side state is committed.
    #[inline]
    pub async fn renew_tgt_session_for_realm(
        &mut self,
        realm: &str,
    ) -> Result<AsRepSession, Error> {
        let tgt = if realm == self.client.realm {
            self.tgt
                .clone()
                .or_else(|| self.tgt_sessions.get(realm).cloned())
        } else {
            self.tgt_sessions.get(realm).cloned()
        }
        .ok_or(Error::NoTgtSession)?;
        session_renewable_at(&tgt, SystemTime::now()).ok_or(Error::TicketNotRenewable)?;
        let renewed = self
            .transport
            .renew_tgt_with_config(&self.config, self.protocol, &tgt, self.tgs_req_options()?)
            .await?;
        let renewed_realm = tgt_realm(&renewed).ok_or_else(|| Error::InvalidTgtSession {
            service: renewed.service.name(),
        })?;
        if renewed_realm == self.client.realm {
            self.tgt = Some(renewed.clone());
            self.service_tickets.clear();
        }
        drop(self.tgt_sessions.insert(renewed_realm, renewed.clone()));
        Ok(renewed)
    }
    /// Refresh the primary TGT if it is missing, expired, or inside the refresh window.
    /// # Errors
    ///
    /// Returns [`Error::NoClientCredentials`] when a new login is needed but no
    /// credential is configured, and any renewal or AS exchange error.
    /// # Cancel safety
    ///
    /// cancel-safe: the client's TGT and ticket caches are updated only after an
    /// exchange completes, so dropping the future leaves the previous sessions in
    /// place and the call can be repeated. No server-side state is committed.
    #[inline]
    pub async fn refresh_tgt_if_needed(&mut self) -> Result<&AsRepSession, Error> {
        drop(self.ensure_tgt().await?);
        self.tgt.as_ref().ok_or(Error::NoTgtSession)
    }
    /// Return a service ticket from cache or acquire one from a KDC.
    /// # Errors
    ///
    /// Returns the errors of acquiring a TGT, [`Error::Random`] when the nonce
    /// cannot be generated, and any TGS exchange, referral, transport or
    /// validation error.
    /// # Cancel safety
    ///
    /// cancel-safe: each cache update (a renewed TGT or service ticket) happens only
    /// after its exchange completes, so dropping the future leaves every cache in a
    /// consistent state and the call can be repeated. No server-side state is
    /// committed.
    #[inline]
    pub async fn get_service_ticket(
        &mut self,
        requested: Principal,
    ) -> Result<TgsRepSession, Error> {
        self.get_service_ticket_with_clock(requested, SystemTime::now)
            .await
    }

    /// Acquire a service ticket with a clock shared by the cache-selection decisions.
    ///
    /// # Errors
    /// Returns the same policy, discovery and exchange errors as service acquisition.
    ///
    /// # Cancel safety
    /// cancel-safe: cache updates occur only after authenticated exchanges complete.
    async fn get_service_ticket_with_clock<F>(
        &mut self,
        requested: Principal,
        mut clock: F,
    ) -> Result<TgsRepSession, Error>
    where
        F: FnMut() -> SystemTime,
    {
        crypto_policy::ready(self)?;
        let service = self.resolve_service_principal(requested);
        let key = service_cache_key(&service);
        if let Some(mut ticket) = self.service_tickets.get(&key).cloned() {
            crypto_policy::session(
                &crypto_policy::configured(&self.config.libdefaults)?,
                &ticket,
                Use::SessionKey,
            )?;
            let now = clock();
            if session_valid_at(&ticket, now) {
                ticket.service = service;
                return Ok(ticket);
            }
        }
        let tgt = match self.cached_tgt_session_for_realm(&service.realm, clock()) {
            Some(tgt) => tgt,
            None if service.realm != self.client.realm => match self
                .renew_cached_tgt_session_for_realm(&service.realm, clock())
                .await?
            {
                Some(tgt) => tgt,
                None => self.ensure_tgt().await?,
            },
            None => self.ensure_tgt().await?,
        };
        let result = self
            .transport
            .get_service_ticket_with_referral_trace(
                &self.config,
                self.protocol,
                &tgt,
                service,
                self.tgs_req_options()?,
            )
            .await?;
        for referral_tgt in result.referral_tgts {
            self.cache_tgt_session(referral_tgt)?;
        }
        let ticket = result.ticket;
        self.cache_service_ticket(ticket.clone())?;
        Ok(ticket)
    }
    /// Acquire an `S4U2Self` ticket for an impersonated user using the current service TGT.
    /// # Errors
    ///
    /// Returns [`Error::Random`] when the nonce cannot be generated, and the errors
    /// of [`Self::s4u2self_with_options`].
    /// # Cancel safety
    ///
    /// cancel-safe: the issued ticket is returned, not cached; a TGT acquired on the
    /// way is cached only after its exchange completes, so dropping the future leaves
    /// the client consistent and the call can be repeated.
    #[inline]
    pub async fn s4u2self(&mut self, user: Principal) -> Result<TgsRepSession, Error> {
        let options = self.tgs_req_options()?;
        self.s4u2self_with_options(user, options).await
    }
    /// Acquire an `S4U2Self` ticket using explicit TGS request options.
    /// # Errors
    ///
    /// Returns the errors of acquiring the service TGT, and any TGS exchange,
    /// transport or validation error.
    /// # Cancel safety
    ///
    /// cancel-safe: the issued ticket is returned, not cached; a TGT acquired on the
    /// way is cached only after its exchange completes, so dropping the future leaves
    /// the client consistent and the call can be repeated.
    #[inline]
    pub async fn s4u2self_with_options(
        &mut self,
        user: Principal,
        mut options: TgsReq,
    ) -> Result<TgsRepSession, Error> {
        if options.delegation_keytab.is_none()
            && let Some(TokioClientCredentials::Keytab(keytab)) = &self.credentials
        {
            options.delegation_keytab = Some(keytab.clone());
        }
        let service_tgt = self.ensure_tgt().await?;
        self.transport
            .s4u2self_with_config(&self.config, self.protocol, &service_tgt, user, options)
            .await
    }
    /// Acquire an `S4U2Proxy` ticket for a target service using a user evidence ticket.
    /// # Errors
    ///
    /// Returns [`Error::Random`] when the nonce cannot be generated, and the errors
    /// of [`Self::s4u2proxy_with_options`].
    /// # Cancel safety
    ///
    /// cancel-safe: the issued ticket is returned, not cached; a TGT acquired on the
    /// way is cached only after its exchange completes, so dropping the future leaves
    /// the client consistent and the call can be repeated.
    #[inline]
    pub async fn s4u2proxy(
        &mut self,
        evidence_ticket: &TgsRepSession,
        target_service: Principal,
    ) -> Result<TgsRepSession, Error> {
        let options = self.tgs_req_options()?;
        self.s4u2proxy_with_options(evidence_ticket, target_service, options)
            .await
    }
    /// Acquire an `S4U2Proxy` ticket using explicit TGS request options.
    /// # Errors
    ///
    /// Returns the errors of acquiring the service TGT, and any TGS exchange,
    /// transport or validation error.
    /// # Cancel safety
    ///
    /// cancel-safe: the issued ticket is returned, not cached; a TGT acquired on the
    /// way is cached only after its exchange completes, so dropping the future leaves
    /// the client consistent and the call can be repeated.
    #[inline]
    pub async fn s4u2proxy_with_options(
        &mut self,
        evidence_ticket: &TgsRepSession,
        target_service: Principal,
        mut options: TgsReq,
    ) -> Result<TgsRepSession, Error> {
        if options.delegation_keytab.is_none()
            && let Some(TokioClientCredentials::Keytab(keytab)) = &self.credentials
        {
            options.delegation_keytab = Some(keytab.clone());
        }
        let service_tgt = self.ensure_tgt().await?;
        self.transport
            .s4u2proxy_with_config(
                &self.config,
                self.protocol,
                &service_tgt,
                evidence_ticket,
                target_service,
                options,
            )
            .await
    }
    /// Build a SPNEGO HTTP `Authorization` header for a service.
    /// # Errors
    ///
    /// Returns the errors of [`Self::spnego_context`].
    /// # Cancel safety
    ///
    /// cancel-safe: a service ticket is cached only after its exchange completes,
    /// so dropping the future leaves the client consistent and the call can be
    /// repeated.
    #[cfg(feature = "spnego")]
    #[inline]
    pub async fn spnego_header(&mut self, service: Principal) -> Result<String, Error> {
        Ok(self.spnego_context(service).await?.header.to_string())
    }
    /// Build a SPNEGO HTTP `Authorization` header with explicit initiator options.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: a service ticket is cached only after its exchange completes,
    /// so dropping the future leaves the client's caches consistent and the call
    /// can be repeated.
    /// # Errors
    ///
    /// Returns the errors of [`Self::spnego_context_with_options`].
    #[cfg(feature = "spnego")]
    #[inline]
    pub async fn spnego_header_with_options(
        &mut self,
        service: Principal,
        options: spnego::InitiatorContextOptions,
    ) -> Result<String, Error> {
        Ok(self
            .spnego_context_with_options(service, options)
            .await?
            .header
            .to_string())
    }
    /// Build a SPNEGO initiator context for a service.
    ///
    /// The returned context includes the HTTP `Authorization` header and the
    /// key material needed to verify an AP-REP response token.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: a service ticket is cached only after its exchange completes,
    /// so dropping the future leaves the client's caches consistent and the call
    /// can be repeated.
    /// # Errors
    ///
    /// Returns the errors of [`Self::spnego_context_with_options`].
    #[cfg(feature = "spnego")]
    #[inline]
    pub async fn spnego_context(
        &mut self,
        service: Principal,
    ) -> Result<spnego::InitiatorContext, Error> {
        self.spnego_context_with_options(service, spnego::InitiatorContextOptions::new())
            .await
    }
    /// Build a SPNEGO initiator context with explicit initiator options.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: a service ticket is cached only after its exchange completes,
    /// so dropping the future leaves the client's caches consistent and the call
    /// can be repeated.
    /// # Errors
    ///
    /// Returns the errors of [`Self::get_service_ticket`], and [`Error::Spnego`]
    /// when the initiator token cannot be built.
    #[cfg(feature = "spnego")]
    #[inline]
    pub async fn spnego_context_with_options(
        &mut self,
        service: Principal,
        mut options: spnego::InitiatorContextOptions,
    ) -> Result<spnego::InitiatorContext, Error> {
        options.crypto_policy = Some(crypto_policy::configured(&self.config.libdefaults)?);
        let ticket = self.get_service_ticket(service).await?;
        Ok(spnego::init_sec_context(&ticket, options)?)
    }
    /// Return a TGT that is valid and outside the refresh window, renewing or
    /// logging in again as needed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoClientCredentials`] when a new login is needed but no
    /// password or keytab is configured, and any renewal or login error.
    // cancel-safe: the TGT and caches are replaced only after an exchange
    // completes, so dropping the future leaves the previous session in place.
    async fn ensure_tgt(&mut self) -> Result<AsRepSession, Error> {
        crypto_policy::ready(self)?;
        if let Some(tgt) = self.tgt.clone() {
            crypto_policy::session(
                &crypto_policy::configured(&self.config.libdefaults)?,
                &tgt,
                Use::SessionKey,
            )?;
            let now = SystemTime::now();
            if session_valid_at(&tgt, now) && !session_refresh_due_at(&tgt, now) {
                return Ok(tgt);
            }
            if session_renewable_at(&tgt, now) {
                let has_credentials = self.credentials.is_some();
                match self.renew_tgt().await.cloned() {
                    Ok(session) => return Ok(session),
                    Err(error) if !has_credentials => return Err(error),
                    Err(_) => {}
                }
            }
            if session_valid_at(&tgt, now) && self.credentials.is_none() {
                return Ok(tgt);
            }
        }
        if self.credentials.is_none() {
            return Err(Error::NoClientCredentials);
        }
        Ok(self.login().await?.clone())
    }
    /// AS-REQ options from the configuration, with a fresh nonce.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Random`] when the nonce cannot be generated.
    fn as_req_options(&self) -> Result<AsReq, Error> {
        crypto_policy::ready(self)?;
        Ok(
            AsReq::from_libdefaults(SystemTime::now(), random_nonce()?, &self.config.libdefaults)
                .with_assume_preauthentication(self.assume_preauthentication)
                .with_fast_negotiation(self.fast_negotiation),
        )
    }
    /// TGS-REQ options from the configuration, with a fresh nonce.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Random`] when the nonce cannot be generated.
    fn tgs_req_options(&self) -> Result<TgsReq, Error> {
        crypto_policy::ready(self)?;
        Ok(TgsReq::from_libdefaults(
            SystemTime::now(),
            random_nonce()?,
            &self.config.libdefaults,
        ))
    }
    /// Fill in an empty service realm from the domain-realm mapping, falling back
    /// to the client realm.
    fn resolve_service_principal(&self, mut service: Principal) -> Principal {
        if service.realm.is_empty() {
            service.realm =
                service_realm(&self.config, &service).unwrap_or_else(|| self.client.realm.clone());
        }
        service
    }

    /// All cached TGT and service-ticket sessions as ccache credentials.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TimeOverflow`] when a session time does not fit the ccache
    /// time format.
    fn ccache_credentials(&self) -> Result<Vec<ccache::Credential>, Error> {
        // A capacity hint only: saturating at `usize::MAX` is harmless.
        let mut credentials = Vec::with_capacity(
            self.tgt_sessions
                .len()
                .max(usize::from(self.tgt.is_some()))
                .saturating_add(self.service_tickets.len()),
        );
        if self.tgt_sessions.is_empty() {
            if let Some(tgt) = &self.tgt {
                credentials.push(tgt.to_ccache_credential()?);
            }
        } else {
            for tgt in self.tgt_sessions.values() {
                credentials.push(tgt.to_ccache_credential()?);
            }
        }
        for ticket in self.service_tickets.values() {
            credentials.push(ticket.to_ccache_credential()?);
        }
        Ok(credentials)
    }

    /// The cached TGT session for `realm`, if it is currently valid.
    fn cached_tgt_session_for_realm(&self, realm: &str, now: SystemTime) -> Option<AsRepSession> {
        let tgt = self.tgt_sessions.get(realm)?;
        session_valid_at(tgt, now).then(|| tgt.clone())
    }

    /// Renew the cached TGT session for `realm` when it is renewable.
    ///
    /// Returns `Ok(None)` when no renewable session is cached or the renewal fails.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Random`] when the request nonce cannot be generated and
    /// [`Error::InvalidTgtSession`] when the renewed ticket is not a TGT.
    // cancel-safe: the renewed session is cached only after the renewal exchange
    // completes; dropping the future leaves the previous session in place.
    async fn renew_cached_tgt_session_for_realm(
        &mut self,
        realm: &str,
        now: SystemTime,
    ) -> Result<Option<AsRepSession>, Error> {
        let Some(tgt) = self.tgt_sessions.get(realm).cloned() else {
            return Ok(None);
        };
        if !session_renewable_at(&tgt, now) {
            return Ok(None);
        }

        let Ok(renewed) = self
            .transport
            .renew_tgt_with_config(&self.config, self.protocol, &tgt, self.tgs_req_options()?)
            .await
        else {
            return Ok(None);
        };
        let renewed_realm = tgt_realm(&renewed).ok_or_else(|| Error::InvalidTgtSession {
            service: renewed.service.name(),
        })?;
        if renewed_realm == self.client.realm {
            self.tgt = Some(renewed.clone());
        }
        drop(self.tgt_sessions.insert(renewed_realm, renewed.clone()));
        Ok(Some(renewed))
    }

    /// KDC endpoints discovered for the client realm, recording a discovery
    /// failure in `errors`.
    // cancel-safe: KDC discovery only reads configuration and DNS; dropping the
    // future changes no client state.
    async fn diagnostic_kdc_endpoints(
        &self,
        protocol: KdcProtocol,
        errors: &mut Vec<String>,
    ) -> Vec<String> {
        match self
            .transport
            .discover_kdcs(&self.config, &self.client.realm, protocol)
            .await
        {
            Ok(endpoints) => endpoints.iter().map(KdcEndpoint::authority).collect(),
            Err(error) => {
                errors.push(format!(
                    "error when resolving KDCs for {} communication: {error}",
                    protocol_label(protocol)
                ));
                Vec::new()
            }
        }
    }

    /// Change this client's password using generated timestamp and sequence metadata.
    ///
    /// # Errors
    ///
    /// Returns an error when reading the clock or the random source fails, when
    /// the `kadmin/changepw` service ticket cannot be obtained, when the request
    /// cannot be built or exchanged with a kpasswd server, when the reply's
    /// AP-REP fails verification (including [`Error::MissingKpasswdApRep`] for a
    /// success result without one), when the result cannot be decrypted, or
    /// when the server reports a non-success result code.
    ///
    /// # Cancel safety
    ///
    /// NOT cancel-safe: this mutates credentials on the KDC. Dropping the future
    /// after the kpasswd request is sent does not roll the server back, so the
    /// password may or may not have changed; treat the outcome as unknown and
    /// verify it (for example with a fresh login) before retrying.
    #[inline]
    pub async fn change_password(
        &mut self,
        new_password: Password,
        sender_address: rasn_kerberos::HostAddress,
    ) -> Result<kadmin::ChangePasswordResult, Error> {
        let (timestamp, cusec) = current_preauth_time()?;
        let sequence_number = random_nonce()?;
        self.change_password_for_with_options(
            self.client.clone(),
            new_password,
            RequestOptions::new(timestamp, cusec, sequence_number, sender_address),
        )
        .await
    }

    /// Change the given target principal's password using generated timestamp and
    /// sequence metadata.
    ///
    /// # Errors
    ///
    /// Returns an error when reading the clock or the random source fails, when
    /// the `kadmin/changepw` service ticket cannot be obtained, when the request
    /// cannot be built or exchanged with a kpasswd server, when the reply's
    /// AP-REP fails verification (including [`Error::MissingKpasswdApRep`] for a
    /// success result without one), when the result cannot be decrypted, or
    /// when the server reports a non-success result code.
    ///
    /// # Cancel safety
    ///
    /// NOT cancel-safe: this mutates credentials on the KDC. Dropping the future
    /// after the kpasswd request is sent does not roll the server back, so the
    /// password may or may not have changed; treat the outcome as unknown and
    /// verify it (for example with a fresh login) before retrying.
    #[inline]
    pub async fn change_password_for(
        &mut self,
        target: Principal,
        new_password: Password,
        sender_address: rasn_kerberos::HostAddress,
    ) -> Result<kadmin::ChangePasswordResult, Error> {
        let (timestamp, cusec) = current_preauth_time()?;
        let sequence_number = random_nonce()?;
        self.change_password_for_with_options(
            target,
            new_password,
            RequestOptions::new(timestamp, cusec, sequence_number, sender_address),
        )
        .await
    }

    /// Change this client's password using explicit kpasswd request metadata.
    ///
    /// # Errors
    ///
    /// Returns an error when the `kadmin/changepw` service ticket cannot be
    /// obtained, when the request cannot be built or exchanged with a kpasswd
    /// server, when the reply's AP-REP fails verification (including
    /// [`Error::MissingKpasswdApRep`] for a success result without one), when
    /// the result cannot be decrypted, or when the server reports a
    /// non-success result code.
    ///
    /// # Cancel safety
    ///
    /// NOT cancel-safe: this mutates credentials on the KDC. Dropping the future
    /// after the kpasswd request is sent does not roll the server back, so the
    /// password may or may not have changed; treat the outcome as unknown and
    /// verify it (for example with a fresh login) before retrying.
    #[inline]
    pub async fn change_password_with_options(
        &mut self,
        new_password: Password,
        options: RequestOptions,
    ) -> Result<kadmin::ChangePasswordResult, Error> {
        self.change_password_for_with_options(self.client.clone(), new_password, options)
            .await
    }

    /// Change the given target principal's password using explicit request metadata.
    ///
    /// Takes ownership of the original password allocation and erases it on
    /// completion, failure, or cancellation. A confirmed change to this client's
    /// own password retains a separate zeroizing credential for future logins.
    ///
    /// # Errors
    ///
    /// Returns an error when the `kadmin/changepw` service ticket cannot be
    /// obtained, when the request cannot be built or exchanged with a kpasswd
    /// server, when the reply's AP-REP fails verification (including
    /// [`Error::MissingKpasswdApRep`] for a success result without one), when
    /// the result cannot be decrypted, or when the server reports a
    /// non-success result code.
    ///
    /// # Cancel safety
    ///
    /// NOT cancel-safe: this mutates credentials on the KDC. Dropping the future
    /// after the kpasswd request is sent does not roll the server back, so the
    /// password may or may not have changed; treat the outcome as unknown and
    /// verify it (for example with a fresh login) before retrying.
    #[inline]
    pub async fn change_password_for_with_options(
        &mut self,
        target: Principal,
        new_password: Password,
        mut options: RequestOptions,
    ) -> Result<kadmin::ChangePasswordResult, Error> {
        let client = self.client.clone();
        let service = Principal::new(
            target.realm.clone(),
            KRB_NT_PRINCIPAL,
            ["kadmin".to_owned(), "changepw".to_owned()],
        );
        let update_password_credential = password_rotation::should_rotate(self, &target);
        let ticket = match self.credentials.clone() {
            Some(TokioClientCredentials::Password(password)) => {
                self.transport
                    .login_as_service_with_password_config(
                        &self.config,
                        self.protocol,
                        client,
                        service,
                        &password,
                        self.as_req_options()?,
                    )
                    .await?
            }
            Some(TokioClientCredentials::Keytab(keytab)) => {
                self.transport
                    .login_as_service_with_keytab_config(
                        &self.config,
                        self.protocol,
                        client,
                        service,
                        &keytab,
                        self.as_req_options()?,
                    )
                    .await?
            }
            None => self.get_service_ticket(service).await?,
        };
        let change_data = kadmin::ChangePasswdData::for_target(
            Password::from_vec(new_password.as_bytes().to_vec()),
            target.name_type,
            target.components.iter().map(String::as_str),
            &target.realm,
        )?;
        options.crypto_policy = Some(crypto_policy::configured(&self.config.libdefaults)?);
        let request = build_kpasswd_request(&ticket, &change_data, &options)?;
        let reply = self
            .transport
            .exchange_kpasswd_request_with_config(
                &self.config,
                self.protocol,
                &target.realm,
                &request.request,
            )
            .await?;
        // Delivery has occurred: unsigned refusals are unauthenticated diagnostics,
        // not proof of rollback. Wrap validator failures once, before ensure_success.
        let result = validated_result(&reply, &request, &options, &request.crypto_policy)
            .map_err(|source| Error::KpasswdOutcomeUnknown(Box::new(source)))?;
        result.ensure_success()?;

        if update_password_credential {
            self.credentials = Some(TokioClientCredentials::Password(Zeroizing::new(
                new_password.as_bytes().to_vec(),
            )));
        }
        drop(new_password);
        Ok(result)
    }
}

/// JSON shape of one service ticket in [`Tokio::service_ticket_cache_json`].
#[cfg(all(feature = "tokio", feature = "serde"))]
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "PascalCase")]
struct ServiceTicketJsonEntry {
    /// Service principal name.
    #[serde(rename = "SPN")]
    spn: String,
    /// Initial authentication time (RFC 3339).
    auth_time: String,
    /// Ticket start time (RFC 3339).
    start_time: String,
    /// Ticket end time (RFC 3339).
    end_time: String,
    /// Renewable-until time, or the end time when not renewable (RFC 3339).
    renew_till: String,
}

/// JSON entry for one service ticket.
#[cfg(all(feature = "tokio", feature = "serde"))]
fn service_ticket_json_entry(ticket: &TgsRepSession) -> ServiceTicketJsonEntry {
    ServiceTicketJsonEntry {
        spn: ticket.service.name(),
        auth_time: json_time(ticket.auth_time),
        start_time: json_time(ticket.start_time),
        end_time: json_time(ticket.end_time),
        renew_till: json_time(ticket.renew_till.unwrap_or(ticket.end_time)),
    }
}

/// RFC 3339 UTC timestamp with whole seconds.
#[cfg(all(feature = "tokio", feature = "serde"))]
fn json_time(time: SystemTime) -> String {
    let timestamp: chrono::DateTime<chrono::Utc> = time.into();
    timestamp.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Diagnostic label for the configured long-term credential.
#[cfg(feature = "tokio")]
const fn credential_source(credentials: Option<&TokioClientCredentials>) -> &'static str {
    match credentials {
        Some(TokioClientCredentials::Password(_)) => "password",
        Some(TokioClientCredentials::Keytab(_)) => "keytab",
        None => "none",
    }
}

/// Sorted, de-duplicated enctypes for the client identity, ignoring advisory name type.
#[cfg(feature = "tokio")]
fn keytab_client_enctypes(keytab: &Keytab, client: &Principal) -> Vec<i32> {
    let mut enctypes = keytab
        .entries()
        .iter()
        .filter(|entry| {
            entry.principal.realm == client.realm && entry.principal.components == client.components
        })
        .map(|entry| entry.key.etype)
        .collect::<Vec<_>>();
    enctypes.sort_unstable();
    enctypes.dedup();
    enctypes
}

/// Record a diagnostic for each `configured` enctype missing from the keytab.
#[cfg(feature = "tokio")]
fn record_keytab_enctype_diagnostics(
    errors: &mut Vec<String>,
    keytab_enctypes: &[i32],
    configured: &[i32],
    field: &str,
) {
    for etype in configured {
        if !keytab_enctypes.contains(etype) {
            errors.push(format!(
                "{field} specifies {etype} but this enctype is not available in the client's keytab"
            ));
        }
    }
}

/// Diagnostic label for a KDC transport protocol.
#[cfg(feature = "tokio")]
const fn protocol_label(protocol: KdcProtocol) -> &'static str {
    match protocol {
        KdcProtocol::Udp => "UDP",
        KdcProtocol::Tcp => "TCP",
        KdcProtocol::Auto => "Auto",
    }
}

/// Build a TGT AS-REQ for the supplied client principal.
/// # Errors
///
/// Returns the errors of [`build_as_req`].
#[inline]
pub fn build_tgt_as_req(client: Principal, options: AsReq) -> Result<BuiltAsReq, Error> {
    let service = Principal::tgt_service(client.realm.clone());
    build_as_req(client, service, options)
}

/// Build an AS-REQ for an explicit service principal.
/// # Errors
///
/// Returns [`Error::EmptyEtypes`] when no enctype is requested,
/// [`Error::TimeOverflow`] when a requested time is out of range,
/// [`Error::InvalidKerberosString`] for an invalid principal or realm string, and
/// [`Error::Encode`] when the request cannot be encoded.
#[inline]
pub fn build_as_req(
    client: Principal,
    service: Principal,
    options: AsReq,
) -> Result<BuiltAsReq, Error> {
    crypto_policy::padata(&options.padata)?;
    let crypto_policy = crypto_policy::request(&options.crypto_policy, &options.etypes)?;
    if options.etypes.is_empty() {
        return Err(Error::EmptyEtypes);
    }

    let till = options
        .now
        .checked_add(options.ticket_lifetime)
        .ok_or(Error::TimeOverflow)?;
    let renew_till = options
        .renew_lifetime
        .map(|duration| options.now.checked_add(duration).ok_or(Error::TimeOverflow))
        .transpose()?;
    let padata = (!options.padata.is_empty()).then_some(options.padata);
    let kdc_option_bits = request_kdc_option_bits(
        options.kdc_option_bits & !KDC_OPTION_CANONICALIZE,
        options.renew_lifetime,
    );
    let req_body = rasn_kerberos::KdcReqBody {
        kdc_options: kdc_options_from_bits(kdc_option_bits),
        cname: Some(principal_to_rasn(&client)?),
        realm: kerberos_string(&client.realm)?,
        sname: Some(principal_to_rasn(&service)?),
        from: None,
        till: kerberos_time_from_system_time(till)?,
        rtime: renew_till.map(kerberos_time_from_system_time).transpose()?,
        nonce: options.nonce,
        etype: options.etypes,
        addresses: None,
        enc_authorization_data: None,
        additional_tickets: None,
    };
    let message = kdc_req::build_as_req(req_body, padata);
    let der = Zeroizing::new(kdc_req::encode_as_req(&message).map_err(kdc_req_error)?);

    Ok(BuiltAsReq {
        crypto_policy,
        reply_clock: (options.now, options.clock_skew),
        message,
        der,
        client,
        service,
        nonce: options.nonce,
    })
}

/// Build encrypted timestamp preauthentication data with an explicit confounder.
/// # Errors
///
/// Returns [`Error::UnsupportedEtype`] for an unknown key enctype,
/// [`Error::TimeOverflow`] for an out-of-range timestamp, [`Error::Crypto`] when
/// encryption fails, and [`Error::Encode`] when encoding fails.
#[inline]
pub fn pa_enc_timestamp_with_confounder(
    key: &EncryptionKey,
    timestamp: SystemTime,
    cusec: u32,
    confounder: &[u8],
    kvno: Option<u32>,
) -> Result<rasn_kerberos::PaData, Error> {
    let enc_ts = rasn_kerberos::PaEncTsEnc {
        patimestamp: time::authenticator(timestamp, cusec, "PA-ENC-TIMESTAMP")?,
        pausec: Some(Integer::from(cusec)),
    };
    let etype = selection::enctype(key.etype)?.ok_or(Error::UnsupportedEtype(key.etype))?;
    let plaintext = encode("PA-ENC-TS-ENC", &enc_ts)?;
    let cipher = etype.encrypt_message_with_confounder(
        &key.value,
        &plaintext,
        AS_REQ_PA_ENC_TIMESTAMP_USAGE,
        confounder,
    )?;
    let encrypted = rasn_kerberos::EncryptedData {
        etype: key.etype,
        kvno,
        cipher: cipher.into(),
    };
    Ok(rasn_kerberos::PaData {
        r#type: PA_ENC_TIMESTAMP,
        value: encode("PA-ENC-TIMESTAMP", &encrypted)?.into(),
    })
}

/// Build the MS-SFU byte array signed by PA-FOR-USER.
#[inline]
pub fn s4u_byte_array(user: &Principal, auth_package: &str) -> Vec<u8> {
    // A capacity hint only: saturating at `usize::MAX` is harmless.
    let mut out = Vec::with_capacity(
        user.components
            .iter()
            .map(String::len)
            .fold(4_usize, usize::saturating_add)
            .saturating_add(user.realm.len())
            .saturating_add(auth_package.len()),
    );
    out.extend_from_slice(&user.name_type.to_le_bytes());
    for component in &user.components {
        out.extend_from_slice(component.as_bytes());
    }
    out.extend_from_slice(user.realm.as_bytes());
    out.extend_from_slice(auth_package.as_bytes());
    out
}

/// Build PA-FOR-USER padata using the default `Kerberos` auth package.
/// # Errors
///
/// Returns the errors of [`pa_for_user_padata_with_auth_package`].
#[inline]
pub fn pa_for_user_padata(
    user: &Principal,
    tgt_session_key: &EncryptionKey,
) -> Result<rasn_kerberos::PaData, Error> {
    pa_for_user_padata_with_auth_package(user, tgt_session_key, "Kerberos")
}

/// Build PA-FOR-USER padata for `S4U2Self`.
/// # Errors
///
/// Returns [`Error::InvalidKerberosString`] for an invalid user name, realm or
/// auth package, and [`Error::Message`] when the padata cannot be encoded.
#[inline]
pub fn pa_for_user_padata_with_auth_package(
    user: &Principal,
    tgt_session_key: &EncryptionKey,
    auth_package: &str,
) -> Result<rasn_kerberos::PaData, Error> {
    let s4u_bytes = s4u_byte_array(user, auth_package);
    let checksum = kerb_checksum_hmac_md5(
        &tgt_session_key.value,
        &s4u_bytes,
        PA_FOR_USER_CHECKSUM_USAGE,
    );
    let value = messages::PaForUser {
        user_name: principal_to_rasn(user)?,
        user_realm: kerberos_string(&user.realm)?,
        cksum: rasn_kerberos::Checksum {
            r#type: Rc4HmacEtype::checksum_type_id(),
            checksum: checksum.into(),
        },
        auth_package: kerberos_string(auth_package)?,
    };

    Ok(rasn_kerberos::PaData {
        r#type: PA_FOR_USER,
        value: value.encode_der()?.into(),
    })
}

/// Build PA-PAC-OPTIONS padata from a raw PAC option bit mask.
/// # Errors
///
/// Returns [`Error::Message`] when the padata cannot be encoded.
#[inline]
pub fn pa_pac_options_padata(option_bits: u32) -> Result<rasn_kerberos::PaData, Error> {
    let value = messages::PaPacOptions::from_bits(option_bits);
    Ok(rasn_kerberos::PaData {
        r#type: PA_PAC_OPTIONS,
        value: value.encode_der()?.into(),
    })
}

/// Build encrypted timestamp preauthentication data with random confounder bytes.
/// # Errors
///
/// Returns [`Error::UnsupportedEtype`] for an unknown key enctype,
/// [`Error::Random`] when the confounder cannot be generated, and the errors of
/// [`pa_enc_timestamp_with_confounder`].
#[inline]
pub fn pa_enc_timestamp(
    key: &EncryptionKey,
    timestamp: SystemTime,
    cusec: u32,
    kvno: Option<u32>,
) -> Result<rasn_kerberos::PaData, Error> {
    let etype = selection::enctype(key.etype)?.ok_or(Error::UnsupportedEtype(key.etype))?;
    let mut confounder = vec![0; etype.confounder_len()];
    getrandom::fill(&mut confounder)?;
    pa_enc_timestamp_with_confounder(key, timestamp, cusec, &confounder, kvno)
}

/// Build an AS-REQ for an explicit service principal with PA-ENC-TIMESTAMP preauthentication.
/// # Errors
///
/// Returns [`Error::TimeOverflow`] when the clock is before the Unix epoch, and
/// the errors of [`pa_enc_timestamp`] and [`build_as_req`].
#[inline]
pub fn build_preauthenticated_as_req(
    client: Principal,
    service: Principal,
    mut options: AsReq,
    key: &EncryptionKey,
    kvno: Option<u32>,
) -> Result<BuiltAsReq, Error> {
    crypto_policy::padata(&options.padata)?;
    let policy = crypto_policy::request(&options.crypto_policy, &options.etypes)?;
    policy.check_use(key.etype, Use::ReplyKey)?;
    let (timestamp, cusec) = current_preauth_time()?;
    options
        .padata
        .retain(|padata| padata.r#type != PA_ENC_TIMESTAMP);
    options
        .padata
        .push(pa_enc_timestamp(key, timestamp, cusec, kvno)?);
    build_as_req(client, service, options)
}

/// Build a TGT AS-REQ with PA-ENC-TIMESTAMP preauthentication.
/// # Errors
///
/// Returns the errors of [`build_preauthenticated_as_req`].
#[inline]
pub fn build_preauthenticated_tgt_as_req(
    client: Principal,
    options: AsReq,
    key: &EncryptionKey,
    kvno: Option<u32>,
) -> Result<BuiltAsReq, Error> {
    let service = Principal::tgt_service(client.realm.clone());
    build_preauthenticated_as_req(client, service, options, key, kvno)
}

/// Build a TGS-REQ for a service ticket using the supplied TGT session.
/// # Errors
///
/// Returns the errors of [`build_tgs_req_for_realm`].
#[inline]
pub fn build_tgs_req(
    tgt: &AsRepSession,
    service: Principal,
    options: TgsReq,
) -> Result<BuiltTgsReq, Error> {
    build_tgs_req_for_realm(tgt, service.realm.clone(), service, options)
}

/// Build a TGS-REQ for a service ticket while contacting an explicit KDC realm.
/// # Errors
///
/// Returns [`Error::UnsupportedEtype`] for an unknown session-key enctype,
/// [`Error::Random`] when the confounder cannot be generated, and the errors of
/// [`build_tgs_req_for_realm_with_confounder`].
#[inline]
pub fn build_tgs_req_for_realm<P>(
    tgt: &AsRepSession,
    kdc_realm: P,
    service: Principal,
    options: TgsReq,
) -> Result<BuiltTgsReq, Error>
where
    P: Into<String>,
{
    crypto_policy::padata(&options.padata)?;
    let policy = crypto_policy::request(&options.crypto_policy, &options.etypes)?;
    crypto_policy::session(&policy, tgt, Use::SessionKey)?;
    let (timestamp, cusec) = current_preauth_time()?;
    let etype = KerberosEtype::from_etype_id(tgt.session_key.etype)
        .ok_or(Error::UnsupportedEtype(tgt.session_key.etype))?;
    let mut confounder = vec![0; etype.confounder_len()];
    getrandom::fill(&mut confounder)?;
    build_tgs_req_for_realm_with_confounder(
        tgt,
        kdc_realm,
        service,
        options,
        timestamp,
        cusec,
        &confounder,
    )
}

/// Build a TGS-REQ with an explicit authenticator timestamp and confounder.
/// # Errors
///
/// Returns the errors of [`build_tgs_req_for_realm_with_confounder`].
#[inline]
pub fn build_tgs_req_with_confounder(
    tgt: &AsRepSession,
    service: Principal,
    options: TgsReq,
    timestamp: SystemTime,
    cusec: u32,
    confounder: &[u8],
) -> Result<BuiltTgsReq, Error> {
    build_tgs_req_for_realm_with_confounder(
        tgt,
        service.realm.clone(),
        service,
        options,
        timestamp,
        cusec,
        confounder,
    )
}

/// Build an `S4U2Self` TGS-REQ using the supplied service TGT.
///
/// The requested service is the TGT client principal, and the impersonated user
/// is carried in PA-FOR-USER.
/// # Errors
///
/// Returns [`Error::UnsupportedEtype`] for an unknown session-key enctype,
/// [`Error::Random`] when the confounder cannot be generated, and the errors of
/// [`build_s4u2self_req_with_confounder`].
#[inline]
pub fn build_s4u2self_req(
    service_tgt: &AsRepSession,
    user: Principal,
    options: TgsReq,
) -> Result<BuiltTgsReq, Error> {
    crypto_policy::padata(&options.padata)?;
    let policy = crypto_policy::request(&options.crypto_policy, &options.etypes)?;
    crypto_policy::session(&policy, service_tgt, Use::SessionKey)?;
    let (timestamp, cusec) = current_preauth_time()?;
    let etype = KerberosEtype::from_etype_id(service_tgt.session_key.etype)
        .ok_or(Error::UnsupportedEtype(service_tgt.session_key.etype))?;
    let mut confounder = vec![0; etype.confounder_len()];
    getrandom::fill(&mut confounder)?;
    build_s4u2self_req_with_confounder(service_tgt, user, options, timestamp, cusec, &confounder)
}

/// Build a deterministic `S4U2Self` TGS-REQ with an explicit authenticator timestamp and confounder.
/// # Errors
///
/// Returns the errors of [`pa_for_user_padata`] and
/// [`build_tgs_req_for_realm_with_confounder`].
#[inline]
pub fn build_s4u2self_req_with_confounder(
    service_tgt: &AsRepSession,
    user: Principal,
    mut options: TgsReq,
    timestamp: SystemTime,
    cusec: u32,
    confounder: &[u8],
) -> Result<BuiltTgsReq, Error> {
    crypto_policy::padata(&options.padata)?;
    let policy = crypto_policy::request(&options.crypto_policy, &options.etypes)?;
    crypto_policy::session(&policy, service_tgt, Use::SessionKey)?;
    options.padata.retain(|padata| padata.r#type != PA_FOR_USER);
    options
        .padata
        .push(pa_for_user_padata(&user, &service_tgt.session_key)?);
    let service = service_tgt.client.clone();
    let mut request = build_tgs_req_for_realm_with_confounder(
        service_tgt,
        service.realm.clone(),
        service,
        options,
        timestamp,
        cusec,
        confounder,
    )?;
    request.client = user;
    Ok(request)
}

/// Build an `S4U2Proxy` TGS-REQ using a service TGT and user evidence ticket.
/// # Errors
///
/// Returns [`Error::UnsupportedEtype`] for an unknown session-key enctype,
/// [`Error::Random`] when the confounder cannot be generated, and the errors of
/// [`build_s4u2proxy_req_with_confounder`].
#[inline]
pub fn build_s4u2proxy_req(
    service_tgt: &AsRepSession,
    evidence_ticket: &TgsRepSession,
    target_service: Principal,
    options: TgsReq,
) -> Result<BuiltTgsReq, Error> {
    crypto_policy::padata(&options.padata)?;
    let policy = crypto_policy::request(&options.crypto_policy, &options.etypes)?;
    crypto_policy::session(&policy, service_tgt, Use::SessionKey)?;
    crypto_policy::session(&policy, evidence_ticket, Use::TicketKey)?;
    let (timestamp, cusec) = current_preauth_time()?;
    let etype = KerberosEtype::from_etype_id(service_tgt.session_key.etype)
        .ok_or(Error::UnsupportedEtype(service_tgt.session_key.etype))?;
    let mut confounder = vec![0; etype.confounder_len()];
    getrandom::fill(&mut confounder)?;
    build_s4u2proxy_req_with_confounder(
        service_tgt,
        evidence_ticket,
        target_service,
        options,
        timestamp,
        cusec,
        &confounder,
    )
}

/// Build a deterministic `S4U2Proxy` TGS-REQ with an explicit authenticator timestamp and confounder.
/// # Errors
///
/// Returns [`Error::ServicePrincipalMismatch`] when the evidence ticket was not
/// issued to the service TGT's client, [`Error::Decode`] when the evidence
/// ticket does not decode, and the errors of
/// [`build_tgs_req_for_realm_with_confounder`].
#[inline]
pub fn build_s4u2proxy_req_with_confounder(
    service_tgt: &AsRepSession,
    evidence_ticket: &TgsRepSession,
    target_service: Principal,
    mut options: TgsReq,
    timestamp: SystemTime,
    cusec: u32,
    confounder: &[u8],
) -> Result<BuiltTgsReq, Error> {
    crypto_policy::padata(&options.padata)?;
    let policy = crypto_policy::request(&options.crypto_policy, &options.etypes)?;
    crypto_policy::session(&policy, service_tgt, Use::SessionKey)?;
    crypto_policy::session(&policy, evidence_ticket, Use::TicketKey)?;
    if !principal_matches(&evidence_ticket.service, &service_tgt.client) {
        return Err(Error::ServicePrincipalMismatch {
            expected: service_tgt.client.name(),
            actual: evidence_ticket.service.name(),
        });
    }
    options.kdc_option_bits |= KDC_OPTION_CNAME_IN_ADDL_TKT;
    options
        .additional_tickets
        .push(ticket::decode(&evidence_ticket.ticket).map_err(ticket_error)?);
    let mut request = build_tgs_req_for_realm_with_confounder(
        service_tgt,
        target_service.realm.clone(),
        target_service,
        options,
        timestamp,
        cusec,
        confounder,
    )?;
    request.client = evidence_ticket.client.clone();
    Ok(request)
}

/// Build a TGS-REQ for an explicit KDC realm, timestamp, and confounder.
///
/// The authenticator carries **no** subkey: this is the unarmored shape every
/// existing caller gets. A request that will be FAST-armored uses
/// [`build_tgs_req_for_realm_with_subkey`] or
/// [`build_tgs_req_for_realm_with_confounder_and_subkey`], whose authenticator
/// carries the subkey RFC 6113 section 5.4.2 derives the implicit armor key
/// from.
/// # Errors
///
/// Returns [`Error::EmptyEtypes`] when no enctype is requested,
/// [`Error::TimeOverflow`] for an out-of-range time,
/// [`Error::InvalidKerberosString`] for an invalid principal or realm string,
/// [`Error::Crypto`] when the authenticator cannot be encrypted, and
/// [`Error::Encode`] or [`Error::Decode`] when a message cannot be encoded or the
/// TGT does not decode.
#[inline]
pub fn build_tgs_req_for_realm_with_confounder<P>(
    tgt: &AsRepSession,
    kdc_realm: P,
    service: Principal,
    options: TgsReq,
    timestamp: SystemTime,
    cusec: u32,
    confounder: &[u8],
) -> Result<BuiltTgsReq, Error>
where
    P: Into<String>,
{
    build_tgs_req_for_realm_inner(
        tgt,
        kdc_realm,
        service,
        options,
        TgsAuthenticatorContext {
            timestamp,
            cusec,
            confounder,
            subkey: None,
        },
    )
    .map(|(request, _ap_req_der)| request)
}

/// Build a TGS-REQ that carries an authenticator subkey, with random confounder
/// and subkey: the input RFC 6113 section 5.4.2's implicit TGS armor needs.
///
/// The subkey is fresh for every call, in the TGT session key's enctype and
/// length, and it never leaves [`TgsFastRequestParts::authenticator_subkey`]
/// except into the request and the caller's armor key.
///
/// # Errors
///
/// Returns [`Error::UnsupportedEtype`] when the TGT session key's enctype has
/// no profile here, [`Error::Random`] when the OS random source fails, and the
/// ticket, encoding, time or crypto error of whichever build step fails.
#[inline]
pub fn build_tgs_req_for_realm_with_subkey<R>(
    tgt: &AsRepSession,
    kdc_realm: R,
    service: Principal,
    options: TgsReq,
) -> Result<TgsFastRequestParts, Error>
where
    R: Into<String>,
{
    crypto_policy::padata(&options.padata)?;
    let policy = crypto_policy::request(&options.crypto_policy, &options.etypes)?;
    crypto_policy::session(&policy, tgt, Use::SessionKey)?;
    let (timestamp, cusec) = current_preauth_time()?;
    let etype = KerberosEtype::from_etype_id(tgt.session_key.etype)
        .ok_or(Error::UnsupportedEtype(tgt.session_key.etype))?;
    let mut confounder = vec![0; etype.confounder_len()];
    getrandom::fill(&mut confounder)?;
    let subkey = random_subkey_for(&tgt.session_key)?;
    let (request, ap_req_der) = build_tgs_req_for_realm_inner(
        tgt,
        kdc_realm,
        service,
        options,
        TgsAuthenticatorContext {
            timestamp,
            cusec,
            confounder: &confounder,
            subkey: Some(&subkey),
        },
    )?;
    Ok(TgsFastRequestParts {
        request,
        ap_req_der,
        authenticator_subkey: subkey,
    })
}

/// Build a TGS-REQ that carries `subkey`, with an explicit timestamp and
/// confounder.
///
/// This helper only accepts a subkey shaped as
/// [`build_tgs_req_for_realm_with_subkey`] generates it, in the TGT session
/// key's enctype and length, and the bytes should be fresh random bytes. The
/// shape is this crate's constraint: RFC 6113 lets the two KRB-FX-CF2 inputs
/// differ in enctype. A subkey of another enctype is
/// [`Error::ApReqKeyEtypeMismatch`]; one of another length is [`Error::Crypto`].
///
/// # Errors
///
/// Returns the enctype or length mismatch errors above, and the ticket,
/// encoding, time or crypto error of whichever build step fails.
#[inline]
pub fn build_tgs_req_for_realm_with_confounder_and_subkey<R>(
    tgt: &AsRepSession,
    kdc_realm: R,
    service: Principal,
    parts: TgsRequestParts<'_>,
) -> Result<TgsFastRequestParts, Error>
where
    R: Into<String>,
{
    let TgsRequestParts {
        options,
        timestamp,
        cusec,
        confounder,
        subkey,
    } = parts;
    if subkey.etype != tgt.session_key.etype {
        return Err(Error::ApReqKeyEtypeMismatch {
            key_etype: subkey.etype,
            encrypted_data_etype: tgt.session_key.etype,
        });
    }
    if subkey.value.len() != tgt.session_key.value.len() {
        return Err(error::Crypto::InvalidKeyLength {
            expected: tgt.session_key.value.len(),
            actual: subkey.value.len(),
        }
        .into());
    }
    let (request, ap_req_der) = build_tgs_req_for_realm_inner(
        tgt,
        kdc_realm,
        service,
        options,
        TgsAuthenticatorContext {
            timestamp,
            cusec,
            confounder,
            subkey: Some(subkey),
        },
    )?;
    Ok(TgsFastRequestParts {
        request,
        ap_req_der,
        authenticator_subkey: subkey.clone(),
    })
}

/// Explicit request options and authenticator inputs for a subkey-bearing TGS request.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct TgsRequestParts<'request> {
    /// The ticket request options.
    pub options: TgsReq,
    /// The authenticator timestamp.
    pub timestamp: SystemTime,
    /// The authenticator microseconds.
    pub cusec: u32,
    /// The encryption confounder.
    pub confounder: &'request [u8],
    /// The authenticator subkey.
    pub subkey: &'request EncryptionKey,
}

impl<'request> TgsRequestParts<'request> {
    /// Creates explicit authenticator inputs with the request options' timestamp.
    #[must_use]
    #[inline]
    pub const fn new(
        options: TgsReq,
        confounder: &'request [u8],
        subkey: &'request EncryptionKey,
    ) -> Self {
        Self {
            timestamp: options.now,
            options,
            cusec: 0,
            confounder,
            subkey,
        }
    }

    /// Sets the explicit authenticator timestamp and microseconds.
    #[must_use]
    #[inline]
    pub const fn with_timestamp(mut self, timestamp: SystemTime, cusec: u32) -> Self {
        self.timestamp = timestamp;
        self.cusec = cusec;
        self
    }
}

/// A fresh key of `key`'s enctype and length, from the OS CSPRNG.
///
/// # Errors
///
/// Returns [`Error::Random`] when the OS random source fails.
pub(crate) fn random_subkey_for(key: &EncryptionKey) -> Result<EncryptionKey, Error> {
    let mut value = vec![0; key.value.len()];
    getrandom::fill(&mut value)?;
    Ok(EncryptionKey {
        etype: key.etype,
        value,
    })
}

/// The per-request authenticator inputs of [`build_tgs_req_for_realm_inner`].
#[derive(Clone, Copy)]
struct TgsAuthenticatorContext<'request> {
    /// Authenticator `ctime`.
    timestamp: SystemTime,
    /// Authenticator `cusec`, in microseconds.
    cusec: u32,
    /// Confounder for the encrypted authenticator.
    confounder: &'request [u8],
    /// Optional authenticator subkey.
    subkey: Option<&'request EncryptionKey>,
}

/// Build a TGS-REQ for an explicit KDC realm, timestamp, and confounder, with
/// an optional authenticator subkey: the request, and the DER of the AP-REQ
/// that went into its `PA-TGS-REQ` padata.
///
/// # Errors
///
/// Returns [`Error::EmptyEtypes`] for an empty enctype list, and the ticket,
/// encoding, time or crypto error of whichever step fails.
fn build_tgs_req_for_realm_inner(
    tgt: &AsRepSession,
    kdc_realm: impl Into<String>,
    service: Principal,
    options: TgsReq,
    authenticator_context: TgsAuthenticatorContext<'_>,
) -> Result<(BuiltTgsReq, Zeroizing<Vec<u8>>), Error> {
    crypto_policy::padata(&options.padata)?;
    let crypto_policy = crypto_policy::request(&options.crypto_policy, &options.etypes)?;
    crypto_policy::session(&crypto_policy, tgt, Use::SessionKey)?;
    let TgsAuthenticatorContext {
        timestamp,
        cusec,
        confounder,
        subkey,
    } = authenticator_context;
    let ctime = time::authenticator(timestamp, cusec, "TGS authenticator")?;
    if options.etypes.is_empty() {
        return Err(Error::EmptyEtypes);
    }

    let kdc_realm_name: String = kdc_realm.into();
    let ticket = ticket::decode(&tgt.ticket).map_err(ticket_error)?;
    let till = options
        .now
        .checked_add(options.ticket_lifetime)
        .ok_or(Error::TimeOverflow)?;
    let renew_till = options
        .renew_lifetime
        .map(|duration| options.now.checked_add(duration).ok_or(Error::TimeOverflow))
        .transpose()?;
    let additional_tickets =
        (!options.additional_tickets.is_empty()).then_some(options.additional_tickets);
    let cname = principal_to_rasn(&tgt.client)?;
    let kdc_option_bits = request_kdc_option_bits(options.kdc_option_bits, options.renew_lifetime);
    let req_body = rasn_kerberos::KdcReqBody {
        kdc_options: kdc_options_from_bits(kdc_option_bits),
        cname: Some(cname.clone()),
        realm: kerberos_string(&kdc_realm_name)?,
        sname: Some(principal_to_rasn(&service)?),
        from: None,
        till: kerberos_time_from_system_time(till)?,
        rtime: renew_till.map(kerberos_time_from_system_time).transpose()?,
        nonce: options.nonce,
        etype: options.etypes,
        addresses: None,
        enc_authorization_data: None,
        additional_tickets,
    };
    let req_body_der = kdc_req::encode_kdc_req_body(&req_body).map_err(kdc_req_error)?;
    let etype = KerberosEtype::from_etype_id(tgt.session_key.etype)
        .ok_or(Error::UnsupportedEtype(tgt.session_key.etype))?;
    let checksum = etype.checksum(
        &tgt.session_key.value,
        &req_body_der,
        TGS_REQ_AUTHENTICATOR_CHECKSUM_USAGE,
    )?;
    let authenticator = rasn_kerberos::Authenticator {
        authenticator_vno: Integer::from(KRB5_PVNO),
        crealm: kerberos_string(&tgt.client.realm)?,
        cname,
        cksum: Some(rasn_kerberos::Checksum {
            r#type: etype.checksum_type_id(),
            checksum: checksum.into(),
        }),
        cusec: Integer::from(cusec),
        ctime,
        subkey: subkey.map(encryption_key_to_rasn),
        seq_number: None,
        authorization_data: None,
    };
    let authenticator_kvno = ticket.enc_part.kvno;
    let ap_req = ap_req::build_ap_req_with_confounder(
        ticket,
        ap_req::ap_options_from_bits(0),
        &authenticator,
        &tgt.session_key,
        TGS_REQ_AUTHENTICATOR_USAGE,
        authenticator_kvno,
        confounder,
    )
    .map_err(ap_req_error)?;
    let ap_req_der = Zeroizing::new(ap_req::encode(&ap_req).map_err(ap_req_error)?);
    let pa_tgs_req = rasn_kerberos::PaData {
        r#type: PA_TGS_REQ,
        value: ap_req_der.to_vec().into(),
    };
    // A capacity hint only: saturating at `usize::MAX` is harmless.
    let mut padata = Vec::with_capacity(options.padata.len().saturating_add(1));
    padata.push(pa_tgs_req);
    padata.extend(options.padata);
    let message = kdc_req::build_tgs_req(req_body, Some(padata));
    let der = kdc_req::encode_tgs_req(&message).map_err(kdc_req_error)?;

    Ok((
        BuiltTgsReq {
            crypto_policy,
            reply_clock: (options.now, options.clock_skew),
            message,
            der: Zeroizing::new(der),
            client: tgt.client.clone(),
            kdc_realm: kdc_realm_name,
            service,
            nonce: options.nonce,
            delegation_keytab: options.delegation_keytab,
        },
        ap_req_der,
    ))
}

/// Build a client AP-REQ with an explicit authenticator timestamp and confounder.
/// # Errors
///
/// Returns [`Error::Decode`] when the service ticket does not decode,
/// [`Error::InvalidKerberosString`] for an invalid client name or realm,
/// [`Error::TimeOverflow`] for an out-of-range timestamp, and the AP-REQ build,
/// encryption and encoding errors. Fractional timestamps return [`Error::Encode`];
/// supply whole seconds in `timestamp` and the fractional part separately in `cusec`.
#[inline]
pub fn build_ap_req_with_confounder(
    service_ticket: &TgsRepSession,
    options: ApReq,
    timestamp: SystemTime,
    cusec: u32,
    confounder: &[u8],
) -> Result<BuiltApReq, Error> {
    if let Some(checksum) = &options.checksum {
        selection::reject_checksum(checksum.r#type)?;
    }
    let policy = options.crypto_policy.clone().unwrap_or_default();
    crypto_policy::session(&policy, service_ticket, Use::SessionKey)?;
    if let Some(subkey) = &options.subkey {
        policy.check_use(subkey.etype, Use::SessionKey)?;
    }
    let ctime = time::authenticator(timestamp, cusec, "AP-REQ timestamp")?;
    let ticket = ticket::decode(&service_ticket.ticket).map_err(ticket_error)?;
    let authenticator = rasn_kerberos::Authenticator {
        authenticator_vno: Integer::from(KRB5_PVNO),
        crealm: kerberos_string(&service_ticket.client.realm)?,
        cname: principal_to_rasn(&service_ticket.client)?,
        cksum: options.checksum,
        cusec: Integer::from(cusec),
        ctime,
        subkey: options.subkey.as_ref().map(encryption_key_to_rasn),
        seq_number: options.sequence_number,
        authorization_data: None,
    };
    let authenticator_usage = ap_req::authenticator_usage_for_ticket(&ticket);
    let authenticator_kvno = ticket.enc_part.kvno;
    let message = ap_req::build_ap_req_with_confounder(
        ticket,
        ap_req::ap_options_from_bits(options.ap_option_bits),
        &authenticator,
        &service_ticket.session_key,
        authenticator_usage,
        authenticator_kvno,
        confounder,
    )
    .map_err(ap_req_error)?;
    let der = Zeroizing::new(ap_req::encode(&message).map_err(ap_req_error)?);
    let authenticator_time = timestamp
        .checked_add(Duration::from_micros(cusec.into()))
        .ok_or(Error::TimeOverflow)?;

    Ok(BuiltApReq {
        message,
        der,
        client: service_ticket.client.clone(),
        service: service_ticket.service.clone(),
        session_key: service_ticket.session_key.clone(),
        authenticator_ctime: timestamp,
        authenticator_cusec: cusec,
        authenticator_time,
        sequence_number: options.sequence_number,
        subkey: options.subkey,
    })
}

/// Build a TGS-REQ that renews an existing TGT session.
/// Keeps the original server and contacts its issuing realm, including `krbtgt/B@A`.
/// # Errors
///
/// Returns [`Error::InvalidTgtSession`] when the session is not a TGT, and the
/// errors of [`build_tgs_req_for_realm`].
#[inline]
pub fn build_tgt_renewal_req(tgt: &AsRepSession, options: TgsReq) -> Result<BuiltTgsReq, Error> {
    let _destination = tgt_realm(tgt).ok_or_else(|| Error::InvalidTgtSession {
        service: tgt.service.name(),
    })?;
    build_ticket_renewal_req(tgt, options)
}

/// Build a deterministic TGT renewal request with an explicit authenticator timestamp and confounder.
/// Keeps the original server and contacts its issuing realm, including `krbtgt/B@A`.
/// # Errors
///
/// Returns [`Error::InvalidTgtSession`] when the session is not a TGT, and the
/// errors of [`build_tgs_req_for_realm_with_confounder`].
#[inline]
pub fn build_tgt_renewal_req_with_confounder(
    tgt: &AsRepSession,
    options: TgsReq,
    timestamp: SystemTime,
    cusec: u32,
    confounder: &[u8],
) -> Result<BuiltTgsReq, Error> {
    let _destination = tgt_realm(tgt).ok_or_else(|| Error::InvalidTgtSession {
        service: tgt.service.name(),
    })?;
    build_ticket_renewal_req_with_confounder(tgt, options, timestamp, cusec, confounder)
}

/// Build a TGS-REQ that renews an existing service ticket.
/// # Errors
///
/// Returns the errors of [`build_tgs_req_for_realm`].
#[inline]
pub fn build_ticket_renewal_req(
    ticket: &AsRepSession,
    options: TgsReq,
) -> Result<BuiltTgsReq, Error> {
    build_tgs_req_for_realm(
        ticket,
        ticket.service.realm.clone(),
        ticket.service.clone(),
        options.with_renewal(),
    )
}

/// Build a deterministic service-ticket renewal request with an explicit authenticator timestamp and confounder.
/// # Errors
///
/// Returns the errors of [`build_tgs_req_for_realm_with_confounder`].
#[inline]
pub fn build_ticket_renewal_req_with_confounder(
    ticket: &AsRepSession,
    options: TgsReq,
    timestamp: SystemTime,
    cusec: u32,
    confounder: &[u8],
) -> Result<BuiltTgsReq, Error> {
    build_tgs_req_for_realm_with_confounder(
        ticket,
        ticket.service.realm.clone(),
        ticket.service.clone(),
        options.with_renewal(),
        timestamp,
        cusec,
        confounder,
    )
}

/// Send an AS-REQ through a transport and process the returned AS-REP.
/// # Errors
///
/// Returns the transport's error, and the errors of [`process_as_rep`].
#[inline]
pub fn exchange_as_req<T>(
    transport: &mut T,
    request: &BuiltAsReq,
    reply_key: &EncryptionKey,
) -> Result<AsRepSession, Error>
where
    T: KdcTransport + ?Sized,
{
    crypto_policy::padata(request.message.0.padata.as_deref().unwrap_or_default())?;
    crypto_policy::before_exchange(
        &request.crypto_policy,
        &request.message.0.req_body.etype,
        reply_key,
    )?;
    let response = transport.send(&request.client.realm, &request.der)?;
    process_as_rep(request, &response, reply_key)
}

/// Send a TGS-REQ through a transport and process the returned TGS-REP.
/// # Errors
///
/// Returns the transport's error, and the errors of [`process_tgs_rep`].
#[inline]
pub fn exchange_tgs_req<T>(
    transport: &mut T,
    request: &BuiltTgsReq,
    tgs_session_key: &EncryptionKey,
) -> Result<TgsRepSession, Error>
where
    T: KdcTransport + ?Sized,
{
    crypto_policy::padata(request.message.0.padata.as_deref().unwrap_or_default())?;
    crypto_policy::before_exchange(
        &request.crypto_policy,
        &request.message.0.req_body.etype,
        tgs_session_key,
    )?;
    let response = transport.send(&request.kdc_realm, &request.der)?;
    process_tgs_rep(request, &response, tgs_session_key)
}

/// Perform `S4U2Self` through a runtime-neutral transport.
/// # Errors
///
/// Returns the errors of [`build_s4u2self_req`] and [`exchange_tgs_req`].
#[inline]
pub fn s4u2self<T>(
    transport: &mut T,
    service_tgt: &AsRepSession,
    user: Principal,
    options: TgsReq,
) -> Result<TgsRepSession, Error>
where
    T: KdcTransport + ?Sized,
{
    let request = build_s4u2self_req(service_tgt, user, options)?;
    exchange_tgs_req(transport, &request, &service_tgt.session_key)
}

/// Perform `S4U2Proxy` through a runtime-neutral transport.
/// # Errors
///
/// Returns the errors of [`build_s4u2proxy_req`] and [`exchange_tgs_req`].
#[inline]
pub fn s4u2proxy<T>(
    transport: &mut T,
    service_tgt: &AsRepSession,
    evidence_ticket: &TgsRepSession,
    target_service: Principal,
    options: TgsReq,
) -> Result<TgsRepSession, Error>
where
    T: KdcTransport + ?Sized,
{
    let request = build_s4u2proxy_req(service_tgt, evidence_ticket, target_service, options)?;
    exchange_tgs_req(transport, &request, &service_tgt.session_key)
}

/// Renew an existing TGT through a runtime-neutral transport.
/// # Errors
///
/// Returns the errors of [`build_tgt_renewal_req`] and [`exchange_tgs_req`].
#[inline]
pub fn renew_tgt<T>(
    transport: &mut T,
    tgt: &AsRepSession,
    options: TgsReq,
) -> Result<TgsRepSession, Error>
where
    T: KdcTransport + ?Sized,
{
    let request = build_tgt_renewal_req(tgt, options)?;
    exchange_tgs_req(transport, &request, &tgt.session_key)
}

/// Renew an existing service ticket through a runtime-neutral transport.
/// # Errors
///
/// Returns the errors of [`build_ticket_renewal_req`] and [`exchange_tgs_req`].
#[inline]
pub fn renew_ticket<T>(
    transport: &mut T,
    ticket: &AsRepSession,
    options: TgsReq,
) -> Result<TgsRepSession, Error>
where
    T: KdcTransport + ?Sized,
{
    let request = build_ticket_renewal_req(ticket, options)?;
    exchange_tgs_req(transport, &request, &ticket.session_key)
}

/// Perform a TGT AS login using password credentials and KDC preauth hints.
///
/// # Security
/// The caller retains erasure duties for the borrowed password and all caller-created
/// copies. Prefer a caller-owned [`Password`] or [`Zeroizing`] buffer; library
/// erasure of derived keys does not erase the original password.
/// # Errors
///
/// Returns the errors of [`login_as_service_with_password`].
#[inline]
pub fn login_tgt_with_password<T>(
    transport: &mut T,
    client: Principal,
    password: &[u8],
    options: AsReq,
) -> Result<AsRepSession, Error>
where
    T: KdcTransport + ?Sized,
{
    let service = Principal::tgt_service(client.realm.clone());
    login_as_service_with_password(transport, client, service, password, options)
}

/// Perform an AS login for an explicit service using password credentials and KDC preauth hints.
///
/// # Security
/// The caller retains erasure duties for the borrowed password and all caller-created
/// copies. Prefer a caller-owned [`Password`] or [`Zeroizing`] buffer; library
/// erasure of derived keys does not erase the original password.
/// # Errors
///
/// Returns the transport's error, [`Error::Kdc`] when the KDC rejects the login,
/// [`Error::NoSupportedPreauthEtype`] when no requested enctype can be used,
/// key derivation errors, and the errors of [`process_as_rep`].
#[inline]
pub fn login_as_service_with_password<T>(
    transport: &mut T,
    client: Principal,
    service: Principal,
    password: &[u8],
    options: AsReq,
) -> Result<AsRepSession, Error>
where
    T: KdcTransport + ?Sized,
{
    let initial_request =
        password_initial_as_req(client.clone(), service.clone(), password, options.clone())?;
    let mut initial_response = transport.send(&client.realm, &initial_request.der)?;
    if let Some(session) =
        password_initial_as_rep_session(&initial_request, &initial_response, &client, password)?
    {
        return Ok(session);
    }
    if let Some(probe) = preauth::discovery_request(&initial_request, &options, &initial_response)?
    {
        initial_response = transport.send(&client.realm, &probe.der)?;
        preauth::validate_discovery(&initial_response, &options)?;
    }
    let (request, reply_key) =
        password_preauth_request(client, service, password, options, &initial_response)?;
    let response = transport.send(&request.client.realm, &request.der)?;
    process_as_rep(&request, &response, &reply_key)
}

/// Perform a TGT AS login using keytab credentials and KDC preauth hints.
/// # Errors
///
/// Returns the errors of [`login_as_service_with_keytab`].
#[inline]
pub fn login_tgt_with_keytab<T>(
    transport: &mut T,
    client: Principal,
    keytab: &Keytab,
    options: AsReq,
) -> Result<AsRepSession, Error>
where
    T: KdcTransport + ?Sized,
{
    let service = Principal::tgt_service(client.realm.clone());
    login_as_service_with_keytab(transport, client, service, keytab, options)
}

/// Perform an AS login for an explicit service using keytab credentials and KDC preauth hints.
/// # Errors
///
/// Returns the transport's error, [`Error::Kdc`] when the KDC rejects the login,
/// [`Error::NoSupportedPreauthEtype`] or [`Error::Keytab`] when the keytab has no
/// usable key, and the errors of [`process_as_rep`].
#[inline]
pub fn login_as_service_with_keytab<T>(
    transport: &mut T,
    client: Principal,
    service: Principal,
    keytab: &Keytab,
    options: AsReq,
) -> Result<AsRepSession, Error>
where
    T: KdcTransport + ?Sized,
{
    let initial_request =
        keytab_initial_as_req(client.clone(), service.clone(), keytab, options.clone())?;
    let mut initial_response = transport.send(&client.realm, &initial_request.der)?;
    if let Some(session) =
        keytab_initial_as_rep_session(&initial_request, &initial_response, &client, keytab)?
    {
        return Ok(session);
    }
    if let Some(probe) = preauth::discovery_request(&initial_request, &options, &initial_response)?
    {
        initial_response = transport.send(&client.realm, &probe.der)?;
        preauth::validate_discovery(&initial_response, &options)?;
    }
    let (request, reply_key) =
        keytab_preauth_request(client, service, keytab, options, &initial_response)?;
    let response = transport.send(&request.client.realm, &request.der)?;
    process_as_rep(&request, &response, &reply_key)
}

/// Decrypt and validate an AS-REP against the original AS-REQ.
/// # Errors
///
/// Returns [`Error::Kdc`] for a KRB-ERROR reply, [`Error::Decode`] or a
/// decryption error for a malformed reply, [`Error::EnctypeNotRequested`] for an
/// enctype the request did not offer, the FAST negotiation errors, and
/// [`Error::NonceMismatch`], [`Error::PrincipalMismatch`] or
/// [`Error::ServicePrincipalMismatch`] when the reply does not answer the
/// request.
#[inline]
pub fn process_as_rep(
    request: &BuiltAsReq,
    bytes: &[u8],
    reply_key: &EncryptionKey,
) -> Result<AsRepSession, Error> {
    request
        .crypto_policy
        .check_use(reply_key.etype, Use::ReplyKey)?;
    if let Ok(error) = process_kdc_error(bytes) {
        return Err(Error::Kdc(Box::new(error)));
    }

    let as_rep = kdc_rep::decode_as_rep(bytes).map_err(kdc_rep_error)?;
    let kdc_rep = &as_rep.0;
    enforce_requested_enctypes(&request.message.0.req_body.etype, kdc_rep.enc_part.etype)?;
    request
        .crypto_policy
        .check_use(kdc_rep.enc_part.etype, Use::ReplyKey)?;
    request
        .crypto_policy
        .check_use(kdc_rep.ticket.enc_part.etype, Use::TicketKey)?;

    let client = principal_from_parts(&kdc_rep.crealm, &kdc_rep.cname)?;
    if !principal_matches(&client, &request.client) {
        return Err(Error::PrincipalMismatch {
            expected: request.client.name(),
            actual: client.name(),
        });
    }

    let enc_part = kdc_rep::decrypt_as_rep_enc_part(&as_rep, reply_key).map_err(kdc_rep_error)?;
    request
        .crypto_policy
        .check_use(enc_part.key.r#type, Use::SessionKey)?;
    reply_constraints::validate(&request.message.0.req_body, &enc_part, request.reply_clock)?;
    enforce_requested_enctypes(&request.message.0.req_body.etype, enc_part.key.r#type)?;
    validate_reply_encrypted_padata(
        (&request.der, request.message.0.padata.as_deref()),
        &enc_part,
        reply_key,
    )?;

    if enc_part.nonce != request.nonce {
        return Err(Error::NonceMismatch {
            expected: request.nonce,
            actual: enc_part.nonce,
        });
    }

    let enc_part_service = principal_from_parts(&enc_part.srealm, &enc_part.sname)?;
    if !principal_matches(&enc_part_service, &request.service) {
        return Err(Error::ServicePrincipalMismatch {
            expected: request.service.name(),
            actual: enc_part_service.name(),
        });
    }

    let ticket_service = principal_from_parts(&kdc_rep.ticket.realm, &kdc_rep.ticket.sname)?;
    if !principal_matches(&ticket_service, &enc_part_service) {
        return Err(Error::ServicePrincipalMismatch {
            expected: enc_part_service.name(),
            actual: ticket_service.name(),
        });
    }

    let ticket = Zeroizing::new(ticket::encode(&kdc_rep.ticket).map_err(ticket_error)?);
    Ok(AsRepSession {
        client,
        service: enc_part_service,
        session_key: encryption_key_from_rasn(&enc_part.key),
        ticket,
        ticket_flags: ticket_flags_to_bytes(&enc_part.flags),
        auth_time: system_time_from_kerberos_time(&enc_part.auth_time)?,
        start_time: system_time_from_kerberos_time(
            enc_part.start_time.as_ref().unwrap_or(&enc_part.auth_time),
        )?,
        end_time: system_time_from_kerberos_time(&enc_part.end_time)?,
        renew_till: enc_part
            .renew_till
            .as_ref()
            .map(system_time_from_kerberos_time)
            .transpose()?,
        key_expiration: enc_part
            .key_expiration
            .as_ref()
            .map(system_time_from_kerberos_time)
            .transpose()?,
    })
}

/// Verify negotiated AS/TGS request integrity (RFC 6806 section 11).
///
/// The check runs only when the request carried PA-REQ-ENC-PA-REP and the reply
/// sets the `enc-pa-rep` ticket flag.
///
/// # Errors
///
/// Returns [`Error::InvalidFastNegotiationResponse`] when the encrypted padata
/// is missing or incomplete, [`Error::UnsupportedChecksumType`] for an unknown
/// checksum type, [`Error::FastNegotiationChecksumMismatch`] when the checksum
/// does not match the request, and [`Error::Message`] when the checksum does not
/// decode.
fn validate_reply_encrypted_padata(
    request: (&[u8], Option<&[rasn_kerberos::PaData]>),
    enc_part: &rasn_kerberos::EncKdcRepPart,
    reply_key: &EncryptionKey,
) -> Result<(), Error> {
    if !request
        .1
        .is_some_and(|data| padata_contains(data, PA_REQ_ENC_PA_REP))
        || !ticket_flags_contain_bits(&enc_part.flags, TICKET_FLAG_ENC_PA_REP)
    {
        return Ok(());
    }

    let encrypted_pa_data = enc_part
        .encrypted_pa_data
        .as_ref()
        .ok_or(Error::InvalidFastNegotiationResponse)?;
    let pa_req_enc_pa_rep = encrypted_pa_data
        .iter()
        .find(|padata| padata.r#type == PA_REQ_ENC_PA_REP)
        .ok_or(Error::InvalidFastNegotiationResponse)?;
    let checksum = messages::PaReqEncPaRep::decode_der(pa_req_enc_pa_rep.value.as_ref())?;
    let etype = selection::checksum(checksum.checksum_type)?
        .ok_or(Error::UnsupportedChecksumType(checksum.checksum_type))?;
    if !etype.verify_checksum(
        &reply_key.value,
        request.0,
        checksum.checksum.as_ref(),
        AS_REQ_CHECKSUM_USAGE,
    ) {
        return Err(Error::FastNegotiationChecksumMismatch);
    }
    Ok(())
}

/// Whether `padata` contains an entry of `padata_type`.
fn padata_contains(padata: &[rasn_kerberos::PaData], padata_type: i32) -> bool {
    padata.iter().any(|entry| entry.r#type == padata_type)
}

/// Whether every bit of `bits` is set in the ticket flags.
fn ticket_flags_contain_bits(flags: &rasn_kerberos::TicketFlags, bits: u32) -> bool {
    u32::from_be_bytes(ticket_flags_to_bytes(flags)) & bits == bits
}

/// Decrypt and validate a TGS-REP against the original TGS-REQ.
/// # Errors
///
/// Returns [`Error::Kdc`] for a KRB-ERROR reply, decode and decryption errors,
/// and the principal, nonce and enctype mismatch errors of the validation.
#[inline]
pub fn process_tgs_rep(
    request: &BuiltTgsReq,
    bytes: &[u8],
    tgs_session_key: &EncryptionKey,
) -> Result<TgsRepSession, Error> {
    process_tgs_rep_inner(request, bytes, tgs_session_key, false)
}

/// Decrypt and validate a TGS-REP, permitting intermediate referral TGTs.
/// # Errors
///
/// Returns the errors of [`process_tgs_rep`].
#[inline]
pub fn process_tgs_rep_with_referral(
    request: &BuiltTgsReq,
    bytes: &[u8],
    tgs_session_key: &EncryptionKey,
) -> Result<TgsRepSession, Error> {
    process_tgs_rep_inner(request, bytes, tgs_session_key, true)
}

/// Decrypt and validate a TGS-REP; `allow_referral` accepts a `krbtgt`
/// ticket for another realm in place of the requested service.
///
/// # Errors
///
/// Returns [`Error::Kdc`] for a KRB-ERROR reply, decode and decryption errors,
/// and the principal, nonce and enctype mismatch errors of the validation.
fn process_tgs_rep_inner(
    request: &BuiltTgsReq,
    bytes: &[u8],
    tgs_session_key: &EncryptionKey,
    allow_referral: bool,
) -> Result<TgsRepSession, Error> {
    request
        .crypto_policy
        .check_use(tgs_session_key.etype, Use::ReplyKey)?;
    if let Ok(error) = process_kdc_error(bytes) {
        return Err(Error::Kdc(Box::new(error)));
    }

    let tgs_rep = kdc_rep::decode_tgs_rep(bytes).map_err(kdc_rep_error)?;
    let kdc_rep = &tgs_rep.0;
    request
        .crypto_policy
        .check_use(kdc_rep.enc_part.etype, Use::ReplyKey)?;
    request
        .crypto_policy
        .check_use(kdc_rep.ticket.enc_part.etype, Use::TicketKey)?;

    crypto_policy::delegated(request, &kdc_rep.ticket)?;

    let client = principal_from_parts(&kdc_rep.crealm, &kdc_rep.cname)?;
    if !principal_matches(&client, &request.client) {
        return Err(Error::PrincipalMismatch {
            expected: request.client.name(),
            actual: client.name(),
        });
    }

    let enc_part =
        kdc_rep::decrypt_tgs_rep_enc_part(&tgs_rep, tgs_session_key).map_err(kdc_rep_error)?;
    request
        .crypto_policy
        .check_use(enc_part.key.r#type, Use::SessionKey)?;
    reply_constraints::validate(&request.message.0.req_body, &enc_part, request.reply_clock)?;
    enforce_requested_enctypes(&request.message.0.req_body.etype, enc_part.key.r#type)?;
    validate_reply_encrypted_padata(
        (&request.der, request.message.0.padata.as_deref()),
        &enc_part,
        tgs_session_key,
    )?;

    if enc_part.nonce != request.nonce {
        return Err(Error::NonceMismatch {
            expected: request.nonce,
            actual: enc_part.nonce,
        });
    }

    let enc_part_service = principal_from_parts(&enc_part.srealm, &enc_part.sname)?;
    let referral = allow_referral
        && is_tgt_principal(&enc_part_service)
        && !principal_matches(&enc_part_service, &request.service);
    if !principal_matches(&enc_part_service, &request.service) && !referral {
        return Err(Error::ServicePrincipalMismatch {
            expected: request.service.name(),
            actual: enc_part_service.name(),
        });
    }

    let ticket_service = principal_from_parts(&kdc_rep.ticket.realm, &kdc_rep.ticket.sname)?;
    if !principal_matches(&ticket_service, &enc_part_service) {
        return Err(Error::ServicePrincipalMismatch {
            expected: enc_part_service.name(),
            actual: ticket_service.name(),
        });
    }

    let ticket = Zeroizing::new(ticket::encode(&kdc_rep.ticket).map_err(ticket_error)?);
    Ok(AsRepSession {
        client,
        service: enc_part_service,
        session_key: encryption_key_from_rasn(&enc_part.key),
        ticket,
        ticket_flags: ticket_flags_to_bytes(&enc_part.flags),
        auth_time: system_time_from_kerberos_time(&enc_part.auth_time)?,
        start_time: system_time_from_kerberos_time(
            enc_part.start_time.as_ref().unwrap_or(&enc_part.auth_time),
        )?,
        end_time: system_time_from_kerberos_time(&enc_part.end_time)?,
        renew_till: enc_part
            .renew_till
            .as_ref()
            .map(system_time_from_kerberos_time)
            .transpose()?,
        key_expiration: enc_part
            .key_expiration
            .as_ref()
            .map(system_time_from_kerberos_time)
            .transpose()?,
    })
}

/// Bind a delegated user to a frontend-decryptable ticket, not KDC-REP cleartext.
///
/// # Errors
/// Returns key lookup/decryption errors, or `DelegationPrincipalMismatch` when
/// the protected ticket client differs from the requested/evidence identity.
fn validate_delegated_ticket(
    ticket: &rasn_kerberos::Ticket,
    expected: &Principal,
    keys: &Keytab,
) -> Result<(), Error> {
    let service = principal_from_parts(&ticket.realm, &ticket.sname)?;
    let names = service
        .components
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let (key, _) = keys.find_key(
        &names,
        &service.realm,
        ticket.enc_part.kvno.unwrap_or_default(),
        ticket.enc_part.etype,
    )?;
    let part = ticket::decrypt_ticket_enc_part(ticket, key).map_err(ticket_error)?;
    let client = principal_from_parts(&part.crealm, &part.cname)?;
    if !principal_matches(&client, expected) {
        return Err(Error::DelegationPrincipalMismatch);
    }
    Ok(())
}

/// Decode a KRB-ERROR and any METHOD-DATA preauthentication hints.
/// # Errors
///
/// Returns [`Error::Decode`] when `bytes` is not a KRB-ERROR or its
/// preauthentication data is malformed, and [`Error::InvalidString`] or
/// [`Error::InvalidUnsignedInteger`] for invalid fields.
#[inline]
pub fn process_kdc_error(bytes: &[u8]) -> Result<KdcError, Error> {
    let krb_error = krb_error::decode(bytes).map_err(krb_error_error)?;
    let info = krb_error::info(&krb_error).map_err(krb_error_error)?;
    let e_data = info.e_data;
    let method_data = krb_error::preauth_method_data(&krb_error, KDC_ERR_PREAUTH_REQUIRED)
        .map_err(krb_error_error)?;
    let preauth_key_info = preauth_key_info_from_method_data(&method_data)?;

    Ok(KdcError {
        ctime: info.ctime,
        cusec: info.cusec,
        stime: info.stime,
        susec: info.susec,
        error_code: info.error_code,
        text: info.e_text,
        client: info.client.map(principal_from_message_info),
        service: principal_from_message_info(info.service),
        e_data,
        method_data,
        preauth_key_info,
    })
}

/// Select a supported preauthentication key hint for the requested enctypes.
/// # Errors
///
/// Returns [`Error::NoSupportedPreauthEtype`] when no requested, supported
/// enctype is offered by the KDC.
#[inline]
pub fn select_preauth_key_info(
    error: &KdcError,
    requested_etypes: &[i32],
) -> Result<PreauthKeyInfo, Error> {
    for etype in requested_etypes {
        if KerberosEtype::from_etype_id(*etype).is_none() {
            continue;
        }
        if let Some(info) = error
            .preauth_key_info
            .iter()
            .find(|info| info.etype == *etype)
        {
            return Ok(info.clone());
        }
    }

    if error.preauth_key_info.is_empty()
        && let Some(etype) = requested_etypes
            .iter()
            .copied()
            .find(|etype| KerberosEtype::from_etype_id(*etype).is_some())
    {
        return Ok(PreauthKeyInfo {
            etype,
            salt: None,
            s2kparams: None,
        });
    }

    Err(Error::NoSupportedPreauthEtype {
        requested: requested_etypes.to_vec(),
    })
}

#[must_use]
/// Return the default Kerberos password salt for a principal.
#[inline]
pub fn default_password_salt(client: &Principal) -> String {
    let mut salt = client.realm.clone();
    for component in &client.components {
        salt.push_str(component);
    }
    salt
}

/// Derive a reply key from password credentials and a preauthentication hint.
///
/// Applies RFC-default minimum work factors to peer parameters. Application
/// overrides on `LibDefaults` are carried by the high-level request/login APIs.
/// Raw `KerberosEtype::string_to_key` remains policy-free for trusted RFC vectors.
///
/// # Security
/// The caller retains erasure duties for the borrowed password and all caller-created
/// copies. Prefer a caller-owned [`Password`] or [`Zeroizing`] buffer; library
/// erasure of derived keys does not erase the original password.
/// # Errors
///
/// Returns [`Error::UnsupportedEtype`] for an unknown enctype and
/// [`Error::Crypto`] for below-minimum, above-ceiling or malformed work factors,
/// or when key derivation fails.
#[inline]
pub fn derive_password_reply_key(
    client: &Principal,
    password: &[u8],
    key_info: &PreauthKeyInfo,
) -> Result<EncryptionKey, Error> {
    password_derivation::derive(&CryptoPolicy::default(), client, password, key_info)
}

/// Shared password derivation after trusted peer-parameter checks.
mod password_derivation;

/// Select a reply key from a keytab using a preauthentication hint.
/// # Errors
///
/// Returns [`Error::Keytab`] when the keytab has no key for the client and
/// enctype.
#[inline]
pub fn select_keytab_reply_key(
    keytab: &Keytab,
    client: &Principal,
    key_info: &PreauthKeyInfo,
) -> Result<(EncryptionKey, u32), Error> {
    selection::reject_enctype(key_info.etype)?;
    let components = client
        .components
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let (key, kvno) = keytab.find_key(&components, &client.realm, 0, key_info.etype)?;
    Ok((key.clone(), kvno))
}

use crate::error::Client as Error;

/// DER-decode `bytes` as `T`, naming `target` in the error.
///
/// # Errors
///
/// Returns [`Error::Decode`] when the bytes are not a valid DER `T`.
fn decode<T>(target: &'static str, bytes: &[u8]) -> Result<T, Error>
where
    T: rasn::Decode,
{
    der::decode(bytes).map_err(|source| Error::Decode {
        target,
        message: source.to_string(),
    })
}

/// DER-encode `value`, naming `target` in the error.
///
/// # Errors
///
/// Returns [`Error::Encode`] when encoding fails.
fn encode<T>(target: &'static str, value: &T) -> Result<Vec<u8>, Error>
where
    T: rasn::Encode,
{
    der::encode(value).map_err(|source| Error::Encode {
        target,
        message: source.to_string(),
    })
}

/// Map an AP-REQ helper error into the client error.
fn ap_req_error(error: error::ApReq) -> Error {
    match error {
        error::ApReq::Decode { target, message } => Error::Decode { target, message },
        error::ApReq::Encode { target, message } => Error::Encode { target, message },
        error::ApReq::InvalidMessage {
            field,
            expected,
            actual,
        } => Error::InvalidMessage {
            field,
            expected,
            actual,
        },
        error::ApReq::UnsupportedEtype(etype) => Error::UnsupportedEtype(etype),
        error::ApReq::KeyEtypeMismatch {
            key_etype,
            encrypted_data_etype,
        } => Error::ApReqKeyEtypeMismatch {
            key_etype,
            encrypted_data_etype,
        },
        error::ApReq::Random(source) => Error::Random(source),
        error::ApReq::Crypto(source) => Error::Crypto(source),
    }
}

/// Map a KDC-REQ helper error into the client error.
fn kdc_req_error(error: error::KdcReq) -> Error {
    match error {
        error::KdcReq::Decode { target, message } => Error::Decode { target, message },
        error::KdcReq::Encode { target, message } => Error::Encode { target, message },
        error::KdcReq::InvalidMessage {
            field,
            expected,
            actual,
        } => Error::InvalidMessage {
            field,
            expected,
            actual,
        },
        error::KdcReq::UnsupportedEtype(etype) => Error::UnsupportedEtype(etype),
        error::KdcReq::TicketKeyEtypeMismatch {
            key_etype,
            encrypted_data_etype,
        } => Error::TicketKeyEtypeMismatch {
            key_etype,
            encrypted_data_etype,
        },
        error::KdcReq::Random(source) => Error::Random(source),
        error::KdcReq::Crypto(source) => Error::Crypto(source),
    }
}

include!("client/krb_error_mapping.rs");

/// Map a ticket helper error into the client error.
fn ticket_error(error: error::Ticket) -> Error {
    match error {
        error::Ticket::Decode { target, message } => Error::Decode { target, message },
        error::Ticket::Encode { target, message } => Error::Encode { target, message },
        error::Ticket::InvalidMessage {
            field,
            expected,
            actual,
        } => Error::InvalidMessage {
            field,
            expected,
            actual,
        },
        error::Ticket::UnsupportedEtype(etype) => Error::UnsupportedEtype(etype),
        error::Ticket::KeyEtypeMismatch {
            key_etype,
            encrypted_data_etype,
        } => Error::TicketKeyEtypeMismatch {
            key_etype,
            encrypted_data_etype,
        },
        error::Ticket::Random(source) => Error::Random(source),
        error::Ticket::Crypto(source) => Error::Crypto(source),
    }
}

/// Map a KDC-REP helper error into the client error.
fn kdc_rep_error(error: error::KdcRep) -> Error {
    match error {
        error::KdcRep::Decode { target, message } => Error::Decode { target, message },
        error::KdcRep::Encode { target, message } => Error::Encode { target, message },
        error::KdcRep::InvalidMessage {
            field,
            expected,
            actual,
        } => Error::InvalidMessage {
            field,
            expected,
            actual,
        },
        error::KdcRep::UnsupportedEtype(etype) => Error::UnsupportedEtype(etype),
        error::KdcRep::KeyEtypeMismatch {
            key_etype,
            encrypted_data_etype,
        } => Error::KeyEtypeMismatch {
            key_etype,
            encrypted_data_etype,
        },
        error::KdcRep::TicketKeyEtypeMismatch {
            key_etype,
            encrypted_data_etype,
        } => Error::TicketKeyEtypeMismatch {
            key_etype,
            encrypted_data_etype,
        },
        error::KdcRep::Random(source) => Error::Random(source),
        error::KdcRep::Crypto(source) => Error::Crypto(source),
    }
}

/// Map an AP-REP helper error into the client error.
fn ap_rep_error(error: error::ApRep) -> Error {
    match error {
        error::ApRep::Decode { target, message } => Error::Decode { target, message },
        error::ApRep::Encode { target, message } => Error::Encode { target, message },
        error::ApRep::InvalidMessage {
            field,
            expected,
            actual,
        } => Error::InvalidMessage {
            field,
            expected,
            actual,
        },
        error::ApRep::UnsupportedEtype(etype) => Error::UnsupportedEtype(etype),
        error::ApRep::KeyEtypeMismatch {
            key_etype,
            encrypted_data_etype,
        } => Error::ApRepKeyEtypeMismatch {
            key_etype,
            encrypted_data_etype,
        },
        error::ApRep::Random(source) => Error::Random(source),
        error::ApRep::Crypto(source) => Error::Crypto(source),
    }
}

/// The first AS-REQ of a password login: preauthenticated when configured to
/// assume preauthentication, otherwise a plain probe.
///
/// # Errors
///
/// Returns [`Error::NoSupportedPreauthEtype`], key derivation and request
/// building errors.
fn password_initial_as_req(
    client: Principal,
    service: Principal,
    password: &[u8],
    requested: AsReq,
) -> Result<BuiltAsReq, Error> {
    crypto_policy::padata(&requested.padata)?;
    let policy = crypto_policy::request(&requested.crypto_policy, &requested.etypes)?;
    let options = initial_preauth_probe_options(requested);
    if options.assume_preauthentication {
        let key_info = assumed_preauth_key_info(&options.etypes)?;
        policy.check_use(key_info.etype, Use::ReplyKey)?;
        let reply_key = password_derivation::derive(&policy, &client, password, &key_info)?;
        build_preauthenticated_as_req(client, service, options, &reply_key, None)
    } else {
        build_as_req(client, service, options)
    }
}

/// Process an AS-REP received without preauthentication, deriving the reply
/// key from `password`. Returns `Ok(None)` when `response` is not an AS-REP.
///
/// # Errors
///
/// Returns [`Error::EnctypeNotRequested`] for an enctype the request did not
/// offer, and key derivation and AS-REP validation errors.
fn password_initial_as_rep_session(
    request: &BuiltAsReq,
    response: &[u8],
    client: &Principal,
    password: &[u8],
) -> Result<Option<AsRepSession>, Error> {
    let Some((etype, _)) = as_rep_reply_key_info(response) else {
        return Ok(None);
    };
    enforce_requested_enctypes(&request.message.0.req_body.etype, etype)?;
    let reply = kdc_rep::decode_as_rep(response).map_err(kdc_rep_error)?;
    let padata = reply.0.padata.as_deref().unwrap_or_default();
    let infos = preauth_key_info_from_method_data(padata)?;
    let key_info = match infos.into_iter().find(|info| info.etype == etype) {
        Some(info) => info,
        None => PreauthKeyInfo {
            etype,
            salt: padata
                .iter()
                .find(|pa| pa.r#type == PA_PW_SALT)
                .map(|pa| str::from_utf8(pa.value.as_ref()).map(str::to_owned))
                .transpose()?,
            s2kparams: None,
        },
    };
    request
        .crypto_policy
        .check_use(key_info.etype, Use::ReplyKey)?;
    let reply_key =
        password_derivation::derive(&request.crypto_policy, client, password, &key_info)?;
    process_as_rep(request, response, &reply_key).map(Some)
}

/// The first AS-REQ of a keytab login: preauthenticated when configured to
/// assume preauthentication, otherwise a plain probe.
///
/// # Errors
///
/// Returns [`Error::NoSupportedPreauthEtype`], keytab lookup and request
/// building errors.
fn keytab_initial_as_req(
    client: Principal,
    service: Principal,
    keytab: &Keytab,
    requested: AsReq,
) -> Result<BuiltAsReq, Error> {
    drop(crypto_policy::request(
        &requested.crypto_policy,
        &requested.etypes,
    )?);
    let options = initial_preauth_probe_options(requested);
    if options.assume_preauthentication {
        let (reply_key, kvno) = select_assumed_keytab_reply_key(keytab, &client, &options)?;
        build_preauthenticated_as_req(client, service, options, &reply_key, Some(kvno))
    } else {
        build_as_req(client, service, options)
    }
}

/// Key info for assumed preauthentication: the first supported requested enctype
/// with the default salt.
///
/// # Errors
///
/// Returns [`Error::NoSupportedPreauthEtype`] when no requested enctype is
/// supported.
fn assumed_preauth_key_info(requested_etypes: &[i32]) -> Result<PreauthKeyInfo, Error> {
    requested_etypes
        .iter()
        .copied()
        .find(|etype| KerberosEtype::from_etype_id(*etype).is_some())
        .map(|etype| PreauthKeyInfo {
            etype,
            salt: None,
            s2kparams: None,
        })
        .ok_or_else(|| Error::NoSupportedPreauthEtype {
            requested: requested_etypes.to_vec(),
        })
}

/// The first keytab key, in request enctype order, usable for assumed
/// preauthentication, with its kvno.
///
/// # Errors
///
/// Returns [`Error::NoSupportedPreauthEtype`] when the keytab holds no key for a
/// supported requested enctype, and [`Error::Keytab`] for other keytab errors.
fn select_assumed_keytab_reply_key(
    keytab: &Keytab,
    client: &Principal,
    options: &AsReq,
) -> Result<(EncryptionKey, u32), Error> {
    let components = client
        .components
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    for etype in options
        .etypes
        .iter()
        .copied()
        .filter(|etype| KerberosEtype::from_etype_id(*etype).is_some())
    {
        match keytab.find_key(&components, &client.realm, 0, etype) {
            Ok((key, kvno)) => return Ok((key.clone(), kvno)),
            Err(error::Keytab::NoMatchingKey {
                principal: _,
                realm: _,
                kvno: _,
                etype: _,
            }) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Err(Error::NoSupportedPreauthEtype {
        requested: options.etypes.clone(),
    })
}

/// Process an AS-REP received without preauthentication, using the keytab
/// key that matches the reply. Returns `Ok(None)` when `response` is not an
/// AS-REP.
///
/// # Errors
///
/// Returns [`Error::EnctypeNotRequested`] for an enctype the request did not
/// offer, [`Error::Keytab`] when no key matches, and AS-REP validation errors.
fn keytab_initial_as_rep_session(
    request: &BuiltAsReq,
    response: &[u8],
    client: &Principal,
    keytab: &Keytab,
) -> Result<Option<AsRepSession>, Error> {
    let Some((etype, kvno)) = as_rep_reply_key_info(response) else {
        return Ok(None);
    };
    request.crypto_policy.check_use(etype, Use::ReplyKey)?;
    enforce_requested_enctypes(&request.message.0.req_body.etype, etype)?;
    let (reply_key, _) =
        select_keytab_reply_key_for_etype(keytab, client, kvno.unwrap_or_default(), etype)?;
    process_as_rep(request, response, &reply_key).map(Some)
}

/// The keytab key for the client, `kvno` and `etype`, with its kvno.
///
/// # Errors
///
/// Returns [`Error::Keytab`] when no matching key exists.
fn select_keytab_reply_key_for_etype(
    keytab: &Keytab,
    client: &Principal,
    kvno: u32,
    etype: i32,
) -> Result<(EncryptionKey, u32), Error> {
    let components = client
        .components
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let (key, found_kvno) = keytab.find_key(&components, &client.realm, kvno, etype)?;
    Ok((key.clone(), found_kvno))
}

/// Add PA-REQ-ENC-PA-REP to the request padata when FAST negotiation is on.
fn initial_preauth_probe_options(mut options: AsReq) -> AsReq {
    if options.fast_negotiation
        && !options
            .padata
            .iter()
            .any(|padata| padata.r#type == PA_REQ_ENC_PA_REP)
    {
        options.padata.push(rasn_kerberos::PaData {
            r#type: PA_REQ_ENC_PA_REP,
            value: Vec::new().into(),
        });
    }
    options
}

/// Replace conversation state with the KDC's exact cookies, never other hints.
fn preauth_retry_options(mut options: AsReq, method_data: &[rasn_kerberos::PaData]) -> AsReq {
    options.padata.retain(|entry| entry.r#type != PA_FX_COOKIE);
    options.padata.extend(
        method_data
            .iter()
            .filter(|entry| entry.r#type == PA_FX_COOKIE)
            .cloned(),
    );
    initial_preauth_probe_options(options)
}

/// Reject a reply enctype the request did not offer.
///
/// # Errors
///
/// Returns [`Error::EnctypeNotRequested`] when `requested` does not contain
/// `etype`.
fn enforce_requested_enctypes(requested: &[i32], etype: i32) -> Result<(), Error> {
    if requested.contains(&etype) {
        Ok(())
    } else {
        Err(Error::EnctypeNotRequested(etype))
    }
}

/// Reject a reply enctype outside an explicit operator allowlist.
///
/// Callers consult the allowlist only when `permitted_enctypes` was set
/// explicitly, so an empty allowlist permits nothing.
///
/// # Errors
///
/// Returns [`Error::EnctypeNotPermitted`] when `permitted` does not contain
/// `etype`.
#[cfg(feature = "tokio")]
pub(crate) fn ensure_permitted_enctype(permitted: &[i32], etype: i32) -> Result<(), Error> {
    if permitted.contains(&etype) {
        Ok(())
    } else {
        Err(Error::EnctypeNotPermitted(etype))
    }
}

/// Enctype and kvno of an AS-REP encrypted part, or `None` when `response` is
/// not an AS-REP.
fn as_rep_reply_key_info(response: &[u8]) -> Option<(i32, Option<u32>)> {
    kdc_rep::decode_as_rep(response)
        .ok()
        .map(|as_rep| (as_rep.0.enc_part.etype, as_rep.0.enc_part.kvno))
}

/// Key info entries from the ETYPE-INFO2 and ETYPE-INFO padata of a
/// KRB-ERROR, ETYPE-INFO2 first.
///
/// # Errors
///
/// Returns [`Error::Decode`] for malformed entries and [`Error::InvalidString`]
/// for a salt that is not UTF-8.
fn preauth_key_info_from_method_data(
    method_data: &[rasn_kerberos::PaData],
) -> Result<Vec<PreauthKeyInfo>, Error> {
    let mut infos = Vec::new();
    for padata in method_data
        .iter()
        .filter(|padata| padata.r#type == PA_ETYPE_INFO2)
    {
        let entries = decode::<rasn_kerberos::EtypeInfo2>("ETYPE-INFO2", padata.value.as_ref())?;
        for entry in entries {
            infos.push(PreauthKeyInfo {
                etype: entry.etype,
                salt: entry
                    .salt
                    .as_ref()
                    .map(kerberos_string_to_string)
                    .transpose()?,
                s2kparams: entry.s2kparams.map(|bytes| bytes.as_ref().to_vec()),
            });
        }
    }
    for padata in method_data
        .iter()
        .filter(|padata| padata.r#type == PA_ETYPE_INFO)
    {
        let entries = decode::<rasn_kerberos::EtypeInfo>("ETYPE-INFO", padata.value.as_ref())?;
        for entry in entries {
            infos.push(PreauthKeyInfo {
                etype: entry.etype,
                salt: entry
                    .salt
                    .as_ref()
                    .map(|salt| str::from_utf8(salt.as_ref()).map(str::to_owned))
                    .transpose()?,
                s2kparams: None,
            });
        }
    }
    Ok(infos)
}

/// The current time split into whole seconds and microseconds.
///
/// # Errors
///
/// Returns [`Error::TimeOverflow`] when the clock is before the Unix epoch.
fn current_preauth_time() -> Result<(SystemTime, u32), Error> {
    let now = SystemTime::now();
    let elapsed = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_before_epoch| Error::TimeOverflow)?;
    let whole_seconds = UNIX_EPOCH
        .checked_add(Duration::from_secs(elapsed.as_secs()))
        .ok_or(Error::TimeOverflow)?;
    Ok((whole_seconds, elapsed.subsec_micros()))
}

/// A fresh request nonce: 31 random bits from the OS random source, so the value
/// stays positive for peers that decode the nonce as a signed 32-bit integer.
///
/// # Errors
///
/// Returns [`Error::Random`] when the OS random source fails.
#[inline]
pub fn random_nonce() -> Result<u32, Error> {
    let mut bytes = [0; 4];
    getrandom::fill(&mut bytes)?;
    Ok(u32::from_be_bytes(bytes) & 0x7fff_ffff)
}

/// Lowercase hexadecimal encoding of `bytes`.
fn encode_hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    // A capacity hint only: saturating at `usize::MAX` is harmless.
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        // Both nibbles are below 16, so every lookup hits the table.
        for nibble in [byte >> 4_u32, byte & 0x0f] {
            if let Some(&digit) = HEX.get(usize::from(nibble)) {
                out.push(char::from(digit));
            }
        }
    }
    out
}

/// Convert a principal to its ASN.1 name.
///
/// # Errors
///
/// Returns [`Error::InvalidKerberosString`] when a component is not a valid
/// Kerberos string.
fn principal_to_rasn(value: &Principal) -> Result<rasn_kerberos::PrincipalName, Error> {
    Ok(rasn_kerberos::PrincipalName {
        r#type: value.name_type,
        string: value
            .components
            .iter()
            .map(|component| kerberos_string(component))
            .collect::<Result<Vec<_>, _>>()?,
    })
}

/// Build a principal from an ASN.1 realm and name.
///
/// # Errors
///
/// Returns [`Error::InvalidString`] when the realm or a component is not UTF-8.
fn principal_from_parts(
    realm: &rasn_kerberos::Realm,
    name: &rasn_kerberos::PrincipalName,
) -> Result<Principal, Error> {
    Ok(Principal {
        realm: kerberos_string_to_string(realm)?,
        name_type: name.r#type,
        components: name
            .string
            .iter()
            .map(kerberos_string_to_string)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

/// Convert a decoded principal name into a client [`Principal`].
fn principal_from_message_info(value: messages::PrincipalNameInfo) -> Principal {
    Principal {
        realm: value.realm,
        name_type: value.name_type,
        components: value.components,
    }
}

/// Whether two principals have the same realm and components; the name type is
/// ignored.
fn principal_matches(left: &Principal, right: &Principal) -> bool {
    left.realm == right.realm && left.components == right.components
}

/// Whether a principal is a `krbtgt/<realm>` service.
fn is_tgt_principal(principal: &Principal) -> bool {
    matches!(principal.components.as_slice(), [service, destination]
        if service == "krbtgt" && !destination.is_empty())
}

/// The realm a TGT session is issued for, or `None` for a non-TGT session.
fn tgt_realm(session: &AsRepSession) -> Option<String> {
    if is_tgt_principal(&session.service) {
        session.service.components.get(1).cloned()
    } else {
        None
    }
}

/// The realm mapped to the service host (its last component), if any.
#[cfg(feature = "tokio")]
fn service_realm(config: &Config, service: &Principal) -> Option<String> {
    service
        .components
        .last()
        .and_then(|host| config.realm_for_host(host))
        .map(str::to_owned)
}

/// Convert a string to an ASN.1 Kerberos string.
///
/// # Errors
///
/// Returns [`Error::InvalidKerberosString`] when the value is not a valid
/// Kerberos string.
fn kerberos_string(value: &str) -> Result<rasn_kerberos::KerberosString, Error> {
    rasn_kerberos::KerberosString::from_bytes(value.as_bytes())
        .map_err(|source| Error::InvalidKerberosString(source.to_string()))
}

/// Convert an ASN.1 Kerberos string to a `String`.
///
/// # Errors
///
/// Returns [`Error::InvalidString`] when the value is not UTF-8.
fn kerberos_string_to_string(value: &rasn_kerberos::KerberosString) -> Result<String, Error> {
    Ok(str::from_utf8(value.as_bytes())?.to_owned())
}

/// Convert an ASN.1 encryption key to the keytab key type.
fn encryption_key_from_rasn(value: &rasn_kerberos::EncryptionKey) -> EncryptionKey {
    EncryptionKey {
        etype: value.r#type,
        value: value.value.as_ref().to_vec(),
    }
}

/// Convert a keytab key to the ASN.1 encryption key type.
fn encryption_key_to_rasn(value: &EncryptionKey) -> rasn_kerberos::EncryptionKey {
    rasn_kerberos::EncryptionKey {
        r#type: value.etype,
        value: value.value.clone().into(),
    }
}

/// KDC options from a big-endian bit mask.
fn kdc_options_from_bits(bits: u32) -> rasn_kerberos::KdcOptions {
    rasn_kerberos::KdcOptions(rasn_kerberos::KerberosFlags::from_slice(
        &bits.to_be_bytes(),
    ))
}

/// Request option bits, with `renewable` set when a renew lifetime is
/// requested.
const fn request_kdc_option_bits(bits: u32, renew_lifetime: Option<Duration>) -> u32 {
    if renew_lifetime.is_some() {
        bits | KDC_OPTION_RENEWABLE
    } else {
        bits
    }
}

/// Option bits for a renewal request: `renewable` and `renew` set.
const fn renewal_kdc_option_bits(bits: u32) -> u32 {
    bits | KDC_OPTION_RENEWABLE | KDC_OPTION_RENEW
}

/// The first four bytes of the ticket flags, zero-padded.
fn ticket_flags_to_bytes(flags: &rasn_kerberos::TicketFlags) -> [u8; 4] {
    let raw = flags.0.as_raw_slice();
    [
        raw.first().copied().unwrap_or_default(),
        raw.get(1).copied().unwrap_or_default(),
        raw.get(2).copied().unwrap_or_default(),
        raw.get(3).copied().unwrap_or_default(),
    ]
}

/// Convert a client principal to a ccache principal.
fn ccache_principal(value: &Principal) -> ccache::Principal {
    ccache::Principal::new(
        value.realm.clone(),
        value.name_type,
        value.components.clone(),
    )
}

/// `default_ccache_name` from the configuration.
///
/// # Errors
///
/// Returns [`Error::NoDefaultCCacheName`] when it is empty.
#[cfg(feature = "tokio")]
fn configured_default_ccache_name(config: &Config) -> Result<String, Error> {
    let cache_name =
        credential_names::resolve_credential_template(&config.libdefaults, DefaultName::Ccache)
            .map_err(error::Ccache::Expansion)?;
    if cache_name.is_empty() {
        return Err(Error::NoDefaultCCacheName);
    }
    Ok(cache_name)
}

/// The default ccache name: `KRB5CCNAME` when set, else the configured
/// `default_ccache_name`.
///
/// # Ambient input
/// Reads `KRB5CCNAME` before the configured cache name.
///
/// # Errors
///
/// Returns [`Error::CCache`] when `KRB5CCNAME` is not valid Unicode and
/// [`Error::NoDefaultCCacheName`] when neither source names a cache.
#[cfg(feature = "tokio")]
fn default_ccache_name(config: &Config) -> Result<String, Error> {
    match env::var(KRB5CCNAME_ENV) {
        Ok(cache_name) => file_name::expand_path_tokens(&cache_name)
            .map_err(|_source| error::Ccache::IdentityUnavailable.into()),
        Err(env::VarError::NotPresent) => configured_default_ccache_name(config),
        Err(error) => Err(error::Ccache::DefaultCacheName(error).into()),
    }
}

/// The default client keytab name: `KRB5_CLIENT_KTNAME` when set, else the
/// configured `default_client_keytab_name`.
///
/// # Ambient input
/// Reads `KRB5_CLIENT_KTNAME` before the configured client-keytab name.
///
/// # Errors
///
/// Returns [`Error::DefaultClientKeytabName`] when `KRB5_CLIENT_KTNAME` is not
/// valid Unicode.
#[cfg(feature = "tokio")]
fn default_client_keytab_name(config: &Config) -> Result<Keytab, Error> {
    match env::var(KRB5_CLIENT_KTNAME_ENV) {
        Ok(keytab_name) => Ok(Keytab::load_name(keytab_name)?),
        Err(env::VarError::NotPresent) => Ok(configured_keytab(
            &config.libdefaults,
            DefaultName::ClientKeytab,
        )?),
        Err(error) => Err(Error::DefaultClientKeytabName(error)),
    }
}

/// Whether two ccache principals have the same realm and components.
#[cfg(feature = "tokio")]
fn same_ccache_client_identity(left: &ccache::Principal, right: &ccache::Principal) -> bool {
    left.realm == right.realm && left.components == right.components
}

/// Convert a ccache principal to a client principal.
#[cfg(feature = "tokio")]
fn client_principal_from_ccache(value: &ccache::Principal) -> Principal {
    Principal::new(
        value.realm.clone(),
        value.name_type,
        value.components.clone(),
    )
}

/// A session from a ccache credential; a zero start time falls back to the
/// authentication time.
#[cfg(feature = "tokio")]
fn ccache_credential_session(credential: &ccache::Credential) -> AsRepSession {
    let auth_time = system_time_from_u32_seconds(credential.times.auth_time);
    let start_time = if credential.times.start_time == 0 {
        auth_time
    } else {
        system_time_from_u32_seconds(credential.times.start_time)
    };
    AsRepSession {
        client: client_principal_from_ccache(&credential.client),
        service: client_principal_from_ccache(&credential.server),
        session_key: EncryptionKey {
            etype: credential.key.etype,
            value: credential.key.value.clone(),
        },
        ticket: credential.ticket.clone(),
        ticket_flags: credential.ticket_flags,
        auth_time,
        start_time,
        end_time: system_time_from_u32_seconds(credential.times.end_time),
        renew_till: (credential.times.renew_till != 0)
            .then(|| system_time_from_u32_seconds(credential.times.renew_till)),
        key_expiration: None,
    }
}

/// A `SystemTime` from ccache seconds since the Unix epoch.
#[cfg(feature = "tokio")]
fn system_time_from_u32_seconds(seconds: u32) -> SystemTime {
    // Every u32 second count (up to 2106) is representable as a `SystemTime`
    // on the supported platforms; the epoch fallback is unreachable.
    UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds.into()))
        .unwrap_or(UNIX_EPOCH)
}

/// The better of an existing and a candidate session at `now`.
#[cfg(feature = "tokio")]
fn preferred_session_at(
    current: Option<AsRepSession>,
    candidate: AsRepSession,
    now: SystemTime,
) -> AsRepSession {
    match current {
        Some(existing) if prefer_current_session_at(&existing, &candidate, now) => existing,
        _ => candidate,
    }
}

/// Whether `current` beats `candidate` at `now`: a valid session wins, and
/// otherwise the later end time wins (ties keep `current`).
#[cfg(feature = "tokio")]
fn prefer_current_session_at(
    current: &AsRepSession,
    candidate: &AsRepSession,
    now: SystemTime,
) -> bool {
    match (
        session_valid_at(current, now),
        session_valid_at(candidate, now),
    ) {
        (true, false) => true,
        (false, true) => false,
        _ => current.end_time >= candidate.end_time,
    }
}

/// Service identity keeps realm/component boundaries; name type is advisory.
#[cfg(feature = "tokio")]
fn service_cache_key(service: &Principal) -> (String, Vec<String>) {
    (service.realm.clone(), service.components.clone())
}

/// Whether a session is inside its start and end time at `now`.
#[cfg(feature = "tokio")]
fn session_valid_at(session: &AsRepSession, now: SystemTime) -> bool {
    u32::from_be_bytes(session.ticket_flags) & TICKET_FLAG_INVALID == 0
        && session.start_time <= now
        && now < session.end_time
}

/// Convert a Kerberos time to a `SystemTime`.
///
/// # Errors
///
/// Returns [`Error::TimeOverflow`] for fractions or times outside `SystemTime` range.
fn system_time_from_kerberos_time(time: &rasn_kerberos::KerberosTime) -> Result<SystemTime, Error> {
    time::from_kerberos(time).ok_or(Error::TimeOverflow)
}

/// Convert a `SystemTime` to a Kerberos time, truncated to whole seconds.
///
/// # Errors
///
/// Returns [`Error::TimeOverflow`] when the time is out of Kerberos time range.
fn kerberos_time_from_system_time(time: SystemTime) -> Result<rasn_kerberos::KerberosTime, Error> {
    let (seconds, _) = unix_timestamp_parts(time)?;
    let utc =
        chrono::DateTime::<chrono::Utc>::from_timestamp(seconds, 0).ok_or(Error::TimeOverflow)?;
    let offset = chrono::FixedOffset::east_opt(0).ok_or(Error::TimeOverflow)?;
    Ok(rasn_kerberos::KerberosTime(utc.with_timezone(&offset)))
}

/// Convert an ASN.1 integer to `u32`, naming `field` in the error.
///
/// # Errors
///
/// Returns [`Error::InvalidUnsignedInteger`] when the value does not fit.
fn integer_to_u32(field: &'static str, value: &Integer) -> Result<u32, Error> {
    value
        .to_string()
        .parse::<u32>()
        .map_err(|_out_of_range| Error::InvalidUnsignedInteger {
            field,
            actual: value.to_string(),
        })
}

/// Seconds and non-negative nanoseconds relative to the Unix epoch; times before
/// the epoch round the seconds down.
///
/// # Errors
///
/// Returns [`Error::TimeOverflow`] when the seconds do not fit `i64`.
fn unix_timestamp_parts(time: SystemTime) -> Result<(i64, u32), Error> {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => Ok((
            duration
                .as_secs()
                .try_into()
                .map_err(|_out_of_range| Error::TimeOverflow)?,
            duration.subsec_nanos(),
        )),
        Err(source) => {
            let duration = source.duration();
            let seconds: i64 = duration
                .as_secs()
                .try_into()
                .map_err(|_out_of_range| Error::TimeOverflow)?;
            if duration.subsec_nanos() == 0 {
                return Ok((seconds.checked_neg().ok_or(Error::TimeOverflow)?, 0));
            }

            // Round the whole seconds away from the epoch and express the
            // remainder as a non-negative nanosecond offset; `subsec_nanos`
            // is below one billion, so the subtraction cannot fail.
            let rounded = seconds
                .checked_add(1)
                .and_then(i64::checked_neg)
                .ok_or(Error::TimeOverflow)?;
            let nanos = 1_000_000_000_u32
                .checked_sub(duration.subsec_nanos())
                .ok_or(Error::TimeOverflow)?;
            Ok((rounded, nanos))
        }
    }
}

/// Whole seconds since the Unix epoch as `u32`.
///
/// # Errors
///
/// Returns [`Error::TimeOverflow`] for times before the epoch, with a fractional
/// second, or after 2106.
fn system_time_to_u32_seconds(time: SystemTime) -> Result<u32, Error> {
    let (seconds, nanos) = unix_timestamp_parts(time)?;
    if seconds < 0 || nanos != 0 {
        return Err(Error::TimeOverflow);
    }
    seconds
        .try_into()
        .map_err(|_out_of_range| Error::TimeOverflow)
}

/// Unit tests for the fork's public request-building helpers.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    #[cfg(feature = "tokio")]
    mod realm_mutations;
    use core::time::Duration;
    use std::time::UNIX_EPOCH;

    use super::{
        AsRepSession, EncryptionKey, Error, PA_AS_FRESHNESS, PA_FX_COOKIE, Principal, SystemTime,
        TgsReq, build_tgs_req_for_realm_with_confounder_and_subkey,
        build_tgs_req_for_realm_with_subkey, random_nonce,
    };
    use crate::error;
    #[cfg(feature = "tokio")]
    use crate::{ccache::Principal as CachePrincipal, kadmin::Request as PasswordRequest, ticket};

    // RFC 6113 section 5.2 registers PA-FX-COOKIE as 133, and RFC 8070
    // registers PA-AS-FRESHNESS as 150.
    const _: () = assert!(
        PA_FX_COOKIE == 133 && PA_AS_FRESHNESS == 150,
        "the FAST padata constants must match their IANA registrations"
    );

    /// A TGT session for `client@EXAMPLE.TEST` holding `session_key`. Its ticket
    /// is empty: the validation paths pinned here run before any ticket decode.
    fn session_with_key(session_key: EncryptionKey) -> Result<AsRepSession, Error> {
        let now = SystemTime::now();
        Ok(AsRepSession {
            client: Principal::parse_user("client@EXAMPLE.TEST")?,
            service: Principal::parse_service("krbtgt/EXAMPLE.TEST@EXAMPLE.TEST")?,
            session_key,
            ticket: Vec::new().into(),
            ticket_flags: [0_u8; 4],
            auth_time: now,
            start_time: now,
            end_time: now,
            renew_till: None,
            key_expiration: None,
        })
    }

    /// Validity excludes future, expired and INVALID sessions at exact boundaries.
    #[cfg(feature = "tokio")]
    #[test]
    fn session_validity_boundaries() -> Result<(), Error> {
        let mut session = session_with_key(EncryptionKey::new(18, vec![0; 32]))?;
        let now = UNIX_EPOCH + Duration::from_secs(100);
        session.auth_time = now;
        session.start_time = now;
        session.end_time = now + Duration::from_secs(1);
        for (start, end, flags, expected) in [
            (100_u64, 101_u64, 0_u32, true),
            (101, 102, 0, false),
            (99, 100, 0, false),
            (99, 101, 0x0100_0000, false),
        ] {
            session.start_time = UNIX_EPOCH + Duration::from_secs(start);
            session.end_time = UNIX_EPOCH + Duration::from_secs(end);
            session.ticket_flags = flags.to_be_bytes();
            assert_eq!(super::session_valid_at(&session, now), expected);
        }
        Ok(())
    }

    /// A valid shorter candidate beats an invalid longer cached session.
    #[cfg(feature = "tokio")]
    #[test]
    fn valid_candidate_beats_longer_invalid_session() -> Result<(), Error> {
        let mut existing = session_with_key(EncryptionKey::new(18, vec![0; 32]))?;
        let now = UNIX_EPOCH + Duration::from_secs(100);
        existing.start_time = now;
        existing.end_time = now + Duration::from_secs(100);
        existing.ticket_flags = 0x0100_0000_u32.to_be_bytes();
        let mut candidate = existing.clone();
        candidate.ticket_flags = [0; 4];
        candidate.end_time = now + Duration::from_secs(1);
        assert!(!super::prefer_current_session_at(
            &existing, &candidate, now
        ));
        Ok(())
    }

    /// Renewal options retain bits that the caller already set.
    #[test]
    fn renewal_options_are_idempotent() {
        assert_eq!(super::renewal_kdc_option_bits(0x0080_0002), 0x0080_0002);
    }

    /// Explicit enctype allowlists reject omitted algorithms, including an empty list.
    #[cfg(feature = "tokio")]
    #[test]
    fn permitted_enctype_requires_membership() -> Result<(), Error> {
        super::ensure_permitted_enctype(&[18_i32], 18_i32)?;
        for permitted in [&[][..], &[17_i32][..]] {
            assert!(matches!(
                super::ensure_permitted_enctype(permitted, 18),
                Err(Error::EnctypeNotPermitted(18_i32))
            ));
        }
        Ok(())
    }

    /// Flag membership requires every requested bit rather than any nonempty mask.
    #[test]
    fn ticket_flag_membership_requires_all_bits() {
        assert!(!super::ticket_flags_contain_bits(
            &rasn_kerberos::TicketFlags(rasn_kerberos::KerberosFlags::from_slice(&[0; 4])),
            0x4000_0000
        ));
        assert!(!super::ticket_flags_contain_bits(
            &rasn_kerberos::TicketFlags(rasn_kerberos::KerberosFlags::from_slice(
                &0x4000_0000_u32.to_be_bytes()
            )),
            0x5000_0000
        ));
        assert!(super::ticket_flags_contain_bits(
            &rasn_kerberos::TicketFlags(rasn_kerberos::KerberosFlags::from_slice(
                &0x5000_0000_u32.to_be_bytes()
            )),
            0x4000_0000
        ));
    }

    /// Draft-9 padata policy rejects explicit legacy selections at its shared boundary.
    #[test]
    fn padata_policy_rejects_draft9() {
        assert!(
            super::crypto_policy::padata(&[rasn_kerberos::PaData {
                r#type: 14,
                value: vec![].into()
            }])
            .is_err()
        );
    }

    /// Principal matching rejects foreign realms and components while ignoring name type.
    #[test]
    fn principal_matching_preserves_identity() -> Result<(), Error> {
        let client = Principal::parse_user("user@A")?;
        assert!(super::principal_matches(
            &client,
            &Principal::new("A", 2, ["user"])
        ));
        assert!(!super::principal_matches(
            &client,
            &Principal::new("B", 1, ["user"])
        ));
        assert!(!super::principal_matches(
            &client,
            &Principal::new("A", 1, ["other"])
        ));
        Ok(())
    }

    /// Invalid principal diagnostics distinguish missing and repeated realm separators.
    #[test]
    fn principal_separator_reasons_are_specific() -> Result<(), Error> {
        drop(Principal::parse_user("user@A")?);
        for (input, expected) in [
            ("user", "principal realm separator is missing"),
            (
                "u@A@B",
                "principal contains more than one unescaped realm separator",
            ),
        ] {
            assert!(
                matches!(Principal::parse_user(input), Err(Error::InvalidPrincipalName { value, reason }) if value == input && reason == expected)
            );
        }
        Ok(())
    }

    /// Ticket flag conversion retains wire bytes and zero-pads short bitstrings.
    #[test]
    fn ticket_flag_conversion_preserves_bytes() {
        assert_eq!(
            super::ticket_flags_to_bytes(&rasn_kerberos::TicketFlags(
                rasn_kerberos::KerberosFlags::from_slice(&[0x40, 0x80])
            )),
            [0x40, 0x80, 0, 0]
        );
    }

    /// Cache-only due TGT renewal preserves its discovery failure before service lookup.
    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn due_tgt_renewal_error_is_preserved() -> Result<(), Error> {
        let mut session = session_with_key(EncryptionKey::new(18, vec![0; 32]))?;
        session.ticket = ticket::encode(
            &PasswordRequest::parse(
                &hex::decode(include_str!("../tests/fixtures/kpasswd-request.hex").trim())
                    .map_err(|error| Error::Transport(error.to_string()))?,
            )?
            .ap_req
            .ticket,
        )
        .map_err(|error| Error::Transport(error.to_string()))?
        .into();
        let mut wire = ticket::decode(&session.ticket).map_err(super::ticket_error)?;
        wire.realm = super::kerberos_string(&session.service.realm)?;
        wire.sname = super::principal_to_rasn(&session.service)?;
        session.ticket = ticket::encode(&wire).map_err(super::ticket_error)?.into();
        let now = SystemTime::now();
        session.auth_time = now - Duration::from_secs(55);
        session.start_time = session.auth_time;
        session.end_time = now + Duration::from_secs(5);
        session.renew_till = Some(now + Duration::from_secs(60));
        session.ticket_flags = super::KDC_OPTION_RENEWABLE.to_be_bytes();
        let config = super::Config::parse(
            "[libdefaults]\ndns_lookup_kdc = false\n[realms]\nEXAMPLE.TEST = {\n}\n",
        )?;
        let mut client = super::Tokio::new(
            config,
            super::transport::KdcProtocol::Tcp,
            session.client.clone(),
            None,
        );
        client.tgt = Some(session);
        let result = client.ensure_tgt().await;
        assert!(
            matches!(
                result,
                Err(Error::NoKdcEndpoints {
                    realm: _,
                    protocol: _
                })
            ),
            "renewal failure must not become reuse"
        );
        Ok(())
    }

    /// Realm cache lookup returns the matching live TGT rather than forcing fresh login.
    #[cfg(feature = "tokio")]
    #[test]
    fn realm_cache_lookup_returns_live_ticket() -> Result<(), Error> {
        let mut session = session_with_key(EncryptionKey::new(18, vec![0; 32]))?;
        session.end_time = SystemTime::now() + Duration::from_secs(60);
        let mut client = super::Tokio::from_tgt_session(
            super::Config::new(),
            super::transport::KdcProtocol::Tcp,
            session.clone(),
        );
        drop(
            client
                .tgt_sessions
                .insert("EXAMPLE.TEST".to_owned(), session.clone()),
        );
        assert_eq!(
            client.cached_tgt_session_for_realm("EXAMPLE.TEST", SystemTime::now()),
            Some(session)
        );
        Ok(())
    }

    /// Partial prune reports are nonempty when any cache lost a session.
    #[cfg(feature = "tokio")]
    #[test]
    fn prune_reports_each_nonempty_field() {
        assert!(
            !super::PrunedSessions::default()
                .with_tgt_sessions(1)
                .is_empty(),
            "realm TGT removals make report nonempty"
        );
        assert!(
            !super::PrunedSessions::default()
                .with_service_tickets(1)
                .is_empty(),
            "service removals make report nonempty"
        );
        assert!(
            !super::PrunedSessions::default()
                .with_primary_tgt(true)
                .is_empty(),
            "primary removal makes report nonempty"
        );
    }

    /// Public login settings reflect the configured opt-in and opt-out values.
    #[cfg(feature = "tokio")]
    #[test]
    fn login_setting_queries_preserve_both_values() -> Result<(), Error> {
        for enabled in [false, true] {
            let client = super::Tokio::with_password(
                super::Config::new(),
                super::transport::KdcProtocol::Tcp,
                Principal::parse_user("user@A")?,
                b"password".to_vec(),
            )
            .with_assume_preauthentication(enabled)
            .with_fast_negotiation(enabled);
            assert_eq!(client.assume_preauthentication(), enabled);
            assert_eq!(client.fast_negotiation(), enabled);
        }
        Ok(())
    }

    /// Cache identity compares realm and ordered components independently.
    #[cfg(feature = "tokio")]
    #[test]
    fn ccache_identity_requires_both_coordinates() {
        assert!(!super::same_ccache_client_identity(
            &CachePrincipal::new("A", 1, vec!["user".to_owned()]),
            &CachePrincipal::new("B", 1, vec!["user".to_owned()])
        ));
        assert!(!super::same_ccache_client_identity(
            &CachePrincipal::new("A", 1, vec!["user".to_owned()]),
            &CachePrincipal::new("A", 1, vec!["other".to_owned()])
        ));
    }

    /// Whole-second cache timestamps include the epoch but reject pre-epoch values.
    #[test]
    fn cache_timestamp_epoch_boundaries() -> Result<(), Error> {
        assert_eq!(super::system_time_to_u32_seconds(UNIX_EPOCH)?, 0);
        assert_eq!(
            super::system_time_to_u32_seconds(UNIX_EPOCH + Duration::from_secs(1))?,
            1
        );
        assert!(matches!(
            super::system_time_to_u32_seconds(UNIX_EPOCH - Duration::from_secs(1)),
            Err(Error::TimeOverflow)
        ));
        Ok(())
    }

    /// The request nonce keeps its top bit clear, so peers that decode it as a
    /// signed 32-bit integer still see a positive value.
    #[test]
    fn random_nonce_keeps_the_sign_bit_clear() -> Result<(), Error> {
        let nonce = random_nonce()?;
        assert_eq!(nonce & 0x8000_0000, 0, "the nonce's top bit must be clear");
        Ok(())
    }

    /// A subkey in another enctype than the TGT session key's is refused before
    /// any request is built.
    #[test]
    fn explicit_subkey_of_another_enctype_is_refused() -> Result<(), Error> {
        let tgt = session_with_key(EncryptionKey {
            etype: 18,
            value: vec![0x11; 32],
        })?;
        let subkey = EncryptionKey {
            etype: 17,
            value: vec![0x22; 16],
        };
        let now = SystemTime::now();
        let result = build_tgs_req_for_realm_with_confounder_and_subkey(
            &tgt,
            "EXAMPLE.TEST",
            Principal::parse_service("HTTP/host.example.test@EXAMPLE.TEST")?,
            crate::client::TgsRequestParts::new(TgsReq::new(now, 1), &[], &subkey)
                .with_timestamp(now, 0),
        );
        assert!(
            matches!(
                result,
                Err(Error::ApReqKeyEtypeMismatch {
                    key_etype: 17_i32,
                    encrypted_data_etype: 18_i32,
                })
            ),
            "a subkey of another enctype must be an enctype mismatch"
        );
        Ok(())
    }

    /// A subkey of the right enctype but the wrong length is refused before any
    /// request is built.
    #[test]
    fn explicit_subkey_of_another_length_is_refused() -> Result<(), Error> {
        let tgt = session_with_key(EncryptionKey {
            etype: 18,
            value: vec![0x11; 32],
        })?;
        let subkey = EncryptionKey {
            etype: 18,
            value: vec![0x22; 16],
        };
        let now = SystemTime::now();
        let result = build_tgs_req_for_realm_with_confounder_and_subkey(
            &tgt,
            "EXAMPLE.TEST",
            Principal::parse_service("HTTP/host.example.test@EXAMPLE.TEST")?,
            crate::client::TgsRequestParts::new(TgsReq::new(now, 1), &[], &subkey)
                .with_timestamp(now, 0),
        );
        assert!(
            matches!(
                result,
                Err(Error::Crypto(error::Crypto::InvalidKeyLength {
                    expected: 32,
                    actual: 16,
                }))
            ),
            "a subkey of another length must be an invalid key length"
        );
        Ok(())
    }

    /// The generated-subkey builder refuses a TGT whose session key enctype has
    /// no confounder profile, before drawing any random bytes for it.
    #[test]
    fn generated_subkey_needs_a_supported_session_key_enctype() -> Result<(), Error> {
        use crate::error::{Policy, RejectedFeature};
        let tgt = session_with_key(EncryptionKey {
            etype: 1,
            value: vec![0x11; 8],
        })?;
        let result = build_tgs_req_for_realm_with_subkey(
            &tgt,
            "EXAMPLE.TEST",
            Principal::parse_service("HTTP/host.example.test@EXAMPLE.TEST")?,
            TgsReq::new(SystemTime::now(), 1),
        );
        assert!(
            matches!(
                result,
                Err(Error::Crypto(error::Crypto::Policy(
                    Policy::RejectedFeature {
                        feature: RejectedFeature::SingleDes,
                        reason: _
                    }
                )))
            ),
            "single DES is rejected by policy before random generation"
        );
        Ok(())
    }
}

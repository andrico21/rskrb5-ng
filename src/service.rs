//! AP-REQ service-side validation.
//!
//! This module validates Kerberos AP-REQ messages by decoding the request,
//! decrypting the service ticket from a keytab, decrypting the authenticator
//! with the ticket session key, and enforcing the core identity, ticket-time,
//! clock-skew, address, and replay checks from gokrb5's service tests. It also
//! builds and verifies AP-REP mutual-auth replies using the AP-REQ
//! authenticator timestamp.

use alloc::{borrow::Cow, collections::BTreeSet, sync::Arc};
use core::{fmt::Debug, str::from_utf8, time::Duration};
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{SystemTime, SystemTimeError, UNIX_EPOCH},
};

use rasn::types::Integer;

use crate::{
    ap_rep,
    config::{Config, parameters::DefaultName, restrictions},
    crypto::{CryptoPolicy, Use},
    der::decode_complete,
    error,
    keytab::{self, EncryptionKey, Keytab},
    pac::{self, Pac},
};

/// Default AP-REQ acceptance window: five minutes, MIT's default `clockskew`.
const DEFAULT_MAX_CLOCK_SKEW: Duration = Duration::from_mins(5);
/// Bit index of the `invalid` ticket flag (RFC 4120 section 5.3).
const INVALID_TICKET_FLAG: usize = 7;

/// Kerberos principal identity.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub struct Principal {
    /// Principal realm.
    pub realm: String,
    /// Kerberos name type. Name type is advisory and is not used for matching.
    pub name_type: i32,
    /// Principal name components.
    pub components: Vec<String>,
}

impl Principal {
    /// Creates a `Principal` from its required fields.
    #[must_use]
    #[inline]
    pub const fn new(realm: String, name_type: i32, components: Vec<String>) -> Self {
        Self {
            realm,
            name_type,
            components,
        }
    }

    #[must_use]
    /// Principal components joined by `/`.
    #[inline]
    pub fn name(&self) -> String {
        self.components.join("/")
    }
}

/// Host address used for optional ticket address validation.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct HostAddress {
    /// Kerberos host address type.
    pub addr_type: i32,
    /// Raw address bytes.
    pub address: Vec<u8>,
}

mod host_address;

/// Successful AP-REQ validation result.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ValidatedApReq {
    /// Effective policy retained for outgoing context keys.
    pub crypto_policy: CryptoPolicy,
    /// Client identity from the KDC-authenticated ticket.
    pub client: Principal,
    /// Realm and components matched by the keytab lookup that decrypted the ticket.
    /// The name type remains advisory ticket metadata, not an authenticated identity.
    pub service: Principal,
    /// Ticket session key used to decrypt the authenticator.
    pub session_key: EncryptionKey,
    /// Optional subkey supplied by the client authenticator.
    pub subkey: Option<EncryptionKey>,
    /// Optional sequence number supplied by the client authenticator.
    pub sequence_number: Option<u32>,
    /// Ticket start time, or auth time when start time is absent.
    pub ticket_start: SystemTime,
    /// Ticket end time.
    pub ticket_end: SystemTime,
    /// Authenticator `ctime` without `cusec`.
    pub authenticator_ctime: SystemTime,
    /// Authenticator microsecond field.
    pub authenticator_cusec: u32,
    /// Authenticator timestamp including `cusec`.
    pub authenticator_time: SystemTime,
    /// Verified PAC from the ticket authorization data, when present.
    pub pac: Option<Pac>,
}

impl ValidatedApReq {
    /// Build an AP-REP mutual-auth reply with an explicit confounder.
    ///
    /// The explicit confounder keeps tests deterministic and lets callers
    /// choose their own randomness policy. The AP-REP encrypted part is
    /// encrypted with the ticket session key using key usage 12.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TimeOverflow`] when the authenticator time is not a
    /// representable Kerberos time, and an encoding, crypto or key-type error
    /// when the AP-REP cannot be encrypted or encoded.
    #[inline]
    pub fn build_ap_rep_with_confounder(
        &self,
        confounder: &[u8],
        options: &ApRepOptions,
    ) -> Result<Vec<u8>, Error> {
        self.crypto_policy
            .check_use(self.session_key.etype, Use::SessionKey)?;
        if let Some(subkey) = &options.subkey {
            self.crypto_policy
                .check_use(subkey.etype, Use::AcceptorSubkey)?;
        }
        let cusec = microseconds_to_u32(
            "authenticator.cusec",
            &Integer::from(self.authenticator_cusec),
        )?;
        let enc_part = rasn_kerberos::EncApRepPart {
            ctime: kerberos_time_from_system_time(self.authenticator_ctime)?,
            cusec: Integer::from(cusec),
            subkey: options.subkey.as_ref().map(encryption_key_to_rasn),
            seq_number: options.sequence_number,
        };
        let ap_rep = ap_rep::build_ap_rep_with_confounder(
            &enc_part,
            &self.session_key,
            options.kvno,
            confounder,
        )
        .map_err(ap_rep_error)?;
        ap_rep::encode(&ap_rep).map_err(ap_rep_error)
    }

    /// Verify an AP-REP mutual-auth reply against this AP-REQ.
    ///
    /// The reply must use the same client timestamp from the AP-REQ
    /// authenticator. A verified AP-REP may carry a server-selected subkey and
    /// sequence number.
    ///
    /// # Errors
    ///
    /// Returns a decode, crypto or key-type error when the reply cannot be
    /// decoded or decrypted with the session key, a time or integer error when
    /// its timestamp is out of range, and [`Error::ApRepTimestampMismatch`]
    /// when its timestamp differs from the AP-REQ authenticator's.
    #[inline]
    pub fn verify_ap_rep(&self, bytes: &[u8]) -> Result<VerifiedApRep, Error> {
        self.crypto_policy
            .check_use(self.session_key.etype, Use::SessionKey)?;
        let ap_rep = ap_rep::decode(bytes).map_err(ap_rep_error)?;
        self.crypto_policy
            .check_use(ap_rep.enc_part.etype, Use::SessionKey)?;
        let enc_part =
            ap_rep::decrypt_ap_rep_enc_part(&ap_rep, &self.session_key).map_err(ap_rep_error)?;
        if let Some(subkey) = &enc_part.subkey {
            self.crypto_policy
                .check_use(subkey.r#type, Use::AcceptorSubkey)?;
        }
        let ctime = system_time_from_kerberos_time(&enc_part.ctime)?;
        let cusec = microseconds_to_u32("ap-rep.cusec", &enc_part.cusec)?;
        let authenticator_time = ctime
            .checked_add(Duration::from_micros(cusec.into()))
            .ok_or(Error::TimeOverflow)?;

        if ctime != self.authenticator_ctime || cusec != self.authenticator_cusec {
            return Err(Error::ApRepTimestampMismatch {
                expected: self.authenticator_time,
                actual: authenticator_time,
            });
        }

        Ok(VerifiedApRep {
            ctime,
            cusec,
            authenticator_time,
            subkey: enc_part.subkey.as_ref().map(encryption_key_from_rasn),
            sequence_number: enc_part.seq_number,
        })
    }
}

/// Options for constructing an AP-REP mutual-auth reply.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct ApRepOptions {
    /// Optional server-selected subkey.
    pub subkey: Option<EncryptionKey>,
    /// Optional server sequence number.
    pub sequence_number: Option<u32>,
    /// Optional encrypted-data key version number.
    pub kvno: Option<u32>,
}

impl ApRepOptions {
    /// Sets `subkey`, preserving the other fields.
    #[must_use]
    #[inline]
    pub fn with_subkey(mut self, value: Option<EncryptionKey>) -> Self {
        self.subkey = value;
        self
    }
    /// Sets `sequence_number`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_sequence_number(mut self, value: Option<u32>) -> Self {
        self.sequence_number = value;
        self
    }
    /// Sets `kvno`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_kvno(mut self, value: Option<u32>) -> Self {
        self.kvno = value;
        self
    }
}

/// Verified AP-REP mutual-auth reply.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct VerifiedApRep {
    /// Reply `ctime` without `cusec`.
    pub ctime: SystemTime,
    /// Reply microsecond field.
    pub cusec: u32,
    /// Reply timestamp including `cusec`.
    pub authenticator_time: SystemTime,
    /// Optional server-selected subkey.
    pub subkey: Option<EncryptionKey>,
    /// Optional server sequence number.
    pub sequence_number: Option<u32>,
}

/// In-memory AP-REQ replay cache.
///
/// Size total capacity for peak admission rate times three times the maximum
/// clock skew, with headroom for bursts and replay refreshes. Each live record
/// occupies paired key, digest and expiry indexes. Capacity exhaustion rejects
/// new records, never evicts live replay evidence. The default total is 65,536;
/// each client realm/components identity gets one eighth (minimum one), tunable
/// with [`Self::with_principal_capacity`]. Size both limits for expected traffic.
#[derive(Debug)]
pub struct ReplayCache {
    /// Immutable skew ceiling for every validator using this cache.
    max_clock_skew: Duration,
    /// Maximum live records; admission never evicts a live replay record.
    capacity: usize,
    /// Per-client admission accounting, independent of service aliases.
    principal_quota: replay_quota::PrincipalQuota,
    /// Highest admission time, preserved even by explicit clearing.
    watermark: Option<SystemTime>,
    /// RFC 4120 replay keys of the accepted authenticators, each with the digest
    /// admitted with it; the pair shares one last-seen record in `authenticators`.
    entries: HashMap<Arc<ReplayKey>, [u8; 32]>,
    /// SHA-256 digests of the accepted authenticator ciphertexts, each with its
    /// key and the watermark when the pair was last seen, so a re-presented
    /// authenticator is a replay whatever cleartext ticket field was rewritten
    /// around it. Keys and digests pair one to one.
    authenticators: HashMap<[u8; 32], DigestRecord>,
    /// Ordered last-seen times, with the unique digest breaking ties.
    expiry: BTreeSet<(SystemTime, [u8; 32])>,
}

/// The digest-index record of one admitted key and digest pair.
#[derive(Debug)]
struct DigestRecord {
    /// Watermark when the pair was last seen.
    last_seen: SystemTime,
    /// The replay key admitted with the digest, so expiry removes the pair
    /// without scanning the key index.
    key: Arc<ReplayKey>,
}

mod replay;
mod replay_quota;
mod ticket_pac;
mod validation;

use ticket_pac::verified_ticket_pac;

/// Shareable in-memory AP-REQ replay cache.
///
/// This is useful when a service framework clones middleware or builds several
/// service instances from the same acceptor state.
/// Size the underlying [`ReplayCache`] for aggregate peak admission rate across
/// all clones over the three-skew retention window, including burst headroom.
/// Principal quotas and the global limit fail closed without evicting evidence.
#[derive(Clone, Debug, Default)]
pub struct SharedReplayCache {
    /// The cache shared by every clone.
    inner: Arc<Mutex<ReplayCache>>,
}

impl SharedReplayCache {
    /// Verify a validator's window under the cache lock.
    ///
    /// # Errors
    ///
    /// Returns a poisoned-lock or incompatible-skew error.
    pub(crate) fn ensure_skew(&self, requested: Duration) -> Result<(), Error> {
        self.with_cache(|cache| cache.ensure_skew(requested))?
    }

    /// Configure an internally owned shared cache before its first admission.
    ///
    /// # Errors
    ///
    /// Returns a poisoned-lock error or refuses an increase after admission.
    #[cfg(feature = "tower")]
    pub(crate) fn configure_owned_skew(&self, requested: Duration) -> Result<(), Error> {
        self.with_cache_mut(|cache| cache.configure_owned_skew(requested))?
    }
    /// Safely prune expired pairs while holding the shared admission lock.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ReplayCachePoisoned`] if the cache lock is poisoned.
    #[inline]
    pub fn prune_expired(&self) -> Result<usize, Error> {
        self.with_cache_mut(ReplayCache::prune_expired)
    }

    /// Safely prune at `min(now, admission watermark)` across every clone.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ReplayCachePoisoned`] if the cache lock is poisoned.
    #[inline]
    pub fn prune_expired_at(&self, now: SystemTime) -> Result<usize, Error> {
        self.with_cache_mut(|cache| cache.prune_expired_at(now))
    }

    #[must_use]
    /// Create an empty shared replay cache.
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    /// Create a shared replay cache from an existing in-memory cache.
    #[inline]
    pub fn from_cache(cache: ReplayCache) -> Self {
        Self {
            inner: Arc::new(Mutex::new(cache)),
        }
    }

    /// Remove all cached replay entries.
    ///
    /// # Security
    ///
    /// Clearing reopens replay protection across every clone. Prefer safe pruning.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ReplayCachePoisoned`] when the lock is poisoned.
    #[inline]
    pub fn clear(&self) -> Result<(), Error> {
        self.with_cache_mut(ReplayCache::clear)
    }

    /// Number of cached replay entries.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ReplayCachePoisoned`] when the lock is poisoned.
    #[inline]
    pub fn len(&self) -> Result<usize, Error> {
        self.with_cache(ReplayCache::len)
    }

    /// Whether the replay cache is empty.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ReplayCachePoisoned`] when the lock is poisoned.
    #[inline]
    pub fn is_empty(&self) -> Result<bool, Error> {
        self.with_cache(ReplayCache::is_empty)
    }

    /// Remove entries last seen more than `max_age` ago.
    ///
    /// Entries are aged by the watermark at which they were last seen, not by
    /// the clock sample of their presentation.
    ///
    /// # Security
    ///
    /// Arbitrary ages reopen replay protection across every clone.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ReplayCachePoisoned`] when the lock is poisoned.
    #[inline]
    pub fn force_clear_older_than(&self, max_age: Duration) -> Result<usize, Error> {
        self.with_cache_mut(|cache| cache.force_clear_older_than(max_age))
    }

    /// Remove entries last seen more than `max_age` before `now`.
    ///
    /// Entries are aged by the watermark at which they were last seen, not by
    /// the clock sample of their presentation. A replay key and its
    /// authenticator digest are removed together.
    ///
    /// # Security
    ///
    /// Arbitrary ages or future samples reopen replay protection across every clone.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ReplayCachePoisoned`] when the lock is poisoned.
    #[inline]
    pub fn force_clear_older_than_at(
        &self,
        max_age: Duration,
        now: SystemTime,
    ) -> Result<usize, Error> {
        self.with_cache_mut(|cache| cache.force_clear_older_than_at(max_age, now))
    }

    /// [`ReplayCache::insert`] on the shared cache, under its lock.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ReplayCachePoisoned`] when the lock is poisoned.
    fn insert(
        &self,
        key: ReplayKey,
        authenticator_digest: [u8; 32],
        presented_at: SystemTime,
        validator_skew: Duration,
    ) -> Result<bool, Error> {
        self.with_cache_mut(|cache| {
            cache.insert(key, authenticator_digest, presented_at, validator_skew)
        })?
    }

    /// Run `read` on the shared cache under its lock.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ReplayCachePoisoned`] when the lock is poisoned.
    fn with_cache<R>(&self, read: impl FnOnce(&ReplayCache) -> R) -> Result<R, Error> {
        let cache = self
            .inner
            .lock()
            .map_err(|_poisoned| Error::ReplayCachePoisoned)?;
        Ok(read(&cache))
    }

    /// Run `update` on the shared cache under its lock.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ReplayCachePoisoned`] when the lock is poisoned.
    fn with_cache_mut<R>(&self, update: impl FnOnce(&mut ReplayCache) -> R) -> Result<R, Error> {
        let mut cache = self
            .inner
            .lock()
            .map_err(|_poisoned| Error::ReplayCachePoisoned)?;
        Ok(update(&mut cache))
    }
}

/// Caller-owned policy for unchecked cross-realm transit (RFC 4120 section 2.7).
///
/// Implementations must validate both endpoint realms and the complete encoded
/// path. Empty contents mean direct cross-realm transit, not same-realm use.
/// Unsupported encodings must be rejected unless the implementation understands
/// their semantics. This policy is called only when the KDC has not set
/// TRANSITED-POLICY-CHECKED and either the endpoint realms differ or the
/// transited path is nonempty: a same-realm ticket with a nonempty unchecked
/// path needs the same explicit approval.
pub trait TransitValidator: Debug + Send + Sync {
    /// Return whether this realm path is explicitly trusted by the application.
    fn accepts(
        &self,
        client_realm: &str,
        service_realm: &str,
        transited: &rasn_kerberos::TransitedEncoding,
    ) -> bool;
}

/// Explicit trust in exact DOMAIN-X500-COMPRESS paths between two realms.
///
/// Active Directory does not set TRANSITED-POLICY-CHECKED (MS-KILE 3.1.5.4).
/// Attach this opt-in through [`Validator::with_transit_validator`]; the default
/// still rejects unchecked cross-realm tickets, as required by RFC 4120 §2.7.
/// Paths are matched byte-for-byte, not decoded or inferred from realm suffixes.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct TransitPolicy {
    /// Trusted client endpoint realm, compared case-sensitively.
    client_realm: String,
    /// Trusted service endpoint realm, compared case-sensitively.
    service_realm: String,
    /// Complete trusted DOMAIN-X500-COMPRESS encodings, including direct paths.
    paths: Vec<Vec<u8>>,
}

impl TransitPolicy {
    /// Trust only a direct cross-realm ticket between the named endpoint realms.
    ///
    /// Requires encoding type 1 (DOMAIN-X500-COMPRESS) with empty contents.
    /// Empty endpoint names and all other encodings are rejected.
    #[must_use]
    #[inline]
    pub fn direct(client_realm: &str, service_realm: &str) -> Self {
        Self {
            client_realm: client_realm.to_owned(),
            service_realm: service_realm.to_owned(),
            paths: vec![Vec::new()],
        }
    }

    /// Trust a caller-supplied allow-list of complete DOMAIN-X500-COMPRESS paths.
    ///
    /// Each entry is the exact RFC 4120 §3.3.3.2 encoded path, not an individual
    /// realm. Include an empty entry explicitly to permit direct transit. An
    /// empty allow-list rejects every unchecked path. Unknown encoding types
    /// are always rejected, even if their contents match an allowed entry.
    #[must_use]
    #[inline]
    pub fn domain_x500_paths<I, P>(client_realm: &str, service_realm: &str, paths: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: AsRef<[u8]>,
    {
        Self {
            client_realm: client_realm.to_owned(),
            service_realm: service_realm.to_owned(),
            paths: paths
                .into_iter()
                .map(|path| path.as_ref().to_vec())
                .collect(),
        }
    }
}

impl TransitValidator for TransitPolicy {
    #[inline]
    fn accepts(
        &self,
        client_realm: &str,
        service_realm: &str,
        transited: &rasn_kerberos::TransitedEncoding,
    ) -> bool {
        !self.client_realm.is_empty()
            && !self.service_realm.is_empty()
            && client_realm == self.client_realm
            && service_realm == self.service_realm
            && transited.r#type == 1
            && self
                .paths
                .iter()
                .any(|path| path.as_slice() == transited.contents.as_ref())
    }
}

/// AP-REQ validator backed by a service keytab.
#[derive(Debug)]
pub struct Validator<'keytab> {
    /// Runtime permission shared by ticket and authenticator validation.
    crypto_policy: CryptoPolicy,
    /// The service keytab, borrowed or owned.
    keytab: Cow<'keytab, Keytab>,
    /// The accepted clock skew between the authenticator time and now.
    max_clock_skew: Duration,
    /// A fixed validation time; `None` uses the system clock.
    now: Option<SystemTime>,
    /// Keytab principal components that override the ticket's server name.
    keytab_principal: Option<Vec<String>>,
    /// The peer address matched against the ticket's client addresses.
    client_address: Option<HostAddress>,
    /// Whether a ticket without client addresses is rejected.
    require_client_address: bool,
    /// This validator's own replay cache.
    replay_cache: ReplayCache,
    /// A shared replay cache that replaces `replay_cache` when attached.
    shared_replay_cache: Option<SharedReplayCache>,
    /// Explicit policy for cross-realm tickets not checked by the KDC.
    transit_policy: Option<Arc<dyn TransitValidator>>,
}

impl<'keytab> Validator<'keytab> {
    /// Set explicit enctype permission; defaults permit only the secure DEFAULT list.
    #[inline]
    #[must_use]
    pub fn with_crypto_policy(mut self, policy: CryptoPolicy) -> Self {
        self.crypto_policy = policy;
        self
    }
    /// Change the window without consuming replay evidence on failure.
    ///
    /// # Errors
    ///
    /// Returns a retention-policy error for an incompatible window.
    pub(crate) fn set_max_clock_skew(&mut self, requested: Duration) -> Result<(), Error> {
        if let Some(cache) = &self.shared_replay_cache {
            cache.ensure_skew(requested)?;
        }
        self.replay_cache.configure_owned_skew(requested)?;
        self.max_clock_skew = requested;
        Ok(())
    }

    /// Attach shared state only when its retention covers this validator.
    ///
    /// # Errors
    /// Returns a skew-policy error or a poisoned-cache error before replacement.
    #[cfg(feature = "tower")]
    pub(crate) fn attach_replay_cache(&mut self, cache: SharedReplayCache) -> Result<(), Error> {
        cache.ensure_skew(self.max_clock_skew)?;
        self.shared_replay_cache = Some(cache);
        Ok(())
    }
    /// Apply replay settings already checked by the HTTP construction boundary.
    #[cfg(feature = "tower")]
    pub(crate) fn apply_replay_settings(
        &mut self,
        skew: Duration,
        cache: Option<SharedReplayCache>,
    ) {
        self.max_clock_skew = skew;
        self.replay_cache.max_clock_skew = skew;
        self.shared_replay_cache = cache;
    }
    /// Create a validator with secure AES-only enctype permission and default replay settings.
    #[must_use]
    #[inline]
    pub fn new(keytab: &'keytab Keytab) -> Self {
        Self::from_keytab_cow(Cow::Borrowed(keytab))
    }

    /// Create a validator with gokrb5-compatible defaults from a borrowed or
    /// owned keytab.
    pub(crate) fn from_keytab_cow(keytab: Cow<'keytab, Keytab>) -> Self {
        Self {
            crypto_policy: CryptoPolicy::default(),
            keytab,
            max_clock_skew: DEFAULT_MAX_CLOCK_SKEW,
            now: None,
            keytab_principal: None,
            client_address: None,
            require_client_address: false,
            replay_cache: ReplayCache::new(),
            shared_replay_cache: None,
            transit_policy: None,
        }
    }

    /// Override the validation clock. Useful for deterministic tests.
    #[must_use]
    #[inline]
    pub const fn with_now(mut self, now: SystemTime) -> Self {
        self.now = Some(now);
        self
    }

    /// Override the maximum accepted clock skew.
    ///
    /// # Errors
    ///
    /// Returns a cache policy error for incompatible retention. Increasing the
    /// window after admission begins is rejected rather than losing evidence.
    #[inline]
    pub fn with_max_clock_skew(mut self, max_clock_skew: Duration) -> Result<Self, Error> {
        self.set_max_clock_skew(max_clock_skew)?;
        Ok(self)
    }

    /// Override the principal used for keytab lookup.
    ///
    /// The ticket realm remains the lookup realm, matching gokrb5's
    /// `KeytabPrincipal` behavior.
    #[must_use]
    #[inline]
    pub fn with_keytab_principal<I, S>(mut self, components: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.keytab_principal = Some(components.into_iter().map(Into::into).collect());
        self
    }

    /// Provide the client address observed by the service.
    #[must_use]
    #[inline]
    pub fn with_client_address(mut self, client_address: HostAddress) -> Self {
        self.client_address = Some(client_address);
        self
    }

    /// Require the ticket to contain client addresses.
    #[must_use]
    #[inline]
    pub const fn require_client_address(mut self, require_client_address: bool) -> Self {
        self.require_client_address = require_client_address;
        self
    }

    /// Accept unchecked cross-realm or nonempty same-realm paths only when this
    /// policy explicitly trusts them.
    ///
    /// For AD cross-domain tickets, which lack TRANSITED-POLICY-CHECKED, use
    /// [`TransitPolicy::direct`] for a trusted endpoint pair or
    /// [`TransitPolicy::domain_x500_paths`] for an exact-path allow-list.
    #[must_use]
    #[inline]
    pub fn with_transit_validator(mut self, validator: Arc<dyn TransitValidator>) -> Self {
        self.transit_policy = Some(validator);
        self
    }

    /// Share replay detection state with other validators.
    ///
    /// # Errors
    ///
    /// Returns a cache policy error when the retention ceiling is incompatible.
    #[inline]
    pub fn with_shared_replay_cache(
        mut self,
        replay_cache: SharedReplayCache,
    ) -> Result<Self, Error> {
        replay_cache.ensure_skew(self.max_clock_skew)?;
        self.shared_replay_cache = Some(replay_cache);
        Ok(self)
    }

    /// Remove any shared replay cache and use this validator's local cache.
    #[must_use]
    #[inline]
    pub fn without_shared_replay_cache(mut self) -> Self {
        self.shared_replay_cache = None;
        self
    }

    /// Shared replay cache used by this validator, if any.
    #[must_use]
    #[inline]
    pub const fn shared_replay_cache(&self) -> Option<&SharedReplayCache> {
        self.shared_replay_cache.as_ref()
    }

    /// Mutable replay cache for tests and integration with service state.
    ///
    /// If a shared replay cache has been installed, validation uses the shared
    /// cache instead of this local cache.
    #[inline]
    pub const fn replay_cache_mut(&mut self) -> &mut ReplayCache {
        &mut self.replay_cache
    }

    /// Decode and validate an AP-REQ.
    ///
    /// # Errors
    ///
    /// Returns a decode error for a malformed AP-REQ, [`Error::Keytab`] when
    /// no keytab key matches the ticket, a crypto, key-type or PAC error when
    /// the ticket, authenticator or PAC fails to decrypt or verify, and the
    /// policy errors [`Error::TicketNotYetValid`], [`Error::TicketExpired`],
    /// [`Error::BadClientAddress`], [`Error::RequiredClientAddressMissing`],
    /// [`Error::ClientPrincipalMismatch`], [`Error::ClockSkew`] and
    /// [`Error::Replay`]. A poisoned shared replay cache returns
    /// [`Error::ReplayCachePoisoned`]. Unchecked cross-realm transit, or an
    /// unchecked nonempty same-realm path, without an approving caller policy
    /// returns [`Error::TransitPolicyRejected`].
    #[inline]
    pub fn validate_ap_req(&mut self, bytes: &[u8]) -> Result<ValidatedApReq, Error> {
        self.validate_ap_req_with_check(bytes, |_, _| Ok::<(), Error>(()))
    }

    /// The validation time: the fixed time when one is set, otherwise the
    /// system clock.
    fn now(&self) -> SystemTime {
        self.now.unwrap_or_else(SystemTime::now)
    }

    /// Record an accepted AP-REQ in the shared replay cache when one is
    /// attached, otherwise in this validator's own cache.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Replay`] when the replay key or the authenticator
    /// digest was already recorded, and [`Error::ReplayCachePoisoned`] when the
    /// shared cache's lock is poisoned.
    fn record_replay(
        &mut self,
        replay_key: ReplayKey,
        authenticator_digest: [u8; 32],
        now: SystemTime,
    ) -> Result<(), Error> {
        let inserted = if let Some(replay_cache) = &self.shared_replay_cache {
            replay_cache.insert(replay_key, authenticator_digest, now, self.max_clock_skew)?
        } else {
            self.replay_cache
                .insert(replay_key, authenticator_digest, now, self.max_clock_skew)?
        };
        if inserted { Ok(()) } else { Err(Error::Replay) }
    }

    /// Check the ticket's start and end times, and its invalid flag, against
    /// now and the accepted clock skew.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TicketNotYetValid`] for a future or invalid ticket,
    /// [`Error::TicketExpired`] for an expired one, and
    /// [`Error::TimeOverflow`] when a ticket time is out of range.
    fn validate_ticket_times(
        &self,
        service: &Principal,
        enc_ticket: &rasn_kerberos::EncTicketPart,
    ) -> Result<(), Error> {
        let _: SystemTime = system_time_from_kerberos_time(&enc_ticket.auth_time)?;
        if let Some(renew_till) = &enc_ticket.renew_till {
            let _: SystemTime = system_time_from_kerberos_time(renew_till)?;
        }
        let now = self.now();
        let start = ticket_start_time(enc_ticket)?;
        if starts_after_skew(start, now, self.max_clock_skew) || has_invalid_flag(&enc_ticket.flags)
        {
            return Err(Error::TicketNotYetValid {
                service: service.name(),
                realm: service.realm.clone(),
            });
        }

        let end = system_time_from_kerberos_time(&enc_ticket.end_time)?;
        if expired_after_skew(now, end, self.max_clock_skew) {
            return Err(Error::TicketExpired {
                service: service.name(),
                realm: service.realm.clone(),
            });
        }

        Ok(())
    }

    /// Match the ticket's client addresses against the configured peer
    /// address.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RequiredClientAddressMissing`] when addresses are
    /// required and the ticket has none, and [`Error::BadClientAddress`] when
    /// the ticket has addresses and none matches the peer address.
    fn validate_client_address(
        &self,
        service: &Principal,
        enc_ticket: &rasn_kerberos::EncTicketPart,
    ) -> Result<(), Error> {
        let Some(ticket_addresses) = &enc_ticket.caddr else {
            if self.require_client_address {
                return Err(Error::RequiredClientAddressMissing {
                    service: service.name(),
                    realm: service.realm.clone(),
                });
            }
            return Ok(());
        };

        let Some(client_address) = &self.client_address else {
            return Err(Error::BadClientAddress {
                service: service.name(),
                realm: service.realm.clone(),
            });
        };

        if ticket_addresses.iter().any(|address| {
            let same_type = address.addr_type == client_address.addr_type;
            same_type && address.address.as_ref() == client_address.address.as_slice()
        }) {
            Ok(())
        } else {
            Err(Error::BadClientAddress {
                service: service.name(),
                realm: service.realm.clone(),
            })
        }
    }
}

impl Validator<'static> {
    #[must_use]
    /// Create a validator from an owned keytab.
    #[inline]
    pub fn from_keytab(keytab: Keytab) -> Self {
        Self::from_keytab_cow(Cow::Owned(keytab))
    }

    /// Create a validator by loading a file-backed keytab name.
    ///
    /// Bare paths, `FILE:path`, and `WRFILE:path` are supported by the keytab
    /// module. Other keytab stores are rejected explicitly.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Keytab`] when the name is not a file keytab or the
    /// file cannot be read or parsed.
    #[inline]
    pub fn from_keytab_name<P>(keytab_name: P) -> Result<Self, Error>
    where
        P: AsRef<str>,
    {
        Ok(Self::from_keytab(Keytab::load_name(keytab_name)?))
    }

    /// Create a validator from `config.libdefaults.default_keytab_name`.
    ///
    /// # Ambient input
    /// Expands templates using `TMPDIR`, `TEMP`, `APPDATA` and process identity.
    /// Use `from_keytab_name` with a literal name to avoid this discovery.
    ///
    /// The configured `[libdefaults] clockskew` becomes the acceptance window;
    /// [`Self::new`] keeps the gokrb5-compatible 300 s default.
    /// The configured permitted list and legacy flags become the runtime policy.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Keytab`] when the configured name is not a file keytab
    /// or the file cannot be read or parsed.
    #[inline]
    pub fn from_default_keytab_name(config: &Config) -> Result<Self, Error> {
        restrictions::config(config).map_err(|_invalid| error::Policy::InvalidConfiguration)?;
        let policy = CryptoPolicy::from_libdefaults(&config.libdefaults)
            .map_err(|_invalid| error::Policy::InvalidConfiguration)?;
        Self::from_keytab(keytab::configured_keytab(
            &config.libdefaults,
            DefaultName::Keytab,
        )?)
        .with_crypto_policy(policy)
        .with_max_clock_skew(config.libdefaults.clockskew)
    }

    /// Create a validator from the default keytab.
    ///
    /// # Ambient input
    /// Reads `KRB5_KTNAME` before the configured fallback; invalid Unicode is an
    /// expansion error when `TMPDIR`, `TEMP` or `APPDATA` supplies invalid text;
    /// process identity is read for identity tokens. An invalid `KRB5_KTNAME` is an
    /// error. Use [`Self::from_keytab_name`] for an explicit keytab name.
    ///
    /// `KRB5_KTNAME` takes precedence when set. Otherwise this falls back to
    /// `config.libdefaults.default_keytab_name`. The configured
    /// `[libdefaults] clockskew` becomes the acceptance window.
    /// The configured permitted list and legacy flags also apply to acceptance.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Keytab`] when the selected name is not a file keytab
    /// or the file cannot be read or parsed.
    #[inline]
    pub fn from_default_keytab(config: &Config) -> Result<Self, Error> {
        restrictions::config(config).map_err(|_invalid| error::Policy::InvalidConfiguration)?;
        let policy = CryptoPolicy::from_libdefaults(&config.libdefaults)
            .map_err(|_invalid| error::Policy::InvalidConfiguration)?;
        Self::from_keytab(keytab::default_keytab_name(&config.libdefaults)?)
            .with_crypto_policy(policy)
            .with_max_clock_skew(config.libdefaults.clockskew)
    }

    /// Create a validator by loading the file keytab named by `KRB5_KTNAME`.
    ///
    /// # Ambient input
    /// Reads `KRB5_KTNAME`; unset or non-Unicode values are errors. Use
    /// [`Self::from_keytab_name`] for an explicit keytab name.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Keytab`] when the variable is unset, names a
    /// non-file keytab, or the file cannot be read or parsed.
    #[inline]
    pub fn from_keytab_env() -> Result<Self, Error> {
        Ok(Self::from_keytab(Keytab::load_from_env()?))
    }
}

use crate::error::Service as Error;

/// Authorization-data interpretation context, including wrapper criticality.
#[derive(Clone, Copy)]
struct AuthorizationScope {
    /// AD-IF-RELEVANT makes unknown direct children optional.
    critical: bool,
    /// Only ticket PACs are authenticated by the existing PAC verification path.
    ticket: bool,
    /// Maximum nesting is eight wrappers, independently of DER validity.
    depth: usize,
}

/// Validate every restriction independently of first-PAC extraction (RFC 4120 section 5.2.6).
///
/// # Errors
///
/// Returns [`Error::UnsupportedAuthorizationData`] for uninterpreted mandatory
/// semantics, [`Error::AuthorizationDataLimit`] for excess depth/decoded bytes,
/// and [`Error::Decode`] for malformed known wrappers.
fn validate_authorization_data(
    data: Option<&rasn_kerberos::AuthorizationData>,
    ticket: bool,
) -> Result<(), Error> {
    if let Some(elements) = data {
        validate_authorization_elements(
            elements,
            AuthorizationScope {
                critical: true,
                ticket,
                depth: 0,
            },
            &mut AuthorizationBudget {
                remaining: 0x0010_0000,
                pac_seen: false,
            },
        )?;
    }
    Ok(())
}

/// Shared bounds across sibling and nested authorization restrictions.
struct AuthorizationBudget {
    /// Bytes left to decode.
    remaining: usize,
    /// Whether this ticket already supplied a PAC.
    pac_seen: bool,
}

/// Interpret wrapper criticality with a shared decoded-byte budget.
///
/// # Errors
///
/// Returns the errors documented by [`validate_authorization_data`].
fn validate_authorization_elements(
    data: &rasn_kerberos::AuthorizationData,
    scope: AuthorizationScope,
    budget: &mut AuthorizationBudget,
) -> Result<(), Error> {
    for entry in data {
        budget.remaining = budget
            .remaining
            .checked_sub(entry.data.len())
            .ok_or(Error::AuthorizationDataLimit)?;
        match entry.r#type {
            pac::AD_IF_RELEVANT | 8_i32 => {
                if scope.depth >= 8 {
                    return Err(Error::AuthorizationDataLimit);
                }
                let nested =
                    decode_complete::<rasn_kerberos::AuthorizationData>(entry.data.as_ref())
                        .map_err(|source| Error::Decode {
                            target: "AuthorizationData",
                            message: source,
                        })?;
                validate_authorization_elements(
                    &nested,
                    AuthorizationScope {
                        critical: entry.r#type == 8_i32,
                        ticket: scope.ticket,
                        depth: scope.depth.saturating_add(1),
                    },
                    budget,
                )?;
            }
            pac::AD_WIN2K_PAC if scope.ticket => {
                (!budget.pac_seen)
                    .ok_or(Error::UnsupportedAuthorizationData { kind: entry.r#type })?;
                budget.pac_seen = true;
            }
            4_i32 | 5_i32 => {
                return Err(Error::UnsupportedAuthorizationData { kind: entry.r#type });
            }
            _ if scope.critical => {
                return Err(Error::UnsupportedAuthorizationData { kind: entry.r#type });
            }
            _ => {}
        }
    }
    Ok(())
}

/// RFC 4120 section 3.2.3 replay-cache key of one authenticator.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ReplayKey {
    /// The accepting service principal, without its name type.
    service: Principal,
    /// The authenticator's client principal, without its name type.
    client: Principal,
    /// The authenticator's `ctime`, in seconds since the Unix epoch.
    ctime_seconds: i64,
    /// The authenticator's `cusec`.
    cusec: u32,
}

/// Map an AP-REQ message error onto the service error.
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

/// Map a ticket message error onto the service error.
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

/// Map an AP-REP message error onto the service error.
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

/// Build a principal from a wire realm and principal name.
///
/// # Errors
///
/// Returns [`Error::InvalidString`] when the realm or a name component is not
/// UTF-8.
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

/// Convert a wire Kerberos string to a Rust string.
///
/// # Errors
///
/// Returns [`Error::InvalidString`] when the string is not UTF-8.
fn kerberos_string_to_string(value: &rasn_kerberos::KerberosString) -> Result<String, Error> {
    Ok(from_utf8(value.as_bytes())?.to_owned())
}

/// Convert a wire encryption key to the keytab key type.
fn encryption_key_from_rasn(value: &rasn_kerberos::EncryptionKey) -> EncryptionKey {
    EncryptionKey {
        etype: value.r#type,
        value: value.value.as_ref().to_vec(),
    }
}

/// Convert a keytab key to the wire encryption key type.
fn encryption_key_to_rasn(value: &EncryptionKey) -> rasn_kerberos::EncryptionKey {
    rasn_kerberos::EncryptionKey {
        r#type: value.etype,
        value: value.value.clone().into(),
    }
}

/// The ticket's start time, or its auth time when it has none.
///
/// # Errors
///
/// Returns [`Error::TimeOverflow`] when the time is out of range.
fn ticket_start_time(enc_ticket: &rasn_kerberos::EncTicketPart) -> Result<SystemTime, Error> {
    system_time_from_kerberos_time(
        enc_ticket
            .start_time
            .as_ref()
            .unwrap_or(&enc_ticket.auth_time),
    )
}

/// Convert a Kerberos time to a `SystemTime`.
///
/// # Errors
///
/// Returns [`Error::TimeOverflow`] when the time is not representable.
fn system_time_from_kerberos_time(time: &rasn_kerberos::KerberosTime) -> Result<SystemTime, Error> {
    let seconds = time.0.timestamp();
    let nanos = time.0.timestamp_subsec_nanos();
    if nanos != 0 {
        return Err(Error::FractionalKerberosTime);
    }
    u64::try_from(seconds)
        .map_or_else(
            |_before_epoch| UNIX_EPOCH.checked_sub(Duration::new(seconds.unsigned_abs(), nanos)),
            |after_epoch| UNIX_EPOCH.checked_add(Duration::new(after_epoch, nanos)),
        )
        .ok_or(Error::TimeOverflow)
}

/// Convert a `SystemTime` to a Kerberos time in UTC.
///
/// # Errors
///
/// Returns [`Error::TimeOverflow`] when the time is not representable.
fn kerberos_time_from_system_time(time: SystemTime) -> Result<rasn_kerberos::KerberosTime, Error> {
    let (seconds, nanos) = unix_timestamp_parts(time)?;
    if nanos != 0 {
        return Err(Error::FractionalKerberosTime);
    }
    let utc = chrono::DateTime::<chrono::Utc>::from_timestamp(seconds, nanos)
        .ok_or(Error::TimeOverflow)?;
    let offset = chrono::FixedOffset::east_opt(0).ok_or(Error::TimeOverflow)?;
    Ok(rasn_kerberos::KerberosTime(utc.with_timezone(&offset)))
}

/// Split a `SystemTime` into whole seconds since the Unix epoch (floored)
/// and the non-negative nanoseconds past them.
///
/// # Errors
///
/// Returns [`Error::TimeOverflow`] when the seconds do not fit in `i64`.
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
            let whole_seconds: i64 = duration
                .as_secs()
                .try_into()
                .map_err(|_out_of_range| Error::TimeOverflow)?;
            if duration.subsec_nanos() == 0 {
                return Ok((whole_seconds.checked_neg().ok_or(Error::TimeOverflow)?, 0));
            }

            // The seconds are floored: a time 1.25 s before the epoch is
            // -2 s plus 750 ms. `subsec_nanos` is below one billion.
            let floored_seconds = whole_seconds.checked_add(1).ok_or(Error::TimeOverflow)?;
            let nanos = 1_000_000_000_u32
                .checked_sub(duration.subsec_nanos())
                .ok_or(Error::TimeOverflow)?;
            Ok((
                floored_seconds.checked_neg().ok_or(Error::TimeOverflow)?,
                nanos,
            ))
        }
    }
}

/// Enforce the RFC 4120 Microseconds domain before timestamp arithmetic.
///
/// # Errors
///
/// Returns [`Error::IntegerOutOfRange`], naming `field`, outside 0..=999999.
fn microseconds_to_u32(field: &'static str, value: &Integer) -> Result<u32, Error> {
    value
        .to_string()
        .parse::<u32>()
        .ok()
        .filter(|parsed| *parsed <= 999_999)
        .ok_or_else(|| Error::IntegerOutOfRange {
            field,
            value: value.to_string(),
        })
}

/// Whether the ticket's `invalid` flag is set.
fn has_invalid_flag(flags: &rasn_kerberos::TicketFlags) -> bool {
    flags.0.get(INVALID_TICKET_FLAG).is_some_and(|bit| *bit)
}

/// Whether `start` lies more than `max_clock_skew` after `now`.
fn starts_after_skew(start: SystemTime, now: SystemTime, max_clock_skew: Duration) -> bool {
    start
        .duration_since(now)
        .is_ok_and(|delta| delta > max_clock_skew)
}

/// Whether `end` lies more than `max_clock_skew` before `now`.
fn expired_after_skew(now: SystemTime, end: SystemTime, max_clock_skew: Duration) -> bool {
    now.duration_since(end)
        .is_ok_and(|delta| delta > max_clock_skew)
}

/// The absolute distance between two times.
fn abs_duration(left: SystemTime, right: SystemTime) -> Duration {
    // An error carries how far `right` lies after `left`.
    left.duration_since(right)
        .unwrap_or_else(|later| SystemTimeError::duration(&later))
}

/// Replay-cache purge equivalence and cost regressions.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod replay_tests;

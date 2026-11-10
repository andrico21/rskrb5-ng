use core::{fmt, mem, time::Duration};
use std::time::SystemTime;

use zeroize::Zeroize as _;

use super::{
    DEFAULT_TGS_ENCTYPES, DEFAULT_TICKET_LIFETIME, DEFAULT_TKT_ENCTYPES, KDC_OPTION_CANONICALIZE,
    renewal_kdc_option_bits,
};
use crate::{
    config::LibDefaults,
    crypto::CryptoPolicy,
    error::{Client as ClientError, Policy},
    keytab::{EncryptionKey, Keytab},
};

/// Options for constructing an AS-REQ.
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub struct AsReq {
    /// Runtime policy captured at option construction; errors fail before use.
    crypto_policy: Result<CryptoPolicy, Policy>,
    /// Acceptable KDC reply start-time skew from the request clock.
    clock_skew: Duration,
    /// Client clock used for request time fields.
    now: SystemTime,
    /// Requested ticket lifetime.
    ticket_lifetime: Duration,
    /// Optional renewable lifetime.
    renew_lifetime: Option<Duration>,
    /// Client nonce. Callers are responsible for supplying fresh randomness.
    nonce: u32,
    /// Requested response encryption types in preference order.
    etypes: Vec<i32>,
    /// KDC option bits. Unarmored AS builders suppress `canonicalize`: changed
    /// reply identities require authenticated exchange protection not provided here.
    kdc_option_bits: u32,
    /// Optional preauthentication data.
    padata: Vec<rasn_kerberos::PaData>,
    /// Send PA-ENC-TIMESTAMP in the first AS-REQ using requested etype defaults.
    assume_preauthentication: bool,
    /// Advertise support for AS-REP encrypted padata negotiation.
    fast_negotiation: bool,
}

impl fmt::Debug for AsReq {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            crypto_policy,
            clock_skew,
            now,
            ticket_lifetime,
            renew_lifetime,
            nonce,
            etypes,
            kdc_option_bits,
            padata,
            assume_preauthentication,
            fast_negotiation,
        } = self;
        f.debug_struct("AsReq")
            .field("crypto_policy", crypto_policy)
            .field("clock_skew", clock_skew)
            .field("now", now)
            .field("ticket_lifetime", ticket_lifetime)
            .field("renew_lifetime", renew_lifetime)
            .field("nonce", nonce)
            .field("etypes", etypes)
            .field("kdc_option_bits", kdc_option_bits)
            .field("padata_count", &padata.len())
            .field("assume_preauthentication", assume_preauthentication)
            .field("fast_negotiation", fast_negotiation)
            .finish()
    }
}

impl AsReq {
    /// Borrow the captured policy result.
    #[inline]
    #[must_use]
    pub const fn crypto_policy(&self) -> &Result<CryptoPolicy, Policy> {
        &self.crypto_policy
    }
    /// Return the clock skew.
    #[inline]
    #[must_use]
    pub const fn clock_skew(&self) -> Duration {
        self.clock_skew
    }
    /// Return the request clock.
    #[inline]
    #[must_use]
    pub const fn now(&self) -> SystemTime {
        self.now
    }
    /// Return the ticket lifetime.
    #[inline]
    #[must_use]
    pub const fn ticket_lifetime(&self) -> Duration {
        self.ticket_lifetime
    }
    /// Return the renewable lifetime.
    #[inline]
    #[must_use]
    pub const fn renew_lifetime(&self) -> Option<Duration> {
        self.renew_lifetime
    }
    /// Return the nonce.
    #[inline]
    #[must_use]
    pub const fn nonce(&self) -> u32 {
        self.nonce
    }
    /// Borrow requested encryption types.
    #[inline]
    #[must_use]
    pub fn etypes(&self) -> &[i32] {
        &self.etypes
    }
    /// Return KDC flags.
    #[inline]
    #[must_use]
    pub const fn kdc_option_bits(&self) -> u32 {
        self.kdc_option_bits
    }
    /// Borrow dependency-owned preauthentication data; ASN.1 residual copies remain.
    #[inline]
    #[must_use]
    pub fn padata(&self) -> &[rasn_kerberos::PaData] {
        &self.padata
    }
    /// Transfer preauthentication data without copying it.
    pub(super) fn take_padata(&mut self) -> Vec<rasn_kerberos::PaData> {
        mem::take(&mut self.padata)
    }
    /// Mutate dependency-owned padata only inside the request builder module.
    pub(super) const fn padata_mut(&mut self) -> &mut Vec<rasn_kerberos::PaData> {
        &mut self.padata
    }
    /// Transfer the non-secret enctype list into the wire request.
    pub(super) fn take_etypes(&mut self) -> Vec<i32> {
        mem::take(&mut self.etypes)
    }
    /// Return the optimistic preauthentication setting.
    #[inline]
    #[must_use]
    pub const fn assume_preauthentication(&self) -> bool {
        self.assume_preauthentication
    }
    /// Return the FAST negotiation setting.
    #[inline]
    #[must_use]
    pub const fn fast_negotiation(&self) -> bool {
        self.fast_negotiation
    }
    /// Replace the captured policy result.
    #[inline]
    pub fn set_crypto_policy(&mut self, value: Result<CryptoPolicy, Policy>) {
        self.crypto_policy = value;
    }
    /// Replace the request clock.
    #[inline]
    pub const fn set_now(&mut self, value: SystemTime) {
        self.now = value;
    }
    /// Replace the nonce.
    #[inline]
    pub const fn set_nonce(&mut self, value: u32) {
        self.nonce = value;
    }
    #[must_use]
    /// Construct options with gokrb5-compatible AES defaults.
    #[inline]
    pub fn new(now: SystemTime, nonce: u32) -> Self {
        Self {
            crypto_policy: Ok(CryptoPolicy::default()),
            clock_skew: Duration::from_secs(300),
            now,
            ticket_lifetime: DEFAULT_TICKET_LIFETIME,
            renew_lifetime: None,
            nonce,
            etypes: DEFAULT_TKT_ENCTYPES.to_vec(),
            kdc_option_bits: 0,
            padata: Vec::new(),
            assume_preauthentication: false,
            fast_negotiation: true,
        }
    }

    /// Construct options from parsed `[libdefaults]`.
    ///
    /// Parsed implicit defaults already inherit the permitted list. Staged
    /// request lists are validated without removing any requested enctype.
    /// # Errors
    /// Returns named configuration errors or the permanent policy cause.
    #[inline]
    pub fn from_libdefaults(
        now: SystemTime,
        nonce: u32,
        defaults: &LibDefaults,
    ) -> Result<Self, ClientError> {
        let mut options = Self::new(now, nonce);
        options.crypto_policy = Ok(super::crypto_policy::configured(defaults)?);
        options.clock_skew = defaults.clockskew;
        options.ticket_lifetime = defaults.ticket_lifetime;
        options.renew_lifetime =
            (defaults.renew_lifetime != Duration::ZERO).then_some(defaults.renew_lifetime);
        options.etypes = defaults.default_tkt_enctype_ids();
        options.kdc_option_bits = defaults.kdc_default_options;
        options.kdc_option_bits &= !0x4000_0000;
        options.kdc_option_bits &= !0x1000_0000;
        if defaults.proxiable.is_enabled() {
            options.kdc_option_bits |= 0x1000_0000;
        }
        if defaults.forwardable.is_enabled() {
            options.kdc_option_bits |= 0x4000_0000;
        }
        if defaults.canonicalize.is_enabled() {
            options.kdc_option_bits |= KDC_OPTION_CANONICALIZE;
        }
        Ok(options)
    }

    #[must_use]
    /// Override the requested ticket lifetime.
    #[inline]
    pub const fn with_ticket_lifetime(mut self, ticket_lifetime: Duration) -> Self {
        self.ticket_lifetime = ticket_lifetime;
        self
    }

    #[must_use]
    /// Override the renewable lifetime.
    #[inline]
    pub const fn with_renew_lifetime(mut self, renew_lifetime: Option<Duration>) -> Self {
        self.renew_lifetime = renew_lifetime;
        self
    }

    #[must_use]
    /// Override requested response encryption types.
    #[inline]
    pub fn with_etypes<P>(mut self, etypes: P) -> Self
    where
        P: Into<Vec<i32>>,
    {
        self.etypes = etypes.into();
        self
    }

    #[must_use]
    /// Override KDC options using the raw krb5.conf bit representation.
    #[inline]
    pub const fn with_kdc_option_bits(mut self, kdc_option_bits: u32) -> Self {
        self.kdc_option_bits = kdc_option_bits;
        self
    }

    #[must_use]
    /// Add preauthentication data.
    #[inline]
    pub fn with_padata<P>(mut self, padata: P) -> Self
    where
        P: Into<Vec<rasn_kerberos::PaData>>,
    {
        self.padata = padata.into();
        self
    }

    #[must_use]
    /// Send PA-ENC-TIMESTAMP in the first AS-REQ.
    #[inline]
    pub const fn with_assume_preauthentication(mut self, assume_preauthentication: bool) -> Self {
        self.assume_preauthentication = assume_preauthentication;
        self
    }

    #[must_use]
    /// Configure whether high-level AS login advertises PA-REQ-ENC-PA-REP.
    #[inline]
    pub const fn with_fast_negotiation(mut self, fast_negotiation: bool) -> Self {
        self.fast_negotiation = fast_negotiation;
        self
    }
}

/// Options for constructing a TGS-REQ.
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub struct TgsReq {
    /// Runtime policy captured at option construction; errors fail before use.
    crypto_policy: Result<CryptoPolicy, Policy>,
    /// Acceptable KDC reply start-time skew from the request clock.
    clock_skew: Duration,
    /// Frontend service keys used to authenticate delegated ticket identities.
    delegation_keytab: Option<Keytab>,
    /// Client clock used for request time fields.
    now: SystemTime,
    /// Requested service-ticket lifetime.
    ticket_lifetime: Duration,
    /// Optional renewable lifetime.
    renew_lifetime: Option<Duration>,
    /// Client nonce. Callers are responsible for supplying fresh randomness.
    nonce: u32,
    /// Requested response encryption types in preference order.
    etypes: Vec<i32>,
    /// KDC option bit string as stored in krb5.conf.
    kdc_option_bits: u32,
    /// Additional TGS padata appended after PA-TGS-REQ.
    padata: Vec<rasn_kerberos::PaData>,
    /// Additional tickets included in the TGS request body.
    additional_tickets: Vec<rasn_kerberos::Ticket>,
}

impl fmt::Debug for TgsReq {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            crypto_policy,
            clock_skew,
            delegation_keytab,
            now,
            ticket_lifetime,
            renew_lifetime,
            nonce,
            etypes,
            kdc_option_bits,
            padata,
            additional_tickets,
        } = self;
        f.debug_struct("TgsReq")
            .field("crypto_policy", crypto_policy)
            .field("clock_skew", clock_skew)
            .field("delegation_keytab", delegation_keytab)
            .field("now", now)
            .field("ticket_lifetime", ticket_lifetime)
            .field("renew_lifetime", renew_lifetime)
            .field("nonce", nonce)
            .field("etypes", etypes)
            .field("kdc_option_bits", kdc_option_bits)
            .field("padata_count", &padata.len())
            .field("additional_tickets_count", &additional_tickets.len())
            .finish()
    }
}

impl TgsReq {
    /// Resolve requested end times against the captured request clock.
    /// # Errors
    /// Returns [`ClientError::TimeOverflow`] when a lifetime exceeds the clock range.
    pub(super) fn end_times(&self) -> Result<(SystemTime, Option<SystemTime>), ClientError> {
        let till = self
            .now
            .checked_add(self.ticket_lifetime)
            .ok_or(ClientError::TimeOverflow)?;
        let renew = self
            .renew_lifetime
            .map(|duration| {
                self.now
                    .checked_add(duration)
                    .ok_or(ClientError::TimeOverflow)
            })
            .transpose()?;
        Ok((till, renew))
    }
    /// Borrow the captured policy result.
    #[inline]
    #[must_use]
    pub const fn crypto_policy(&self) -> &Result<CryptoPolicy, Policy> {
        &self.crypto_policy
    }
    /// Return clock skew.
    #[inline]
    #[must_use]
    pub const fn clock_skew(&self) -> Duration {
        self.clock_skew
    }
    /// Return the request clock.
    #[inline]
    #[must_use]
    pub const fn now(&self) -> SystemTime {
        self.now
    }
    /// Return requested ticket lifetime.
    #[inline]
    #[must_use]
    pub const fn ticket_lifetime(&self) -> Duration {
        self.ticket_lifetime
    }
    /// Return requested renewable lifetime.
    #[inline]
    #[must_use]
    pub const fn renew_lifetime(&self) -> Option<Duration> {
        self.renew_lifetime
    }
    /// Return the nonce.
    #[inline]
    #[must_use]
    pub const fn nonce(&self) -> u32 {
        self.nonce
    }
    /// Borrow requested encryption types.
    #[inline]
    #[must_use]
    pub fn etypes(&self) -> &[i32] {
        &self.etypes
    }
    /// Return KDC flags.
    #[inline]
    #[must_use]
    pub const fn kdc_option_bits(&self) -> u32 {
        self.kdc_option_bits
    }
    /// Borrow dependency-owned preauthentication data.
    #[inline]
    #[must_use]
    pub fn padata(&self) -> &[rasn_kerberos::PaData] {
        &self.padata
    }
    /// Borrow dependency-owned additional tickets.
    #[inline]
    #[must_use]
    pub fn additional_tickets(&self) -> &[rasn_kerberos::Ticket] {
        &self.additional_tickets
    }
    /// Borrow the delegation keytab.
    #[inline]
    #[must_use]
    pub const fn delegation_keytab(&self) -> Option<&Keytab> {
        self.delegation_keytab.as_ref()
    }
    /// Replace the captured policy.
    #[inline]
    pub fn set_crypto_policy(&mut self, value: Result<CryptoPolicy, Policy>) {
        self.crypto_policy = value;
    }
    /// Replace KDC flags.
    #[inline]
    pub const fn set_kdc_option_bits(&mut self, value: u32) {
        self.kdc_option_bits = value;
    }
    /// Mutate padata only inside the request builder module.
    pub(super) const fn padata_mut(&mut self) -> &mut Vec<rasn_kerberos::PaData> {
        &mut self.padata
    }
    /// Mutate additional tickets only inside the request builder module.
    pub(super) const fn additional_tickets_mut(&mut self) -> &mut Vec<rasn_kerberos::Ticket> {
        &mut self.additional_tickets
    }
    /// Transfer padata without cloning residual dependency storage.
    pub(super) fn take_padata(&mut self) -> Vec<rasn_kerberos::PaData> {
        mem::take(&mut self.padata)
    }
    /// Transfer additional tickets without cloning residual dependency storage.
    pub(super) fn take_additional_tickets(&mut self) -> Vec<rasn_kerberos::Ticket> {
        mem::take(&mut self.additional_tickets)
    }
    /// Transfer the enctype list.
    pub(super) fn take_etypes(&mut self) -> Vec<i32> {
        mem::take(&mut self.etypes)
    }
    /// Transfer the delegation keytab owner.
    pub(super) const fn take_delegation_keytab(&mut self) -> Option<Keytab> {
        self.delegation_keytab.take()
    }
    /// Supply frontend keys for S4U ticket/evidence validation.
    #[must_use]
    #[inline]
    pub fn with_delegation_keytab(mut self, keytab: Keytab) -> Self {
        self.delegation_keytab = Some(keytab);
        self
    }
    #[must_use]
    /// Construct options with gokrb5-compatible AES defaults.
    #[inline]
    pub fn new(now: SystemTime, nonce: u32) -> Self {
        Self {
            crypto_policy: Ok(CryptoPolicy::default()),
            clock_skew: Duration::from_secs(300),
            now,
            ticket_lifetime: DEFAULT_TICKET_LIFETIME,
            renew_lifetime: None,
            nonce,
            etypes: DEFAULT_TGS_ENCTYPES.to_vec(),
            kdc_option_bits: 0,
            padata: Vec::new(),
            additional_tickets: Vec::new(),
            delegation_keytab: None,
        }
    }

    /// Construct options from parsed `[libdefaults]`.
    ///
    /// Parsed implicit defaults already inherit the permitted list. Staged
    /// request lists are validated without removing any requested enctype.
    /// # Errors
    /// Returns named configuration errors or the permanent policy cause.
    #[inline]
    pub fn from_libdefaults(
        now: SystemTime,
        nonce: u32,
        defaults: &LibDefaults,
    ) -> Result<Self, ClientError> {
        let mut options = Self::new(now, nonce);
        options.crypto_policy = Ok(super::crypto_policy::configured(defaults)?);
        options.clock_skew = defaults.clockskew;
        options.ticket_lifetime = defaults.ticket_lifetime;
        options.renew_lifetime =
            (defaults.renew_lifetime != Duration::ZERO).then_some(defaults.renew_lifetime);
        options.etypes = defaults.default_tgs_enctype_ids();
        options.kdc_option_bits = defaults.kdc_default_options;
        options.kdc_option_bits &= !0x4000_0000;
        options.kdc_option_bits &= !0x1000_0000;
        if defaults.proxiable.is_enabled() {
            options.kdc_option_bits |= 0x1000_0000;
        }
        if defaults.forwardable.is_enabled() {
            options.kdc_option_bits |= 0x4000_0000;
        }
        if defaults.canonicalize.is_enabled() {
            options.kdc_option_bits |= KDC_OPTION_CANONICALIZE;
        }
        Ok(options)
    }

    #[must_use]
    /// Override the requested service-ticket lifetime.
    #[inline]
    pub const fn with_ticket_lifetime(mut self, ticket_lifetime: Duration) -> Self {
        self.ticket_lifetime = ticket_lifetime;
        self
    }

    #[must_use]
    /// Override the renewable lifetime.
    #[inline]
    pub const fn with_renew_lifetime(mut self, renew_lifetime: Option<Duration>) -> Self {
        self.renew_lifetime = renew_lifetime;
        self
    }

    #[must_use]
    /// Override requested response encryption types.
    #[inline]
    pub fn with_etypes<P>(mut self, etypes: P) -> Self
    where
        P: Into<Vec<i32>>,
    {
        self.etypes = etypes.into();
        self
    }

    #[must_use]
    /// Override KDC options using the raw krb5.conf bit representation.
    #[inline]
    pub const fn with_kdc_option_bits(mut self, kdc_option_bits: u32) -> Self {
        self.kdc_option_bits = kdc_option_bits;
        self
    }

    #[must_use]
    /// Add additional TGS padata.
    #[inline]
    pub fn with_padata<P>(mut self, padata: P) -> Self
    where
        P: Into<Vec<rasn_kerberos::PaData>>,
    {
        self.padata = padata.into();
        self
    }

    #[must_use]
    /// Add additional tickets to the TGS request body.
    #[inline]
    pub fn with_additional_tickets<P>(mut self, additional_tickets: P) -> Self
    where
        P: Into<Vec<rasn_kerberos::Ticket>>,
    {
        self.additional_tickets = additional_tickets.into();
        self
    }

    #[must_use]
    /// Add the TGS renewal flags used for renewing an existing ticket.
    #[inline]
    pub const fn with_renewal(mut self) -> Self {
        self.kdc_option_bits = renewal_kdc_option_bits(self.kdc_option_bits);
        self
    }
}

/// Options for constructing a client AP-REQ.
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub struct ApReq {
    /// Explicit runtime policy, or secure defaults when absent.
    crypto_policy: Option<CryptoPolicy>,
    /// Raw AP option bit string.
    ap_option_bits: u32,
    /// Optional authenticator checksum.
    checksum: Option<rasn_kerberos::Checksum>,
    /// Optional client-selected subkey.
    subkey: Option<EncryptionKey>,
    /// Optional client sequence number.
    sequence_number: Option<u32>,
}

impl fmt::Debug for ApReq {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            crypto_policy,
            ap_option_bits,
            checksum,
            subkey,
            sequence_number,
        } = self;
        f.debug_struct("ApReq")
            .field("crypto_policy", crypto_policy)
            .field("ap_option_bits", ap_option_bits)
            .field(
                "checksum_type",
                &checksum.as_ref().map(|value| value.r#type),
            )
            .field("subkey", subkey)
            .field("sequence_number", sequence_number)
            .finish()
    }
}

impl ApReq {
    /// Borrow the selected crypto policy.
    #[inline]
    #[must_use]
    pub const fn crypto_policy(&self) -> Option<&CryptoPolicy> {
        self.crypto_policy.as_ref()
    }
    /// Set explicit cryptographic permission.
    #[inline]
    pub fn set_crypto_policy(&mut self, value: Option<CryptoPolicy>) {
        self.crypto_policy = value;
    }
    /// Return AP option bits.
    #[inline]
    #[must_use]
    pub const fn ap_option_bits(&self) -> u32 {
        self.ap_option_bits
    }
    /// Borrow the dependency-owned checksum; its ASN.1 copies are residuals.
    #[inline]
    #[must_use]
    pub const fn checksum(&self) -> Option<&rasn_kerberos::Checksum> {
        self.checksum.as_ref()
    }
    /// Borrow the subkey.
    #[inline]
    #[must_use]
    pub const fn subkey(&self) -> Option<&EncryptionKey> {
        self.subkey.as_ref()
    }
    /// Return the selected sequence number.
    #[inline]
    #[must_use]
    pub const fn sequence_number(&self) -> Option<u32> {
        self.sequence_number
    }
    /// Transfer option components without copying credential material.
    pub(super) fn into_parts(
        self,
    ) -> (
        Option<CryptoPolicy>,
        u32,
        Option<rasn_kerberos::Checksum>,
        Option<EncryptionKey>,
        Option<u32>,
    ) {
        let Self {
            crypto_policy,
            ap_option_bits,
            checksum,
            subkey,
            sequence_number,
        } = self;
        (
            crypto_policy,
            ap_option_bits,
            checksum,
            subkey,
            sequence_number,
        )
    }
    #[must_use]
    /// Construct AP-REQ options with no flags or optional authenticator fields.
    #[inline]
    pub const fn new() -> Self {
        Self {
            crypto_policy: None,
            ap_option_bits: 0,
            checksum: None,
            subkey: None,
            sequence_number: None,
        }
    }

    #[must_use]
    /// Override AP-REQ option bits.
    #[inline]
    pub const fn with_ap_option_bits(mut self, ap_option_bits: u32) -> Self {
        self.ap_option_bits = ap_option_bits;
        self
    }

    #[must_use]
    /// Set or clear the authenticator checksum.
    #[inline]
    pub fn with_checksum(mut self, checksum: Option<rasn_kerberos::Checksum>) -> Self {
        self.checksum = checksum;
        self
    }

    #[must_use]
    /// Set or clear the client-selected subkey.
    #[inline]
    pub fn with_subkey(mut self, subkey: Option<EncryptionKey>) -> Self {
        if let Some(previous) = &mut self.subkey {
            previous.zeroize();
        }
        self.subkey = subkey;
        self
    }

    #[must_use]
    /// Set or clear the client sequence number.
    #[inline]
    pub const fn with_sequence_number(mut self, sequence_number: Option<u32>) -> Self {
        self.sequence_number = sequence_number;
        self
    }
}

impl Default for ApReq {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

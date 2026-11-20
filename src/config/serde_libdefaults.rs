//! The `[libdefaults]` part of the JSON snapshot.

#[cfg(feature = "serde")]
use super::LibDefaults;
#[cfg(feature = "serde")]
use super::Toggle;
#[cfg(feature = "serde")]
use super::hostname;
#[cfg(feature = "serde")]
use super::serde_stage::KerberosBitStringJson;
#[cfg(feature = "serde")]
use super::serde_stage::duration_nanos;
#[cfg(feature = "serde")]
use super::serde_stage::optional_ip_addresses;

/// The gokrb5 JSON snapshot of a [`LibDefaults`], borrowing from it.
#[cfg(feature = "serde")]
#[derive(serde::Serialize)]
pub(super) struct LibDefaultsJson<'config> {
    /// [`LibDefaults::allow_weak_crypto`], as gokrb5's `AllowWeakCrypto`.
    #[serde(rename = "AllowWeakCrypto")]
    allow_weak_crypto: Toggle,
    /// [`LibDefaults::canonicalize`], as gokrb5's `Canonicalize`.
    #[serde(rename = "Canonicalize")]
    canonicalize: Toggle,
    /// [`LibDefaults::ccache_type`], as gokrb5's `CCacheType`.
    #[serde(rename = "CCacheType")]
    ccache_type: i32,
    /// [`LibDefaults::clockskew`] in nanoseconds, as gokrb5's `Clockskew`.
    #[serde(rename = "Clockskew")]
    clockskew: u128,
    /// [`LibDefaults::default_ccache_name`], as gokrb5's `DefaultCCacheName`.
    #[serde(rename = "DefaultCCacheName")]
    default_ccache_name: &'config str,
    /// [`LibDefaults::default_client_keytab_name`], as gokrb5's `DefaultClientKeytabName`.
    #[serde(rename = "DefaultClientKeytabName")]
    default_client_keytab_name: &'config str,
    /// [`LibDefaults::default_keytab_name`], as gokrb5's `DefaultKeytabName`.
    #[serde(rename = "DefaultKeytabName")]
    default_keytab_name: &'config str,
    /// [`LibDefaults::default_realm`], as gokrb5's `DefaultRealm`.
    #[serde(rename = "DefaultRealm")]
    default_realm: &'config str,
    /// [`LibDefaults::default_tgs_enctypes`], as gokrb5's `DefaultTGSEnctypes`.
    #[serde(rename = "DefaultTGSEnctypes")]
    default_tgs_enctypes: &'config [String],
    /// [`LibDefaults::default_tkt_enctypes`], as gokrb5's `DefaultTktEnctypes`.
    #[serde(rename = "DefaultTktEnctypes")]
    default_tkt_enctypes: &'config [String],
    /// [`LibDefaults::default_tgs_enctype_ids`], as gokrb5's `DefaultTGSEnctypeIDs`.
    #[serde(rename = "DefaultTGSEnctypeIDs")]
    default_tgs_enctype_ids: Vec<i32>,
    /// [`LibDefaults::default_tkt_enctype_ids`], as gokrb5's `DefaultTktEnctypeIDs`.
    #[serde(rename = "DefaultTktEnctypeIDs")]
    default_tkt_enctype_ids: Vec<i32>,
    /// [`LibDefaults::dns_canonicalize_hostname`], as gokrb5's `DNSCanonicalizeHostname`.
    #[serde(rename = "DNSCanonicalizeHostname")]
    dns_canonicalize_hostname: hostname::Canonicalization,
    /// [`LibDefaults::dns_lookup_kdc`], as gokrb5's `DNSLookupKDC`.
    #[serde(rename = "DNSLookupKDC")]
    dns_lookup_kdc: Toggle,
    /// [`LibDefaults::dns_lookup_realm`], as gokrb5's `DNSLookupRealm`.
    #[serde(rename = "DNSLookupRealm")]
    dns_lookup_realm: Toggle,
    /// [`LibDefaults::extra_addresses`] as strings, or `None` when empty, as gokrb5's `ExtraAddresses`.
    #[serde(rename = "ExtraAddresses")]
    extra_addresses: Option<Vec<String>>,
    /// [`LibDefaults::forwardable`], as gokrb5's `Forwardable`.
    #[serde(rename = "Forwardable")]
    forwardable: Toggle,
    /// [`LibDefaults::ignore_acceptor_hostname`], as gokrb5's `IgnoreAcceptorHostname`.
    #[serde(rename = "IgnoreAcceptorHostname")]
    ignore_acceptor_hostname: Toggle,
    /// [`LibDefaults::k5login_authoritative`], as gokrb5's `K5LoginAuthoritative`.
    #[serde(rename = "K5LoginAuthoritative")]
    k5login_authoritative: Toggle,
    /// [`LibDefaults::k5login_directory`], as gokrb5's `K5LoginDirectory`.
    #[serde(rename = "K5LoginDirectory")]
    k5login_directory: &'config str,
    /// [`LibDefaults::kdc_default_options`] as a bit string, as gokrb5's `KDCDefaultOptions`.
    #[serde(rename = "KDCDefaultOptions")]
    kdc_default_options: KerberosBitStringJson,
    /// [`LibDefaults::kdc_time_sync`], as gokrb5's `KDCTimeSync`.
    #[serde(rename = "KDCTimeSync")]
    kdc_time_sync: i32,
    /// [`LibDefaults::no_addresses`], as gokrb5's `NoAddresses`.
    #[serde(rename = "NoAddresses")]
    no_addresses: Toggle,
    /// [`LibDefaults::permitted_enctypes`], as gokrb5's `PermittedEnctypes`.
    #[serde(rename = "PermittedEnctypes")]
    permitted_enctypes: &'config [String],
    /// [`LibDefaults::permitted_enctype_ids`], as gokrb5's `PermittedEnctypeIDs`.
    #[serde(rename = "PermittedEnctypeIDs")]
    permitted_enctype_ids: Vec<i32>,
    /// [`LibDefaults::preferred_preauth_types`], as gokrb5's `PreferredPreauthTypes`.
    #[serde(rename = "PreferredPreauthTypes")]
    preferred_preauth_types: &'config [i32],
    /// [`LibDefaults::proxiable`], as gokrb5's `Proxiable`.
    #[serde(rename = "Proxiable")]
    proxiable: Toggle,
    /// [`LibDefaults::rdns`], as gokrb5's `RDNS`.
    #[serde(rename = "RDNS")]
    rdns: Toggle,
    /// [`LibDefaults::realm_try_domains`], as gokrb5's `RealmTryDomains`.
    #[serde(rename = "RealmTryDomains")]
    realm_try_domains: i32,
    /// [`LibDefaults::renew_lifetime`] in nanoseconds, as gokrb5's `RenewLifetime`.
    #[serde(rename = "RenewLifetime")]
    renew_lifetime: u128,
    /// [`LibDefaults::safe_checksum_type`], as gokrb5's `SafeChecksumType`.
    #[serde(rename = "SafeChecksumType")]
    safe_checksum_type: i32,
    /// [`LibDefaults::ticket_lifetime`] in nanoseconds, as gokrb5's `TicketLifetime`.
    #[serde(rename = "TicketLifetime")]
    ticket_lifetime: u128,
    /// [`LibDefaults::udp_preference_limit`], as gokrb5's `UDPPreferenceLimit`.
    #[serde(rename = "UDPPreferenceLimit")]
    udp_preference_limit: i32,
    /// [`LibDefaults::verify_ap_req_nofail`], as gokrb5's `VerifyAPReqNofail`.
    #[serde(rename = "VerifyAPReqNofail")]
    verify_ap_req_nofail: Toggle,
}

#[cfg(feature = "serde")]
impl<'config> From<&'config LibDefaults> for LibDefaultsJson<'config> {
    fn from(libdefaults: &'config LibDefaults) -> Self {
        Self {
            allow_weak_crypto: libdefaults.allow_weak_crypto,
            canonicalize: libdefaults.canonicalize,
            ccache_type: libdefaults.ccache_type,
            clockskew: duration_nanos(libdefaults.clockskew),
            default_ccache_name: &libdefaults.default_ccache_name,
            default_client_keytab_name: &libdefaults.default_client_keytab_name,
            default_keytab_name: &libdefaults.default_keytab_name,
            default_realm: &libdefaults.default_realm,
            default_tgs_enctypes: &libdefaults.default_tgs_enctypes,
            default_tkt_enctypes: &libdefaults.default_tkt_enctypes,
            default_tgs_enctype_ids: libdefaults.default_tgs_enctype_ids(),
            default_tkt_enctype_ids: libdefaults.default_tkt_enctype_ids(),
            dns_canonicalize_hostname: libdefaults.dns_canonicalize_hostname,
            dns_lookup_kdc: libdefaults.dns_lookup_kdc,
            dns_lookup_realm: libdefaults.dns_lookup_realm,
            extra_addresses: optional_ip_addresses(&libdefaults.extra_addresses),
            forwardable: libdefaults.forwardable,
            ignore_acceptor_hostname: libdefaults.ignore_acceptor_hostname,
            k5login_authoritative: libdefaults.k5login_authoritative,
            k5login_directory: &libdefaults.k5login_directory,
            kdc_default_options: KerberosBitStringJson::from_u32(libdefaults.kdc_default_options),
            kdc_time_sync: libdefaults.kdc_time_sync,
            no_addresses: libdefaults.no_addresses,
            permitted_enctypes: &libdefaults.permitted_enctypes,
            permitted_enctype_ids: libdefaults.permitted_enctype_ids(),
            preferred_preauth_types: &libdefaults.preferred_preauth_types,
            proxiable: libdefaults.proxiable,
            rdns: libdefaults.rdns,
            realm_try_domains: libdefaults.realm_try_domains,
            renew_lifetime: duration_nanos(libdefaults.renew_lifetime),
            safe_checksum_type: libdefaults.safe_checksum_type,
            ticket_lifetime: duration_nanos(libdefaults.ticket_lifetime),
            udp_preference_limit: libdefaults.udp_preference_limit,
            verify_ap_req_nofail: libdefaults.verify_ap_req_nofail,
        }
    }
}

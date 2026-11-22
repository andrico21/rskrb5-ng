//! Default configuration values and the ambient home-directory defaults.

use alloc::collections::BTreeMap;
use core::time::Duration;

use super::{Config, LibDefaults, ParseMode, Realm, Toggle, hostname, section_values};
use crate::{crypto::s2k::Minima, error::Config as Error};

/// The enctype names every default request and permitted list starts from.
pub(super) const DEFAULT_ENCTYPES: &[&str] = &[
    "aes256-cts-hmac-sha384-192",
    "aes128-cts-hmac-sha256-128",
    "aes256-cts-hmac-sha1-96",
    "aes128-cts-hmac-sha1-96",
];

/// The default `preferred_preauth_types`, most preferred first.
pub(super) const DEFAULT_PREAUTH_TYPES: &[i32] = &[17, 16];

/// Create a config with MIT/gokrb5-style defaults and no parsed sections.
pub(super) fn new_config() -> Config {
    Config {
        libdefaults: LibDefaults::new(),
        realms: Vec::new(),
        domain_realm: BTreeMap::new(),
        capaths: BTreeMap::new(),
        applications: section_values::Applications::default(),
        plugins: BTreeMap::new(),
    }
}

impl Default for Config {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

/// Create default libdefaults without reading the environment.
pub(super) fn new_libdefaults() -> LibDefaults {
    let default_enctypes = DEFAULT_ENCTYPES
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    LibDefaults {
        allow_rc4: Toggle::Disabled,
        min_s2k_iterations: Minima::new(),
        allow_des3: Toggle::Disabled,
        allow_weak_crypto: Toggle::Disabled,
        canonicalize: Toggle::Disabled,
        ccache_type: 4,
        clockskew: Duration::from_secs(300),
        default_ccache_name: String::new(),
        default_client_keytab_name: "/usr/local/var/krb5/user/%{euid}/client.keytab".to_owned(),
        default_keytab_name: "/etc/krb5.keytab".to_owned(),
        default_rcache_name: String::new(),
        default_realm: String::new(),
        default_tgs_enctypes: default_enctypes.clone(),
        default_tkt_enctypes: default_enctypes.clone(),
        dns_canonicalize_hostname: hostname::Canonicalization::Always,
        dns_lookup_kdc: Toggle::Disabled,
        dns_lookup_realm: Toggle::Disabled,
        dns_uri_lookup: Toggle::Disabled,
        enforce_ok_as_delegate: Toggle::Disabled,
        err_fmt: String::new(),
        extra_addresses: Vec::new(),
        forwardable: Toggle::Disabled,
        ignore_acceptor_hostname: Toggle::Disabled,
        k5login_authoritative: Toggle::Enabled,
        k5login_directory: String::new(),
        kcm_mach_service: "org.h5l.kcm".to_owned(),
        kcm_socket: "/var/run/.heim_org.h5l.kcm-socket".to_owned(),
        plugin_base_dir: "%{LIBDIR}/krb5/plugins".to_owned(),
        qualify_shortname: None,
        request_timeout: Duration::ZERO,
        spake_preauth_groups: vec!["edwards25519".to_owned()],
        client_aware_channel_bindings: Toggle::Disabled,
        kdc_default_options: 0x0000_0010,
        kdc_time_sync: 1,
        no_addresses: Toggle::Enabled,
        permitted_enctypes: default_enctypes,
        permitted_enctypes_explicit: Toggle::Disabled,
        preferred_preauth_types: DEFAULT_PREAUTH_TYPES.to_vec(),
        proxiable: Toggle::Disabled,
        rdns: Toggle::Enabled,
        realm_try_domains: -1,
        renew_lifetime: Duration::ZERO,
        safe_checksum_type: 15,
        ticket_lifetime: Duration::from_hours(24),
        udp_preference_limit: 1465,
        verify_ap_req_nofail: Toggle::Disabled,
        verify_ap_req_nofail_explicit: Toggle::Disabled,
        enctype_parse_mode: ParseMode::Compatible,
        enctype_diagnostics: Vec::new(),
        #[cfg(feature = "serde")]
        protocol_relations: BTreeMap::new(),
    }
}

impl Default for LibDefaults {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

/// Create a named realm with empty server lists.
///
/// # Errors
/// Returns [`Error::InvalidRealmsSection`] for an empty realm name.
pub(super) fn new_realm(realm: String) -> Result<Realm, Error> {
    if realm.is_empty() {
        return Err(Error::InvalidRealmsSection("empty realm name".to_owned()));
    }
    Ok(Realm {
        #[cfg(feature = "serde")]
        protocol_relations: BTreeMap::new(),
        name: realm,
        admin_server: Vec::new(),
        default_domain: String::new(),
        kdc: Vec::new(),
        kpasswd_server: Vec::new(),
        master_kdc: Vec::new(),
        primary_kdc: Vec::new(),
        relations: BTreeMap::new(),
        auth_to_local_names: BTreeMap::new(),
    })
}

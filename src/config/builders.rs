//! `LibDefaults` builders and derived accessors.

use alloc::borrow::Cow;
use core::{net::IpAddr, time::Duration};

use super::{ConfigDiagnostic, EnctypeDefaults as _, LibDefaults, ParseMode, Toggle};
use crate::{crypto::s2k::Family, error::Policy};

/// Override a family's minimum through trusted application code only.
///
/// # Errors
/// Rejects zero and minima above the existing 2^24 work ceiling.
pub(super) fn with_min_s2k_iterations(
    mut this: LibDefaults,
    family: Family,
    minimum: u32,
) -> Result<LibDefaults, Policy> {
    this.min_s2k_iterations = this.min_s2k_iterations.with_minimum(family, minimum)?;
    Ok(this)
}

/// Diagnostics for skipped secure enctypes and ignored draft-9 preferences.
/// Serde retains preference IDs for diagnostics, never for outgoing selection.
pub(super) fn diagnostics(this: &LibDefaults) -> Cow<'_, [ConfigDiagnostic]> {
    let ignored = this
        .preferred_preauth_types
        .iter()
        .copied()
        .filter(|id| matches!(*id, 14_i32 | 15_i32));
    let mut diagnostics = Cow::Borrowed(this.enctype_diagnostics.as_slice());
    for id in ignored {
        diagnostics
            .to_mut()
            .push(ConfigDiagnostic::IgnoredPreauthType { id });
    }
    diagnostics
}

/// Parsing mode used for subsequent expression resolution.
pub(super) const fn parse_mode(this: &LibDefaults) -> ParseMode {
    this.enctype_parse_mode
}

/// Stage `allow_weak_crypto`; enabled values are rejected by runtime policy construction.
pub(super) const fn with_allow_weak_crypto(mut this: LibDefaults, value: Toggle) -> LibDefaults {
    this.allow_weak_crypto = value;
    this
}

/// Sets `canonicalize`, preserving the other fields.
pub(super) const fn with_canonicalize(mut this: LibDefaults, value: Toggle) -> LibDefaults {
    this.canonicalize = value;
    this
}

/// Sets `ccache_type`, preserving the other fields.
pub(super) const fn with_ccache_type(mut this: LibDefaults, value: i32) -> LibDefaults {
    this.ccache_type = value;
    this
}

/// Sets `clockskew`, preserving the other fields.
pub(super) const fn with_clockskew(mut this: LibDefaults, value: Duration) -> LibDefaults {
    this.clockskew = value;
    this
}

/// Sets `default_ccache_name`, preserving the other fields.
pub(super) fn with_default_ccache_name(mut this: LibDefaults, value: String) -> LibDefaults {
    this.default_ccache_name = value;
    this
}

/// Sets `default_client_keytab_name`, preserving the other fields.
pub(super) fn with_default_client_keytab_name(mut this: LibDefaults, value: String) -> LibDefaults {
    this.default_client_keytab_name = value;
    this
}

/// Sets `default_keytab_name`, preserving the other fields.
pub(super) fn with_default_keytab_name(mut this: LibDefaults, value: String) -> LibDefaults {
    this.default_keytab_name = value;
    this
}

/// Sets `default_realm`, preserving the other fields.
pub(super) fn with_default_realm(mut this: LibDefaults, value: String) -> LibDefaults {
    this.default_realm = value;
    this
}

/// Sets `default_tgs_enctypes`, preserving the other fields.
pub(super) fn with_default_tgs_enctypes(mut this: LibDefaults, value: Vec<String>) -> LibDefaults {
    this.default_tgs_enctypes = value;
    this
}

/// Sets `default_tkt_enctypes`, preserving the other fields.
pub(super) fn with_default_tkt_enctypes(mut this: LibDefaults, value: Vec<String>) -> LibDefaults {
    this.default_tkt_enctypes = value;
    this
}

/// Derives supported TGS enctype IDs from the current names and policy.
pub(super) fn default_tgs_enctype_ids(this: &LibDefaults) -> Vec<i32> {
    this.effective_enctype_ids(&this.default_tgs_enctypes)
}

/// Derives supported ticket enctype IDs from the current names and policy.
pub(super) fn default_tkt_enctype_ids(this: &LibDefaults) -> Vec<i32> {
    this.effective_enctype_ids(&this.default_tkt_enctypes)
}

/// Sets `dns_canonicalize_hostname`, preserving the other fields.
pub(super) fn with_dns_canonicalize_hostname(mut this: LibDefaults, value: Toggle) -> LibDefaults {
    this.dns_canonicalize_hostname = value.into();
    this
}

/// Sets `dns_lookup_kdc`, preserving the other fields.
pub(super) const fn with_dns_lookup_kdc(mut this: LibDefaults, value: Toggle) -> LibDefaults {
    this.dns_lookup_kdc = value;
    this
}

/// Sets `dns_lookup_realm`, preserving the other fields.
pub(super) const fn with_dns_lookup_realm(mut this: LibDefaults, value: Toggle) -> LibDefaults {
    this.dns_lookup_realm = value;
    this
}

/// Sets `extra_addresses`, preserving the other fields.
pub(super) fn with_extra_addresses(mut this: LibDefaults, value: Vec<IpAddr>) -> LibDefaults {
    this.extra_addresses = value;
    this
}

/// Sets `forwardable`, preserving the other fields.
pub(super) const fn with_forwardable(mut this: LibDefaults, value: Toggle) -> LibDefaults {
    this.forwardable = value;
    this
}

/// Sets `ignore_acceptor_hostname`, preserving the other fields.
pub(super) const fn with_ignore_acceptor_hostname(
    mut this: LibDefaults,
    value: Toggle,
) -> LibDefaults {
    this.ignore_acceptor_hostname = value;
    this
}

/// Sets `k5login_authoritative`, preserving the other fields.
pub(super) const fn with_k5login_authoritative(
    mut this: LibDefaults,
    value: Toggle,
) -> LibDefaults {
    this.k5login_authoritative = value;
    this
}

/// Sets `k5login_directory`, preserving the other fields.
pub(super) fn with_k5login_directory(mut this: LibDefaults, value: String) -> LibDefaults {
    this.k5login_directory = value;
    this
}

/// Sets `kdc_default_options`, preserving the other fields.
pub(super) const fn with_kdc_default_options(mut this: LibDefaults, value: u32) -> LibDefaults {
    this.kdc_default_options = value;
    this
}

/// Sets `kdc_time_sync`, preserving the other fields.
pub(super) const fn with_kdc_time_sync(mut this: LibDefaults, value: i32) -> LibDefaults {
    this.kdc_time_sync = value;
    this
}

/// Sets `no_addresses`, preserving the other fields.
pub(super) const fn with_no_addresses(mut this: LibDefaults, value: Toggle) -> LibDefaults {
    this.no_addresses = value;
    this
}

/// Sets `permitted_enctypes`, preserving the other fields.
pub(super) fn with_permitted_enctypes(mut this: LibDefaults, value: Vec<String>) -> LibDefaults {
    this.permitted_enctypes = value;
    this
}

/// Derives supported permitted enctype IDs from the current names and policy.
pub(super) fn permitted_enctype_ids(this: &LibDefaults) -> Vec<i32> {
    this.effective_enctype_ids(&this.permitted_enctypes)
}

/// Sets `permitted_enctypes_explicit`, preserving the other fields.
pub(super) const fn with_permitted_enctypes_explicit(
    mut this: LibDefaults,
    value: Toggle,
) -> LibDefaults {
    this.permitted_enctypes_explicit = value;
    this
}

/// Sets `preferred_preauth_types`, preserving the other fields.
pub(super) fn with_preferred_preauth_types(mut this: LibDefaults, value: Vec<i32>) -> LibDefaults {
    this.preferred_preauth_types = value;
    this
}

/// Sets `proxiable`, preserving the other fields.
pub(super) const fn with_proxiable(mut this: LibDefaults, value: Toggle) -> LibDefaults {
    this.proxiable = value;
    this
}

/// Sets `rdns`, preserving the other fields.
pub(super) const fn with_rdns(mut this: LibDefaults, value: Toggle) -> LibDefaults {
    this.rdns = value;
    this
}

/// Sets `realm_try_domains`, preserving the other fields.
pub(super) const fn with_realm_try_domains(mut this: LibDefaults, value: i32) -> LibDefaults {
    this.realm_try_domains = value;
    this
}

/// Sets `renew_lifetime`, preserving the other fields.
pub(super) const fn with_renew_lifetime(mut this: LibDefaults, value: Duration) -> LibDefaults {
    this.renew_lifetime = value;
    this
}

/// Stage `safe_checksum_type`; forbidden values are rejected by runtime policy construction.
pub(super) const fn with_safe_checksum_type(mut this: LibDefaults, value: i32) -> LibDefaults {
    this.safe_checksum_type = value;
    this
}

/// Sets `ticket_lifetime`, preserving the other fields.
pub(super) const fn with_ticket_lifetime(mut this: LibDefaults, value: Duration) -> LibDefaults {
    this.ticket_lifetime = value;
    this
}

/// Sets `udp_preference_limit`, preserving the other fields.
pub(super) const fn with_udp_preference_limit(mut this: LibDefaults, value: i32) -> LibDefaults {
    this.udp_preference_limit = value;
    this
}

/// Sets `verify_ap_req_nofail_explicit`, preserving the other fields.
pub(super) const fn with_verify_ap_req_nofail_explicit(
    mut this: LibDefaults,
    value: Toggle,
) -> LibDefaults {
    this.verify_ap_req_nofail_explicit = value;
    this
}

/// Sets `verify_ap_req_nofail`, preserving the other fields.
pub(super) const fn with_verify_ap_req_nofail(mut this: LibDefaults, value: Toggle) -> LibDefaults {
    this.verify_ap_req_nofail = value;
    this
}

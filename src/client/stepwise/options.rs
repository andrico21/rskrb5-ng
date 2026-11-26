//! Request options of the exchanges and their `[libdefaults]` defaults.

use core::{net::IpAddr, time::Duration};
use std::time::SystemTime;

use super::{
    super::{options::AsReq, principal::Principal},
    InitCredsOptions,
};
use crate::{
    config::{Config, Toggle, section_values::Value},
    error::Client as Error,
    extensions::{Interface, order::arrange},
    preauth::{
        pkinit::{AnonymousOptions, KDC_OPTION_REQUEST_ANONYMOUS},
        spake::Policy as SpakePolicy,
    },
};

/// The `forwardable` KDC option bit.
pub(super) const FORWARDABLE: u32 = 0x4000_0000;
/// The `proxiable` KDC option bit.
pub(super) const PROXIABLE: u32 = 0x1000_0000;
/// MIT's default `preferred_preauth_types` (`get_in_tkt.c:421-423`).
const MIT_PREFERRED: [i32; 4] = [17, 16, 15, 14];

/// The `clpreauth` names of the mechanisms the exchange engine implements,
/// in MIT's registration order (`preauth2.c`, `plugin.c:133-146`).
pub(super) const PKINIT: &str = "pkinit";
/// `spake` (RFC 9588).
pub(super) const SPAKE: &str = "spake";
/// `encrypted_challenge` (RFC 6113 section 5.4.6).
pub(super) const ENCRYPTED_CHALLENGE: &str = "encrypted_challenge";
/// `encrypted_timestamp` (`PA-ENC-TIMESTAMP`).
pub(super) const ENCRYPTED_TIMESTAMP: &str = "encrypted_timestamp";
/// `sam2` has no mechanism here; the name is accepted and answers nothing.
const SAM2: &str = "sam2";
/// `otp` (RFC 6560).
pub(super) const OTP: &str = "otp";
/// The built-in mechanisms in MIT's registration order.
const BUILTIN_PREAUTH: [&str; 6] = [
    PKINIT,
    SPAKE,
    ENCRYPTED_CHALLENGE,
    ENCRYPTED_TIMESTAMP,
    SAM2,
    OTP,
];

/// Options with the template's values and none of the profile's.
pub(super) fn from_request(request: AsReq) -> InitCredsOptions {
    InitCredsOptions {
        request,
        service: None,
        kdc_timesync: false,
        preferred_preauth_types: MIT_PREFERRED.to_vec(),
        spake: None,
        timestamp_disabled: Vec::new(),
        builtin_preauth: BUILTIN_PREAUTH.to_vec(),
        anonymous: None,
    }
}

/// Options from `[libdefaults]`.
///
/// # Errors
/// Returns the errors of [`AsReq::from_libdefaults`].
pub(super) fn from_config(
    config: &Config,
    now: SystemTime,
    nonce: u32,
) -> Result<InitCredsOptions, Error> {
    let defaults = &config.libdefaults;
    Ok(InitCredsOptions {
        request: AsReq::from_libdefaults(now, nonce, defaults)?,
        service: None,
        kdc_timesync: defaults.kdc_time_sync != 0,
        preferred_preauth_types: defaults.preferred_preauth_types.clone(),
        spake: Some(SpakePolicy::from_libdefaults(defaults)),
        timestamp_disabled: timestamp_disabled(config),
        builtin_preauth: permitted_builtins(config),
        anonymous: None,
    })
}

/// The built-in mechanisms `[plugins] clpreauth` leaves in use.
///
/// MIT's name-level arrangement (`plugin.c:302-347`) over the built-in names,
/// case-sensitive: `disable` removes and a non-empty `enable_only` keeps.
fn permitted_builtins(config: &Config) -> Vec<&'static str> {
    arrange(Interface::ClientPreauth, config, BUILTIN_PREAUTH)
}

/// Whether the client may send an encrypted timestamp as `realm`: neither the
/// realm's `disable_encrypted_timestamp` nor `[plugins] clpreauth` excludes it.
pub(in crate::client) fn timestamp_permitted(config: &Config, realm: &str) -> bool {
    permitted_builtins(config).contains(&ENCRYPTED_TIMESTAMP)
        && !timestamp_disabled(config).iter().any(|name| name == realm)
}

/// The realms whose `disable_encrypted_timestamp` is set; any value other than
/// an explicit `false` counts as set (fail closed).
pub(in crate::client) fn timestamp_disabled(config: &Config) -> Vec<String> {
    config
        .realms
        .iter()
        .filter(|realm| {
            realm
                .relations
                .get("disable_encrypted_timestamp")
                .is_some_and(|value| !matches!(value, Value::Boolean(Toggle::Disabled)))
        })
        .map(|realm| realm.name.clone())
        .collect()
}

/// Whether the built-in mechanism `name` is in use for these options.
pub(super) fn permits(options: &InitCredsOptions, name: &str) -> bool {
    options.builtin_preauth.contains(&name)
}

/// Adopt `config`: its SPAKE groups unless a policy is set, its
/// timestamp-disabled realms in addition to the ones already set, and the
/// built-in mechanisms both it and the options leave in use.
pub(super) fn adopt(options: &mut InitCredsOptions, config: &Config) {
    let permitted = permitted_builtins(config);
    options
        .builtin_preauth
        .retain(|name| permitted.contains(name));
    if options.spake.is_none() {
        options.spake = Some(SpakePolicy::from_libdefaults(&config.libdefaults));
    }
    for realm in timestamp_disabled(config) {
        if !options.timestamp_disabled.contains(&realm) {
            options.timestamp_disabled.push(realm);
        }
    }
}

/// Set the SPAKE policy.
pub(super) fn with_spake(mut options: InitCredsOptions, policy: SpakePolicy) -> InitCredsOptions {
    options.spake = Some(policy);
    options
}

/// Ask for anonymous credentials: the `request-anonymous` KDC option.
pub(super) fn with_anonymous(
    options: InitCredsOptions,
    anonymous: AnonymousOptions,
) -> InitCredsOptions {
    let mut flagged = with_flag(options, KDC_OPTION_REQUEST_ANONYMOUS, true);
    flagged.anonymous = Some(anonymous);
    flagged
}

/// Request another service.
pub(super) fn with_service(mut options: InitCredsOptions, service: Principal) -> InitCredsOptions {
    options.service = Some(service);
    options
}

/// Set or clear one KDC option bit.
pub(super) fn with_flag(mut options: InitCredsOptions, bit: u32, set: bool) -> InitCredsOptions {
    let bits = options.request.kdc_option_bits();
    options.request =
        options
            .request
            .with_kdc_option_bits(if set { bits | bit } else { bits & !bit });
    options
}

/// Set the ticket lifetime.
pub(super) fn with_ticket_lifetime(
    mut options: InitCredsOptions,
    lifetime: Duration,
) -> InitCredsOptions {
    options.request = options.request.with_ticket_lifetime(lifetime);
    options
}

/// Set the renewable lifetime.
pub(super) fn with_renew_lifetime(
    mut options: InitCredsOptions,
    lifetime: Option<Duration>,
) -> InitCredsOptions {
    options.request = options.request.with_renew_lifetime(lifetime);
    options
}

/// Set the request addresses.
pub(super) fn with_addresses(
    mut options: InitCredsOptions,
    addresses: Vec<IpAddr>,
) -> InitCredsOptions {
    options.request = options.request.with_addresses(addresses);
    options
}

/// Set the preferred PA types.
pub(super) fn with_preferred(mut options: InitCredsOptions, types: Vec<i32>) -> InitCredsOptions {
    options.preferred_preauth_types = types;
    options
}

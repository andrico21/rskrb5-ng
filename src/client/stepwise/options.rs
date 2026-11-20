//! Request options of the exchanges and their `[libdefaults]` defaults.

use core::{net::IpAddr, time::Duration};
use std::time::SystemTime;

use super::{
    super::{options::AsReq, principal::Principal},
    InitCredsOptions,
};
use crate::{config::Config, error::Client as Error};

/// The `forwardable` KDC option bit.
pub(super) const FORWARDABLE: u32 = 0x4000_0000;
/// The `proxiable` KDC option bit.
pub(super) const PROXIABLE: u32 = 0x1000_0000;
/// MIT's default `preferred_preauth_types` (`get_in_tkt.c:421-423`).
const MIT_PREFERRED: [i32; 4] = [17, 16, 15, 14];

/// Options with the template's values and none of the profile's.
pub(super) fn from_request(request: AsReq) -> InitCredsOptions {
    InitCredsOptions {
        request,
        service: None,
        kdc_timesync: false,
        preferred_preauth_types: MIT_PREFERRED.to_vec(),
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
    })
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

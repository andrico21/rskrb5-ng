//! Remaining MIT libdefaults scalars, without discovery or plugin loading.

use core::time::Duration;

use super::{
    super::{Error, LibDefaults, Line, Toggle, invalid_integer, parse_boolean, parse_i32},
    duration,
};

/// Decode newly recognized C2 relations into the existing typed configuration.
/// # Errors
/// Returns typed boolean, duration, integer or list-token errors at admission.
pub(crate) fn parse(defaults: &mut LibDefaults, line: &Line) -> Result<(), Error> {
    let (key, value) = super::super::parse_assignment(line, "libdefaults")?;
    match key {
        "kcm_mach_service" => value.clone_into(&mut defaults.kcm_mach_service),
        "kcm_socket" => value.clone_into(&mut defaults.kcm_socket),
        "plugin_base_dir" => value.clone_into(&mut defaults.plugin_base_dir),
        "qualify_shortname" => defaults.qualify_shortname = Some(value.to_owned()),
        "request_timeout" => defaults.request_timeout = duration::parse(value)?,
        "client_aware_channel_bindings" => {
            defaults.client_aware_channel_bindings = Toggle::from_bool(parse_boolean(value)?);
        }
        "spake_preauth_groups" => {
            // MIT groups.c: strtok_r delimiters are exactly " \t\r\n,"; FF and VT stay token bytes.
            defaults.spake_preauth_groups = value
                .split([',', ' ', '\t', '\r', '\n'])
                .filter(|word| !word.is_empty())
                .map(|word| {
                    ["edwards25519", "P-256", "P-384", "P-521"]
                        .into_iter()
                        .find(|known| known.eq_ignore_ascii_case(word))
                        .map(str::to_owned)
                        .ok_or_else(|| Error::InvalidLine {
                            section: "libdefaults",
                            line: line.number,
                            text: line.text.clone(),
                        })
                })
                .collect::<Result<Vec<_>, _>>()?;
        }
        _ => {}
    }
    Ok(())
}

/// MIT reads decimal signed integers; retain explicitly prefixed hex as an extension.
/// # Errors
/// Rejects malformed numbers and values outside the underlying 32-bit representation.
pub(crate) fn option_bits(value: &str, line: &Line) -> Result<u32, Error> {
    if let Some(digits) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u32::from_str_radix(digits, 16)
            .map_err(|_invalid| invalid_integer(value, line, "kdc_default_options"))
    } else {
        let signed = parse_i32(value, line, "kdc_default_options")?;
        Ok(u32::from_be_bytes(signed.to_be_bytes()))
    }
}

/// Whether ignoring a C2 setting would weaken the currently implemented behavior.
pub(super) fn stricter(defaults: &LibDefaults, relation: &str) -> bool {
    match relation {
        "noaddresses" | "no_addresses" => !defaults.no_addresses.is_enabled(),
        "request_timeout" => defaults.request_timeout != Duration::ZERO,
        "verify_ap_req_nofail" => defaults.verify_ap_req_nofail.is_enabled(),
        "client_aware_channel_bindings" => defaults.client_aware_channel_bindings.is_enabled(),
        _ => false,
    }
}

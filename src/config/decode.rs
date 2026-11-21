//! Typed decoding of `[libdefaults]` and `[realms]` relation lines.

use core::net::{IpAddr, SocketAddr};

use super::{
    EnctypeDefaults as _, EnctypeExpr, EnctypeParseState, LibDefaults, Line, Realm, Toggle,
    hostname, parse_boolean, profile_syntax, protocol, sections::parse_assignment,
};
use crate::{crypto::selection, error::Config as Error};

/// Apply one `[libdefaults]` section's lines, recording in `enctypes` which
/// request enctype lists the section set explicitly.
///
/// # Errors
/// Returns an error for malformed assignments, enabling removed protocols,
/// invalid scalar values or unknown enctype tokens. Records expressions for
/// final family-permission and request/permitted validation after all sections;
/// `Config::parse` never returns a configuration with deferred parse errors.
pub(super) fn parse_lines(
    this: &mut LibDefaults,
    lines: &[Line],
    enctypes: &mut EnctypeParseState,
) -> Result<(), Error> {
    for line in lines {
        let (key, value) = parse_assignment(line, "libdefaults")?;
        protocol::relation(key, value)?;

        match key {
            "allow_rc4" => this.allow_rc4 = Toggle::from_bool(parse_boolean(value)?),
            "allow_des3" => this.allow_des3 = Toggle::from_bool(parse_boolean(value)?),
            "allow_weak_crypto" => {
                this.allow_weak_crypto = Toggle::from_bool(parse_boolean(value)?);
                this.reject_weak_crypto()?;
            }
            "canonicalize" => this.canonicalize = Toggle::from_bool(parse_boolean(value)?),
            "ccache_type" => this.ccache_type = parse_i32(value, line, key)?,
            "clockskew" => this.clockskew = super::libdefaults::duration::parse(value)?,
            "default_ccache_name" => value.clone_into(&mut this.default_ccache_name),
            "default_client_keytab_name" => {
                value.clone_into(&mut this.default_client_keytab_name);
            }
            "default_keytab_name" => value.clone_into(&mut this.default_keytab_name),
            "default_rcache_name" => value.clone_into(&mut this.default_rcache_name),
            "err_fmt" => value.clone_into(&mut this.err_fmt),
            "default_realm" => value.clone_into(&mut this.default_realm),
            "default_tgs_enctypes" => {
                enctypes.expressions.push(EnctypeExpr::parse(value)?);
                this.default_tgs_enctypes = vec![value.to_owned()];
                enctypes.tgs_explicit = true;
            }
            "default_tkt_enctypes" => {
                enctypes.expressions.push(EnctypeExpr::parse(value)?);
                this.default_tkt_enctypes = vec![value.to_owned()];
                enctypes.tkt_explicit = true;
            }
            "dns_canonicalize_hostname" => {
                this.dns_canonicalize_hostname = hostname::Canonicalization::parse(value)?;
            }
            "dns_lookup_kdc" => this.dns_lookup_kdc = Toggle::from_bool(parse_boolean(value)?),
            "dns_lookup_realm" => {
                this.dns_lookup_realm = Toggle::from_bool(parse_boolean(value)?);
            }
            "dns_uri_lookup" => this.dns_uri_lookup = Toggle::from_bool(parse_boolean(value)?),
            "enforce_ok_as_delegate" => {
                this.enforce_ok_as_delegate = Toggle::from_bool(parse_boolean(value)?);
            }
            "extra_addresses" => this.extra_addresses = parse_ip_addresses(value)?,
            "forwardable" => this.forwardable = Toggle::from_bool(parse_boolean(value)?),
            "ignore_acceptor_hostname" => {
                this.ignore_acceptor_hostname = Toggle::from_bool(parse_boolean(value)?);
            }
            "k5login_authoritative" => {
                this.k5login_authoritative = Toggle::from_bool(parse_boolean(value)?);
            }
            "k5login_directory" => value.clone_into(&mut this.k5login_directory),
            "kdc_default_options" => {
                this.kdc_default_options = super::libdefaults::c2::option_bits(value, line)?;
            }
            "kdc_timesync" => this.kdc_time_sync = parse_i32(value, line, key)?,
            "noaddresses" | "no_addresses" => {
                this.no_addresses = Toggle::from_bool(parse_boolean(value)?);
            }
            "permitted_enctypes" => {
                enctypes.expressions.push(EnctypeExpr::parse(value)?);
                this.permitted_enctypes = vec![value.to_owned()];
                this.permitted_enctypes_explicit = Toggle::Enabled;
            }
            "preferred_preauth_types" => {
                this.preferred_preauth_types = parse_i32_list(value, line, key)?;
            }
            "proxiable" => this.proxiable = Toggle::from_bool(parse_boolean(value)?),
            "rdns" => this.rdns = Toggle::from_bool(parse_boolean(value)?),
            "realm_try_domains" => this.realm_try_domains = parse_i32(value, line, key)?,
            "renew_lifetime" => this.renew_lifetime = super::libdefaults::duration::parse(value)?,
            "safe_checksum_type" => {
                let id = selection::checksum_name(value)
                    .map_or_else(|| parse_i32(value, line, key), Ok)?;
                selection::reject_checksum(id)?;
                this.safe_checksum_type = id;
            }
            "ticket_lifetime" => this.ticket_lifetime = super::libdefaults::duration::parse(value)?,
            "udp_preference_limit" => {
                this.udp_preference_limit = parse_i32(value, line, key)?;
            }
            "verify_ap_req_nofail" => {
                this.verify_ap_req_nofail = Toggle::from_bool(parse_boolean(value)?);
                this.verify_ap_req_nofail_explicit = Toggle::Enabled;
            }
            _ => super::libdefaults::c2::parse(this, line)?,
        }
    }

    Ok(())
}

/// Parse the lines of one realm's `{ ... }` block.
///
/// # Errors
/// Returns [`Error::InvalidLine`] for a line that is not an assignment, and
/// [`Error::Policy`] for an enabled removed-protocol directive.
pub(super) fn realm(name: &str, lines: &[Line]) -> Result<Realm, Error> {
    let mut realm = Realm::new(name.to_owned())?;

    for line in lines {
        let (key, value) = parse_assignment(line, "realms")?;
        protocol::relation(key, value)?;

        match key {
            "admin_server" => {
                realm.admin_server.push(value.to_owned());
            }
            "default_domain" => value.clone_into(&mut realm.default_domain),
            "kdc" => {
                let with_port = add_default_port(value, 88);
                realm.kdc.push(with_port);
            }
            "kpasswd_server" => {
                realm.kpasswd_server.push(value.to_owned());
            }
            "master_kdc" => {
                realm.master_kdc.push(value.to_owned());
            }
            "primary_kdc" => realm.primary_kdc.push(value.to_owned()),
            _ => {}
        }
    }

    if realm.primary_kdc.is_empty() {
        realm.primary_kdc.clone_from(&realm.master_kdc);
    }
    if realm.kpasswd_server.is_empty() {
        realm.kpasswd_server = realm
            .admin_server
            .iter()
            .map(|admin| {
                if let Ok(address) = admin.parse::<SocketAddr>() {
                    return SocketAddr::new(address.ip(), 464).to_string();
                }
                if let Ok(address) = admin.parse::<IpAddr>() {
                    return SocketAddr::new(address, 464).to_string();
                }
                let host = admin.strip_circumfix('[', ']').unwrap_or_else(|| {
                    admin
                        .split_once(':')
                        .map_or(admin.as_str(), |(host, _)| host)
                });
                if host.contains(':') {
                    format!("[{host}]:464")
                } else {
                    format!("{host}:464")
                }
            })
            .collect();
    }

    Ok(realm)
}

/// Parse a decimal `i32` value of `key`.
///
/// # Errors
///
/// Returns [`Error::InvalidInteger`] when the value is not a decimal `i32`.
pub(super) fn parse_i32(value: &str, line: &Line, key: &str) -> Result<i32, Error> {
    value
        .parse()
        .ok()
        .ok_or_else(|| invalid_integer(value, line, key))
}

/// Parse a list of decimal `i32` values of `key`, separated by commas or
/// whitespace.
///
/// # Errors
///
/// Returns [`Error::InvalidInteger`] for the first item that is not a decimal
/// `i32`.
pub(super) fn parse_i32_list(value: &str, line: &Line, key: &str) -> Result<Vec<i32>, Error> {
    value
        .split([',', ' ', '\t'])
        .filter(|part| !part.trim_matches(profile_syntax::tag_whitespace).is_empty())
        .map(|part| parse_i32(part.trim_matches(profile_syntax::tag_whitespace), line, key))
        .collect()
}

/// The [`Error::InvalidInteger`] for `value` of `key` on `line`.
pub(super) fn invalid_integer(value: &str, line: &Line, key: &str) -> Error {
    Error::InvalidInteger {
        line: line.number,
        key: key.to_owned(),
        value: value.to_owned(),
    }
}

/// Decode an address list without silently narrowing malformed input.
/// # Errors
/// Returns a typed failure naming the malformed address token.
pub(super) fn parse_ip_addresses(value: &str) -> Result<Vec<IpAddr>, Error> {
    value
        .split(|ch: char| ch == ',' || profile_syntax::tag_whitespace(ch))
        .filter(|part| !part.is_empty())
        .map(|part| {
            part.parse()
                .map_err(|_invalid_address| Error::InvalidAddress(part.to_owned()))
        })
        .collect()
}

/// Append a default port to a literal endpoint already admitted by the profile.
pub(super) fn add_default_port(value: &str, port: u16) -> String {
    if value.contains(':') {
        value.to_owned()
    } else {
        format!("{value}:{port}")
    }
}

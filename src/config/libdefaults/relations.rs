//! C1 documentation source of truth, pinned to MIT krb5-1.22.2-final.
//!
//! Defaults: <https://web.mit.edu/kerberos/krb5-1.22/doc/admin/conf_files/krb5_conf.html#libdefaults>.
//! Grammar: `src/util/profile/prof_get.c` and `src/lib/krb5/krb/x-deltat.y` at that tag.
//! All entries are scalar profile lookups, including the list-valued relations.

/// The rows `ignore_acceptor_hostname` through `client_aware_channel_bindings`.
#[path = "relations/tail.rs"]
mod tail;

/// Columns: name, value kind, MIT default, consumer/package, classification, test.
///
/// Step F reads the literal rows of [`RELATIONS_HEAD`] and `tail::RELATIONS_TAIL`, in
/// that order, to generate and check the relation document.
pub(crate) const RELATIONS: [(&str, &str, &str, &str, &str, &str); 43] = {
    let mut rows = [("", "", "", "", "", ""); 43];
    let (head, tail) = rows.split_at_mut(RELATIONS_HEAD.len());
    head.copy_from_slice(&RELATIONS_HEAD);
    tail.copy_from_slice(&tail::RELATIONS_TAIL);
    rows
};

/// The rows `allow_des3` through `forwardable`, in catalogue order.
pub(crate) const RELATIONS_HEAD: [(&str, &str, &str, &str, &str, &str); 21] = [
    (
        "allow_des3",
        "boolean",
        "false",
        "CryptoPolicy::from_libdefaults",
        "Effective client-side too, stricter than MIT's KDC-only permission",
        "allow_des3",
    ),
    (
        "allow_rc4",
        "boolean",
        "false",
        "CryptoPolicy::from_libdefaults",
        "Effective client-side too, stricter than MIT's KDC-only permission",
        "allow_rc4",
    ),
    (
        "allow_weak_crypto",
        "boolean",
        "false",
        "LibDefaults::reject_weak_crypto",
        "true permanently rejected by POL-01",
        "allow_weak_crypto",
    ),
    (
        "canonicalize",
        "boolean",
        "false",
        "plan 2 WP-04",
        "TGS option consumed; AS builders suppress canonicalization, preserving identity; either value diagnostic",
        "canonicalize",
    ),
    (
        "ccache_type",
        "signed decimal i32",
        "4",
        "CacheVersion::from_libdefaults; TokioClient::to_ccache",
        "Effective: caches the stores and the client write-back create or replace use versions 1 to 4; another value is InvalidCacheType at use, where MIT writes a file no reader accepts",
        "ccache_type",
    ),
    (
        "clockskew",
        "duration",
        "300 seconds",
        "AsReq::from_libdefaults; TgsReq::from_libdefaults; Validator::from_default_keytab_name",
        "Effective; MIT init reads integer seconds, time syntax is an extension; negative tolerance rejected",
        "clockskew",
    ),
    (
        "default_ccache_name",
        "parameter template",
        "DEFCCNAME",
        "TokioClient::from_default_ccache_name",
        "Effective B2 expansion; missing username, Windows USERID/SID, LIBDIR/BINDIR/SBINDIR facts error at resolution, never credential fallback; crate default unset",
        "default_ccache_name",
    ),
    (
        "default_client_keytab_name",
        "parameter template",
        "DEFCKTNAME",
        "TokioClient::with_client_keytab_from_config",
        "Effective B2 expansion; missing username, Windows USERID/SID, LIBDIR/BINDIR/SBINDIR facts error at resolution, never credential fallback",
        "default_client_keytab_name",
    ),
    (
        "default_keytab_name",
        "parameter template",
        "DEFKTNAME",
        "Validator::from_default_keytab_name",
        "Effective B2 expansion; missing username, Windows USERID/SID, LIBDIR/BINDIR/SBINDIR facts error at resolution, never credential fallback",
        "default_keytab_name",
    ),
    (
        "default_rcache_name",
        "parameter template",
        "dfl:",
        "plan 2 WP-20",
        "Any value except none: requires unavailable persistent/shared replay protection and errors; none: diagnostic because memory replay protection remains",
        "default_rcache_name",
    ),
    (
        "default_realm",
        "string",
        "unset",
        "Config::realm_for_host; client::service_realm",
        "Effective fallback after domain mapping; explicit service realm remains authoritative",
        "default_realm",
    ),
    (
        "default_tgs_enctypes",
        "enctype expression",
        "permitted_enctypes",
        "TgsReq::from_libdefaults",
        "Effective WP-02; AES SHA2-first default, forbidden positives error",
        "default_tgs_enctypes",
    ),
    (
        "default_tkt_enctypes",
        "enctype expression",
        "permitted_enctypes",
        "AsReq::from_libdefaults",
        "Effective WP-02; AES SHA2-first default, forbidden positives error",
        "default_tkt_enctypes",
    ),
    (
        "dns_canonicalize_hostname",
        "boolean or fallback",
        "true",
        "plan 2 WP-10",
        "No DNS canonicalization occurs; all values diagnostic, including fallback per todo 15",
        "dns_canonicalize_hostname",
    ),
    (
        "dns_lookup_kdc",
        "boolean",
        "true when built with DNS support",
        "client::transport::discover_kdcs",
        "Effective SRV switch; crate default false avoids ambient DNS",
        "dns_lookup_kdc",
    ),
    (
        "dns_lookup_realm",
        "boolean",
        "false",
        "plan 2 WP-10",
        "No TXT realm discovery occurs; false satisfied, true cannot relax behavior; diagnostic",
        "dns_lookup_realm",
    ),
    (
        "dns_uri_lookup",
        "boolean",
        "true",
        "plan 2 WP-10",
        "No URI discovery occurs; false satisfied, true cannot relax behavior; diagnostic; crate default false",
        "dns_uri_lookup",
    ),
    (
        "enforce_ok_as_delegate",
        "boolean",
        "false",
        "plan 2 WP-12",
        "GSS credential forwarding is unavailable; no credentials delegated, so true already satisfied; diagnostic",
        "enforce_ok_as_delegate",
    ),
    (
        "err_fmt",
        "string",
        "unset",
        "plan 2 WP-18",
        "Formatting does not alter typed errors or authentication policy; diagnostic",
        "err_fmt",
    ),
    (
        "extra_addresses",
        "IP address list",
        "unset",
        "plan 2 WP-04",
        "Ignored when noaddresses=true; nonempty list with noaddresses=false requires unavailable address-bound requests and errors",
        "extra_addresses",
    ),
    (
        "forwardable",
        "boolean",
        "false",
        "AsReq::from_libdefaults; TgsReq::from_libdefaults",
        "Effective forwardable bit; explicit false overrides raw KDC option bit",
        "forwardable",
    ),
];

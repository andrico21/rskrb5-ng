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
        "AsReq::from_libdefaults; TgsReq::from_libdefaults; preauth::fast::Exchange",
        "Effective under FAST: the armored AS request asks for canonicalization and a changed client is accepted only from KrbFastFinished; unarmored AS requests drop the option (no unauthenticated identity change, stricter than MIT); TGS option consumed",
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
        "replay::RcacheName::default_for",
        "Effective: dfl:, file2:<path>, none: and memory: select the replay store of replay::RcacheName::open; a malformed or unknown-type name is refused when the profile is read",
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
        "discovery::hostname::CanonicalizationPolicy::acquire through client::Tokio::get_host_service_ticket, gss::Credential::acquire_host_service_ticket and http::agent::NegotiateHttpClient::with_host_name_policy",
        "Effective: true canonicalizes the host with DNS, false never does, fallback tries the plain name first; no client route canonicalizes a host implicitly",
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
        "discovery::realm::HostRealmResolver",
        "Effective opt-in TXT realm lookup for service hosts and fallback realms; never read when false",
        "dns_lookup_realm",
    ),
    (
        "dns_uri_lookup",
        "boolean",
        "true",
        "discovery::locate::ServerLocator",
        "Effective URI-before-SRV discovery under dns_lookup_kdc; crate default false",
        "dns_uri_lookup",
    ),
    (
        "enforce_ok_as_delegate",
        "boolean",
        "false",
        "gss::InitiatorOptions::from_config",
        "Effective for GSS initiators: true turns a delegation request into the delegation-policy flag, so the TGT is forwarded only to services whose ticket carries OK-AS-DELEGATE",
        "enforce_ok_as_delegate",
    ),
    (
        "err_fmt",
        "string",
        "unset",
        "ErrFmt::from_config; ErrFmt::report",
        "Effective as presentation only: %M is the message, %C the MIT code of a KDC refusal (0 when the error has none), %% a percent; the typed error, its code and its sources are unchanged; empty counts as unset",
        "err_fmt",
    ),
    (
        "extra_addresses",
        "IP address list",
        "unset",
        "AsReq::from_libdefaults; InitCredsOptions::from_config",
        "Effective with noaddresses=false as the request addresses; MIT also adds interface addresses, which this library does not enumerate; ignored when noaddresses=true",
        "extra_addresses",
    ),
    (
        "forwardable",
        "boolean",
        "false",
        "AsReq::from_libdefaults; TgsReq::from_libdefaults; InitCredsOptions::from_config",
        "Effective forwardable bit; explicit false overrides raw KDC option bit",
        "forwardable",
    ),
];

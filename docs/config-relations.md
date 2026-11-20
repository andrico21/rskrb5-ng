# Configuration relations

Generated from the three Rust relation tables. Do not edit by hand.
Regenerate with `python3 scripts/check-config-relations.py --write`.

Reference: [MIT krb5 1.22 documentation](https://web.mit.edu/kerberos/krb5-1.22/doc/admin/conf_files/krb5_conf.html).
Defaults below are MIT's; stricter library defaults and unavailable consumers
are noted in the classification. See [profile semantics](config-profile.md)
and [security policy](security-policy.md) for explicit divergences and limits.
Compatible mode reports deferred or unknown policy; Strict rejects every
diagnostic. Unsupported settings that would tighten current behavior fail in
both modes. Parsed values do not imply an implemented mechanism.

## libdefaults (43)

| Section | Relation | Typed value | MIT default | Effective consumer / package | Fail-closed classification | Test |
| --- | --- | --- | --- | --- | --- | --- |
| libdefaults | allow_des3 | boolean | false | CryptoPolicy::from_libdefaults | Effective client-side too, stricter than MIT's KDC-only permission | allow_des3 |
| libdefaults | allow_rc4 | boolean | false | CryptoPolicy::from_libdefaults | Effective client-side too, stricter than MIT's KDC-only permission | allow_rc4 |
| libdefaults | allow_weak_crypto | boolean | false | LibDefaults::reject_weak_crypto | true permanently rejected by POL-01 | allow_weak_crypto |
| libdefaults | canonicalize | boolean | false | AsReq::from_libdefaults; TgsReq::from_libdefaults; preauth::fast::Exchange | Effective under FAST: the armored AS request asks for canonicalization and a changed client is accepted only from KrbFastFinished; unarmored AS requests drop the option (no unauthenticated identity change, stricter than MIT); TGS option consumed | canonicalize |
| libdefaults | ccache_type | signed decimal i32 | 4 | CacheVersion::from_libdefaults; TokioClient::to_ccache | Effective: caches the stores and the client write-back create or replace use versions 1 to 4; another value is InvalidCacheType at use, where MIT writes a file no reader accepts | ccache_type |
| libdefaults | clockskew | duration | 300 seconds | AsReq::from_libdefaults; TgsReq::from_libdefaults; Validator::from_default_keytab_name | Effective; MIT init reads integer seconds, time syntax is an extension; negative tolerance rejected | clockskew |
| libdefaults | default_ccache_name | parameter template | DEFCCNAME | TokioClient::from_default_ccache_name | Effective B2 expansion; missing username, Windows USERID/SID, LIBDIR/BINDIR/SBINDIR facts error at resolution, never credential fallback; crate default unset | default_ccache_name |
| libdefaults | default_client_keytab_name | parameter template | DEFCKTNAME | TokioClient::with_client_keytab_from_config | Effective B2 expansion; missing username, Windows USERID/SID, LIBDIR/BINDIR/SBINDIR facts error at resolution, never credential fallback | default_client_keytab_name |
| libdefaults | default_keytab_name | parameter template | DEFKTNAME | Validator::from_default_keytab_name | Effective B2 expansion; missing username, Windows USERID/SID, LIBDIR/BINDIR/SBINDIR facts error at resolution, never credential fallback | default_keytab_name |
| libdefaults | default_rcache_name | parameter template | dfl: | plan 2 WP-20 | Any value except none: requires unavailable persistent/shared replay protection and errors; none: diagnostic because memory replay protection remains | default_rcache_name |
| libdefaults | default_realm | string | unset | Config::realm_for_host; client::service_realm | Effective fallback after domain mapping; explicit service realm remains authoritative | default_realm |
| libdefaults | default_tgs_enctypes | enctype expression | permitted_enctypes | TgsReq::from_libdefaults | Effective WP-02; AES SHA2-first default, forbidden positives error | default_tgs_enctypes |
| libdefaults | default_tkt_enctypes | enctype expression | permitted_enctypes | AsReq::from_libdefaults | Effective WP-02; AES SHA2-first default, forbidden positives error | default_tkt_enctypes |
| libdefaults | dns_canonicalize_hostname | boolean or fallback | true | discovery::hostname::CanonicalizationPolicy | Effective: true canonicalizes the host with DNS, false never does, fallback tries the plain name first; no client route canonicalizes a host implicitly | dns_canonicalize_hostname |
| libdefaults | dns_lookup_kdc | boolean | true when built with DNS support | client::transport::discover_kdcs | Effective SRV switch; crate default false avoids ambient DNS | dns_lookup_kdc |
| libdefaults | dns_lookup_realm | boolean | false | discovery::realm::HostRealmResolver | Effective opt-in TXT realm lookup for service hosts and fallback realms; never read when false | dns_lookup_realm |
| libdefaults | dns_uri_lookup | boolean | true | discovery::locate::ServerLocator | Effective URI-before-SRV discovery under dns_lookup_kdc; crate default false | dns_uri_lookup |
| libdefaults | enforce_ok_as_delegate | boolean | false | plan 2 WP-12 | GSS credential forwarding is unavailable; no credentials delegated, so true already satisfied; diagnostic | enforce_ok_as_delegate |
| libdefaults | err_fmt | string | unset | ErrFmt::from_config; ErrFmt::report | Effective as presentation only: %M is the message, %C the MIT code of a KDC refusal (0 when the error has none), %% a percent; the typed error, its code and its sources are unchanged; empty counts as unset | err_fmt |
| libdefaults | extra_addresses | IP address list | unset | AsReq::from_libdefaults; InitCredsOptions::from_config | Effective with noaddresses=false as the request addresses; MIT also adds interface addresses, which this library does not enumerate; ignored when noaddresses=true | extra_addresses |
| libdefaults | forwardable | boolean | false | AsReq::from_libdefaults; TgsReq::from_libdefaults; InitCredsOptions::from_config | Effective forwardable bit; explicit false overrides raw KDC option bit | forwardable |
| libdefaults | ignore_acceptor_hostname | boolean | false | plan 2 WP-12 | No GSS acceptor-name relaxation; strict service/keytab identity checks retained; either value diagnostic | ignore_acceptor_hostname |
| libdefaults | k5login_authoritative | boolean | true | plan 2 WP-17 | No local-login authorization exists; neither value grants login; diagnostic | k5login_authoritative |
| libdefaults | k5login_directory | string | unset: user home/.k5login | plan 2 WP-17 | No local-login authorization or file lookup occurs; diagnostic | k5login_directory |
| libdefaults | kcm_mach_service | string | org.h5l.kcm | plan 2 WP-09 | No KCM connection exists, including when - disables Mach RPC; diagnostic | kcm_mach_service |
| libdefaults | kcm_socket | string | /var/run/.heim_org.h5l.kcm-socket | kcm::Store::from_libdefaults | Effective for KCM stores built from the configuration: names the daemon socket; - or an empty value disables the Unix socket transport (Kcm::NoServer); the KCM: name routes and the client keep the default socket until plan 2 todo 28 | kcm_socket |
| libdefaults | kdc_default_options | signed decimal i32 bits; explicit 0x extension | 16 (KDC_OPT_RENEWABLE_OK) | AsReq::from_libdefaults; TgsReq::from_libdefaults | Effective except security-preserving AS canonicalize suppression and boolean option overrides; scalar first-wins | kdc_default_options |
| libdefaults | kdc_timesync | signed decimal i32 | 1 | InitCredsOptions::from_config; InitCreds | Effective in the exchange engine: nonzero adopts the KDC clock of a preauthentication error and of the AS-REP; the AsReq login functions keep the strict reply start-time check | kdc_timesync |
| libdefaults | noaddresses | boolean | true | AsReq::from_libdefaults; InitCredsOptions::from_config | Effective: true omits addresses; false binds requests to extra_addresses and fails closed with NoRequestAddresses without them | noaddresses |
| libdefaults | permitted_enctypes | enctype expression | aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 aes256-cts-hmac-sha384-192 aes128-cts-hmac-sha256-128 des3-cbc-sha1 arcfour-hmac-md5 camellia256-cts-cmac camellia128-cts-cmac | CryptoPolicy::from_libdefaults | Effective everywhere via WP-02; crate AES SHA2-first default, explicit forbidden positives rejected | permitted_enctypes |
| libdefaults | plugin_base_dir | parameter template | %{LIBDIR}/krb5/plugins | plan 2 WP-16 | Inert template, no expansion/discovery or executable code loading; diagnostic | plugin_base_dir |
| libdefaults | preferred_preauth_types | signed decimal i32 list | 17,16,15,14 | InitCredsOptions::from_config; InitCreds::with_preauth | Effective order of the KDC offers between registered mechanisms and encrypted timestamp; not an allowlist; draft-9 IDs 14/15 ignored with IgnoredPreauthType | preferred_preauth_types |
| libdefaults | proxiable | boolean | false | AsReq::from_libdefaults; TgsReq::from_libdefaults; InitCredsOptions::from_config | Effective proxiable bit; false clears conflicting raw bit | proxiable |
| libdefaults | qualify_shortname | optional string | first system DNS search domain | discovery::hostname::CanonicalizationPolicy | Effective suffix of a one-label name that DNS did not canonicalize; unset adds none because the system resolver configuration is not read to name a service, empty disables | qualify_shortname |
| libdefaults | rdns | boolean | true | discovery::hostname::CanonicalizationPolicy | Effective reverse lookup after the forward lookup of DNS canonicalization; false skips it | rdns |
| libdefaults | realm_try_domains | signed decimal i32 | -1 | discovery::realm::HostRealmResolver | Effective bounded search of the host's domain and parents for a realm; negative disables | realm_try_domains |
| libdefaults | renew_lifetime | duration | 0 | AsReq::from_libdefaults; TgsReq::from_libdefaults | Effective optional renewable lifetime, zero disables renewal; checked MIT intervals | renew_lifetime |
| libdefaults | request_timeout | duration | 0 | client::transport::Tokio::send_to_realm | Effective total budget over DNS, connect, retries and read of each KDC and kpasswd request; zero is no budget | request_timeout |
| libdefaults | spake_preauth_groups | SPAKE group name list | edwards25519 (client) | plan 2 WP-07 | No SPAKE group is used; allowed-group lists do not require SPAKE; diagnostic; unknown names rejected rather than skipped | spake_preauth_groups |
| libdefaults | ticket_lifetime | duration | 1 day | AsReq::from_libdefaults; TgsReq::from_libdefaults | Effective request lifetime; checked MIT intervals | ticket_lifetime |
| libdefaults | udp_preference_limit | signed decimal i32 | 1465 | client::transport::auto_uses_udp_first | Effective only in Auto transport; negative uses MIT default, large values capped at 32700 | udp_preference_limit |
| libdefaults | verify_ap_req_nofail | boolean | false | plan 2 WP-11 | true requires unavailable verify-init-creds orchestration and errors; false diagnostic | verify_ap_req_nofail |
| libdefaults | client_aware_channel_bindings | boolean | false | plan 2 WP-12 | true requires unavailable GSS channel-binding-aware signaling and errors; false diagnostic | client_aware_channel_bindings |

## realms (28)

| Section | Relation | Typed value | MIT default | Effective consumer / package | Fail-closed classification | Test |
| --- | --- | --- | --- | --- | --- | --- |
| realms | admin_server | endpoint list | unset | Realm::parse kpasswd fallback | Effective port-464 fallback; kadm5 administration remains WP-15 | admin_server |
| realms | auth_to_local | rule list | DEFAULT | plan 2 WP-17 | No local authorization or mapping executes; diagnostic, rule expressions inert | auth_to_local |
| realms | auth_to_local_names | case-sensitive string map | unset | plan 2 WP-17 | No local authorization executes; diagnostic | auth_to_local_names |
| realms | default_domain | string | unset | plan 2 WP-17 | Legacy V4 mapping not performed; diagnostic | default_domain |
| realms | disable_encrypted_timestamp | boolean | false | plan 2 WP-07 | true errors because current client may send encrypted timestamp; false diagnostic | disable_encrypted_timestamp |
| realms | http_anchors | location list | system CA set | plan 2 WP-10 | No HTTPS proxy connection exists; trust restrictions cannot be bypassed; diagnostic | http_anchors |
| realms | kdc | endpoint list | DNS discovery when enabled | Config::configured_kdcs; transport::Tokio::discover_kdcs | Existing network endpoint consumer; Unix sockets/proxies remain WP-10 | kdc |
| realms | kpasswd_server | endpoint list | DNS then admin_server port 464 | Config::configured_kpasswd_servers | Effective configured password endpoint selection | kpasswd_server |
| realms | master_kdc | endpoint list | unset | discovery::locate::ServerLocator | Effective fallback only when primary_kdc is absent | master_kdc |
| realms | primary_kdc | endpoint list | master_kdc | client::transport::Tokio::login_as_service_with_password_config | Effective primary KDC retry after a replica's failure to authenticate | primary_kdc |
| realms | sitename | string | unset | discovery::locate::sitename | Effective site-first DNS names for KDC, admin and kpasswd discovery | sitename |
| realms | v4_instance_convert | rejected subsection | unset | protocol::relation | Permanent V4 conversion rejection before composition | v4_instance_convert |
| realms | v4_realm | rejected string | unset | protocol::relation | Permanent V4 conversion rejection before composition | v4_realm |
| realms | pkinit_anchors | location list | unset | plan 2 WP-06 | No PKINIT trust acceptance occurs; diagnostic | pkinit_anchors |
| realms | pkinit_cert_match | certificate rule list | unset | plan 2 WP-06 | No certificate selected; expressions retained without execution; diagnostic | pkinit_cert_match |
| realms | pkinit_eku_checking | kpKDC&#124;kpServerAuth&#124;none | kpKDC | plan 2 WP-06 | No certificate accepted even when EKU relaxation requested; diagnostic | pkinit_eku_checking |
| realms | pkinit_dh_min_bits | 1024&#124;2048&#124;4096&#124;P-256&#124;P-384&#124;P-521 | 2048 | plan 2 WP-06 | No DH or ECDH performed; diagnostic | pkinit_dh_min_bits |
| realms | pkinit_identities | identity location list | unset | plan 2 WP-06 | No identity loaded or environment reference resolved; diagnostic | pkinit_identities |
| realms | pkinit_kdc_hostname | hostname list | unset | plan 2 WP-06 | No certificate hostname acceptance occurs; diagnostic | pkinit_kdc_hostname |
| realms | pkinit_pool | location list | unset | plan 2 WP-06 | No chain building or certificate acceptance; diagnostic | pkinit_pool |
| realms | pkinit_require_crl_checking | boolean | false | plan 2 WP-06 | No certificate accepted, so CRL requirement cannot be bypassed; diagnostic | pkinit_require_crl_checking |
| realms | pkinit_revoke | location list | unset | plan 2 WP-06 | No certificate accepted; diagnostic | pkinit_revoke |
| realms | pkinit_identity | identity location | unset | plan 2 WP-06 | KDC identity remains inert; diagnostic | pkinit_identity |
| realms | pkinit_allow_upn | boolean | false (KDC) | plan 2 WP-06 | No certificate authorization occurs; diagnostic | pkinit_allow_upn |
| realms | pkinit_indicator | string list | unset | plan 2 WP-06 | No KDC issuance or PKINIT authentication; diagnostic | pkinit_indicator |
| realms | pkinit_require_freshness | boolean | false (KDC) | plan 2 WP-06 | No PKINIT authentication accepted; diagnostic | pkinit_require_freshness |
| realms | pkinit_win2k | rejected boolean | false | protocol::relation | Removed draft-9 PKINIT, enabled value permanently rejected | pkinit_win2k |
| realms | pkinit_draft9 | rejected boolean | false | protocol::relation | Removed draft-9 PKINIT, enabled value permanently rejected | pkinit_draft9 |

## sections (6)

| Section | Relation | Typed value | MIT default | Effective consumer / package | Fail-closed classification | Test |
| --- | --- | --- | --- | --- | --- | --- |
| domain_realm | domain_realm | DNS-name -> realm map | unset | Config::resolve_realm | Exact then longest suffix; dotted suffix excludes apex | domain_realm |
| capaths | capaths | client -> server -> direct/via graph | unset | plan 2 WP-11 | No profile-driven routing/validation; current acceptor denies cross-realm without explicit policy; diagnostic | capaths |
| appdefaults | appdefaults | hierarchical string/boolean lookup | application-defined | Config::appdefault; Config::appdefault_boolean | Caller chooses type and consumes result; no implicit behavior | appdefaults |
| plugins | disable | repeated module names | empty | plan 2 WP-16 | extensions::Registry::enabled filters registered providers; diagnosed until built-in consumers use it; excluding timestamp preauth fails | disable |
| plugins | enable_only | repeated module names | all built-ins | plan 2 WP-16 | extensions::Registry::enabled keeps and orders registered providers; diagnosed until built-in consumers use it; excluding timestamp preauth fails | enable_only |
| plugins | module | registered extension id and ignored path | empty | extensions::Registry::parse_config; extensions::Registry::enabled | A registered provider id of the interface resolves and comes first in profile order, before the other registered providers (MIT plugin.c); any other module is rejected before composition | module |


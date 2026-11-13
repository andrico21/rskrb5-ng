# MIT krb5 parity

<!-- Generated from mit-krb5-parity.toml by tests/mit_parity_manifest.rs. Do not edit. -->

Target: MIT krb5 1.22.2 (`krb5-1.22.2-final`, released 2026-01-29), inventory of 2026-10-29, statuses as of `a6a1851`.

## Summary

| Status | Rows |
| --- | ---: |
| implemented | 36 |
| partial | 75 |
| absent | 42 |
| rejected | 8 |
| omitted | 1 |
| out-of-scope | 7 |
| total | 169 |

<a id="scope"></a>
## Scope

The manifest covers MIT's client and service library surface. D1 rows are
KDC, kadmind, database and C-ABI machinery: they are recorded as
`out-of-scope` and no API is provided for them. D2 rows are features MIT
removed or that are insecure by design: they are `rejected` with a typed
`error::RejectedFeature` and a section of
[the security policy](security-policy.md). D13 records the owner decision to
omit the legacy Windows `API:` credential cache.

Completion means the union of this manifest and
[the gokrb5 manifest](gokrb5-parity.md), not their intersection. Each row's
closing todo is the plan todo that makes it final; `P1-N` is plan 1 todo N
and `P2-N` is plan 2 todo N, listed in `docs/parity-todo-index.toml`.

<a id="rust-extension-points"></a>
## Rust extension points

MIT loads C plugin modules from `plugin_base_dir` and `module` directives. This
crate loads no code: `module` is `Config::UnsupportedDynamicModule` in every
mode, and plan 2 todo 3 adds statically registered Rust providers in place of
the C plugin interfaces.


## client

| ID | Capability | Status | Evidence | Disposition | Closing | Missing | Policy and divergence | Symbols | Features | Tests |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| MIT-client-1 | AS exchange / initial TGT acquisition; password, keytab, preauth callback/responder, multi-round-trip step API | partial | unproven | WP-04 | P2-4 | Login/build/process exist, no responder or general multi-round step API. | - | - | - | - |
| MIT-client-2 | TGS service-ticket acquisition and asynchronous step API | partial | unproven | WP-04 | P2-4 | Async acquisition/referral APIs, no transport-neutral tkt-creds step context. | - | - | - | - |
| MIT-client-3 | Client principal referrals and enterprise principal canonicalization | partial | unproven | WP-05 | P2-7 +P2-4 | Unarmored AS canonicalize deliberately stripped and returned client must equal request; no authenticated client-referral/enterprise flow. | - | - | - | - |
| MIT-client-4 | Server referrals and cross-realm routing; referral-TGT processing and credential acquisition | implemented | unit | ALREADY | - | - | Referral chains are bounded and the final service name is bound to the request; Go's omitted TGS identity checks are not copied. | `client::process_tgs_rep_with_referral` | `tokio` | `tests/client/tgs_exchange.rs::process_tgs_rep_with_referral_accepts_intermediate_tgt`, `tests/client/session_cache.rs::tokio_client_reacquires_expired_cached_referral_tgt` |
| MIT-client-5 | Cross-realm TGT path configuration via `capaths`; hierarchical and non-hierarchical traversal | partial | unproven | WP-11 | P2-17 | Explicit acceptor TransitPolicy exists and [capaths] is parsed into a typed graph, but no configured path construction or profile-driven transit validation. | - | - | - | - |
| MIT-client-6 | S4U2Self protocol transition / impersonation | partial | unproven | WP-11 | P2-17 +P2-8 | PA-FOR-USER/principal S4U exists; no certificate S4U identity. | - | - | - | - |
| MIT-client-7 | S4U2Proxy constrained delegation using evidence ticket | implemented | unit | ALREADY | - | - | Reply processing binds the evidence ticket's client to the frontend key before accepting the result; request construction and transport precede this validation. | `client::build_s4u2proxy_req`, `client::Tokio::s4u2proxy` | `tokio` | `tests/client/tgs_exchange.rs::builds_s4u2proxy_tgs_req_with_evidence_ticket`, `tests/client/review_s4u.rs::s4u_proxy_rejects_relabelled_evidence`, `tests/client/tgs_exchange.rs::tokio_client_s4u2proxy_uses_current_service_tgt_without_service_cache` |
| MIT-client-8 | Resource-Based Constrained Delegation (RBCD), including client-side cross-realm S4U2Proxy | partial | unproven | WP-11 | P2-17 | Raw RBCD PAC mask/padata and proxy primitives, no complete cross-realm RBCD workflow/proof. | - | - | - | - |
| MIT-client-9 | Anonymous and realm-exposed anonymous initial credentials | absent | unproven | WP-06 | P2-8 | AS options lack anonymous identity/policy orchestration. | - | - | - | - |
| MIT-client-10 | Ticket request flags and lifetimes: forwardable, proxiable, renewable, renewable-ok, address controls, canonicalize, etc. | partial | unproven | WP-04 | P2-4 | Forwardable/proxiable/lifetime relations map to request options; address controls (extra_addresses, noaddresses = false), authenticated canonicalization and a typed per-request options API are missing. | - | - | - | - |
| MIT-client-11 | Initial-credential options and prompting: lifetimes, addresses, enctypes, preauth options, service, anonymous, callbacks/responders | partial | unproven | WP-15 | P2-23 +P2-4 | Options/password/keytab helpers; no responder, automatic password-on-expiry or anonymous flow. | - | - | - | - |
| MIT-client-12 | Verify initial credentials against a host/service keytab (`krb5_verify_init_creds`) | absent | unproven | WP-11 | P2-17 | Generic AP validation is not verify-init-creds orchestration; verify_ap_req_nofail = true fails closed until it exists. | - | - | - | - |
| MIT-client-13 | KRB-CRED marshal/unmarshal, `mk_1cred`/`mk_ncred`, `rd_cred`; forwarding/delegation credential transport | partial | unproven | WP-20 | P2-27 | Encrypted ccache conversion exists; full contextual forwarding/import controls and authdata/second-ticket conversion incomplete. | - | - | - | - |
| MIT-client-14 | AP-REQ/AP-REP create/read (`mk_req`, `rd_req`, `mk_rep`, `rd_rep`) including DCE-style variants | partial | unproven | WP-12 | P2-19 +P2-18 | AP exchange exists; DCE variants/three-leg not provided. | - | - | - | - |
| MIT-client-15 | KRB-SAFE and KRB-PRIV create/read; KRB-ERROR create/read | implemented | fixture | ALREADY | - | - | KRB-SAFE accepts keyed checksums only; unkeyed checksum types are RejectedFeature::UnauthenticatedChecksum. [docs/security-policy.md#unauthenticated-checksum](security-policy.md#unauthenticated-checksum) | `krb_safe::verify_krb_safe_checksum`, `krb_priv::build_krb_priv_with_confounder`, `krb_priv::decrypt_krb_priv_enc_part` | `messages` | `tests/krb_safe.rs::builds_and_verifies_krb_safe_checksum`, `tests/krb_safe.rs::rejects_krb_safe_checksum_mismatch`, `tests/krb_priv.rs::builds_and_decrypts_krb_priv_with_explicit_confounder`, `tests/krb_error.rs::decodes_and_roundtrips_gokrb5_krb_error_fixture` |
| MIT-client-16 | Replay cache interface: `dfl`, `file2`, `none`; replay detection and configurable cache name | partial | unproven | WP-20 | P2-27 | Bounded memory/shared cache only; no persistent file2/dfl/name dispatch. | - | - | - | - |

## preauth

| ID | Capability | Status | Evidence | Disposition | Closing | Missing | Policy and divergence | Symbols | Features | Tests |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| MIT-preauth-1 | Encrypted timestamp (PA-ENC-TIMESTAMP) and password salt / ETYPE-INFO(2) processing | implemented | unit | ALREADY | - | - | Peer s2kparams below the CryptoPolicy minimum (4096 AES-SHA1, 32768 AES-SHA2) are rejected before any key derivation. [docs/security-policy.md#policy](security-policy.md#policy) | `client::pa_enc_timestamp` | `tokio` | `tests/client/as_exchange.rs::builds_and_encrypts_pa_enc_timestamp`, `tests/client/login_preauth.rs::parses_kdc_preauth_required_error_and_selects_etype_info2`, `src/client/s2k_tests.rs::info2_challenge_checks_before_timestamp_derivation` |
| MIT-preauth-2 | FAST negotiation, armor-ticket use, request/response protection, cookies, encrypted challenges | partial | unproven | WP-05 | P2-7 | Request-integrity advertisement/check and cookies are not full FAST armor. | - | - | - | - |
| MIT-preauth-3 | FAST anonymous armor via anonymous PKINIT | absent | unproven | WP-06 | P2-8 +P2-7 | No PKINIT/armor exchange. | - | - | - | - |
| MIT-preauth-4 | Encrypted challenge FAST factor | absent | unproven | WP-05 | P2-7 | Timestamp helper is distinct from armored challenge. | - | - | - | - |
| MIT-preauth-5 | PKINIT certificate authentication (RSA and supported ECC paths) | absent | unproven | WP-06 | P2-8 | PKINIT excluded by current code; implement current ECC/DH, not removed RSA mode. | - | - | - | - |
| MIT-preauth-6 | Anonymous PKINIT | absent | unproven | WP-06 | P2-8 | No certificate-less anonymous exchange. | - | - | - | - |
| MIT-preauth-7 | SPAKE password-authenticated key exchange | absent | unproven | WP-07 | P2-9 | Built-in timestamp/key-hint flow only. | - | - | - | - |
| MIT-preauth-8 | OTP client interaction and OTP-over-FAST protocol support | absent | unproven | WP-08 | P2-10 | OTP dependency types enabled but no client factor/responder exchange. | - | - | - | - |
| MIT-preauth-9 | PA-PAC-REQUEST (request PAC inclusion/exclusion) | absent | unproven | WP-14 | P2-22 | Generic padata and PAC-OPTIONS helper only, not a typed PAC-request API/consumer. | - | - | - | - |
| MIT-preauth-10 | Client preauth (`clpreauth`) and KDC preauth (`kdcpreauth`) plugin interfaces | partial | unproven | WP-16 | P2-4 +P2-3 | Built-in retries/padata; no pluggable client-preauth interface; kdcpreauth subpart D1 excluded. | - | - | - | - |

## crypto

| ID | Capability | Status | Evidence | Disposition | Closing | Missing | Policy and divergence | Symbols | Features | Tests |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| MIT-crypto-1 | AES128/AES256 CTS with HMAC-SHA1-96 | implemented | unit | ALREADY | - | - | - | `crypto::AesSha1Etype` | - | `tests/crypto_aes.rs::aes128_string_to_key_matches_gokrb5_vectors`, `tests/crypto_aes.rs::aes_cts_encrypts_and_decrypts_rfc3962_vectors`, `tests/crypto_aes.rs::checksums_and_messages_match_gokrb5_aes256` |
| MIT-crypto-2 | AES128-SHA256 and AES256-SHA384 (AES-SHA2) | implemented | unit | ALREADY | - | - | The MAC is verified in constant time before decryption. | `crypto::AesSha2Etype` | - | `tests/crypto_aes.rs::aes_sha2_string_to_key_matches_gokrb5_vectors`, `tests/crypto_aes.rs::aes128_sha2_derive_checksum_integrity_and_crypto_match_gokrb5_vectors`, `tests/crypto_aes.rs::aes256_sha2_derive_checksum_integrity_and_crypto_match_gokrb5_vectors` |
| MIT-crypto-3 | Camellia128/256 CTS-CMAC | absent | unproven | WP-03 | P2-5 | Closed enctype dispatcher has AES/DES3/RC4 only. | - | - | - | - |
| MIT-crypto-4 | DES3-CBC-SHA1 | implemented | unit | WP-02 | P1-14 | - | DES3 needs allow_des3 = true. Enforced client- and acceptor-side for every policy-checked use (request lists, replies, tickets, acceptor keys, imports, checked low-level APIs); MIT's flag only gates KDC issuance. Raw RFC-vector APIs stay policy-free. [docs/security-policy.md#policy](security-policy.md#policy) | `crypto::Des3CbcSha1KdEtype`, `crypto::CryptoPolicy::check_use` | - | `tests/crypto_des3.rs::des3_checksum_and_message_encryption_match_gokrb5_vectors`, `tests/policy/profile.rs::policy_legacy_flags_and_mutated_defaults`, `tests/policy/checked.rs::checked_dispatch_requires_permission`, `tests/config/relations_c1.rs::allow_des3` |
| MIT-crypto-5 | RC4-HMAC / RC4-HMAC-EXP | implemented | unit | WP-02 | P1-14 | - | RC4-HMAC needs allow_rc4 = true. RC4-EXP (etype 24) is permanently rejected as RejectedFeature::Rc4Export, even with both legacy flags set. `RejectedFeature::Rc4Export` [docs/security-policy.md#rc4-export](security-policy.md#rc4-export) | `crypto::Rc4HmacEtype`, `error::RejectedFeature::Rc4Export` | - | `tests/crypto_rc4.rs::rc4_hmac_message_encryption_matches_gokrb5_vector`, `tests/policy/acceptor.rs::default_acceptor_rejects_rc4_ticket`, `tests/policy/expressions.rs::insecure_names_are_typed_rejections`, `tests/policy/selection.rs::numeric_selection_is_typed` |
| MIT-crypto-6 | Single-DES types (DES-CBC-CRC/MD4/MD5) | rejected | unit | D2 | P1-14 | - | Single-DES ids 1/2/3 and names are rejected at every textual, numeric, serde and raw entry point before any crypto. `RejectedFeature::SingleDes` [docs/security-policy.md#single-des](security-policy.md#single-des) | `error::RejectedFeature::SingleDes` | - | `tests/policy/expressions.rs::insecure_names_are_typed_rejections`, `tests/policy/selection.rs::numeric_selection_is_typed`, `tests/policy/raw_selection.rs::raw_encryption_rejects_forbidden_selection` |
| MIT-crypto-7 | Configured enctype policy: `permitted_enctypes`, `default_tkt_enctypes`, `default_tgs_enctypes` | implemented | unit | WP-02 | P1-14 | - | The permitted list applies to every use, including acceptor keys and imported credentials. The crate default is AES only (SHA2 first). Camellia names are a diagnostic in Compatible mode and an error in Strict mode until Camellia exists (MIT-crypto-3, plan-2 todo 5). [docs/security-policy.md#policy](security-policy.md#policy) | `crypto::CryptoPolicy::from_libdefaults`, `crypto::CryptoPolicy::check_use`, `crypto::policy::Use` | - | `tests/policy/profile.rs::policy_checks_every_use`, `tests/policy/client.rs::as_request_rejects_excluded_list`, `tests/policy/reply_isolation.rs::as_session_policy_isolated`, `tests/policy/acceptor.rs::acceptor_applies_explicit_policy`, `tests/config/relations_c2.rs::permitted_enctypes` |
| MIT-crypto-8 | Enctype list operators (`+`/`-`), `DEFAULT` and enctype-family selectors | implemented | unit | WP-02 | P1-14 | - | MIT 1.22.2's parser (init_ctx.c) recognizes DEFAULT, aes, des3, rc4 and camellia selectors; ALL is an unknown token here as there. DEFAULT expands to the secure AES list, never DES3/RC4; Camellia remains unimplemented. Unknown tokens, forbidden positive terms and empty results are errors. [docs/security-policy.md#policy](security-policy.md#policy) | `config::EnctypeExpr`, `crypto::CryptoPolicy::resolve` | - | `tests/policy/expressions.rs::selector_order_removal_and_readdition`, `tests/policy/expressions.rs::aliases_case_and_delimiters`, `tests/policy/ordering.rs::ordered_edits_match_model`, `tests/policy/expressions.rs::unknown_tokens_are_named`, `tests/policy/expressions.rs::empty_results_fail_closed` |
| MIT-crypto-9 | `allow_weak_crypto` | implemented | unit | WP-02 | P1-14 | - | allow_weak_crypto = true is permanently rejected as RejectedFeature::WeakCrypto; false is accepted. `RejectedFeature::WeakCrypto` [docs/security-policy.md#weak-crypto](security-policy.md#weak-crypto) | `error::RejectedFeature::WeakCrypto` | - | `tests/policy/profile.rs::weak_crypto_is_permanently_rejected`, `tests/config/relations_c1.rs::allow_weak_crypto` |
| MIT-crypto-10 | `allow_rc4` and `allow_des3` | implemented | unit | WP-02 | P1-14 | - | Enforced client- and acceptor-side for every policy-checked use (request lists, replies, tickets, acceptor keys, imports, checked low-level APIs); MIT's flag only gates KDC issuance. Raw RFC-vector APIs stay policy-free. [docs/security-policy.md#policy](security-policy.md#policy) | `crypto::CryptoPolicy::from_libdefaults` | - | `tests/config/relations_c1.rs::allow_des3`, `tests/config/relations_c1.rs::allow_rc4`, `tests/policy/profile.rs::policy_legacy_flags_and_mutated_defaults`, `tests/policy/acceptor_http.rs::http_builders_propagate_legacy_permission` |
| MIT-crypto-11 | Keyed checksum types, checksum selection, checksum/key-usage enforcement | partial | unproven | WP-03 | P2-5 | Existing keyed AES/DES3/RC4 suite works; Camellia checksum suite missing. | - | - | - | - |

## ccache

| ID | Capability | Status | Evidence | Disposition | Closing | Missing | Policy and divergence | Symbols | Features | Tests |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| MIT-ccache-1 | FILE ccache | implemented | fixture | ALREADY | - | - | Saved caches are private to the owner and symlinked destinations are rejected. | `ccache::CCache::load`, `ccache::CCache::save`, `ccache::CacheName` | - | `tests/ccache.rs::parses_gokrb5_ccache_fixture`, `tests/ccache.rs::saves_and_loads_ccache_file`, `tests/ccache.rs::saves_cache_with_private_permissions`, `tests/ccache.rs::resolves_file_cache_names` |
| MIT-ccache-2 | DIR cache and collections | partial | unproven | WP-09 | P2-11 | Primary and DIR:: load/save exist; enumeration/switch/new-unique/locking API missing. | - | - | - | - |
| MIT-ccache-3 | Linux KEYRING: process/thread/user/session/persistent | absent | unproven | WP-09 | P2-13 | KEYRING: names fail with a typed UnsupportedCacheType error; no kernel keyring backend. | - | - | - | - |
| MIT-ccache-4 | KCM cache client | absent | unproven | WP-09 | P2-12 | KCM: names fail with a typed UnsupportedCacheType error; no KCM socket protocol. | - | - | - | - |
| MIT-ccache-5 | MEMORY cache | absent | unproven | WP-09 | P2-11 | In-memory CCache value is not a named MEMORY backend. | - | - | - | - |
| MIT-ccache-6 | Windows API cache | omitted | unit | D13 | P2-14 | Omitted by owner decision D13: the legacy KfW API: cache is not provided; API: names fail with a typed UnsupportedCacheType error. | [docs/security-policy.md#windows-api-ccache](security-policy.md#windows-api-ccache) | `ccache::CacheName` | - | `tests/ccache.rs::rejects_unsupported_cache_names` |
| MIT-ccache-7 | Windows MSLSA cache | absent | unproven | WP-09 | P2-14 | MSLSA: names fail with a typed UnsupportedCacheType error; no LSA cache backend. | - | - | - | - |
| MIT-ccache-8 | Credential-cache collections, primary selection, switching and cursor APIs | partial | unproven | WP-09 | P2-11 | Primary name resolution only, no collection/cursor/select API. | - | - | - | - |
| MIT-ccache-9 | Per-cache configuration entries (`krb5_cc_get_config`/`set_config`) | implemented | unit | ALREADY | - | - | - | `ccache::CCache::upsert_config_entry`, `ccache::CCache::config_entries`, `ccache::ConfigEntry` | - | `tests/ccache.rs::builds_and_upserts_x_cacheconf_entries`, `tests/ccache.rs::entries_filter_out_x_cacheconf_credentials` |
| MIT-ccache-10 | Ccache file format versions 1–4; configurable `ccache_type` | partial | unproven | WP-09 | P2-11 | Versions parse/serialize, configured ccache_type not applied to new caches. | - | - | - | - |

## keytab

| ID | Capability | Status | Evidence | Disposition | Closing | Missing | Policy and divergence | Symbols | Features | Tests |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| MIT-keytab-1 | FILE keytab read, enumerate, resolve and mutate APIs | implemented | fixture | ALREADY | - | - | Saved keytabs are private to the owner and symlinked destinations are rejected. | `keytab::Keytab`, `keytab::Keytab::find_key`, `keytab::Entry` | - | `tests/keytab.rs::parses_gokrb5_keytab_fixture`, `tests/keytab.rs::saves_and_loads_keytab_file`, `tests/keytab.rs::finds_matching_key_by_principal_kvno_and_etype`, `tests/keytab.rs::generates_gokrb5_user_keytab_entries_from_password` |
| MIT-keytab-2 | WRFILE keytab | implemented | unit | ALREADY | - | - | - | `keytab::Name`, `keytab::Keytab::load_name` | - | `tests/keytab.rs::parses_typed_file_keytab_names` |
| MIT-keytab-3 | MEMORY keytab | partial | unproven | WP-09 | P2-11 | Owned in-memory Keytab/entry mutation exists, no named MEMORY registry. | - | - | - | - |
| MIT-keytab-4 | Client keytab, automatic initial creds and refresh | partial | unproven | WP-12 | P2-18 +P2-4 +P2-11 | Explicit client-keytab and renewal/relogin exist, no full GSS implicit acquisition/refresh integration. | - | - | - | - |

## config

| ID | Capability | Status | Evidence | Disposition | Closing | Missing | Policy and divergence | Symbols | Features | Tests |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| MIT-config-1 | `allow_des3` | implemented | unit | WP-02 | P1-14 | - | Enforced client- and acceptor-side for every policy-checked use (request lists, replies, tickets, acceptor keys, imports, checked low-level APIs); MIT's flag only gates KDC issuance. Raw RFC-vector APIs stay policy-free. [docs/security-policy.md#policy](security-policy.md#policy) | `crypto::CryptoPolicy::from_libdefaults` | - | `tests/config/relations_c1.rs::allow_des3`, `tests/policy/profile.rs::policy_legacy_flags_and_mutated_defaults` |
| MIT-config-2 | `allow_rc4` | implemented | unit | WP-02 | P1-14 | - | Enforced client- and acceptor-side for every policy-checked use (request lists, replies, tickets, acceptor keys, imports, checked low-level APIs); MIT's flag only gates KDC issuance. Raw RFC-vector APIs stay policy-free. [docs/security-policy.md#policy](security-policy.md#policy) | `crypto::CryptoPolicy::from_libdefaults` | - | `tests/config/relations_c1.rs::allow_rc4`, `tests/policy/acceptor.rs::default_acceptor_rejects_rc4_ticket` |
| MIT-config-3 | `allow_weak_crypto` | implemented | unit | WP-02 | P1-14 | - | true is permanently rejected as RejectedFeature::WeakCrypto; false is accepted. `RejectedFeature::WeakCrypto` [docs/security-policy.md#weak-crypto](security-policy.md#weak-crypto) | `error::RejectedFeature::WeakCrypto` | - | `tests/config/relations_c1.rs::allow_weak_crypto`, `tests/policy/profile.rs::weak_crypto_is_permanently_rejected` |
| MIT-config-4 | `canonicalize` | partial | unit | WP-05 | P2-7 +P2-4 | TGS option consumed; AS builders suppress canonicalization, preserving identity; either value diagnostic (consumer: plan 2 WP-04). | - | - | - | `tests/config/relations_c1.rs::canonicalize` |
| MIT-config-5 | `ccache_type` | partial | unit | WP-09 | P2-11 | New caches remain v4; version choice does not strengthen credential protection; diagnostic (consumer: plan 2 WP-09). | - | - | - | `tests/config/relations_c1.rs::ccache_type` |
| MIT-config-6 | `clockskew` | implemented | unit | ALREADY | - | - | A negative tolerance is rejected; time-unit syntax is accepted as an extension of MIT's integer seconds. | `config::LibDefaults` | - | `tests/config/relations_c1.rs::clockskew`, `tests/config/libdefaults_c1.rs::clockskew_when_invalid_mit_syntax`, `tests/http.rs::tower_layer_config_clockskew_rejects_stale_authenticator` |
| MIT-config-7 | `default_ccache_name` | implemented | unit | WP-01 | P1-15 | - | Unknown tokens and missing facts are errors at resolution, never a credential fallback; %{uid}/%{euid} are Linux-only. | `config::parameters::ExpansionContext`, `client::Tokio::from_default_ccache_name` | `tokio` | `tests/config/relations_c1.rs::default_ccache_name`, `tests/config/expansion.rs::documented_tokens_expand_when_context_is_supplied`, `tests/config/expansion.rs::unknown_tokens_fail_when_not_exactly_named` |
| MIT-config-8 | `default_client_keytab_name` | implemented | unit | WP-01 | P1-15 | - | Unknown tokens and missing facts are errors at resolution, never a credential fallback; %{uid}/%{euid} are Linux-only. | `config::parameters::ExpansionContext`, `client::Tokio::with_client_keytab_from_config` | `tokio` | `tests/config/relations_c1.rs::default_client_keytab_name`, `tests/config/expansion.rs::profile_names_expand_when_selected_with_context` |
| MIT-config-9 | `default_keytab_name` | implemented | unit | WP-01 | P1-15 | - | Unknown tokens and missing facts are errors at resolution, never a credential fallback; %{uid}/%{euid} are Linux-only. | `config::parameters::ExpansionContext`, `service::Validator::from_default_keytab_name` | `messages` | `tests/config/relations_c1.rs::default_keytab_name`, `tests/config/expansion.rs::identity_tokens_expand_when_linux` |
| MIT-config-10 | `default_rcache_name` | partial | unit | WP-20 | P2-27 | Any value except none: requires unavailable persistent/shared replay protection and errors; none: diagnostic because memory replay protection remains (consumer: plan 2 WP-20). | - | - | - | `tests/config/relations_c1.rs::default_rcache_name` |
| MIT-config-11 | `default_realm` | implemented | unit | ALREADY | - | - | - | `config::Config::realm_for_host` | - | `tests/config/relations_c1.rs::default_realm` |
| MIT-config-12 | `default_tgs_enctypes` | implemented | unit | WP-02 | P1-14 | - | Uses the MIT expression syntax; forbidden positive terms are errors and the default is the AES list. [docs/security-policy.md#policy](security-policy.md#policy) | `client::options::TgsReq::from_libdefaults`, `config::EnctypeExpr` | `tokio` | `tests/config/relations_c1.rs::default_tgs_enctypes`, `tests/policy/client.rs::tgs_request_rejects_excluded_session` |
| MIT-config-13 | `default_tkt_enctypes` | implemented | unit | WP-02 | P1-14 | - | Uses the MIT expression syntax; forbidden positive terms are errors and the default is the AES list. [docs/security-policy.md#policy](security-policy.md#policy) | `client::options::AsReq::from_libdefaults`, `config::EnctypeExpr` | `tokio` | `tests/config/relations_c1.rs::default_tkt_enctypes`, `tests/policy/client.rs::as_request_rejects_excluded_list` |
| MIT-config-14 | `dns_canonicalize_hostname` | partial | unit | WP-10 | P2-15 | No DNS canonicalization occurs; all values diagnostic, including fallback per todo 15 (consumer: plan 2 WP-10). | - | - | - | `tests/config/relations_c1.rs::dns_canonicalize_hostname` |
| MIT-config-15 | `dns_lookup_kdc` | implemented | unit | ALREADY | - | - | The crate default is false, so no ambient DNS lookup happens unless configured. | `client::transport::Tokio::discover_kdcs` | `tokio` | `tests/config/relations_c1.rs::dns_lookup_kdc` |
| MIT-config-16 | `dns_lookup_realm` | partial | unit | WP-10 | P2-15 | No TXT realm discovery occurs; false satisfied, true cannot relax behavior; diagnostic (consumer: plan 2 WP-10). | - | - | - | `tests/config/relations_c1.rs::dns_lookup_realm` |
| MIT-config-17 | `dns_uri_lookup` | partial | unit | WP-10 | P2-15 | No URI discovery occurs; false satisfied, true cannot relax behavior; diagnostic; crate default false (consumer: plan 2 WP-10). | - | - | - | `tests/config/relations_c1.rs::dns_uri_lookup` |
| MIT-config-18 | `enforce_ok_as_delegate` | partial | unit | WP-12 | P2-18 | GSS credential forwarding is unavailable; no credentials delegated, so true already satisfied; diagnostic (consumer: plan 2 WP-12). | - | - | - | `tests/config/relations_c1.rs::enforce_ok_as_delegate` |
| MIT-config-19 | `err_fmt` | partial | unit | WP-18 | P2-6 | Formatting does not alter typed errors or authentication policy; diagnostic (consumer: plan 2 WP-18). | - | - | - | `tests/config/relations_c1.rs::err_fmt` |
| MIT-config-20 | `extra_addresses` | partial | unit | WP-04 | P2-4 | Ignored when noaddresses=true; nonempty list with noaddresses=false requires unavailable address-bound requests and errors (consumer: plan 2 WP-04). | - | - | - | `tests/config/relations_c1.rs::extra_addresses` |
| MIT-config-21 | `forwardable` | partial | unit | WP-04 | P2-4 | The relation already sets the AS/TGS forwardable bit; the typed per-request option API and KDC-backed proof close in plan-2 todo 4. | - | `client::options::AsReq::from_libdefaults` | `tokio` | `tests/config/relations_c1.rs::forwardable` |
| MIT-config-22 | `ignore_acceptor_hostname` | partial | unit | WP-12 | P2-18 | No GSS acceptor-name relaxation; strict service/keytab identity checks retained; either value diagnostic (consumer: plan 2 WP-12). | - | - | - | `tests/config/relations_c1.rs::ignore_acceptor_hostname` |
| MIT-config-23 | `k5login_authoritative` | partial | unit | WP-17 | P2-25 | No local-login authorization exists; neither value grants login; diagnostic (consumer: plan 2 WP-17). | - | - | - | `tests/config/relations_c2.rs::k5login_authoritative` |
| MIT-config-24 | `k5login_directory` | partial | unit | WP-17 | P2-25 | No local-login authorization or file lookup occurs; diagnostic (consumer: plan 2 WP-17). | - | - | - | `tests/config/relations_c2.rs::k5login_directory` |
| MIT-config-25 | `kcm_mach_service` | partial | unit | WP-09 | P2-14 | No KCM connection exists, including when - disables Mach RPC; diagnostic (consumer: plan 2 WP-09). | - | - | - | `tests/config/relations_c2.rs::kcm_mach_service` |
| MIT-config-26 | `kcm_socket` | partial | unit | WP-09 | P2-12 | No KCM connection exists, including when - disables Unix sockets; diagnostic (consumer: plan 2 WP-09). | - | - | - | `tests/config/relations_c2.rs::kcm_socket` |
| MIT-config-27 | `kdc_default_options` | implemented | unit | ALREADY | - | - | The canonicalize bit is suppressed on unarmored AS requests so the client identity cannot change. | `client::options::AsReq::from_libdefaults`, `client::options::TgsReq::from_libdefaults` | `tokio` | `tests/config/relations_c2.rs::kdc_default_options`, `tests/client/as_exchange.rs::as_req_options_from_libdefaults_suppresses_canonicalize_flag` |
| MIT-config-28 | `kdc_timesync` | partial | unit | WP-04 | P2-4 | No clock correction occurs; zero satisfied, nonzero does not tighten authentication; diagnostic (consumer: plan 2 WP-04). | - | - | - | `tests/config/relations_c2.rs::kdc_timesync` |
| MIT-config-29 | `noaddresses` | partial | unit | WP-04 | P2-4 | Requests currently omit addresses; false requires unavailable address restriction and errors; true diagnostic (consumer: plan 2 WP-04). | - | - | - | `tests/config/relations_c2.rs::noaddresses` |
| MIT-config-30 | `permitted_enctypes` | implemented | unit | WP-02 | P1-14 | - | The crate default is the AES list (SHA2 first), not MIT's list with DES3, RC4 and Camellia; the list governs every use. [docs/security-policy.md#policy](security-policy.md#policy) | `crypto::CryptoPolicy::from_libdefaults` | - | `tests/config/relations_c2.rs::permitted_enctypes`, `tests/policy/profile.rs::policy_checks_every_use`, `tests/policy/profile.rs::profile_subtractions_resolve_to_exact_ids` |
| MIT-config-31 | `plugin_base_dir` | out-of-scope | unit | D1 | - | Nothing in scope (D1): a C shared-library search path; D3 forbids a C loader. The relation is parsed as an inert template with a diagnostic; registered Rust providers are plan-2 todo 3. | [docs/mit-krb5-parity.md#rust-extension-points](mit-krb5-parity.md#rust-extension-points) | - | - | `tests/config/relations_c2.rs::plugin_base_dir` |
| MIT-config-32 | `preferred_preauth_types` | partial | unit | WP-04 | P2-4 | Preference ordering is not an allowlist; no new preauth selection, diagnostic; draft-9 IDs 14/15 removed with existing IgnoredPreauthType (consumer: plan 2 WP-04). | - | - | - | `tests/config/relations_c2.rs::preferred_preauth_types` |
| MIT-config-33 | `proxiable` | partial | unit | WP-04 | P2-4 | The relation already sets the AS/TGS proxiable bit; the typed per-request option API and KDC-backed proof close in plan-2 todo 4. | - | `client::options::AsReq::from_libdefaults` | `tokio` | `tests/config/relations_c2.rs::proxiable` |
| MIT-config-34 | `qualify_shortname` | partial | unit | WP-10 | P2-15 | No automatic qualification exists; empty disables and nonempty requests unavailable name rewriting; diagnostic (consumer: plan 2 WP-10). | - | - | - | `tests/config/relations_c2.rs::qualify_shortname` |
| MIT-config-35 | `rdns` | partial | unit | WP-10 | P2-15 | No reverse DNS occurs; false satisfied, true cannot relax current behavior; diagnostic (consumer: plan 2 WP-10). | - | - | - | `tests/config/relations_c2.rs::rdns` |
| MIT-config-36 | `realm_try_domains` | partial | unit | WP-10 | P2-15 | No domain realm probing occurs; negative disables, nonnegative does not tighten behavior; diagnostic (consumer: plan 2 WP-10). | - | - | - | `tests/config/relations_c2.rs::realm_try_domains` |
| MIT-config-37 | `renew_lifetime` | implemented | unit | ALREADY | - | - | - | `client::options::AsReq::from_libdefaults` | `tokio` | `tests/config/relations_c2.rs::renew_lifetime`, `tests/client/as_exchange.rs::builds_tgt_as_req_with_renew_lifetime_sets_renewable_flag` |
| MIT-config-38 | `request_timeout` | partial | unit | WP-10 | P2-15 | Existing per-attempt timeouts are not a total budget; every nonzero value errors; zero diagnostic (consumer: plan 2 WP-10). | - | - | - | `tests/config/relations_c2.rs::request_timeout` |
| MIT-config-39 | `spake_preauth_groups` | partial | unit | WP-07 | P2-9 | No SPAKE group is used; allowed-group lists do not require SPAKE; diagnostic; unknown names rejected rather than skipped (consumer: plan 2 WP-07). | - | - | - | `tests/config/relations_c2.rs::spake_preauth_groups` |
| MIT-config-40 | `ticket_lifetime` | implemented | unit | ALREADY | - | - | - | `client::options::AsReq::from_libdefaults` | `tokio` | `tests/config/relations_c2.rs::ticket_lifetime`, `tests/client/as_exchange.rs::builds_tgt_as_req_with_expected_fields` |
| MIT-config-41 | `udp_preference_limit` | implemented | unit | ALREADY | - | - | Negative values use MIT's default and large values are capped at 32700. | `client::transport::Tokio` | `tokio` | `tests/config/relations_c2.rs::udp_preference_limit`, `tests/client_transport/tests/affinity.rs::tokio_transport_auto_honors_tcp_first_udp_preference_limit` |
| MIT-config-42 | `verify_ap_req_nofail` | partial | unit | WP-11 | P2-17 | true requires unavailable verify-init-creds orchestration and errors; false diagnostic (consumer: plan 2 WP-11). | - | - | - | `tests/config/relations_c2.rs::verify_ap_req_nofail` |
| MIT-config-43 | `client_aware_channel_bindings` | partial | unit | WP-12 | P2-18 | true requires unavailable GSS channel-binding-aware signaling and errors; false diagnostic (consumer: plan 2 WP-12). | - | - | - | `tests/config/relations_c2.rs::client_aware_channel_bindings` |
| MIT-config-44 | `[realms]`: `admin_server`, `kdc`, `kpasswd_server` | partial | unit | WP-15 | P2-24 +P2-15 +P2-23 | Remote kadm5 consumer of admin_server (plan-2 todo 24); kdc and kpasswd_server endpoints are effective and admin_server feeds the port-464 kpasswd fallback. | - | - | - | `tests/config/realm_relations_d.rs::kdc`, `tests/config/realm_relations_d.rs::kpasswd_server`, `tests/config/realm_relations_d.rs::admin_server` |
| MIT-config-45 | `[realms]`: `primary_kdc` (formerly `master_kdc`) | partial | unit | WP-10 | P2-15 | Primary-KDC retry after a bad password against a replica; primary_kdc and master_kdc are parsed (primary_kdc wins) with a diagnostic. | - | - | - | `tests/config/section_composition_d.rs::primary_kdc_precedence`, `tests/config/realm_relations_d.rs::primary_kdc`, `tests/config/realm_relations_d.rs::master_kdc` |
| MIT-config-46 | `[realms]`: `sitename` | partial | unit | WP-10 | P2-15 | Site-local DNS discovery; the relation is parsed with a diagnostic. | - | - | - | `tests/config/realm_relations_d.rs::sitename` |
| MIT-config-47 | `[realms]`: `auth_to_local`, `auth_to_local_names` | partial | unit | WP-17 | P2-25 | No local authorization or name mapping executes; the relations are parsed with diagnostics. | - | - | - | `tests/config/realm_relations_d.rs::auth_to_local`, `tests/config/realm_relations_d.rs::auth_to_local_names` |
| MIT-config-48 | `[realms]`: `default_domain`, `v4_instance_convert`, `v4_realm` | rejected | unit | D2 | P1-15 +P1-14 | - | v4_instance_convert and v4_realm are rejected before composition; default_domain stays a parsed, inert relation with a diagnostic. `RejectedFeature::V4Conversion` [docs/security-policy.md#v4-conversion](security-policy.md#v4-conversion) | `error::RejectedFeature::V4Conversion` | - | `tests/config.rs::rejects_v4_realm_directives`, `tests/policy/protocols.rs::relation_api_rejects_removed_modes` |
| MIT-config-49 | `[realms]`: `disable_encrypted_timestamp` | partial | unit | WP-07 | P2-9 | SPAKE consumer; true is rejected (fail closed) because the current client may still send encrypted timestamp. | - | - | - | `tests/config/sections_d.rs::encrypted_timestamp_disable_fails_closed`, `tests/config/realm_relations_d.rs::disable_encrypted_timestamp` |
| MIT-config-50 | `[realms]`: `http_anchors` for HTTPS KDC/kpasswd proxy | partial | unit | WP-10 | P2-16 | MS-KKDCP HTTPS proxy transport; the relation is parsed with a diagnostic. | - | - | - | `tests/config/realm_relations_d.rs::http_anchors` |
| MIT-config-51 | `[realms]`: PKINIT identity/trust/cert-auth options | partial | unit | WP-06 | P2-8 | PKINIT; realm pkinit_* relations are parsed with diagnostics and enabled pkinit_win2k/pkinit_draft9 values are rejected (D2). | - | - | - | `tests/config/sections_d.rs::pkinit_invalid_enums_fail`, `tests/config/realm_relations_d.rs::pkinit_anchors`, `tests/config/realm_relations_d.rs::pkinit_identities` |
| MIT-config-52 | `[domain_realm]` exact-host and domain/subdomain to realm mapping | implemented | unit | ALREADY | - | - | Matching is case-folded: exact host first, then the longest dotted suffix; a dotted suffix does not match the apex. | `config::Config::resolve_realm` | - | `tests/config/section_composition_d.rs::domain_realm` |
| MIT-config-53 | `[capaths]` explicit non-hierarchical cross-realm paths | partial | unit | WP-11 | P2-17 | Profile-driven cross-realm routing and transit validation; [capaths] is parsed into a typed graph with a diagnostic. | - | - | - | `tests/config/section_composition_d.rs::capaths` |
| MIT-config-54 | `[plugins]` `disable`, `enable_only`, `module` common relations | partial | unit | WP-16 | P2-3 | Registered Rust provider selection; disable/enable_only are parsed per interface and restrictions that would exclude the current timestamp preauth fail. | - | - | - | `tests/config/section_composition_d.rs::disable`, `tests/config/section_composition_d.rs::enable_only`, `tests/config/section_composition_d.rs::restrictive_preauth_plugins` |
| MIT-config-55 | `include`, `includedir`, `module` config source directive | partial | unit | WP-16 | P2-3 +P1-15 | P2-3: MIT `module` config providers; `module` is Config::UnsupportedDynamicModule in every mode until registered Rust profile providers exist. include/includedir semantics were delivered by P1-15. | - | - | - | `tests/config/profile.rs::includes_resume_parent_state`, `tests/config/readers.rs::reader_composes_absolute_includes`, `tests/config_relative_include.rs::relative_includes_follow_the_working_directory`, `tests/config/readers.rs::dynamic_modules_fail_in_every_mode` |
| MIT-config-56 | Profile merging, final section/subsection/relation markers, multiple `KRB5_CONFIG` files | implemented | unit | WP-01 | P1-15 | - | A missing or unreadable KRB5_CONFIG entry is an error (MIT skips it). The value-suffix final marker is kept as a gokrb5 extension beside MIT's tag* and [section]* forms. | `config::Config::load_paths`, `config::Config::diagnostics` | - | `tests/config/profile.rs::first_values_win_within_file`, `tests/config/profile.rs::section_and_subsection_finals_stop_routes`, `tests/config/profile.rs::relation_final_accumulates_until_marker`, `tests/config/profile.rs::directory_sources_filter_and_accumulate_in_order`, `tests/config.rs::loads_config_path_list_in_order` |

## dns

| ID | Capability | Status | Evidence | Disposition | Closing | Missing | Policy and divergence | Symbols | Features | Tests |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| MIT-dns-1 | KDC/admin/password server DNS SRV discovery | partial | unproven | WP-10 | P2-15 | KDC/kpasswd and admin-to-kpasswd fallback exist; distinct remote-admin endpoint discovery missing. | - | - | - | - |
| MIT-dns-2 | KDC/KPASSWD DNS URI discovery | absent | unproven | WP-10 | P2-15 | SRV-only discovery. | - | - | - | - |
| MIT-dns-3 | DNS TXT realm lookup | absent | unproven | WP-10 | P2-15 | Flag only; resolver paths do not issue TXT. | - | - | - | - |
| MIT-dns-4 | Hostname canonicalization with DNS, `fallback`, short-name qualification and reverse DNS | partial | unproven | WP-10 | P2-15 | Host component lowercase normalization only; DNS/PTR/fallback policy absent. | - | - | - | - |
| MIT-dns-5 | KDC proxy transport over HTTPS (MS-KKDCP) | absent | unproven | WP-10 | P2-16 | No HTTP KDC transport. | - | - | - | - |
| MIT-dns-6 | Site-local KDC discovery (`sitename`) | absent | unproven | WP-10 | P2-15 | No site-local DNS queries; sitename is parsed with a diagnostic. | - | - | - | - |
| MIT-dns-7 | Primary KDC retry after invalid password | absent | unproven | WP-10 | P2-15 | Master metadata not a primary retry workflow. | - | - | - | - |
| MIT-dns-8 | KDC transport ordering, failover, timeout and TCP/UDP fallback | partial | unproven | WP-10 | P2-15 | Bounded UDP/TCP fallback/endpoint retries exist; request_timeout config/whole discovery budget absent. | - | - | - | - |

## gss

| ID | Capability | Status | Evidence | Disposition | Closing | Missing | Policy and divergence | Symbols | Features | Tests |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| MIT-gss-1 | Kerberos V5 GSS mechanism (initiator/acceptor, names, credentials, contexts) | partial | unproven | WP-12 | P2-18 | SPNEGO init/accept wrappers, not full GSS names/credentials/inquiry/context API. | - | - | - | - |
| MIT-gss-2 | SPNEGO mechanism negotiation; HTTP Negotiate token use | partial | unproven | WP-12 | P2-18 | One-init negotiation/MIC and HTTP exist; stateful continuation fails NegotiationRequiresState. | - | - | - | - |
| MIT-gss-3 | IAKERB mechanism | absent | unproven | WP-13 | P2-20 | No relay mechanism. | - | - | - | - |
| MIT-gss-4 | NegoEx mechanism negotiation integration | absent | unproven | WP-13 | P2-21 | Kerberos OIDs only, no NegoEx state. | - | - | - | - |
| MIT-gss-5 | Channel bindings; channel-bound result flag and strict CBT request | absent | unproven | WP-12 | P2-18 | Explicit no-channel-bindings API ignores initiator binding. | - | - | - | - |
| MIT-gss-6 | Credential delegation and delegation policy flag | absent | unproven | WP-12 | P2-18 | DelegationRequiresCredential is returned; the acceptor checks framing but imports no delegated credentials. | - | - | - | - |
| MIT-gss-7 | Credential selection, store extensions: `gss_acquire_cred_from`, `gss_store_cred_into`, `gss_store_cred` | partial | unproven | WP-12 | P2-19 +P2-18 | Cache/keytab client constructors exist, no GSS store/acquire-from interface or collection selection. | - | - | - | - |
| MIT-gss-8 | GSS naming extensions and name attributes (enterprise/X.509 names, auth indicators, PAC attributes) | partial | unproven | WP-12 | P2-19 +P2-18 +P2-22 | Principals/PAC summaries only; enterprise/certificate/anonymous names and RFC6680 attribute API missing. | - | - | - | - |
| MIT-gss-9 | GSS inquiry families: context, credential, name, mechanism and per-OID inquiry | partial | unproven | WP-12 | P2-18 | Public context metadata exists, no complete GSS inquiry/OID/SSF/session-key families. | - | - | - | - |
| MIT-gss-10 | MIC, Wrap/Unwrap, IOV wrap, IOV MIC, AEAD associated-data wrapping | partial | unproven | WP-12 | P2-19 +P2-18 | MIC/Wrap helpers exist, no IOV/AEAD operations. | - | - | - | - |
| MIT-gss-11 | GSS pseudo-random function / PRF+ | absent | unproven | WP-12 | P2-19 +P2-18 | KDF helpers are not GSS pseudo_random/PRF+. | - | - | - | - |
| MIT-gss-12 | DCE-style context establishment / three-leg setup and DCE-compatible wrap tokens | absent | unproven | WP-12 | P2-19 +P2-18 | No DCE context flag/state/layout API. | - | - | - | - |
| MIT-gss-13 | Export/import security context and credentials | absent | unproven | WP-12 | P2-19 +P2-18 | No transfer API; Clone/Debug context isn't secure ownership-transfer serialization. | - | - | - | - |
| MIT-gss-14 | GSS S4U impersonation and proxy credentials | partial | unproven | WP-12 | P2-19 +P2-17 +P2-18 | Client S4U exchange exists, no GSS acquire-impersonate credential/RBCD integration. | - | - | - | - |
| MIT-gss-15 | `gss_pseudo_random`, `gss_store_cred`, `gss_inquire_*`, exported names and standard v2 interface | partial | unproven | WP-12 | P2-19 +P2-18 | Init/accept/token helpers only; complete standard semantic surface absent. | - | - | - | - |

## admin

| ID | Capability | Status | Evidence | Disposition | Closing | Missing | Policy and divergence | Symbols | Features | Tests |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| MIT-admin-1 | Password-change client protocol (change password / set password) | partial | unproven | WP-15 | P2-23 | Authenticated change/target-set APIs exist; expiry responder/automatic change/restart absent. | Transport order matches changepw.c (TCP first over every endpoint, then UDP only after the TCP pass failed; `udp_preference_limit` does not apply). Three kept divergences: (1) UDP is never tried after a TCP request that may have been delivered (the result is `KpasswdOutcomeUnknown`), where MIT kills the connection and then runs its UDP pass; (2) one datagram per endpoint with no retransmit, where MIT resends the datagram on each of up to three passes; (3) only `ConnectionRefused` or `ConnectionReset` while the single UDP reply is awaited is a plain endpoint failure and every other failure after the datagram was sent stays `KpasswdOutcomeUnknown`, where MIT treats any UDP receive error as that server failing. | - | - | - |
| MIT-admin-2 | Microsoft set-password protocol compatibility | implemented | unit | ALREADY | - | - | - | `kadmin::ChangePasswdData`, `client::Tokio::change_password_for` | `tokio` | `tests/kadmin.rs::change_passwd_data_decodes_and_encodes_target_payload`, `tests/client/password_change.rs::tokio_client_changes_explicit_target_password` |
| MIT-admin-3 | Remote kadm5 client APIs over authenticated RPCSEC_GSS | absent | unproven | WP-15 | P2-24 | Kadmin module is kpasswd framing only, no principal/policy RPC client. | - | - | - | - |

## pac

| ID | Capability | Status | Evidence | Disposition | Closing | Missing | Policy and divergence | Symbols | Features | Tests |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| MIT-pac-1 | PAC parse, buffer get/add/type enumeration and client info | partial | unproven | WP-14 | P2-22 | Parse/raw table/get/client info present; no consistent PAC mutation/builder API. | - | - | - | - |
| MIT-pac-2 | PAC server checksum / KDC checksum verification (`krb5_pac_verify`, `krb5_pac_verify_ext`) | partial | unproven | WP-14 | P2-22 | Verifies server only; KDC signature merely parsed/required, no KDC/client-info verify_ext. | - | - | - | - |
| MIT-pac-3 | Ticket signature and full KDC checksum support | absent | unproven | WP-14 | P2-22 | Signature dispatch handles buffers 6/7 only; no ticket or full-KDC checksum verification. | - | - | - | - |
| MIT-pac-4 | UPN_DNS_INFO and logon-info PAC buffer parsing | implemented | fixture | ALREADY | - | - | - | `pac::UpnDnsInfo`, `pac::KerbValidationInfo` | - | `tests/pac.rs::parses_gokrb5_pac_container_and_buffers`, `tests/pac.rs::derives_ad_credentials_from_kerb_validation_info` |
| MIT-pac-5 | PAC attributes and requestor SID buffer handling | absent | unproven | WP-14 | P2-22 | Unrecognized buffers skipped, not typed decode/validation. | - | - | - | - |
| MIT-pac-6 | PA-PAC-REQUEST and PAC request choice | absent | unproven | WP-14 | P2-22 | PAC-OPTIONS/padata isn't PA-PAC-REQUEST. | - | - | - | - |
| MIT-pac-7 | PAC construction/signing (`krb5_pac_sign`, `sign_ext`, KDC ticket signing) | absent | unproven | WP-14 | P2-22 | Only verify_server_checksum; no builder or signing API (KDC issuance policy is not a deliverable). | - | - | - | - |

## authz

| ID | Capability | Status | Evidence | Disposition | Closing | Missing | Policy and divergence | Symbols | Features | Tests |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| MIT-authz-1 | `.k5login` principal-to-local-account authorization | absent | unproven | WP-17 | P2-25 | Parsed k5login fields only, no file authorizer. | - | - | - | - |
| MIT-authz-2 | `auth_to_local` RULE and DEFAULT mapping | absent | unproven | WP-17 | P2-25 | auth_to_local is parsed with a diagnostic; no RULE/DEFAULT mapping executes. | - | - | - | - |
| MIT-authz-3 | `auth_to_local_names` explicit principal mapping | absent | unproven | WP-17 | P2-25 | auth_to_local_names is parsed with a diagnostic; no mapping consumer. | - | - | - | - |
| MIT-authz-4 | `an2ln` principal-name-to-local-name authorization | absent | unproven | WP-17 | P2-25 | No local-name API. | - | - | - | - |
| MIT-authz-5 | `localauth` plugin interface | absent | unproven | WP-16 | P2-25 | No authorizer registry. | - | - | - | - |
| MIT-authz-6 | Host-to-realm plugin interface | partial | unproven | WP-16 | P2-15 | Built-in profile realm resolution, no trait/provider chain. | - | - | - | - |

## plugin

| ID | Capability | Status | Evidence | Disposition | Closing | Missing | Policy and divergence | Symbols | Features | Tests |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| MIT-plugin-1 | `clpreauth` client preauthentication | absent | unproven | WP-16 | P2-4 +P2-3 | No registered preauth trait. | - | - | - | - |
| MIT-plugin-2 | `ccselect` credential-cache selection | absent | unproven | WP-16 | P2-11 +P2-3 | Explicit cache constructors only, no k5identity/realm/hostname selection registry. | - | - | - | - |
| MIT-plugin-3 | `hostrealm` hostname/default-realm mapping | partial | unproven | WP-16 | P2-15 | Profile resolve exists, DNS/domain provider chain incomplete. | - | - | - | - |
| MIT-plugin-4 | `localauth` local authorization | absent | unproven | WP-16 | P2-25 | No local authorizer/provider. | - | - | - | - |
| MIT-plugin-5 | `profile` configuration provider | partial | unproven | WP-16 | P2-3 | Config value/parse exist, no hierarchical provider interface. | - | - | - | - |
| MIT-plugin-6 | `locate` server-location interface | partial | unproven | WP-16 | P2-15 | Built-in transport discovery, no provider registry. | - | - | - | - |
| MIT-plugin-7 | GSSAPI mechanism interface and SPNEGO mechanism plugins | partial | unproven | WP-16 | P2-21 +P2-3 +P2-18 | Fixed Kerberos negotiation only; no mechanism trait/registry. | - | - | - | - |
| MIT-plugin-8 | NegoEx module interface | absent | unproven | WP-13 | P2-21 | No NegoEx/provider contract. | - | - | - | - |
| MIT-plugin-9 | Interposer modules | absent | unproven | WP-16 | P2-6 | No safe extension/observer API; C symbol interposition mechanics excluded, Rust equivalent required. | - | - | - | - |
| MIT-plugin-10 | Password quality (`pwqual`) | out-of-scope | unproven | D1 | - | Nothing in scope (D1): server-side password-quality modules run in kadmind; the client only reports kpasswd result codes. | [docs/mit-krb5-parity.md#scope](mit-krb5-parity.md#scope) | - | - | - |
| MIT-plugin-11 | KADM5 hooks (`kadm5_hook`) | out-of-scope | unproven | D1 | - | Nothing in scope (D1): kadmind lifecycle hooks. | [docs/mit-krb5-parity.md#scope](mit-krb5-parity.md#scope) | - | - | - |
| MIT-plugin-12 | `kadm5_auth` | out-of-scope | unproven | D1 | - | Nothing in scope (D1): kadmind authorization modules. | [docs/mit-krb5-parity.md#scope](mit-krb5-parity.md#scope) | - | - | - |
| MIT-plugin-13 | `kdcpreauth`, `certauth`, `kdcpolicy`, KDB, authdata | out-of-scope | unproven | D1 | - | Nothing in scope (D1): KDC preauth, certauth, kdcpolicy, KDB and authdata plugins; service-side authdata validation stays in scope elsewhere. | [docs/mit-krb5-parity.md#scope](mit-krb5-parity.md#scope) | - | - | - |

## trace

| ID | Capability | Status | Evidence | Disposition | Closing | Missing | Policy and divergence | Symbols | Features | Tests |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| MIT-trace-1 | `KRB5_TRACE` diagnostic trace logging and programmatic trace controls | absent | unproven | WP-18 | P2-6 | Diagnostics JSON exists but no event sink/env trace controls. | - | - | - | - |

## removed

| ID | Capability | Status | Evidence | Disposition | Closing | Missing | Policy and divergence | Symbols | Features | Tests |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| MIT-removed-1 | Kerberos IV (`krb4`) support | rejected | unit | D2 | P1-14 | - | krb4 relations and selections are rejected before composition. `RejectedFeature::KerberosV4` [docs/security-policy.md#kerberos-v4](security-policy.md#kerberos-v4) | `error::RejectedFeature::KerberosV4` | - | `tests/policy/protocols.rs::enabling_protocol_relations_are_typed`, `tests/policy/protocols.rs::relation_api_rejects_removed_modes`, `tests/policy/protocols.rs::serde_protocol_relations_are_rejected` |
| MIT-removed-2 | Single-DES encryption types: DES-CBC-CRC/MD4/MD5 | rejected | unit | D2 | P1-14 | - | Single DES is rejected even when legacy flags are set. `RejectedFeature::SingleDes` [docs/security-policy.md#single-des](security-policy.md#single-des) | `error::RejectedFeature::SingleDes` | - | `tests/policy/expressions.rs::insecure_names_are_typed_rejections`, `tests/policy/selection.rs::numeric_selection_is_typed`, `src/client/s2k_tests.rs::forbidden_profiles_never_enter_pbkdf2` |
| MIT-removed-3 | RSA PKINIT client authentication | rejected | unit | D2 | P1-14 | - | RSA-mode PKINIT selections are rejected; RSA signatures on certificate chains are a separate matter for plan-2 PKINIT. `RejectedFeature::RsaPkinit` [docs/security-policy.md#rsa-pkinit](security-policy.md#rsa-pkinit) | `error::RejectedFeature::RsaPkinit` | - | `tests/policy/protocols.rs::relation_api_rejects_removed_modes`, `tests/policy/protocols.rs::enabling_protocol_relations_are_typed` |
| MIT-removed-4 | Draft 9 PKINIT variant | rejected | unit | D2 | P1-14 | - | Explicit selection of PA types 14/15 is rejected; their preferred_preauth_types entries and KDC advertisements are ignored with a diagnostic. `RejectedFeature::Draft9Pkinit` [docs/security-policy.md#draft9-pkinit](security-policy.md#draft9-pkinit) | `error::RejectedFeature::Draft9Pkinit` | - | `tests/policy/protocols.rs::draft9_api_selection_is_rejected`, `tests/policy/protocols.rs::draft9_preferences_are_ignored_with_diagnostics`, `tests/policy/protocols.rs::draft9_advertisements_are_ignored` |
| MIT-removed-5 | Triple-DES session-key issuance by default | out-of-scope | unproven | D1 | - | Nothing in scope (D1): default DES3 session-key issuance is KDC behavior; client opt-in policy is MIT-crypto-4 and MIT-crypto-10. | [docs/mit-krb5-parity.md#scope](mit-krb5-parity.md#scope) | - | - | - |
| MIT-removed-6 | RC4 session-key issuance by default | out-of-scope | unproven | D1 | - | Nothing in scope (D1): default RC4 session-key issuance is KDC behavior; client opt-in policy is MIT-crypto-5 and MIT-crypto-10. | [docs/mit-krb5-parity.md#scope](mit-krb5-parity.md#scope) | - | - | - |
| MIT-removed-7 | DES3/RC4 as default long-term key generation types | partial | unit | WP-15 | P2-24 +P1-14 | P2-24: remote-admin keysalt defaults and policy. Client request defaults never include DES3/RC4 (P1-14). | - | - | - | `tests/policy/profile.rs::policy_defaults_and_numeric_rejection` |
| MIT-removed-8 | Unkeyed checksum algorithms / unauthenticated integrity | rejected | unit | D2 | P1-14 | - | Unkeyed checksum ids are rejected at every selection entry point. `RejectedFeature::UnauthenticatedChecksum` [docs/security-policy.md#unauthenticated-checksum](security-policy.md#unauthenticated-checksum) | `error::RejectedFeature::UnauthenticatedChecksum` | - | `tests/policy/selection.rs::checksum_selection_is_typed`, `tests/policy/selection.rs::textual_checksum_selection_is_typed`, `tests/policy/raw_selection.rs::peer_checksum_selection_is_typed`, `tests/krb_safe.rs::rejects_unsupported_krb_safe_checksum_type` |
| MIT-removed-9 | Legacy unauthenticated KRB5 password change or cleartext password transport | rejected | unit | D2 | P1-14 | - | Unprotected password-change modes are rejected; unauthenticated replies never count as success. `RejectedFeature::UnprotectedPasswordChange` [docs/security-policy.md#unprotected-password-change](security-policy.md#unprotected-password-change) | `error::RejectedFeature::UnprotectedPasswordChange` | - | `tests/policy/protocols.rs::password_versions_fail_closed`, `tests/policy/protocols.rs::null_password_payload_is_rejected` |

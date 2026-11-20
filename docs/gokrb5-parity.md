# gokrb5 parity

<!-- Generated from gokrb5-parity.toml by tests/gokrb5_parity_manifest.rs. Do not edit. -->

Target: `github.com/jcmturner/gokrb5/v8` v8.4.4 (commit `47cd2e7744531465a983bf457bac38e6ad8f4684`, released 2023-02-25). The observed upstream master `855dbc707a37a21467aef6c0245fcf3328dc39ed` is tracked separately and is not the pin. Inventory of 2026-10-29, statuses as of `a6a1851`.

This file is generated from [`gokrb5-parity.toml`](gokrb5-parity.toml); edit the
TOML and regenerate it with `cargo test --test gokrb5_parity_manifest` (a drift
leaves the regenerated copy in the test's temporary directory).

The target is relative: a row is required because gokrb5 v8.4.4 provides it.
Platform credential stores, FAST armor, PKINIT and the other MIT-only features
are not gokrb5 rows, but the combined target is the union of this manifest and
[the MIT krb5 manifest](mit-krb5-parity.md), so they remain required there. Only
C-ABI or system-library wrappers and server machinery are excluded globally
([scope](mit-krb5-parity.md#scope)). Behaviours of gokrb5 that a secure
superset must not copy are listed under
[Upstream behaviours not copied](#upstream-behaviours-not-copied).

## Summary

| Status | Rows |
| --- | ---: |
| implemented | 18 |
| partial | 17 |
| absent | 0 |
| rejected | 0 |
| omitted | 0 |
| out-of-scope | 0 |
| total | 35 |

## Parity areas

| Area | Name | Status | Evidence | Next |
| --- | --- | --- | --- | --- |
| config | krb5.conf configuration | partial | unit tests cover parsing, defaults, realm lookup, enctype mapping, path-list loading, reader adapters and gokrb5-shaped JSON; every [libdefaults], [realms] and section relation has a typed value and a consumer, a diagnostic or an error (docs/config-relations.md); unknown relations are diagnostics and Strict mode rejects them; unit tests cover the MIT [domain_realm] semantics that diverge from gokrb5: DNS case folding and bare tags applied to subdomains | GO-config-2: relation consumers close across plan-2 todos 4, 15, 18 and 25; P2-28 closes the row; GO-config-3: primary-KDC retry and DNS realm discovery close in P2-15 |
| keytab | Keytab parsing, writing, and lookup | covered | unit tests cover gokrb5 fixtures, load/save, FILE names, env/default handling, generated entries, kvno and enctype lookup | - |
| ccache | Credential cache parsing, writing, and collection names | covered-with-gated-evidence | unit tests cover FILE/WRFILE/DIR parsing, writing, lookup, cacheconf entries, JSON, and env/default names; unit and property tests cover the record-count bounds checked against the remaining input, including the 32-bit LengthOverflow arms in the CI i686 job; historical upstream clelange/rskrb5: GitHub Actions run 28073249506 passed external kinit and kvno ccache coverage with TESTPRIVILEGED=1 on ubuntu-latest | keep privileged kinit/kvno coverage green: run locally with scripts/run-gated-integration.sh before release; the fork's ci.yml has no Docker integration job |
| crypto | Kerberos cryptography | covered | unit vectors cover AES-SHA1, AES-SHA2, DES3-CBC-SHA1-KD, RC4-HMAC, nfold, string-to-key, checksums, message encryption, and tamper rejection; one CryptoPolicy governs every enctype use; DES3 and RC4-HMAC need allow_des3/allow_rc4, and RC4-EXP and single DES are typed rejections | - |
| messages | ASN.1 and Kerberos message wrappers | partial | translated gokrb5 DER fixtures decode and round-trip through rasn-backed wrappers; typed domain errors keep their causes | GO-messages-1: a dedicated U2U request constructor closes in P2-17; GO-iana-1, GO-types-1 and GO-asn1tools-1: public assigned-number tables, authorization-data handling and checked DER utilities close in P2-27 |
| kadmin-kpasswd | RFC 3244 password change | covered-with-gated-evidence | unit tests cover ChangePasswdData, request/reply frames, AP-REP verification, and reply decryption; historical upstream clelange/rskrb5: GitHub Actions run 28073249506 passed docker_mit_kdc_tokio_client_change_password with TEST_KPASSWD=1 on ubuntu-latest | keep TEST_KPASSWD=1 green: run locally with scripts/run-gated-integration.sh before release; the fork's ci.yml has no Docker integration job |
| client | AS/TGS client flows | partial | unit tests cover password/keytab/ccache login, AS/TGS exchange, referrals, renewal, S4U2Self, S4U2Proxy, diagnostics, write-back, and cache behavior; unit tests cover the renewal series: the refresh band from the current ticket life, auto-renewal pacing, and the AS fallback for an expired or refused renewal; historical upstream clelange/rskrb5: GitHub Actions run 28073249506 passed 40 Docker MIT client_integration tests on ubuntu-latest, including DNS-SRV, referrals, renewal, cached tickets, ccache, HTTP, and kpasswd | GO-client-1: logger and key-access contract close in P2-6; GO-client-2: authenticated changed-client referrals and the logger; P2-28 closes the row; GO-client-3: U2U request constructor closes in P2-17; keep full Docker MIT integration green: run locally with scripts/run-gated-integration.sh before release; the fork's ci.yml has no Docker integration job |
| service | AP-REQ/AP-REP service validation | partial | unit tests cover AP-REQ validation, replay cache, clock skew, client address checks, AP-REP mutual auth, mutual-required completion enforcement (classifier and send wrappers fail closed), [libdefaults] clockskew on the Config-driven acceptors, keytab adapters, and PAC checksum validation; historical upstream clelange/rskrb5: GitHub Actions run 28073249506 passed Docker HTTP/SPNEGO service acceptance, raw KRB5 Negotiate, and replay rejection on ubuntu-latest | GO-service-1: logger contract and settings equivalence close in P2-6; keep Linux Docker HTTP/SPNEGO coverage green: run locally with scripts/run-gated-integration.sh before release; the fork's ci.yml has no Docker integration job |
| gssapi-spnego | GSSAPI, SPNEGO, and HTTP Negotiate tokens | partial | MIC, Wrap, SPNEGO token, raw KRB5 Negotiate, AP-REP verification, HTTP helpers, Tower middleware, and high-level header generation are covered; transport-agnostic async and blocking HTTP client wrappers retry 401 Negotiate responses through replayable request factories | GO-spnego-2 and GO-gssapi-1: credential delegation and a general mechanism/context interface close in P2-18; GO-client-6 and GO-service-3: HTTP client conveniences, cookies, redirects and the session manager close in P2-26; keep HTTP wrapper tests green in CI and Docker SPNEGO integration green locally before release |
| pac | PAC and NDR parsing | partial | unit tests cover PAC container data, validation info, credentials, UPN/DNS, S4U delegation, device info, claims, compression, server signatures, and AD credential summaries | GO-pac-1 and GO-credentials-3: KDC-checksum verification and a credential-attribute model close in P2-22; run TESTAD=1 against a maintained AD lab and keep it green before claiming full AD parity |
| docker-mit | Docker MIT KDC integration fixtures | covered-with-gated-evidence | focused forwarded-port configured-KDC AS login passed locally; full local direct-container-IP run timed out to 192.168.215.x:88 on macOS Docker networking; historical upstream clelange/rskrb5: GitHub Actions workflow_dispatch run 28073249506 passed Docker-backed integration on ubuntu-latest with INTEGRATION=1, TESTPRIVILEGED=1, TEST_KPASSWD=1, and TEST_DNS_KDC=1 | run scripts/run-gated-integration.sh run, and again with TEST_KPASSWD=1, locally before release; the fork's ci.yml has no Docker integration job and its workflow_dispatch declares no inputs |
| active-directory | Active Directory integration | blocked-on-lab | AD integration tests exist, the lab contract is documented in docs/ad-integration.md, TESTAD_REQUIRED=1 fails when the strict gate would otherwise soft-skip, lab-specific keytab path/hex/base64 overrides are supported, scripts/check-ad-integration-env.py preflights strict AD runs, scripts/check-github-ad-gate.py checks GitHub secret readiness and refuses to dispatch while ci.yml has no AD job, docs/ad-lab-provisioning.md documents the live AD lab contract, and docs/github-ad-gate-setup.md documents the secret setup a restored AD job needs; tests/client_ad_integration.rs statically verifies the embedded AD keytab fixtures contain testuser1, testuser2, testuser3, and sysHTTP principals with AES128, AES256, and RC4 key material; historical upstream clelange/rskrb5: GitHub Actions run 28119806826 passed the hosted keytab secret-shape dry-run job (upstream dispatch input test_ad_dry_run=true); historical upstream clelange/rskrb5: GitHub Actions run 28117082548 reached hosted ubuntu-latest and decoded the four keytab secrets before failing because the four endpoint secrets were absent | GO-doc-1: maintained live MIT, Samba and Windows AD evidence for this commit closes in P2-28; strict AD parity stays deferred: TEST_AD_USER_KDC_ADDR, TEST_AD_RESOURCE_KDC_ADDR, TEST_AD_USER_ADMIN_ADDR, and TEST_AD_RESOURCE_ADMIN_ADDR are unavailable and the fork's ci.yml has no AD job; do not add random or placeholder endpoint secrets; endpoint secrets must identify real reachable AD services; use docs/samba-ad-feasibility.md only as a backup spike, not as Windows AD parity evidence; to restore a hosted AD gate, add an AD job and its workflow_dispatch inputs to ci.yml, then run scripts/check-github-ad-gate.py before dispatching it; after strict AD is available, run scripts/check-ad-integration-env.py before TESTAD=1 TESTAD_REQUIRED=1 with lab-specific keytabs as needed and record keytab login, no-preauth login, user-domain PAC, and resource-trust PAC evidence |
| non-goals | Not required by gokrb5 alone (target-relative scope) | intentionally-out-of-scope | gokrb5 v8.4.4 has no API, KCM, KEYRING, MSLSA or MEMORY credential stores, FAST armor, PKINIT or system GSSAPI/SSPI facade, so they are not gokrb5 parity rows; the combined MIT and gokrb5 superset still requires the in-scope ones, tracked in docs/mit-krb5-parity.toml; only C-ABI or system-library wrappers and D1 server machinery are excluded globally | keep unsupported-store errors typed until the MIT manifest rows close (plan-2 todos 7-8 and 11-14) |

## Features

### config

| ID | Capability | Status | Evidence | Disposition | Closing | Missing | Policy and divergence | Symbols | Features | Tests |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| GO-config-1 | `Load`, `NewFromString`, `NewFromReader`, `NewFromScanner`, `New`, `JSON` | implemented | unit | WP-01 | P1-15 | - | Config::from_reader stands in for NewFromReader and NewFromScanner and shares the include byte budget; relative includes resolve against the working directory, as in MIT and v0.2.2. A missing or unreadable KRB5_CONFIG entry fails closed (MIT skips it), a deliberate divergence from MIT. | `config::Config::from_reader`, `config::Config::parse`, `config::Config::load_paths`, `config::Config::json` | `serde` | `tests/config/readers.rs::reader_accepts_exact_limit`, `tests/config/readers.rs::reader_composes_absolute_includes`, `tests/config.rs::loads_config_file`, `tests/config.rs::loads_config_path_list_in_order`, `tests/config.rs::config_json_matches_gokrb5_shape` |
| GO-config-2 | `[libdefaults]` values | partial | unit | WP-01 | P2-28 +P1-15 +P2-4 +P2-15 +P2-18 +P2-25 | Every [libdefaults] relation is parsed with a typed value and a consumer, a diagnostic or an error (P1-15, docs/config-relations.md); the consumers still missing close across P2-4, P2-15, P2-18 and P2-25, and P2-28 closes the row. | Relation names are case-sensitive, as in MIT; gokrb5 folds them (krb5conf.go:140). gokrb5 silently ignores unknown keys; here they are diagnostics and ParseMode::Strict turns every diagnostic into an error. A value asking for behaviour stricter than the library provides is an error in both modes. | `config::LibDefaults`, `config::Config::diagnostics` | - | `tests/config/relations_c1.rs::canonicalize`, `tests/config/diagnostics_e.rs::unknown_paths_preserve_scope_and_finality`, `src/config/diagnostic_tests.rs::every_diagnostic_promotes_to_error`, `tests/config/name_case.rs::upper_libdefaults_relation_is_not_honoured` |
| GO-config-3 | `[realms]`, endpoint precedence, KDC and kpasswd lookup | partial | unit | WP-10 | P2-15 +P1-15 | Primary-KDC retry after a bad password and DNS realm discovery (P2-15); configured kdc and kpasswd_server endpoints, the terminal `*`, the admin_server port-464 kpasswd fallback, IPv6 endpoints and KDC/kpasswd SRV lookup exist. | Relation names are case-sensitive, as in MIT; gokrb5 folds them (krb5conf.go:378). | `config::Realm` | - | `tests/config/realm_relations_d.rs::kdc`, `tests/config/realm_relations_d.rs::kpasswd_server`, `tests/config/realm_relations_d.rs::admin_server`, `tests/config/section_composition_d.rs::primary_kdc_precedence`, `tests/client_transport/cases.rs::kpasswd_admin_fallback_preserves_ipv6`, `tests/config/name_case.rs::realms_header_and_relation_are_case_sensitive` |
| GO-config-4 | `[domain_realm]` and realm resolution | implemented | unit | ALREADY | - | - | MIT krb5.conf(5) semantics: a key with an upper-case letter never matches (gokrb5 folds keys, krb5conf.go:479); the host is folded to ASCII lower case after a trailing dot is dropped, and at each suffix level the leading-dot tag is tried before the bare tag, so a bare tag covers its subdomains. gokrb5 v8.4.4 compares the query as given and walks leading-dot tags only. | `config::Config::resolve_realm` | - | `tests/config/section_composition_d.rs::domain_realm`, `tests/config/name_case.rs::upper_domain_realm_key_never_matches` |

### keytab

| ID | Capability | Status | Evidence | Disposition | Closing | Missing | Policy and divergence | Symbols | Features | Tests |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| GO-keytab-1 | `Unmarshal`, `Load`, `Marshal`, `Write` | implemented | fixture | ALREADY | - | - | Saved keytabs are private to the owner and symlinked destinations are rejected. | `keytab::Keytab`, `keytab::Keytab::parse` | - | `tests/keytab.rs::parses_gokrb5_keytab_fixture`, `tests/keytab.rs::roundtrips_gokrb5_keytab_fixture`, `tests/keytab.rs::saves_and_loads_keytab_file`, `tests/keytab.rs::serializer_checks_version_one_realm_count`, `tests/keytab.rs::rejects_partial_next_entry_sizes` |
| GO-keytab-2 | `New`, `AddEntry`, `GetEncryptionKey`, `String`, `JSON` | implemented | unit | ALREADY | - | - | Metadata JSON redacts key values. | `keytab::Keytab::add_entry_from_password`, `keytab::Keytab::find_key`, `keytab::EntryMetadata` | `serde` | `tests/keytab.rs::generates_gokrb5_user_keytab_entries_from_password`, `tests/keytab.rs::finds_matching_key_by_principal_kvno_and_etype`, `tests/keytab.rs::kvno_zero_selects_newest_matching_key`, `tests/keytab.rs::keytab_metadata_json_redacts_key_values` |

### ccache

| ID | Capability | Status | Evidence | Disposition | Closing | Missing | Policy and divergence | Symbols | Features | Tests |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| GO-credentials-1 | CCache v1–v4 read, v4 header, `LoadCCache`, `Unmarshal` | implemented | fixture | ALREADY | - | - | gokrb5 has a ccache reader only; writing and DIR collections are a deliberate superset. Every record count is checked against the remaining input before memory is reserved (see GO-T2-8). | `ccache::CCache`, `ccache::CCache::parse` | - | `tests/ccache.rs::parses_gokrb5_ccache_fixture`, `tests/ccache.rs::roundtrips_gokrb5_ccache_fixture`, `tests/ccache.rs::serde_supported_ccache_versions_roundtrip`, `tests/ccache.rs::legacy_ccaches_reject_unrepresentable_fields` |
| GO-credentials-2 | CCache accessors / entry filtering | implemented | unit | ALREADY | - | - | - | `ccache::CCache::entries`, `ccache::CCache::config_entries` | - | `tests/ccache.rs::gets_client_and_server_entries`, `tests/ccache.rs::entries_filter_out_x_cacheconf_credentials` |

### pac

| ID | Capability | Status | Evidence | Disposition | Closing | Missing | Policy and divergence | Symbols | Features | Tests |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| GO-credentials-3 | Credentials and AD identity attributes | partial | unit | WP-14 | P2-22 | PAC AdCredentials and the validated service identity exist; there is no generic mutable credential-attribute model or serialization contract (P2-22). | - | `pac::AdCredentials` | - | `tests/pac.rs::derives_ad_credentials_from_kerb_validation_info` |

### client

| ID | Capability | Status | Evidence | Disposition | Closing | Missing | Policy and divergence | Symbols | Features | Tests |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| GO-client-1 | Client constructors, login and lifecycle | partial | unit | WP-18 | P2-6 +P2-4 | Password, keytab and ccache constructors, login, destroy, diagnostics and cache APIs exist; the logger contract (P2-6) and key-access and lifecycle compatibility (P2-4) are missing. | - | `client::Tokio` | `tokio` | `tests/client/session_cache.rs::tokio_client_affirm_login_returns_current_cache_only_tgt` |
| GO-client-2 | AS exchange, pre-authentication, referrals, FAST indicators | partial | unit | WP-04 | P2-28 +P2-4 +P2-6 +P2-7 | Encrypted timestamp, ETYPE-INFO2/INFO/PW-SALT selection, cookies and PA-REQ-ENC-PA-REP exist; authenticated changed-client referrals (P2-7) and the logger (P2-6) are missing, and P2-28 closes the row. | - | - | `tokio` | `tests/client/login_preauth.rs::parses_kdc_preauth_required_error_and_selects_etype_info2`, `tests/client/as_exchange.rs::process_as_rep_rejects_invalid_pa_req_enc_pa_rep_checksum`, `tests/client/review_integrity.rs::as_reply_checksum_type_is_the_reply_keys_own`, `tests/client/review_integrity.rs::tgs_reply_checksum_type_is_the_reply_keys_own` |
| GO-client-3 | TGS, referrals, U2U, S4U, service ticket cache | partial | unit | WP-11 | P2-17 | TGS, referrals, S4U and the service-ticket cache with JSON and removal exist; there is no dedicated U2U request constructor or flow (P2-17). | - | - | `tokio` | `tests/client/tgs_exchange.rs::process_tgs_rep_with_referral_accepts_intermediate_tgt`, `tests/client/tgs_exchange.rs::builds_s4u2proxy_tgs_req_with_evidence_ticket` |
| GO-client-4 | UDP/TCP KDC transport and endpoint iteration | implemented | unit | ALREADY | - | - | KDC TCP framing uses 31-bit lengths and rejects the reserved bit before reading the body; an oversized UDP datagram is an error, never a truncated prefix (see GO-T2-9). | `client::transport::Tokio`, `client::transport::kdc_tcp_record_length` | `tokio` | `tests/client_transport/tests/affinity.rs::tokio_transport_auto_honors_tcp_first_udp_preference_limit`, `tests/client_transport/cases.rs::tokio_transport_auto_retries_tcp_after_udp_response_too_big`, `tests/client_transport/cases.rs::udp_transport_rejects_truncated_datagram`, `tests/client_transport/cases.rs::configured_endpoint_preserves_bare_ipv6` |
| GO-client-5 | TGT sessions, renewal and renewal fallback | implemented | unit | ALREADY | - | - | A TGT is due in the last sixth of end_time - start_time (gokrb5 measures from auth_time); a failed or no-progress refresh sleeps the retry delay; with a password or keytab a refused or expired renewal falls back to the AS exchange, which gokrb5 v8.4.4 does not do while renew_till is in the future. | `client::Tokio::spawn_auto_renewal_with_retry` | `tokio` | `tests/client/session_cache.rs::tokio_client_tracks_multiple_tgt_sessions`, `tests/client/session_cache.rs::tokio_client_auto_renewal_uses_as_when_renewal_refused`, `tests/client/session_cache.rs::tokio_client_auto_renewal_paces_after_renewal`, `tests/client/review_cancellation.rs::tokio_client_auto_renewal_handle_aborts` |

### gssapi-spnego

| ID | Capability | Status | Evidence | Disposition | Closing | Missing | Policy and divergence | Symbols | Features | Tests |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| GO-client-6 | HTTP SPNEGO client | partial | unit | WP-19 | P2-26 | Transport-agnostic 401 retry helpers over replayable request factories exist; there is no ready HTTP client with a cookie jar, redirect policy and Get/Post conveniences (P2-26). | Mutual authentication requested by the caller fails closed unless the final response carries an AP-REP that verifies (see GO-T2-5). | `http::send_with_negotiate` | `http` | `tests/http.rs::negotiate_http_client_retries_challenge_with_replayable_request` |

### kadmin-kpasswd

| ID | Capability | Status | Evidence | Disposition | Closing | Missing | Policy and divergence | Symbols | Features | Tests |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| GO-client-7 | RFC 3244 password change | implemented | unit | ALREADY | - | - | Success is reported only through a verified AP-REP and KRB-PRIV; a bare KRB-ERROR with result 0 is Kadmin::UnauthenticatedSuccess and the stored password is kept. A possibly delivered request is never retried (see GO-T2-10). [docs/security-policy.md#unprotected-password-change](security-policy.md#unprotected-password-change) | `client::Tokio::change_password`, `client::Tokio::change_password_for` | `tokio` | `tests/client/password_change.rs::tokio_client_changes_explicit_target_password`, `tests/client/password_change.rs::tokio_client_rejects_unsigned_kpasswd_success`, `tests/client_transport/cases.rs::kpasswd_lost_reply_does_not_retry_endpoint` |

### service

| ID | Capability | Status | Evidence | Disposition | Closing | Missing | Policy and divergence | Symbols | Features | Tests |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| GO-service-1 | AP-REQ verification / credentials | partial | unit | WP-18 | P2-6 | A strict AP-REQ validator with address, PAC, keytab-override and clockskew settings exists; the logger contract and settings equivalence are missing (P2-6). | The authenticator realm is compared with the ticket realm (see GO-T2-4); Config-driven acceptors apply [libdefaults] clockskew, which gokrb5 reads on the client side only. | `service::Validator`, `service::ValidatedApReq` | `messages` | `tests/service.rs::rejects_authenticator_client_realm_mismatch`, `tests/http.rs::tower_layer_config_clockskew_rejects_stale_authenticator` |
| GO-service-2 | Global replay cache | implemented | unit | ALREADY | - | - | Per-instance or shared caches with a capacity (65,536 records by default) that fail closed when full replace gokrb5's unbounded process-wide singleton (see GO-T2-7). | `service::ReplayCache`, `service::SharedReplayCache` | `messages` | `tests/service.rs::replay_lifecycle_capacity_preserves_live_records`, `tests/service.rs::replay_lifecycle_accepts_concurrent_shared_validations`, `src/service/replay/policy_tests.rs::capacity_default_and_custom_limit_are_enforced` |

### gssapi-spnego

| ID | Capability | Status | Evidence | Disposition | Closing | Missing | Policy and divergence | Symbols | Features | Tests |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| GO-service-3 | HTTP server authentication wrapper | partial | unit | WP-19 | P2-26 | Tower NegotiateLayer and NegotiateService with request identity exist; session-manager continuation and the logger contract are missing (P2-26). | - | `http::NegotiateLayer`, `http::NegotiateService` | `tower` | `tests/http.rs::negotiate_layer_integrates_with_axum_router` |
| GO-spnego-1 | SPNEGO tokens and mech negotiation | implemented | fixture | ALREADY | - | - | Stateless continuations fail closed and supplied mechListMICs are verified (see GO-T2-6). | `spnego::NegTokenInit`, `spnego::NegTokenResp`, `spnego::NegState` | `spnego` | `tests/spnego.rs::decodes_and_roundtrips_gokrb5_neg_token_init`, `tests/spnego.rs::decodes_and_roundtrips_gokrb5_neg_token_resp`, `tests/spnego.rs::acceptor_rejects_stateless_continuation`, `tests/spnego.rs::acceptor_rejects_unverified_mech_list_mic` |
| GO-spnego-2 | Kerberos GSS mechanism tokens, AP-REQ and AP-REP | partial | unit | WP-12 | P2-18 | AP-REQ checksum and flags, AP-REP verification and MIC checks exist; an advertised delegation flag cannot carry or import credentials (DelegationRequiresCredential) until P2-18. | - | `spnego::InitiatorContext` | `spnego` | `tests/http.rs::completion_verifies_acceptor_mic`, `tests/http.rs::blocking_mutual_wrapper_rejects_a_missing_ap_rep` |

### ccache

| ID | Capability | Status | Evidence | Disposition | Closing | Missing | Policy and divergence | Symbols | Features | Tests |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| GO-credentials-4 | Ccache integration and environment/default selection | implemented | unit | ALREADY | - | - | - | `client::Tokio::from_ccache`, `client::Tokio::from_ccache_name` | `tokio` | `tests/client/session_cache.rs::tokio_client_from_ccache_ignores_other_client_credentials`, `tests/client/session_cache.rs::tokio_client_exports_and_saves_ccache`, `tests/ccache.rs::saves_and_loads_ccache_from_env` |

### crypto

| ID | Capability | Status | Evidence | Disposition | Closing | Missing | Policy and divergence | Symbols | Features | Tests |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| GO-crypto-1 | Supported enctypes and checksums | implemented | unit | WP-02 | P1-14 | - | One CryptoPolicy governs every enctype use. Default lists are AES only; DES3 and RC4-HMAC need allow_des3/allow_rc4; RC4-EXP and single DES are typed rejections; MIT list syntax applies and forbidden positive terms are errors. des3-cbc-sha1 and des3-hmac-sha1 mean etype 16 as in MIT, where gokrb5 maps them to unimplemented 7 and 8. [docs/security-policy.md#policy](security-policy.md#policy) | `crypto::KerberosEtype`, `crypto::CryptoPolicy::check_use` | - | `tests/crypto_aes.rs::reports_aes_sha1_metadata`, `tests/crypto_aes.rs::reports_aes_sha2_metadata_and_dispatch`, `tests/crypto_des3.rs::reports_des3_metadata_and_dispatch`, `tests/crypto_rc4.rs::reports_rc4_hmac_metadata_and_dispatch`, `tests/policy/profile.rs::policy_checks_every_use`, `tests/policy/selection.rs::numeric_selection_is_typed` |
| GO-crypto-2 | String-to-key, key derivation, encryption/integrity | implemented | unit | ALREADY | - | - | AES-SHA2 verifies the HMAC before decrypting (see GO-T2-1). | `crypto::AesSha1Etype`, `crypto::AesSha2Etype`, `crypto::Des3CbcSha1KdEtype`, `crypto::Rc4HmacEtype` | - | `tests/crypto_aes.rs::nfold_matches_gokrb5_vectors`, `tests/crypto_aes.rs::aes128_string_to_key_matches_gokrb5_vectors`, `tests/crypto_aes.rs::aes_sha2_string_to_key_matches_gokrb5_vectors`, `tests/crypto_des3.rs::des3_string_to_key_matches_gokrb5_vectors`, `tests/crypto_rc4.rs::rc4_hmac_string_to_key_matches_gokrb5_vector`, `src/crypto.rs::sha2_rejects_bad_tag_before_any_decryption` |

### messages

| ID | Capability | Status | Evidence | Disposition | Closing | Missing | Policy and divergence | Symbols | Features | Tests |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| GO-messages-1 | Kerberos wire message marshal/unmarshal | partial | unit | WP-11 | P2-17 | AS/TGS/AP/KRB-SAFE/KRB-PRIV/KRB-CRED/KRB-ERROR codecs and builders exist; there is no dedicated U2U request constructor, only raw additional-ticket and option bits (P2-17). | - | - | `messages` | `tests/kdc_req.rs::decodes_gokrb5_as_req_fixtures`, `tests/asn1_fixture_matrix.rs::rasn_kerberos_roundtrips_expected_gokrb5_asn1_fixtures` |

### kadmin-kpasswd

| ID | Capability | Status | Evidence | Disposition | Closing | Missing | Policy and divergence | Symbols | Features | Tests |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| GO-kadmin-1 | RFC 3244 ChangePasswdData, Request/Reply, ChangePasswdMsg | implemented | fixture | ALREADY | - | - | A bare KRB-ERROR reply can never assert success. | `kadmin::ChangePasswdData`, `kadmin::Request`, `kadmin::Reply` | `messages` | `tests/kadmin.rs::change_passwd_data_matches_gokrb5_fixture`, `tests/kadmin.rs::kpasswd_request_builder_encrypts_payload_and_frames_request`, `tests/kadmin.rs::kpasswd_reply_decrypt_result_returns_parsed_error_result`, `tests/kadmin.rs::kpasswd_bare_error_cannot_assert_success` |

### pac

| ID | Capability | Status | Evidence | Disposition | Closing | Missing | Policy and divergence | Symbols | Features | Tests |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| GO-pac-1 | PAC container and signatures | partial | unit | WP-14 | P2-22 | Container parsing and server-checksum verification exist; the KDC checksum is parsed and required but not verified cryptographically (P2-22). | - | `pac::Pac::verify_server_checksum` | - | `tests/pac.rs::parses_signature_data_and_zeroes_checksum_bytes` |
| GO-pac-2 | PAC buffer payload decoders | implemented | fixture | ALREADY | - | - | Claims decompression is bounded; decoded PAC data is not authorization until the required signatures are checked. | `pac::KerbValidationInfo`, `pac::UpnDnsInfo`, `pac::CredentialData`, `pac::NtlmSupplementalCredential`, `pac::S4UDelegationInfo`, `pac::DeviceInfo`, `pac::ClaimsSet` | - | `tests/pac.rs::parses_gokrb5_pac_container_and_buffers`, `tests/pac.rs::derives_ad_credentials_from_kerb_validation_info`, `tests/pac.rs::decrypts_credentials_info_and_parses_ntlm_supplemental_credential`, `tests/pac.rs::parses_s4u_delegation_info`, `tests/pac.rs::parses_gokrb5_client_claims_info_multi_str`, `tests/pac.rs::parses_generated_compressed_claims_formats` |

### gssapi-spnego

| ID | Capability | Status | Evidence | Disposition | Closing | Missing | Policy and divergence | Symbols | Features | Tests |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| GO-gssapi-1 | GSS mechanism, OIDs, status and context flags | partial | unproven | WP-12 | P2-18 | Fixed Kerberos tokens, OIDs and context flags exist; there is no general mechanism or context interface and no complete GSS status mapping (P2-18). | - | `spnego::Krb5TokenId` | `spnego` | - |
| GO-gssapi-2 | MIC and Wrap tokens | implemented | unit | ALREADY | - | - | - | `spnego::MicToken`, `spnego::WrapToken` | `spnego` | `tests/gssapi.rs::mic_token_decodes_and_roundtrips_gokrb5_vectors`, `tests/gssapi.rs::mic_token_rejects_wrong_sender_and_missing_checksum`, `tests/gssapi.rs::sealed_wrap_token_encrypts_decrypts_and_roundtrips`, `tests/gssapi.rs::sealed_wrap_token_rejects_tampering_and_wrong_usage` |

### messages

| ID | Capability | Status | Evidence | Disposition | Closing | Missing | Policy and divergence | Symbols | Features | Tests |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| GO-iana-1 | Kerberos assigned numbers and lookup tables | partial | unproven | WP-20 | P2-27 | Identifiers and selected mappings are spread across modules; there are no exhaustive public assigned-numbers tables (P2-27). | - | - | - | - |
| GO-krberror-1 | Typed/wrapped library errors | implemented | unit | ALREADY | - | - | Typed domain enums keep their causes through Error::source, which gokrb5's Krberror does not expose. | `error::Any` | - | `tests/error_api/sources.rs::unknown_outcome_io_chain`, `tests/config.rs::load_paths_reports_failing_path_and_io_source`, `tests/policy/rejections.rs::catalogue_converts_without_losing_feature` |
| GO-types-1 | Principal names, credentials, addresses, flags, cryptosystem, PA data | partial | unproven | WP-20 | P2-27 | rasn types and principals exist; AD-KDCIssued and AND-OR authorization data are rejected rather than handled, and high-level helpers are incomplete (P2-27). | - | - | - | - |
| GO-asn1tools-1 | ASN.1 length/application tag utilities | partial | unit | WP-20 | P2-27 | The internal SPNEGO DER reader validates lengths and rejects non-minimal forms; there are no public checked app-tag and length utilities with size and nesting budgets (P2-27). | - | - | - | `src/spnego/der/tests.rs::der_lengths_reject_nonminimal_forms` |

### active-directory

| ID | Capability | Status | Evidence | Disposition | Closing | Missing | Policy and divergence | Symbols | Features | Tests |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| GO-doc-1 | Supported encryption and interoperability statement | partial | unproven | WP-14 | P2-28 | Docker MIT evidence is historical-upstream and AD is blocked-on-lab; a maintained Docker MIT 1.22.2 and Samba gate on this commit and a strict Windows AD run are needed (P2-28). | - | - | - | - |

<a id="upstream-behaviours-not-copied"></a>
## Upstream behaviours not copied

| Status | Rows |
| --- | ---: |
| implemented | 0 |
| partial | 1 |
| absent | 0 |
| rejected | 13 |
| omitted | 0 |
| out-of-scope | 0 |
| total | 14 |

### Table 2 behaviours

| ID | Capability | Status | Evidence | Disposition | Closing | Missing | Policy and divergence | Symbols | Features | Tests |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| GO-T2-1 | AES-SHA2 decrypts before authenticating | rejected | unit | ALREADY | - | - | The HMAC is verified in constant time before any decryption (RFC 8009 section 5); no unauthenticated plaintext reaches callers or errors. | `crypto::AesSha2Etype` | - | `src/crypto.rs::sha2_rejects_bad_tag_before_any_decryption`, `src/crypto.rs::integrity_failure_erases_scratch` |
| GO-T2-2 | AS-REP reply encryption enctype is not constrained by request list | rejected | unit | ALREADY | - | - | The reply-key enctype must be one the request offered and the policy permits before any key derivation, and the session-key enctype is checked too (Client::EnctypeNotRequested, CryptoPolicy). | `crypto::CryptoPolicy::check_use` | `tokio` | `tests/client/login_preauth.rs::initial_as_rep_outside_requested_enctypes_is_rejected`, `tests/client/as_exchange.rs::process_as_rep_rejects_session_key_outside_requested_enctypes`, `tests/policy/client.rs::as_reply_rejects_excluded_key_before_crypto` |
| GO-T2-3 | TGS-REP server identity checks are commented out | rejected | unit | ALREADY | - | - | Both the decrypted sname and the ticket sname are bound to the requested service (Client::ServicePrincipalMismatch); the referral exception is limited to a cross-realm TGT form. | - | `tokio` | `tests/client/tgs_exchange.rs::process_tgs_rep_with_referral_accepts_intermediate_tgt`, `tests/client/as_exchange.rs::rejects_as_rep_ticket_service_mismatch` |
| GO-T2-4 | AP-REQ identity comparison omits realm | rejected | unit | ALREADY | - | - | The acceptor compares the authenticator realm and ordered name components with the ticket's (RFC 4120 section 3.2.3) and returns the ticket-derived identity. | `service::Validator` | `messages` | `tests/service.rs::rejects_authenticator_client_realm_mismatch` |
| GO-T2-5 | AP-REP verification unimplemented | rejected | unit | ALREADY | - | - | The AP-REP is decrypted and matched to the authenticator; with mutual authentication requested, the HTTP wrappers return MutualAuthenticationNotProven unless the final response proves it. | `service::VerifiedApRep` | `http` | `tests/http.rs::blocking_mutual_wrapper_rejects_a_missing_ap_rep`, `tests/http.rs::mutual_mask_matrix_rejects_unproven_responses`, `tests/http.rs::completion_rejects_invalid_metadata` |
| GO-T2-6 | SPNEGO mechListMIC is declared unused for Kerberos | rejected | unit | ALREADY | - | - | The acceptor verifies supplied mechListMICs, requires one for a non-first Kerberos selection and replies with a reciprocal MIC (RFC 4178); the initiator verifies the acceptor MIC on completion. Multi-round continuation fails closed until plan-2 todo 18. | `spnego::AcceptedContext` | `spnego` | `tests/spnego.rs::acceptor_rejects_unverified_mech_list_mic`, `tests/spnego.rs::acceptor_rejects_nonfirst_kerberos`, `tests/spnego.rs::mech_list_mic_accepts_nonfirst_and_authenticates_response`, `tests/http.rs::completion_verifies_acceptor_mic` |
| GO-T2-7 | Replay protection is process-wide and unbounded | rejected | unit | ALREADY | - | - | Replay caches are per instance or explicitly shared, bounded (65,536 records and 300 s skew by default), expire records and fail closed when full. | `service::ReplayCache` | `messages` | `tests/service.rs::replay_lifecycle_capacity_preserves_live_records`, `src/service/replay/policy_tests.rs::capacity_default_and_custom_limit_are_enforced` |
| GO-T2-8 | CCache parser uses input-derived counts/slices without bounds checks | rejected | unit | ALREADY | - | - | Every principal component, address and authorization-data count is checked against the remaining input before memory is reserved (Ccache::Truncated, Ccache::LengthOverflow on 32-bit targets). | `ccache::CCache::parse` | - | `tests/ccache.rs::rejects_impossible_component_count`, `tests/ccache.rs::rejects_impossible_address_count`, `tests/ccache.rs::rejects_impossible_auth_data_count`, `tests/ccache.rs::parse_never_panics_on_arbitrary_input` |
| GO-T2-9 | KDC TCP frame length is used directly for allocation; UDP buffer truncates | rejected | unit | ALREADY | - | - | TCP record marks are 31-bit, the reserved bit is rejected and the configured size cap is checked before allocation (RFC 4120 section 7.2.2); an oversized UDP datagram is Client::UdpResponseTooLarge. | `client::transport::kdc_tcp_record_length` | `tokio` | `tests/client_transport/cases.rs::kdc_tcp_rejects_reserved_bit_before_body_read`, `tests/client_transport/cases.rs::udp_transport_rejects_truncated_datagram`, `src/client/transport/framing.rs::reserved_record_bit_is_rejected` |
| GO-T2-10 | kpasswd retries next endpoint after potentially delivered request | rejected | unit | ALREADY | - | - | Once a kpasswd request may have been delivered it is never retried on another endpoint or protocol; the result is Client::KpasswdOutcomeUnknown. | - | `tokio` | `tests/client_transport/cases.rs::kpasswd_lost_reply_does_not_retry_endpoint`, `tests/client_transport/cases.rs::kpasswd_udp_timeout_does_not_retry_tcp`, `tests/client/password_change.rs::kpasswd_lost_reply_has_unknown_outcome` |
| GO-T2-11 | TGS reply verification omits ticket version, transited policy and requested enctype policy | rejected | unit | ALREADY | - | - | tkt-vno and authenticator-vno other than 5 are rejected, the requested session enctype is enforced, and a cross-realm ticket without TRANSITED-POLICY-CHECKED needs an explicit TransitPolicy. Profile-driven capaths transit validation is plan-2 todo 17 (MIT-client-5). | `service::TransitPolicy` | `messages` | `tests/service.rs::service_rejects_nested_ticket_version`, `tests/service.rs::transit_rejects_unchecked_cross_realm_paths`, `tests/service.rs::transit_policy_rejects_mismatching_paths`, `tests/client/tgs_exchange.rs::process_tgs_rep_rejects_session_key_outside_requested_enctypes` |
| GO-T2-12 | Principal normalization is not consistently RFC-canonical | rejected | unit | ALREADY | - | - | Host-based constructors fold the DNS host component to lower case (RFC 4120 section 6.2.1) so host-case variants share one principal and cached ticket; service names and realms keep their case. | `client::principal::Principal::host_based_service` | `messages` | `tests/client_principal.rs::host_based_service_folds_dns_host_case`, `tests/client_principal.rs::host_based_service_preserves_service_and_realm_case` |
| GO-T2-13 | Configuration parser silently ignores unsupported/unknown keys and some section features | rejected | unit | ALREADY | - | - | Unknown sections and relations are ConfigDiagnostic values, ParseMode::Strict makes every diagnostic an error, and settings stricter than current behaviour fail in both modes (plan-1 todo 15). | `config::Config::diagnostics`, `config::diagnostic::ParseMode` | - | `tests/config/diagnostics_e.rs::unknown_paths_preserve_scope_and_finality`, `src/config/diagnostic_tests.rs::every_diagnostic_promotes_to_error`, `tests/config/sections_d.rs::server_only_sections_are_not_silent` |
| GO-T2-14 | ASN.1 helper length parsing is low-level and caller must validate | partial | unit | WP-20 | P2-27 | Public checked app-tag and length utilities with explicit size and nesting budgets (P2-27); raw convenience codecs keep their documented prefix decoding. | No unvalidated length helper is public; the internal SPNEGO DER reader bounds slices, rejects indefinite and non-minimal lengths and checks OIDs. | - | - | `src/spnego/der/tests.rs::der_lengths_reject_nonminimal_forms` |

## Upstream changes after the pin

Commits between v8.4.4 and the observed master; protocol-relevant ones need named regression tests.

| Commit | Change | Protocol relevant | Tests |
| --- | --- | --- | --- |
| `855dbc707a37a21467aef6c0245fcf3328dc39ed` | Add HMAC-SHA256/HMAC-SHA384 signature sizes (RFC 8009) | yes | tests/crypto_aes.rs::aes128_sha2_derive_checksum_integrity_and_crypto_match_gokrb5_vectors, tests/crypto_aes.rs::aes256_sha2_derive_checksum_integrity_and_crypto_match_gokrb5_vectors |
| `f8771d3db4076ffb0466df5b44f3ea0c6a962186` | Fix KDC-REP verification | yes | tests/client/as_exchange.rs::rejects_as_rep_ticket_service_mismatch, tests/client/tgs_exchange.rs::process_tgs_rep_rejects_session_key_outside_requested_enctypes |
| `1b8a082de8677cfacfb1750c6789e05dbd62dfca` | Fix gofmt | no | - |
| `8464c11eee151ff1b7b04d3a06a6ab2e2b72d288` | Remove -d from the gofmt test | no | - |
| `00865968d09b3acdab9b6f0b366f1956f7291f88` | Update Go versions in tests | no | - |
| `64e62c1691b3a8e3bd6042171240a2a2dd019704` | UDP client connection uses Dial for address resolution | yes | tests/client_transport/cases.rs::configured_endpoint_preserves_bare_ipv6 |
| `92aa4db89ebe5e6f8871387fab88c3c64d9ea571` | Fix TCP resolve when using IPv6 | yes | tests/client_transport/cases.rs::configured_endpoint_preserves_bare_ipv6, tests/client_transport/cases.rs::kpasswd_admin_fallback_preserves_ipv6 |

## Parity gates

| Gate | Status | Proves | Command | CI job | Evidence | Next |
| --- | --- | --- | --- | --- | --- | --- |
| Full Linux Docker MIT integration | historical-upstream | docker-mit, client, service, ccache | `scripts/run-gated-integration.sh run --test client_integration` | - | historical upstream clelange/rskrb5: GitHub Actions run 28073249506 passed the Docker-backed integration job on ubuntu-latest with 40 client_integration tests green | run locally with scripts/run-gated-integration.sh before release; the fork's ci.yml has no Docker integration job |
| Linux Docker MIT password-change integration | historical-upstream | kadmin-kpasswd, client | `TEST_KPASSWD=1 scripts/run-gated-integration.sh run --test client_integration` | - | historical upstream clelange/rskrb5: GitHub Actions run 28073249506 passed docker_mit_kdc_tokio_client_change_password with TEST_KPASSWD=1 on ubuntu-latest | run locally with scripts/run-gated-integration.sh before release; the fork's ci.yml has no Docker integration job |
| Linux Docker DNS-SRV KDC discovery | historical-upstream | docker-mit, client | `TEST_DNS_KDC=1 scripts/run-gated-integration.sh run --test client_integration docker_mit_kdc_dns_srv_as_login -- --nocapture` | - | historical upstream clelange/rskrb5: GitHub Actions run 28073249506 passed docker_mit_kdc_dns_srv_as_login with TEST_DNS_KDC=1 on ubuntu-latest | run locally with scripts/run-gated-integration.sh before release; the fork's ci.yml has no Docker integration job |
| Linux Docker privileged external ccache | historical-upstream | ccache, client | `TESTPRIVILEGED=1 scripts/run-gated-integration.sh run --test client_integration` | - | historical upstream clelange/rskrb5: GitHub Actions run 28073249506 passed docker_mit_kdc_loads_external_kinit_ccache and docker_mit_kdc_reads_external_kvno_service_ticket_ccache with TESTPRIVILEGED=1 on ubuntu-latest | run locally with scripts/run-gated-integration.sh before release; the fork's ci.yml has no Docker integration job |
| Linux Docker HTTP SPNEGO service integration | historical-upstream | service, gssapi-spnego, client | `scripts/run-gated-integration.sh run --test client_integration docker_mit_kdc_spnego_header_authenticates_to_docker_http -- --nocapture` | - | historical upstream clelange/rskrb5: GitHub Actions run 28073249506 passed Docker HTTP/SPNEGO service acceptance, raw KRB5 Negotiate, and replay rejection on ubuntu-latest | run locally with scripts/run-gated-integration.sh before release; the fork's ci.yml has no Docker integration job |
| Active Directory TESTAD integration | blocked-on-lab | active-directory, pac, client, service | `scripts/check-github-ad-gate.py` | - | AD integration tests exist, docs/ad-integration.md defines the test contract, docs/ad-lab-provisioning.md defines the live AD lab contract, TESTAD_REQUIRED=1 prevents unreachable-lab soft skips from counting as evidence, keytab path/hex/base64 overrides allow lab-specific account keys, scripts/check-ad-integration-env.py validates strict gate readiness, docs/github-ad-gate-setup.md defines the secret setup a restored AD job needs, and scripts/check-github-ad-gate.py checks GitHub secret readiness and refuses to dispatch while ci.yml has no AD job; tests/client_ad_integration.rs statically verifies the embedded AD keytab fixtures contain testuser1, testuser2, testuser3, and sysHTTP principals with AES128, AES256, and RC4 key material; historical upstream clelange/rskrb5: GitHub Actions run 28119806826 passed the hosted keytab secret-shape dry-run job (upstream dispatch input test_ad_dry_run=true); historical upstream clelange/rskrb5: GitHub Actions run 28117082548 reached hosted ubuntu-latest and decoded the four keytab secrets before failing because the four endpoint secrets were absent | strict AD parity stays deferred: TEST_AD_USER_KDC_ADDR, TEST_AD_RESOURCE_KDC_ADDR, TEST_AD_USER_ADMIN_ADDR, and TEST_AD_RESOURCE_ADMIN_ADDR are unavailable and the fork's ci.yml has no AD job; do not add random or placeholder endpoint secrets; endpoint secrets must identify real reachable AD services; use docs/samba-ad-feasibility.md only as a backup spike, not as Windows AD parity evidence; to restore a hosted AD gate, add an AD job and its workflow_dispatch inputs to ci.yml, then run scripts/check-github-ad-gate.py before dispatching it; record keytab login, no-preauth login, user-domain PAC, and resource-trust PAC evidence from scripts/check-ad-integration-env.py plus a strict TESTAD_REQUIRED=1 run with lab-specific keytabs as needed |
| Ready-to-use HTTP Negotiate client wrapper | proven | gssapi-spnego, client | `cargo test --all-features --test http` | test | async send_with_negotiate and blocking send_with_blocking_negotiate wrappers retry 401 Negotiate responses using caller-provided replayable request factories; tests cover retry header insertion, final Negotiate classification, no-challenge pass-through, and body replay constraints | keep HTTP wrapper tests green before release |

## Status values

Feature rows use `implemented`, `partial` (the `missing` column names the gap
and its closing todo) and `absent`; behaviour rows are `rejected` when the
gokrb5 behaviour is not copied and `partial` while a fix is outstanding. Areas
and gates use these values:

- `covered`: unit and fixture evidence is sufficient for every row of the area.
- `covered-with-gated-evidence`: implemented and unit-covered, but release
  confidence depends on keeping a live Docker or privileged gate green.
- `covered-needs-ad-evidence`: implemented and unit-covered, but AD parity is
  not proven until `TESTAD=1` runs against a maintained lab.
- `partial`: at least one row of the area is not implemented yet.
- `needs-live-evidence`: implementation may exist, but current proof is not
  broad enough for a release parity claim.
- `blocked-on-lab`: code exists, but external infrastructure is required.
- `historical-upstream`: the gate was captured green only by the upstream
  `clelange/rskrb5` workflow; this repository's CI doesn't run it (see
  [`gated-integration.md`](gated-integration.md)).
- `proven`: the named gate has been captured green on the required platform.
- `unproven`: the proof target is known but has not been captured.
- `missing-api`: supporting pieces exist, but the user-facing API is missing.
- `intentionally-out-of-scope`: not required by gokrb5 alone; see the scope above.

## Deferred blockers

- Active Directory parity is blocked on reachable USER and RESOURCE AD
  endpoints; see [`ad-integration.md`](ad-integration.md). Do not add random or
  placeholder endpoint secrets.
- Use [`samba-ad-feasibility.md`](samba-ad-feasibility.md) as a backup spike
  only; Samba results are not Windows AD parity evidence.

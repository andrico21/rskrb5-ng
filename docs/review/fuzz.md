# Fuzzing of attacker-facing parsers

Todo 40 adds a `cargo fuzz` target for every parser that reads bytes or
text from outside the process, seeds each target from the fixtures the tests
already use, runs every target, and proves by coverage that each target
itself reaches the parsers mapped to it.

## Targets

`cargo +nightly-2026-10-03 fuzz list` prints these thirteen targets. All take
arbitrary bytes; most use the first byte as a selector and pass the rest to
the chosen entry point, so one target covers a family of related decoders.

| Target | Input | Entry points |
| --- | --- | --- |
| `keytab_parse` | keytab bytes | `Keytab::parse`, then `Keytab::to_bytes` on accepted input |
| `ccache_parse` | ccache bytes, and the same bytes as a cache name | `CCache::parse`, `config_entries`, `to_bytes`; `CacheName::parse` |
| `kpasswd_reply` | kpasswd frames | `Reply::parse`, `ChangePasswordResult::parse`, `Request::parse`; an accepted reply is decrypted (`Reply::decrypt_result`) and verified (`verify_kpasswd_ap_rep`) against a fixed request |
| `pac_parse` | PAC container, one NDR buffer, or authorization data | `Pac::parse_and_process` with the server checksum check, `Pac::parse` with `buffer_bytes`, every info-buffer parser (validation info, signatures, credentials info and the decrypted credential data, NTLM credentials, client info, UPN/DNS info, S4U delegation, device info, claims info, claims metadata and the decompressed claims set), and `find_pac_in_authorization_data` on authorization data carried in an Authenticator |
| `spnego_token` | Negotiate header text or SPNEGO bytes | `parse_negotiate_header`, `Token`, `NegotiationToken`, `NegTokenInit` and `NegTokenResp` decoding, `accept_sec_context_header` and `Validator::validate_ap_req` with a synthetic keytab, `ValidatedApReq::verify_ap_rep`, and a structured mode that encrypts a fuzzed `EncTicketPart` and Authenticator under the keytab and session keys so the acceptance checks behind decryption run (ticket times, addresses, transited realms, authorization data, PAC) |
| `gss_token` | RFC 4121 tokens and AP-REP bytes | `Krb5MechToken::decode`; `MicToken` and `WrapToken` decode, verify and unwrap with AES128, AES256, AES-SHA2, DES3 and RC4 test keys; a sealed Wrap whose fuzzed plaintext is encrypted under the key; `InitiatorContext::verify_ap_rep` and `verify_ap_rep_response_header`, raw and with a fuzzed `EncAPRepPart` encrypted under the session key |
| `http_negotiate` | `Authorization` or `WWW-Authenticate` header values | `http::accept_request` (service side) and `www_authenticate_negotiate_header`, `classify_negotiate_response` and `verify_ap_rep_response` (client side) |
| `kdc_reply` | KDC replies | `decode_as_rep`, `decode_tgs_rep`, `decode_enc_kdc_rep_part`, the KRB-ERROR and METHOD-DATA decoders, `process_kdc_error` with preauthentication hint selection and `s2kparams` parsing, `process_as_rep`, `process_tgs_rep` and `process_tgs_rep_with_referral` against fixed requests, and structured AS/TGS replies whose fuzzed `EncKDCRepPart` is encrypted under the request's key |
| `kdc_tcp_frame` | four-byte KDC TCP record mark, tested against zero, small and large caps | `client::transport::kdc_tcp_record_length`; production shares the reserved-bit, zero-length and pre-allocation cap checks |
| `krb_messages` | Kerberos messages | AP-REQ, Authenticator, AP-REP, `EncAPRepPart`, KRB-CRED, `EncKrbCredPart`, KRB-PRIV, `EncKrbPrivPart`, KRB-SAFE, Ticket, `EncTicketPart`, KRB-ERROR, `KDC-REQ-BODY`, AS-REQ, TGS-REQ, the PA-DATA messages and the kpasswd `ChangePasswdData` and KRB-PRIV codecs; the decrypt functions under a fixed key; and a sealed mode that encrypts the fuzzed plaintext into a message template so the decoders behind decryption see it |
| `der_oid` | DER and OID bytes | the crate's SPNEGO DER reader and OID decoder (decode, re-encode, decode again must give the same value), `ObjectIdentifier::from_arcs`, and a decrypted Authenticator whose fuzzed plaintext reaches the zero-padding trimmer and the complete-message decoder |
| `krb5_conf` | `krb5.conf` text (UTF-8-lossy) | `Config::parse` and includes, then the enctype-list accessors `default_tkt_enctype_ids`, `default_tgs_enctype_ids` and `permitted_enctype_ids` on an accepted configuration |
| `name_parse` | names and values as text | `Principal::parse_user`, `Principal::parse_service`, `CacheName::parse`, `keytab::Name::parse`, `KdcEndpoint::configured`, `Tokio::with_dns_server`, `config::parse_duration`, `config::parse_boolean`, `crypto::s2kparams_to_iterations` |

The keys, keytabs, tickets and templates the targets use are the synthetic
gokrb5 test vectors the tests already carry (`fuzz/fixtures/`). The fuzz
crate depends on `libfuzzer-sys` and on `rskrb5-ng` with its `http` feature;
the `http_negotiate` target needs that feature.

### The TCP record-mark reader

The `kdc_tcp_frame` target exercises the pure KDC record-mark validator,
`client::transport::kdc_tcp_record_length`, independently of inner DER decoding.
Production calls the same validator before allocating a response body. Seeds
cover zero length, the inclusive small cap, oversized length and the reserved
high bit. Kpasswd retains its distinct unsigned framing rules.

## Corpus

`fuzz/corpus/<target>/` holds the seeds: the hex fixtures of `tests/`
(keytabs, ccaches, PACs and claims, SPNEGO and GSS tokens, every Kerberos
message vector, `krb5.conf` texts), each behind the selector byte of its
mode, plus small synthetic inputs for shapes no fixture has (one
`krb5.conf` key per seed, NDR credential data and device info, a Boolean
claim, a PREAUTH_REQUIRED KRB-ERROR with ETYPE-INFO2, a ccache whose
credentials carry addresses, authorization data and a configuration entry,
an `EncTicketPart` whose authorization data carries the gokrb5 PAC, and the
structured inputs that pass the reply checks up to the encrypted padata).
The seeds alone reach every mapped parser: the coverage proof below runs
`cargo fuzz coverage` on the committed corpus only.
The F2 M1 seed `spnego_token/accept-header-mech-list-mic` uses mode 5 and the
synthetic service fixture, offering MS Kerberos first and standard Kerberos
second with an independently constructed initiator MIC. It reaches mechanism
selection, raw list retention, MIC verification and reciprocal response signing.
`keytab_parse` also holds `truncated-two-bytes`, a deliberately truncated
2-byte keytab; the runs stay clean with it.

## Runs

Each target ran for 120 seconds with

```text
RUSTFLAGS=--cap-lints=warn CARGO_BUILD_WARNINGS=allow \
  cargo +nightly-2026-10-03 fuzz run <target> <scratch corpus> fuzz/corpus/<target> \
  -- -max_total_time=120 -rss_limit_mb=2048
```

(a scratch first corpus directory keeps the inputs libFuzzer adds out of the
committed seeds). Every run ended with `Done N runs` and no crash, OOM or
timeout artifact:

| Target | Runs | Time | Crash, OOM or timeout artifacts |
| --- | --- | --- | --- |
| `keytab_parse` | 2,791,355 | 121 s | 0 |
| `ccache_parse` | 1,769,062 | 121 s | 0 |
| `kpasswd_reply` | 1,226,962 | 121 s | 0 |
| `pac_parse` | 839,490 | 121 s | 0 |
| `spnego_token` | 861,077 | 121 s | 0 |
| `gss_token` | 293,635 | 121 s | 0 |
| `http_negotiate` | 284,293 | 121 s | 0 |
| `kdc_reply` | 650,531 | 121 s | 0 |
| `kdc_tcp_frame` | 24,229,707 | 121 s | 0 |
| `krb_messages` | 306,487 | 121 s | 0 |
| `der_oid` | 348,348 | 121 s | 0 |
| `krb5_conf` | 140,698 (todo 15 F, 2026-11-01) | 121 s | 0 |
| `name_parse` | 2,629,623 | 121 s | 0 |

### Crashes

None. No run produced a crash, OOM or timeout artifact, so there is no
regression test or fix to record. A crash in a later run is a defect:
minimize it, add a regression test that fails before the fix, fix it, and
add a row here.

## Coverage proof

Each row of the inventory below that names a target is proved by that
target's own coverage, not by a test that calls the parser directly:

```text
RUSTFLAGS=--cap-lints=warn CARGO_BUILD_WARNINGS=allow \
  cargo +nightly-2026-10-03 fuzz coverage <target> fuzz/corpus/<target> [--target-dir <cov>]
python3 scripts/lint-gates/fuzz_coverage.py --export <dir> [--coverage-target-dir <cov>]
python3 scripts/lint-gates/fuzz_coverage.py --inventory --coverage <dir> --record <file>
```

`--export` runs `llvm-cov export` (from the `llvm-tools-preview` component
of `nightly-2026-10-03`) on each target's coverage binary, found through
`cargo metadata --manifest-path fuzz/Cargo.toml` (or under the
`--target-dir` given to `cargo fuzz coverage`), with the
`coverage.profdata` that `cargo fuzz coverage` wrote. The check demangles
each symbol, normalizes it (crate disambiguators, generic arguments and the
inherent-impl `<Type>::` brackets removed) and accepts a row only when that
name equals the row's fully qualified function, the record's defining file is
the row's source file and the execution count is above zero; it saves the
matched symbol, file and count of every mapping. Its self-test shows that a
covered `Pac::parse` (the PAC header) does not prove the NDR
`CredentialData::parse`, and that the right name in another file does not
count either. `--inventory` checks that every function the search
`rg -n 'fn (parse|decode|load_bytes|from_bytes|read)\w*' src` finds, plus
`find_pac_in_authorization_data`, is a row, and that every named target is in
`cargo fuzz list`.

F2 M1 re-ran `cargo fuzz coverage spnego_token` with the new MIC seed and
exported that target with `llvm-cov export`. Applying the same script's
`coverage_index` and `check_coverage` functions to the `spnego_token` rows proved
all 37 mappings, including the five new helpers (record:
`m1-spnego-coverage.tsv` in the execution evidence). The all-target coverage
record was not regenerated: the other eleven targets were unchanged and were
not rebuilt in this lane. A full refresh uses the commands above for all targets.

## Round-trip properties

| Encoder and parser | Property | Where |
| --- | --- | --- |
| keytab `to_bytes` and `parse` | `serialized_keytab_roundtrips` (todo 37) | `tests/keytab.rs` |
| ccache `to_bytes` and `parse` | `serialized_ccache_roundtrips` (this todo): every cache the API builds, with addresses, authorization data and second tickets, parses back unchanged and re-serializes to the same bytes | `tests/ccache.rs` |
| SPNEGO DER and OID encode and decode | `der_oid_roundtrip_property` (todo 29) | `src/spnego/der/tests.rs` |

## Inventory

Every function, public or private, that parses or decodes bytes or text from
outside the process: the search above, then by behaviour from the network,
file and HTTP entry points (transport readers, service and SPNEGO acceptance,
ccache, keytab and configuration loaders) to the parsers they call, including
the decrypt-then-decode and verify steps over received data. A row names the
fuzz target whose own coverage reaches the function, or the reason no target
does.

| Function | Source | Fuzz target | Reason |
| --- | --- | --- | --- |
| `rskrb5_ng::client::crypto_policy::ready` | `src/client/crypto_policy.rs` | - | Runtime policy readiness check, not a byte parser. |
| `rskrb5_ng::krb_cred::import::decode_decrypt` | `src/krb_cred/import.rs` | `krb_messages` | |
| `rskrb5_ng::ap_rep::decode` | `src/ap_rep.rs` | `krb_messages` |  |
| `rskrb5_ng::ap_rep::decode_der` | `src/ap_rep.rs` | `krb_messages` |  |
| `rskrb5_ng::ap_rep::decode_enc_ap_rep_part` | `src/ap_rep.rs` | `krb_messages` |  |
| `rskrb5_ng::ap_rep::decrypt_ap_rep_enc_part` | `src/ap_rep.rs` | `krb_messages` |  |
| `rskrb5_ng::ap_rep::validate` | `src/ap_rep.rs` | `krb_messages` |  |
| `rskrb5_ng::ap_req::decode` | `src/ap_req.rs` | `krb_messages` |  |
| `rskrb5_ng::ap_req::decode_authenticator` | `src/ap_req.rs` | `krb_messages` |  |
| `rskrb5_ng::ap_req::decode_der` | `src/ap_req.rs` | `krb_messages` |  |
| `rskrb5_ng::ap_req::decrypt_ap_req_authenticator` | `src/ap_req.rs` | `krb_messages` |  |
| `rskrb5_ng::ap_req::validate` | `src/ap_req.rs` | `krb_messages` |  |
| `rskrb5_ng::ccache::AuthorizationDataEntry::parse` | `src/ccache.rs` | `ccache_parse` |  |
| `rskrb5_ng::ccache::CCache::config_entries` | `src/ccache.rs` | `ccache_parse` |  |
| `rskrb5_ng::ccache::CCache::load` | `src/ccache.rs` | - | reads the file, then calls `CCache::parse` (`ccache_parse`) |
| `rskrb5_ng::ccache::CCache::load_from_env` | `src/ccache.rs` | - | reads `KRB5CCNAME`, then `CCache::load_name` |
| `rskrb5_ng::ccache::CCache::load_name` | `src/ccache.rs` | - | resolves the name with `CacheName::parse` (`ccache_parse`, `name_parse`), then `CCache::load` |
| `rskrb5_ng::ccache::CCache::parse` | `src/ccache.rs` | `ccache_parse` |  |
| `rskrb5_ng::ccache::CacheName::parse` | `src/ccache.rs` | `ccache_parse` |  |
| `rskrb5_ng::ccache::Credential::parse` | `src/ccache.rs` | `ccache_parse` |  |
| `rskrb5_ng::ccache::Header::parse` | `src/ccache.rs` | `ccache_parse` |  |
| `rskrb5_ng::ccache::HostAddress::parse` | `src/ccache.rs` | `ccache_parse` |  |
| `rskrb5_ng::ccache::Principal::parse` | `src/ccache.rs` | `ccache_parse` |  |
| `rskrb5_ng::ccache::dir_collection_primary_path` | `src/ccache.rs` | - | filesystem step of `DIR:` collections (may create the `primary` file); the name it starts from is parsed by `file_path_from_name` (`name_parse`) |
| `rskrb5_ng::ccache::parse_config_entry` | `src/ccache.rs` | `ccache_parse` |  |
| `rskrb5_ng::ccache::parse_dir_primary_name` | `src/ccache.rs` | - | reads the `primary` file of a `DIR:` collection; only `CCache::file_path_from_cache_name` reaches it, which creates that file when missing, so it never runs on bytes a fuzz target can supply; covered by `saves_and_loads_dir_primary_collection_cache_name` (tests/ccache.rs) |
| `rskrb5_ng::ccache::read_array` | `src/ccache.rs` | `ccache_parse` |  |
| `rskrb5_ng::ccache::read_bytes` | `src/ccache.rs` | `ccache_parse` |  |
| `rskrb5_ng::ccache::read_count` | `src/ccache.rs` | `ccache_parse` |  |
| `rskrb5_ng::ccache::read_counted_string` | `src/ccache.rs` | `ccache_parse` |  |
| `rskrb5_ng::ccache::read_data` | `src/ccache.rs` | `ccache_parse` |  |
| `rskrb5_ng::ccache::read_i16` | `src/ccache.rs` | `ccache_parse` |  |
| `rskrb5_ng::ccache::read_i32` | `src/ccache.rs` | `ccache_parse` |  |
| `rskrb5_ng::ccache::read_u16` | `src/ccache.rs` | `ccache_parse` |  |
| `rskrb5_ng::ccache::read_u32` | `src/ccache.rs` | `ccache_parse` |  |
| `rskrb5_ng::ccache::read_u8` | `src/ccache.rs` | `ccache_parse` |  |
| `rskrb5_ng::client::decode` | `src/client.rs` | `kdc_reply` |  |
| `rskrb5_ng::client::kerberos_string_to_string` | `src/client.rs` | `kdc_reply` |  |
| `rskrb5_ng::client::preauth_key_info_from_method_data` | `src/client.rs` | `kdc_reply` |  |
| `rskrb5_ng::client::principal_from_message_info` | `src/client.rs` | `kdc_reply` |  |
| `rskrb5_ng::client::principal_from_parts` | `src/client.rs` | `kdc_reply` |  |
| `rskrb5_ng::client::process_as_rep` | `src/client.rs` | `kdc_reply` |  |
| `rskrb5_ng::client::process_kdc_error` | `src/client.rs` | `kdc_reply` |  |
| `rskrb5_ng::client::process_tgs_rep` | `src/client.rs` | `kdc_reply` |  |
| `rskrb5_ng::client::process_tgs_rep_inner` | `src/client.rs` | `kdc_reply` |  |
| `rskrb5_ng::client::process_tgs_rep_with_referral` | `src/client.rs` | `kdc_reply` |  |
| `rskrb5_ng::client::select_preauth_key_info` | `src/client.rs` | `kdc_reply` |  |
| `rskrb5_ng::client::system_time_from_kerberos_time` | `src/client.rs` | `kdc_reply` |  |
| `rskrb5_ng::client::validate_delegated_ticket` | `src/client.rs` | - | runs only inside a TGS-REP that already decrypted under the TGS session key and requested S4U evidence with a delegation keytab; the ticket it checks is decrypted with that keytab first |
| `rskrb5_ng::client::validate_reply_encrypted_padata` | `src/client.rs` | `kdc_reply` |  |
| `rskrb5_ng::client::kpasswd::validated_result` | `src/client/kpasswd.rs` | - | crate-private step of the password-change exchange over the network; its inputs come from `kadmin::Reply::parse` and `verify_kpasswd_ap_rep` (`kpasswd_reply`) and `kadmin::decrypt_krb_priv_enc_part` (`krb_messages`); covered by the kpasswd exchange tests in tests/client/password_change.rs |
| `rskrb5_ng::client::kpasswd::verify_kpasswd_ap_rep` | `src/client/kpasswd.rs` | `kpasswd_reply` |  |
| `rskrb5_ng::client::principal::Principal::parse_service` | `src/client/principal.rs` | `name_parse` |  |
| `rskrb5_ng::client::principal::Principal::parse_user` | `src/client/principal.rs` | `name_parse` |  |
| `rskrb5_ng::client::principal::parse_name_and_realm` | `src/client/principal.rs` | `name_parse` |  |
| `rskrb5_ng::client::principal::parse_principal_components` | `src/client/principal.rs` | `name_parse` |  |
| `rskrb5_ng::client::transport::KdcEndpoint::configured` | `src/client/transport.rs` | `name_parse` |  |
| `rskrb5_ng::client::transport::KdcEndpoint::configured_with_default_port` | `src/client/transport.rs` | `name_parse` |  |
| `rskrb5_ng::client::transport::Tokio::discover_srv_endpoints` | `src/client/transport.rs` | - | DNS answers are decoded by hickory-resolver (a dependency); this keeps typed SRV records only |
| `rskrb5_ng::client::transport::Tokio::exchange_tcp_framed` | `src/client/transport.rs` | - | socket I/O is exercised by transport tests; extracted KDC record-mark validation delegates to kdc_tcp_record_length, covered by kdc_tcp_frame, before body allocation; reply bodies reach kdc_reply. Kpasswd retains its distinct unsigned record-mark rules. |
| `rskrb5_ng::client::transport::kdc_tcp_record_length` | `src/client/transport.rs` | `kdc_tcp_frame` |  |
| `rskrb5_ng::client::transport::Tokio::send_udp` | `src/client/transport.rs` | - | socket I/O: receives at most `udp_response_limit + 1` bytes and rejects a larger datagram before any decode; the datagram goes to the reply decoders `kdc_reply` fuzzes; covered by `udp_transport_rejects_truncated_datagram` (tests/client_transport.rs) |
| `rskrb5_ng::client::transport::Tokio::with_dns_server` | `src/client/transport.rs` | `name_parse` |  |
| `rskrb5_ng::client::transport::kdc_error_code` | `src/client/transport.rs` | - | private wrapper of `krb_error::decode` (fuzzed by `kdc_reply` and `krb_messages`) on a received reply |
| `rskrb5_ng::client::transport::non_empty_kdc_response` | `src/client/transport.rs` | - | rejects an empty reply the transport received; no parsing: the reply then goes to the decoders `kdc_reply` fuzzes |
| `rskrb5_ng::client::transport::order_srv_records` | `src/client/transport.rs` | - | orders DNS SRV records already decoded by the resolver (priority, weight, target, port); no byte or text parsing; covered by `srv_zero_draw_selects_zero_weight`, `srv_weight_boundaries_select_each_peer` and `srv_all_zero_weights_use_uniform_index` (src) |
| `rskrb5_ng::client::transport::parse_dns_server` | `src/client/transport.rs` | `name_parse` |  |
| `rskrb5_ng::client::transport::parse_kdc_endpoint` | `src/client/transport.rs` | `name_parse` |  |
| `rskrb5_ng::client::transport::parse_kdc_port` | `src/client/transport.rs` | `name_parse` |  |
| `rskrb5_ng::client::transport::resolve_dns_endpoint_host` | `src/client/transport.rs` | - | IP-literal check and resolver lookup on an SRV target name; the DNS reply is decoded by hickory-resolver |
| `rskrb5_ng::client::transport::tests::parses_dns_server_override_ip_and_default_port` | `src/client/transport.rs` | - | unit test, not a parser |
| `rskrb5_ng::client::transport::tests::parses_dns_server_override_ip_and_explicit_port` | `src/client/transport.rs` | - | unit test, not a parser |
| `rskrb5_ng::client::transport::framing::validate_tcp_length` | `src/client/transport/framing.rs` | - | service-specific dispatch: KDC marks delegate to kdc_tcp_record_length (kdc_tcp_frame); kpasswd marks use their separate unsigned length contract; tcp_lengths_are_service_specific covers dispatch. |
| `rskrb5_ng::config::Config::load` | `src/config.rs` | - | delegates to bounded `load_paths`; shared grammar reached by `krb5_conf` |
| `rskrb5_ng::config::Config::load_default` | `src/config.rs` | - | reads the platform default path, then `load_paths` |
| `rskrb5_ng::config::Config::load_default_or_parse` | `src/config.rs` | - | the default file, else `Config::parse` on embedded text (`krb5_conf`) |
| `rskrb5_ng::config::Config::load_from_env` | `src/config.rs` | - | reads `KRB5_CONFIG`, then `load_paths` |
| `rskrb5_ng::config::Config::load_paths` | `src/config.rs` | - | bounded independent file reads, shared `IncludeExpansion::expand` grammar |
| `rskrb5_ng::config::Config::parse` | `src/config.rs` | `krb5_conf` |  |
| `rskrb5_ng::config::Config::parse_with_mode` | `src/config.rs` | `krb5_conf` | |
| `rskrb5_ng::config::Config::parse_with_roots` | `src/config.rs` | `krb5_conf` |  |
| `rskrb5_ng::config::Config::parse_with_roots_mode` | `src/config.rs` | `krb5_conf` | |
| `rskrb5_ng::config::IncludeDirective::parse` | `src/config.rs` | `krb5_conf` |  |
| `rskrb5_ng::config::IncludeExpansion::expand` | `src/config.rs` | `krb5_conf` |  |
| `rskrb5_ng::config::IncludeExpansion::include_dir` | `src/config.rs` | `krb5_conf` |  |
| `rskrb5_ng::config::IncludeExpansion::include_file` | `src/config.rs` | `krb5_conf` |  |
| `rskrb5_ng::config::IncludeExpansion::read_include` | `src/config.rs` | `krb5_conf` |  |
| `rskrb5_ng::config::IncludeExpansion::splice` | `src/config.rs` | `krb5_conf` |  |
| `rskrb5_ng::config::LibDefaults::parse_lines` | `src/config.rs` | `krb5_conf` |  |
| `rskrb5_ng::config::LibDefaults::parse_mode` | `src/config.rs` | - | Typed mode accessor, not a parser. |
| `rskrb5_ng::config::Realm::parse` | `src/config.rs` | `krb5_conf` |  |
| `rskrb5_ng::config::profile::Profile::finish` | `src/config/profile.rs` | `krb5_conf` | |
| `rskrb5_ng::config::profile_syntax::State::line` | `src/config/profile_syntax.rs` | `krb5_conf` | |
| `rskrb5_ng::config::profile_syntax::State::finish` | `src/config/profile_syntax.rs` | `krb5_conf` | |
| `rskrb5_ng::config::profile_syntax::quoted` | `src/config/profile_syntax.rs` | `krb5_conf` | |
| `rskrb5_ng::config::profile_syntax::comments` | `src/config/profile_syntax.rs` | `krb5_conf` | |
| `rskrb5_ng::config::hostname::Canonicalization::parse` | `src/config/hostname.rs` | `krb5_conf` | |
| `rskrb5_ng::config::libdefaults::c2::parse` | `src/config/libdefaults/c2.rs` | `krb5_conf` | |
| `rskrb5_ng::config::libdefaults::duration::parse` | `src/config/libdefaults/duration.rs` | `krb5_conf` | |
| `rskrb5_ng::config::realm_values::decode` | `src/config/realm_values.rs` | `krb5_conf` | |
| `rskrb5_ng::config::fork_tests::parse_does_not_read_uid_or_home` | `src/config.rs` | - | unit test, not a parser |
| `rskrb5_ng::config::enctype_expr::EnctypeExpr::parse` | `src/config/enctype_expr.rs` | `krb5_conf` | |
| `rskrb5_ng::config::enctype_names::Selector::parse` | `src/config/enctype_names.rs` | `krb5_conf` | |
| `rskrb5_ng::config::sections::parse_assignment` | `src/config/sections.rs` | `krb5_conf` |  |
| `rskrb5_ng::config::parse_boolean` | `src/config.rs` | `name_parse` |  |
| `rskrb5_ng::config::parse_colon_duration` | `src/config.rs` | `krb5_conf` |  |
| `rskrb5_ng::config::parse_duration` | `src/config.rs` | `name_parse` |  |
| `rskrb5_ng::config::parse_i32` | `src/config.rs` | `krb5_conf` |  |
| `rskrb5_ng::config::parse_i32_list` | `src/config.rs` | `krb5_conf` |  |
| `rskrb5_ng::config::parse_ip_addresses` | `src/config.rs` | `krb5_conf` |  |
| `rskrb5_ng::config::parse_supported_enctype_ids` | `src/config.rs` | - | cfg(test)-only capability mapping helper; normal fuzz dependency builds do not contain it; configuration tests cover it |
| `rskrb5_ng::config::parse_unit_duration` | `src/config.rs` | `krb5_conf` |  |
| `rskrb5_ng::crypto::AesSha1Etype::decrypt_message` | `src/crypto.rs` | `gss_token` |  |
| `rskrb5_ng::crypto::AesSha2Etype::decrypt_message` | `src/crypto.rs` | `gss_token` |  |
| `rskrb5_ng::crypto::Des3CbcSha1KdEtype::decrypt_message` | `src/crypto.rs` | `gss_token` |  |
| `rskrb5_ng::crypto::KerberosEtype::decrypt_message` | `src/crypto.rs` | `gss_token` |  |
| `rskrb5_ng::crypto::KerberosEtype::verify_checksum` | `src/crypto.rs` | `pac_parse` |  |
| `rskrb5_ng::crypto::Rc4HmacEtype::decrypt_message` | `src/crypto.rs` | `gss_token` |  |
| `rskrb5_ng::crypto::aes_cts_decrypt` | `src/crypto.rs` | `gss_token` |  |
| `rskrb5_ng::crypto::cbc_decrypt` | `src/crypto.rs` | `gss_token` |  |
| `rskrb5_ng::crypto::cts_decrypt` | `src/crypto.rs` | `gss_token` |  |
| `rskrb5_ng::crypto::des3_cbc_decrypt` | `src/crypto.rs` | `gss_token` |  |
| `rskrb5_ng::crypto::hex_pair` | `src/crypto.rs` | `name_parse` |  |
| `rskrb5_ng::crypto::hex_value` | `src/crypto.rs` | `name_parse` |  |
| `rskrb5_ng::crypto::rc4_hmac_crypt` | `src/crypto.rs` | `gss_token` |  |
| `rskrb5_ng::crypto::s2kparams_to_iterations` | `src/crypto.rs` | `name_parse` |  |
| `rskrb5_ng::crypto::split_trailing_mac` | `src/crypto.rs` | `gss_token` |  |
| `rskrb5_ng::crypto::strip_confounder` | `src/crypto.rs` | `gss_token` |  |
| `rskrb5_ng::der::decode_complete` | `src/der.rs` | `der_oid` |  |
| `rskrb5_ng::der::top_level_der_end` | `src/der.rs` | `der_oid` |  |
| `rskrb5_ng::der::trim_zero_padded_der` | `src/der.rs` | `der_oid` |  |
| `rskrb5_ng::file_name::expand_path_tokens` | `src/file_name.rs` | `name_parse` |  |
| `rskrb5_ng::file_name::file_path_from_name` | `src/file_name.rs` | `name_parse` |  |
| `rskrb5_ng::file_name::is_windows_drive_path` | `src/file_name.rs` | `name_parse` |  |
| `<rskrb5_ng::http::WwwAuthenticateSegments as core::iter::traits::iterator::Iterator>::next` | `src/http.rs` | `http_negotiate` |  |
| `rskrb5_ng::http::WwwAuthenticateSegments::new` | `src/http.rs` | `http_negotiate` |  |
| `rskrb5_ng::http::NegotiateFuture::ready` | `src/http.rs` | - | constructs an already-completed Tower future from a response the layer built; matches the search only through the `read` prefix of `ready` and parses nothing |
| `rskrb5_ng::http::accept_request` | `src/http.rs` | `http_negotiate` |  |
| `rskrb5_ng::http::authorization_header` | `src/http.rs` | `http_negotiate` |  |
| `rskrb5_ng::http::classify_negotiate_challenge` | `src/http.rs` | `http_negotiate` |  |
| `rskrb5_ng::http::classify_negotiate_response` | `src/http.rs` | `http_negotiate` |  |
| `rskrb5_ng::http::negotiate_challenge` | `src/http.rs` | `http_negotiate` |  |
| `rskrb5_ng::http::negotiate_challenge_is_bare` | `src/http.rs` | `http_negotiate` |  |
| `rskrb5_ng::http::verify_ap_rep_response` | `src/http.rs` | `http_negotiate` |  |
| `rskrb5_ng::http::www_authenticate_negotiate_header` | `src/http.rs` | `http_negotiate` |  |
| `rskrb5_ng::kadmin::payload::ChangePasswdData::decode_der` | `src/kadmin/payload.rs` | `krb_messages` |  |
| `<rskrb5_ng::kadmin::password::Bytes as rasn::de::Decode>::decode_with_tag_and_constraints` | `src/kadmin/password.rs` | `krb_messages` |  |
| `rskrb5_ng::kadmin::result::ChangePasswordResult::parse` | `src/kadmin/result.rs` | `kpasswd_reply` |  |
| `rskrb5_ng::kadmin::reply::Reply::decrypt_result` | `src/kadmin/reply.rs` | `kpasswd_reply` |  |
| `rskrb5_ng::kadmin::reply::Reply::parse` | `src/kadmin/reply.rs` | `kpasswd_reply` |  |
| `rskrb5_ng::kadmin::request::Request::parse` | `src/kadmin/request.rs` | `kpasswd_reply` |  |
| `rskrb5_ng::kadmin::codec::decode` | `src/kadmin/codec.rs` | `krb_messages` |  |
| `rskrb5_ng::kadmin::decode_enc_krb_priv_part` | `src/kadmin.rs` | `krb_messages` |  |
| `rskrb5_ng::kadmin::decode_krb_priv` | `src/kadmin.rs` | `kpasswd_reply` |  |
| `rskrb5_ng::kadmin::codec::parse_header` | `src/kadmin/codec.rs` | `kpasswd_reply` |  |
| `rskrb5_ng::kdc_rep::decode` | `src/kdc_rep.rs` | `kdc_reply` |  |
| `rskrb5_ng::kdc_rep::decode_as_rep` | `src/kdc_rep.rs` | `kdc_reply` |  |
| `rskrb5_ng::kdc_rep::decode_enc_kdc_rep_part` | `src/kdc_rep.rs` | `kdc_reply` |  |
| `rskrb5_ng::kdc_rep::decode_tgs_rep` | `src/kdc_rep.rs` | `kdc_reply` |  |
| `rskrb5_ng::kdc_rep::decrypt_as_rep_enc_part` | `src/kdc_rep.rs` | `kdc_reply` |  |
| `rskrb5_ng::kdc_rep::decrypt_tgs_rep_enc_part` | `src/kdc_rep.rs` | `kdc_reply` |  |
| `rskrb5_ng::kdc_rep::validate_as_rep` | `src/kdc_rep.rs` | `kdc_reply` |  |
| `rskrb5_ng::kdc_rep::validate_tgs_rep` | `src/kdc_rep.rs` | `kdc_reply` |  |
| `rskrb5_ng::kdc_req::decode` | `src/kdc_req.rs` | `krb_messages` |  |
| `rskrb5_ng::kdc_req::decode_as_req` | `src/kdc_req.rs` | `krb_messages` |  |
| `rskrb5_ng::kdc_req::decode_kdc_req_body` | `src/kdc_req.rs` | `krb_messages` |  |
| `rskrb5_ng::kdc_req::decode_tgs_req` | `src/kdc_req.rs` | `krb_messages` |  |
| `rskrb5_ng::keytab::Keytab::load` | `src/keytab.rs` | - | reads the file, then calls `Keytab::parse` (`keytab_parse`) |
| `rskrb5_ng::keytab::Keytab::load_from_env` | `src/keytab.rs` | - | reads `KRB5_KTNAME`, then `Keytab::load_name` |
| `rskrb5_ng::keytab::Keytab::load_name` | `src/keytab.rs` | - | resolves the name with `keytab::Name::parse` (`name_parse`), then `Keytab::load` |
| `rskrb5_ng::keytab::Keytab::parse` | `src/keytab.rs` | `keytab_parse` |  |
| `rskrb5_ng::keytab::Name::parse` | `src/keytab.rs` | `name_parse` |  |
| `rskrb5_ng::keytab::Principal::parse` | `src/keytab.rs` | `keytab_parse` |  |
| `rskrb5_ng::keytab::read_array` | `src/keytab.rs` | `keytab_parse` |  |
| `rskrb5_ng::keytab::read_bytes` | `src/keytab.rs` | `keytab_parse` |  |
| `rskrb5_ng::keytab::read_counted_string` | `src/keytab.rs` | `keytab_parse` |  |
| `rskrb5_ng::keytab::read_i16` | `src/keytab.rs` | `keytab_parse` |  |
| `rskrb5_ng::keytab::read_i32` | `src/keytab.rs` | `keytab_parse` |  |
| `rskrb5_ng::keytab::read_u32` | `src/keytab.rs` | `keytab_parse` |  |
| `rskrb5_ng::keytab::read_u8` | `src/keytab.rs` | `keytab_parse` |  |
| `rskrb5_ng::krb_cred::decode` | `src/krb_cred.rs` | `krb_messages` |  |
| `rskrb5_ng::krb_cred::decode_decrypt_krb_cred_to_ccache_credentials` | `src/krb_cred.rs` | `krb_messages` |  |
| `rskrb5_ng::krb_cred::decode_der` | `src/krb_cred.rs` | `krb_messages` |  |
| `rskrb5_ng::krb_cred::decode_enc_krb_cred_part` | `src/krb_cred.rs` | `krb_messages` |  |
| `rskrb5_ng::krb_cred::decrypt_krb_cred_enc_part` | `src/krb_cred.rs` | `krb_messages` |  |
| `rskrb5_ng::krb_cred::decrypt_krb_cred_to_ccache_credentials` | `src/krb_cred.rs` | `krb_messages` |  |
| `rskrb5_ng::krb_cred::decrypted_krb_cred_to_ccache_credentials` | `src/krb_cred.rs` | `krb_messages` |  |
| `rskrb5_ng::krb_error::decode` | `src/krb_error.rs` | `kdc_reply` |  |
| `rskrb5_ng::krb_error::decode_der` | `src/krb_error.rs` | `kdc_reply` |  |
| `rskrb5_ng::krb_error::decode_krb_error_info` | `src/krb_error.rs` | `kdc_reply` |  |
| `rskrb5_ng::krb_error::decode_method_data` | `src/krb_error.rs` | `kdc_reply` |  |
| `rskrb5_ng::krb_error::info` | `src/krb_error.rs` | `kdc_reply` |  |
| `rskrb5_ng::krb_error::preauth_method_data` | `src/krb_error.rs` | `kdc_reply` |  |
| `rskrb5_ng::krb_error::validate` | `src/krb_error.rs` | `kdc_reply` |  |
| `rskrb5_ng::krb_priv::decode` | `src/krb_priv.rs` | `krb_messages` |  |
| `rskrb5_ng::krb_priv::decode_der` | `src/krb_priv.rs` | `krb_messages` |  |
| `rskrb5_ng::krb_priv::decode_enc_krb_priv_part` | `src/krb_priv.rs` | `krb_messages` |  |
| `rskrb5_ng::krb_priv::decrypt_krb_priv_enc_part` | `src/krb_priv.rs` | `krb_messages` |  |
| `rskrb5_ng::krb_priv::validate` | `src/krb_priv.rs` | `krb_messages` |  |
| `rskrb5_ng::krb_safe::decode` | `src/krb_safe.rs` | `krb_messages` |  |
| `rskrb5_ng::krb_safe::decode_der` | `src/krb_safe.rs` | `krb_messages` |  |
| `rskrb5_ng::krb_safe::verify_krb_safe_checksum` | `src/krb_safe.rs` | `krb_messages` |  |
| `rskrb5_ng::messages::KrbErrorInfo::decode_der` | `src/messages.rs` | `krb_messages` |  |
| `rskrb5_ng::messages::KrbErrorInfo::from_rasn` | `src/messages.rs` | `kdc_reply` |  |
| `rskrb5_ng::messages::PaForUser::decode_der` | `src/messages.rs` | `krb_messages` |  |
| `rskrb5_ng::messages::PaPacOptions::decode_der` | `src/messages.rs` | `krb_messages` |  |
| `rskrb5_ng::messages::PaReqEncPaRep::decode_der` | `src/messages.rs` | `krb_messages` |  |
| `rskrb5_ng::messages::decode_der` | `src/messages.rs` | `krb_messages` |  |
| `rskrb5_ng::messages::decode_named` | `src/messages.rs` | `krb_messages` |  |
| `rskrb5_ng::messages::kerberos_string_to_string` | `src/messages.rs` | `krb_messages` |  |
| `rskrb5_ng::messages::microseconds` | `src/messages.rs` | `krb_messages` |  |
| `rskrb5_ng::messages::principal_from_parts` | `src/messages.rs` | `krb_messages` |  |
| `rskrb5_ng::messages::system_time_from_kerberos_time` | `src/messages.rs` | `krb_messages` |  |
| `rskrb5_ng::messages::whole_seconds` | `src/messages.rs` | `krb_messages` |  |
| `rskrb5_ng::pac::ClaimsInfo::parse` | `src/pac.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::ClaimsSet::parse` | `src/pac.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::ClaimsSetMetadata::claims_set` | `src/pac.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::ClaimsSetMetadata::decoded_claims_set_bytes` | `src/pac.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::ClaimsSetMetadata::parse` | `src/pac.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::ClientInfo::parse` | `src/pac.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::CredentialData::parse` | `src/pac.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::CredentialsInfo::decrypt_credential_data` | `src/pac.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::CredentialsInfo::parse` | `src/pac.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::DeviceInfo::parse` | `src/pac.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::InfoBuffer::copy_zeroed_signature` | `src/pac.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::InfoBuffer::slice` | `src/pac.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::InfoBuffer::validate` | `src/pac.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::KerbValidationInfo::parse` | `src/pac.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::KerbValidationInfo::read_fields` | `src/pac.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::NtlmSupplementalCredential::parse` | `src/pac.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::Pac::buffer_bytes` | `src/pac.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::Pac::parse` | `src/pac.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::Pac::parse_and_process` | `src/pac.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::Pac::process_buffers` | `src/pac.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::Pac::verify` | `src/pac.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::Pac::verify_server_checksum` | `src/pac.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::S4UDelegationInfo::parse` | `src/pac.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::SignatureData::parse` | `src/pac.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::UpnDnsInfo::parse` | `src/pac.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::find_pac_in_authorization_data` | `src/pac.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::authorization::find` | `src/pac/authorization.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::ndr::RpcUnicodeStringDescriptor::read` | `src/pac/ndr.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::ndr::ensure_zero_trailing` | `src/pac/ndr.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::ndr::ndr_len` | `src/pac/ndr.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::ndr::read_claim_entry_descriptor` | `src/pac/ndr.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::ndr::read_counted_supplemental_credentials` | `src/pac/ndr.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::ndr::read_deferred_bool_array` | `src/pac/ndr.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::ndr::read_deferred_claim_entries` | `src/pac/ndr.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::ndr::read_deferred_claim_string` | `src/pac/ndr.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::ndr::read_deferred_claims_arrays` | `src/pac/ndr.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::ndr::read_deferred_domain_group_memberships` | `src/pac/ndr.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::ndr::read_deferred_group_memberships` | `src/pac/ndr.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::ndr::read_deferred_i64_array` | `src/pac/ndr.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::ndr::read_deferred_lpwstr_array` | `src/pac/ndr.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::ndr::read_deferred_rpc_unicode_strings` | `src/pac/ndr.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::ndr::read_deferred_sid` | `src/pac/ndr.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::ndr::read_deferred_sid_and_attributes` | `src/pac/ndr.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::ndr::read_deferred_u64_array` | `src/pac/ndr.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::ndr::read_deferred_u8_array` | `src/pac/ndr.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::ndr::read_deferred_unicode_string` | `src/pac/ndr.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::ndr::read_ndr_reasonable_count` | `src/pac/ndr.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::ndr::read_ndr_u16` | `src/pac/ndr.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::ndr::read_ndr_u32` | `src/pac/ndr.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::ndr::read_ndr_u64` | `src/pac/ndr.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::ndr::read_ndr_wrapper` | `src/pac/ndr.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::ndr::read_reasonable_count` | `src/pac/ndr.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::reader::Reader::align` | `src/pac/reader.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::reader::Reader::read_array` | `src/pac/reader.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::reader::Reader::read_bytes` | `src/pac/reader.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::reader::Reader::read_filetime` | `src/pac/reader.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::reader::Reader::read_u16` | `src/pac/reader.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::reader::Reader::read_u32` | `src/pac/reader.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::reader::Reader::read_u64` | `src/pac/reader.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::reader::Reader::read_u8` | `src/pac/reader.rs` | `pac_parse` |  |
| `rskrb5_ng::service::ValidatedApReq::verify_ap_rep` | `src/service.rs` | `spnego_token` |  |
| `rskrb5_ng::service::Validator::validate_ap_req` | `src/service.rs` | `spnego_token` |  |
| `rskrb5_ng::service::Validator::validate_client_address` | `src/service.rs` | `spnego_token` |  |
| `rskrb5_ng::service::Validator::validate_ticket_times` | `src/service.rs` | `spnego_token` |  |
| `rskrb5_ng::service::kerberos_string_to_string` | `src/service.rs` | `spnego_token` |  |
| `rskrb5_ng::service::microseconds_to_u32` | `src/service.rs` | `spnego_token` |  |
| `rskrb5_ng::service::principal_from_parts` | `src/service.rs` | `spnego_token` |  |
| `rskrb5_ng::service::system_time_from_kerberos_time` | `src/service.rs` | `spnego_token` |  |
| `rskrb5_ng::service::ticket_pac::verified_ticket_pac` | `src/service/ticket_pac.rs` | `spnego_token` |  |
| `rskrb5_ng::service::ticket_start_time` | `src/service.rs` | `spnego_token` |  |
| `rskrb5_ng::service::validate_authorization_data` | `src/service.rs` | `spnego_token` |  |
| `rskrb5_ng::service::validate_authorization_elements` | `src/service.rs` | `spnego_token` |  |
| `rskrb5_ng::service::validation::Validator::validate_ap_req_with_check` | `src/service/validation.rs` | `spnego_token` |  |
| `rskrb5_ng::service::validation::Validator::validate_transit` | `src/service/validation.rs` | `spnego_token` |  |
| `rskrb5_ng::spnego::InitiatorContext::verify_ap_rep` | `src/spnego.rs` | `gss_token` |  |
| `rskrb5_ng::spnego::InitiatorContext::verify_ap_rep_response_header` | `src/spnego.rs` | `gss_token` |  |
| `rskrb5_ng::spnego::Krb5MechToken::decode` | `src/spnego.rs` | `spnego_token` |  |
| `rskrb5_ng::spnego::Krb5TokenId::from_bytes` | `src/spnego.rs` | `spnego_token` |  |
| `rskrb5_ng::spnego::MicToken::decode` | `src/spnego.rs` | `gss_token` |  |
| `rskrb5_ng::spnego::MicToken::verify` | `src/spnego.rs` | `gss_token` |  |
| `rskrb5_ng::spnego::NegState::from_value` | `src/spnego.rs` | `spnego_token` |  |
| `rskrb5_ng::spnego::NegTokenInit::decode` | `src/spnego.rs` | `spnego_token` |  |
| `rskrb5_ng::spnego::NegTokenInit::krb5_ap_req` | `src/spnego.rs` | `spnego_token` |  |
| `rskrb5_ng::spnego::NegTokenResp::decode` | `src/spnego.rs` | `spnego_token` |  |
| `rskrb5_ng::spnego::NegotiationToken::decode` | `src/spnego.rs` | `spnego_token` |  |
| `rskrb5_ng::spnego::Token::decode` | `src/spnego.rs` | `spnego_token` |  |
| `rskrb5_ng::spnego::Token::krb5_ap_req` | `src/spnego.rs` | `spnego_token` |  |
| `rskrb5_ng::spnego::WrapToken::decode` | `src/spnego.rs` | `gss_token` |  |
| `rskrb5_ng::spnego::WrapToken::decrypt_and_set_payload` | `src/spnego.rs` | `gss_token` |  |
| `rskrb5_ng::spnego::WrapToken::decrypt_payload` | `src/spnego.rs` | `gss_token` |  |
| `rskrb5_ng::spnego::WrapToken::verify` | `src/spnego.rs` | `gss_token` |  |
| `rskrb5_ng::spnego::accept_sec_context_header` | `src/spnego.rs` | `spnego_token` |  |
| `rskrb5_ng::spnego::decode_negotiate_header` | `src/spnego.rs` | `spnego_token` |  |
| `rskrb5_ng::spnego::negotiation::optimistic_token` | `src/spnego/negotiation.rs` | `spnego_token` |  |
| `rskrb5_ng::spnego::negotiation::received_mech_types` | `src/spnego/negotiation.rs` | `spnego_token` |  |
| `rskrb5_ng::spnego::negotiation::verify_mic` | `src/spnego/negotiation.rs` | `spnego_token` |  |
| `rskrb5_ng::spnego::negotiation::response_mic` | `src/spnego/negotiation.rs` | `spnego_token` |  |
| `rskrb5_ng::spnego::decode_neg_token_init` | `src/spnego.rs` | `spnego_token` |  |
| `rskrb5_ng::spnego::decode_neg_token_resp` | `src/spnego.rs` | `spnego_token` |  |
| `rskrb5_ng::spnego::decode_negotiation_choice` | `src/spnego.rs` | `spnego_token` |  |
| `rskrb5_ng::spnego::ensure_kerberos_mechanism` | `src/spnego.rs` | `spnego_token` |  |
| `rskrb5_ng::spnego::integer_to_u32` | `src/spnego.rs` | `gss_token` |  |
| `rskrb5_ng::spnego::parse_negotiate_header` | `src/spnego.rs` | `spnego_token` |  |
| `rskrb5_ng::spnego::raw_krb5_negotiate_token` | `src/spnego.rs` | `spnego_token` |  |
| `rskrb5_ng::spnego::rotate_left` | `src/spnego.rs` | `gss_token` |  |
| `rskrb5_ng::spnego::system_time_from_kerberos_time` | `src/spnego.rs` | `gss_token` |  |
| `rskrb5_ng::spnego::validate_gss_sender` | `src/spnego.rs` | `gss_token` |  |
| `rskrb5_ng::spnego::validate_gss_token_id` | `src/spnego.rs` | `gss_token` |  |
| `rskrb5_ng::spnego::authenticator::validate` | `src/spnego/authenticator.rs` | `spnego_token` |  |
| `rskrb5_ng::spnego::der::DerReader::read_array` | `src/spnego/der.rs` | `spnego_token` |  |
| `rskrb5_ng::spnego::der::DerReader::read_len` | `src/spnego/der.rs` | `der_oid` |  |
| `rskrb5_ng::spnego::der::DerReader::read_tlv` | `src/spnego/der.rs` | `der_oid` |  |
| `rskrb5_ng::spnego::der::decode_base128` | `src/spnego/der.rs` | `der_oid` |  |
| `rskrb5_ng::spnego::der::decode_oid_tlv` | `src/spnego/der.rs` | `der_oid` |  |
| `rskrb5_ng::spnego::der::decode_oid_value` | `src/spnego/der.rs` | `der_oid` |  |
| `rskrb5_ng::spnego::der::decode_u32` | `src/spnego/der.rs` | `der_oid` |  |
| `rskrb5_ng::spnego::der::read_single_tlv` | `src/spnego/der.rs` | `der_oid` |  |
| `rskrb5_ng::spnego::oid::ObjectIdentifier::from_arcs` | `src/spnego/oid.rs` | `der_oid` |  |
| `rskrb5_ng::spnego::oid::validate_arcs` | `src/spnego/oid.rs` | `der_oid` |  |
| `rskrb5_ng::spnego::field_tests::decode_fields` | `src/spnego/field_tests.rs` | - | unit-test helper, not a parser |
| `rskrb5_ng::ticket::decode` | `src/ticket.rs` | `krb_messages` |  |
| `rskrb5_ng::ticket::decode_der` | `src/ticket.rs` | `krb_messages` |  |
| `rskrb5_ng::ticket::decode_enc_ticket_part` | `src/ticket.rs` | `krb_messages` |  |
| `rskrb5_ng::ticket::decrypt_ticket_enc_part` | `src/ticket.rs` | `krb_messages` |  |
| `rskrb5_ng::ticket::validate` | `src/ticket.rs` | `krb_messages` |  |

# Fuzzing of attacker-facing parsers

Todo 40 adds a `cargo fuzz` target for every parser that reads bytes or
text from outside the process, seeds each target from the fixtures the tests
already use, runs every target, and proves by coverage that each target
itself reaches the parsers mapped to it.

## Targets

`cargo +nightly-2026-10-03 fuzz list` prints these sixteen targets. All take
arbitrary bytes; most use the first byte as a selector and pass the rest to
the chosen entry point, so one target covers a family of related decoders.

| Target | Input | Entry points |
| --- | --- | --- |
| `keytab_parse` | keytab bytes | `Keytab::parse`, then `Keytab::to_bytes` on accepted input |
| `ccache_parse` | ccache bytes, and the same bytes as a cache name | `CCache::parse`, `config_entries`, `to_bytes`; `CacheName::parse` |
| `kpasswd_reply` | kpasswd frames | `Reply::parse`, `ChangePasswordResult::parse` with its `message` and `ad_policy` readings, `Request::parse`; an accepted reply is decrypted (`Reply::decrypt_result`) and verified (`verify_kpasswd_ap_rep`) against a fixed request |
| `pac_parse` | PAC container, one NDR buffer, PAC attributes, requestor SID, `PA-PAC-REQUEST` or authorization data | `Pac::parse_and_process` with the server checksum check and the explicit-policy `verify_ext` (server, KDC, ticket and full signatures, client binding) followed by the builder's re-signing of the parsed PAC, `Pac::parse` with `buffer_bytes`, every info-buffer parser (validation info, signatures, credentials info and the decrypted credential data, NTLM credentials, client info, UPN/DNS info, S4U delegation, device info, claims info, claims metadata and the decompressed claims set), and `AttributesInfo::parse`, `RequestorSid::parse`, `Request::decode_der` (an accepted element encodes and decodes again to itself), and `find_pac_in_authorization_data` on authorization data carried in an Authenticator |
| `spnego_token` | Negotiate header text or SPNEGO bytes | `parse_negotiate_header`, `Token`, `NegotiationToken`, `NegTokenInit` and `NegTokenResp` decoding, `accept_sec_context_header` and `Validator::validate_ap_req` with a synthetic keytab, `ValidatedApReq::verify_ap_rep`, and a structured mode that encrypts a fuzzed `EncTicketPart` and Authenticator under the keytab and session keys so the acceptance checks behind decryption run (ticket times, addresses, transited realms, authorization data, PAC) |
| `gss_token` | RFC 4121 tokens and AP-REP bytes | `Krb5MechToken::decode`; `MicToken` and `WrapToken` decode, verify and unwrap with AES128, AES256, AES-SHA2, DES3 and RC4 test keys; a sealed Wrap whose fuzzed plaintext is encrypted under the key; `InitiatorContext::verify_ap_rep` and `verify_ap_rep_response_header`, raw and with a fuzzed `EncAPRepPart` encrypted under the session key |
| `negoex_message` | a selector byte, then a `NegoEx` token, a SPNEGO token, or framed meta-data, mechanism-token and checksum bytes | `gss::negoex::Conversation::parse` as an acceptor and as an initiator (an accepted token is encoded again and must parse to as many messages), `gss::negoex::Context::step` as an acceptor and as an initiator after its own first token, `spnego::negoex::Acceptor::accept_sec_context` on raw bytes and on a continuation after a valid first token, and a structured mode that frames fuzzed meta-data, a mechanism token and `VERIFY` checksum bytes in valid `INITIATOR_NEGO`, meta-data, `AP_REQUEST` and `VERIFY` messages |
| `gss_name` | a selector byte for the name type, then a GSS-API name buffer | `gss::Name::import` and `Name::import_uid` for every MIT krb5 name type (host-based, user, user ids, anonymous, exported, composite exported, principal, enterprise, certificate), then `display`, `export` with re-import and comparison, and `canonicalize` |
| `gss_context` | a selector byte, then a context token, a SPNEGO token, or a DER `Authenticator` | `gss::Acceptor::accept_sec_context` and `spnego::Acceptor::accept_sec_context` on raw tokens; a structured mode that encrypts the fuzzed `Authenticator` (RFC 4121 checksum, delegation option, extensions, `AD-AP-OPTIONS`) under the fixture ticket's session key and accepts the AP-REQ, with and without acceptor channel bindings (optional or required) |
| `gss_iov` | a selector byte (context: AES256-SHA1, AES256-SHA384, DCE-style AES256-SHA1, opted-in DES3 or RC4; raw or mutation mode), then an IOV array or a mutation list | `EstablishedContext::unwrap_iov` and `verify_mic_iov` on fuzzed `kind, length, bytes` IOV records (HEADER, DATA, SIGN_ONLY, PADDING, TRAILER, STREAM, MIC_TOKEN, duplicates and inconsistent lengths); in mutation mode the initiator's `wrap_iov` (with and without a TRAILER), `wrap_aead`, `wrap` and `get_mic` tokens are mutated before `unwrap_iov`, `unwrap_aead`, `unwrap` and `verify_mic` open them, which runs the RFC 1964/4757 parsers on the DES3 and RC4 contexts |
| `gss_transfer` | a selector byte (context or credential; raw blob or a payload sealed as the documented version-1 format), then the bytes | `EstablishedContext::import` and `Credential::import` with one `MemoryTransferLedger` per run: the header and size checks, the RFC 8009 authentication, and in sealed mode the payload decoder; a second import of an accepted blob must fail |
| `gss_iakerb` | a selector byte, then an IAKERB token, an acceptor input, an acceptor answer or the bytes of an `IAKERB-FINISHED` | `gss::iakerb::token::Token::decode` on every input (an accepted token is an IAKERB token and re-encodes to one that decodes to the same token); after a valid relayed request (asserted, answered by a fixed relay) the acceptor `iakerb::Context::accept_sec_context` on the raw bytes (proxy tokens, realm discovery, AP-REQs); the initiator `iakerb::Context::init_sec_context` on the bytes as its first answer, raw and as the message of a proxy token for the realm; and the acceptor on an AP-REQ of the fixture ticket whose authenticator checksum carries the bytes as the `IAKERB-FINISHED` extension, after a realm-discovery exchange (a transcript to check) and without one (the finished is refused) |
| `kadm5_reply` | ONC RPC records and replies from kadmind and kadm5 results, one selector byte then bytes (for a result a second byte picks the procedure and the API version) | `rpcsec_gss::decode_record` (the bounded record-mark reassembler: fragment and total-size bounds from the headers, at most 16,384 fragments), `rpcsec_gss::Reply::decode` (RFC 5531 replies, verifiers of at most 400 bytes) and `kadm5::Response::decode` for every kadm5 procedure under API v2, v3 and v4 (principal and policy records, name, key, key-data and string lists with every count checked against its bytes before allocation, MIT's NUL-terminated strings, no trailing bytes) |
| `http_negotiate` | `Authorization` or `WWW-Authenticate` header values | `http::accept_request` (service side) and `www_authenticate_negotiate_header`, `classify_negotiate_response` and `verify_ap_rep_response` (client side) |
| `kdc_reply` | KDC replies | `decode_as_rep`, `decode_tgs_rep`, `decode_enc_kdc_rep_part`, the KRB-ERROR and METHOD-DATA decoders, `process_kdc_error` with preauthentication hint selection and `s2kparams` parsing, `process_as_rep`, `process_tgs_rep` and `process_tgs_rep_with_referral` against fixed requests, and structured AS/TGS replies whose fuzzed `EncKDCRepPart` is encrypted under the request's key |
| `kdc_tcp_frame` | four-byte KDC TCP record mark, tested against zero, small and large caps | `client::transport::kdc_tcp_record_length`; production shares the reserved-bit, zero-length and pre-allocation cap checks |
| `krb_messages` | Kerberos messages | AP-REQ, Authenticator, AP-REP, `EncAPRepPart`, KRB-CRED, `EncKrbCredPart`, KRB-PRIV, `EncKrbPrivPart`, KRB-SAFE, Ticket, `EncTicketPart`, KRB-ERROR, `KDC-REQ-BODY`, AS-REQ, TGS-REQ, the PA-DATA messages and the kpasswd `ChangePasswdData` and KRB-PRIV codecs; the decrypt functions under a fixed key; and a sealed mode that encrypts the fuzzed plaintext into a message template so the decoders behind decryption see it |
| `der_oid` | DER and OID bytes | the crate's SPNEGO DER reader and OID decoder (decode, re-encode, decode again must give the same value), `ObjectIdentifier::from_arcs`, and a decrypted Authenticator whose fuzzed plaintext reaches the zero-padding trimmer and the complete-message decoder |
| `krb5_conf` | `krb5.conf` text (UTF-8-lossy) | `Config::parse` and includes, then the enctype-list accessors `default_tkt_enctype_ids`, `default_tgs_enctype_ids` and `permitted_enctype_ids` on an accepted configuration |
| `extensions` | `.k5identity` contents, or `krb5.conf` text parsed through an extension registry | `K5Identity::from_bytes` and `CacheSelector::choose` (the `.k5identity` grammar and its `fnmatch` patterns, for a host-based and a plain server), and `Registry::parse_config` (the `module <id>:<residual>` profile directive and `[plugins]` module resolution) in both parse modes |
| `ccache_collection` | a `DIR` collection's `primary` pointer and its `tkt` cache file, split at the first byte | `DirStore` collection enumeration, primary resolution and loads (`read_primary`, the locked reads and `FileCache::parse`), and the `FILE` store load of the same file |
| `camellia_crypto` | Camellia-CTS-CMAC input: a selector byte (entry point and camellia128 or camellia256), the key usage and the input | `CtsCmacEtype::decrypt_message` on the raw input, then on a sealed copy of it (round trip, and a changed MAC is refused); `verify_checksum` on a checksum split from its data, then on the computed one (and a changed one is refused); `decrypt_data` and the re-encryption of an accepted ciphertext; `string_to_key` on `s2kparams` text (the count is bounded to 64 so the run stays fast; zero, over-limit and malformed counts are refused before any work) |
| `kcm_reply` | a KCM daemon's reply byte stream | the blocking KCM client (`Client::call`, `read_frame`, `read_exact`) over the input as the whole reply stream, once for each reply shape: cache name, UUID list, default principal, one credential, counted credential list, KDC offset and empty (`Shape::decode` of each), with the reply limit lowered to 64 KiB; the announced length is checked before the body is allocated |
| `keyring_index` | the payload of the `krb_ccache:primary` key of a `KEYRING:` collection | `ccache::keyring::index::parse`, then `encode` and `parse` again on accepted input (the version, the length and the name of the primary cache; MIT `cc_keyring.c:541-571`) |
| `fast_reply` | replies to an armored AS request (RFC 6113 FAST) | the stepwise AS engine armored by `preauth::fast::Exchange` with a fixed armor ticket: the raw reply (outer AS-REP or KRB-ERROR, METHOD-DATA, `PA-FX-FAST-REPLY`), and the fuzzed bytes sealed as the `KrbFastResponse` under the conversation's armor key inside a KRB-ERROR or an AS-REP (`KrbFastResponse`, `PA-FX-ERROR`, the cookie bound, `KrbFastFinished` and its ticket checksum); no fuzzed reply may complete the exchange |
| `kkdcp_message` | a proxy's KDC-PROXY-MESSAGE (MS-KKDCP) and the text of an `https://` server entry or DNS URI target, one selector byte then bytes or text | `transport::kkdcp::ProxyMessage::decode` (then encode and decode again must give the same message), `transport::kkdcp::decode_reply` (an accepted reply is non-empty and shorter than its message), and `transport::proxy::Url::parse` (an accepted URL parses again from its display form to the same URL) |
| `spake_message` | a KDC's PA-SPAKE value (RFC 9588) | `preauth::spake::Message::decode` twice (deterministic), then a fresh `Client` permitting all four groups answers the value twice (`Client::process`): support message for empty or out-of-policy values, response for a challenge in a permitted group, which decodes and validates the edwards25519, P-256, P-384 or P-521 element and derives `K'[0]` and `K'[1]`; a second challenge must be refused |
| `otp_challenge` | a KDC's `PA-OTP-CHALLENGE` value (RFC 6560) | `preauth::otp::Challenge::decode` twice (deterministic) and once under a tight policy (token count, field and challenge bounds), then an accepted challenge answers every token and one index past the list, with a value and with a value and a PIN, under an AES256 armor key (`Challenge::request`): every request built is an OTP padata of the request type |
| `pkinit_reply` | the KDC's reply to a PA-PK-AS-REQ (RFC 4556 PKINIT) | the stepwise AS engine with a certificate `preauth::pkinit::Exchange` after a fixed `PREAUTH_REQUIRED`: mode 0 the raw reply (AS-REP or KRB-ERROR, the PA-PK-AS-REP lookup), mode 1 the bytes as the PA-PK-AS-REP value of an AS-REP (`PA-PK-AS-REP`, `DHRepInfo`, the CMS `ContentInfo` and `SignedData`, X.509 certificates and CRLs, the bounded path validator, `KDCDHKeyInfo` and the key agreement); no fuzzed reply may complete the exchange |
| `routing_transit` | a ticket's DOMAIN-X500-COMPRESS transited encoding (RFC 4120 section 3.3.3.2), a KDC's `PA-S4U-X509-USER` (MS-SFU) and the text of two realm names, one selector byte then bytes or text | `routing::transited::decode` between two fixed realms (an accepted list stays within `MAX_REALMS` and, when `encode` takes it, decodes again to the same list), `routing::s4u::PaS4uX509User::decode_der` (then encode and decode again must give the same element), and `routing::RealmPath::hierarchical` (a path starts at the first realm, ends at the second and stays within `RealmPath::MAX_REALMS`) |
| `localauth_rule` | the text of an `auth_to_local` value, a newline, then a principal (`a/b/c` in `EXAMPLE.COM`) | `localauth::AuthToLocalRule::parse` (the bounded `RULE:[n:format](regex)s/re/text/g` grammar and the linear-time `regex` compiler), then `apply` on the principal and `principal_to_local_name` through a `LocalNameMapper` (a result stays within the selection bound, a mapped name is never empty, longer than 64 bytes or NUL-holding) |
| `localauth_k5login` | a principal (`a/b@REALM`, up to the first newline), then the bytes of a `.k5login` file | `localauth::k5login::lists` (the size, line-count and line-length bounds and the exact line match; a file past the size bound is refused) |
| `replay_file` | a selector byte, then the bytes of an existing MIT `file2` replay-cache file, or a replay-cache name | `replay::File2ReplayStore::admit` over an in-memory file holding the fuzzed bytes (the seed, the hash tables, truncated and hostile files; a tag accepted twice is a failure), and `replay::RcacheName::parse` (`dfl:`, `file2:<path>`, `none:`, `memory:`) |
| `auth_message` | a selector byte, then a KRB-PRIV, KRB-SAFE, KRB-CRED, a DER element or an authorization-data element | `messages::AuthContext::rd_priv`, `rd_safe` and `rd_cred` (encrypted, and unencrypted over a vouched channel) under a fixed key, clock and sequence checking (an accepted message is refused the second time), the public `asn1` length, element, application-tag and structure readers under a size budget, and the `authdata` AD-KDC-ISSUED and AD-AND-OR decoders |
| `name_parse` | names and values as text | `Principal::parse_user`, `Principal::parse_service`, `CacheName::parse`, `keytab::Name::parse`, `KdcEndpoint::configured`, `Tokio::with_dns_server`, `config::parse_duration`, `config::parse_boolean`, `crypto::s2kparams_to_iterations` |
| `discovery_uri` | the data DNS hands to server discovery, one selector byte then bytes or text | `discovery::uri::parse` (a `krb5srv:flags:transport:host` URI record target) and `host_port` on an accepted target, `split_rdata` (URI record data), `realm_from_txt` (the first string of a TXT realm record) and `host_port` on arbitrary text; the target text, the host and the realm stay within their bounds |
| `http_location` | a base URI, a newline and a `Location` value | `http::origin::resolve_location` (absolute, scheme-relative, path-absolute, query-only and path-relative references, dot-segment removal, fragment removal; the refusals of user information, foreign schemes and forbidden bytes) and `Origin::of` on every accepted target |
| `http_session` | a selector byte, then a session cookie value or `Cookie` header, or a principal | `SessionManager::resume` (base64url, the sealed-blob framing and the RFC 8009 authentication; no value the manager never sealed may resume) and `attach` on a `Cookie` header; an odd selector issues a session for the fuzzed principal and requires it to resume to the same principal |
| `http_set_cookie` | a request URI, a newline and `Set-Cookie` values, one per line | `http::cookies::CookieStore::store_set_cookie` (parsing, the size, `Secure` and `Domain` refusals and the RFC 6265 storage model over a small public-suffix list) and `cookie_header` on the accepted jar (the `http-client` leaf) |

The keys, keytabs, tickets and templates the targets use are the synthetic
gokrb5 test vectors the tests already carry (`fuzz/fixtures/`). The fuzz
crate depends on `libfuzzer-sys` and on `rskrb5-ng` with its `http` and `camellia`
features; the `http_negotiate` target needs `http`, the `http_set_cookie` target
the `http-client` leaf and the `camellia_crypto` target
needs the `camellia` leaf. Compiling the leaf in does not grant runtime permission
(`docs/security-policy.md#camellia`).

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
| `pac_parse` | 959,198 (todo 22 of plan 2, 2026-11-22; was 839,490) | 121 s | 0 |
| `spnego_token` | 861,077 | 121 s | 0 |
| `gss_token` | 293,635 | 121 s | 0 |
| `http_negotiate` | 284,293 | 121 s | 0 |
| `kdc_reply` | 650,531 | 121 s | 0 |
| `kdc_tcp_frame` | 24,229,707 | 121 s | 0 |
| `krb_messages` | 306,487 | 121 s | 0 |
| `der_oid` | 348,348 | 121 s | 0 |
| `krb5_conf` | 140,698 (todo 15 F, 2026-11-01) | 121 s | 0 |
| `name_parse` | 2,629,623 | 121 s | 0 |
| `extensions` | 651,170 (todo 3 of plan 2, 2026-11-18) | 121 s | 0 |
| `ccache_collection` | 163,889 (todo 11 of plan 2, 2026-11-19) | 121 s | 0 |
| `discovery_uri` | 5,245,496 (todo 15 of plan 2, 2026-11-20) | 91 s | 0 |
| `camellia_crypto` | 725,278 (todo 33 of plan 2, 2026-11-19) | 121 s | 0 |
| `kcm_reply` | 596,862 (todo 12 of plan 2, 2026-11-19) | 121 s | 0 |
| `keyring_index` | 6,296,962 (todo 13 of plan 2, 2026-11-19) | 121 s | 0 |
| `fast_reply` | 28,010 (todo 7 of plan 2, 2026-11-20) | 121 s | 0 |
| `spake_message` | 336,637 (todo 9 of plan 2, 2026-11-20) | 121 s | 0 |
| `kkdcp_message` | 6,458,968 (todo 16 of plan 2, 2026-11-21) | 121 s | 0 |
| `otp_challenge` | 1,658,639 (todo 10 of plan 2, 2026-11-21) | 121 s | 0 |
| `pkinit_reply` | 4,823 (todo 8 of plan 2, 2026-11-21) | 121 s | 0 |
| `routing_transit` | 2,195,539 (todo 17 of plan 2, 2026-11-21) | 121 s | 0 |
| `localauth_rule` | 283,256 (todo 25 of plan 2, 2026-11-22) | 121 s | 0 |
| `localauth_k5login` | 2,439,093 (todo 25 of plan 2, 2026-11-22) | 121 s | 0 |
| `http_location` | 1,197,682 (todo 26 of plan 2, 2026-11-25) | 61 s | 0 |
| `http_session` | 469,278 (todo 26 of plan 2, 2026-11-25) | 61 s | 0 |
| `http_set_cookie` | 242,019 (todo 26 of plan 2, 2026-11-25) | 61 s | 0 |
| `gss_name` | 2,118,533 (todo 18 of plan 2, 2026-11-22) | 121 s | 0 |
| `gss_context` | 1,096,589 (todo 18 of plan 2, 2026-11-22) | 121 s | 0 |
| `gss_iov` | 24,211 (todo 19 of plan 2, 2026-11-23) | 121 s | 0 |
| `gss_transfer` | 565,305 (todo 19 of plan 2, 2026-11-23) | 121 s | 0 |
| `gss_iakerb` | 49,306 (todo 20 of plan 2, 2026-11-23) | 121 s | 0 |
| `replay_file` | 6,582,638 (todo 27 of plan 2, 2026-11-23) | 121 s | 0 |
| `auth_message` | 2,718,082 (todo 27 of plan 2, 2026-11-23) | 121 s | 0 |

### Round-2 session admission repair (FU-FUZ-R02)

The original `ticket.der` is a NULL-enctype codec vector, not an admissible
session ticket. The four reply harnesses now share a deterministic AES ticket
builder that decrypts the genuine AP-REQ fixture and re-encrypts its body with
the advertised session key and service. GSS legacy modes explicitly enable
RC4 and DES3 in their policy. Fixed request/context construction is asserted
before arbitrary-input processing, including all six GSS keys and both TGS
request modes, so admission failures cannot silently remove those paths.

On 2026-11-08 all thirteen targets built. Each affected target ran with
`cargo +nightly-2026-10-03 fuzz run <target> -- -max_total_time=60`,
`RUSTFLAGS=--cap-lints=warn` and `CARGO_BUILD_WARNINGS=allow`:

| Target | Runs | Time | New crash, OOM or timeout artifacts |
| --- | ---: | ---: | ---: |
| `kpasswd_reply` | 43,053 | 61 s | 0 |
| `gss_token` | 7,138 | 61 s | 0 |
| `http_negotiate` | 31,346 | 61 s | 0 |
| `kdc_reply` | 20,475 | 61 s | 0 |

The failing-first `kpasswd_reply` construction assertion exited 77 before
the fixture repair. An initial repair used the wrong fixture decryption key
and failed the same assertion; both setup failures were corrected before the
four clean runs above. Their artifacts were removed, and the separate fuzz
target directory was deleted after the runs. `fuzz_lint.py --enforce` passes.

Fresh per-target coverage exports from the committed seeds prove all seven
AP-REP/TGS mappings affected by this finding: `process_tgs_rep` 53,
`process_tgs_rep_inner` 106, `process_tgs_rep_with_referral` 53,
`verify_kpasswd_ap_rep` 1, HTTP `verify_ap_rep_response` 3, initiator
`verify_ap_rep` 4 and `verify_ap_rep_response_header` 2. This is a scoped
reachability proof, not a refreshed whole-inventory proof: checking all 71
mappings of those four targets matched 51 and reported 20 unmatched mappings
(including moved source owners and deeper reply-validation paths).

### KEYRING collection index (todo 13 of plan 2)

`keyring_index` fuzzes the one new parser of bytes that another process of the
same user can write, the payload of the `krb_ccache:primary` key
(`ccache::keyring::index::parse`). The run of 2026-11-19 made 6,296,962
executions in 121 s from the eight committed seeds with no artifact. The
coverage export of the target's own binary from the seeds alone reaches the
mapped function (`scripts/lint-gates/fuzz_coverage.py --inventory --coverage`
with only this target's export: `rskrb5_ng::ccache::keyring::index::parse` in
`src/ccache/keyring/index.rs`, count 10). The other functions of the keyring
module that the inventory search finds are reason-only rows: they hand bytes to
parsers that other rows already cover, split text the application or the kernel
produced, or are the key calls themselves.

### Server discovery (todo 15 of plan 2)

`discovery_uri` fuzzes the four parsers of the data that DNS hands to server
discovery: the `krb5srv:flags:transport:host` target of a URI record
(`discovery::uri::parse`), its `host[:port]` (`host_port`), the URI record data
(`split_rdata`) and the first string of a TXT realm record (`realm_from_txt`).
The run of 2026-11-20 made 5,245,496 executions in 91 s from the seven committed
seeds and a scratch corpus with no artifact. The coverage export of the target's
own binary from the seeds alone reaches all four mapped functions
(`scripts/lint-gates/fuzz_coverage.py --inventory --coverage` with only this
target's export proves 4 mappings, counts 3, 5, 1 and 1). The server-name
parsers that the DNS answer reaches afterwards (`KdcEndpoint::configured`) stay
under `name_parse`.

### FAST replies (todo 7 of plan 2)

`fast_reply` fuzzes the replies to an armored AS request: the stepwise engine
is armored by `preauth::fast::Exchange` with a fixed armor ticket, and the
harness recovers the conversation's armor key from the armor AP-REQ as the KDC
would, so its structured modes reach the decoders behind decryption
(`KrbFastResponse`, `PA-FX-ERROR`, the cookie bound, `KrbFastFinished`). Each
input builds a fresh exchange (a new armor subkey and AP-REQ), which keeps the
rate near 230 inputs a second. The run of 2026-11-20 made 28,010 executions in
121 s from the seven committed seeds with no artifact; an earlier run stopped
at once on a harness assertion (the DER walk wrapped the armor AP-REQ in a
second tag), fixed before this run. The coverage export of the target's own
binary from the seeds alone reaches all six mapped functions (`decode_request`
8, `keys::decode` 3, `keys::open` 5, `error_reply` 4, `fast_response` 5,
`reply::unwrap` 7). `EncryptedChallenge::verify_reply` is mapped to its tests:
a one-reply exchange never reaches the final round.

### KDC proxy messages (todo 16 of plan 2)

`kkdcp_message` fuzzes what an MS-KKDCP proxy and a DNS URI record can hand the
client: the KDC-PROXY-MESSAGE codec (`ProxyMessage::decode`, bounded at 1 MiB
before decoding, complete DER only), the reply framing behind it (`decode_reply`:
the four-byte record mark must equal the length of the message behind it), and
the `https://` URL parser of server entries and `kkdcp` URI targets
(`Url::parse`). The seeds are MIT 1.22.2's reference encoding of a
KDC-PROXY-MESSAGE (`src/tests/asn.1/reference_encode.out:69`), two framed replies
and three URLs. The first 120-second run found a host part with a space and NUL
bytes that `Url::parse` accepted and whose display form parsed differently; the
parser now refuses any host-part byte outside visible ASCII (red run and fix in
the task-16 evidence log), and the rerun recorded above found nothing. Coverage
proof: `task-16-kkdcp-coverage.tsv` in the execution evidence.

### SPAKE messages (todo 9 of plan 2)

`spake_message` fuzzes the PA-SPAKE value a KDC sends (`Message::decode`,
`wire::decode`: the bounded DER codec of RFC 9588 appendix A) and the client
half behind it, which decodes and validates the KDC's group element in the
four groups of the `spake` leaf (the fuzz crate enables the leaf). The seeds
are the support and challenge messages of the RFC 9588 appendix C vectors, an
empty value and an `encdata` message. Coverage proof: record
`task-9-spake-coverage.tsv` in the execution evidence.

### OTP challenges (todo 10 of plan 2)

`otp_challenge` fuzzes the `PA-OTP-CHALLENGE` a KDC sends inside FAST
(`Challenge::decode` and its decoder `challenge::decode`: the size bound, the
count and field bounds, the RFC 6560 flag rules and MIT's token filter) and the
request builder behind it (`Challenge::request`). The seeds are MIT's own
minimal and maximal challenges (`src/tests/asn.1/reference_encode.out`), a
challenge with two PIN-collecting tokens, one that sets both PIN flags, an empty
value and a truncated one. Coverage proof: record `task-10-otp-coverage.tsv` in
the execution evidence.

### PKINIT replies (todo 8 of plan 2)

`pkinit_reply` fuzzes the KDC's answer to a PA-PK-AS-REQ: every input runs a
fresh certificate exchange (the OpenSSL client fixture of `tests/pkinit`, an
ephemeral P-256 key and an ECDSA signature per input, which keeps the rate near
40 inputs a second), answers the fixed `PREAUTH_REQUIRED`, and feeds the fuzzed
bytes as the reply or as the PA-PK-AS-REP value of an AS-REP. The seeds are an
OpenSSL `cms -sign` SignedData inside a `DHRepInfo` (it verifies and chains to
the fixture anchor, then fails on its content), an `encKeyPack` (refused by
policy) and a KRB-ERROR. The run of 2026-11-21 made 4,823 executions in 121 s
with no artifact. Coverage proof: `task-8-pkinit-coverage.tsv` in the
execution evidence.

### PAC API (todo 22 of plan 2)

`pac_parse` gained four entry points for what a service reads from a KDC or a peer:
`AttributesInfo::parse` and `RequestorSid::parse` (selectors 16 and 17: at most 1,024 flag bits
and at most 15 sub-authorities), `Request::decode_der` (selector 18; an accepted
`PA-PAC-REQUEST` encodes and decodes again to itself) and the explicit-policy verification
(selector 19: `Pac::verify_ext` under the policy that requires every signature, with the keys and
ticket bytes of the independent vectors, then `Builder::from_pac` re-signing the parsed PAC and
verifying the result), besides the stricter container checks (duplicate and overlapping buffers,
at most 4,096 buffers) that `whole_pac` and `header_only` already reach. Five seeds were added
(one per new selector and a Samba-shaped PAC with a zero-length claims buffer). The 120-second
run recorded above found nothing. Coverage proof: `task-22-pac-coverage.tsv` in the execution
evidence (63 of 64 `pac_parse` rows; `KerberosEtype::verify_checksum` is reached but its row
names the module `crypto` while the symbol is `cryptography`, a mismatch older than this todo,
register row FU-PAC-P06).

### Cross-realm routing (todo 17 of plan 2)

`routing_transit` fuzzes what an acceptor and a delegating service read from
other parties: the transited encoding inside a ticket an acceptor decrypts
(`transited::decode`: at most 4,096 bytes, realm names of at most 512 bytes,
at most 64 realms with the expanded ones, refusing what MIT 1.22.2's
`chk_trans.c` refuses plus a trailing escape, inner NUL bytes and names that
are not UTF-8), the `PA-S4U-X509-USER` element a KDC answers an `S4U2Self`
request with (`PaS4uX509User::decode_der`), and the realm hierarchy walk over
arbitrary names (`RealmPath::hierarchical`). The seeds are MIT 1.22.2's
`transit-tests` and `walktree-tests` vectors (`src/lib/krb5/krb/`) and one
encoding of escaped and protected names. The 120-second run recorded above
found nothing. Coverage proof: `task-17-routing-coverage.tsv` in the execution
evidence.

### Local authorization (todo 25 of plan 2)

`localauth_rule` fuzzes the `auth_to_local` rule language that an administrator
writes into `krb5.conf`: `AuthToLocalRule::parse` reads at most 2,048 bytes
(patterns of at most 512 bytes, replacement texts of at most 256, at most 16
substitutions) and compiles every pattern with the linear-time `regex` engine
under a compiled-size and a nesting limit, and the accepted rule is applied to
a principal. `localauth_k5login` fuzzes what a `.k5login` file can hold
(`k5login::lists`: at most 1 MiB, 16,384 lines, 8,191 bytes per line). The seeds
are MIT 1.22.2's `t_localauth.py` rules, a catastrophic-backtracking pattern
that stays linear, and `.k5login` files with escaped components and near
misses. The 120-second runs recorded above found nothing. Coverage proof:
`task-25-localauth-coverage.tsv` in the execution evidence.

### HTTP client and sessions (todo 26 of plan 2)

Three targets read what an HTTP peer sends. `http_location` fuzzes the redirect
resolver: a `Location` value of at most 8,192 bytes is resolved against the
request URI (RFC 3986 section 5.2), and an accepted target must be a plain
`http` or `https` URI with a host, without user information in its authority,
without a fragment or a dot segment. `http_session` fuzzes the session cookie a
server reads back: a value of at most 4,096 bytes is decoded and authenticated
under a fixed key, and no value the manager never sealed may resume (the
framing after the authentication is reached by the structured mode, which
issues a session for a fuzzed principal and requires it to resume to the same
principal). `http_set_cookie` fuzzes the `Set-Cookie` handling of the `http-client`
leaf's jar. The seeds are the redirect forms of the tests, issued and garbage
session values, and the cookie attributes the jar refuses. The first
`http_location` run stopped on an assertion of the target itself (an `@` in a
path was taken for user information; the library's output was right and the
assertion now inspects the authority). The second `http_set_cookie` run found a
real defect: a `Set-Cookie` value holding a byte outside visible ASCII was stored and
came back in a `Cookie` header that `HeaderValue::to_str` refuses; the jar now refuses
such a value (regression test `a_non_ascii_cookie_is_refused`, seed
`non-ascii-value`). The three 61-second runs recorded above are the clean ones after
these two fixes. Coverage proof: `task-26-http-coverage.tsv` in the
execution evidence.

### GSS-API (todo 18 of plan 2)

`gss_name` fuzzes GSS-API name import for every name type MIT krb5 1.22.2
imports (`import_name.c:126-345`): principal strings with MIT's escapes and
the enterprise rule (`parse.c:30-210`), host-based names, user ids through a
fixed resolver, and RFC 2743 exported and RFC 6680 composite exported tokens
(names of at most 4 KiB, certificates and attribute blocks of at most
64 KiB). `gss_context` fuzzes the acceptor: raw context tokens, SPNEGO tokens,
and a structured mode that encrypts a fuzzed `Authenticator` under the
fixture ticket's session key so the RFC 4121 checksum (bindings, flags,
delegation option, at most 16 extensions) and the `AD-AP-OPTIONS` search
(at most eight `AD-IF-RELEVANT` levels) run. Per-message tokens stay with
`gss_token`. Seeds: exported names in MIT's layout and authenticators of the
fixture client with GSS checksums, bindings, a CBT assertion and truncated
options. The first `gss_name` run found that a host-based name did not
compare equal to its exported form imported back (register row FU-GSS-P02,
fixed); the 120-second runs recorded above found nothing after the fix.
Coverage proof: `task-18-gss-coverage.tsv` in the execution evidence (3 of 3
mappings).

### GSS-API II (todo 19 of plan 2)

`gss_iov` fuzzes the per-message parsers todo 19 adds to an established
context: IOV arrays in MIT's buffer model (`k5sealiov.c`, `k5unsealiov.c`;
duplicated HEADER, TRAILER, PADDING, STREAM or MIC_TOKEN buffers, short
trailers and inconsistent lengths are refused), AEAD tokens, the DCE-style
RRC rule, and the RFC 1964 (DES3) and RFC 4757 (RC4) token formats of
opted-in legacy contexts, including the single-DES algorithm identifiers
that are refused by name. Each run builds its context pair in process from
the fixture ticket re-sealed with the chosen session key, so it runs about
200 inputs a second. `gss_transfer` fuzzes the import of context and
credential transfer blobs: raw blobs exercise the size, header and RFC 8009
authentication checks; the sealed mode encrypts the fuzzed payload under the
fixed transfer key so the version-1 payload decoder behind the
authentication runs, and a second import of an accepted blob through the
same ledger must fail. Seeds: tokens and blobs built by hand per RFC 4121
section 4.2, RFC 1964 and the documented transfer format. The 120-second
runs recorded above found nothing. `TransferBlob::from_bytes` stores bytes
without reading them; the decoders it hands them to (`export::open` and
the payload reader) are reached by the committed `gss_transfer` seeds
(record `task-19-gss-coverage.tsv` in the execution evidence).

### Remote kadm5 (todo 24 of plan 2)

`kadm5_reply` fuzzes what a kadmind (or anything posing as one before the
RPCSEC_GSS context is checked) sends the remote kadm5 client: the RFC 5531
record marks, the RPC reply around the verifier, and every kadm5 result layout
of MIT krb5 1.22.2's `kadm_rpc_xdr.c` under each API version. The RPCSEC_GSS
verifier and body checks themselves are per-message GSS tokens, which stay
with `gss_token`. Seeds: a reply split over two fragments, an accepted and a
denied reply, and one result of each payload shape (principal record with TL
and key data, v2 and v4 policy records, name list, random keys, key data,
string attributes, privileges). Coverage proof: `task-24-kadm5-coverage.tsv`
in the execution evidence.

### Earlier campaign crashes

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

Plan 2 todo 3 added the `extensions` target and proved its four rows the same
way: `cargo fuzz coverage extensions` on the committed seeds, `llvm-cov export`
of that target, then `coverage_index` and `check_coverage` on the `extensions`
rows (4 of 4 mappings; record `task-3-extensions-coverage.tsv` in the
execution evidence). The other targets were not rebuilt in that lane.

Plan 2 todo 11 added the `ccache_collection` target for the `DIR` collection
readers and proved its four rows the same way (4 of 4 mappings; record
`task-11-ccache-collection-coverage.tsv` in the execution evidence). The
auxiliary-vector parser of the secure-environment decision has no target: it
reads only this process's kernel-written `/proc/self/auxv`, and its row says so.

Plan 2 todo 33 added the `camellia_crypto` target (the supervisor finding Y3-05,
register row FU-CRY-P06) and proved its six rows the same way: `cargo fuzz coverage
camellia_crypto` on the committed seeds, `llvm-cov export` of that target, then
`coverage_index` and `check_coverage` on its rows (6 of 6 mappings; record
`task-33-camellia-coverage.tsv` in the execution evidence). The inventory names a
function by its source path, while the coverage symbols follow the module tree: this
crate mounts `src/crypto.rs` as `pub mod cryptography` (re-exported as `crypto`), and
the `impl CtsCmacEtype` blocks in `src/crypto/camellia/etype.rs` belong to the type
declared in `camellia`. The proof therefore maps those two names before matching
(`cryptography` to `crypto`, and `etype::` inserted for that file), and the unmodified
`--coverage` mode does not match these rows; register row FU-FUZ-P01 records it. The
other targets were not rebuilt in that lane.

Plan 2 todo 12 added the `kcm_reply` target for the KCM client's reply reader
and proved its nine rows the same way (9 of 9 mappings: `Client::read_frame`,
`Client::read_exact` and the seven `Shape::decode` implementations; record
`task-12-kcm-reply-coverage.tsv` in the execution evidence). The target serves
each input as the whole reply stream to a fresh client once per reply shape, so
every decoder is reached by every seed; the seeds are one valid reply per shape
(name, UUID list, principal, credential, counted credential list, KDC offset,
empty), a daemon status, a transport status, an announced length of 4 GiB and a
credential count larger than the payload. `Deadline::read` reads the daemon
socket and parses nothing, so its row names no target.

Plan 2 todo 26 added the `http_location`, `http_session` and `http_set_cookie`
targets and proved their four rows the same way (4 of 4 mappings: `resolve_location`,
`SessionManager::resume`, the blob reader `open` and `CookieStore::store_set_cookie`;
record `task-26-http-coverage.tsv` in the execution evidence). The other targets were
not rebuilt in that lane.

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
| `rskrb5_ng::ccache::dir_store::read_primary` | `src/ccache/dir_store.rs` | `ccache_collection` |  |
| `rskrb5_ng::ccache::keyring::index::parse` | `src/ccache/keyring/index.rs` | `keyring_index` |  |
| `rskrb5_ng::ccache::keyring::payload::parse_credential` | `src/ccache/keyring/payload.rs` | - | Hands a key payload to `Credential::parse` (row `ccache_parse`) and refuses bytes after the credential; it reads no bytes itself. |
| `rskrb5_ng::ccache::keyring::payload::parse_principal` | `src/ccache/keyring/payload.rs` | - | Hands a key payload to `Principal::parse` (row `ccache_parse`) and refuses bytes after the principal; it reads no bytes itself. |
| `rskrb5_ng::ccache::keyring::residual::Residual::parse` | `src/ccache/keyring/residual.rs` | - | Splits the cache name the application passes in (`anchor:collection:subsidiary`) at two colons; text of the caller, not bytes read from outside the process. |
| `rskrb5_ng::ccache::keyring::residual::parse_description` | `src/ccache/keyring/residual.rs` | - | Splits the text the kernel prints for `keyctl_describe` (`type;uid;gid;permissions;description`) at four semicolons; one bounded split, the kernel formats every field but the description. |
| `rskrb5_ng::ccache::keyring::residual::parse_owner` | `src/ccache/keyring/residual.rs` | - | Reads the owner field of the same kernel text: one split and an integer parse. |
| `rskrb5_ng::ccache::keyring::residual::parse_serials` | `src/ccache/keyring/residual.rs` | - | Chunks the array of 4-byte key serial numbers the kernel returns for a keyring read; no length field, a partial tail is dropped. |
| `rskrb5_ng::ccache::keyring::backend::read` | `src/ccache/keyring/backend.rs` | - | The `keyctl_read` call as a trait method: it returns the caller's buffer and parses nothing. |
| `<rskrb5_ng::ccache::keyring::kernel::Kernel as Backend>::read` | `src/ccache/keyring/kernel.rs` | - | The `keyctl_read` call of the kernel backend: one system call into a zeroizing buffer, no parsing. |
| `<rskrb5_ng::ccache::keyring::fake::calls::Fake as Backend>::read` | `src/ccache/keyring/fake/calls.rs` | - | The in-memory kernel of the unit tests (`cfg(test)`), no parsing. |
| `rskrb5_ng::ccache::file_store::FileCache::parse` | `src/ccache/file_store.rs` | `ccache_collection` |  |
| `rskrb5_ng::ccache::kcm::client::Client::read_exact` | `src/ccache/kcm/client.rs` | `kcm_reply` |  |
| `rskrb5_ng::ccache::kcm::client::Client::read_frame` | `src/ccache/kcm/client.rs` | `kcm_reply` |  |
| `<rskrb5_ng::ccache::kcm::socket::Deadline as Read>::read` | `src/ccache/kcm/socket.rs` | - | reads the daemon socket into the caller's buffer under the call deadline and parses nothing; the framing that calls it is `Client::read_frame` (`kcm_reply`) |
| `<rskrb5_ng::ccache::kcm::wire::shape::Credentials as rskrb5_ng::ccache::kcm::wire::shape::Shape>::decode` | `src/ccache/kcm/wire/shape.rs` | `kcm_reply` |  |
| `<rskrb5_ng::ccache::kcm::wire::shape::DefaultPrincipal as rskrb5_ng::ccache::kcm::wire::shape::Shape>::decode` | `src/ccache/kcm/wire/shape.rs` | `kcm_reply` |  |
| `<rskrb5_ng::ccache::kcm::wire::shape::Empty as rskrb5_ng::ccache::kcm::wire::shape::Shape>::decode` | `src/ccache/kcm/wire/shape.rs` | `kcm_reply` |  |
| `<rskrb5_ng::ccache::kcm::wire::shape::KdcOffset as rskrb5_ng::ccache::kcm::wire::shape::Shape>::decode` | `src/ccache/kcm/wire/shape.rs` | `kcm_reply` |  |
| `<rskrb5_ng::ccache::kcm::wire::shape::Name as rskrb5_ng::ccache::kcm::wire::shape::Shape>::decode` | `src/ccache/kcm/wire/shape.rs` | `kcm_reply` |  |
| `<rskrb5_ng::ccache::kcm::wire::shape::OneCredential as rskrb5_ng::ccache::kcm::wire::shape::Shape>::decode` | `src/ccache/kcm/wire/shape.rs` | `kcm_reply` |  |
| `<rskrb5_ng::ccache::kcm::wire::shape::Uuids as rskrb5_ng::ccache::kcm::wire::shape::Shape>::decode` | `src/ccache/kcm/wire/shape.rs` | `kcm_reply` |  |
| `rskrb5_ng::ccache::kcm::wire::shape::decode` | `src/ccache/kcm/wire/shape.rs` | - | the declaration of the `Shape::decode` trait method, which has no body; each implementation has its own row |
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
| `rskrb5_ng::config::load::parse` | `src/config/load.rs` | `krb5_conf` |  |
| `rskrb5_ng::config::load::parse_with_mode` | `src/config/load.rs` | `krb5_conf` |  |
| `rskrb5_ng::config::load::parse_with_roots` | `src/config/load.rs` | `krb5_conf` |  |
| `rskrb5_ng::config::load::parse_with_roots_mode` | `src/config/load.rs` | `krb5_conf` |  |
| `rskrb5_ng::config::include_source::read_include` | `src/config/include_source.rs` | `krb5_conf` |  |
| `rskrb5_ng::config::decode::parse_lines` | `src/config/decode.rs` | `krb5_conf` |  |
| `rskrb5_ng::config::builders::parse_mode` | `src/config/builders.rs` | - | Typed mode accessor, not a parser. |
| `rskrb5_ng::config::profile::Profile::finish` | `src/config/profile.rs` | `krb5_conf` | |
| `rskrb5_ng::config::profile_syntax::State::line` | `src/config/profile_syntax.rs` | `krb5_conf` | |
| `rskrb5_ng::config::profile_syntax::State::finish` | `src/config/profile_syntax.rs` | `krb5_conf` | |
| `rskrb5_ng::config::profile_syntax::quoted` | `src/config/profile_syntax.rs` | `krb5_conf` | |
| `rskrb5_ng::config::profile_syntax::comments` | `src/config/profile_syntax.rs` | `krb5_conf` | |
| `rskrb5_ng::config::hostname::Canonicalization::parse` | `src/config/hostname.rs` | `krb5_conf` | |
| `rskrb5_ng::config::libdefaults::c2::parse` | `src/config/libdefaults/c2.rs` | `krb5_conf` | |
| `rskrb5_ng::config::libdefaults::duration::parse` | `src/config/libdefaults/duration.rs` | `krb5_conf` | |
| `rskrb5_ng::config::realm_values::decode` | `src/config/realm_values.rs` | `krb5_conf` | |
| `rskrb5_ng::config::fork_tests::parse_does_not_read_uid_or_home` | `src/config/fork_tests.rs` | - | unit test, not a parser |
| `rskrb5_ng::config::EnctypeExpr::parse` | `src/config.rs` | `krb5_conf` | |
| `rskrb5_ng::config::enctype_expr::parse` | `src/config/enctype_expr.rs` | `krb5_conf` | |
| `rskrb5_ng::config::enctype_names::Selector::parse` | `src/config/enctype_names.rs` | `krb5_conf` | |
| `rskrb5_ng::config::sections::parse_assignment` | `src/config/sections.rs` | `krb5_conf` |  |
| `rskrb5_ng::config::parse_boolean` | `src/config.rs` | `name_parse` |  |
| `rskrb5_ng::config::values::parse_colon_duration` | `src/config/values.rs` | `krb5_conf` |  |
| `rskrb5_ng::config::parse_duration` | `src/config.rs` | `name_parse` |  |
| `rskrb5_ng::config::values::parse_duration` | `src/config/values.rs` | `name_parse` |  |
| `rskrb5_ng::config::values::parse_boolean` | `src/config/values.rs` | `name_parse` |  |
| `rskrb5_ng::config::decode::parse_i32` | `src/config/decode.rs` | `krb5_conf` |  |
| `rskrb5_ng::config::decode::parse_i32_list` | `src/config/decode.rs` | `krb5_conf` |  |
| `rskrb5_ng::config::decode::parse_ip_addresses` | `src/config/decode.rs` | `krb5_conf` |  |
| `rskrb5_ng::config::parse_supported_enctype_ids` | `src/config.rs` | - | cfg(test)-only capability mapping helper; normal fuzz dependency builds do not contain it; configuration tests cover it |
| `rskrb5_ng::config::values::parse_supported_enctype_ids` | `src/config/values.rs` | - | cfg(test)-only capability mapping helper; normal fuzz dependency builds do not contain it; configuration tests cover it |
| `rskrb5_ng::config::values::parse_unit_duration` | `src/config/values.rs` | `krb5_conf` |  |
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
| `rskrb5_ng::crypto::camellia::cts::decrypt` | `src/crypto/camellia/cts.rs` | `camellia_crypto` |  |
| `rskrb5_ng::crypto::camellia::etype::CtsCmacEtype::decrypt_data` | `src/crypto/camellia/etype.rs` | `camellia_crypto` |  |
| `rskrb5_ng::crypto::camellia::etype::CtsCmacEtype::decrypt_message` | `src/crypto/camellia/etype.rs` | `camellia_crypto` |  |
| `rskrb5_ng::crypto::camellia::etype::CtsCmacEtype::string_to_key` | `src/crypto/camellia/etype.rs` | `camellia_crypto` |  |
| `rskrb5_ng::crypto::camellia::etype::CtsCmacEtype::verify_checksum` | `src/crypto/camellia/etype.rs` | `camellia_crypto` |  |
| `rskrb5_ng::crypto::camellia::kdf::verify` | `src/crypto/camellia/kdf.rs` | `camellia_crypto` |  |
| `rskrb5_ng::der::decode_complete` | `src/der.rs` | `der_oid` |  |
| `rskrb5_ng::der::top_level_der_end` | `src/der.rs` | `der_oid` |  |
| `rskrb5_ng::asn1::decode_length` | `src/asn1.rs` | `auth_message` |  |
| `rskrb5_ng::asn1::read_complete` | `src/asn1.rs` | `auth_message` |  |
| `rskrb5_ng::asn1::read_element` | `src/asn1.rs` | `auth_message` |  |
| `rskrb5_ng::asn1::identifier::read_identifier` | `src/asn1/identifier.rs` | `auth_message` |  |
| `rskrb5_ng::authdata::decode` | `src/authdata.rs` | `auth_message` |  |
| `rskrb5_ng::authdata::decode_and_or` | `src/authdata.rs` | `auth_message` |  |
| `rskrb5_ng::authdata::decode_kdc_issued` | `src/authdata.rs` | `auth_message` |  |
| `rskrb5_ng::messages::forwarding::read_cred` | `src/messages/forwarding.rs` | `auth_message` |  |
| `rskrb5_ng::messages::private_safe::read_priv` | `src/messages/private_safe.rs` | `auth_message` |  |
| `rskrb5_ng::messages::private_safe::read_safe` | `src/messages/private_safe.rs` | `auth_message` |  |
| `rskrb5_ng::messages::private_safe::reading_key` | `src/messages/private_safe.rs` | `auth_message` |  |
| `rskrb5_ng::replay::RcacheName::parse` | `src/replay.rs` | `replay_file` |  |
| `rskrb5_ng::replay::table::parse` | `src/replay/table.rs` | `replay_file` |  |
| `<rskrb5_ng::replay::files::LockedFile as OpenFile>::read_at` | `src/replay/files.rs` | - | the operating-system implementation of the read of the cache file; the fuzz target reads through its own in-memory `OpenFile`, and the table walk behind it is the row `rskrb5_ng::replay::table::parse`; covered by tests/replay_store/concurrency.rs on real files |
| `rskrb5_ng::replay::read_at` | `src/replay.rs` | - | declaration of the `OpenFile` method (no body); the implementations are the row above and the fuzz target's own file |
| `rskrb5_ng::der::trim_zero_padded_der` | `src/der.rs` | `der_oid` |  |
| `rskrb5_ng::discovery::uri::parse` | `src/discovery/uri.rs` | `discovery_uri` |  |
| `rskrb5_ng::discovery::uri::host_port` | `src/discovery/uri.rs` | `discovery_uri` |  |
| `rskrb5_ng::discovery::uri::split_rdata` | `src/discovery/uri.rs` | `discovery_uri` |  |
| `rskrb5_ng::discovery::uri::realm_from_txt` | `src/discovery/uri.rs` | `discovery_uri` |  |
| `rskrb5_ng::extensions::K5Identity::from_bytes` | `src/extensions.rs` | `extensions` |  |
| `rskrb5_ng::extensions::Registry::parse_config` | `src/extensions.rs` | `extensions` |  |
| `rskrb5_ng::extensions::k5identity::parse_line` | `src/extensions/k5identity.rs` | `extensions` |  |
| `rskrb5_ng::extensions::k5identity::parse_principal` | `src/extensions/k5identity.rs` | `extensions` |  |
| `rskrb5_ng::gss::checksum::decode` | `src/gss/checksum.rs` | `gss_context` |  |
| `rskrb5_ng::gss::contexts::TransferBlob::from_bytes` | `src/gss/contexts.rs` | - | stores the received bytes without reading them; `EstablishedContext::import` and `Credential::import` authenticate and decode them (`gss_transfer`) |
| `rskrb5_ng::gss::iakerb::token::Token::decode` | `src/gss/iakerb/token.rs` | `gss_iakerb` |  |
| `rskrb5_ng::gss::name::parse` | `src/gss/name.rs` | `gss_name` |  |
| `rskrb5_ng::gss::negoex::codec::parse_alert` | `src/gss/negoex/codec.rs` | `negoex_message` |  |
| `rskrb5_ng::gss::negoex::codec::parse_exchange` | `src/gss/negoex/codec.rs` | `negoex_message` |  |
| `rskrb5_ng::gss::negoex::codec::parse_message` | `src/gss/negoex/codec.rs` | `negoex_message` |  |
| `rskrb5_ng::gss::negoex::codec::parse_nego` | `src/gss/negoex/codec.rs` | `negoex_message` |  |
| `rskrb5_ng::gss::negoex::codec::parse_verify` | `src/gss/negoex/codec.rs` | `negoex_message` |  |
| `rskrb5_ng::gss::negoex::conversation::Conversation::parse` | `src/gss/negoex/conversation.rs` | `negoex_message` |  |
| `rskrb5_ng::gss::negoex::guid::AuthScheme::from_bytes` | `src/gss/negoex/guid.rs` | `negoex_message` |  |
| `rskrb5_ng::gss::negoex::guid::ConversationId::from_bytes` | `src/gss/negoex/guid.rs` | `negoex_message` |  |
| `rskrb5_ng::file_name::expand_path_tokens` | `src/file_name.rs` | `name_parse` |  |
| `rskrb5_ng::file_name::file_path_from_name` | `src/file_name.rs` | `name_parse` |  |
| `rskrb5_ng::file_name::is_windows_drive_path` | `src/file_name.rs` | `name_parse` |  |
| `rskrb5_ng::file_name::locked::read_all` | `src/file_name/locked.rs` | `ccache_collection` |  |
| `rskrb5_ng::file_name::locked::read_shared` | `src/file_name/locked.rs` | `ccache_collection` |  |
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
| `rskrb5_ng::kadmin::result_text::AdPasswordPolicy::parse` | `src/kadmin/result_text.rs` | `kpasswd_reply` |  |
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
| `rskrb5_ng::pac::AttributesInfo::parse` | `src/pac.rs` | `pac_parse` |  |
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
| `rskrb5_ng::localauth::k5login::lists` | `src/localauth/k5login.rs` | `localauth_k5login` |  |
| `rskrb5_ng::localauth::AuthToLocalRule::parse` | `src/localauth.rs` | `localauth_rule` |  |
| `rskrb5_ng::http::origin::resolve_location` | `src/http/origin.rs` | `http_location` |  |
| `rskrb5_ng::http::sessions::SessionManager::resume` | `src/http/sessions.rs` | `http_session` |  |
| `rskrb5_ng::http::sessions::blob::open` | `src/http/sessions/blob.rs` | `http_session` |  |
| `rskrb5_ng::http::cookies::CookieStore::store_set_cookie` | `src/http/cookies.rs` | `http_set_cookie` |  |
| `rskrb5_ng::pac::Pac::buffer_bytes` | `src/pac.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::Pac::parse` | `src/pac.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::Pac::parse_and_process` | `src/pac.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::Pac::process_buffers` | `src/pac.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::Pac::verify` | `src/pac.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::Pac::verify_server_checksum` | `src/pac.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::Request::decode_der` | `src/pac.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::RequestorSid::parse` | `src/pac.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::S4UDelegationInfo::parse` | `src/pac.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::SignatureData::parse` | `src/pac.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::UpnDnsInfo::parse` | `src/pac.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::find_pac_in_authorization_data` | `src/pac.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::authorization::find` | `src/pac/authorization.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::ndr::RpcUnicodeStringDescriptor::read` | `src/pac/ndr.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::ndr::ensure_zero_trailing` | `src/pac/ndr.rs` | `pac_parse` |  |
| `rskrb5_ng::pac::ndr::ndr_len` | `src/pac/ndr.rs` | `pac_parse` |  |
| `rskrb5_ng::preauth::pkinit::chain::parse` | `src/preauth/pkinit/chain.rs` | `pkinit_reply` |  |
| `rskrb5_ng::preauth::pkinit::chain::parse_crls` | `src/preauth/pkinit/chain.rs` | `pkinit_reply` |  |
| `rskrb5_ng::preauth::pkinit::config::read` | `src/preauth/pkinit/config.rs` | - | reads a bounded local file named by the profile (`pkinit_identities`, `pkinit_anchors`, `pkinit_pool`, `pkinit_revoke`); its PEM content is decoded by `keys::pem_certificates`, whose certificates are re-parsed by `chain::parse` in `pkinit_reply` |
| `rskrb5_ng::preauth::spake::Message::decode` | `src/preauth/spake.rs` | `spake_message` |  |
| `rskrb5_ng::routing::s4u::PaS4uX509User::decode_der` | `src/routing/s4u.rs` | `routing_transit` |  |
| `rskrb5_ng::routing::transited::decode` | `src/routing/transited.rs` | `routing_transit` |  |
| `rskrb5_ng::transport::kkdcp::ProxyMessage::decode` | `src/transport/kkdcp.rs` | `kkdcp_message` |  |
| `rskrb5_ng::transport::kkdcp::decode_reply` | `src/transport/kkdcp.rs` | `kkdcp_message` |  |
| `rskrb5_ng::transport::proxy::Url::parse` | `src/transport/proxy.rs` | `kkdcp_message` |  |
| `rskrb5_ng::preauth::spake::wire::decode` | `src/preauth/spake/wire.rs` | `spake_message` |  |
| `rskrb5_ng::preauth::otp::Challenge::decode` | `src/preauth/otp.rs` | `otp_challenge` |  |
| `rskrb5_ng::preauth::otp::challenge::decode` | `src/preauth/otp/challenge.rs` | `otp_challenge` |  |
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
| `rskrb5_ng::preauth::encrypted_challenge::EncryptedChallenge::verify_reply` | `src/preauth/encrypted_challenge.rs` | - | decrypts the KDC's challenge only in the final round after the client's own challenge, which a one-reply fuzz exchange never reaches; its rejections (missing, repeated, wrong key) are the tamper and vector tests of `tests/fast.rs` |
| `rskrb5_ng::preauth::fast::armor::decode_request` | `src/preauth/fast/armor.rs` | `fast_reply` |  |
| `rskrb5_ng::preauth::fast::keys::decode` | `src/preauth/fast/keys.rs` | `fast_reply` |  |
| `rskrb5_ng::preauth::fast::keys::open` | `src/preauth/fast/keys.rs` | `fast_reply` |  |
| `rskrb5_ng::preauth::fast::reply::error_reply` | `src/preauth/fast/reply.rs` | `fast_reply` |  |
| `rskrb5_ng::preauth::fast::reply::fast_response` | `src/preauth/fast/reply.rs` | `fast_reply` |  |
| `rskrb5_ng::preauth::fast::reply::unwrap` | `src/preauth/fast/reply.rs` | `fast_reply` |  |
| `rskrb5_ng::secure_env::parse_auxv` | `src/secure_env.rs` | - | reads this process's auxiliary vector, which the kernel writes (`/proc/self/auxv`), not bytes an attacker supplies; a malformed vector is restricted (fail closed); covered by `auxv_fixtures_decide_without_the_os` (AT_SECURE 0, 1, absent, truncated) |
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
| `rskrb5_ng::spnego::gss_contexts::decode` | `src/spnego/gss_contexts.rs` | `gss_context` |  |
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
| `rskrb5_ng::kadm5::name::parse` | `src/kadm5/name.rs` | `kadm5_reply` |  |
| `rskrb5_ng::kadm5::response::Response::decode` | `src/kadm5/response.rs` | - | Public wrapper of `kadm5::wire::decode_response`, which `kadm5_reply` covers; it parses nothing itself. |
| `rskrb5_ng::kadm5::wire::decode_key_data` | `src/kadm5/wire.rs` | `kadm5_reply` |  |
| `rskrb5_ng::kadm5::wire::decode_keys` | `src/kadm5/wire.rs` | `kadm5_reply` |  |
| `rskrb5_ng::kadm5::wire::decode_names` | `src/kadm5/wire.rs` | `kadm5_reply` |  |
| `rskrb5_ng::kadm5::wire::decode_policy_record` | `src/kadm5/wire.rs` | `kadm5_reply` |  |
| `rskrb5_ng::kadm5::wire::decode_principal` | `src/kadm5/wire.rs` | `kadm5_reply` |  |
| `rskrb5_ng::kadm5::wire::decode_principal_record` | `src/kadm5/wire.rs` | `kadm5_reply` |  |
| `rskrb5_ng::kadm5::wire::decode_response` | `src/kadm5/wire.rs` | `kadm5_reply` |  |
| `rskrb5_ng::kadm5::wire::decode_strings` | `src/kadm5/wire.rs` | `kadm5_reply` |  |
| `rskrb5_ng::kadm5::wire::decode_tl_data` | `src/kadm5/wire.rs` | `kadm5_reply` |  |
| `rskrb5_ng::rpcsec_gss::message::decode_reply` | `src/rpcsec_gss/message.rs` | `kadm5_reply` |  |
| `rskrb5_ng::rpcsec_gss::record::decode` | `src/rpcsec_gss/record.rs` | `kadm5_reply` |  |
| `rskrb5_ng::rpcsec_gss::record::read` | `src/rpcsec_gss/record.rs` | - | The record reader of a live kadmind connection: each fragment header passes `fragment`, the header and total-size bound `record::decode` shares (covered by `kadm5_reply`), before its body is read, and the reader stops after 16,384 fragments. |
| `rskrb5_ng::rpcsec_gss::types::Reply::decode` | `src/rpcsec_gss/types.rs` | - | Public wrapper of `rpcsec_gss::message::decode_reply`, which `kadm5_reply` covers; it parses nothing itself. |
| `rskrb5_ng::rpcsec_gss::types::decode_record` | `src/rpcsec_gss/types.rs` | - | Public wrapper of `rpcsec_gss::record::decode`, which `kadm5_reply` covers; it parses nothing itself. |

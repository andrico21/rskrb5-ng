# Changelog

## [0.3.0] - unreleased

The first release as `rskrb5-ng` (library `rskrb5_ng`), which continues
`rskrb5` independently from upstream `clelange/rskrb5` `main` at `6f4abc9`.
Changes are listed against `rskrb5-patched` 0.2.2, the last published
version; they include everything prepared for an `rskrb5-patched` 0.3.0 that
was never published. Upgrade steps, with every renamed path and changed
signature, are in
[`docs/migration-from-rskrb5-patched.md`](docs/migration-from-rskrb5-patched.md);
the lineage is in [`PROVENANCE.md`](PROVENANCE.md).

### Crate, library and repository

- The package is `rskrb5-ng` (was `rskrb5-patched`) and the library
  `rskrb5_ng` (was `rskrb5`): depend on `rskrb5-ng = "0.3"` and replace
  `use rskrb5::` with `use rskrb5_ng::`.
- The compatibility-report binary is `rskrb5-ng-compat-report` and the fuzz
  crate `rskrb5-ng-fuzz`.
- The repository is `https://github.com/andrico21/rskrb5-ng`, a standalone
  repository (the old `andrico21/rskrb5` URL redirects there).

### API

- `KerbValidationInfo::user_session_key` is now an owning, redacted
  `pac::session_key::SessionKey`; raw PAC buffers use `Zeroizing<Vec<u8>>`.
  Debug no longer exposes key-bearing PAC bytes, and parsing erases key staging
  on success or later failure (FU-PAC-R06).

- `Rc4HmacEtype::random_to_key` now returns `Result<Vec<u8>, error::Crypto>`:
  exactly sixteen random bytes are preserved, not MD4-hashed; other lengths
  return `InvalidKeyLength` (FU-CRY-R01). Password string-to-key is unchanged.

- Client request DER, FAST AP-REQ bytes and session tickets now use
  `Zeroizing<Vec<u8>>`; owning constructors require that owner. Client request
  and session `Debug` expose metadata and lengths, never credential bytes
  (FU-CLI-R02).

- Add opt-in `service::TransitPolicy::{direct, domain_x500_paths}` presets for
  AD cross-domain tickets without TRANSITED-POLICY-CHECKED. Both pin endpoint
  realms; the latter allow-lists exact complete encoded paths. Default rejection
  and rejection of unknown encodings remain unchanged (RSK-3E3C2278).

- Kpasswd preserves definite pre-send errors and reports possible-delivery
  failures as `Client::KpasswdOutcomeUnknown` exactly once, including malformed
  replies. Connection refusal is safely retryable; unknown outcomes are not
  (RSK-14E2755A).

These are breaking; the migration guide maps each one.

- Public structs and enums are `#[non_exhaustive]` and gain constructors or
  `with_*` builders; struct literals no longer compile outside the crate.
- The module-local error types move into the new `error` module
  (`client::Error` is `error::Client`, the crate-level `Error` is
  `error::Any`, and so on); the old paths are private.
- Module-repeating names are dropped (`ap_req::build_ap_req` is
  `ap_req::build`, `service::ServiceValidator` is `service::Validator`,
  `client::TokioClient` is `client::Tokio`), and items move to new public
  modules (`client::{kpasswd, negotiate, options, principal, transport}`,
  `spnego::oid`, `evaluation::data`). The crate-root re-exports `Principal`,
  `TokioClient`, `NegotiateClient`, `BlockingNegotiateClient`, `Config` and
  `ServiceValidator` keep their names.
- `config::LibDefaults` stores enctype names only:
  `default_tkt_enctype_ids`, `default_tgs_enctype_ids` and
  `permitted_enctype_ids` are methods that derive the ids; update the
  `*_enctypes` name lists directly or through `with_*_enctypes` builders. Its
  thirteen boolean options use `config::Toggle`, and the new `allow_rc4` and
  `allow_des3` options join them.
- `config::Realm::realm` is `name`. Several functions borrow their option
  structs, group arguments into parameter structs
  (`client::TgsRequestParts`, `kadmin::PasswordEncryption`) or become
  associated functions; argument-position `impl Trait` becomes a named
  generic; many functions gain `#[must_use]` or become `const fn`.
- New error variants, among them `error::Client::{EnctypeNotRequested,
  EnctypeNotPermitted, KpasswdOutcomeUnknown, UdpResponseTooLarge,
  DnsServiceUnavailable}`, `error::Config::EnctypeNotPermitted`,
  `error::Kadmin::UnauthenticatedSuccess`,
  `error::Ccache::IdentityUnavailable` and
  `http::NegotiateHttpError::MutualAuthenticationNotProven`. The variants
  added by the follow-up review are listed under "Changes from the follow-up
  review" below.
  `http::NegotiateHttpError<E>` becomes `NegotiateHttpError<E, B>`, where `B`
  is the response body type the new variant carries.
- New public fields: `LibDefaults.permitted_enctypes_explicit` and
  `InitiatorContext.context_flags`.

### Dependencies and toolchain

- `rust-version` is 1.99 (was 1.88).
- Every direct dependency is on its latest major version: `base64` 0.23,
  `getrandom` 0.4, `rasn` and `rasn-kerberos` 0.29, `compcol` 0.7,
  `picky-krb` 0.13 (optional, `evaluation`), dev `toml` 1.1, and `pbkdf2`
  0.13 instead of the `=0.13.0-rc.10` pre-release pin. `proptest` is a new
  dev-dependency. No runtime dependency was added.

### Behaviour changes

- Quoted profile values preserve leading/trailing whitespace after escape
  decoding, including credential names and appdefaults (FU-CFG-R02).

- `no_addresses` and `noaddresses` now share first-occurrence precedence and
  final markers instead of overwriting by lexical spelling (FU-CFG-R01).

- PAC NDR arrays validate aligned descriptor/element extent before reserving
  from peer counts, preventing large allocations for truncated inputs
  (FU-PAC-R05).

- Nonempty PAC RPC strings with null pointers now return `MissingNdrPointer`
  instead of silently becoming empty strings (FU-PAC-R04).

- PAC parsing rejects nonzero format versions with `Pac::InvalidPacVersion`
  before allocating the buffer table (FU-PAC-R02).

- AP authenticators, tickets, KDC replies and KRB-PRIV now reject authenticated
  trailing zero bytes unless they are DES3 padding shorter than eight bytes
  (FU-MSG-R01).

- Direct AS reply processing enforces the offered reply encryption type before
  decryption, independently of the session-key type (`EnctypeNotRequested`,
  FU-CLI-R07); TGS reply wrapping is unchanged.

- Cached/imported sessions and AP construction reject service metadata that
  disagrees with the encoded ticket's realm or ordered components
  (`ServicePrincipalMismatch`, FU-CLI-R06).

- Keytab diagnostics count only keys for the client's realm and ordered name
  components, ignoring advisory name type; other users' keys no longer hide
  missing credentials (FU-CLI-R05).

- Complete PA/TGS/AP authenticator builders reject fractional explicit seconds
  and microseconds above 999999 before encryption (`Client::Encode`, FU-CLI-R03).

- Ccache parsing bounds every record count (principal components, addresses,
  authorization data) against the remaining input before reserving memory, so
  a short malformed cache returns `error::Ccache::Truncated` instead of
  aborting the process on a multi-GB allocation.
- kpasswd: a success result is accepted only with authenticated provenance. An
  unsigned KRB-ERROR reply carrying result code 0 is rejected with
  `error::Kadmin::UnauthenticatedSuccess`, and the high-level client keeps
  its stored password; non-zero error results keep their
  `PasswordChangeFailed` behaviour.
- `[libdefaults] permitted_enctypes` is an enctype allowlist when it's set
  explicitly: request lists are narrowed to it and the config-driven AS/TGS
  exchanges reject a session key outside it
  (`error::Client::EnctypeNotPermitted`). An explicit `default_tkt_enctypes`
  or `default_tgs_enctypes` naming an enctype outside an explicit allowlist is
  a parse error (`error::Config::EnctypeNotPermitted`) rather than a silent
  narrowing, checked once on the final values across included files. The
  explicit flag (`LibDefaults.permitted_enctypes_explicit`) survives a serde
  round-trip.
- An explicit allowlist fails closed instead of meaning "no policy": a
  `permitted_enctypes` naming an unknown or disabled enctype is a parse error
  naming it, one that resolves to nothing is
  `error::Config::EmptyEnctypeExpression`, and an empty permitted list cannot
  build a crypto policy (FU-CFG-04 below).
- MIT's DES3 names `des3-cbc-sha1` and `des3-hmac-sha1` resolve to enctype 16
  like `des3-cbc-sha1-kd`, so an explicit list using them is honoured (subject
  to `allow_des3`, below) instead of silently dropping DES3.
- AS and TGS replies are bound to the requested enctype list: the AS-REP reply
  key enctype and the AS/TGS session-key enctype must appear in the request's
  `etype` list, otherwise `error::Client::EnctypeNotRequested`.
- The TGT refresh band is measured from the current ticket life
  (`end_time - start_time`) instead of `auth_time`, so a just-renewed TGT is no
  longer immediately due.
- Auto-renewal waits `retry_delay` when a refresh fails or leaves the TGT
  unchanged, so a due, non-renewable, cache-only TGT no longer spins a core.
- Automatic paths (`affirm_login`, `refresh_tgt_if_needed`,
  `get_service_ticket`, auto-renewal) recover through an AS exchange when the
  cached TGT has expired or its renewal is refused and a password or keytab is
  configured. Cache-only clients keep the renewal error.
- Host-based service principals fold the DNS host component to lower case
  (RFC 4120 section 6.2.1), so host-case variants name one SPN and share one
  cached service ticket. Service names, realms and `Principal::parse_service`
  keep their case.
- `[libdefaults] clockskew` reaches the `Config`-driven acceptors
  (`service::Validator::from_default_keytab_name`/`from_default_keytab`,
  `NegotiateLayer::from_default_keytab_name`/`from_default_keytab`). The plain
  constructors keep the 300 s default.
- `[domain_realm]` lookups fold the DNS name to lower case (realm values stay
  case-sensitive).
- A bare `[domain_realm]` tag covers its subdomains, as MIT krb5.conf(5)
  defines; at each suffix level the leading-dot tag wins over the bare one.
- Mutual authentication fails closed. The classifier treats a completion
  without an AP-REP as `InvalidToken` when the `mutual-required` AP option or
  `CONTEXT_FLAG_MUTUAL` was requested, and the send wrappers return
  `NegotiateHttpError::MutualAuthenticationNotProven` unless the final
  response carries an AP-REP that verifies against the initiator context.
  Callers that don't request mutual authentication see no change.
- The AP-REQ replay cache also indexes a digest of the authenticator
  ciphertext, so an authenticator re-presented under a rewritten cleartext
  ticket `sname` (for example a keytab alias sharing the service key) is
  rejected (clelange/rskrb5 PR #20, updated).

#### From the review backlog

Each fixed review item with an observable behaviour change, by area. The
dispositions, tests and commits are indexed in `docs/review/README.md`.

SPNEGO, GSS tokens, DER and OIDs:

- OIDs under arc 2 encode, decode and round-trip for every valid `u32` arc;
  a malformed first subidentifier is `InvalidOidEncoding` (RSK-7487E947).
- DER state values and OID arcs that overflow are rejected instead of
  truncated, and so are redundant integer sign octets and non-minimal arcs
  (RSK-2A2C1928).
- Initiation that requests delegation (DELEG) without a credential fails with
  `DelegationRequiresCredential`; the raw checksum helper no longer fabricates
  delegation fields (RSK-622F4664).
- Sealed DES3 Wrap tokens round-trip for payloads of every length, and an
  EC overflow is rejected (RSK-2A906A3A).
- Unsealed Wrap tokens apply the right-rotation count (RRC) on encode and
  decode (RFC 4121 §4.2.5) (RSK-84FA90AE).
- The SPNEGO acceptor accepts an optimistic token for any offered standard or
  Microsoft Kerberos OID. Both OIDs are one mechanism for first-choice selection:
  Windows SSPI MS-KRB5-first / standard-inner AP-REQs work without mechListMIC.
  Only a non-Kerberos first preference requires a valid mechListMIC;
  supplied first-choice MICs also verify before replay insertion. Replies select
  the first offered Kerberos OID in `supportedMech`, preserving the token OID in
  AP-REP `thisMech` through the additive `AcceptedContext::token_mechanism` field
  (MIT/MS-SPNG behavior). Replies include a reciprocal MIC over the received list when
  one was verified, retained in `AcceptedContext::mech_types_der`. Only RFC 4121
  MIC tokens with AES session enctypes are supported for mechListMIC; RFC 4757
  RC4 and RFC 1964 DES3 MIC formats fail closed as `InvalidMechListMic`.
  Missing or invalid MICs fail closed (`MissingMechListMic`,
  `InvalidMechListMic`); stateless continuations remain `NegotiationRequiresState`
  (RFC 4178 §§4-5, RFC 4121 §2) (RSK-C4BE57A0, F2 M1).
- GSS acceptance checks the RFC 4121 §4.1.1 authenticator checksum type and
  framing and requires a sequence number before replay insertion
  (RSK-FAF64A85, run-2 lead `mandatory-gss-authenticator-fields`).
- A Negotiate header longer than 65,536 bytes is rejected with
  `NegotiateHeaderTooLong` before base64 decoding (upstream issue #9).

Service acceptor and HTTP layer:

- The Axum example sets the overlay's security response headers and removes
  `Server`, `X-Powered-By` and the ASP.NET fingerprint headers on every status
  (overlay deviation 8).
- Nonzero fractional seconds in ticket times, the authenticator `ctime` and
  AP-REP construction or verification are rejected with
  `Service::FractionalKerberosTime` (RFC 4120 §5.2.3) (RSK-B161A328).
- Authenticator and AP-REP microseconds outside 0..=999999 are rejected
  (RSK-985742B6).
- Replay caches own their skew and capacity (300 s and 65,536 records by
  default), expire entries automatically, reject a wider shared skew and a
  clock rollback larger than the configured maximum skew, tolerate smaller or
  equal backward steps without lowering the high-water mark, and fail closed
  on replay even after a tolerated rollback. Retention is three times the skew
  from each record's last-seen watermark; records admitted from a stepped-back
  sample are stamped at the watermark, so they never expire before earlier
  records. A replay refreshes the matched replay key and authenticator digest
  together without accepting it, and both expire together, so a rewritten-sname
  replay cannot keep a digest alive past its key record.
  The default retention is 900 seconds; capacity planning needs 1.5 times the
  previous two-skew window. Caches fail closed when full (RSK-7D80FA41, run-2
  lead `ReplayCache:indefinite-entry-retention`).
- Ticket and authenticator authorization data are validated before success:
  unknown critical elements and unsupported AD-KDCIssued or AD-AND-OR are
  rejected, within eight wrappers and 1 MiB of decoded payload (RFC 4120
  §5.2.6) (RSK-D1D6BDC3, run-2 lead `mandatory-authorization-data-discarded`).
- A cross-realm ticket without TRANSITED-POLICY-CHECKED is rejected unless a
  caller-supplied `TransitValidator` accepts its path (RFC 4120 §§2.7,
  3.3.3.2) (RSK-3E3C2278, run-2 lead `unchecked-cross-realm-transit`).
- Tickets with `tkt-vno` other than 5 and authenticators with
  `authenticator-vno` other than 5 are rejected (RSK-39F18D3B).

Cryptography and key derivation:

- RC4-HMAC encodes key usages as four-byte little-endian (RFC 4757 §3), so
  high usages no longer alias (RSK-11BF294C).
- The AES-SHA2 PRF accepts an empty input string (RFC 8009) (RSK-FA2BF25E).
- AES string-to-key and password reply-key derivation reject iteration counts
  above 2^24 with `Crypto::IterationCountTooHigh` before running PBKDF2
  (RSK-F240C18F, run-2 lead
  `s2kparams_to_iterations:unauthenticated-pbkdf2-work`).
- AES-SHA2 decryption verifies the HMAC before decrypting (RFC 8009 §5)
  (RSK-CE4ACA12).
- AES-SHA1 and DES3 key derivation reject constants longer than the cipher
  block with `Crypto::DerivationConstantTooLong` (RSK-8F3B02EE).
- Key-derived scratch buffers are zeroized: password encodings, PBKDF2 and
  DR intermediates, derived keys, decrypted buffers and HMAC key blocks
  (RSK-DEF6C438, upstream issue #6).

PAC and NDR:

- PAC lookup in authorization data stops at eight wrappers and 1 MiB of
  visited payload (RSK-6DF06BE8, run-2 lead
  `pac.authorization-data.unbounded-if-relevant-recursion`).
- Claims decompression has an independent 1 MiB output ceiling
  (RSK-B5912AE2, run-2 lead `pac.claims-decompression.peer-controlled-cap`).
- Credential counts (at most 1,000,000) are checked against the remaining
  input before reserving memory (RSK-A9B8B032, run-2 lead
  `pac.ndr.supplemental-credentials-unbounded-capacity`).
- PAC_CREDENTIAL_DATA parsing consumes and checks the NDR conformant count
  (MS-PAC 2.6.2) (RSK-DB101DC5).
- NTLM supplemental credentials use the validity masks 1 and 2 and reject a
  record with neither (MS-PAC 2.6.4) (RSK-8BA3D269).
- Both fixed NTLM hash slots are consumed whatever the validity flags say
  (RSK-59B45280).
- Boolean claims decode as aligned 64-bit values and reject values other than
  0 and 1 (RSK-8E17F182).
- Decrypted PAC credentials are zeroized and print redacted (RSK-5E15962F).
- The NDR private-header object length must equal the object extent
  (RSK-6A286805).
- SID summaries deduplicate with a set and keep first-seen order
  (RSK-D33671B2).

Client AS/TGS exchanges, renewal and caches:

- TGS authenticators carry the client realm, not the ticket issuer realm
  (RFC 4120 §5.5.1) (RSK-AFE184E0).
- Password and keytab preauthentication retries echo the latest PA-FX-COOKIE
  (RFC 6113 §5.2) (RSK-34601373).
- Initial password AS replies use the reply's ETYPE-INFO2, ETYPE-INFO or
  PW-SALT salt and parameters (RSK-072A268D).
- AS request-integrity checks no longer require FAST to be advertised
  (RFC 6806 §11) (RSK-2099CE19).
- TGS replies are checked for the negotiated request checksum (RFC 6806 §11)
  (RSK-BC016031).
- An explicit login always replaces the primary TGT and clears dependent
  service tickets (RSK-F526D18D).
- Tickets with the INVALID flag are not used and not renewed in place of
  validation (RSK-E48DA39B).
- Service-ticket cache keys keep realm and component boundaries
  (RSK-1922A31B).
- Unarmored AS requests no longer set the canonicalize option (RFC 6806 §6)
  (RSK-45397760).
- S4U2Self and S4U2Proxy bind the delegated client to the decrypted ticket
  and the request; a missing service key fails with `DelegationKeyRequired`,
  a mismatch with `DelegationPrincipalMismatch` (run-2 lead
  `s4u-delegation:delegated-client-unbound-to-ticket-payload`).

kpasswd, KRB-PRIV/KRB-SAFE messages and secrets:

- KRB-SAFE checksums are generated and verified over the whole DER KRB-SAFE
  with an empty checksum placeholder (RFC 4120 §5.6.1), not over the body
  only (RSK-A5F7D975).
- Bare RFC 3244 KRB-ERROR replies to kpasswd are accepted and keep their
  encoding; they never count as success (RSK-3B6BA222).
- The kpasswd result checks the KRB-PRIV sequence number or timestamp (within
  300 s), microseconds and sender addresses (RSK-789A6FBB).
- Whole-message decoders (AP, KDC, ticket and KRB messages) reject trailing
  bytes, and kpasswd frames must match their declared length
  (RSK-0C0007B7).
- Microsecond and whole-second KerberosTime limits apply to KRB-ERROR
  diagnostics, kpasswd request values and kpasswd AP-REP times
  (RSK-6A673A85).
- Password plaintext copies are zeroized and print redacted (RSK-471362A3,
  upstream issue #1).
- A kpasswd exchange that fails after the request may have been delivered
  returns `Client::KpasswdOutcomeUnknown` (RSK-14E2755A, upstream issue #8).

Transport, DNS, IPv6, SRV and kpasswd retry:

- Bare IPv6 literals keep their full address and the default port; an IPv6
  port needs brackets (RSK-03EDCC7E).
- The admin-server fallback for kpasswd keeps IPv6 hosts and uses port 464
  (RSK-3F13B5FE).
- UDP transport reaches IPv6-only endpoints (RSK-0D8D7D97).
- An oversized UDP datagram is `Client::UdpResponseTooLarge`, never a
  truncated success (RSK-484961E9).
- The transport no longer reads `RSKRB5_DNS_SERVER`; set a DNS server with
  `Tokio::with_dns_server` (ambient input `RSKRB5_DNS_SERVER`).
- DNS admin-server fallback for kpasswd uses port 464 (RSK-4AD555A5).
- An SRV record with target `.` returns `Client::DnsServiceUnavailable` and
  stops the fallback (RSK-DF8D47BE).
- DNS resolution keeps every address of each SRV target (RSK-521F824C).
- SRV weights select targets by probability within a priority (RFC 2782)
  (RSK-DBD57F3E).
- KDC TCP framing uses 31-bit lengths and rejects the reserved high bit
  (RFC 4120 §7.2.2); kpasswd framing is unchanged (RSK-351DC798).
- kpasswd never retries on another endpoint or protocol once the request may
  have been delivered; it returns `Client::KpasswdOutcomeUnknown`
  (RSK-4DB854C8, upstream issue #7, run-2 lead
  `send_to_endpoints/post-send-mutation-retry`).

Config and enctype policy:

- Repeated `[realms]` sections, path lists and includes merge per realm the
  way MIT does, so configured KDCs no longer fall back to DNS (RSK-40161D92,
  run-2 lead `apply_section/realms-replacement-dns-fallback`).
- Enctype names are the only stored policy; the wire ids are derived through
  methods, and an empty request list fails closed (RSK-77250646, upstream
  issue #4).
- Explicit enctype lists never fall back to defaults or an empty policy
  (RSK-45AC5D3A); since FU-CFG-04 and FU-CFG-05 (below) they are MIT list
  expressions that fail closed by token.
- The default enctypes are AES only. RC4 and DES3 need the
  `[libdefaults]` flags `allow_rc4` and `allow_des3` (both false by
  default), and a disabled explicit entry is an error naming it. Export RC4
  is refused permanently (RSK-5ECE9681, run-2 lead
  `DEFAULT_ENCTYPES/deprecated-rc4-default`, upstream issue #3).
- `LibDefaults::new()` reads no environment; `LibDefaults::from_env()` reads
  `HOME`. The default client keytab keeps the `%{euid}` template and
  `k5login_directory` defaults to empty (upstream issue #10, project rule
  (13)).

Ccache, keytab and credential files:

- Ccache upsert replaces a record with the same principal regardless of the
  name type (RSK-7F30E854).
- Serde rejects ccache versions outside 1-4 (RSK-01B7A90E).
- Keytab serialization rejects counts, strings, keys and enctypes the parser
  would reject (RSK-98FEE876).
- `%{uid}` and `%{euid}` come from `/proc/self/status` on Linux and never from
  the environment. **On macOS, Windows and other platforms these tokens now
  fail with `IdentityUnavailable`** (RSK-DC80DC52, run-2 lead
  `file-name/uid-token-environment-substitution`).
- Credential files are saved with mode 0600 on Unix, through a new file and
  a rename, and existing permissions are never widened. Unix saves also sync
  the parent directory after replacement; cleanup failures preserve the
  original write/rename/sync error (RSK-DF3180A2, run-2
  lead `credential-file/save/inherited-permissions`).
- Saves reject a symlinked destination file, and DIR primary initialization
  rejects a symlink; parent-directory symlinks still work (RSK-58A6D5DD, run-2
  lead `credential-file/path-write/followed-symlink`).
- File read buffers, save buffers and partial serializer output holding key
  material are zeroized (RSK-361F35CC).

Release workflow, CI docs and fixture scripts:

- Publishing runs only in the `release` environment (required reviewer), for
  a release tag on a commit that is an ancestor of `main` (run-2 lead
  `release.publish.crates-io-token.unprotected-tag-authorization`); the
  workflow split and the `N.N.N` tags are under FU-CI-06 below.
  `CARGO_REGISTRY_TOKEN` is an environment secret of `release` only (moved by
  the owner on 2026-10-29, FU-OPS-01).
- `scripts/check-github-ad-gate.py --dispatch` refuses to dispatch inputs the
  CI workflow does not declare, and the parity manifest names the fork CI job
  for each gate (RSK-E0AFE152).
- The gated-integration runner writes its environment file with mode 0600 in
  a private directory and prints keytab values as `<redacted>`;
  `RSKRB5_INTEGRATION_ENV_FILE` is replaced by `RSKRB5_INTEGRATION_ENV_DIR`
  (RSK-A8D595D8).

#### Changes from the follow-up review

Each fixed row of the follow-up review of `6586b7a` with a behaviour or API
change, by area, with its register ID. The proofs and commits are in
`docs/review/followup-6586b7a.md`, and the migration guide's "Follow-up review
changes" section shows each API change. Where a bullet here changes an earlier
bullet of this section, this one describes 0.3.0.

Security fail-closed parsing and verification:

- SPNEGO sequences with duplicate or reordered known fields fail with the new
  `Spnego::InvalidFieldOrder`; legal omissions are still accepted (FU-SPN-03).
- Unknown constructed SPNEGO context fields `[4]` to `[30]` are skipped after
  their framing is validated, instead of being rejected (FU-SPN-04).
- DER lengths in non-minimal long form fail with the new
  `Spnego::NonminimalLength` (FU-SPN-05).
- `WrapToken::encrypt_payload_with_confounder` leaves the token unchanged when
  encryption fails (FU-SPN-R02).
- `MicToken::verify` and `WrapToken::verify` return `Result<(), Spnego>`
  instead of a `bool` that was never `false` (FU-SPN-R04).
- `Spnego::Client` keeps the typed `Box<Client>` cause instead of a string
  (FU-SPN-R03).
- Mutual authentication requested through a combined context-flag mask needs a
  verified AP-REP, exactly as the split masks do, in the async and blocking
  wrappers and the response classification (FU-HTTP-03).
- The Negotiate client requires accept-completed and an offered
  `supportedMech`, and verifies a supplied mechListMIC against the offer, the
  acceptor sequence and the selected context key; `InitiatorContext` gains a
  redacted `initiator_subkey` (FU-HTTP-05).
- The Axum example builds the AP-REP and its header before calling the
  handler; a failure is an opaque hardened 500 (FU-HTTP-01). It loads the
  keytab with `Keytab::load_name`, so `WRFILE:` works and the keytab bytes are
  zeroized (FU-HTTP-R01).
- Generated `Authorization`/`WWW-Authenticate: Negotiate` values and forwarded
  incoming `Authorization` values are marked sensitive (FU-HTTP-02).
- Responses generated by the HTTP layer carry twelve hardening headers; the
  layer fills missing defaults on inner responses and strips fingerprints
  unless `with_response_hardening(false)` (FU-HTTP-04).
- `NegotiateFuture` is a public concrete future that is `Send` when the inner
  future, body and error are (FU-HTTP-06).
- `NegotiateService` maps replay-cache, keytab I/O and poisoned-validator
  faults to an opaque hardened 500 with the cause as an `Arc<Http>` response
  extension; authentication failures stay 401 (FU-HTTP-R02).
- `NegotiateService` is `Clone`; clones share the validator and replay state
  (FU-HTTP-R03).
- AP-REP and KRB-CRED accept DES3 zero padding below eight bytes; other
  padding stays strict (FU-MSG-02).
- KRB-CRED import rejects fractional ticket times with `TimeOutOfRange`
  instead of truncating them (FU-MSG-03).
- The complete KRB-PRIV builders reject fractional times and microseconds
  outside 0..=999999 (FU-MSG-04).
- The named KRB-ERROR and PA-* decoders reject trailing bytes (FU-MSG-05).
- KerberosTime conversion to `SystemTime` is whole-second and checked:
  `client::build_ap_req_with_confounder` rejects a fractional timestamp with
  `Client::Encode` (FU-API-06).
- PAC checksum type `0xffffff76` maps to HMAC-MD5 (`-138`) (FU-PAC-01).
- Ccache versions before 4 with nonempty headers, and version-1 principals
  with a nonzero name type, fail to serialize instead of losing data
  (FU-FIL-01).
- A DIR cache publishes a missing primary file only after the cache is saved,
  through a synced private stage that is hard-linked without replacing a
  concurrent winner (FU-FIL-03; the register row is still open).
- A 1-3 byte keytab entry-size fragment is `Truncated`, not end of file
  (FU-FIL-04).
- Opaque negative keytab enctype IDs serialize unchanged (FU-FIL-05).
- `keytab::Entry::new` applies the 8-bit kvno fallback immediately and is no
  longer `const`; serialization rejects a zero kvno with a nonzero kvno8
  (FU-FIL-06).

Passwords and secret ownership:

- Password APIs take `client::Password` (alias of `client::password::Secret`)
  by value: the `change_password*` methods of `client::Tokio`,
  `NegotiateClient` and `BlockingNegotiateClient`, and
  `ChangePasswdData::new`/`for_target`. The password is erased on completion,
  error and cancellation (FU-CLI-07).
- `ChangePasswdData::new_passwd` is a redacted zeroizing
  `kadmin::password::Bytes`, and the request builders encode into zeroizing
  buffers (FU-TRN-14).
- MIC and Wrap payloads are owned as `Zeroizing<Vec<u8>>`, and their `Debug`
  is redacted (FU-SPN-01).
- `InitiatorContext` and the HTTP results print metadata and lengths, never the
  `Authorization` token; the quick start no longer logs it (FU-SPN-02).
- AP-REQ, AP-REP, KDC-reply, KRB-CRED and ticket DER staging and decrypted DER
  are erased on drop (FU-MSG-01).
- The checked kpasswd result helpers take the `BuiltKpasswdRequest` and its
  `RequestOptions`, authenticate the AP-REP, use the server subkey and check
  freshness, sequence, addresses and reflection (FU-TRN-10).
- A reply that reflects the request KRB-PRIV is rejected before any password
  bytes are parsed and reported as an unknown outcome (FU-TRN-02).
- An unsigned refusal after delivery is
  `KpasswdOutcomeUnknown(Kadmin::UnauthenticatedRejection { code, text_raw })`,
  not a definite failure (FU-TRN-03).
- Decrypt and validation failures after delivery are wrapped in
  `KpasswdOutcomeUnknown` exactly once (FU-TRN-11).
- A fractional local request time or `cusec` of 1,000,000 or more is
  `Client::Encode`, not a reply-control error, and nothing is sent (FU-TRN-01).
- Own-password rotation of the stored credential ignores the advisory name
  type (FU-CLI-08).

Crypto policy:

- New `crypto::CryptoPolicy` snapshot (`from_libdefaults`, `check_use` with
  `crypto::Use`) applied at every consumer; enctype relations are
  `config::EnctypeExpr` expressions. Unknown, disabled and refused positive
  terms fail by token (`UnknownEnctype`, `DisabledEnctype`,
  `RejectedEnctype`), Camellia is a diagnostic in compatible mode and an error
  in strict mode, `allow_weak_crypto = true` is rejected, and an empty result
  is `EmptyEnctypeExpression`. `NoUsableEnctypes` and `NoPermittedEnctypes`
  are removed. New `Config::parse_with_mode` and `ParseMode` (FU-CFG-04).
- `-name` removes an entry, `DEFAULT` is the SHA2-first AES list
  `[20, 19, 18, 17]` and `aes` follows MIT's order (FU-CFG-05).
- KDC-supplied string-to-key counts below 4096 (AES-SHA1) or 32768 (AES-SHA2)
  are rejected before PBKDF2; `LibDefaults::with_min_s2k_iterations` lowers a
  minimum from trusted code (FU-CRY-01).
- MAC checks use the audited `hmac` verification instead of a hand-written
  comparison (FU-CRY-02).
- The acceptor applies the policy: `with_crypto_policy` on `Validator`,
  `NegotiateLayer` and `NegotiateService`. **A keytab with only RC4 keys no
  longer authorizes RC4**; that needs `allow_rc4` and RC4 in the permitted
  list (FU-SVC-R04).
- The `safe_checksum_type` default is 15 (was 8); refused checksums and
  protocols fail with typed `error::Policy::RejectedFeature` errors, and
  `Config::UnsupportedDirective` is removed. Every domain error and
  `error::Any` accept `error::Policy`; `RejectedFeature` and `RejectionReason`
  catalogue the permanent refusals. `LibDefaults::diagnostics()` returns
  `Cow<[ConfigDiagnostic]>` (FU-DOC-21).

Configuration:

- A top-level file that cannot be read is `Config::File { path, source }`
  (FU-CFG-01).
- `Config::new_without_env`, `Config::parse_without_env` and
  `LibDefaults::new_without_env` are removed; use `new` and `parse`
  (FU-CFG-02).
- The first value of a repeated scalar wins (it was the last), across files,
  includes, lists and `[domain_realm]`. `forwardable` and `proxiable` set the
  request bits, `default_realm` is the host fallback, a bare
  `kdc_default_options` number is decimal, a malformed `extra_addresses` entry
  is `InvalidAddress`, and `noaddresses = false` is `NotYetEffective`
  (FU-CFG-03).
- Section, subsection and relation finals (`*`) stop later contributions;
  `auth_to_local` and `pkinit_cert_match` values keep a trailing `*`, and
  application, realm and local-name scopes keep their case (FU-CFG-06).
- A plain `0` duration means zero seconds (FU-CFG-07).
- `parse_supported_enctype_ids` is no longer public (FU-CFG-08).
- Ignored sections have their own brace state; re-reading a completed include
  is not a cycle; the limits are 256 files and 4 MiB. Unknown sections and
  relations are diagnostics in compatible mode and errors in strict mode,
  settings without a runtime consumer are `NotYetEffective`, `module` is
  `UnsupportedDynamicModule`, and default-name templates are expanded once
  when a name is resolved, failing on unavailable facts. New
  `Config::from_reader`, `from_string` and `from_path` (FU-CFG-09).

Service and replay cache:

- `clear_older_than[_at]` is renamed `force_clear_older_than[_at]`, and the
  new `prune_expired[_at]` removes only expired records (FU-SVC-03).
- Admission expires records through an ordered index instead of scanning the
  live digest table (FU-SVC-04); bulk expiry removes only expired pairs
  (FU-SVC-05); debug builds check the index invariants (FU-SVC-06).
- `with_max_clock_skew` and `with_shared_replay_cache` on `Validator`,
  `NegotiateLayer` and `NegotiateService` return `Result`; an explicit cache
  with too small a skew fails at construction (FU-SVC-09).
- A same-realm ticket with a nonempty unchecked transited path is rejected
  with `TransitPolicyRejected` unless the KDC checked it or a
  `TransitValidator` accepts it (FU-SVC-10).
- PACs inside AD-MANDATORY-FOR-KDC are found and verified (FU-SVC-11).
- Each client principal may hold one eighth of the replay cache by default;
  `ReplayCache::with_principal_capacity` sets the share, and a full share is
  `ReplayCacheCapacityExceeded` with the share as `capacity` (FU-SVC-R01).
- `ValidatedApReq.service` names the keytab key that decrypted the ticket, not
  the cleartext `sname` (FU-SVC-R02).
- A signed PAC_CLIENT_INFO must match the ticket client name and auth time,
  else the new `Service::PacClientMismatch` (FU-SVC-R03).

Client:

- `spawn_auto_renewal[_with_retry]` return the `#[must_use]`
  `client::auto_renewal::Handle` (`TokioClientAutoRenewal` is an alias)
  (FU-CLI-01).
- Cached and imported credentials are checked against the enctype policy
  before the cache changes; explicit RC4/DES3 permission reaches the SPNEGO
  AP options (FU-CLI-02).
- A failed in-memory ccache export leaves the destination unchanged
  (FU-CLI-03).
- An INVALID or future-dated primary TGT is due for refresh immediately
  (FU-CLI-04).
- Diagnostics no longer report preauth PA-DATA numbers as missing keytab
  enctypes (FU-CLI-05).
- `cache_service_ticket` returns `Result`, and both cache insertion APIs
  reject another client identity with the new `Client::CacheClientMismatch`
  (FU-CLI-06).
- `sessions_json` reports a cross-realm TGT under its destination realm
  (FU-CLI-09).
- TGT renewal keeps the exact `krbtgt/B@A` service and routes to its issuing
  realm (FU-CLI-10).
- An optimistic preauthentication that gets error 24 retries at most twice,
  guided by the KDC's hints, keeping cookies and the pinned TCP connection
  (FU-CLI-11).
- AS/TGS replies that break the requested times or grant unrequested flags
  fail with the new `ReplyTimeConstraint`/`ReplyFlagConstraint`;
  `AsReq`/`TgsReq` gain `clock_skew`, `BuiltAsReq`/`BuiltTgsReq` gain
  `reply_clock`, and their constructors are no longer `const` (FU-CLI-12).
- PREAUTH_FAILED exposes its ETYPE-INFO2 hints and cookies (FU-CLI-13).
- Keytab preauthentication picks the first requested enctype the KDC offers
  and the keytab holds (FU-CLI-15).
- Renewal requires a valid RENEWABLE ticket inside its renewal window; explicit
  renewal otherwise fails with the new `Client::TicketNotRenewable` (FU-CLI-16).
- The blocking clients return the new `Client::BlockingRuntimeUnavailable`
  inside an entered Tokio context instead of panicking (FU-CLI-17).
- New constructors `Realm::new`, `ccache::HeaderField::new`,
  `ccache::HostAddress::{new, ipv4, ipv6}` and
  `service::HostAddress::{new, ipv6}` (FU-API-01).
- `error::Any` gains `Messages` and `Http` (FU-API-03).
- `source()` returns the kept cause of `DefaultCacheName`,
  `DefaultKeytabName`, `DefaultClientKeytabName`, `Spnego::Base64` and
  `KpasswdOutcomeUnknown` (FU-API-04).
- `error::Any::Decode` and `error::Config::InvalidIpAddress` are removed
  (FU-API-05).

Transport:

- Windows `WSAEMSGSIZE` is `UdpResponseTooLarge` (FU-TRN-04).
- Configured `Auto` keeps the winning TCP connection for preauthentication
  (FU-TRN-06).
- Pre-delivery password errors name the endpoint authority (FU-TRN-07).
- Password address APIs need `ToSocketAddrs` only, not `Clone` (FU-TRN-08).
- The kpasswd admin fallback always queries `_kerberos-adm._tcp` (FU-TRN-12).
- An SRV target that does not resolve no longer stops failover to the others
  (FU-TRN-13).
- New `client::transport::kdc_tcp_record_length` (FU-FUZ-02).

Gates, tests and CI:

- The gates scan every Rust source Cargo compiles, including build scripts and
  custom target paths, and fail closed on a source outside the checkout or an
  empty set (FU-GATE-01).
- Dead gate flags are removed (`--report`, `completeness_check.py --enforce`);
  `--paths` with an empty selection selects nothing (FU-GATE-02).
- Lint paths are canonicalized before the exception allowlist (FU-GATE-03).
- `feature_closures.py check-ci` also rejects lint-capping or
  failure-swallowing settings and checks `.cargo/config.toml` (FU-GATE-04).
- `fuzz_coverage.py --enforce` is a blocking gate (FU-GATE-05) and rejects a
  row whose function is gone (FU-GATE-06).
- Prose rules cover every non-test file and macro-generated items
  (FU-GATE-07); a cancellation contract must sit directly above its function
  (FU-GATE-08).
- `semver-checks` takes its baseline from crates.io and fails a release tag
  whose manifest version differs (FU-GATE-10), and compares with the highest
  published version up to the candidate, so an unbumped published version
  fails (FU-GATE-11).
- The fixture runner writes operator values as `printf %q` data (FU-GATE-12)
  and prints keytab secrets as `<redacted>` (FU-GATE-13).
- docs.rs builds the `http` and `tower` features (FU-CI-01).
- CI and the prek hook run the AD helper suites (FU-CI-02).
- The advisory `geiger` job uploads a JSON report (FU-CI-03).
- `mutants` runs in 32 shards under a kill deadline, aggregated by
  `mutants-report` (FU-CI-04).
- `publish.yml` uses CI's stable toolchain revision (FU-CI-05).
- Releases use `N.N.N` tags: the secret-free `Release` coordinator dispatches
  `publish.yml`, whose token-free `verify` job builds the crate and whose
  `publish` job uploads it with `--no-verify` after checking its sha256
  (FU-CI-06); re-dispatching `publish.yml` is the recovery path (FU-CI-07).
- The example's security-header tests run under `cargo test` (FU-TST-01).
- `INTEGRATION_REQUIRED=1` fails when a requested live prerequisite is
  missing (FU-TST-05); the live harness brackets bare IPv6 addresses
  (FU-TST-07) and bounds its TCP probe (FU-TST-10).

Documentation:

- The cache insertion methods document which entry wins (FU-DOC-16).
- `error::Ccache::Io` says "read or written" (FU-DOC-22).

### Lint compliance

- The crate passes the core Section 9 lint profile of the vendored Rust
  guidelines unchanged, with `clippy.toml`, `rustfmt.toml` and
  `.cargo/config.toml` (`build.warnings = "deny"`). There is no baseline, no
  `allow` attribute and no `unsafe` code; the only `expect` attributes are
  the six sanctioned forms in `docs/lint-policy.md`.
- Every feature closure (36, computed from `[features]`) passes
  `cargo clippy --all-targets -- -D warnings` and its tests, and clippy is
  clean on Windows.
- The core's non-lint rules apply to the whole tree: cancel-safety sections
  on async functions (`NOT cancel-safe` on credential-mutating ones), test
  docs, `Result`-returning tests, Drop audits and emptiness messages.
- The tests set environment variables in a child test process instead of
  through `unsafe` `set_var`; shared test helpers live under
  `tests/support/`.
- The universal Rust guidelines and the project overlay are vendored at
  `docs/rust-guidelines/` (pinned and checksummed), indexed by
  `RUST_GUIDELINES.md`.

### Fuzzing, tests and CI

- Thirteen `cargo fuzz` targets cover every attacker-facing parser
  (`kpasswd_reply`, `ccache_parse`, `keytab_parse`, `pac_parse`,
  `spnego_token`, `gss_token`, `kdc_reply`, `krb5_conf`, `der_oid`,
  `krb_messages`, `name_parse`, `http_negotiate`, `kdc_tcp_frame`), seeded from the test
  fixtures; `docs/review/fuzz.md` maps each parser to its target. Ccache and
  config property tests run with `proptest`, including a ccache
  serialization round-trip.
- CI runs on floating stable: rustfmt (`nightly-2026-10-03`), strict clippy
  and the tests in each of the 36 feature closures (`closures`, held equal to
  `feature_closures.py list`), clippy on Windows, library-only feature sets,
  the README commands, the test suite on Linux, macOS and Windows, i686,
  rustdoc on stable and nightly, MSRV 1.99.0, `cargo semver-checks` once a
  published `rskrb5-ng` baseline exists, a publish dry run, a path-dependency
  consumer build, `cargo deny`, `cargo audit`, `cargo vet`, `cargo machete`,
  `taplo`, an offline link check with the guideline checksums, the lint gates,
  a build of every fuzz target and `cargo package`. Advisory: `geiger`, a
  floating-nightly rustdoc canary, and on schedule or dispatch the
  whole-crate mutants run in 32 shards and 300 s of fuzzing per target.
- Publishing needs an `N.N.N` tag on a CI-green commit of `main` and the
  owner's approval of the `release` environment (`docs/RELEASING.md`).
- The Docker MIT KDC and Active Directory integration gates run locally with
  `scripts/run-gated-integration.sh`; the upstream workflow-dispatch jobs
  aren't part of this CI, and `docs/gokrb5-parity.toml` records their upstream
  runs as historical evidence.

## [0.2.2] - 2026-10-23

Published to crates.io on 2026-10-23; the `v0.2.2` tag was created on
2026-10-07.

Patched fork of `rskrb5`, still based on upstream `clelange/rskrb5` `main` at
`6f4abc9`, adding the changes below on top of the 0.2.1 set. The upstream
references are in `PROVENANCE.md` (formerly `FORK-NOTES.md`).

- AP-REQ replay identity is canonicalized over the advisory name-type: a
  name-type-only replay of a captured AP-REQ is rejected, and the replay key
  binds the service component to the key identity that accepted the ticket
  (clelange/rskrb5 PR #20).
- The authenticator client realm is bound to the KDC-authenticated ticket
  realm, and `ValidatedApReq.client` returns the ticket-derived identity, so
  no authenticator-supplied value reaches callers (clelange/rskrb5 PR #21).
- TCP transport: the record mark and the request body are written as one
  segment, `TCP_NODELAY` is set, and the preauth retry rides the pinned stream
  that answered the first AS phase (third-party PR #19's commits, authorship
  preserved), plus a pinning extension for the `Auto` fallback (Gittingc0dez
  stacked PR #1).
- Documentation: detailed fix plans for the remaining audit findings live in
  `docs/fix-plans/` (now `docs/history/fix-plans/`, excluded from packaging).

## [0.2.1] - 2026-10-06

Patched fork of `rskrb5`, based on upstream `clelange/rskrb5` `main` at
`6f4abc9` plus the changes below - published as `rskrb5-patched` so consumers
can depend on a registry version that carries them while they wait upstream.
The upstream references are in `PROVENANCE.md` (formerly `FORK-NOTES.md`).

- Clippy lints reported by Rust 1.98 (PR #15).
- `hex` as a dev-dependency so the crate's own integration tests build
  (issue #12, PR #16).
- `PA_FX_COOKIE`, `PA_AS_FRESHNESS` and `random_nonce` exported (issue #14,
  PR #17).
- `ChangePasswordResult` and `PasswordChangeFailed` carry the result bytes as
  received (`text_raw`), instead of `String::from_utf8_lossy`; the test
  fixtures are completed (issue #2, PR #18).
- `Config`/`LibDefaults` constructors that read no environment
  (`new_without_env`, `parse_without_env`) (issue #10).
- `include`/`includedir` support in `krb5.conf`, with depth/count/byte bounds
  and named errors; cycle detection for root files and directories; the scan
  cap enforced while scanning; non-UTF-8 `.conf` names read, MIT-style
  (issue #11).
- TGS-REQ builder returns the AP-REQ bytes and the authenticator subkey
  (RFC 6113 implicit FAST armor inputs) (issue #13).
- `TCP_NODELAY` on the KDC TCP connect (the record mark and body are two
  writes; Nagle holds the body) (equivalent third-party PR #19).

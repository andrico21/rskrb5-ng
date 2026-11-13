# Migrating from rskrb5-patched
`rskrb5-patched` 0.2.x users move to `rskrb5-ng` 0.3. This guide lists every
change a caller can see: the new package and library names, renamed paths,
constructors that replace struct literals, changed signatures and error
types, new configuration keys and behaviour changes. The full change list is
the `[0.3.0]` section of `CHANGELOG.md`.

## Dependency and imports

CI maintainers must keep `docs-validate` independent and unconditional
(FU-GATE-R13). Job/step conditions, `needs`, advisory failures and decoy action
inputs are rejected. Its checkout, checksum command and pinned lychee action
must run in order, with recursive offline fragment checking and `fail: true`.
The schedule/dispatch-only advisory jobs do not exempt `docs-validate`.

Package documentation with unmatched or escaped backticks does not hide later
relative links from the package gate (FU-CI-R05). Fix any newly reported target
rather than relying on malformed code-span delimiters. Real equal-length code
spans suppress link syntax, including multiline spans within one block;
backslashes inside code spans are literal under CommonMark.

When maintaining parity manifests, cite symbols enabled by at least one resolved
Cargo feature closure (FU-TST-R20). The evidence lexer uses the same closure
universe as `feature_closures.py list`, including feature implications; independent
Boolean assignments such as `tower` without `http` do not count as evidence.

Configured acceptors (`Validator`, `NegotiateLayer` and `NegotiateService`)
retain permanent `Policy::RejectedFeature` causes from both whole-configuration
admission and enctype policy construction (FU-SPN-R17). Inspect `Error::source`
to distinguish the exact prohibited feature from ordinary `InvalidConfiguration`;
both `from_default_keytab_name` and `from_default_keytab` refuse before discovery.

Replace the dependency:

```toml
[dependencies]
rskrb5-ng = "0.3"
```

and the imports: `use rskrb5::...` becomes `use rskrb5_ng::...`, and so does
every `rskrb5::` path. A manifest that renames the dependency key,
`rskrb5 = { package = "rskrb5-ng", version = "0.3" }`, keeps the `rskrb5::`
paths compiling and changes only the package. The features are the same
(`messages`, `spnego`, `tokio`, `http`, `tower`, `serde`, `evaluation`;
default `spnego`, `tokio`, `serde`).

`rskrb5-ng` needs Rust 1.99 or newer (`rust-version = "1.99"`; it was 1.88).
It depends on `rasn` and `rasn-kerberos` 0.29 (v0.2.2: 0.28.13); a caller that
passes `rasn` values to or from this crate needs the same versions. The bump
also changes the derived `rasn::enc::Encode` and `rasn::de::Decode` methods that
five of this crate's types expose (`kadmin::ChangePasswdData`,
`messages::{EncryptedData, PaForUser, PaPacOptions, PaReqEncPaRep}`):
`encode_with_constraints`, `encode_with_constraints_and_identifier`,
`encode_with_tag_and_constraints`, `decode_with_constraints` and
`decode_with_tag_and_constraints` take `&Constraints` instead of `Constraints`.
Callers of the plain `encode`/`decode` methods or of the crate's own DER helpers
are unaffected; a direct caller of any `*_with_constraints*` or
`*_with_tag_and_constraints` method passes a reference (FU-DOC-R54,
FU-DOC-R74).

## New configuration keys

`client::options::AsReq::from_libdefaults` and `TgsReq::from_libdefaults` now
return `Result<Self, error::Client>`: add `?` before chaining option builders.
Programmatically supplied request lists are validated under the actual legacy
permissions and parse mode and rejected by name if any entry is outside the
permitted set; no intersection silently removes entries. Parsed implicit
request defaults continue to inherit the permitted list. Programmatic callers
setting a narrower permitted list must also set compatible request lists
(FU-CLI-R18). Client admission preserves permanent `Policy::RejectedFeature`
causes through `Error::source`, and ordinary configuration failures retain
their named `error::Config` cause (FU-CLI-R19).

Raw AS, TGS and KDC-request-body encoders reject permanently prohibited numeric
requested enctypes, including single DES and RC4-EXP. Passive decoding remains
available for historical records; raw encoding still does not impose runtime
RC4-HMAC or DES3 opt-in permission (FU-MSG-R02).

An explicit `auth_to_local_names = { ... }` subsection selects deferred local
authorization even if it is empty (FU-CFG-R14). Compatible parsing reports one
`NotYetEffective` diagnostic per admitted map; Strict parsing rejects it with
relation `auth_to_local_names` and package `plan 2 WP-17`. Omit the subsection
when no local-name mapping is intended. Finalized, discarded later scopes do
not select it. This diagnostic policy is stricter than MIT's profile getter,
which simply finds no relation in an empty subsection.

Principal keys such as `krb4_get_tickets` or `pkinit_draft9` inside a realm's
`auth_to_local_names` map now parse as names (FU-CFG-R13). Their case and first
mapping value are retained. The exemption is limited to that exact mapping
path; enabled protocol selectors elsewhere, including discarded scopes, fail
permanently. Local authorization is deferred to WP-17 and Strict mode rejects
its diagnostic.

A local principal literally named `module` in that exact map is mapping data
(FU-CFG-R16); real `module` declarations elsewhere are rejected.

Two `[libdefaults]` flags gate the legacy enctypes. Both default to false,
independently of `allow_weak_crypto`:

```text
[libdefaults]
    allow_rc4 = true
    allow_des3 = true
```

Without them the default enctype lists are AES only, and an explicit
`default_tkt_enctypes`, `default_tgs_enctypes` or `permitted_enctypes` entry
naming RC4 or DES3 fails to parse with `error::Config::DisabledEnctype`. The
flags permit a family; they do not add it to any list. In code, set
`LibDefaults::allow_rc4` and `LibDefaults::allow_des3` (both `config::Toggle`)
or use their `with_*` builders. "Derived enctype policy" and "Runtime crypto
policy" below have the details.

## Behaviour changes before the review backlog

These came with the 0.3 line before the review fixes below; `CHANGELOG.md`
describes each one.

- A KDC reply or session key outside the requested enctypes fails with
  `error::Client::EnctypeNotRequested`; with an explicit
  `permitted_enctypes`, a session key outside it fails with
  `error::Client::EnctypeNotPermitted`.
- An explicit `default_tkt_enctypes`/`default_tgs_enctypes` entry outside an
  explicit `permitted_enctypes` is a parse error
  (`error::Config::EnctypeNotPermitted`), and an enctype list that resolves to
  nothing is `error::Config::EmptyEnctypeExpression` (see "Runtime crypto
  policy").
- `des3-cbc-sha1` and `des3-hmac-sha1` mean enctype 16.
- An unsigned kpasswd success is `error::Kadmin::UnauthenticatedSuccess`.
- Host-based service principals carry a lower-cased host, and
  `[domain_realm]` lookups fold case and apply bare tags to subdomains.
- `[libdefaults] clockskew` reaches the `Config`-driven acceptors.
- TGT refresh, auto-renewal pacing and AS recovery follow the renewal series
  in `CHANGELOG.md`.
- The HTTP send wrappers return
  `NegotiateHttpError::MutualAuthenticationNotProven` when requested mutual
  authentication isn't proven; `NegotiateHttpError<E>` is now
  `NegotiateHttpError<E, B>`.
- Malformed ccache record counts return `error::Ccache::Truncated` instead of
  reserving memory.

## Review backlog behaviour changes

### Derived enctype policy

`LibDefaults` no longer stores writable `default_tkt_enctype_ids`,
`default_tgs_enctype_ids` or `permitted_enctype_ids` fields. Call the methods
with those names instead; each derives IDs from the current public name list
and policy. Their signatures are `pub fn default_tkt_enctype_ids(&self) -> Vec<i32>`,
`pub fn default_tgs_enctype_ids(&self) -> Vec<i32>` and
`pub fn permitted_enctype_ids(&self) -> Vec<i32>`.
Replace assignments to the old ID fields with updates to the corresponding
`*_enctypes` name lists, directly or through `with_*_enctypes` builders. The 0.2.2
`LibDefaults` API had public ID fields, not `with_*_enctype_ids` builders.
Serde input cannot inject cached IDs;
the compatibility JSON snapshot derives IDs on demand. Empty request lists no
longer substitute an unrelated built-in policy.

Explicit enctype lists are MIT list expressions (`DEFAULT`, families and
`+`/`-` terms) and fail closed by token: an unknown, disabled or permanently
refused positive entry is an error naming the original token, and a list that
resolves to nothing is `error::Config::EmptyEnctypeExpression`. Neither case
substitutes defaults or an unrestricted policy. The table under "Runtime
crypto policy" maps each input to its error. The `NoUsableEnctypes` and
`NoPermittedEnctypes` variants of the earlier 0.3 work, and the unconstructed
`UnsupportedEnctype` and `EnctypeDisabled`, were removed before the 0.3.0
release; none of them existed in 0.2.2.

Defaults now advertise only AES (20, 19, 18, 17). Set `[libdefaults] allow_rc4`
or `allow_des3` explicitly to true before configuring RC4 or DES3 names; both
are disabled by default. A disabled name is `error::Config::DisabledEnctype`.
Export RC4 is refused permanently, and `allow_weak_crypto = true` is an error.
The flags are public `Toggle` fields and serde defaults missing flags to false.
Policy is evaluated after all sections and includes.

### Durable credential-file replacement

Credential-file saves sync the parent directory after rename on Unix. A sync
failure is returned even though replacement has already completed; cleanup
failure never masks the original write, rename or sync error. On Windows, supply
a directory with an owner-only ACL (std does not expose ACL construction).

### Environment-free configuration defaults

`LibDefaults::new`, `Config::new` and parsing no longer read `UID` or `HOME`.
The client-keytab default is the template
`/usr/local/var/krb5/user/%{euid}/client.keytab`, expanded when the name is used
(v0.2.2 filled in the `UID` environment variable when the value was built, so
an unset variable gave `/usr/local/var/krb5/user/0/client.keytab`), and
`k5login_directory` defaults to empty (FU-DOC-R72).
Use the new `LibDefaults::from_env()` only when HOME discovery is intended.
The `*_without_env` twins were removed ("Removed configuration twins"). Remaining
configuration/credential discovery entry points document `# Ambient input`.

### Explicit transport DNS configuration

`client::transport::Tokio` no longer reads `RSKRB5_DNS_SERVER`. Applications
that choose this input must read it themselves and pass its value to
`Tokio::new().with_dns_server(&value)?`. IP literals use port 53 unless an
explicit port is provided; blank input selects the system resolver. Invalid
input returns `Client::DnsResolverConfig`.

A root SRV target now returns `Client::DnsServiceUnavailable { service, realm }`
instead of allowing administration-service fallback.

KDC TCP framing rejects the reserved high bit with `Client::TcpReservedBitSet`;
outgoing KDC lengths above 31 bits return `Client::TcpRequestTooLarge`.
Kpasswd TCP retains RFC 3244's separate unsigned length rules.

Password transport no longer retries after a send may have started. Such I/O
failures, response errors and timeouts return `Client::KpasswdOutcomeUnknown`.
`KdcProtocol::Auto` for a password change tries TCP first and UDP only after
a definite TCP failure (all TCP endpoints, then all UDP endpoints; for an
explicit address TCP, then UDP), as MIT's `changepw.c` does, and
`udp_preference_limit` does not apply to it. A refusal while the single UDP
reply is awaited (`ConnectionRefused`, or `ConnectionReset` on Windows) is a
definite endpoint failure, so a closed UDP kpasswd port moves on to the next
endpoint and, when every endpoint failed, is reported as `KdcEndpointFailures`
(for an explicit address, as the plain `Client::Io`) (v0.2.2: UDP first for a request within
`udp_preference_limit`, a configured realm falling back to TCP after any UDP
failure; an explicit address always UDP first, then TCP). If TCP fails after the
request may have been delivered, UDP is never tried. Do
not treat an unknown outcome as a failed mutation or blindly retry it. A
password change also gives connection setup (TCP connect, or UDP socket bind and
connect) and the send-and-reply phase a full `Tokio::with_timeout` each, so one
attempt on one endpoint can take up to twice the configured timeout (v0.2.2: one
timeout covered the whole attempt); only a timeout or failure in the second
phase is `KpasswdOutcomeUnknown`; a timeout while connecting is
`Client::TransportTimeout` (FU-DOC-R76).

UDP response limits now reject oversized responses with the new
`Client::UdpResponseTooLarge { limit }` variant instead of returning a prefix.

### Credential filename identity tokens

`%{uid}` and `%{euid}` in keytab and credential-cache names now use the
Linux process's real and effective UIDs from `/proc/self/status`, respectively.
The `UID` environment variable is never read for expansion. Missing or malformed
procfs identity data, and all non-Linux platforms including macOS and Windows,
return the new `error::Ccache::IdentityUnavailable` or
`error::Keytab::IdentityUnavailable` variant. Use explicitly resolved literal
paths on those platforms; token-free names do not require procfs.

### Decrypted PAC credential ownership

`SecpkgSupplementalCredential::credentials` is now `Zeroizing<Vec<u8>>`.
Borrow it as a slice for intentional access; avoid extracting a nonzeroizing copy.
Decryption scratch is zeroizing even on parse errors. NTLM credentials erase
their owned optional hashes on Drop and redact Debug, as do package entries.
Their array field types are unchanged, but moving fields out of a Drop type is
restricted; borrow them instead. Copies deliberately made by callers, borrowed
parser inputs, dependency-internal state and compiler/register copies are outside
this guarantee. Abort does not run Drop.

### Boolean claim values

Boolean claim arrays are decoded as aligned ULONG64 values, not bytes.
Values other than zero or one return `error::Pac::InvalidBooleanClaim`.

### NTLM supplemental validity masks

`NTLM_SUPPLEMENTAL_CRED_LMOWF` and `NTLM_SUPPLEMENTAL_CRED_NTOWF` now hold
numeric masks 1 and 2, not the erroneous indices 31 and 30. Test these masks
directly against the decoded flags. Reserved bits are ignored when receiving
credentials; records with neither validity bit return
`error::Pac::MissingNtlmValidityFlag` as required by MS-PAC 2.6.4.

### Bounded supplemental credential allocation

Credential data rejects counts above 1,000,000 or whose 16-byte fixed
descriptors cannot fit the remaining input, before reserving either vector.
Allocation failures after admission return `error::Pac::CredentialAllocation`.
Zero credentials remain valid; no public signatures change.

### Bounded claims output

`ClaimsSetMetadata::decoded_claims_set_bytes` rejects declared output lengths
or stored payloads above 1 MiB with `error::Pac::ClaimsOutputLimit` before
framing, decompression or copying. The cap applies to mutable metadata and to
uncompressed claims too. At most one client and one device claims buffer are
processed, bounding total decoded claims output to 2 MiB per PAC. Existing
decompressed-size correlation remains unchanged; no output is clamped.

### Bounded public PAC lookup

`pac::find_pac_in_authorization_data` now rejects more than eight nested
AD-IF-RELEVANT or AD-MANDATORY-FOR-KDC wrappers with `Pac::AuthorizationDataDepthLimit` and more than
1 MiB of cumulative visited entry payloads with `Pac::AuthorizationDataByteLimit`
(both in `error::Pac`). The inclusive byte budget is shared across siblings and
counts nested payloads again at each decoded level, before decoding or PAC
processing. Its signature is unchanged. It now also descends into
AD-MANDATORY-FOR-KDC (type 8) wrappers, which v0.2.2 skipped, so a PAC inside
one is returned (FU-SVC-11, FU-DOC-R94); the first PAC still ends the search.
Service acceptance imposes these limits independently while validating all restrictions.

### HTTP replay-cache scope and binding limits

Layer clones already share replay state. Independently constructed
`NegotiateLayer`/`NegotiateService` instances for the same service principal
must be wired to the same `SharedReplayCache`; never construct a fresh cache
per request. This is in-process only: replicas, restarts and separate hosts
require external coordination or a single accepting boundary. There is no
automatic global cache keyed by principal.

The adapter authenticates an AP-REQ, not HTTP method, URI, headers or body.
No TLS channel-binding input is available. Use TLS, but do not claim that TLS
alone makes this adapter's tokens request/channel-bound. A captured token's
first-use race is not prevented by replay detection. No API signatures change.

### Whole-second KerberosTime (RSK-B161A328)

Service acceptance rejects fractional ticket `authtime`, `starttime`, `endtime`
and `renew-till`, plus fractional authenticator `ctime`, with the new
`Service::FractionalKerberosTime` variant. Service AP-REP verification and
construction enforce the same rule, including mutable public construction
inputs. Fractions are neither truncated nor added to `cusec`; the separate
microseconds field remains valid. Generic DER codecs are unchanged.

### Strict Microseconds domain (RSK-985742B6)

Service AP-REQ acceptance and `ValidatedApReq` AP-REP construction/verification
now reject microseconds outside 0..=999999 using `Service::IntegerOutOfRange`
(v0.2.2 `service::Error::IntegerOutOfRange`, raised only for integers that do
not fit `u32`; `authenticator.cusec` or `ap-rep.cusec`). Values at or above one
million are not normalized into additional seconds. Construction rechecks the
mutable public `authenticator_cusec` field. Zero and 999999 remain valid. Public
signatures and error variants are unchanged.

### Bounded replay-cache lifecycle (RSK-7D80FA41)

`ReplayCache::new`/`default` now own an immutable 300-second skew ceiling and
65,536-record capacity. Use `ReplayCache::with_limits(max_clock_skew, capacity)`
and `SharedReplayCache::from_cache` for an explicitly different policy. A validator
whose skew exceeds the cache ceiling fails admission with
`Service::ReplayCacheSkewExceeded`; `with_max_clock_skew` does not widen a cache.
This also applies to the shared cache created by a Tower layer.

Each insert prunes records last seen more than three times the cache skew ago,
evaluated against `max(watermark, presented_at)`, then checks replay and capacity
atomically under the shared lock. Three-skew retention covers future authenticators
and the additional one-skew rollback tolerance. Equality at the expiry boundary
stays live. Backward validation samples up to the cache's
configured maximum skew are tolerated, including out-of-order concurrent samples.
The high-water mark never moves backwards; a rollback larger than the skew returns
`ReplayCacheClockRollback`, and even explicit `clear` does not reset that mark.
New records and existing records seen again are timestamped at the watermark,
never at a stepped-back sample. A replay key and its authenticator digest share
one last-seen time: a replay matching either refreshes both, and pruning removes
them together, so the digest index never holds more records than the key index.
Neither index expires a record within three skew windows of its latest sighting.
At the default skew this is 900 seconds; size capacity for peak admissions over
that window. The
65,536-record default holds about 72 new records/second sustained before
bursts or replay refreshes need extra headroom. Full capacity returns
`ReplayCacheCapacityExceeded`, never evicting live replay evidence.
Admission expires records through an ordered expiry index (v0.2.2 expired
nothing at admission; only an explicit `clear_older_than` scan did) (FU-SVC-04);
each client principal is limited to a
share of the capacity ("Replay cache" under the follow-up changes).

Explicit `clear`/`force_clear_older_than*` are administrative overrides that can erase
live replay protection. Do not schedule aggressive pruning; automatic admission now
maintains expiry. Replace caches only with service downtime lasting at least the replay
window; creating a fresh cache or restarting still loses in-memory evidence. Capacity
bounds records, not principal-string bytes or allocator RSS.

### Mandatory authorization-data policy (RSK-D1D6BDC3)

Service acceptance now scans all ticket and authenticator authorization data,
independently of first-PAC extraction, before replay admission. Unknown critical
elements return `error::Service::UnsupportedAuthorizationData { kind }`.
AD-IF-RELEVANT permits unknown direct children; AD-MANDATORY-FOR-KDC contents
are interpreted with criticality restored. Unsupported AD-KDCIssued and
AD-AND-OR containers fail closed, including inside optional wrappers. Ticket
PACs retain their existing server-checksum verification; authenticator PACs
are not treated as KDC-authenticated authorization evidence.

Policy traversal is limited to eight wrappers and 1,048,576 cumulative payload
bytes (including decoded nested payloads), returning `AuthorizationDataLimit`.
Malformed known wrappers return the existing `Service::Decode` classification.
These service-only bounds do not change the standalone PAC extraction limits.

### Explicit unchecked cross-realm transit policy (RSK-3E3C2278)

The service validator now rejects cross-realm tickets lacking
TRANSITED-POLICY-CHECKED with `error::Service::TransitPolicyRejected`, unless
an explicitly configured `service::TransitValidator` approves the complete path.
Use `Validator::with_transit_validator(Arc<dyn TransitValidator>)` or the matching
`http::NegotiateLayer` builder. A custom policy implements one method,
`TransitValidator::accepts(&self, client_realm: &str, service_realm: &str,
transited: &rasn_kerberos::TransitedEncoding) -> bool` (FU-DOC-07): it
receives the client realm, the service realm and the raw transited encoding,
and must validate all three. Empty contents still represent cross-realm
transit. Reject unknown encodings unless your implementation understands
them. The library does not decode or implicitly trust transit paths.
KDC-checked tickets and same-realm tickets with an empty path are
unaffected; since FU-SVC-10 a same-realm ticket with a nonempty unchecked
path also needs the KDC check or an accepting policy.

**Active Directory:** MS-KILE §3.1.5.4 does not set this flag, so cross-domain and
forest-trust tickets require explicit policy; rejection is the secure default. Use
`Arc::new(service::TransitPolicy::direct("USER.REALM", "SERVICE.REALM"))` with
either builder for a trusted direct endpoint pair (type 1, empty contents). For
indirect tickets, `TransitPolicy::domain_x500_paths(client, service, paths)`
accepts an allow-list of exact complete DOMAIN-X500-COMPRESS encoded byte paths,
not individual realms. For example, `[b"TRUSTED.REALM".as_slice()]` trusts only
that complete path; a path containing an extra untrusted realm is rejected.
Include `b""` explicitly to allow direct transit in a path allow-list. Empty
allow-lists, empty endpoint names, type 0 and unknown encoding types are rejected.
No hierarchy inference, suffix matching or permissive fallback is performed.

### RFC3961 derivation constant bounds (RSK-8F3B02EE)

AES-SHA1 `derive_random` and `derive_key` now reject constants longer than
16 bytes; DES3 rejects constants longer than 8 bytes. Handle the new
`error::Crypto::DerivationConstantTooLong { maximum, actual }` variant.
The limits are inclusive cipher-block bounds from RFC3961 section 5.1;
constants are not silently reduced. Empty constants still return `EmptyUsage`.
Signatures, generic `nfold`, and SHA2 PRF contexts/derivation labels are unchanged.

### Bounded AES password derivation (RSK-F240C18F)

`crypto::s2kparams_to_iterations` and both AES families' `string_to_key` now
reject counts above 16,777,216 (2^24) with
`error::Crypto::IterationCountTooHigh { maximum, actual }`. The limit is
inclusive, fixed locally, and not a Kerberos protocol maximum. Excessive counts
are rejected, never clamped. Zero retains `UnsupportedIterationCountZero`.
The common client password-reply-key path propagates the new error before
PBKDF2, including for unauthenticated ETYPE-INFO2 hints. Deployments with larger
work factors must adjust their KDC policy to use this bounded path.
Public signatures are unchanged; direct `string_to_pbkdf2` remains a trusted,
caller-controlled primitive and must not receive unchecked peer work factors.

### Bounded HTTP Negotiate headers (upstream issue #9)

`spnego::parse_negotiate_header` now rejects header values longer than 65,536
bytes with `error::Spnego::NegotiateHeaderTooLong { maximum, actual }` before
scanning or base64 decoding. The limit includes the scheme and whitespace;
exactly 65,536 bytes remain eligible for normal parsing. It applies to both
SPNEGO and raw Kerberos tokens, including acceptor and AP-REP verification
callers. Smaller malformed headers retain their existing error classifications.
Public signatures and token encoders are unchanged. This is a local resource
limit, not a Kerberos protocol maximum; callers needing larger headers must
account for this compatibility restriction.

### Unsupported initiator delegation (RSK-622F4664)

Checked SPNEGO initiation now returns `error::Spnego::DelegationRequiresCredential`
when any context flag mask contains `CONTEXT_FLAG_DELEG`, whether supplied alone,
split across entries or combined with other flags. These builders have no delegated
credential input; they no longer emit malformed delegation checksums. Remove the
request if delegation is not needed; credential forwarding is not implemented.
Public signatures are unchanged. Nondelegating callers are unaffected.

The low-level `authenticator_checksum` helper returns a 24-byte prefix for every
flag representation, not a complete delegation checksum. It no longer appends four
zero bytes for a standalone delegation flag. A caller building delegation manually
must append DlgOpt=1, a little-endian length and the encrypted KRB-CRED specified by
RFC 4121 section 4.1.1. The acceptor does not import delegated credentials; its
framing checks are described in the next section.

### Mandatory GSS authenticator fields (RSK-FAF64A85)

`spnego::accept_sec_context_header` (and the HTTP acceptor using it) now checks
the RFC 4121 section 4.1.1 authenticator checksum type, framing and sequence
presence before recording a replay. Handle the new `error::Spnego` variants
`MissingAuthenticatorChecksum`, `InvalidAuthenticatorChecksum` and
`MissingAuthenticatorSequence`. Generic `service::Validator::validate_ap_req`
still permits authenticators without these GSS-specific fields.

`init_sec_context_with_confounder` now requires
`InitiatorContextOptions::with_sequence_number(Some(sequence))`; zero is valid.
The random `init_sec_context` builder still supplies a sequence when omitted.
No signatures change. The acceptor still has no channel-binding input, ignores
unknown flags and extensions, and does not import delegated credentials.

### SPNEGO acceptor negotiation (RSK-C4BE57A0)

`AcceptedContext::selected_mechanism` records the first offered Kerberos OID, echoed
as SPNEGO `supportedMech`. The additive `token_mechanism` field preserves the
optimistic token's OID for the inner AP-REP `thisMech`. Both standard and Microsoft
legacy OIDs identify the same mechanism, including raw Kerberos headers. An
MS-KRB5-first offer with a standard Kerberos AP-REQ and no MIC is accepted, as sent by
Windows SSPI. Its reply uses MS-KRB5 `supportedMech` and standard `thisMech`, matching
MIT and MS-SPNG; equal offer/token OIDs are unchanged. Only a non-Kerberos first
preference (such as NTLM) requires a valid RFC 4121 MIC. A supplied first-choice MIC
is verified. Handle `error::Spnego::MissingMechListMic` and `InvalidMechListMic`;
unsupported mechanisms return `UnsupportedMechanism`. The unconstructed
`error::Spnego::OptimisticMechanismMismatch` variant was removed before 0.3.0 release;
it never existed in 0.2.2.

The additive `AcceptedContext::mech_types_der` field retains the exact received
list TLV when a MIC verified. AP-REP response helpers include a reciprocal MIC
over it, using usage 23 and the AP-REP acceptor subkey, authenticator subkey or
ticket key (in that order). Verification uses usage 25 and the authenticator
subkey or ticket key: no acceptor subkey exists in this initial leg. MIC sequence
numbers must match the authenticator; response MICs use the AP-REP sequence,
falling back to the authenticator sequence. In that fallback the AP-REP carries
the same number, so initiators that read the acceptor sequence from the AP-REP
(as MIT does, 0 when absent) agree with the MIC. A MIC consumes that
per-direction sequence number; applications using per-message tokens next must
increment it. The no-MIC first-choice AP-REP encoding is unchanged.

Only RFC 4121 MIC tokens with AES session enctypes are supported for mechListMIC.
RC4 (RFC 4757) and DES3 (RFC 1964) MIC formats fail closed as `InvalidMechListMic`.

All `NegTokenResp` continuations return `NegotiationRequiresState`: they lack
the original offer and prior key/MIC phase. A peer needing a request-mic round
trip must use a stateful implementation. The keyless extraction helpers
`NegTokenInit::krb5_ap_req` and `Token::krb5_ap_req` return
`MechListMicRequiresState` for supplied MICs; use `accept_sec_context_header`
for cryptographic verification. Decoding alone never authenticates negotiation.

### S4U frontend keys (delegated-client-unbound-to-ticket-payload)

S4U exchanges now require frontend long-term keys to validate delegated ticket
identity. Set `TgsReq::with_delegation_keytab(keytab)` for runtime-neutral or
transport APIs. High-level keytab-backed clients provide their keys automatically.
Without keys, reply processing returns `error::Client::DelegationKeyRequired`;
protected ticket/evidence identity mismatches return `DelegationPrincipalMismatch`.
`TgsReq` and `BuiltTgsReq` carry optional local-only `delegation_keytab` metadata.

### Unknown password-mutation outcome (RSK-14E2755A, RSK-8BBFC1EE)

Password mutation failures after possible delivery return exactly one
`Client::KpasswdOutcomeUnknown(Box<Client>)`, preserving the underlying cause.
Pre-send encoding, discovery, TCP connection and UDP socket-setup failures
retain their definite error classes and may be retried safely, and so does a
UDP refusal (`ConnectionRefused`, or `ConnectionReset` on Windows, which is the
ICMP port-unreachable reported while the reply is awaited; FU-CLI-R24). Every
other failure after a UDP datagram was sent, and malformed replies, are unknown
outcomes. It
does not mean rejection or rollback: reconcile with a fresh login before
retrying. Dropping a mutation future returns no error at all; the caller must
record unknown externally. Confirmed server rejection remains a normal result
failure. Async Negotiate wrappers preserve this error and the same cancellation
contract. Transport stops failover after possible delivery, and `Auto` never
sends UDP after a TCP request that may have been delivered (deliberately
stricter than MIT's `changepw.c`, which then tries UDP).

### Password plaintext ownership (RSK-471362A3)

Password-specific `ChangePasswdData` Debug now redacts `new_passwd`. High-level
password copies and owned DER staging buffers use zeroizing owners. Passwords
are now passed as `client::Password` ("Owned passwords" under the follow-up
changes). The copies that dependencies own are listed in
[`security-policy.md`](security-policy.md#residual-copies).

### RFC 3244 bare error responses (RSK-3B6BA222)

`kadmin::Reply::parse` also accepts standalone KRB-ERROR responses. For these
responses `version` is `CHANGE_PASSWORD_REQUEST_VERSION` (0xff80),
`message_length` is the DER wire length and `ap_rep_length` is zero. `encode`
preserves this bare profile. Legacy version-1 error replies remain framed;
callers constructing responders can select the profile through `version`.
Neither error form authenticates a success result.

### Validated kpasswd response controls (RSK-789A6FBB)

High-level password changes now reject invalid KRB-PRIV response controls with
`error::Client::KpasswdReplyControl`. If AP-REP negotiates a server sequence,
the result must carry that sequence (not the client's starting sequence).
Otherwise a timestamp/usec pair is required. Supplied times must be whole-second
KerberosTime plus 0..=999999 microseconds and within 300 seconds of the request
metadata. `RequestOptions::recipient_address`, when present, pins the response
sender; absent that option, the sender must have valid IPv4/IPv6 encoding but
is not bound to the transport endpoint. A supplied response recipient must
match `RequestOptions::sender_address`. Raw `Reply::decrypt_result` remains a
decryption-only API with no contextual freshness/address claim.

## Follow-up review changes

The independent follow-up review of `6586b7a` changed the API and behaviour
again before 0.3.0. Each heading names its rows in the
[follow-up register](https://github.com/andrico21/rskrb5-ng/blob/main/docs/review/followup-6586b7a.md),
which records the proof and commit of each one. Where an earlier section of
this guide described the previous state, it points here. The compiled
examples below are doctests.

### Owned passwords (FU-CLI-07, FU-TRN-14)

Password-changing APIs take the new owning type `client::Password` (an alias
of `client::password::Secret`) by value instead of a generic
`P: AsRef<[u8]>`. The affected methods are `change_password`,
`change_password_for`, `change_password_with_options` and
`change_password_for_with_options` on `client::Tokio`,
`client::negotiate::Client` and `client::negotiate::BlockingClient`, plus
`kadmin::ChangePasswdData::new(Password) -> Self` and
`ChangePasswdData::for_target(Password, name_type, components, realm) ->
Result<Self, error::Kadmin>`. The other parameters and results are unchanged.

- `Password::from_string(String)` and `Password::from_vec(Vec<u8>)` take over
  the allocation without copying it; it is erased when the password is
  dropped, including on error and cancellation.
- `Password::copy_from_str(&str)` copies; the caller keeps the duty to erase
  the borrowed original.
- `as_bytes()` borrows the bytes. `Password` has no `Clone` or `Display`, and
  its `Debug` is redacted.
- The `ChangePasswdData::new_passwd` field (v0.2.2: a public `OctetString`) is
  private; `new_passwd()` returns a redacted zeroizing
  `&kadmin::password::Bytes`, and the request builders encode the password
  envelope directly into zeroizing buffers (FU-DOC-R52).

The 0.2 call with a string literal no longer compiles:

```compile_fail
use rskrb5_ng::kadmin::ChangePasswdData;

let data = ChangePasswdData::new("n3w-Secret");
```

Pass an owned password instead:

```rust
# #[cfg(feature = "messages")]
# {
use rskrb5_ng::client::Password;
use rskrb5_ng::kadmin::ChangePasswdData;

let password = Password::from_string(String::from("n3w-Secret"));
assert_eq!(password.as_bytes(), b"n3w-Secret");
let own = ChangePasswdData::new(password);
let target = ChangePasswdData::for_target(
    Password::copy_from_str("n3w-Secret"),
    1,
    ["alice"],
    "EXAMPLE.COM",
);
assert!(target.is_ok());
drop(own);
# }
```

The high-level clients take the same type:

```rust
# #[cfg(all(feature = "tokio", feature = "spnego"))]
# {
use rskrb5_ng::NegotiateClient;
use rskrb5_ng::client::{Password, kpasswd::RequestOptions};
use rskrb5_ng::error::Client;

async fn rotate(
    client: &mut NegotiateClient,
    new_password: String,
    options: RequestOptions,
) -> Result<bool, Client> {
    let result = client
        .change_password_with_options(Password::from_string(new_password), options)
        .await?;
    Ok(result.is_success())
}
# }
```

### Checked kpasswd results (FU-TRN-02, FU-TRN-03, FU-TRN-10, FU-TRN-11)

`client::transport::Tokio::exchange_kpasswd_result` and
`exchange_kpasswd_result_with_config` take the `client::kpasswd::BuiltKpasswdRequest`
from `build_kpasswd_request` and the `RequestOptions` it was built with,
instead of a raw `kadmin::Request` and a reply key:

| v0.2.2 | Now |
| --- | --- |
| `exchange_kpasswd_result(protocol, addr, &kadmin::Request, &EncryptionKey)` | `exchange_kpasswd_result(protocol, addr, &BuiltKpasswdRequest, &RequestOptions)` |
| `exchange_kpasswd_result_with_config(config, protocol, realm, &kadmin::Request, &EncryptionKey)` | `exchange_kpasswd_result_with_config(config, protocol, realm, &BuiltKpasswdRequest, &RequestOptions)` |

The address no longer needs `Clone` (FU-TRN-08). Both helpers now
authenticate the AP-REP, use the server's subkey when it selects one, and
check the reply's freshness, sequence number, addresses and that it is not
the reflected request. After the request may have been delivered, every
decryption, validation or unsigned-result failure is wrapped exactly once in
`error::Client::KpasswdOutcomeUnknown`. An unsigned refusal is no longer a
definite failure: it is
`KpasswdOutcomeUnknown(Client::Kadmin(Kadmin::UnauthenticatedRejection { code, text_raw }))`,
with the code and the raw bytes kept. Only an authenticated rejection that
passes the context checks is a definite `Kadmin::PasswordChangeFailed`. The
raw `kadmin::Reply::decrypt_result` still only decrypts.

```rust
# #[cfg(feature = "tokio")]
# {
use core::net::SocketAddr;

use rskrb5_ng::client::kpasswd::{BuiltKpasswdRequest, RequestOptions};
use rskrb5_ng::client::transport::{KdcProtocol, Tokio};
use rskrb5_ng::error::{Client, Kadmin};

/// `Some(true)`: changed; `Some(false)`: definitely refused; `None`: unknown.
async fn change(
    transport: &Tokio,
    addr: SocketAddr,
    request: &BuiltKpasswdRequest,
    options: &RequestOptions,
) -> Result<Option<bool>, Client> {
    match transport
        .exchange_kpasswd_result(KdcProtocol::Tcp, addr, request, options)
        .await
    {
        Ok(result) => Ok(Some(result.is_success())),
        Err(Client::Kadmin(Kadmin::PasswordChangeFailed { .. })) => Ok(Some(false)),
        // The password may have changed: reconcile (for example with a fresh
        // login) before retrying, never retry blindly.
        Err(Client::KpasswdOutcomeUnknown(_cause)) => Ok(None),
        Err(other) => Err(other),
    }
}
# }
```

Failures before the request was sent keep their definite error classes, and
a local request time with a fractional second or `cusec` of 1,000,000 or more
is `Client::Encode` (FU-TRN-01).

### Runtime crypto policy (FU-CFG-04, FU-CFG-05, FU-CRY-01, FU-SVC-R04, FU-DOC-21)

`crypto::CryptoPolicy` is an immutable permission snapshot built with
`CryptoPolicy::from_libdefaults(&LibDefaults)` (or `TryFrom`); its `Default`
is the secure `DEFAULT` list `[20, 19, 18, 17]` with RC4 and DES3 disabled.
`policy.check_use(etype, crypto::Use::…)` checks a wire enctype before it is
used as a request entry, reply key, session key, ticket key, acceptor ticket,
acceptor subkey, imported credential or checked low-level operation, and
returns `error::Policy::EnctypeNotPermitted { etype, usage }` (or a permanent
`RejectedFeature`). Rebuild the snapshot after changing the configuration;
public `LibDefaults` fields are staging values, not permission. The policy
itself is described in [`security-policy.md`](security-policy.md#policy).

The three enctype relations are parsed as `config::EnctypeExpr`, MIT's
ordered list language: `DEFAULT`, the families `aes`, `des3`, `rc4` and
`camellia`, and left-to-right `+`/`-` terms. This replaces the earlier
behaviour that skipped families, `DEFAULT` and `-name`:

| Input | Before | Now |
| --- | --- | --- |
| unknown name (`typo-enctype`) | skipped | `error::Config::UnknownEnctype { token }` |
| RC4/DES3 name without `allow_rc4`/`allow_des3` | skipped | `error::Config::DisabledEnctype { token }` |
| single DES, RC4 export or another permanently refused name | skipped | `error::Config::RejectedEnctype { token, source }` |
| Camellia | skipped | skipped with a `ConfigDiagnostic` in `ParseMode::Compatible`; `error::Config::UnsupportedSecureEnctype` in `ParseMode::Strict` |
| `-name` | ignored | removes the entry; removing never needs permission |
| nothing left | `NoUsableEnctypes` / `NoPermittedEnctypes` | `error::Config::EmptyEnctypeExpression` |
| `allow_weak_crypto = true` | accepted | `error::Config::Policy(Policy::RejectedFeature { feature: WeakCrypto, .. })` |

`token` is the original spelling, prefix included. `NoUsableEnctypes` and
`NoPermittedEnctypes` are removed. A request list without an explicit value
inherits the permitted list.

```rust
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use rskrb5_ng::config::Config;
use rskrb5_ng::crypto::{CryptoPolicy, Use};
use rskrb5_ng::error::{Config as ConfigError, Policy};

let config = Config::parse(
    "[libdefaults]\n permitted_enctypes = DEFAULT -aes128-cts-hmac-sha1-96\n",
)?;
assert_eq!(config.libdefaults.permitted_enctype_ids(), [20, 19, 18]);
let policy = CryptoPolicy::from_libdefaults(&config.libdefaults)?;
policy.check_use(18, Use::SessionKey)?;
assert!(matches!(
    policy.check_use(17, Use::SessionKey),
    Err(Policy::EnctypeNotPermitted { etype: 17, .. })
));

let unknown = Config::parse("[libdefaults]\n default_tkt_enctypes = aes typo-enctype\n");
assert!(matches!(unknown, Err(ConfigError::UnknownEnctype { token }) if token == "typo-enctype"));
let disabled = Config::parse("[libdefaults]\n default_tgs_enctypes = rc4-hmac\n");
assert!(matches!(disabled, Err(ConfigError::DisabledEnctype { token }) if token == "rc4-hmac"));
let empty = Config::parse("[libdefaults]\n permitted_enctypes = aes -aes\n");
assert!(matches!(empty, Err(ConfigError::EmptyEnctypeExpression)));
# Ok(())
# }
```

`allow_rc4` and `allow_des3` permit a family; they do not insert names into
the request or permitted lists (FU-DOC-05). An RC4 enctype is used only when
`allow_rc4` is set and RC4 is a member of the permitted list, and it is
requested only when it is also in the request list. Read the effective lists
with the derived-ID methods `default_tkt_enctype_ids()`,
`default_tgs_enctype_ids()` and `permitted_enctype_ids()`:

```rust
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use rskrb5_ng::config::Config;

// The family is enabled, but no list names RC4: nothing changes.
let enabled = Config::parse("[libdefaults]\n allow_rc4 = true\n")?;
assert_eq!(enabled.libdefaults.default_tkt_enctype_ids(), [20, 19, 18, 17]);
assert!(!enabled.libdefaults.permitted_enctype_ids().contains(&23));

// Enabled and listed: RC4 is permitted and requested, after the AES entries.
let listed = Config::parse(
    "[libdefaults]\n allow_rc4 = true\n permitted_enctypes = DEFAULT rc4-hmac\n",
)?;
assert_eq!(listed.libdefaults.permitted_enctype_ids(), [20, 19, 18, 17, 23]);
assert_eq!(listed.libdefaults.default_tkt_enctype_ids(), [20, 19, 18, 17, 23]);
# Ok(())
# }
```

`Config::parse_with_mode(input, ParseMode)` selects the mode;
`config::ParseMode::Compatible` is what `Config::parse` uses.
`Config::diagnostics()` returns `&[ConfigDiagnostic]`, and
`LibDefaults::diagnostics()` returns `Cow<[ConfigDiagnostic]>` (call
`.as_ref()` to match on a slice); diagnostics are not serialized. Draft-9
preauthentication types are ignored with `ConfigDiagnostic::IgnoredPreauthType`
in compatible mode and are an error in strict mode.

The `safe_checksum_type` default is 15 (was 8), and a permanently refused
checksum selection fails with a typed `RejectedFeature` instead of the
removed `error::Config::UnsupportedDirective`. Serde input is checked the
same way: a refused enctype, checksum or weak-crypto selection fails
deserialization through the format's own error, carrying the typed
`error::Policy` text.

### Permanent rejections and `error::Policy` (FU-DOC-21)

`error::Policy::RejectedFeature { feature, reason }` reports a feature this
crate refuses permanently. `error::RejectedFeature` names it (`SingleDes`,
`KerberosV4`, `V4Conversion`, `RsaPkinit`, `Draft9Pkinit`, `Rc4Export`,
`UnauthenticatedChecksum { id }`, `UnprotectedPasswordChange`, `WeakCrypto`;
each variant links its section of `security-policy.md`), and
`error::RejectionReason` (`RemovedAndInsecure`, `InsecureByDesign`,
`MissingAuthentication`) explains it. `RejectionReason` is not an error
source: match the enums, not the text. `error::Any`, `error::Config`,
`error::Crypto`, `error::Ccache`, `error::Kadmin`, `error::KrbErrorCodec` and
`error::Messages` have a `Policy` variant; every other domain error converts with `From<Policy>`
through its crypto (or, for `error::Http`, SPNEGO) variant, so `?` works
everywhere.

`Pac::verify` and `Pac::verify_server_checksum` return `error::Pac::Crypto`
with `Policy::RejectedFeature` (`SingleDes`, `WeakCrypto`, `Rc4Export`) for a key
of enctype 1 to 6, 8 or 24, before the server checksum is examined (v0.2.2:
`Ok(false)`, so `verify` returned `ServerChecksumVerificationFailed`). Code that
treats `Ok(false)` as "not authentic" and every other error as an
infrastructure failure must handle this case.
`CredentialsInfo::decrypt_credential_data` does the same for such a key when the
credential enctype matches it (v0.2.2: `UnsupportedEncryptionType`) (FU-DOC-R92).

```rust
# fn main() {
use rskrb5_ng::error::{Any, Policy, RejectedFeature, RejectionReason};

let refusal = Policy::RejectedFeature {
    feature: RejectedFeature::WeakCrypto,
    reason: RejectionReason::InsecureByDesign,
};
let any = Any::from(refusal);
assert!(matches!(
    any,
    Any::Policy(Policy::RejectedFeature { feature: RejectedFeature::WeakCrypto, .. })
));
# }
```

### Acceptor enctype policy (FU-SVC-R04)

`service::Validator`, `http::NegotiateLayer` and `http::NegotiateService`
apply a crypto policy, set with `with_crypto_policy(CryptoPolicy)`. The
default is the secure `DEFAULT` list; the `Config`-driven constructors
(`from_default_keytab_name`, `from_default_keytab`) use the configured
permitted list and legacy flags. The ticket and authenticator enctypes are
checked before key lookup and decryption, the ticket session key before PAC
and authenticator work, and the authenticator subkey before replay
admission. **A keytab holding only RC4 keys no longer authorizes RC4 by
itself:** the acceptor needs `allow_rc4` and RC4 in the permitted list.

```rust
# #[cfg(feature = "messages")]
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use rskrb5_ng::config::Config;
use rskrb5_ng::crypto::CryptoPolicy;
use rskrb5_ng::keytab::Keytab;
use rskrb5_ng::service::Validator;

let keytab = Keytab::default();
let config = Config::parse(
    "[libdefaults]\n allow_rc4 = true\n permitted_enctypes = DEFAULT rc4-hmac\n",
)?;
let policy = CryptoPolicy::from_libdefaults(&config.libdefaults)?;
let validator = Validator::new(&keytab).with_crypto_policy(policy);
drop(validator);
# Ok(())
# }
# #[cfg(not(feature = "messages"))]
# fn main() {}
```

`spnego::InitiatorContext` keeps its policy and rejects an excluded AP-REP
subkey.

### Password-derivation minimums (FU-CRY-01)

A KDC-supplied string-to-key iteration count below **4096** (AES-SHA1) or
**32768** (AES-SHA2) is rejected before PBKDF2 with
`error::Policy::S2kIterationsTooLow`. Trusted code can lower a minimum with
`LibDefaults::with_min_s2k_iterations(crypto::s2k::Family, u32) ->
Result<Self, error::Policy>` (1 to 2^24); this weakens resistance to offline
guessing. Text configuration and serde cannot set it; deserialization
restores the defaults. The raw RFC-vector functions are unchanged.

```rust
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use rskrb5_ng::config::LibDefaults;
use rskrb5_ng::crypto::s2k::Family;

let defaults = LibDefaults::new().with_min_s2k_iterations(Family::AesSha1, 1000)?;
assert!(LibDefaults::new().with_min_s2k_iterations(Family::AesSha2, 0).is_err());
drop(defaults);
# Ok(())
# }
```

### Replay cache (FU-SVC-03, FU-SVC-09, FU-SVC-R01)

- `clear_older_than` and `clear_older_than_at` on `ReplayCache` and
  `SharedReplayCache` are renamed `force_clear_older_than[_at]`: they can
  reopen live authenticators. The new `prune_expired` and `prune_expired_at`
  remove only expired records (`usize` on `ReplayCache`,
  `Result<usize, error::Service>` on `SharedReplayCache`).
- `with_max_clock_skew` and `with_shared_replay_cache` on `service::Validator`,
  `http::NegotiateLayer` and `http::NegotiateService` return `Result` (they were
  `Self`). An unused cache the builder owns adopts the new skew; an explicit
  cache whose skew is too small fails here, and raising the window after
  admission has started fails closed.
- Each authenticated client principal may hold at most a share of the cache:
  by default one eighth of the capacity (at least one record). Set it with
  `ReplayCache::with_principal_capacity(usize)`. A principal over its share gets
  `error::Service::ReplayCacheCapacityExceeded { capacity }` with its share as
  `capacity`. Live evidence is never evicted.
- Admission expires records through an ordered index (v0.2.2 expired nothing at
  admission; only an explicit `clear_older_than` scan did) (FU-SVC-04,
  FU-SVC-05).

```rust
# #[cfg(feature = "messages")]
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use core::time::Duration;

use rskrb5_ng::keytab::Keytab;
use rskrb5_ng::service::{ReplayCache, SharedReplayCache, Validator};

let cache = SharedReplayCache::from_cache(
    ReplayCache::with_limits(Duration::from_secs(300), 65_536).with_principal_capacity(1024),
);
let keytab = Keytab::default();
let validator = Validator::new(&keytab)
    .with_max_clock_skew(Duration::from_secs(120))?
    .with_shared_replay_cache(cache.clone())?;
let expired = cache.prune_expired()?;
assert_eq!(expired, 0);
drop(validator);
# Ok(())
# }
# #[cfg(not(feature = "messages"))]
# fn main() {}
```

### Removed configuration twins (FU-CFG-02, FU-CFG-08)

`Config::new`, `Config::parse` and `LibDefaults::new` are environment-free, so
their `*_without_env` twins are gone. Named ambient discovery remains explicit:
`Config::load_from_env` and `Config::load_default` read `KRB5_CONFIG`, and
`LibDefaults::from_env` reads `HOME`.

| Removed | Use |
| --- | --- |
| `config::Config::new_without_env()` | `Config::new()` |
| `config::Config::parse_without_env(input)` | `Config::parse(input)` |
| `config::LibDefaults::new_without_env()` | `LibDefaults::new()` |

`config::parse_supported_enctype_ids` is no longer public; use
`Config::parse` and the derived-ID methods.

### Configuration composition (FU-CFG-01, FU-CFG-03, FU-CFG-06, FU-CFG-07, FU-CFG-09)

`k5login_authoritative` now defaults to true rather than false; its deferred
local-login consumer still grants no authorization. Ticket and renewable
lifetimes use checked MIT intervals: negative totals, overflow, malformed unit
order and trailing garbage are rejected. Zero renewable lifetime disables
renewal. Auto transport uses 1465 for a negative `udp_preference_limit` (v0.2.2:
never UDP first) and caps values above 32700 (v0.2.2: no cap); UDP first at a
request size equal to the limit is as in v0.2.2. Explicit TCP or UDP bypasses
this preference (FU-DOC-R10, FU-DOC-R75).

Configuration now follows MIT profile semantics; the details are in
[`config-profile.md`](config-profile.md) and the generated
[relation catalogue](config-relations.md).

- **First value wins.** A repeated scalar keeps its first value, across files,
  includes, lists and `[domain_realm]` mappings (it was the last). Put the
  value you want first, or remove the duplicate.
- **Finals.** `[section]*`, `subsection* = {`, `}*` and `relation* = value`
  stop later contributions to that scope, within a file and across files.
  Values of `auth_to_local` and `pkinit_cert_match` keep a trailing `*`.
  Application, realm and local-name scopes keep their case.
- **Includes.** Ignored sections no longer share brace state with the rest of
  the file; re-reading a completed source is not a cycle (as in v0.2.2); the
  limits are 256 files (v0.2.2: 64) and 4 MiB in total (v0.2.2: 1 MiB, counted
  over included files only), root files included (FU-DOC-R86).
- **Unknown input.** Unknown sections and relations are diagnostics in
  compatible mode and errors in strict mode. Recognized settings without a
  runtime effect produce `ConfigDiagnostic::NotYetEffective` in compatible mode
  when they do not request tighter security. Unsupported tightening values fail
  with `error::Config::NotYetEffective` in both modes. Strict mode rejects every
  diagnostic; the [relation catalogue](config-relations.md) identifies each case.
- **`[appdefaults]`, `[capaths]`, `[plugins]`.** v0.2.2 skipped these sections.
  They are now parsed into `Config::applications`, `Config::capaths` and
  `Config::plugins` (read with `appdefault`, `appdefault_boolean` and `capath`;
  see [`config-profile.md`](config-profile.md)), and malformed content is
  rejected, so an existing file can stop loading: a `[capaths]` value list that
  mixes `.` with realm names or holds a whitespace token, and an `[appdefaults]`
  subsection nested deeper than application, realm and key, are `InvalidLine`;
  a `[plugins]` control that would disable the encrypted-timestamp mechanism is
  `NotYetEffective` in every mode (FU-DOC-R93).
- **`module`.** `module` directives and relations fail with
  `error::Config::UnsupportedDynamicModule`; no code is loaded.
- `forwardable` and `proxiable` set the request bits, `default_realm` is the
  host fallback, a bare `kdc_default_options` number is decimal (an explicit
  `0x` is hex), a malformed `extra_addresses` entry is `InvalidAddress`, and a
  plain `0` is a valid zero duration.
- A file that cannot be read is `error::Config::File { path, source }` instead
  of a bare `Io`.

New readers mirror gokrb5's: `Config::from_string(&str)` (= `parse`),
`Config::from_path(path)` (= `load`) and `Config::from_reader(impl io::Read)`,
which reads at most 4 MiB.

```rust
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use rskrb5_ng::config::Config;

let text = "[libdefaults]\n default_realm = FIRST.EXAMPLE\n default_realm = SECOND.EXAMPLE\n";
let config = Config::from_reader(text.as_bytes())?;
assert_eq!(config.libdefaults.default_realm, "FIRST.EXAMPLE");
assert_eq!(Config::from_string(text)?.libdefaults.default_realm, "FIRST.EXAMPLE");
assert!(Config::parse("[libdefaults]\n module = /usr/lib/plugin.so:entry\n").is_err());
# Ok(())
# }
```

### Default names (FU-CFG-09)

`default_ccache_name`, `default_keytab_name` and `default_client_keytab_name`
from the profile are expanded once, when a name is resolved, through
`config::parameters::DefaultName::expand` with explicitly gathered facts.
A token whose fact is unavailable (for example `%{username}`, a Windows SID
or an installation directory) is an error; there is no fallback to another
name. The `KRB5CCNAME`/`KRB5_KTNAME`/`KRB5_CLIENT_KTNAME` environment values
keep precedence; their `%{uid}` and `%{euid}` tokens follow "Credential filename
identity tokens".

### Client changes (FU-CLI-01, FU-CLI-06, FU-CLI-12, FU-CLI-16, FU-CLI-17)

- `client::Tokio::spawn_auto_renewal[_with_retry]` return
  `client::auto_renewal::Handle` (`TokioClientAutoRenewal` is now an alias of
  it), which is `#[must_use]`: dropping it cancels the task.
- `Tokio::cache_service_ticket` returns `Result<(), error::Client>`. It and
  `cache_tgt_session` reject a session of another client realm or component
  list with `error::Client::CacheClientMismatch` before changing the cache.
- `error::Client::BlockingRuntimeUnavailable`: the blocking clients refuse to
  run inside an entered Tokio context instead of panicking; use the async
  client there.
- AS/TGS replies that break the requested times or grant unrequested flags
  fail with `error::Client::ReplyTimeConstraint` or `ReplyFlagConstraint`.
  `AsReq`/`TgsReq` gain `clock_skew`, and `BuiltAsReq`/`BuiltTgsReq` gain
  `reply_clock`.
- Explicit renewal of a ticket that is not renewable (or outside its renewal
  window) is `error::Client::TicketNotRenewable`.

```rust
# #[cfg(feature = "tokio")]
# {
use rskrb5_ng::client::{TgsRepSession, Tokio};
use rskrb5_ng::error::Client;

fn insert(client: &mut Tokio, session: TgsRepSession) -> Result<(), Client> {
    client.cache_service_ticket(session)
}
# }
```

### Error types (FU-API-03, FU-API-04, FU-API-05, FU-SPN-R03, FU-SPN-R04)

- `error::Any` gains `Messages(error::Messages)` (feature `messages`) and
  `Http(error::Http)` (feature `http`), so `?` reaches `rskrb5_ng::Result`
  without erasing those causes.
- `source()` now returns the kept cause of `Ccache::DefaultCacheName`,
  `Keytab::DefaultKeytabName`, `Client::DefaultClientKeytabName` (the
  `VarError`), `Spnego::Base64` (the `DecodeError`) and
  `Client::KpasswdOutcomeUnknown` (the boxed `Client`).
- `error::Spnego::Client` holds `Box<error::Client>` (was `String`) and is
  its source.
- Removed variants that nothing constructed: `error::Any::Decode(String)` and
  `error::Config::InvalidIpAddress { line, key, value }`.
- `spnego::MicToken::verify` and `WrapToken::verify` return
  `Result<(), error::Spnego>` instead of `Result<bool, _>`, which was never
  `Ok(false)`: replace `assert!(token.verify(key, usage)?)` with
  `token.verify(key, usage)?`.
- New variants: `error::Spnego::{InvalidFieldOrder, NonminimalLength}`,
  `error::Service::PacClientMismatch`, `error::Kadmin::UnauthenticatedRejection`
  and those named in the sections above.
- `error::Kadmin::Crypto` is the tuple variant `Crypto(error::Crypto)` (v0.2.2:
  `Crypto { message: String }`), and random-source failures, which v0.2.2 also
  reported as `Crypto { message }`, are the new `Random(getrandom::Error)`.
  Replace `Kadmin::Crypto { message }` patterns with `Kadmin::Crypto(source)`
  and match `Kadmin::Random(source)` separately (FU-API-R02, FU-DOC-R57).

```rust
# #[cfg(feature = "http")]
# {
use rskrb5_ng::error::{Any, Http, Messages};

fn widen_messages(error: Messages) -> Any {
    Any::from(error)
}
fn widen_http(error: Http) -> Any {
    Any::from(error)
}
# }
```

### Whole-second AP-REQ timestamps (FU-API-06)

`client::build_ap_req_with_confounder` rejects a timestamp with a fractional
second with `error::Client::Encode`; pass whole seconds and the microseconds
separately. KerberosTime values with a fractional second convert to
`SystemTime` with `TimeOverflow` instead of wrong arithmetic.

### New constructors (FU-API-01, FU-FUZ-02)

`config::Realm::new(String) -> Result`, `ccache::HeaderField::new`,
`ccache::HostAddress::{new, ipv4, ipv6}` and
`service::HostAddress::{new(i32, Vec<u8>), ipv6([u8; 16])}` build values of
these non-exhaustive types. `client::transport::kdc_tcp_record_length([u8; 4],
usize)` validates a KDC TCP record mark.

### Critic-round changes

Rows added by the critic rounds of the follow-up review, by area. Each note
names its register row.

Request option diagnostics (FU-CLI-R13): `AsReq`, `TgsReq`, `ApReq`, and
`TgsRequestParts` print metadata and payload counts/lengths instead of padata,
additional-ticket ciphertext, checksum bytes or confounders. Do not depend on
Debug as a credential serialization format.

Credential field privacy (FU-CLI-R13, FU-TRN-R09, FU-PAC-R09, FU-DOC-R59):
replace direct field reads with same-name getters on client built AS/TGS/AP/FAST
requests, `AsRepSession`, `KdcError`, password frames/build results and
`VerifiedKpasswdApRep`, keytab entries/keys and ccache credentials/authorization
data, `EncryptedData`, `PaForUser`, `PaReqEncPaRep`, `KrbErrorInfo`, PAC containers,
credential and validation records, GSS tokens, initiator options/contexts, service
validation/reply types, and `NegotiateHttpResponse`. Metadata reads likewise use
getters; constructors and `with_*` methods replace struct mutation. A getter
borrows an owned field (`&[u8]`, `&EncryptionKey`, `Option<&T>`) and returns a
`Copy` field (`u32`, `i32`, `SystemTime`, `Option<u32>`) by value. Types the
library only returns (the PAC containers and validation records, `KrbErrorInfo`,
`InitiatorContext`, `NegotiateHttpResponse`, `kadmin::Reply`) have no public
constructor and, apart from the few `set_*` methods they list, no setter: v0.2.2
code that built or edited them through public fields must obtain the value from
the function that returns it (`parse`, `decode_der`, `from_rasn` or the
`build_*` function) instead.
`InitiatorContext` uses `ap_req_ref`, `ap_req_der_ref`, `header_ref`,
`session_key_ref` and `initiator_subkey_ref` for its secret borrows. Other
context metadata uses same-name getters.

For replacement use the type's `set_*` method, or retain the result of its
consuming builder. Session tickets and KDC error payloads take `Zeroizing<Vec<u8>>`;
keys take their existing owning `EncryptionKey`. `KdcError::e_data` is no longer
a public field (v0.2.2: `pub e_data: Option<Vec<u8>>`); build with
`with_e_data(Option<Zeroizing<Vec<u8>>>)` and read with `e_data()`.
`ReferralTgsResult::new` adopts its final
session and referral vector; its fields are private (FU-CLI-R22): borrow them
with `ticket()` and `referral_tgts()`, or take both owners with the consuming
`into_parts()`, which returns `(TgsRepSession, Vec<AsRepSession>)`. Borrowed getters never transfer erasure duties for
the retained owner; callers must erase any copies they make. Dependency-owned
rasn `OctetString` fields remain the residual copies documented in the security
policy, including when a complete ASN.1 message is replaced.

```rust
# #[cfg(feature = "messages")]
# fn migrate() {
use std::time::UNIX_EPOCH;
use rskrb5_ng::{client::{AsRepSession, KdcError, principal::Principal}, keytab::EncryptionKey};
use zeroize::Zeroizing;
let mut session = AsRepSession::new(
    Principal::user("EXAMPLE.COM", "alice"), Principal::tgt_service("EXAMPLE.COM"),
    EncryptionKey::new(17, vec![0x11; 16]), Zeroizing::new(vec![0x22; 16]),
    [0; 4], UNIX_EPOCH, UNIX_EPOCH,
);
session.set_ticket(Zeroizing::new(vec![0x33; 16]));
session.set_session_key(EncryptionKey::new(17, vec![0x44; 16]));
let _borrowed_ticket = session.ticket();
let error = KdcError::new(UNIX_EPOCH, 0, 25, Principal::tgt_service("EXAMPLE.COM"))
    .with_e_data(Some(Zeroizing::new(vec![0x55; 16])));
let _borrowed_error_data = error.e_data();
# }
```

Configured password operations (FU-TRN-R10): public discovery, raw forwarding
and checked result helpers apply whole-config admission. Remove prohibited
selectors such as `kpasswd_cleartext`; refusal occurs before delivery and is a
local `Client::Config` error, not `KpasswdOutcomeUnknown`.

Proxy evidence (FU-CLI-R14): the explicit evidence argument is now the first
additional ticket even when `TgsReq::with_additional_tickets` supplies others.
Those other tickets keep their relative order after the evidence. No call-site
change is required.

Uncompressed claims (FU-PAC-R10): `ClaimsSetMetadata::decoded_claims_set_bytes`
now returns `ClaimsDecompressedSizeMismatch` when NONE-compression metadata
declares a different decoded size. Producers must supply the actual byte count;
matching empty and nonempty streams remain accepted.

#### Configuration

Address aliases (FU-CFG-R01): the first occurrence of either `no_addresses`
or `noaddresses` wins (v0.2.2: the last). A final marker on either spelling
closes both; an initial false value cannot be repaired by a later true
alias.

Section structure (FU-DOC-R38): v0.2.2 selected a section from `[name]` while
ignoring any text after `]`, trimmed the name, accepted `[]` and an unterminated
`[name`, ignored relations and other text before the first section, and dropped
a section that followed a byte order mark. The reader now rejects structure it
used to ignore: `junk` or `default_realm = Y` before `[libdefaults]`,
`[libdefaults] junk`, `[]`, `[libdefaults` and a BOM before the first header are
each an `InvalidLine`. A padded `[ libdefaults ]` is no longer trimmed: it names
a different, unknown section (a diagnostic in `ParseMode::Compatible`, an error
in `ParseMode::Strict`). Remove stray text and any BOM from files that relied on
the old behaviour.

Header grammar (FU-DOC-R63): after the closing `]` a header may carry blanks, a
final marker `*` directly after the bracket and a comment separated from it by
blanks. `[libdefaults]*` and `[libdefaults] # c` are headers; `[libdefaults] *`
and `[libdefaults]#c` are an `InvalidLine`, where v0.2.2 accepted all four. A
padded `[ libdefaults ]` followed by `default_realm = X` leaves `default_realm`
empty (v0.2.2: `X`). A commented-out header leaves the relations below it
without a section, so `#[libdefaults]` followed by `default_realm = X` is an
`InvalidLine` (v0.2.2: `default_realm` stayed empty), and so is a file whose
lines end in a bare CR, such as `[libdefaults]\r default_realm = X\r` (v0.2.2:
`default_realm` stayed empty). MIT ignores every line before the first line that
starts with `[` (`prof_parse.c:326`), so for a file that starts with a BOM MIT,
like v0.2.2, ignores the BOM line and the whole body below it, and silently
loses the first section. This crate rejects any non-comment content before the
first header, the BOM line and a stray line such as `garbage line` included,
which is a deliberate divergence from MIT pinned by
`profile_syntax_rejects_malformed_components` (in
`tests/config/mutation_profile.rs`, where `default_realm = R` before any section
must fail).

Subsection syntax (FU-DOC-R64): as in MIT (`prof_parse.c:177`), a value opens a
subsection only when `{` is the whole value, blanks aside. Unlike MIT, a comment
that blanks separate from the brace is allowed too (`A = { # c`; MIT reads that
line as the plain value `{ # c`). `{}`, `{ kdc = k }` and `{#` are plain values,
so `[realms]` with `A = {}` or `A = { kdc = k }` defines no realm (v0.2.2: an
empty realm `A`), and `A = {#` followed by `kdc = k` and `}` is an `InvalidLine`
because the `}` has nothing to close (v0.2.2: realm `A` with the KDC `k`; MIT
fails with `PROF_EXTRA_CBRACE`, `prof_parse.c:128`). `A = { # c` still opens the
subsection. A closing brace may be followed only by blanks, a `*` or a comment
that blanks separate from it: `} junk` is an `InvalidLine`. A relation name
cannot contain blanks, so the realm line `A B = {` is an `InvalidLine` (v0.2.2:
realm `A B`).

Unclosed braces (FU-DOC-R64): a subsection that is still open at the end of a
file or at the next section header is an `InvalidRealmsSection`, in every
section including unknown ones; the variant name does not name the section.
`[libdefaults]` with `default_realm = {` at the end of the file is that error
(v0.2.2: the value `{`). A `}` at the end of a value line is value text and
closes nothing: v0.2.2 counted braces anywhere on a `[realms]` line, so
`kdc = k }` closed the realm and the KDC became `k }`, while this crate keeps
the subsection open and fails. MIT accepts an unclosed `x = {` at the end of a
file (`profile_parse_file`, `prof_parse.c:418-436`, never checks the group
level); this crate rejects it, a deliberate divergence (FU-CFG-09). Nesting
deeper than eight levels is an `IncludeTooDeep` error; v0.2.2 had no limit.

Lines the old reader skipped (FU-DOC-R64): v0.2.2 read nothing inside an unknown
section, so `[foo]` followed by `not a relation` and then `[libdefaults]` loaded
normally; the unknown section is parsed as well, and a line that is not a
relation, brace or comment is an `InvalidLine`. A plain `A = kdc.example` or
`A = x` line in `[realms]`, even after a realm block, is ignored, where v0.2.2
failed with `InvalidRealmsSection` (section names are case-insensitive, so
`[Realms]` follows the same rule). A brace subsection in
`[libdefaults]` or `[domain_realm]` (`sub = {` over several lines) is accepted
and sets nothing, where v0.2.2 failed with `InvalidLine` on the closing `}`.

Empty relation names (FU-DOC-R65): a relation with an empty name is an
`InvalidLine`: ` = X`, `* = A` (the final marker leaves an empty name) and a
realm line ` = {`. v0.2.2 ignored ` = X` in `[libdefaults]`, stored the literal
key `*` for `* = A` in `[domain_realm]` and created a realm with an empty name
for ` = {`. MIT rejects ` = X` (a line that starts with `=`,
`prof_parse.c:152`) but accepts `* = A`: it strips the `*` and stores a node
with an empty name that nothing matches (`prof_parse.c:203`). This crate rejects
every empty name, a deliberate rule stricter than MIT because its data model
cannot represent one (todo 92 decision).

Repeated realms (FU-DOC-R66): a realm defined twice merges. In one `[realms]`
section `A = {` with `kdc = k1` followed by a second `A = {` with `kdc = k2`
gives one realm with the KDCs `k1` and `k2`; v0.2.2 kept two entries and
`Config::realm("A")` returned the first one, `k1`. A realm in two `[realms]`
sections merges likewise (`a`, then `b`); v0.2.2 let the later section replace
the earlier one, so only `b` survived and a realm named only in the earlier
section was lost.

Preauthentication types and boolean spellings (FU-DOC-R40, FU-DOC-R70):
`LibDefaults::preferred_preauth_types` defaults to `[17, 16]` (v0.2.2:
`[17, 16, 15, 14]`); 14 and 15 are the draft-9 PKINIT IDs, which are permanently
rejected, so an explicit value drops them too: `preferred_preauth_types = 14`
is `[]` (v0.2.2: `[14]`) and `17,14,15,16` is `[17, 16]` (v0.2.2:
`[17, 14, 15, 16]`). Boolean relations also accept `on`, `off` and `nil` like
MIT, in any letter case; v0.2.2 accepted only `1`, `t`, `true`, `y`, `yes` and
`0`, `f`, `false`, `n`, `no` (case-insensitively) and reported `InvalidBoolean`
for any other spelling, so `forwardable = on` failed there.

Numeric and interval values (FU-DOC-R69, FU-DOC-R71): `kdc_default_options` is a
signed 32-bit decimal integer, or hexadecimal with a `0x` or `0X` prefix, and
keeps the 32-bit pattern. `010` is 10 (v0.2.2: 0x10, 16), `-1` is every bit set
(v0.2.2: `InvalidInteger`), `2147483647` and `0X1F` are accepted (v0.2.2:
`InvalidInteger`), and `abc`, `1e3` and `0b11` are an `InvalidInteger` (v0.2.2
read bare text as hex digits, so `abc` was 0xabc). `clockskew` uses the same
checked MIT interval parser as `ticket_lifetime` and `renew_lifetime`, where
v0.2.2 used a lenient reader for all three: `clockskew = 1h1h` (v0.2.2: 7200 s),
`1 d` (86400 s), `+300`, `1m1h` (3660 s) and `99999999999` are an
`InvalidDuration`, as is any value of 2^31 seconds or more. As in MIT's
`x-deltat.y`, a component after the first may carry a sign when the total is
nonnegative, so `1h-1m` is 3540 s (v0.2.2: `InvalidDuration`).

Quoted values (FU-CFG-R02): v0.2.2 had no quote handling, so
`default_realm = "EXAMPLE.COM"` kept the quotes in the value and a backslash
was literal text. The profile reader now removes the quotes and decodes `\n`,
`\t` and `\b`; any other escaped character stands for itself, so `\"` and `\\`
yield `"` and `\`. Drop any code that trimmed the quotes itself. Spaces, tabs
and newlines inside quotes are now literal content, including at the edges. Remove accidental quoted whitespace
from credential paths. Unquoted assignment padding continues to be ignored, but
only ASCII whitespace (space, tab, CR, LF, VT, FF) counts as padding; Unicode
space characters are now value data (FU-CFG-R23). For the same reason a
Unicode space before an inline `#` or `;` no longer starts a comment
(FU-CFG-R27); only ASCII whitespace does. This is a special case of a wider
change: v0.2.2 cut every line at the first `#` or `;` anywhere
(`default_realm = A#B` was `A`), whereas a comment now starts only at line
start or after C-locale ASCII whitespace outside quotes, so `A#B` keeps every
byte and `A #B` is `A` in both. Add whitespace before a trailing comment marker
that has none. Text after a closing quote other than
ASCII whitespace is now an `InvalidLine`: v0.2.2 kept `"EXAMPLE.COM" extra`
verbatim, MIT ignores the text after the quote, and this crate rejects it
(FU-CFG-R31, `docs/config-profile.md`). A value that opens a double quote and
never closes it is an `InvalidLine` (FU-DOC-R68): `default_realm = "X` was the
value `"X` in v0.2.2.

Address lists (FU-CFG-R30, FU-DOC-R25): `extra_addresses` entries are split on
commas and on C-locale ASCII whitespace (space, tab, CR, LF, VT, FF), like MIT.
v0.2.2 split on commas only, so `1.2.3.4 5.6.7.8` was one unparsable part that
was dropped silently; it now yields both addresses, and a malformed entry is an
`InvalidAddress`. `spake_preauth_groups` separators are exactly MIT's
`" \t\r\n,"`; form feed and vertical tab are token bytes and fail as unknown
group names (FU-CFG-R32).

Endpoint stars (FU-CFG-R03): `kdc = "host*"` denotes literal `host*`, not a
final relation. Use `kdc* = host` to finalize. An unquoted `kdc = host*` also
finalizes, as it did in v0.2.2; see the next paragraph for other relations.

Value-final star (FU-DOC-R67): a trailing `*` on an unquoted value marks the
relation final for every relation, and the `*` is dropped from the value, so
`default_realm = X*` and `default_realm = X *` are `X` and `forwardable = true*`
is `true`. v0.2.2 honoured `value*` only in the `kdc`, `admin_server`,
`master_kdc` and `kpasswd_server` lists; elsewhere it kept the `*`
(`default_realm` was `X*`) and rejected `true*` as `InvalidBoolean`. The
rule-language relations `auth_to_local` and `pkinit_cert_match` keep a trailing
`*`. Quote the value to keep a literal star: `default_realm = "X*"` is `X*`.

Subsections (FU-CFG-R04): in realms, appdefaults, plugins and capaths, an empty
assignment now expects an opening brace on the next structural line. Use `""`
for an explicitly empty scalar there. Empty libdefaults/domain_realm values
retain the crate's existing scalar extension.

Restrictive settings (FU-CFG-R05): serde and programmatic configurations now
receive the same refusal for unsupported restrictions as profile input. Runtime
client/service/request boundaries revalidate mutable fields before effects.
Unset these settings until their documented plan-2 consumer exists; text and
client admission return `NotYetEffective`, while infallible request options
retain an invalid-policy error for the eventual build.

Discarded selectors (FU-CFG-R06): quoting or escaping a forbidden RSA, draft-9,
v4 or unprotected-password selector cannot hide it in an ignored profile scope.
Permanent rejection checks the decoded scalar before composition discards it.

Timestamp restriction diagnostics (FU-CFG-R07): the deferred package for
`disable_encrypted_timestamp` is `plan 2 WP-07` for runtime/serde admission, as
for text parsing. Plugin `disable` and `enable_only` are WP-16.

Profile braces (FU-CFG-R08): `name =` followed by `{` has the same subsection
meaning as `name = {` in every section, matching MIT's generic profile grammar.
Unknown and deferred sections reach their normal diagnostics. Quoted empty
strings are scalars; the existing unquoted empty-scalar extension remains
available outside mandatory subsection sections when no brace follows.

Realm restriction values (FU-CFG-R09): `disable_encrypted_timestamp` accepts only
`Value::Boolean(Toggle::Disabled)` or an absent entry. The enabled restriction is
unsupported; Text, List, Choice and Locations return `InvalidBoolean` naming
the relation at runtime admission and serde deserialization. Do not encode
Boolean settings in the Text variant.

Realm selectors (FU-CFG-R10): `Realm::relations` and programmatic
`protocol_relations` are checked before configured discovery. Enabling removed
protocols returns the same `Policy::RejectedFeature` as text parsing;
typed serde uses its native error envelope. Lists and locations are invalid
selector variants. Disabled controls remain accepted; certificate paths are
not protocol selectors. Remove prohibited selections rather than moving them
to a typed or programmatic map.

Include ordering (FU-CFG-R11): an unquoted empty scalar before an `include` or
`includedir` now wins over later values just like `""`. If the included value
should win, remove the earlier empty assignment. The next parent structural line
can open a subsection after intervening includes; included files are parsed with
their own grammar state (v0.2.2 spliced them into the parent's stream; see
"Included sources" below).

Include parsing (FU-CFG-R12): repeated includes rescan a comment tail only when
resolving a pending scalar. This step itself changes no precedence, accepted
syntax or include limit; the include changes of this chapter (the source rules
below) do need a check of existing files.

Include depth (FU-CFG-R15): an `includedir` reached at depth 9 now returns
`IncludeTooDeep` even when the directory is empty or holds only ignored files.
Keep include chains within eight levels.

Include directories and non-UTF-8 files (FU-CFG-R33, FU-CFG-R34): an
`includedir` entry that is a directory is skipped, as in MIT, instead of failing
the whole configuration with `IncludeFile` (`IsADirectory`; for an entry that
points to a directory already being read, `IncludeCycle`). An `includedir`
directive that names such a directory is still `IncludeCycle`. A top-level file
that is not UTF-8 text is `error::Config::File` with kind `InvalidData` (v0.2.2:
`Io`); an included file that is not UTF-8 is still `IncludeFile`.

Included sources (FU-DOC-R83): every included file, and every file of a
`KRB5_CONFIG` list or of `Config::load_paths`, is parsed as its own source that
starts outside every section. A relation before its first section header is an
`InvalidLine`; v0.2.2 spliced the text into one stream and read such lines into
the section that was open at the `include` or at the end of the previous file,
and MIT ignores them. Start the file with a section header or move the lines
into the parent. After an `include` or `includedir` the including file continues
in the section it was in before the directive (v0.2.2: in the section where the
included text ended). An `include` or `includedir` line inside a brace
subsection now runs at its position; v0.2.2 ran a directive only outside a
subsection (`InvalidLine` in a `[realms]` subsection, not run in other
sections).

Path lists (FU-DOC-R83): a directory passed to `Config::load` or
`Config::load_paths`, or listed in `KRB5_CONFIG`, is read like an `includedir`
directory (v0.2.2: an `Io` error). A file of a list that another file of the
same list includes is read twice (v0.2.2: `IncludeCycle`). A missing or
unreadable entry of a list is still an error, as in v0.2.2, where MIT skips it;
the variant is now `File` (v0.2.2: `Io`). A directory of the list that cannot
be listed is `IncludeDir` (v0.2.2: `Io`), not `File` (FU-DOC-R90).

Include limits (FU-DOC-R86): the include byte budget is 4 MiB (v0.2.2: 1 MiB)
and the root counts against it. A root file or root text over 4 MiB, alone or
with the files it includes, is `IncludeTooLarge`; v0.2.2 read a root of any size
and counted only included files. The file limit is 256 (v0.2.2: 64). Any file
with a byte that is not UTF-8 is refused as a whole, as in v0.2.2 (MIT reads
bytes).

#### Client, transport and kpasswd

KRB-ERROR UTF-8 causes (FU-API-R01): `KrbErrorCodec::InvalidString` now contains
`core::str::Utf8Error`, available through `Error::source()` and preserving
`valid_up_to()`/`error_len()`. Construct it from the original error, not its text.

Kadmin causes (FU-API-R02): replace `Crypto { message }` matches with
`Crypto(source)` and handle `Random(source)` separately. Both expose typed
`Error::source()` chains; post-delivery unknown-outcome classification follows
"Unknown password-mutation outcome" above.

Client credential buffers (FU-CLI-R02): `BuiltAsReq::der`, `BuiltTgsReq::der`,
`BuiltApReq::der`, `TgsFastRequestParts::ap_req_der` and `AsRepSession::ticket`
are now `zeroize::Zeroizing<Vec<u8>>`. Pass an owning zeroizing buffer to
`BuiltAsReq::new`, `BuiltTgsReq::new` and `AsRepSession::new`; use `.into()`
on an existing owned vector to transfer it without copying. Slice borrows
continue to work. A deliberate `.to_vec()` copy is caller-erased. Their
`Debug` output, including nested referral/FAST results, keeps metadata and
lengths only. Dependency-owned ASN.1 copies remain residuals as documented
in [the security policy](security-policy.md#residual-copies).

Explicit authenticator times (FU-CLI-R03): pass whole seconds and a separate
microsecond value from 0 through 999999 to PA/TGS/AP builders. Fractions and
out-of-range microseconds now return `error::Client::Encode`; whole-second
pre-epoch timestamps remain supported.

Keytab diagnostics (FU-CLI-R05) now report usable enctypes for the exact client
realm and ordered components, not every principal in that realm. Provision keys
for that client when missing-key diagnostics appear; advisory name type does
not affect selection.

Session service identity (FU-CLI-R06): keep `AsRepSession::service` consistent
with the encoded ticket realm and ordered server components. Relabeling a
ticket now fails cache admission or AP construction with
`error::Client::ServicePrincipalMismatch`; advisory name-type changes remain
accepted. Legacy infallible ccache import skips rejected entries.
Fallible `try_from_ccache` and file-loading constructors return the mismatch
before constructing the client.

Direct AS processing (FU-CLI-R07): include the reply-key enctype in the AS
request's offered list. `process_as_rep` and its exchange callers now return
`EnctypeNotRequested` for an unoffered reply wrapping type even when the
session-key type was offered. This restriction does not apply to TGS wrapping.

Explicit AP checksums (FU-CLI-R08): `client::build_ap_req_with_confounder`
rejects checksum IDs 1 through 10 and 14 with
`Client::Crypto(Crypto::Policy(Policy::RejectedFeature { .. }))`, identifying
`RejectedFeature::UnauthenticatedChecksum`. Select a supported keyed checksum
or the protocol's GSS checksum instead. No unkeyed fallback is performed.

TGT identity (FU-CLI-R09): use exactly two components, `krbtgt` and a nonempty
destination realm. `KRBTGT`, extra components and empty destinations are not
TGTs and return `InvalidTgtSession` from TGT insertion/renewal. Cross-realm
`krbtgt/B@A` and advisory name types remain supported. Ccache classification
and referral processing use the same exact identity rule.

TGS subkey replies (FU-CLI-R11): retain the returned `TgsFastRequestParts`
and pass `authenticator_subkey`, not the TGT session key, to the existing
reply processor. The built request records RFC 4120 usage 9; requests without
a subkey continue to use usage 8. `BuiltTgsReq::new` constructs metadata for
requests without a subkey; use the subkey builders for subkey-bearing requests.
The public `reply_key_usage: TgsReplyKey` metadata distinguishes `Session`
from `Subkey`; manually constructed metadata must match the authenticator.
This completes the existing TGS path, not FAST armor negotiation.

```rust,no_run
# #[cfg(feature = "messages")]
# fn complete(parts: &rskrb5_ng::client::TgsFastRequestParts, reply: &[u8]) -> Result<(), rskrb5_ng::error::Client> {
let session = rskrb5_ng::client::process_tgs_rep(
    parts.request(), reply, parts.authenticator_subkey(),
)?;
drop(session);
# Ok(())
# }
```

Preauthentication hint framing (FU-CLI-R12): each ETYPE-INFO/ETYPE-INFO2 octet
string must contain exactly one complete DER value. Trailing values, garbage,
and zero padding now return `Client::Decode` naming the hint. Correct malformed
producers rather than relying on prefix decoding; unrelated opaque e-data
keeps its existing handling.

Checked request bytes (FU-CLI-R15): the synchronous and Tokio checked AS/TGS
exchanges compare the built request's DER with the canonical DER encoding of
its `message` and return `error::Client::Encode` before transport when they
differ. `set_message` does not re-encode, and built requests have no DER
setter: after replacing the message, or when assembling metadata by hand, pass
`BuiltAsReq::new`/`BuiltTgsReq::new` the bytes of `kdc_req::encode_as_req`/
`encode_tgs_req` for that same message. `new` starts from the default policy and
reply clock (and session reply usage for TGS), so set those again. Requests from
the crate's builders already match.

Additional TGS tickets (FU-CLI-R16): every ticket passed through
`TgsReq::with_additional_tickets`, S4U evidence included, must use an enctype
the effective policy permits for ticket keys. The builders check it before
checksum or encryption, and checked exchanges check every additional ticket of
a directly built request again. Permit the family (`allow_rc4`/`allow_des3`
plus membership) or obtain an AES ticket instead.

Preauthentication envelopes (FU-CLI-R20): PA-TGS-REQ and PA-ENC-TIMESTAMP data
passed through `with_padata`, or present in a built request, is decoded and its
ticket, authenticator and timestamp enctypes authorized under the effective
policy before cryptography or transport. Malformed or trailing DER in those two
types now fails. PA cookies and unknown PA types stay opaque.

Public KDC discovery (FU-TRN-R11, FU-TRN-R12): `transport::Tokio::discover_kdcs`
now applies the same whole-configuration admission as login, so unsupported
restrictions and non-Boolean realm timestamp restrictions fail before endpoint
selection or DNS.

Checked kpasswd transport now enforces crypto policy before delivery and on
authenticated replies (FU-TRN-R01). `RequestOptions.crypto_policy` is optional
(secure defaults when absent); `BuiltKpasswdRequest.crypto_policy` binds the
non-configured checked exchange. Configured exchanges use their configuration
snapshot. A disallowed server subkey after delivery means
`KpasswdOutcomeUnknown`, not a definite password rejection or safe retry.

Complete password request builders require whole-second timestamps and
microseconds in `0..=999999`, including directly mutated option fields
(FU-TRN-R02). Invalid values return a local `Kadmin::Encode` error; split clock
samples before construction rather than passing fractional timestamps.

For low-level kpasswd construction with legacy keys, set
`RequestOptions.crypto_policy = Some(policy)` with explicit family permission
and membership (FU-TRN-R04). High-level password changes supply their configured
policy automatically. The key's enctype alone never grants legacy permission.

Full-message kadmin errors (FU-TRN-R05): AP-REQ and AP-REP crypto/random failures
now use `Kadmin::Crypto` and `Kadmin::Random`, with their original typed sources,
rather than `Kadmin::Decode`. Update matches that previously treated encryption
failure as malformed input; password delivery-outcome rules follow "Unknown
password-mutation outcome" above.

Configured transport admission (FU-TRN-R06): password and keytab configured
AS-login helpers, including their TGT wrappers, now return the named
`Client::Config(Config::NotYetEffective { .. })` restriction before constructing
preauthentication or contacting a KDC. Programmatically supplied realm
`disable_encrypted_timestamp` and clpreauth restrictions have the same
fail-closed handling as high-level clients.

Checked AS exchange (FU-TRN-R07): `exchange_as_req_with_config` now returns
the named `Config::NotYetEffective` error for unsupported realm and clpreauth
restrictions before discovery or sending a previously built request. Programmatic
configuration has the same admission as configured password/keytab login.

#### Crypto policy

Checked derivation (FU-CRY-R02): `crypto::checked::Etype` snapshots the authorized
family's minimum. Counts below it now return `S2kIterationsTooLow` before PBKDF2.
For trusted count-one vectors, construct a policy from `LibDefaults` with
`with_min_s2k_iterations(Family::AesSha1, 1)` (or AesSha2), or use the explicitly
policy-free raw primitive. The upper work limit applies.

#### SPNEGO, HTTP, service and messages

Request flags (FU-SPN-R18): set or clear `NegTokenInit` request flags with
`set_req_flags(Some(bits))` or `set_req_flags(None)`; the field is private
and encoding validates the BIT STRING.

HTTP clone configuration now checks cache compatibility against the shared
validator under its lock (FU-HTTP-R04). Handle the typed skew error that
`with_shared_replay_cache` returns ("Replay cache" above) even when that clone's
original settings used a smaller window. Lowering a layer's window preserves the
shared cache ceiling.

The Axum example now distinguishes replay infrastructure failures from invalid
credentials (FU-HTTP-R05): expect HTTP 500 and inspect `Arc<error::Http>` in local
response extensions, rather than retrying credentials after an apparent 401.

Use `Validator::from_keytab(keytab)` for an owning service, as the Axum example
now does (FU-HTTP-R06). Do not leak a keytab merely to obtain a static validator.

HTTP configuration admission (FU-HTTP-R07): `NegotiateLayer` and
`NegotiateService` constructors taking `Config` now return
`Policy::InvalidConfiguration` for unsupported restrictive realm or clpreauth
settings, before discovering or loading a keytab. Programmatic configuration
has the same fail-closed admission as direct validators; do not rely on these
constructors silently ignoring a restriction.

Encrypted message padding (FU-MSG-R01): complete decryptors require exact DER
for AES and RC4, and accept only fewer than eight zero padding bytes for DES3.
Previously accepted authenticated surplus bytes now return the family's Decode
error. Remove application-added padding; let the encryption profile supply it.

Retained SPNEGO credentials now use `zeroize::Zeroizing`:
`Krb5MechToken.message`, `NegTokenInit.{mech_token, mech_list_mic}`,
`NegTokenResp.{response_token, mech_list_mic}`, and
`InitiatorContext.{ap_req_der, header}` (FU-SPN-R05). These fields are private
in 0.3.0 (see the field-privacy rules above). Replace a value with
`set_message`, `set_mech_token`, `set_mech_list_mic` or `set_response_token`,
converting an owned vector with `.into()`, or build the token with
`Krb5MechToken::new` or `NegTokenResp::with_response_token`. Read with the
same-name getters, or with `ap_req_der_ref()` and `header_ref()`, which return a
plain slice and `&str`; `InitiatorContext` has no setter (FU-DOC-R98). Token and
pending response diagnostics show metadata and lengths, never credential
contents. Plain vectors and strings returned by encoding/header convenience APIs
still require caller erasure after use.

Consuming GSS constructors erase adopted plaintext even when key selection fails
(FU-SPN-R07). No call-site change is required; passing a zeroizing owner remains
the preferred way to retain erasure responsibility across the call boundary.

SPNEGO reqFlags contents must include an unused-bit count from 0 to 7, with zero
padding bits and a payload when the count is nonzero (FU-SPN-R08), at most 32
significant bits, and no trailing zero bits beyond the unused-bit count
(FU-SPN-R19, FU-DOC-R99). Malformed values now return `Spnego::InvalidReqFlags`
on encode and decode; `[0]` remains valid.

Treat `with_ap_rep(false)` as an optional-reply preference (FU-SPN-R09). A valid
initiator mechListMIC receives a completion carrying a reciprocal MIC and the
AP-REP that binds its sequence number. First-choice exchanges without a MIC
retain the no-reply behavior.

Accepted-context reply policy (FU-SPN-R10): `ValidatedApReq.crypto_policy`
retains the validator's policy. Its AP-REP builder and SPNEGO/HTTP response
helpers reject excluded wrapping keys and server subkeys with a typed policy
error before encoding or invoking a protected handler. Configure legacy opt-in
and permitted membership on the validator; the default is AES-only. Raw
`ap_rep` codecs remain policy-free vector APIs.

Token staging (FU-SPN-R11): token encoding and header parsing now erase their
internal credential buffers, including nested DER allocations and error exits.
Header encoding avoids a separate base64 string. Public returned `Vec<u8>` and
`String` signatures are unchanged; callers must still erase those returned
credentials and their own copies after use.

Reciprocal MIC policy (FU-SPN-R12): changing a validated context's initiator subkey
does not bypass its retained policy. Supply permitted keys, or explicitly configure
legacy permission and membership before use. An explicit acceptor subkey takes
precedence; completion verification also admits its selected key.

Service reply verification (FU-SPN-R13): `ValidatedApReq::verify_ap_rep` rejects
excluded wrapping keys and acceptor subkeys with a typed policy error. Retain
an explicitly permitted policy when interoperating with legacy keys; raw AP-REP
codecs still leave policy admission to their caller.

Credential staging (FU-SPN-R14): completion MIC verification now owns its encoded
offer through erasure on both success and failure. The Axum example similarly
adopts the returned header into `Zeroizing<String>` before HTTP conversion.
Callers of raw encoders still own erasure of their returned buffers.

Round 4 secret handling (FU-SPN-R15, FU-TRN-R08): internal plaintext staging
and credential serialization allocate before copying secrets; unknown-length
serde payloads erase old storage during growth. Partially generated reply keys
and random confounders now retain erasing ownership on errors. Raw returned
buffers remain the caller's erasure responsibility; signatures are unchanged.

Reply policy errors (FU-SPN-R16): random AP-REP header construction and the
configured HTTP keytab constructors preserve `Policy::RejectedFeature` causes.
Inspect the error source chain rather than expecting `UnsupportedEtype` or
`InvalidConfiguration` for permanently forbidden selections.

Tickets must supply at most one PAC across their authorization-data tree
(FU-SVC-R05). Duplicate PACs now return `UnsupportedAuthorizationData { kind: 128 }`
before replay admission; issuers must remove duplicates, not rely on first-PAC selection.

#### Credential files and PAC

Ccache diagnostics (FU-FIL-R02): Debug no longer exposes primary/second ticket,
configuration-value or authorization payload bytes, including nested CCache
formatting. Use explicit borrowed fields only where needed; never log them.

Version-one keytabs (FU-FIL-R03): nonzero principal name types cannot be saved
in that format and now return `error::Keytab::UnrepresentableNameType`.
Use version two to preserve the value, or explicitly choose name type zero.
Version-one ccaches follow the same rule (FU-FIL-R07): the refusal is
`error::Ccache::UnrepresentableNameType` (v0.2.2 dropped the value silently).

Keytab file formats (FU-DOC-R87): the enctype of a keytab entry is a signed
16-bit field, so serialization now accepts IDs -32768 to -1 (v0.2.2:
`error::Keytab::LengthOverflow`) and rejects IDs 32768 to 65535 with
`LengthOverflow` (v0.2.2 wrote them, and the parser reads them back as negative
IDs). `Keytab::add_entry_from_password`, `_name` and `_ref` reject single-DES (1
to 4, 8), RC4-EXP (24) and weak (5, 6) enctypes with `error::Keytab::Crypto`,
where v0.2.2 returned `UnsupportedEtype`. A 1-3 byte fragment where the next
entry size should start is `Truncated`; v0.2.2 and MIT (`fread` in
`kt_file.c:918-920`) treat it as the end of the table, so a keytab cut short by
a crashed writer must be repaired before it is read.

Ccache file formats (FU-DOC-R87): `ccache::HeaderField::new` is fallible. It
returns `InvalidHeaderField` for tag 1 with a value that is not 8 bytes and
`LengthOverflow` for a value over 65535 bytes, where v0.2.2 accepted any struct
literal and checked only when a version 4 cache was serialized. A version-1
ccache whose principal component count is 0 or the minimum `i32` is still
rejected, but 0.3 reports `LengthOverflow` and `NegativeLength` respectively
where v0.2.2 reported `NegativeLength` and `LengthOverflow`. A `DIR:` collection
whose `primary` file is a symlink, existing or dangling, fails with `Io` of kind
`InvalidInput` when the name is resolved; v0.2.2 followed the link: it read an
existing target and created the target of a dangling link (FU-DOC-R95).

Ccache payload ownership (FU-FIL-R05): `Credential.ticket`, `second_ticket` and
`AuthorizationDataEntry.data` are `Zeroizing<Vec<u8>>`. Pass zeroizing buffers to
`Credential::new`, `with_second_ticket`, `config_entry`, `upsert_config_entry`
and `AuthorizationDataEntry::new`; convert a moved vector with `.into()` and
borrow with `.as_slice()`. Payload owners erase on drop, replacement and parse
failure. `Credential` and `AuthorizationDataEntry` now implement Drop; borrow
their fields or use `core::mem::take` rather than moving fields out. Binary and serde byte encodings are unchanged.
Caller-owned serialized output and borrowed source buffers remain the caller's
erasure responsibility.

Key replacement (FU-FIL-R06, FU-DOC-R53): `keytab::EncryptionKey` and
`ccache::EncryptionKey` had public `etype: i32` and `value: Vec<u8>` fields in
v0.2.2. Both fields are private on both types: read them with `etype()` and
`value()`, which returns `&keytab::key_bytes::Bytes`. That type
erases its allocation on replacement/drop and exposes only read-only bytes.
Constructors accept an owned `Vec<u8>` or `Zeroizing<Vec<u8>>` without copying.
Replace vector mutation with a new owner. Any
explicit `to_vec()` copy remains the caller's erasure responsibility.

```rust
use rskrb5_ng::keytab::EncryptionKey;
use zeroize::Zeroizing;
let mut key = EncryptionKey::new(18, Zeroizing::new(vec![0x11; 32]));
key.set_value(Zeroizing::new(vec![0x22; 32]));
assert_eq!(key.value().as_slice(), &[0x22; 32]);
```

AuthorizationData wrapper contents must contain exactly one DER value
(FU-PAC-R01). Trailing values or garbage now return the existing service Decode
or PAC DerDecode error; remove the suffix rather than relying on prefix decoding.

PAC versions (FU-PAC-R02): only version zero is supported. Nonzero versions
now return `error::Pac::InvalidPacVersion(u32)` before buffer processing.

RPC strings in PACs (FU-PAC-R04): a null pointer is valid only when logical
length is zero. Nonempty null strings return `error::Pac::MissingNdrPointer`;
maximum capacity and legitimate nonnull termination slack remain supported.

PAC allocation admission (FU-PAC-R05): truncated claims/group/string arrays
fail with `Truncated` before reservation. Valid counts up to the existing
one-million-element ceiling remain accepted when the wire extent is present.

PAC key ownership (FU-PAC-R06): use `user_session_key.as_bytes()` to borrow
the sixteen-byte key; construct replacements with
`pac::session_key::SessionKey::new(Zeroizing::new(bytes))`. The key is no longer
implicitly copied. `Pac::data` and `zero_signature_data` are zeroizing vectors;
slice borrowing is unchanged. Caller-created copies and borrowed parser input
remain the caller's erasure responsibility. Debug emits metadata/lengths,
never the key or raw PAC buffers.

PAC credential replacement (FU-PAC-R09): `NtlmSupplementalCredential` now
exposes `version()`, `flags()`, `lm_password()` and `nt_password()` instead of
public fields. Hash access borrows arrays. Use `set_lm_password` or
`set_nt_password` with `Option<Zeroizing<[u8; 16]>>`; setters erase the old hash
before assignment and update the validity bit. `CredentialsInfo` exposes
`version()`, `encryption_type()` and `encrypted_credential_data()`; replace its
private zeroizing payload with `set_encrypted_credential_data`. Supplemental
packages expose `package_name()`, `credential_size()` and `credentials()`;
`set_credentials(Zeroizing<Vec<u8>>)` checks the new wire size, erases the old
payload and updates the size. Their Debug output omits credential bytes.

```rust
use rskrb5_ng::pac::NtlmSupplementalCredential;
use zeroize::Zeroizing;
let mut wire = vec![0; 4];
wire.extend_from_slice(&3_u32.to_le_bytes());
wire.extend_from_slice(&[0x11; 32]);
let mut credential = NtlmSupplementalCredential::parse(&wire)?;
credential.set_nt_password(Some(Zeroizing::new([0x22; 16])));
credential.set_lm_password(None);
assert_eq!(credential.nt_password(), Some(&[0x22; 16]));
assert!(!credential.has_lm_password());
# Ok::<(), Box<dyn std::error::Error>>(())
```

Password frame ownership (FU-TRN-R09): `BuiltChangePasswordRequest::der` and
`BuiltKpasswdRequest::der` are `Zeroizing<Vec<u8>>`; borrow them as slices for
transport and use `.into()` when supplying an owned replacement. Debug for
password request/reply frames and built results now prints metadata only.

#### Gates, tests and tooling

Release automation must pass a valid commit to `find-tag` (FU-CI-R01). Invalid
objects and Git lookup failures now exit nonzero; only verified untagged commits
produce the successful no-dispatch result.

Package links (FU-CI-R03): multiline Markdown destinations and unquoted HTML
`href`/`src` attributes participate in package-membership validation.
Correct missing/excluded local destinations or use an existing repository URL.

Reference links (FU-CI-R04): multiline Markdown reference definitions receive
the same package-membership checks as inline links. Fix missing or excluded
destinations even when the destination follows the definition label on a new line.

Gate wiring accepts only the sanctioned fail-closed command blocks
(FU-GATE-R01). Keep required CI commands as direct run steps and prek commands
in the success-dependent chain; shell wrappers that merely mention them fail.

Workflow wiring (FU-GATE-R02): quoted YAML keys obey the same restrictions as
plain keys, and `lint-gates` must have exactly one `steps` mapping with no
duplicate step keys. Remove conditional or overriding execution settings;
textually retaining a required command does not satisfy these cases.

Lint interpreter admission (FU-GATE-R03): workflow/job/step environment settings
must use the gate allowlist (`PYTHONDONTWRITEBYTECODE=1`, and workflow-level
`CARGO_TERM_COLOR=always`). PATH, Python startup/optimization, shell startup,
shell/default overrides and unapproved setup action inputs are rejected.

Mutation evidence (FU-GATE-R04): each whole-crate campaign shard must retain
one successful baseline and a nonempty `mutants.json` with the exact tested
mutant names. Rerun filtered, baseline-free or incomplete shards; an end time
and matching counts alone do not certify completeness.

Workflow syntax (FU-GATE-R05): use plain identifier keys or unescaped quoted
identifiers. Escaped keys, explicit complex keys, mapping aliases, anchors and
merge forms are refused by the shared execution reader. Keep gate mappings in
the supported block form rather than relying on alternate YAML spellings.

Lint job environment (FU-GATE-R06): run the gates directly on the configured
runner. Container, service and options settings are rejected, including Docker
environment options; retaining the command text is not proof of its execution.

Package audits (FU-GATE-R07): run both parity manifest audit targets from a
repository checkout. Neither is shipped as a package integration-test entry
point, because they require development scripts and other excluded evidence.

Local lint hook (FU-GATE-R08): retain system language, `pass_filenames = false`,
the pre-push/manual stages and the documented source-file pattern. Global file
filters and unsupported hook applicability settings fail wiring admission.

Mutation campaigns (FU-GATE-R09): provide a positive shard count and disjoint
inventories. Mutant outcomes must be caught, missed, timed out or unviable;
baseline-only Success and unknown summaries do not certify tested mutations.

The gated integration runner now gives explicitly supplied test-time fixture
variables precedence over its saved environment (FU-TST-R07). Omit a variable
to reuse the saved value; explicit empty values also override it.

AD keytab overrides must contain complete records and a correctly sized supported
key for the named fixture principal (FU-TST-R09). Header-only placeholders no
longer pass strict preflight; structural readiness still does not prove a live login.

AD preflight (FU-TST-R13): usable keytab entries must precede the zero-length
terminator. Regenerate an override whose only key follows that terminator;
negative-length deleted slots are skippable, matching the Rust loader.

Parity evidence (FU-TST-R14): symbol claims must resolve to the declared module
and actual impl owner. Comments, string contents and child-local same-named
types cannot prove a parent method; explicit parent paths are supported.

Parity scopes (FU-TST-R15): declarations inside inline modules cannot serve as
symbol evidence. Cite a supported out-of-line public API; private, restricted
and public inline children are all conservatively excluded from this scanner.

## Non-exhaustive types and constructors

Public structs and enums are non-exhaustive. Construct values through their
constructors or builders instead of struct literals. External enum matches
must handle every known variant explicitly and include a final fallback for
future variants. Matches within the library remain exhaustive. A struct pattern
outside the crate needs a trailing `..`, and a unit struct such as
`crypto::Rc4HmacEtype` is built with `new()` or `Default` (see the construction
map). Some of these types have no public constructor at all, because the
library only returns them: `ccache::ConfigEntry`, `ccache::CredentialMetadata`,
`client::BuiltApReq`, `client::TgsFastRequestParts`,
`client::kpasswd::{BuiltKpasswdRequest, VerifiedKpasswdApRep}`,
`kadmin::BuiltChangePasswordRequest`, `keytab::EntryMetadata`,
`messages::PrincipalNameInfo`, `http::NegotiateHttpResponse`,
`service::{ValidatedApReq, VerifiedApRep}`, `spnego::AcceptedContext`, most PAC
records (`pac::{Sid, SidAndAttributes, RpcUnicodeString, InfoBuffer,
ClaimEntry, ClaimsArray, DomainGroupMembership, AdCredentials}` among them) and
the `evaluation::data` report records. v0.2.2 code that built them with a struct
literal (test data, for example) has no replacement constructor: obtain the
value from the function that returns it, or, for a PAC record, from the wire
bytes through `pac::Pac::parse` (FU-DOC-R60).

External construction by struct literal is rejected, including struct update
syntax:

Stable rustdoc accepts any compilation error in a `compile_fail` block; it does
not check the annotated error code. Use
`cargo +nightly-2026-10-03 test --doc --all-features` to check that this example
fails specifically with E0639, rather than an unrelated compilation error.

```compile_fail,E0639
use rskrb5_ng::config::LibDefaults;

let defaults = LibDefaults {
    default_realm: "EXAMPLE.COM".to_owned(),
    ..LibDefaults::default()
};
```

Use the builder path instead:

```rust
use rskrb5_ng::config::LibDefaults;

let defaults = LibDefaults::default().with_default_realm("EXAMPLE.COM".to_owned());
assert_eq!(defaults.default_realm, "EXAMPLE.COM");
```

### Construction map

All constructor arguments retain the corresponding public field's meaning.
Builders consume and return the value. Fields that stay public, such as those of
`config::LibDefaults`, `config::Config` and `ccache::CredentialTimes`, remain
readable and writable; the types named under "Credential field privacy" and in
"Private fields of option and result types" below no longer have public fields.
`Option` builders accept the complete `Option<T>`, including
`None`, unless an existing method explicitly accepts the payload directly.

| Type | Construction path |
| --- | --- |
| `ccache::EncryptionKey`, `keytab::EncryptionKey` | `new(etype, value)` |
| `ccache::Principal`, `keytab::Principal`, `client::principal::Principal` | Existing `new(realm, name_type, components)` |
| `service::Principal` | `new(realm, name_type, components)` |
| `ccache::AuthorizationDataEntry` | `new(ad_type, data)` |
| `ccache::Credential` | `new(client, server, key, times, ticket_flags, ticket)`; `with_is_skey`, `with_addresses`, `with_auth_data`, `with_second_ticket` |
| `ccache::CredentialTimes` | Existing `Default`; then set the public fields |
| `keytab::Entry` | `new(principal, timestamp, kvno8, key, kvno)` |
| `client::BuiltAsReq` | `new(message, der, client, service, nonce)` |
| `client::BuiltTgsReq` | `new(message, der, client, service, kdc_realm, nonce)` |
| `client::AsRepSession` and alias `TgsRepSession` | `new(client, service, session_key, ticket, ticket_flags, auth_time, end_time)`; `with_start_time`, `with_renew_till`, `with_key_expiration`. The initial start time equals `auth_time`. |
| `client::PreauthKeyInfo` | `new(etype)`; `with_salt`, `with_s2kparams` |
| `client::KdcError` | `new(stime, susec, error_code, service)`; `with_ctime`, `with_cusec`, `with_text`, `with_client`, `with_e_data`, `with_method_data`, `with_preauth_key_info` |
| `client::PrunedSessions` | Existing `Default`; `with_primary_tgt`, `with_tgt_sessions`, `with_service_tickets` |
| `config::LibDefaults` | `Default` and `new` are environment-free (`new_without_env` was removed); use `from_env()` explicitly for HOME discovery. Use `with_<field>` for public fields, or the derived ID methods described above. |
| `config::Config` | Existing `new`/`Default` or config parsing; modify public fields after construction |
| `config::Realm` | `Realm::new(realm) -> Result` (new; rejects an empty name; v0.2.2 had no public constructor) or config parsing; modify public fields after construction |
| `service::ApRepOptions` | Existing `Default`; `with_subkey`, `with_sequence_number`, `with_kvno` |
| `messages::EncryptedData` | `new(etype, cipher)`; `with_kvno` |
| `messages::PaReqEncPaRep` | `new(checksum_type, checksum)` |
| `pac::ClaimsInfo` | `new(metadata, claims_set)` |
| `pac::GroupMembership` | `new(relative_id, attributes)` |
| `spnego::MicToken` | `new(flags, snd_seq_num)` (also in v0.2.2) or `Default`; `with_flags`, `with_snd_seq_num`, `with_checksum` and `with_payload` (also in v0.2.2) |
| `spnego::WrapToken` | `new(flags, snd_seq_num)` (also in v0.2.2) or `Default`; `with_flags`, `with_ec`, `with_rrc`, `with_snd_seq_num`, `with_checksum`, `with_encrypted_body` and `with_payload` (also in v0.2.2) |
| `crypto::Rc4HmacEtype`, `crypto::Des3CbcSha1KdEtype` | `new()` or `Default` instead of bare unit-struct values |
| `kadmin::ChangePasswordResult` | Existing `parse(bytes)`; results are decoded, not synthesized |
| Other decoded message, PAC, metadata, and context views | Existing decode/parse/build operations; no literal construction |

Existing request-option and context-option constructors/builders remain the
construction paths for `AsReq`, `TgsReq`, `ApReq`,
`RequestOptions`, `EncKrbPrivPartOptions`, `ChangePasswdMessageOptions`,
and `InitiatorContextOptions`. Existing token constructors remain available for
`NegTokenInit`, `NegTokenResp`, and `Krb5MechToken`.

### Private fields of option and result types (FU-DOC-R50, FU-DOC-R51, FU-DOC-R52)

These public structs of v0.2.2 have only private fields in 0.3.0. Each field has
a same-name getter; replace direct writes as follows.

- `client::options::{AsReq, TgsReq, ApReq}` (v0.2.2: `AsReqOptions`,
  `TgsReqOptions`, `ApReqOptions`): read `now()`, `ticket_lifetime()`,
  `renew_lifetime()`, `nonce()`, `etypes()`, `kdc_option_bits()` and `padata()`;
  `AsReq` adds `assume_preauthentication()` and `fast_negotiation()`, `TgsReq`
  adds `additional_tickets()`, and `ApReq` has `ap_option_bits()`, `checksum()`,
  `subkey()` and `sequence_number()`. `etypes()`, `padata()` and
  `additional_tickets()` return slices where v0.2.2 had `Vec` fields, and
  `checksum()` and `subkey()` return `Option<&T>`. Set the values with the
  `with_*` builder of the same name (`with_etypes`, `with_padata`,
  `with_kdc_option_bits`, `with_ticket_lifetime`, `with_renew_lifetime` and the
  type-specific ones). `now` and `nonce` are arguments of `new` and
  `from_libdefaults`, and only `AsReq` has `set_now` and `set_nonce`: build a
  new `TgsReq` to change them.
- `service::ApRepOptions`: read `subkey()`, `sequence_number()` and `kvno()`;
  set them with `with_subkey`, `with_sequence_number` and `with_kvno` on the
  value that `Default` returns.
- `kadmin::ChangePasswdData`: read `targ_name()` and `targ_realm()` (both
  `Option` borrows) and `new_passwd()`, which returns the redacted
  `&kadmin::password::Bytes` where v0.2.2 had a public `OctetString`. Build the
  value with `new` or `for_target`, and replace the password with
  `set_new_passwd`.


## Password argument type

`Tokio::{change_password, change_password_for, change_password_with_options,
change_password_for_with_options}` accepted an `impl AsRef<[u8]>` argument.
They now take a `client::Password` by value ("Owned passwords").

## Signature changes

### Earlier compliance passes

The lifetime parameter on `service::Validator`, `http::NegotiateLayer`,
and `http::NegotiateService` is named `'keytab` instead of `'a`; the Tower
`Service` implementation uses an anonymous lifetime. The lifetime names carry no
caller impact. The Tower `Service::Future` of `http::NegotiateService` is a
different type, though (FU-DOC-R61): v0.2.2 declared `type Future =
Pin<Box<dyn Future<Output = Result<Response<ResBody>, TowerError<S::Error>>>>>`,
which was never `Send`, and 0.3.0 declares `http::NegotiateFuture<S::Future,
ResBody, S::Error>`, a concrete future that is `Send` when the inner future,
body and error are. Code that names `<NegotiateService<_> as
Service<_>>::Future` as the boxed type, or stores `call` results in a
`Pin<Box<dyn Future>>` field without boxing them, must change;
`Box::pin(service.call(request))` still produces the boxed form.
`http::{challenge_response, reject_response}` retain their generic `B: Default`
bound, now written in a where-clause.

The earlier pass added `#[must_use]` to these public APIs:

- `http::NegotiateLayer::{new, require_client_address, with_ap_rep,
  with_ap_rep_options, with_client_address, with_keytab_principal,
  with_max_clock_skew, with_now, with_reject_invalid, with_shared_replay_cache,
  without_shared_replay_cache}`;
- `http::NegotiateService::{require_client_address, with_ap_rep,
  with_ap_rep_options, with_client_address, with_keytab_principal,
  with_max_clock_skew, with_now, with_reject_invalid, with_shared_replay_cache,
  without_shared_replay_cache}`;
- `service::Validator::{new, require_client_address, shared_replay_cache,
  with_client_address, with_keytab_principal, with_max_clock_skew, with_now,
  with_shared_replay_cache, without_shared_replay_cache}`;
- `evaluation::render_markdown`.

The earlier pass also made these public APIs `const fn`:

- `service::Validator::{with_now, require_client_address,
  shared_replay_cache, replay_cache_mut}`;
- `http::NegotiateLayer::{with_now, require_client_address, with_ap_rep,
  with_reject_invalid}`;
- `http::NegotiateService::{inner, inner_mut, with_ap_rep, with_reject_invalid}`.

Since FU-SVC-09, `with_max_clock_skew` (on `service::Validator`,
`http::NegotiateLayer` and `http::NegotiateService`) and
`with_shared_replay_cache` return `Result` ("Replay cache" under the follow-up changes).

The four password-change methods listed above took an `impl AsRef<[u8]>`
argument in v0.2.2 and now take `client::Password`. The other argument-position
`impl Trait` parameters of this pass become independent named generics with the
same bounds; ordinary calls keep type inference, and callers may now explicitly
name these type arguments using turbofish syntax. Two cases differ (FU-DOC-R55,
FU-DOC-R56):

- `client::principal::Principal::new` and `keytab::Principal::new` already had
  the named parameters `<I, S>` next to their `impl Into<String>` realm. The
  realm is now the third named parameter, `new<I, S, P>(realm: P, ...)`, so a
  call that names the existing arguments, `Principal::new::<I, S>(...)`, no
  longer compiles. Name all three (`new::<I, S, P>`) or let inference choose.
- The payload of `spnego::MicToken::new_initiator` and of
  `WrapToken::{new_initiator, new_initiator_sealed,
  new_initiator_sealed_with_confounder}` changed bound as well:
  `P: Into<Zeroizing<Vec<u8>>>` replaces `impl Into<Vec<u8>>`. Only `Vec<u8>`
  and `Zeroizing<Vec<u8>>` satisfy it, so a `&[u8]`, `&str`, `String` or array
  payload no longer compiles: turn it into a `Vec<u8>` first (`.to_vec()`,
  `.into_bytes()`).
  `with_payload` keeps `P: Into<Vec<u8>>`.

### API pass B call-site migration

- Eleven of the twelve boolean option fields of `config::LibDefaults` in v0.2.2
  now use `config::Toggle::{Disabled, Enabled}`, and the new `with_*` builders
  take a `Toggle`. Read an option with `is_enabled()`, or convert a boolean with
  `Toggle::from_bool` / `From<bool>`. The twelfth, `dns_canonicalize_hostname`
  (`bool` in v0.2.2, where the profile value `fallback` was an `InvalidBoolean`
  error), is the enum `config::hostname::Canonicalization` with `Never`,
  `Always` and `Fallback`, so `if cfg.libdefaults.dns_canonicalize_hostname` no
  longer compiles. Six new `Toggle` options join them: `allow_rc4`,
  `allow_des3`, `dns_uri_lookup`, `enforce_ok_as_delegate`,
  `client_aware_channel_bindings` and `permitted_enctypes_explicit`
  (FU-DOC-R39).
  Both direct serde and gokrb5 JSON snapshots retain boolean representations; a
  missing `permitted_enctypes_explicit` means disabled.
- `config::Realm::realm` is now `name`. Serialized field names remain unchanged.
- `client::{kpasswd::build_kpasswd_request, kpasswd::build_kpasswd_request_with_confounders}` borrow
  their `RequestOptions`; `service::ValidatedApReq::build_ap_rep_with_confounder`
  and the corresponding SPNEGO response-header helpers borrow `ApRepOptions`.
- `client::build_tgs_req_for_realm_with_confounder_and_subkey` now takes
  `(tgt, kdc_realm, service, parts)`. Build `parts` with
  `TgsRequestParts::new(options, confounder, subkey).with_timestamp(timestamp, cusec)`.
  The constructor defaults to `options.now` and zero microseconds; pass the same
  explicit timestamp and microseconds as before to reproduce an existing request.
- `kadmin::build_change_password_message_with_confounders` groups its final three
  encryption inputs into `PasswordEncryption::new(reply_key, ap_req_confounder,
  krb_priv_confounder)`; their order and meaning are unchanged.
- Unused receivers became associated functions with the original public names.
  Use `Type::function(args)` instead of `value.function(args)` for the functions
  listed below. Runtime-dispatched `KerberosEtype` methods keep their receivers.
- Newly `#[must_use]` functions require callers to handle their results. Newly
  `const fn` functions work at runtime as before and may also be used in constant
  expressions. No runtime behavior or error text is changed.

### Auto traits and `Copy` (FU-DOC-R58)

`service::Validator`, `http::NegotiateLayer` and `http::NegotiateService`
implemented `UnwindSafe` and `RefUnwindSafe` in v0.2.2 (the last one when its
inner service `S` did) and implement neither in 0.3.0: each now carries an
`Arc<dyn TransitValidator>` (the new transit-validator setting), and that trait
has no unwind-safety bound. Code that passes a reference to one of them into
`std::panic::catch_unwind` must wrap it in `std::panic::AssertUnwindSafe`.
`pac::GroupMembership`, `pac::InfoBuffer` and `ccache::CredentialTimes`
additionally implement `Copy`; this changes no call, but a caller's own blanket
trait impl that overlaps `Copy` types can now conflict.

### Complete public function inventory for API pass B

The following inventory includes all public signature and must-use changes in
this pass, including const eligibility exposed by the other signature changes.
Generic parameter names are explicit; each where-clause retains the former
argument's independent bound. Items are listed by their defining paths: the
module-local re-exports were removed, and only the crate-root facade
re-exports remain ("Renamed paths" below). The inventory is a snapshot of API
pass B; "Follow-up review changes" above supersedes the entries it changes
(password methods and `ChangePasswdData`, the replay-cache builders, the
kpasswd result helpers, `MicToken::verify`/`WrapToken::verify` and others).

#### New must-use contracts

- `ap_req::ap_options_from_bits`.
- `ap_req::ap_options_to_bits`.
- `ccache::CacheName::file_path`.
- `ccache::CacheName::into_file_path`.
- `ccache::CCache::new`.
- `ccache::CCache::version`.
- `ccache::CCache::header`.
- `ccache::CCache::default_principal`.
- `ccache::CCache::client_realm`.
- `ccache::CCache::client_name`.
- `ccache::CCache::credentials`.
- `ccache::CCache::entries`.
- `ccache::CCache::config_entry_value`.
- `ccache::CCache::contains_server`.
- `ccache::CCache::get_entry`.
- `ccache::Principal::name_string`.
- `ccache::Principal::principal_string`.
- `ccache::Principal::matches_components`.
- `client::kpasswd::RequestOptions::with_recipient_address`.
- `client::negotiate::Client::from_tokio_client`.
- `client::negotiate::Client::with_keytab`.
- `client::negotiate::Client::inner`.
- `client::negotiate::Client::into_inner`.
- `client::options::AsReq::new`.
- `client::options::AsReq::from_libdefaults`.
- `client::options::AsReq::with_ticket_lifetime`.
- `client::options::AsReq::with_renew_lifetime`.
- `client::options::AsReq::with_etypes`.
- `client::options::AsReq::with_kdc_option_bits`.
- `client::options::AsReq::with_padata`.
- `client::options::AsReq::with_assume_preauthentication`.
- `client::options::AsReq::with_fast_negotiation`.
- `client::options::TgsReq::new`.
- `client::options::TgsReq::from_libdefaults`.
- `client::options::TgsReq::with_ticket_lifetime`.
- `client::options::TgsReq::with_renew_lifetime`.
- `client::options::TgsReq::with_etypes`.
- `client::options::TgsReq::with_kdc_option_bits`.
- `client::options::TgsReq::with_padata`.
- `client::options::TgsReq::with_additional_tickets`.
- `client::options::TgsReq::with_renewal`.
- `client::options::ApReq::new`.
- `client::options::ApReq::with_ap_option_bits`.
- `client::options::ApReq::with_checksum`.
- `client::options::ApReq::with_subkey`.
- `client::options::ApReq::with_sequence_number`.
- `client::principal::Principal::name`.
- `client::transport::KdcEndpoint::authority`.
- `client::transport::Tokio::new`.
- `client::transport::Tokio::with_timeout`.
- `client::transport::Tokio::with_udp_response_limit`.
- `client::transport::Tokio::with_tcp_response_limit`.
- `client::TokioClientDiagnostics::is_ok`.
- `client::PrunedSessions::is_empty`.
- `client::TokioClientAutoRenewal::is_finished`.
- `client::Tokio::with_keytab`.
- `client::Tokio::with_password_credential`.
- `client::Tokio::with_keytab_credential`.
- `client::Tokio::from_ccache`.
- `client::Tokio::from_tgt_session`.
- `client::Tokio::with_transport`.
- `client::Tokio::with_assume_preauthentication`.
- `client::Tokio::with_fast_negotiation`.
- `client::Tokio::config`.
- `client::Tokio::protocol`.
- `client::Tokio::client_principal`.
- `client::Tokio::is_configured`.
- `client::Tokio::assume_preauthentication`.
- `client::Tokio::fast_negotiation`.
- `client::Tokio::tgt_session`.
- `client::Tokio::tgt_refresh_due`.
- `client::Tokio::tgt_session_count`.
- `client::Tokio::tgt_session_for_realm`.
- `client::Tokio::cached_service_ticket_count`.
- `client::Tokio::cached_service_ticket`.
- `client::TgsRequestParts<'request>::new`.
- `client::TgsRequestParts<'request>::with_timestamp`.
- `client::default_password_salt`.
- `config::Config::new`.
- `config::Config::realm`.
- `config::Toggle::from_bool`.
- `config::Toggle::is_enabled`.
- `config::LibDefaults::new`.
- `crypto::AesSha1Etype::from_etype_id`.
- `crypto::AesSha1Etype::etype_id`.
- `crypto::AesSha1Etype::checksum_type_id`.
- `crypto::AesSha1Etype::key_len`.
- `crypto::AesSha1Etype::confounder_len`.
- `crypto::AesSha1Etype::hmac_len`.
- `crypto::AesSha1Etype::default_s2kparams`.
- `crypto::AesSha1Etype::string_to_pbkdf2`.
- `crypto::AesSha1Etype::verify_checksum`.
- `crypto::AesSha2Etype::from_etype_id`.
- `crypto::AesSha2Etype::etype_id`.
- `crypto::AesSha2Etype::checksum_type_id`.
- `crypto::AesSha2Etype::ename`.
- `crypto::AesSha2Etype::key_len`.
- `crypto::AesSha2Etype::confounder_len`.
- `crypto::AesSha2Etype::hmac_len`.
- `crypto::AesSha2Etype::default_s2kparams`.
- `crypto::AesSha2Etype::saltp`.
- `crypto::AesSha2Etype::string_to_pbkdf2`.
- `crypto::AesSha2Etype::verify_checksum`.
- `crypto::Des3CbcSha1KdEtype::from_etype_id`.
- `crypto::Des3CbcSha1KdEtype::from_checksum_type_id`.
- `crypto::Des3CbcSha1KdEtype::etype_id`.
- `crypto::Des3CbcSha1KdEtype::checksum_type_id`.
- `crypto::Des3CbcSha1KdEtype::key_len`.
- `crypto::Des3CbcSha1KdEtype::confounder_len`.
- `crypto::Des3CbcSha1KdEtype::hmac_len`.
- `crypto::Des3CbcSha1KdEtype::default_s2kparams`.
- `crypto::Des3CbcSha1KdEtype::verify_checksum`.
- `crypto::Rc4HmacEtype::from_etype_id`.
- `crypto::Rc4HmacEtype::from_checksum_type_id`.
- `crypto::Rc4HmacEtype::etype_id`.
- `crypto::Rc4HmacEtype::checksum_type_id`.
- `crypto::Rc4HmacEtype::key_len`.
- `crypto::Rc4HmacEtype::confounder_len`.
- `crypto::Rc4HmacEtype::hmac_len`.
- `crypto::Rc4HmacEtype::default_s2kparams`.
- `crypto::Rc4HmacEtype::random_to_key`.
- `crypto::Rc4HmacEtype::verify_checksum`.
- `crypto::KerberosEtype::etype_id`.
- `crypto::KerberosEtype::checksum_type_id`.
- `crypto::KerberosEtype::key_len`.
- `crypto::KerberosEtype::confounder_len`.
- `crypto::KerberosEtype::hmac_len`.
- `crypto::KerberosEtype::default_s2kparams`.
- `crypto::KerberosEtype::verify_checksum`.
- `crypto::iterations_to_s2kparams`.
- `crypto::kerb_checksum_hmac_md5`.
- `evaluation::data::Candidate::name`.
- `evaluation::data::Candidate::license`.
- `evaluation::data::DerType::name`.
- `evaluation::data::CandidateAssessment::support_for`.
- `http::NegotiateLayer<'static>::from_keytab`.
- `kadmin::ChangePasswdMessageOptions::with_recipient_address`.
- `kadmin::PasswordEncryption<'request>::new`.
- `kadmin::ChangePasswordResult::is_success`.
- `keytab::Name::file_path`.
- `keytab::Name::into_file_path`.
- `keytab::Keytab::new`.
- `keytab::Keytab::version`.
- `keytab::Keytab::entries`.
- `keytab::Entry::system_time`.
- `keytab::Principal::default_password_salt`.
- `keytab::Principal::name_string`.
- `keytab::Principal::principal_string`.
- `krb_priv::EncKrbPrivPartOptions::with_timestamp`.
- `krb_priv::EncKrbPrivPartOptions::with_sequence_number`.
- `krb_priv::EncKrbPrivPartOptions::with_recipient_address`.
- `krb_priv::ipv4_host_address`.
- `krb_priv::ipv6_host_address`.
- `messages::PaPacOptions::from_bits`.
- `messages::PaPacOptions::bits`.
- `messages::PrincipalNameInfo::name`.
- `pac::Pac::buffer`.
- `pac::NtlmSupplementalCredential::has_lm_password`.
- `pac::NtlmSupplementalCredential::has_nt_password`.
- `pac::DeviceInfo::group_membership_sids`.
- `pac::ClaimValues::len`.
- `pac::ClaimValues::is_empty`.
- `pac::FileTime::from_ticks`.
- `pac::FileTime::ticks`.
- `pac::FileTime::system_time`.
- `pac::KerbValidationInfo::group_membership_sids`.
- `service::Principal::name`.
- `service::HostAddress::ipv4`.
- `service::ReplayCache::new`.
- `service::ReplayCache::len`.
- `service::ReplayCache::is_empty`.
- `service::SharedReplayCache::new`.
- `service::SharedReplayCache::from_cache`.
- `service::Validator<'static>::from_keytab`.
- `spnego::oid::ObjectIdentifier::krb5`.
- `spnego::oid::ObjectIdentifier::ms_legacy_krb5`.
- `spnego::oid::ObjectIdentifier::spnego`.
- `spnego::oid::ObjectIdentifier::arcs`.
- `spnego::oid::ObjectIdentifier::is_kerberos_mechanism`.
- `spnego::MicToken::new`.
- `spnego::MicToken::with_payload`.
- `spnego::WrapToken::new`.
- `spnego::WrapToken::with_payload`.
- `spnego::WrapToken::is_sealed`.
- `spnego::Krb5MechToken::ap_req`.
- `spnego::Krb5MechToken::ap_rep`.
- `spnego::Krb5MechToken::new`.
- `spnego::Krb5MechToken::ap_req_bytes`.
- `spnego::Krb5MechToken::ap_rep_bytes`.
- `spnego::NegTokenInit::krb5`.
- `spnego::NegTokenResp::accept_completed`.
- `spnego::NegTokenResp::accept_incomplete_krb5`.
- `spnego::NegTokenResp::reject`.
- `spnego::NegTokenResp::with_response_token`.
- `spnego::InitiatorContextOptions::new`.
- `spnego::InitiatorContextOptions::with_context_flags`.
- `spnego::InitiatorContextOptions::with_ap_option_bits`.
- `spnego::InitiatorContextOptions::with_subkey`.
- `spnego::InitiatorContextOptions::with_sequence_number`.
- `spnego::challenge_header`.
- `spnego::authenticator_checksum`.

#### Changed or added public signatures

- `ccache::CacheName::parse`: `pub fn parse<P>(name: P) -> Result<Self, Error> where P: AsRef<str>,`.
- `ccache::CCache::load`: `pub fn load<P>(path: P) -> Result<Self, Error> where P: AsRef<Path>,`.
- `ccache::CCache::load_name`: `pub fn load_name<P>(name: P) -> Result<Self, Error> where P: AsRef<str>,`.
- `ccache::CCache::save`: `pub fn save<P>(&self, path: P) -> Result<(), Error> where P: AsRef<Path>,`.
- `ccache::CCache::save_name`: `pub fn save_name<P>(&self, name: P) -> Result<(), Error> where P: AsRef<str>,`.
- `ccache::CCache::version`: `pub const fn version(&self) -> u8`.
- `ccache::CCache::header`: `pub const fn header(&self) -> &Header`.
- `ccache::CCache::header_mut`: `pub const fn header_mut(&mut self) -> &mut Header`.
- `ccache::CCache::default_principal`: `pub const fn default_principal(&self) -> &Principal`.
- `ccache::CCache::default_principal_mut`: `pub const fn default_principal_mut(&mut self) -> &mut Principal`.
- `ccache::CCache::credentials_mut`: `pub const fn credentials_mut(&mut self) -> &mut Vec<Credential>`.
- `ccache::CCache::upsert_config_entry`: `pub fn upsert_config_entry<P>(&mut self, key: P, principal: Option<String>, value: Zeroizing<Vec<u8>>) -> Option<Credential> where P: Into<String>`.
- `ccache::Principal::new`: `pub fn new<P>(realm: P, name_type: i32, components: Vec<String>) -> Self where P: Into<String>,`.
- `ccache::Credential::config_entry`: `pub fn config_entry<P>(client: Principal, key: P, principal: Option<String>, value: Zeroizing<Vec<u8>>) -> Self where P: Into<String>`.
- `client::kpasswd::RequestOptions::new`: `pub const fn new( timestamp: SystemTime, cusec: u32, sequence_number: u32, sender_address: rasn_kerberos::HostAddress, ) -> Self`.
- `client::kpasswd::build_kpasswd_request_with_confounders`: `pub fn build_kpasswd_request_with_confounders( service_ticket: &TgsRepSession, change_data: &kadmin::ChangePasswdData, reply_key: EncryptionKey, options: &RequestOptions, ap_req_confounder: &[u8], krb_priv_confounder: &[u8], ) -> Result<BuiltKpasswdRequest, Error>`.
- `client::kpasswd::build_kpasswd_request`: `pub fn build_kpasswd_request( service_ticket: &TgsRepSession, change_data: &kadmin::ChangePasswdData, options: &RequestOptions, ) -> Result<BuiltKpasswdRequest, Error>`.
- `client::negotiate::Client::from_tokio_client`: `pub const fn from_tokio_client(client: Tokio) -> Self`.
- `client::negotiate::Client::with_password`: `pub fn with_password<P>(config: Config, client: Principal, password: P) -> Self where P: Into<Vec<u8>>,`.
- `client::negotiate::Client::with_keytab`: `pub const fn with_keytab(config: Config, client: Principal, keytab: Keytab) -> Self`.
- `client::negotiate::Client::with_keytab_name`: `pub fn with_keytab_name<P>( config: Config, client: Principal, keytab_name: P, ) -> Result<Self, Error> where P: AsRef<str>,`.
- `client::negotiate::Client::from_ccache_name`: `pub fn from_ccache_name<P>(config: Config, cache_name: P) -> Result<Self, Error> where P: AsRef<str>,`.
- `client::negotiate::Client::inner`: `pub const fn inner(&self) -> &Tokio`.
- `client::negotiate::Client::inner_mut`: `pub const fn inner_mut(&mut self) -> &mut Tokio`.
- `client::negotiate::Client::authorization_header_for_host`: `pub async fn authorization_header_for_host<P, Q>( &mut self, service: P, host: Q, ) -> Result<String, Error> where P: AsRef<str>, Q: AsRef<str>,`.
- `client::negotiate::Client::authorization_context_for_host`: `pub async fn authorization_context_for_host<P, Q>( &mut self, service: P, host: Q, ) -> Result<InitiatorContext, Error> where P: AsRef<str>, Q: AsRef<str>,`.
- `client::negotiate::Client::change_password`: `pub async fn change_password<P>( &mut self, new_password: P, sender_address: rasn_kerberos::HostAddress, ) -> Result<ChangePasswordResult, Error> where P: AsRef<[u8]>,`.
- `client::negotiate::Client::change_password_for`: `pub async fn change_password_for<P>( &mut self, target: Principal, new_password: P, sender_address: rasn_kerberos::HostAddress, ) -> Result<ChangePasswordResult, Error> where P: AsRef<[u8]>,`.
- `client::negotiate::Client::change_password_with_options`: `pub async fn change_password_with_options<P>( &mut self, new_password: P, options: RequestOptions, ) -> Result<ChangePasswordResult, Error> where P: AsRef<[u8]>,`.
- `client::negotiate::Client::change_password_for_with_options`: `pub async fn change_password_for_with_options<P>( &mut self, target: Principal, new_password: P, options: RequestOptions, ) -> Result<ChangePasswordResult, Error> where P: AsRef<[u8]>,`.
- `client::negotiate::BlockingClient::with_password`: `pub fn with_password<P>(config: Config, client: Principal, password: P) -> Result<Self, Error> where P: Into<Vec<u8>>,`.
- `client::negotiate::BlockingClient::with_keytab_name`: `pub fn with_keytab_name<P>( config: Config, client: Principal, keytab_name: P, ) -> Result<Self, Error> where P: AsRef<str>,`.
- `client::negotiate::BlockingClient::from_ccache_name`: `pub fn from_ccache_name<P>(config: Config, cache_name: P) -> Result<Self, Error> where P: AsRef<str>,`.
- `client::negotiate::BlockingClient::client`: `pub const fn client(&self) -> &NegotiateClient`.
- `client::negotiate::BlockingClient::client_mut`: `pub const fn client_mut(&mut self) -> &mut NegotiateClient`.
- `client::negotiate::BlockingClient::authorization_header_for_host`: `pub fn authorization_header_for_host<P, Q>( &mut self, service: P, host: Q, ) -> Result<String, Error> where P: AsRef<str>, Q: AsRef<str>,`.
- `client::negotiate::BlockingClient::authorization_context_for_host`: `pub fn authorization_context_for_host<P, Q>( &mut self, service: P, host: Q, ) -> Result<InitiatorContext, Error> where P: AsRef<str>, Q: AsRef<str>,`.
- `client::negotiate::BlockingClient::change_password`: `pub fn change_password<P>( &mut self, new_password: P, sender_address: rasn_kerberos::HostAddress, ) -> Result<ChangePasswordResult, Error> where P: AsRef<[u8]>,`.
- `client::negotiate::BlockingClient::change_password_for`: `pub fn change_password_for<P>( &mut self, target: Principal, new_password: P, sender_address: rasn_kerberos::HostAddress, ) -> Result<ChangePasswordResult, Error> where P: AsRef<[u8]>,`.
- `client::negotiate::BlockingClient::change_password_with_options`: `pub fn change_password_with_options<P>( &mut self, new_password: P, options: RequestOptions, ) -> Result<ChangePasswordResult, Error> where P: AsRef<[u8]>,`.
- `client::negotiate::BlockingClient::change_password_for_with_options`: `pub fn change_password_for_with_options<P>( &mut self, target: Principal, new_password: P, options: RequestOptions, ) -> Result<ChangePasswordResult, Error> where P: AsRef<[u8]>,`.
- `client::options::AsReq::with_ticket_lifetime`: `pub const fn with_ticket_lifetime(mut self, ticket_lifetime: Duration) -> Self`.
- `client::options::AsReq::with_renew_lifetime`: `pub const fn with_renew_lifetime(mut self, renew_lifetime: Option<Duration>) -> Self`.
- `client::options::AsReq::with_etypes`: `pub fn with_etypes<P>(mut self, etypes: P) -> Self where P: Into<Vec<i32>>,`.
- `client::options::AsReq::with_kdc_option_bits`: `pub const fn with_kdc_option_bits(mut self, kdc_option_bits: u32) -> Self`.
- `client::options::AsReq::with_padata`: `pub fn with_padata<P>(mut self, padata: P) -> Self where P: Into<Vec<rasn_kerberos::PaData>>,`.
- `client::options::AsReq::with_assume_preauthentication`: `pub const fn with_assume_preauthentication(mut self, assume_preauthentication: bool) -> Self`.
- `client::options::AsReq::with_fast_negotiation`: `pub const fn with_fast_negotiation(mut self, fast_negotiation: bool) -> Self`.
- `client::options::TgsReq::with_ticket_lifetime`: `pub const fn with_ticket_lifetime(mut self, ticket_lifetime: Duration) -> Self`.
- `client::options::TgsReq::with_renew_lifetime`: `pub const fn with_renew_lifetime(mut self, renew_lifetime: Option<Duration>) -> Self`.
- `client::options::TgsReq::with_etypes`: `pub fn with_etypes<P>(mut self, etypes: P) -> Self where P: Into<Vec<i32>>,`.
- `client::options::TgsReq::with_kdc_option_bits`: `pub const fn with_kdc_option_bits(mut self, kdc_option_bits: u32) -> Self`.
- `client::options::TgsReq::with_padata`: `pub fn with_padata<P>(mut self, padata: P) -> Self where P: Into<Vec<rasn_kerberos::PaData>>,`.
- `client::options::TgsReq::with_additional_tickets`: `pub fn with_additional_tickets<P>(mut self, additional_tickets: P) -> Self where P: Into<Vec<rasn_kerberos::Ticket>>,`.
- `client::options::TgsReq::with_renewal`: `pub const fn with_renewal(mut self) -> Self`.
- `client::options::ApReq::new`: `pub const fn new() -> Self`.
- `client::options::ApReq::with_ap_option_bits`: `pub const fn with_ap_option_bits(mut self, ap_option_bits: u32) -> Self`.
- `client::options::ApReq::with_sequence_number`: `pub const fn with_sequence_number(mut self, sequence_number: Option<u32>) -> Self`.
- `client::principal::Principal::new`: `pub fn new<I, S, P>(realm: P, name_type: i32, components: I) -> Self where I: IntoIterator<Item = S>, S: Into<String>, P: Into<String>,`.
- `client::principal::Principal::user`: `pub fn user<P, Q>(realm: P, name: Q) -> Self where P: Into<String>, Q: Into<String>,`.
- `client::principal::Principal::parse_user`: `pub fn parse_user<P>(value: P) -> Result<Self, Error> where P: AsRef<str>,`.
- `client::principal::Principal::parse_service`: `pub fn parse_service<P>(value: P) -> Result<Self, Error> where P: AsRef<str>,`.
- `client::principal::Principal::host_based_service`: `pub fn host_based_service<P, Q>(service: P, host: Q) -> Result<Self, Error> where P: AsRef<str>, Q: AsRef<str>,`.
- `client::principal::Principal::host_based_service_in_realm`: `pub fn host_based_service_in_realm<P, Q, R>( service: P, host: Q, realm: R, ) -> Result<Self, Error> where P: AsRef<str>, Q: AsRef<str>, R: AsRef<str>,`.
- `client::principal::Principal::tgt_service`: `pub fn tgt_service<P>(realm: P) -> Self where P: Into<String>,`.
- `client::transport::Tokio::new`: `pub const fn new() -> Self`.
- `client::transport::Tokio::with_timeout`: `pub const fn with_timeout(mut self, timeout: Duration) -> Self`.
- `client::transport::Tokio::with_udp_response_limit`: `pub const fn with_udp_response_limit(mut self, udp_response_limit: usize) -> Self`.
- `client::transport::Tokio::with_tcp_response_limit`: `pub const fn with_tcp_response_limit(mut self, tcp_response_limit: usize) -> Self`.
- `client::TokioClientDiagnostics::is_ok`: `pub const fn is_ok(&self) -> bool`.
- `client::PrunedSessions::is_empty`: `pub const fn is_empty(&self) -> bool`.
- `client::Tokio::with_password`: `pub fn with_password<P>( config: Config, protocol: KdcProtocol, client: Principal, password: P, ) -> Self where P: Into<Vec<u8>>,`.
- `client::Tokio::with_keytab`: `pub const fn with_keytab( config: Config, protocol: KdcProtocol, client: Principal, keytab: Keytab, ) -> Self`.
- `client::Tokio::with_keytab_name`: `pub fn with_keytab_name<P>( config: Config, protocol: KdcProtocol, client: Principal, keytab_name: P, ) -> Result<Self, Error> where P: AsRef<str>,`.
- `client::Tokio::with_password_credential`: `pub fn with_password_credential<P>(mut self, password: P) -> Self where P: Into<Vec<u8>>,`.
- `client::Tokio::from_ccache_name`: `pub fn from_ccache_name<P>( config: Config, protocol: KdcProtocol, cache_name: P, ) -> Result<Self, Error> where P: AsRef<str>,`.
- `client::Tokio::save_ccache`: `pub fn save_ccache<P>(&self, path: P) -> Result<(), Error> where P: AsRef<Path>,`.
- `client::Tokio::save_ccache_name`: `pub fn save_ccache_name<P>(&self, cache_name: P) -> Result<(), Error> where P: AsRef<str>,`.
- `client::Tokio::update_ccache_file`: `pub fn update_ccache_file<P>(&self, path: P) -> Result<(), Error> where P: AsRef<Path>,`.
- `client::Tokio::update_ccache_name`: `pub fn update_ccache_name<P>(&self, cache_name: P) -> Result<(), Error> where P: AsRef<str>,`.
- `client::Tokio::with_transport`: `pub const fn with_transport(mut self, transport: Tokio) -> Self`.
- `client::Tokio::with_assume_preauthentication`: `pub const fn with_assume_preauthentication(mut self, assume_preauthentication: bool) -> Self`.
- `client::Tokio::with_fast_negotiation`: `pub const fn with_fast_negotiation(mut self, fast_negotiation: bool) -> Self`.
- `client::Tokio::config`: `pub const fn config(&self) -> &Config`.
- `client::Tokio::protocol`: `pub const fn protocol(&self) -> KdcProtocol`.
- `client::Tokio::client_principal`: `pub const fn client_principal(&self) -> &Principal`.
- `client::Tokio::assume_preauthentication`: `pub const fn assume_preauthentication(&self) -> bool`.
- `client::Tokio::fast_negotiation`: `pub const fn fast_negotiation(&self) -> bool`.
- `client::Tokio::tgt_session`: `pub const fn tgt_session(&self) -> Option<&AsRepSession>`.
- `client::build_tgs_req_for_realm`: `pub fn build_tgs_req_for_realm<P>( tgt: &AsRepSession, kdc_realm: P, service: Principal, options: TgsReq, ) -> Result<BuiltTgsReq, Error> where P: Into<String>,`.
- `client::build_tgs_req_for_realm_with_subkey`: `pub fn build_tgs_req_for_realm_with_subkey<R>( tgt: &AsRepSession, kdc_realm: R, service: Principal, options: TgsReq, ) -> Result<TgsFastRequestParts, Error> where R: Into<String>,`. The realm argument changed from `impl Into<String>` to the named generic `R`.
- `client::build_tgs_req_for_realm_with_confounder`: `pub fn build_tgs_req_for_realm_with_confounder<P>( tgt: &AsRepSession, kdc_realm: P, service: Principal, options: TgsReq, timestamp: SystemTime, cusec: u32, confounder: &[u8], ) -> Result<BuiltTgsReq, Error> where P: Into<String>,`.
- `client::build_tgs_req_for_realm_with_confounder_and_subkey`: `pub fn build_tgs_req_for_realm_with_confounder_and_subkey<R>( tgt: &AsRepSession, kdc_realm: R, service: Principal, parts: TgsRequestParts<'_>, ) -> Result<TgsFastRequestParts, Error> where R: Into<String>,`.
- `client::TgsRequestParts<'request>::new`: `pub const fn new( options: TgsReq, confounder: &'request [u8], subkey: &'request EncryptionKey, ) -> Self`.
- `client::TgsRequestParts<'request>::with_timestamp`: `pub const fn with_timestamp(mut self, timestamp: SystemTime, cusec: u32) -> Self`.
- `config::Config::load`: `pub fn load<P>(path: P) -> Result<Self, Error> where P: AsRef<Path>,`.
- `config::Toggle::from_bool`: `pub const fn from_bool(value: bool) -> Self`.
- `config::Toggle::is_enabled`: `pub const fn is_enabled(self) -> bool`.
- `config::LibDefaults::with_allow_weak_crypto`: `pub const fn with_allow_weak_crypto(mut self, value: Toggle) -> Self`.
- `config::LibDefaults::with_canonicalize`: `pub const fn with_canonicalize(mut self, value: Toggle) -> Self`.
- `config::LibDefaults::with_dns_canonicalize_hostname`: `pub fn with_dns_canonicalize_hostname(mut self, value: Toggle) -> Self`.
- `config::LibDefaults::with_dns_lookup_kdc`: `pub const fn with_dns_lookup_kdc(mut self, value: Toggle) -> Self`.
- `config::LibDefaults::with_dns_lookup_realm`: `pub const fn with_dns_lookup_realm(mut self, value: Toggle) -> Self`.
- `config::LibDefaults::with_forwardable`: `pub const fn with_forwardable(mut self, value: Toggle) -> Self`.
- `config::LibDefaults::with_ignore_acceptor_hostname`: `pub const fn with_ignore_acceptor_hostname(mut self, value: Toggle) -> Self`.
- `config::LibDefaults::with_k5login_authoritative`: `pub const fn with_k5login_authoritative(mut self, value: Toggle) -> Self`.
- `config::LibDefaults::with_no_addresses`: `pub const fn with_no_addresses(mut self, value: Toggle) -> Self`.
- `config::LibDefaults::with_permitted_enctypes_explicit`: `pub const fn with_permitted_enctypes_explicit(mut self, value: Toggle) -> Self`.
- `config::LibDefaults::with_proxiable`: `pub const fn with_proxiable(mut self, value: Toggle) -> Self`.
- `config::LibDefaults::with_rdns`: `pub const fn with_rdns(mut self, value: Toggle) -> Self`.
- `config::LibDefaults::with_verify_ap_req_nofail`: `pub const fn with_verify_ap_req_nofail(mut self, value: Toggle) -> Self`.
- `crypto::AesSha1Etype::from_etype_id`: `pub const fn from_etype_id(etype_id: i32) -> Option<Self>`.
- `crypto::AesSha1Etype::etype_id`: `pub const fn etype_id(self) -> i32`.
- `crypto::AesSha1Etype::checksum_type_id`: `pub const fn checksum_type_id(self) -> i32`.
- `crypto::AesSha1Etype::key_len`: `pub const fn key_len(self) -> usize`.
- `crypto::AesSha1Etype::confounder_len`: `pub const fn confounder_len() -> usize`.
- `crypto::AesSha1Etype::hmac_len`: `pub const fn hmac_len() -> usize`.
- `crypto::AesSha1Etype::default_s2kparams`: `pub const fn default_s2kparams() -> &'static str`.
- `crypto::AesSha2Etype::from_etype_id`: `pub const fn from_etype_id(etype_id: i32) -> Option<Self>`.
- `crypto::AesSha2Etype::etype_id`: `pub const fn etype_id(self) -> i32`.
- `crypto::AesSha2Etype::checksum_type_id`: `pub const fn checksum_type_id(self) -> i32`.
- `crypto::AesSha2Etype::ename`: `pub const fn ename(self) -> &'static str`.
- `crypto::AesSha2Etype::key_len`: `pub const fn key_len(self) -> usize`.
- `crypto::AesSha2Etype::confounder_len`: `pub const fn confounder_len() -> usize`.
- `crypto::AesSha2Etype::hmac_len`: `pub const fn hmac_len(self) -> usize`.
- `crypto::AesSha2Etype::default_s2kparams`: `pub const fn default_s2kparams() -> &'static str`.
- `crypto::Des3CbcSha1KdEtype::from_etype_id`: `pub const fn from_etype_id(etype_id: i32) -> Option<Self>`.
- `crypto::Des3CbcSha1KdEtype::from_checksum_type_id`: `pub const fn from_checksum_type_id(checksum_type_id: i32) -> Option<Self>`.
- `crypto::Des3CbcSha1KdEtype::etype_id`: `pub const fn etype_id() -> i32`.
- `crypto::Des3CbcSha1KdEtype::checksum_type_id`: `pub const fn checksum_type_id() -> i32`.
- `crypto::Des3CbcSha1KdEtype::key_len`: `pub const fn key_len() -> usize`.
- `crypto::Des3CbcSha1KdEtype::confounder_len`: `pub const fn confounder_len() -> usize`.
- `crypto::Des3CbcSha1KdEtype::hmac_len`: `pub const fn hmac_len() -> usize`.
- `crypto::Des3CbcSha1KdEtype::default_s2kparams`: `pub const fn default_s2kparams() -> &'static str`.
- `crypto::Des3CbcSha1KdEtype::string_to_key`: `pub fn string_to_key(secret: &[u8], salt: &[u8], s2kparams: &str) -> Result<Vec<u8>, Error>`.
- `crypto::Des3CbcSha1KdEtype::random_to_key`: `pub fn random_to_key(bytes: &[u8]) -> Result<Vec<u8>, Error>`.
- `crypto::Des3CbcSha1KdEtype::derive_key`: `pub fn derive_key(protocol_key: &[u8], usage: &[u8]) -> Result<Vec<u8>, Error>`.
- `crypto::Des3CbcSha1KdEtype::derive_random`: `pub fn derive_random(protocol_key: &[u8], usage: &[u8]) -> Result<Vec<u8>, Error>`.
- `crypto::Des3CbcSha1KdEtype::checksum`: `pub fn checksum(protocol_key: &[u8], data: &[u8], usage: u32) -> Result<Vec<u8>, Error>`.
- `crypto::Des3CbcSha1KdEtype::verify_checksum`: `pub fn verify_checksum(protocol_key: &[u8], data: &[u8], checksum: &[u8], usage: u32) -> bool`.
- `crypto::Des3CbcSha1KdEtype::encrypt_data`: `pub fn encrypt_data(key: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error>`.
- `crypto::Des3CbcSha1KdEtype::decrypt_data`: `pub fn decrypt_data(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error>`.
- `crypto::Des3CbcSha1KdEtype::encrypt_message_with_confounder`: `pub fn encrypt_message_with_confounder( protocol_key: &[u8], message: &[u8], usage: u32, confounder: &[u8], ) -> Result<Vec<u8>, Error>`.
- `crypto::Des3CbcSha1KdEtype::decrypt_message`: `pub fn decrypt_message( protocol_key: &[u8], ciphertext: &[u8], usage: u32, ) -> Result<Vec<u8>, Error>`.
- `crypto::Rc4HmacEtype::from_etype_id`: `pub const fn from_etype_id(etype_id: i32) -> Option<Self>`.
- `crypto::Rc4HmacEtype::from_checksum_type_id`: `pub const fn from_checksum_type_id(checksum_type_id: i32) -> Option<Self>`.
- `crypto::Rc4HmacEtype::etype_id`: `pub const fn etype_id() -> i32`.
- `crypto::Rc4HmacEtype::checksum_type_id`: `pub const fn checksum_type_id() -> i32`.
- `crypto::Rc4HmacEtype::key_len`: `pub const fn key_len() -> usize`.
- `crypto::Rc4HmacEtype::confounder_len`: `pub const fn confounder_len() -> usize`.
- `crypto::Rc4HmacEtype::hmac_len`: `pub const fn hmac_len() -> usize`.
- `crypto::Rc4HmacEtype::default_s2kparams`: `pub const fn default_s2kparams() -> &'static str`.
- `crypto::Rc4HmacEtype::string_to_key`: `pub fn string_to_key(secret: &[u8], _salt: &[u8], _s2kparams: &str) -> Result<Vec<u8>, Error>`.
- `crypto::Rc4HmacEtype::random_to_key`: `pub fn random_to_key(bytes: &[u8]) -> Result<Vec<u8>, Error>`. Supply exactly sixteen random bytes and handle `InvalidKeyLength` (FU-CRY-R01). The key equals that seed; password derivation remains `string_to_key`.
- `crypto::Rc4HmacEtype::derive_key`: `pub fn derive_key(protocol_key: &[u8], usage: &[u8]) -> Result<Vec<u8>, Error>`.
- `crypto::Rc4HmacEtype::checksum`: `pub fn checksum(protocol_key: &[u8], data: &[u8], usage: u32) -> Result<Vec<u8>, Error>`.
- `crypto::Rc4HmacEtype::verify_checksum`: `pub fn verify_checksum(protocol_key: &[u8], data: &[u8], checksum: &[u8], usage: u32) -> bool`.
- `crypto::Rc4HmacEtype::encrypt_data`: `pub fn encrypt_data(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error>`.
- `crypto::Rc4HmacEtype::decrypt_data`: `pub fn decrypt_data(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error>`.
- `crypto::Rc4HmacEtype::encrypt_message_with_confounder`: `pub fn encrypt_message_with_confounder( protocol_key: &[u8], message: &[u8], usage: u32, confounder: &[u8], ) -> Result<Vec<u8>, Error>`.
- `crypto::Rc4HmacEtype::decrypt_message`: `pub fn decrypt_message( protocol_key: &[u8], ciphertext: &[u8], usage: u32, ) -> Result<Vec<u8>, Error>`.
- `crypto::KerberosEtype::etype_id`: `pub const fn etype_id(self) -> i32`.
- `crypto::KerberosEtype::checksum_type_id`: `pub const fn checksum_type_id(self) -> i32`.
- `crypto::KerberosEtype::key_len`: `pub const fn key_len(self) -> usize`.
- `crypto::KerberosEtype::confounder_len`: `pub const fn confounder_len(self) -> usize`.
- `crypto::KerberosEtype::hmac_len`: `pub const fn hmac_len(self) -> usize`.
- `crypto::KerberosEtype::default_s2kparams`: `pub const fn default_s2kparams(self) -> &'static str`.
- `http::NegotiateHttpResponse<B>::did_negotiate`: `pub const fn did_negotiate(&self) -> bool`.
- `http::NegotiateLayer<'static>::from_keytab_name`: `pub fn from_keytab_name<P>(keytab_name: P) -> Result<Self> where P: AsRef<str>,`.
- `http::NegotiateService<'static, S>::from_keytab_name`: `pub fn from_keytab_name<P>(inner: S, keytab_name: P) -> Result<Self> where P: AsRef<str>,`.
- `kadmin::ChangePasswdData::new`: `pub fn new<P>(new_passwd: P) -> Self where P: AsRef<[u8]>,`.
- `kadmin::ChangePasswdData::for_target`: `pub fn for_target<I, S, P>( new_passwd: P, name_type: i32, components: I, realm: &str, ) -> Result<Self, Error> where I: IntoIterator<Item = S>, S: AsRef<str>, P: AsRef<[u8]>,`.
- `kadmin::build_enc_krb_priv_part`: `pub fn build_enc_krb_priv_part<P>( user_data: P, options: EncKrbPrivPartOptions, ) -> rasn_kerberos::EncKrbPrivPart where P: AsRef<[u8]>,`.
- `kadmin::build_krb_priv_with_confounder`: `pub fn build_krb_priv_with_confounder<P>( user_data: P, options: EncKrbPrivPartOptions, key: &EncryptionKey, confounder: &[u8], ) -> Result<rasn_kerberos::KrbPriv, Error> where P: AsRef<[u8]>,`.
- `kadmin::build_krb_priv`: `pub fn build_krb_priv<P>( user_data: P, options: EncKrbPrivPartOptions, key: &EncryptionKey, ) -> Result<rasn_kerberos::KrbPriv, Error> where P: AsRef<[u8]>,`.
- `kadmin::ChangePasswdMessageOptions::new`: `pub const fn new( timestamp: rasn_kerberos::KerberosTime, cusec: u32, sequence_number: u32, sender_address: rasn_kerberos::HostAddress, ) -> Self`.
- `kadmin::build_change_password_message_with_confounders`: `pub fn build_change_password_message_with_confounders( client_principal: rasn_kerberos::PrincipalName, client_realm: &str, change_data: &ChangePasswdData, service_ticket: rasn_kerberos::Ticket, session_key: &EncryptionKey, options: ChangePasswdMessageOptions, encryption: PasswordEncryption<'_>, ) -> Result<BuiltChangePasswordRequest, Error>`.
- `kadmin::PasswordEncryption<'request>::new`: `pub const fn new( reply_key: EncryptionKey, ap_req_confounder: &'request [u8], krb_priv_confounder: &'request [u8], ) -> Self`.
- `kadmin::Reply::is_krb_error`: `pub const fn is_krb_error(&self) -> bool`.
- `kadmin::ChangePasswordResult::is_success`: `pub const fn is_success(&self) -> bool`.
- `keytab::Name::parse`: `pub fn parse<P>(name: P) -> Result<Self, Error> where P: AsRef<str>,`.
- `keytab::Keytab::new`: `pub const fn new() -> Self`.
- `keytab::Keytab::load`: `pub fn load<P>(path: P) -> Result<Self, Error> where P: AsRef<Path>,`.
- `keytab::Keytab::load_name`: `pub fn load_name<P>(name: P) -> Result<Self, Error> where P: AsRef<str>,`.
- `keytab::Keytab::save`: `pub fn save<P>(&self, path: P) -> Result<(), Error> where P: AsRef<Path>,`.
- `keytab::Keytab::save_name`: `pub fn save_name<P>(&self, name: P) -> Result<(), Error> where P: AsRef<str>,`.
- `keytab::Keytab::version`: `pub const fn version(&self) -> u8`.
- `keytab::Keytab::entries_mut`: `pub const fn entries_mut(&mut self) -> &mut Vec<Entry>`.
- `keytab::Keytab::add_entry_from_password`: password is now `Zeroizing<Vec<u8>>`; the password generic is removed (FU-FIL-R01). Move existing bytes with `.into()`; use `add_entry_from_password_ref` for `&[u8]` while retaining caller erasure responsibility.
- `keytab::Keytab::add_entry_from_password_name<P, Q>`: password is now `Zeroizing<Vec<u8>>`; name/realm bounds and remaining parameters are unchanged. Invalid names also erase the moved password (FU-FIL-R01).
- `keytab::Principal::new`: `pub fn new<I, S, P>(realm: P, name_type: i32, components: I) -> Self where I: IntoIterator<Item = S>, S: Into<String>, P: Into<String>,`.
- `keytab::Principal::from_name`: `pub fn from_name<P, Q>(realm: P, name_type: i32, principal_name: Q) -> Result<Self, Error> where P: Into<String>, Q: AsRef<str>,`.
- `krb_priv::EncKrbPrivPartOptions::new`: `pub const fn new(sender_address: rasn_kerberos::HostAddress) -> Self`.
- `krb_priv::EncKrbPrivPartOptions::with_sequence_number`: `pub const fn with_sequence_number(mut self, seq_number: u32) -> Self`.
- `krb_priv::host_address`: `pub fn host_address<P>(addr_type: i32, address: P) -> rasn_kerberos::HostAddress where P: AsRef<[u8]>,`.
- `krb_priv::build_enc_krb_priv_part`: `pub fn build_enc_krb_priv_part<P>( user_data: P, options: EncKrbPrivPartOptions, ) -> rasn_kerberos::EncKrbPrivPart where P: AsRef<[u8]>,`.
- `krb_priv::build`: `pub fn build_krb_priv<P>( user_data: P, options: EncKrbPrivPartOptions, key: &EncryptionKey, kvno: Option<u32>, ) -> Result<rasn_kerberos::KrbPriv, Error> where P: AsRef<[u8]>,`.
- `krb_priv::build_krb_priv_with_confounder`: `pub fn build_krb_priv_with_confounder<P>( user_data: P, options: EncKrbPrivPartOptions, key: &EncryptionKey, kvno: Option<u32>, confounder: &[u8], ) -> Result<rasn_kerberos::KrbPriv, Error> where P: AsRef<[u8]>,`.
- `pac::NtlmSupplementalCredential::has_lm_password`: `pub const fn has_lm_password(&self) -> bool`.
- `pac::NtlmSupplementalCredential::has_nt_password`: `pub const fn has_nt_password(&self) -> bool`.
- `pac::ClaimValues::len`: `pub const fn len(&self) -> usize`.
- `pac::ClaimValues::is_empty`: `pub const fn is_empty(&self) -> bool`.
- `pac::FileTime::from_ticks`: `pub const fn from_ticks(ticks: u64) -> Self`.
- `pac::FileTime::ticks`: `pub const fn ticks(self) -> u64`.
- `service::ValidatedApReq::build_ap_rep_with_confounder`: `pub fn build_ap_rep_with_confounder( &self, confounder: &[u8], options: &ApRepOptions, ) -> Result<Vec<u8>, Error>`.
- `service::Validator<'static>::from_keytab_name`: `pub fn from_keytab_name<P>(keytab_name: P) -> Result<Self, Error> where P: AsRef<str>,`.
- `spnego::MicToken::new`: `pub const fn new(flags: u8, snd_seq_num: u64) -> Self`.
- `spnego::MicToken::with_payload`: `pub fn with_payload<P>(mut self, payload: P) -> Self where P: Into<Vec<u8>>,`.
- `spnego::MicToken::new_initiator`: `pub fn new_initiator<P>(payload: P, key:
  &EncryptionKey) -> Result<Self, Error> where P: Into<Zeroizing<Vec<u8>>>,`.
- `spnego::WrapToken::new`: `pub const fn new(flags: u8, snd_seq_num: u64) -> Self`.
- `spnego::WrapToken::with_payload`: `pub fn with_payload<P>(mut self, payload: P) -> Self where P: Into<Vec<u8>>,`.
- `spnego::WrapToken::new_initiator`: `pub fn new_initiator<P>(payload: P, key:
  &EncryptionKey) -> Result<Self, Error> where P: Into<Zeroizing<Vec<u8>>>,`.
- `spnego::WrapToken::new_initiator_sealed`: `pub fn
  new_initiator_sealed<P>(payload: P, key: &EncryptionKey) -> Result<Self,
  Error> where P: Into<Zeroizing<Vec<u8>>>,`.
- `spnego::WrapToken::new_initiator_sealed_with_confounder`: `pub fn
  new_initiator_sealed_with_confounder<P>( payload: P, key: &EncryptionKey,
  confounder: &[u8], ) -> Result<Self, Error> where P:
  Into<Zeroizing<Vec<u8>>>,`.
- `spnego::WrapToken::is_sealed`: `pub const fn is_sealed(&self) -> bool`.
- `spnego::NegTokenResp::reject`: `pub const fn reject() -> Self`.
- `spnego::InitiatorContextOptions::with_context_flags`: `pub fn with_context_flags<P>(mut self, context_flags: P) -> Self where P: Into<Vec<u32>>,`.
- `spnego::InitiatorContextOptions::with_ap_option_bits`: `pub const fn with_ap_option_bits(mut self, ap_option_bits: u32) -> Self`.
- `spnego::InitiatorContextOptions::with_sequence_number`: `pub const fn with_sequence_number(mut self, sequence_number: Option<u32>) -> Self`.
- `spnego::AcceptedContext::ap_rep_response_header`: `pub fn ap_rep_response_header(&self, options: &ApRepOptions) -> Result<String, Error>`.
- `spnego::AcceptedContext::ap_rep_response_header_with_confounder`: `pub fn ap_rep_response_header_with_confounder( &self, confounder: &[u8], options: &ApRepOptions, ) -> Result<String, Error>`.
- `spnego::challenge_header`: `pub const fn challenge_header() -> &'static str`.

## Renamed paths

The following map is exhaustive. Paths are relative to `rskrb5_ng`; error
texts and runtime behavior are unchanged.

| From | To |
| --- | --- |
| `Error` | `error::Any` |
| `ap_rep::Error` | `error::ApRep` |
| `ap_req::Error` | `error::ApReq` |
| `ccache::Error` | `error::Ccache` |
| `client::Error` | `error::Client` |
| `config::Error` | `error::Config` |
| `config::Realm::realm` | `config::Realm::name` |
| `crypto::Error` | `error::Crypto` |
| `http::Error` | `error::Http` |
| `kadmin::Error` | `error::Kadmin` |
| `kdc_rep::Error` | `error::KdcRep` |
| `kdc_req::Error` | `error::KdcReq` |
| `keytab::Error` | `error::Keytab` |
| `krb_cred::Error` | `error::KrbCred` |
| `krb_error::Error` | `error::KrbErrorCodec` |
| `krb_priv::Error` | `error::KrbPriv` |
| `krb_safe::Error` | `error::KrbSafe` |
| `messages::Error` | `error::Messages` |
| `pac::Error` | `error::Pac` |
| `service::Error` | `error::Service` |
| `spnego::Error` | `error::Spnego` |
| `ticket::Error` | `error::Ticket` |
| `ap_rep::build_ap_rep` | `ap_rep::build` |
| `ap_rep::decode_ap_rep` | `ap_rep::decode` |
| `ap_rep::encode_ap_rep` | `ap_rep::encode` |
| `ap_rep::validate_ap_rep` | `ap_rep::validate` |
| `ap_rep::encode_build_ap_rep` | `ap_rep::build_encoded` |
| `ap_req::build_ap_req` | `ap_req::build` |
| `ap_req::decode_ap_req` | `ap_req::decode` |
| `ap_req::encode_ap_req` | `ap_req::encode` |
| `ap_req::validate_ap_req` | `ap_req::validate` |
| `ap_req::encode_build_ap_req` | `ap_req::build_encoded` |
| `ticket::build_ticket` | `ticket::build` |
| `ticket::decode_ticket` | `ticket::decode` |
| `ticket::encode_ticket` | `ticket::encode` |
| `ticket::validate_ticket` | `ticket::validate` |
| `ticket::encode_build_ticket` | `ticket::build_encoded` |
| `krb_priv::build_krb_priv` | `krb_priv::build` |
| `krb_priv::decode_krb_priv` | `krb_priv::decode` |
| `krb_priv::encode_krb_priv` | `krb_priv::encode` |
| `krb_priv::validate_krb_priv` | `krb_priv::validate` |
| `krb_safe::build_krb_safe` | `krb_safe::build` |
| `krb_safe::decode_krb_safe` | `krb_safe::decode` |
| `krb_safe::encode_krb_safe` | `krb_safe::encode` |
| `krb_error::decode_krb_error` | `krb_error::decode` |
| `krb_error::encode_krb_error` | `krb_error::encode` |
| `krb_error::validate_krb_error` | `krb_error::validate` |
| `krb_safe::krb_safe_checksum` | `krb_safe::checksum` |
| `krb_error::krb_error_info` | `krb_error::info` |
| `krb_cred::decode_krb_cred` | `krb_cred::decode` |
| `krb_cred::encrypt_ccache_credentials_to_krb_cred` | `krb_cred::encrypt_ccache_credentials` |
| `krb_cred::encode_encrypt_ccache_credentials_to_krb_cred` | `krb_cred::encode_encrypted_ccache_credentials` |
| `client::TokioClient` | `client::Tokio` |
| `client::NegotiateClient` | `client::negotiate::Client` |
| `client::BlockingNegotiateClient` | `client::negotiate::BlockingClient` |
| `service::ServiceValidator` | `service::Validator` |
| `keytab::KeytabName` | `keytab::Name` |
| `keytab::KeytabEntryMetadata` | `keytab::EntryMetadata` |
| `spnego::SpnegoToken` | `spnego::Token` |
| `spnego::ObjectIdentifier` | `spnego::oid::ObjectIdentifier` |
| `krb_error::KrbErrorInfo` | `messages::KrbErrorInfo` |
| `krb_error::PrincipalNameInfo` | `messages::PrincipalNameInfo` |
| `client::Principal` | `client::principal::Principal` |
| `client::AsReqOptions` | `client::options::AsReq` |
| `client::TgsReqOptions` | `client::options::TgsReq` |
| `client::ApReqOptions` | `client::options::ApReq` |
| `client::KdcEndpoint` | `client::transport::KdcEndpoint` |
| `client::KdcEndpointSource` | `client::transport::KdcEndpointSource` |
| `client::KdcProtocol` | `client::transport::KdcProtocol` |
| `client::TokioKdcTransport` | `client::transport::Tokio` |
| `client::BuiltKpasswdRequest` | `client::kpasswd::BuiltKpasswdRequest` |
| `client::KpasswdRequestOptions` | `client::kpasswd::RequestOptions` |
| `client::VerifiedKpasswdApRep` | `client::kpasswd::VerifiedKpasswdApRep` |
| `client::build_kpasswd_request` | `client::kpasswd::build_kpasswd_request` |
| `client::build_kpasswd_request_with_confounders` | `client::kpasswd::build_kpasswd_request_with_confounders` |
| `client::verify_kpasswd_ap_rep` | `client::kpasswd::verify_kpasswd_ap_rep` |
| `kadmin::EncKrbPrivPartOptions` | `krb_priv::EncKrbPrivPartOptions` |
| `kadmin::KRB_PRIV_ENCPART_USAGE` | `krb_priv::KRB_PRIV_ENCPART_USAGE` |
| `kadmin::KRB_PRIV_MSG_TYPE` | `krb_priv::KRB_PRIV_MSG_TYPE` |
| `kadmin::KRB_PRIV_PVNO` | `krb_priv::KRB_PRIV_PVNO` |
| `kadmin::host_address` | `krb_priv::host_address` |
| `kadmin::ipv4_host_address` | `krb_priv::ipv4_host_address` |
| `kadmin::ipv6_host_address` | `krb_priv::ipv6_host_address` |
| `evaluation::ASN1_FIXTURES` | `evaluation::data::ASN1_FIXTURES` |
| `evaluation::ASSESSMENTS` | `evaluation::data::ASSESSMENTS` |
| `evaluation::Asn1Fixture` | `evaluation::data::Asn1Fixture` |
| `evaluation::Candidate` | `evaluation::data::Candidate` |
| `evaluation::CandidateAssessment` | `evaluation::data::CandidateAssessment` |
| `evaluation::CandidateReport` | `evaluation::data::CandidateReport` |
| `evaluation::Capability` | `evaluation::data::Capability` |
| `evaluation::ContractArea` | `evaluation::data::ContractArea` |
| `evaluation::DerType` | `evaluation::data::DerType` |
| `evaluation::REPORTS` | `evaluation::data::REPORTS` |
| `evaluation::Support` | `evaluation::data::Support` |
| `evaluation::SupportByArea` | `evaluation::data::SupportByArea` |
| `evaluation::V8_CONTRACT` | `evaluation::data::V8_CONTRACT` |
| `client::Error::ClientPrincipalMismatch` | `error::Client::PrincipalMismatch` |
| `config::Error::NoDefaultConfig` | `error::Config::NoDefault` |
| `kadmin::Error::MissingKrbError` | `error::Kadmin::MissingKrb` |
| `Error::KrbError` | `error::Any::Krb` |

The newly public defining modules are
`client::{kpasswd, negotiate, options, principal, transport}`, `configuration`,
`cryptography`, `spnego::oid`, and `evaluation::data`; `error` is new. The
public re-exports are the crate-root facade, `Principal`, `NegotiateClient`,
`BlockingNegotiateClient` and `Config`, which v0.2.2 also re-exported at the
root, and `TokioClient` (`client::Tokio`) and `ServiceValidator`
(`service::Validator`), which v0.2.2 had only under their module paths, plus the
module aliases `config` (for `configuration`) and `crypto` (for `cryptography`),
which keep the v0.2.2 module paths (FU-DOC-R62, FU-DOC-R80). References in the
API dump normalize these aliases to their defining paths; duplicate alias
expansions do not represent distinct items.

The old module-local error path is private and no longer resolves externally:

```compile_fail
use rskrb5_ng::client::Error;
```

Use the public domain error instead:

```rust
# #[cfg(feature = "messages")]
# {
use rskrb5_ng::error::Client;
let error = Client::PrincipalMismatch {
    expected: "alice@EXAMPLE.COM".to_owned(),
    actual: "bob@EXAMPLE.COM".to_owned(),
};
assert!(matches!(error, Client::PrincipalMismatch { .. }));
# }
```

## kpasswd-rs

`kpasswd-rs` depends on `rskrb5-patched` 0.2.1 through its vendored tree
(`crates/kpasswd-rs/Cargo.toml`, `rskrb5 = { version = "0.2.1", package =
"rskrb5-patched", path = "../../vendor/rskrb5", ... }`). This project makes
no change to it. A scratch copy of `kpasswd-rs` at `76bc19b`, with only that
line pointed at `rskrb5-ng` (keeping the `rskrb5` key) and `rasn` and
`rasn-kerberos` moved to 0.29, fails `cargo check --all-targets` with 114
distinct errors; the library target alone fails with 37. The edits it needs,
by group:

- **Manifest.** `rskrb5 = { version = "0.3", package = "rskrb5-ng",
  default-features = false, features = ["tokio"] }` with a new vendored tree
  (and `VENDORING.md` updated to match), `rasn` and `rasn-kerberos` 0.29, and
  a Rust 1.99 toolchain. Keeping the `rskrb5` key leaves the `rskrb5::`
  paths in place.
- **Error types** (`error.rs`, `narration.rs` and others): `client::Error`,
  `config::Error` and `crypto::Error` are `error::Client`, `error::Config`
  and `error::Crypto`. The `match` in `Error::from_client` needs a wildcard
  arm because the error enums are non-exhaustive, `ClientPrincipalMismatch`
  is `PrincipalMismatch`, and the new variants need a mapping; in particular
  `error::Client::KpasswdOutcomeUnknown` means the password may have changed
  and must not be reported as a failure.
- **Moved items:** `client::Principal` is `client::principal::Principal`;
  `client::{KdcEndpoint, KdcEndpointSource, KdcProtocol}` and
  `client::TokioKdcTransport` are `client::transport::{KdcEndpoint,
  KdcEndpointSource, KdcProtocol, Tokio}`; `client::{AsReqOptions,
  TgsReqOptions}` are `client::options::{AsReq, TgsReq}`;
  `client::{KpasswdRequestOptions, build_kpasswd_request,
  verify_kpasswd_ap_rep}` are `client::kpasswd::{RequestOptions,
  build_kpasswd_request, verify_kpasswd_ap_rep}`;
  `ap_req::{build_ap_req, decode_ap_req, encode_ap_req}` are
  `ap_req::{build, decode, encode}`; `kadmin::EncKrbPrivPartOptions` and
  `kadmin::{ipv4_host_address, ipv6_host_address}` are in `krb_priv`.
- **Struct literals** (41 sites): `keytab::EncryptionKey`,
  `ccache::EncryptionKey`, `ccache::Principal`, `ccache::Credential`,
  `keytab::Entry`, `client::PreauthKeyInfo`, `client::AsRepSession` and
  `client::KdcError` use the constructors in the construction map above;
  `ccache::CredentialTimes` starts from `Default`; `config::Realm` comes from
  `Realm::new` or from parsing a `krb5.conf` snippet;
  `kadmin::ChangePasswordResult` comes from
  `ChangePasswordResult::parse`.
- **`LibDefaults`** (`enctype.rs`): `default_tkt_enctype_ids` and
  `default_tgs_enctype_ids` are methods (`defaults.default_tkt_enctype_ids()`),
  and the boolean options are `config::Toggle` (`is_enabled()`,
  `Toggle::from_bool`). `config::Realm::realm` is `name`.
- **Crypto:** `AesSha1Etype` and `AesSha2Etype` `confounder_len` and
  `default_s2kparams` are associated functions
  (`AesSha1Etype::confounder_len()`).
- **TGS builder:** `build_tgs_req_for_realm_with_confounder_and_subkey` takes
  `(tgt, kdc_realm, service, parts)`, with `parts` from
  `TgsRequestParts::new(options, confounder, subkey).with_timestamp(timestamp,
  cusec)`.
- **Behaviour to re-check:** RC4 and DES3 are off unless `allow_rc4` or
  `allow_des3` is set, `%{uid}`/`%{euid}` in file names work only on Linux,
  and every change listed under "Review backlog behaviour changes" above.

These are the first-pass compiler errors; fixing them can surface more (for
example exhaustive matches over other enums that are now non-exhaustive).

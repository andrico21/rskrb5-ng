# Cryptographic security policy

This document describes library policy, not a certification or a promise to
erase memory owned by dependencies. Permanent refusals are reported as
`error::Policy::RejectedFeature { feature, reason }`; domain errors preserve
that cause. `RejectionReason` is a small typed explanation, not an error source.
Serde must render it through its format's native error envelope.

<a id="policy"></a>
## Runtime policy

`crypto::CryptoPolicy::from_libdefaults` builds a permission snapshot from the
current configuration. `check_use` applies permitted membership and explicit
legacy permission to requests, reply keys, session and ticket keys, cached and
imported credentials, acceptors and checked low-level APIs. Rebuild the snapshot
after changing configuration. Public configuration fields are staging values,
not evidence that a selection is authorized. Invalid staging values fail closed.
The snapshot, and so every acceptor, does not read `default_tkt_enctypes` or
`default_tgs_enctypes`: MIT reads those two keys only on the client side. Client request construction (`AsReq::from_libdefaults`,
`TgsReq::from_libdefaults`, the configured Tokio client and the configured
kpasswd result path) rejects a request list outside the permitted list with
`error::Config::EnctypeNotPermitted`.

The implemented secure `DEFAULT` is AES-SHA2 then AES-SHA1: IDs
**[20, 19, 18, 17]**. DES3 and RC4 are never inserted by `DEFAULT`, even when
permitted. Both `allow_des3`/`allow_rc4` and permitted-list membership are needed
for their corresponding profiles (16/23). These flags do not insert names into
explicit request lists. Unlike MIT's KDC-side relations, this library enforces
them on clients and acceptors too: a deliberate, stricter divergence. A service
with only RC4 keys must opt in explicitly or it cannot accept those tickets.

Lists use MIT case-insensitive names/aliases, space/tab/CR/LF/comma delimiters,
`DEFAULT`, `aes`, `des3`, `rc4`, `camellia`, and left-to-right `+`/`-` operators.
Re-adding a present entry retains its position; re-adding a removed one appends.
Unknown, forbidden and policy-disabled positive terms fail by name, never silently
narrow. Known removal terms are accepted. Empty results fail. Compatible mode
skips only secure Camellia names whose `camellia` Cargo feature is not compiled
in, with a diagnostic naming the feature; strict mode rejects them. See
[Camellia](#camellia) for the feature, the `DEFAULT` list and the reason. See
[MIT configuration](https://web.mit.edu/kerberos/krb5-1.22/doc/admin/conf_files/krb5_conf.html),
[encryption types](https://web.mit.edu/kerberos/krb5-1.22/doc/admin/conf_files/kdc_conf.html#encryption-types)
and [MIT list evaluation](https://github.com/krb5/krb5/blob/krb5-1.22.2-final/src/lib/krb5/krb/init_ctx.c#L411-L492).

KDC-supplied password derivation has minimum **4096** iterations for AES-SHA1
([RFC 3962 section 4](https://www.rfc-editor.org/rfc/rfc3962.html#section-4))
**32768** for AES-SHA2
([RFC 8009 section 4](https://www.rfc-editor.org/rfc/rfc8009.html#section-4)) and
**32768** for Camellia ([RFC 6803 section 4](https://www.rfc-editor.org/rfc/rfc6803.html#section-4),
a stricter divergence: MIT has no floor).
The existing upper bound is 2^24; zero is refused. Trusted application code may
lower a minimum with `LibDefaults::with_min_s2k_iterations`; doing so weakens
offline-guess resistance. Text configuration and serde cannot set that override.
Rejection occurs before PBKDF2. Raw RFC-vector primitives retain their documented
low-count behavior and do not enforce application permission; use
`crypto::checked::Etype` for policy-checked low-level operations.

Opaque historical key/cache/message records and peer capability advertisements
are not algorithm authorization. Explicit outgoing selection is checked before
crypto or transport. Draft-9 preferences are ignored with
`ConfigDiagnostic::IgnoredPreauthType`; text removes the entries, while serde
retains the informational IDs and `LibDefaults::diagnostics()` reports them via
`Cow<[ConfigDiagnostic]>`. Neither permits an outgoing draft-9 exchange.

Checked AS/TGS exchanges authorize every visible encrypted envelope before
transport: the body enctype list, optional encrypted authorization data,
additional tickets, PA-TGS-REQ ticket/authenticator, PA-ENC-TIMESTAMP, and the
supplied reply key. Body authorization data uses `Use::SessionKey`, including
the authenticator subkey case (RFC 4120 section 5.4.1, key usages 4/5).
Admission does not decrypt ciphertext or certify that a KDC will accept it.
Encrypted ticket contents and authenticator plaintext are not visible envelope
fields; builders check locally selected keys before encryption.

The checked PA boundary admits only the PA data this client builds, each
checked under the policy before transport: PA-TGS-REQ, PA-ENC-TIMESTAMP,
PA-FX-FAST (the armor AP-REQ's ticket and authenticator, the keyed request
checksum and the armor-key encryption of the inner request),
PA-ENCRYPTED-CHALLENGE, PA-PK-AS-REQ, PA-SPAKE, PA-OTP-REQUEST, PA-FOR-USER,
PA-S4U-X509-USER, PA-PAC-OPTIONS and PA-PAC-REQUEST
(`tests/policy/outgoing_inventory.rs`). It rejects the types it neither builds
nor can check with `error::Client::Encode` targeting `PA-DATA` and the message
`outgoing PA type N is not supported`: legacy Unix-time, hardware-token,
SESAME/DCE and SAM types, the KDC halves of PKINIT and OTP (including
PA-OTP-CHALLENGE and the PIN-change message), extra TGT, authentication sets,
EPAK, PKINIT key exchange, PKU2U, OAuth2 and passkey mechanisms. Outgoing
peer-only enctype hints (11/19/23/165) and the embedding wrapper
PA-GET-FROM-TYPED-DATA (22), whose nested data the policy cannot check, are
rejected too; incoming capability parsing is unchanged. Draft-9 retains its
permanent typed policy cause. Cookies, ordinary informational PA data and
unknown extension IDs remain opaque; unknown payloads are not a supported
credential mechanism or a promise of nested policy enforcement. Implementing a
new credential PA type requires extending admission and its inventory tests.

<a id="single-des"></a>
## Single DES

`SingleDes`: inadequate effective key strength. IDs 1/2/3 and historical raw/HMAC
names are recognized only for rejection or removal. MIT disabled single DES by
default in **1.8** and removed support in **1.18**:
[1.8 release notes](https://web.mit.edu/kerberos/krb5-1.8/krb5-1.8.html),
[1.18 release notes](https://web.mit.edu/kerberos/krb5-1.18/krb5-1.18.4.html).

<a id="kerberos-v4"></a>
## Kerberos V4

`KerberosV4`: obsolete protocol and cryptography, not an available compatibility
mode. Enabled `krb4_*` selections are refused; disabled values are accepted.
MIT removed protocol support in **1.7**:
[release](https://web.mit.edu/kerberos/krb5-1.7/),
[removal project](https://k5wiki.kerberos.org/wiki/Projects/Remove_krb4).

<a id="v4-conversion"></a>
## V4 conversion

`V4Conversion`: conversion into the removed security model is not implemented.
Enabled `krb4_convert`, `v4_*` mappings and realm selections are refused.
`default_domain` remains ordinary parsed metadata. MIT removed the krb524 daemon
and client implementation with **1.7**, but retained some principal-conversion
helpers and a compatibility stub; this is not a claim that every conversion API
vanished: [MIT removal project](https://k5wiki.kerberos.org/wiki/Projects/Remove_krb4).

<a id="rsa-pkinit"></a>
## RSA-mode PKINIT

`RsaPkinit`: removed RSA key-transport/DH-less protocol mode, not RSA signatures
on certificate chains. Explicit mode selectors, including historical
`flag_RSA_PROTOCOL=yes`, are refused before exchange. MIT removed this mode in
the **1.22** development cycle:
[removal commit](https://github.com/krb5/krb5/commit/401f584526e501b68e7516c17d8e467883f8f210),
[1.22 releases](https://web.mit.edu/kerberos/krb5-1.22/).
Certificate filenames, trust anchors and revocation options are not classified
as RSA transport. Current PKINIT (RFC 4556 Diffie-Hellman and ECDH) is
implemented behind the `pkinit` leaf ([Leaf flags](#leaf-flags)).

<a id="draft9-pkinit"></a>
## Draft-9 PKINIT

`Draft9Pkinit`: obsolete Windows-era protocol variant, removed by MIT in
**1.18**: [release notes](https://web.mit.edu/kerberos/krb5-1.18/krb5-1.18.4.html).
Explicit PA types 14/15 and enabling legacy selectors are refused. Preference
lists ignore them with diagnostics; KDC advertisements are ignored, not selected.

<a id="rc4-export"></a>
## Export-strength RC4

`Rc4Export`: deliberately reduced key strength. ID 24 and its aliases are
permanently refused, independent of legacy flags. This policy is stricter than
MIT's historical compatibility table: **no blanket MIT removal release is
claimed**. [RFC 6649](https://www.rfc-editor.org/rfc/rfc6649.html) deprecates it;
[MIT enctype documentation](https://web.mit.edu/kerberos/krb5-1.22/doc/admin/enctypes.html)
still describes historical support. Ordinary RC4-HMAC 23 is distinct and opt-in.

<a id="camellia"></a>
## Camellia

`camellia128-cts-cmac` (25) and `camellia256-cts-cmac` (26), with the checksum types
`cmac-camellia128` (17) and `cmac-camellia256` (18), are implemented per
[RFC 6803](https://www.rfc-editor.org/rfc/rfc6803.html) behind the additive Cargo
feature `camellia` (the RustCrypto `camellia` and `cmac` crates, admitted in
`docs/dependency-admission.md`). Three rules hold:

- **The feature grants nothing.** Without the feature, Camellia names keep their
  diagnostic (compatible mode) or error (strict mode), which names the feature.
  With it, the enctypes are available, but the runtime policy still decides:
  Camellia must be named in `permitted_enctypes`, and then it is permitted for
  every use, and also becomes part of the request lists that default from it.
  A default policy refuses it everywhere (`Use::AcceptorTicket`,
  `Use::CheckedLowLevel` and the others).
- **`DEFAULT` never includes Camellia.** The admitted `camellia` crate reads
  secret-indexed S-box tables (four 256-byte tables, `utils.rs` function `f`), so it
  is not table-free and not constant-time on CPUs with data caches: a local attacker
  who shares the cache can observe which table entries a key-dependent round touches.
  AES is the default for that reason, and
  `crypto::camellia::CONSTANT_TIME` records `false`. MIT's `DEFAULT` list does
  include Camellia (a deliberate, stricter divergence). Use Camellia only when
  a deployment needs it ([RFC 6803 section 8](https://www.rfc-editor.org/rfc/rfc6803.html#section-8)
  says the same).
- **Password work is bounded.** Peer-supplied iteration counts are limited to
  2^24 and, in a policy, to at least 32768 (the RFC default) unless trusted code
  lowers the floor with `LibDefaults::with_min_s2k_iterations(Family::Camellia, ..)`.

The key schedule and cipher state of the dependency are wiped on drop with its
`zeroize` feature, which this crate enables; stack and register copies are not
covered, like elsewhere in this crate.

<a id="unauthenticated-checksum"></a>
## Unauthenticated or weak negotiable checksums

`UnauthenticatedChecksum { id }`: CRC32, raw MD4/MD5/SHA1 and historical weak
checksum selections do not provide acceptable authenticated integrity. Negotiable
IDs 1..10 and 14 are refused with the exact ID, including peer-selected KRB-SAFE
and PAC verification. Protocol-internal hashes and opt-in keyed HMAC-MD5 are
different constructions. **No blanket MIT removal release is claimed**:
[RFC 6649](https://www.rfc-editor.org/rfc/rfc6649.html) deprecates named weak
profiles, while [MIT advisory 2010-007](https://web.mit.edu/kerberos/advisories/MITKRB5-SA-2010-007.txt)
documents specific checksum-acceptance fixes, not removal of all hash primitives.

The RFC 6806 request-integrity checksum of a KDC reply is accepted only with the
checksum type that the reply key's encryption type requires. The reply key is
checked as `Use::ReplyKey` first, so the policy decides the profile. MIT accepts
more combinations (`verify_key` compares encryption providers, and HMAC-MD5 has
none): a deliberate, stricter divergence.

<a id="unprotected-password-change"></a>
## Unprotected password change

`UnprotectedPasswordChange`: password mutations require confidential,
authenticated KRB-PRIV protection. NULL-enctype request payloads and explicit
weaker-mode/version selectors are refused before encoding or transport.
Versions 1 and 0xff80 denote protected change/set forms; the current request
encoder emits 0xff80. Unknown versions never trigger a plaintext fallback.
**No blanket MIT removal release is claimed**: protection is the protocol
requirement in [RFC 3244 section 2](https://www.rfc-editor.org/rfc/rfc3244.html#section-2)
and the [MIT password-change API](https://web.mit.edu/kerberos/krb5-current/doc/appdev/refs/api/krb5_change_password.html).
After possible delivery, an unsigned reply is diagnostic only and cannot prove
success or rejection; outcome remains unknown without authenticated validation.

<a id="weak-crypto"></a>
## Blanket weak-crypto enablement

`WeakCrypto`: `allow_weak_crypto=true` is permanently refused; false is accepted.
Obsolete unauthenticated raw DES3 profiles are also refused. There is **no MIT
release removing the entire boolean**: this is an intentionally stricter crate
policy. MIT's [1.8 release](https://web.mit.edu/kerberos/krb5-1.8/krb5-1.8.html)
made DES default-off, and [current configuration](https://web.mit.edu/kerberos/krb5-1.22/doc/admin/conf_files/krb5_conf.html)
distinguishes weak crypto and family-specific permissions. No Cargo feature
alone grants permission to use legacy algorithms.

<a id="residual-copies"></a>
## Secret ownership and residual copies

First-party owning passwords, keys and secret staging buffers use zeroizing
owners; borrowed convenience APIs leave input erasure to the caller. The
Tokio transport builds its TCP record frames and the kpasswd request frame in
zeroizing owners, erased on success, on error and when the future is dropped.
This is a bounded guarantee, not a claim that every historical copy is erased:

- rasn `OctetString` and decoded ASN.1 storage can own key, ticket or plaintext
  copies that the crate cannot reliably erase through the dependency's API.
- RustCrypto cipher schedules and internal hash/HMAC/KDF state belong to their
  implementation types. No blanket erasure guarantee is made for those copies.
- Returned raw `Vec<u8>`/`String`, caller clones, application buffers, kernel
  and Tokio socket buffers, allocator remnants, registers, stack spills, OS
  paging and core dumps are outside value-owner erasure guarantees. Callers
  must protect and erase what they own, avoid logging tokens, and control
  dumps and persistence.
- `panic=abort` does not run destructors and is not an erasure control.

Password-specific kpasswd DER uses first-party zeroizing writers to avoid known
rasn password copies; generic ASN.1 codecs still have the residuals above.
Closing a dependency residual requires a documented dependency erasure contract
or an ownership-preserving replacement, not just wrapping the first input copy.

Named residuals of the parity work, disclosed and not erased:

- **OTP values and PINs** (`docs/review/parity-register.md`, FU-OTP-P02). The
  answer, the combined PIN and value and the DER of the request live in
  zeroizing owners, but `preauth::otp` builds the `PA-OTP-REQUEST` with `rasn`
  containers: the value is copied into an `OctetString` and a separate PIN into
  a `String` and then a `Utf8String`, which are freed without erasure when the
  request is encoded. The encoded request is then copied into the `PaData` of
  the inner AS-REQ, which the exchange keeps until the reply is processed. The
  armored request that leaves the client is zeroizing, the copies never leave
  the process, and a one-time value does not make a PIN public.
- **HTTP cookies** (FU-HTC-P06). A cookie can be a credential. The
  `http-client` leaf's jar keeps cookie values in the admitted `cookie_store`
  crate, which does not zeroize them on drop. The built-in jar is in memory
  only; persistence is an application's own `CookieJar`.
- **HTTP sessions** (FU-HTC-P06). The `http::sessions::SessionManager` registry
  is per process and per manager: a restart revokes every session, and two
  processes or two managers share none, even under one key. The sealing key is
  erased when dropped.
- **KDC proxy bodies.** The built-in `kkdcp-rustls` transport hands `hyper` a
  `Bytes` copy of the KDC-PROXY-MESSAGE, which `hyper` does not zeroize; the
  crate's own copy is a zeroizing owner and TLS encrypts the body on the wire
  (`docs/dependency-admission.md`, record `hyper`).

## Set-uid and set-gid processes

The functions with an `# Ambient input` rustdoc section read `KRB5_CONFIG`,
`KRB5CCNAME`, `KRB5_KTNAME`, `KRB5_CLIENT_KTNAME`, `TMPDIR` and `HOME` only
when the process environment may be trusted. One shared secure-environment
decision (`src/secure_env.rs`), derived once per process from the operating
system and never from an environment variable, is consulted before each such
read; in a restricted process the reader behaves as if the variable were
unset, as MIT 1.22.2 does through `secure_getenv`
(`src/util/support/secure_getenv.c:105-111`):

- Linux and Android: the process is restricted when `AT_SECURE` of its
  auxiliary vector (`/proc/self/auxv`, the value glibc's `secure_getenv`
  uses) is nonzero. A vector that cannot be read or parsed, or one without
  `AT_SECURE`, is restricted too (fail closed); such programs use the explicit
  constructors (`Config::load_paths`, `CCache::load_name`,
  `Keytab::load_name`, a literal name).
- Other Unix systems: the process is restricted when its real and effective
  user or group ids differ, through `rustix::process` (the one non-optional
  dependency, owner exception 2026-11-18, `docs/dependency-admission.md`).
  This is MIT's fallback (`secure_getenv.c:83-99`) without the saved ids that
  `getresuid`/`getresgid` add there, and without `issetugid`, which rustix
  does not offer: a set-id program that has switched its effective ids back to
  the real ones before the first ambient read is not detected
  (`docs/review/parity-register.md`, FU-SEC-P02).
- Windows has no set-uid or set-gid processes: never restricted.

`LibDefaults::from_env` no longer reads `HOME`: it is `LibDefaults::new`.
MIT never reads `HOME` for `k5login_directory` (it uses the home directory of
the target user's passwd entry, `localauth_k5login.c:106`), and the `localauth`
leaf takes the home directory of an account from the caller's `AccountResolver`,
never from the environment (a test runs the authorizer under a hostile `HOME`).
`docs/config-profile.md` (Deliberate divergences and bounds) lists the MIT sources.

## Local authorization

The `localauth` leaf (`localauth::authorize_local`, `localauth::principal_to_local_name`)
answers MIT's `krb5_kuserok` and `krb5_aname_to_localname`
(`src/lib/krb5/os/localauth*.c`) for a principal the caller has verified. It
reads no environment variable: the home directory and user id of an account come
from the caller's `AccountResolver` (the crate has no default one, because it
forbids `unsafe` and admits no passwd wrapper), never from `HOME`, `UID` or
`USER`. Every failure denies. It is stricter than MIT where a decision rests on
attacker-reachable input: a `.k5login` that is a symbolic link, not a regular
file, writable by its group or by others, replaced between the check and the
open, or past the size, line-count and line-length bounds is refused;
`auth_to_local_names` translates only principals of the default realm; rules are
compiled when the configuration is read, run on the linear-time `regex` engine
and are bounded in size, substitutions and replacements. The differences from MIT
are listed in the `security_divergence` of `MIT-authz-1` to `MIT-authz-5` and in
the register rows `FU-LAU-P01` to `FU-LAU-P06`.

## Credential stores

The store API (`ccache::stores::CredentialStore`, `ccache::stores::CacheCollection`,
`ccache::stores::CacheHandle`, `keytab::stores::KeyStore`) writes cache and keytab files
owner-only (mode 0600, collection directories 0700) and replaces them whole by
atomic rename, and it refuses a file that is a symlink, not a regular file,
writable by group or others, or (Linux) owned by another user, and a `DIR`
collection directory that others may write unless it is sticky. Writers hold
an exclusive `std::fs::File::lock` and readers a shared one; MIT's `fcntl`
locks do not interact with them on Linux, so concurrent MIT and crate writers
serialize only through the atomic rename. `switch` accepts only a cache of the
collection. `MEMORY` caches and keytabs live in one store or table value and
its clones, never in a process-wide table; removed, replaced and destroyed
credentials and keys are erased as they drop. `ccache_type` selects the format
version of new caches and must be 1 to 4. The plan-2 register rows FU-STO-P01
to P06 list where this differs from MIT 1.22.2.

A `KCM:` daemon socket must be a socket, not a symbolic link, owned by root, by
the effective user or by a user the caller names with `kcm::socket::Trust`,
and the Tokio client also checks the peer's user id (FU-KCM-P01). The Linux `KEYRING:` cache treats
only a missing, expired or revoked key as absent and reports permission and
quota errors (FU-KEY-P02).

<a id="leaf-flags"></a>
## Leaf flags

A Cargo feature compiles code; it never grants a runtime permission. Each leaf
flag adds only admitted optional dependencies (`docs/dependency-admission.md`)
and compiles only its own modules and declared seams (`leaf_features.py`).
Without the flag, a relation whose consumer it compiles reports
`ConfigDiagnostic::FeatureUnavailable` (Strict mode refuses it); Camellia
enctype names keep their own diagnostic ([Camellia](#camellia)).

| Leaf flag | What it compiles | What is still needed at run time |
| --- | --- | --- |
| `camellia` | RFC 6803 enctypes | `permitted_enctypes` must name them; `DEFAULT` never includes them |
| `ccache-keyring` | the Linux `KEYRING:` cache | a `KEYRING:` cache name |
| `http-client` | the built-in cookie jar `http::cookies::CookieStore` | the application installs the jar; `Domain` cookies need a public-suffix list it supplies |
| `kkdcp-rustls` | the built-in HTTPS transport of the KDC proxy and the HTTP client | explicit trust anchors ([TLS trust](#tls-trust)) |
| `localauth` | `.k5login`, `auth_to_local` and the local-name mapping | a verified principal and the caller's `AccountResolver`; every failure denies ([Local authorization](#local-authorization)) |
| `pkinit` | PKINIT, anonymous PKINIT and `pkinit_cert_match` | configured identities and KDC anchors; RSA-mode PKINIT stays refused ([RSA-mode PKINIT](#rsa-pkinit)) |
| `spake` | SPAKE pre-authentication | a KDC offer and the client's password; no fallback once SPAKE has started |
| `tracing` | an adapter from trace events to the `tracing` crate | an application subscriber; identities are withheld unless the application asks for them |

The platform stores are not a leaf flag: they live in the companion crate
([Platform stores](#platform-stores)).

<a id="platform-stores"></a>
## Platform stores

`MSLSA:` (the Windows LSA ticket cache), the macOS `API:` cache and the Mach
transport of `KCM:` come from the workspace crate `rskrb5-ng-os`
(`publish = false`), which an application adds itself: `rskrb5-ng` never
depends on it and keeps `#![forbid(unsafe_code)]`. The companion confines its
unsafe code to the OS calls, each with a `SAFETY` comment, copies every OS reply
into owned values and parses it with safe code that Miri checks
(`docs/dependency-admission.md`, section `rskrb5-ng-os`).
`MSLSA:` reads never ask a KDC for a ticket, and mutations of the logon session
need `MslsaStore::with_mutation(true)`. A configuration whose
`kcm_mach_service` names a service other than MIT's default while no Mach
transport is installed fails with `error::Kcm::NoMachTransport`; it never falls
back to a socket.

<a id="tls-trust"></a>
## TLS trust

The built-in TLS transports (`kkdcp-rustls`: the KDC proxy transport and the
HTTP client's `HttpExchange`) use rustls with the pure-Rust RustCrypto
provider, TLS 1.3 or 1.2. There is no implicit trust store and no certificate
bypass: the KDC proxy trusts the realm's `http_anchors` (`FILE:` and `DIR:`;
an `ENV:` anchor is refused, where MIT reads the variable) and the roots the
application configured, and the HTTP exchange trusts only the roots given to
`with_pem_roots`. With no anchor the request fails with `NoAnchors` before any
connection is made. The certificate is checked against the URL's host name,
a redirect is never followed by the transport, and a failure after the
handshake is reported as possibly delivered, so a password change keeps its
outcome-unknown classification. The HTTP exchange speaks `https` only.

<a id="channel-bindings"></a>
## HTTP channel bindings

`http::agent::NegotiateHttpClient` opens the connection first
(`HttpExchange::connect`) and builds each Negotiate token for the connection
that carries it. `ChannelBindingPolicy` decides what goes into the token:

- `WhenAvailable` (the default) binds the token to the RFC 5929
  `tls-server-end-point` value of the TLS connection when the exchange reports
  one, and sends it unbound otherwise.
- `Required` sends no token over a connection without bindings
  (`error::HttpClient::ChannelBindingUnavailable`).
- `Off` derives nothing from the connection.

What a bound token proves: an acceptor that checks bindings refuses it on a
TLS connection to another server certificate, so a token relayed to another
TLS endpoint fails there. A retry connection whose server certificate differs
from the one that carried the challenge is refused before any token is built
(`error::HttpClient::ChannelChanged`). What it does not prove: `WhenAvailable`
sends unbound tokens over plain HTTP and over an exchange that reports no TLS
channel, a binding protects nothing against an acceptor that ignores it, and
it does not authenticate the server by itself; that is the certificate check
of [TLS trust](#tls-trust).

<a id="host-canonicalization"></a>
## Host-name canonicalization

No constructor, no `Principal::host_based_service`, no ordinary ticket request
and no `gss::Name::import` looks up DNS to name a service, whatever
`dns_canonicalize_hostname`, `rdns` and `qualify_shortname` say. Only the
explicit host-acquisition operations do: `CanonicalizationPolicy::acquire`,
`client::Tokio::get_host_service_ticket`,
`gss::Credential::acquire_host_service_ticket` and
`NegotiateHttpClient::with_host_name_policy`. Inside them DNS, a reverse lookup
and `qualify_shortname` only propose names; a name other than the requested
host is used only when the caller's `HostNamePolicy` approves it, because DNS
answers are not authenticated. `qualify_shortname` never falls back to the
system's search domains. In the HTTP client only the principal changes: the
TLS server name, the `Host` header, the redirect and cookie origin and the
channel binding stay the URI host's.

<a id="tgs-fast"></a>
## TGS FAST

Implicit FAST armor of TGS requests is opt-in (`TicketCreds::with_fast`,
`client::Tokio::with_tgs_fast`; default `Off`), where MIT armors every TGS
request (`send_tgs.c:178`): armoring changes the request every existing TGS
exchange sends. Once armor is on, a reply that fails any FAST check (it does
not decrypt, bind the nonce, finish over the ticket with the armor key's
checksum type or carry the strengthen key) ends the exchange under every
policy. Only a reply without any `PA-FX-FAST` is taken for a KDC without FAST,
and only under `Opportunistic`; `Required` refuses it.

<a id="authentication-indicators"></a>
## Authentication indicators

Indicators count only inside an AD-CAMMAC whose service verifier verifies under
the key that decrypted the ticket (RFC 7751 section 4, key usage 64; MIT
`cammac_util.c:36-59`), also through AD-IF-RELEVANT or AD-KDC-ISSUED inside it.
A CAMMAC whose verifier is absent or does not verify refuses the AP-REQ, where
MIT skips a bad one (`authdata.c:555-558`); a CAMMAC in an authenticator is
refused, because the client could copy it from another ticket; a bare
AD-AUTHENTICATION-INDICATOR is never an indicator. The verified values reach
`ValidatedApReq::auth_indicators` and the `auth-indicators` GSS name attribute.

<a id="gss-transfer"></a>
## GSS context and credential transfer

`gss` exports a context or a credential only sealed under a caller-supplied
256-bit `TransferKey` with the RFC 8009 `aes256-cts-hmac-sha384-192` profile;
the header is authenticated with the payload, the exported object is consumed,
and a `TransferLedger` refuses a transfer id it has already imported. MIT's
export format is not used, because it carries the keys in the clear. The RFC
1964 and RFC 4757 per-message token formats serve only DES3 and RC4 contexts
whose enctype policy permits them (`allow_des3`, `allow_rc4`); a token naming
single DES is refused.

<a id="long-term-keys"></a>
## Long-term keys

No long-term key leaves a client: the client facade has no accessor for the
key it derived from a password or read from a keytab (gokrb5 `Client.Key`),
a deliberate security divergence recorded with the manifest row GO-client-8
(disposition D14, [`docs/gokrb5-parity.md#client-key-export`](gokrb5-parity.md#client-key-export)).
Callers that need a key derive it with the `crypto` string-to-key functions
from their own secret or read their own `Keytab`.

<a id="negoex"></a>
## NegoEx

`gss::negoex` is the NegoEx negotiation framework with mechanisms the caller
supplies over a registered `GssMechanism`, as MIT 1.22.2 has it, proven
against MIT's `negoextest` mechanisms. No Kerberos scheme is bundled: no
specification defines a Kerberos scheme or Kerberos tokens inside NegoEx, and
neither MIT's nor Heimdal's krb5 mechanism implements the NegoEx interface.
The parser refuses malformed messages that MIT's trusts (FU-NEG-P02).

<a id="windows-api-ccache"></a>
## Windows API credential cache

The legacy KfW `API:` cache is omitted by owner decision D13. It requires the
Windows-only CCAPI/server integration; this crate does not wrap MIT Kerberos or
load a native Kerberos implementation. [MIT cache types](https://web.mit.edu/kerberos/krb5-latest/doc/basic/ccache_def.html)
describe API credentials held by a server process. API is not the separately
named MSLSA Windows LSA store. An explicit API cache request returns a typed
unsupported-store error; it never falls back to another identity or cache.
This is a platform/integration omission, not a claim MIT removed API caches.

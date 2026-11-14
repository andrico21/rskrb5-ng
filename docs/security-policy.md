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
skips only secure unimplemented Camellia with a diagnostic; strict mode rejects
it. No Camellia implementation is included. See
[MIT configuration](https://web.mit.edu/kerberos/krb5-1.22/doc/admin/conf_files/krb5_conf.html),
[encryption types](https://web.mit.edu/kerberos/krb5-1.22/doc/admin/conf_files/kdc_conf.html#encryption-types)
and [MIT list evaluation](https://github.com/krb5/krb5/blob/krb5-1.22.2-final/src/lib/krb5/krb/init_ctx.c#L411-L492).

KDC-supplied password derivation has minimum **4096** iterations for AES-SHA1
([RFC 3962 section 4](https://www.rfc-editor.org/rfc/rfc3962.html#section-4))
and **32768** for AES-SHA2
([RFC 8009 section 4](https://www.rfc-editor.org/rfc/rfc8009.html#section-4)).
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

The checked PA boundary rejects known unsupported credential mechanisms with
`error::Client::Encode` targeting `PA-DATA`: legacy Unix-time/hardware/SAM,
SESAME/DCE, modern PKINIT, extra TGT, X509 S4U, authentication sets,
FAST armor, encrypted challenge, OTP, EPAK, PKINIT key exchange, PKU2U, SPAKE,
OAuth2 and passkey mechanisms. Outgoing peer-only enctype hints (11/19/23/165)
and the embedding wrapper PA-GET-FROM-TYPED-DATA (22), whose nested data the
policy cannot check, are rejected too; incoming capability parsing is
unchanged. Draft-9 retains its permanent typed policy cause. Cookies,
ordinary informational PA data and unknown extension IDs remain opaque; unknown
payloads are not a supported credential mechanism or a promise of nested policy
enforcement. Implementing a new credential PA type requires extending admission
and its inventory tests.

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
as RSA transport. Current PKINIT itself awaits plan 2.

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

<a id="windows-api-ccache"></a>
## Windows API credential cache

The legacy KfW `API:` cache is omitted by owner decision D13. It requires the
Windows-only CCAPI/server integration; this crate does not wrap MIT Kerberos or
load a native Kerberos implementation. [MIT cache types](https://web.mit.edu/kerberos/krb5-latest/doc/basic/ccache_def.html)
describe API credentials held by a server process. API is not the separately
named MSLSA Windows LSA store. An explicit API cache request returns a typed
unsupported-store error; it never falls back to another identity or cache.
This is a platform/integration omission, not a claim MIT removed API caches.

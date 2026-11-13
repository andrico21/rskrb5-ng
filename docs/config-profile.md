# Profile composition, typed relations and name expansion

WP-01 (todo 15) delivers MIT profile composition, explicit-context credential-name
expansion, bounded readers, typed relations and diagnostics. The generated
[relation catalogue](config-relations.md) covers 43 libdefaults, 28 realm and six
section rows. Each setting has an effective consumer or a diagnostic naming its
deferred plan-2 package; unsupported restrictions fail closed.

The delivery index links the completed parts of this reference. Stage labels
identify the implementation sequence, not outstanding work. The docs tests parse
the delimited status/link rows and check their local destinations.

<!-- profile-delivery:start -->
| Part | Status |
| --- | --- |
| [A: composition](#composition) | delivered |
| [B1: expansion](#expansion) | delivered |
| [B2: readers and consumers](#readers) | delivered |
| [C1: initial typed relations](#relations-c1) | delivered |
| [C2: complete libdefaults](#relations-c2) | delivered |
| [D: realm and section relations](#relations-d) | delivered |
| [E: diagnostics](#diagnostics) | delivered |
| [F: generated catalogue](#catalogue) | delivered |
<!-- profile-delivery:end -->

<a id="composition"></a>

## Reference and lookup classification

The reference is MIT **krb5-1.22.2-final**, commit
`8570e77819563e036027e1da789d08ec9333ed4d`.
[prof_get.c:215–249](https://github.com/krb5/krb5/blob/krb5-1.22.2-final/src/util/profile/prof_get.c#L215-L249)
returns only the first value for scalar lookup;
[155–194](https://github.com/krb5/krb5/blob/krb5-1.22.2-final/src/util/profile/prof_get.c#L155-L194)
collects all values for multi-valued lookup. Boolean and integer getters use
the scalar lookup. A whitespace/comma-separated list inside one value is **not**
a multi-valued profile relation. This crate refuses a `[plugins]` `disable` or
`enable_only` value that is empty or holds ASCII whitespace instead of keeping
it as one name (see the divergence list).

The table below groups representative lookups; the generated catalogue lists
every typed relation and its current consumer or deferred classification.

| Section | Relations | Lookup kind |
| --- | --- | --- |
| libdefaults | allow_rc4, allow_des3, allow_weak_crypto, canonicalize, dns_canonicalize_hostname, dns_lookup_kdc, dns_lookup_realm, forwardable, ignore_acceptor_hostname, k5login_authoritative, noaddresses (alias no_addresses), proxiable, rdns, verify_ap_req_nofail | Boolean; first value |
| libdefaults | ccache_type, clockskew, default_ccache_name, default_client_keytab_name, default_keytab_name, default_realm, k5login_directory, kdc_default_options, kdc_timesync, realm_try_domains, renew_lifetime, safe_checksum_type, ticket_lifetime, udp_preference_limit | Single; first value |
| libdefaults | default_tgs_enctypes, default_tkt_enctypes, permitted_enctypes, extra_addresses, preferred_preauth_types | Delimited list inside a single value; first relation |
| realms / realm | kdc, kpasswd_server, master_kdc, admin_server | Repeated list; accumulate in source order |
| realms / realm | default_domain | Single; first value (legacy parse-only field) |
| domain_realm | each mapping key | Single; first value; existing DNS case folding retained |

`admin_server` is multi-valued for **libkrb5 location and kpasswd fallback**:
[locate_kdc.c:273–296,538–576](https://github.com/krb5/krb5/blob/krb5-1.22.2-final/src/lib/krb5/os/locate_kdc.c#L273-L296),
[changepw.c:60–89](https://github.com/krb5/krb5/blob/krb5-1.22.2-final/src/lib/krb5/os/changepw.c#L60-L89).
The separate kadm5 consumer selects a single string; this crate does not yet
implement that consumer.

Typed decoding preserves the distinction: `auth_to_local`, capaths
intermediates, plugin `disable`/`enable_only`/`module`, and endpoint
`primary_kdc` are multi-valued. Other libdefaults list syntax (for example
`spake_preauth_groups`) is contained in a scalar relation. Unknown paths are
retained during composition and reported by the diagnostic classifier. Typed
decoding does not activate the deferred mechanism consumers.

## Sources, finals and syntax

Files in `KRB5_CONFIG` compose in platform path-list order (colon on Unix). A
directory entry uses the same filter as `includedir`: ASCII alphanumerics, `-`,
`_`, or a non-dot name ending `.conf`. Sorting is bytewise. An entry that is a
directory (or a symlink to one) is skipped, as in MIT, and does not count
against the include file limit (v0.2.2: `IncludeFile` for a directory,
`IncludeCycle` for a symlink to a directory already being read). The same filter
applies to a directory passed to `Config::load` or `Config::load_paths` (v0.2.2:
an `Io` error); one that cannot be listed is `IncludeDir` (v0.2.2: `Io`).
Includes execute at their directive site, even inside a subsection (v0.2.2 ran a
directive only outside a subsection), with fresh syntax state and the shared
profile tree; the parent resumes its original state (v0.2.2 continued in the
section where the included text ended). A relative `include` or `includedir`
path is used as written and resolved against the process working directory, as
MIT does (`fopen` on the token) and v0.2.2 did, also inside an included file: it
is not rebased on the including file's directory. Every source, whether an
included file or a file of a path list, starts outside every section, so a
relation before its first section header is an `InvalidLine` (v0.2.2 read such
lines into the section that was open at the `include` or at the end of the
previous file; MIT ignores them). A file of a path list that another file of the
list includes is read twice (v0.2.2: `IncludeCycle`). See
[prof_parse.c:214–256](https://github.com/krb5/krb5/blob/krb5-1.22.2-final/src/util/profile/prof_parse.c#L214-L256).

`[section]*`, `subsection* = {`, `}*`, and `relation* = value` prevent later
contributions to the marked scope, within the file and across files. Earlier
values remain; a final value does not replace them. The defining block still
contributes its own values. See
[prof_parse.c:92–210](https://github.com/krb5/krb5/blob/krb5-1.22.2-final/src/util/profile/prof_parse.c#L92-L210)
and [prof_tree.c:208–249](https://github.com/krb5/krb5/blob/krb5-1.22.2-final/src/util/profile/prof_tree.c#L208-L249).

Comments begin with `#` or `;` after optional leading whitespace. The gokrb5
extension also recognizes them after C-locale ASCII whitespace outside quotes;
Unicode space before `#` or `;` is value data. `RULE:[2:$1;$2]` survives
unchanged. v0.2.2 cut a line at the first `#` or `;` anywhere in it, so
`default_realm = A#B` was `A`; it is `A#B` here. Quoted values support escaped
quotes, backslashes, newline, tab and backspace. Braces are structural only in a
subsection assignment or closing-brace line, not arbitrary value text. As in MIT
([prof_parse.c:177](https://github.com/krb5/krb5/blob/krb5-1.22.2-final/src/util/profile/prof_parse.c#L177)),
`{` opens a subsection only when it is the whole value, blanks aside; unlike
MIT, a comment after blanks is allowed too (`A = { # c` opens one; MIT reads the
plain value `{ # c`). `{}`, `{ kdc = k }` and `{#` are plain values.

Unquoted assignment padding is removed, but only ASCII whitespace (space, tab,
CR, LF, VT, FF) counts as padding; Unicode space characters at the edges of a
value are value data.

### Deliberate divergences and bounds

- Missing or unreadable explicitly named `KRB5_CONFIG` entries are errors; MIT
  skips them.
- Section headers are case-insensitive (`[Realms]`, `[Plugins]`), as in v0.2.2;
  MIT compares them exactly. Relation names are case-insensitive too, except in
  `[appdefaults]`, `[capaths]`, `[plugins]` (interface and control names), the
  realm names of `[realms]` and the `auth_to_local_names` entries, which keep
  their case as MIT does.
- Leading whitespace before a directive is accepted. No dynamic module code is
  loaded.
- The unquoted value-suffix `value*` final form is a gokrb5 extension. It
  applies to every relation except the rule-language `auth_to_local` and
  `pkinit_cert_match` values, and the `*` is dropped from the value. v0.2.2
  honoured it only in the `kdc`, `admin_server`, `master_kdc` and
  `kpasswd_server` lists and kept the `*` in other values, so
  `default_realm = X*` was `X*` there and is `X` here.
- Non-comment content before the first section header, a BOM line and a stray
  line such as `garbage line` included, is an `InvalidLine`. MIT ignores every
  line before the first line that starts with `[`
  ([prof_parse.c:326](https://github.com/krb5/krb5/blob/krb5-1.22.2-final/src/util/profile/prof_parse.c#L326)),
  so it silently loses the first section of a file that starts with a BOM.
  `tests/config/mutation_profile.rs`
  (`profile_syntax_rejects_malformed_components`) pins the rejection.
- A relation with an empty name is an `InvalidLine`, including `* = A` once the
  final marker is removed. MIT rejects a line that starts with `=` but accepts
  `* = A` as an unmatchable node with an empty name
  ([prof_parse.c:152](https://github.com/krb5/krb5/blob/krb5-1.22.2-final/src/util/profile/prof_parse.c#L152),
  [203](https://github.com/krb5/krb5/blob/krb5-1.22.2-final/src/util/profile/prof_parse.c#L203));
  this crate's data model cannot represent an empty name.
- An unclosed subsection at the end of a file is an `InvalidRealmsSection` in
  every section; MIT accepts it because `profile_parse_file` never checks the
  group level
  ([prof_parse.c:418–436](https://github.com/krb5/krb5/blob/krb5-1.22.2-final/src/util/profile/prof_parse.c#L418-L436)).
- `include` and `includedir` arguments lose ASCII padding at both ends; MIT
  removes only leading blanks and a trailing CR or LF, so it keeps trailing
  spaces and tabs in the file name.
- A closing quote may be followed only by C-locale ASCII whitespace; MIT
  ignores everything after the closing quote.
- A file with any byte that is not UTF-8 is refused as a whole, with kind
  `InvalidData`: `File` for a top-level file, `IncludeFile` for an included file
  and `Io` for `from_reader`; MIT reads bytes. v0.2.2 had the same restriction
  (its top-level error was `Io`).
- Total source bytes, including caller text and root files: **4 MiB** (v0.2.2: 1
  MiB, counted over included files only, so a root of any size was read). Every
  filesystem read stops at remaining budget plus one byte.
- Total files, including repeated reads and root files: **256** (the v0.2.2
  limit was 64 included files).
- Include depth: **8 edges**, with root depth zero. Subsection nesting is also
  capped at eight to bound path allocations. Excess uses `IncludeTooDeep`.
- Typed limits: `IncludeTooDeep`, `IncludeTooMany`, `IncludeTooLarge`.
  Canonical active-chain cycles use `IncludeCycle`; re-reading a completed
  source is not a cycle. An unclosed subsection is an error in every section,
  unknown ones included, and always reports `InvalidRealmsSection`.
- A `[plugins]` `disable` or `enable_only` value that is empty or holds ASCII
  whitespace (`"a b"`, `""`) is an `InvalidLine`; MIT compares each value with
  `strcmp` as one module name
  ([plugin.c:179–186](https://github.com/krb5/krb5/blob/krb5-1.22.2-final/src/lib/krb5/krb/plugin.c#L179-L186)),
  loads the file and disables nothing for such a value. A comma form is one
  name, as in MIT. `capath_and_plugin_names_use_c_locale` in
  `tests/config/value_whitespace_sites.rs` pins the rule; the `[capaths]` realm
  tokens follow it, and a token emptied by a final marker (`B = *`) is an
  `InvalidLine` as well. v0.2.2 skipped both sections.
- v0.2.2 read relations only in `[libdefaults]`, `[realms]` and
  `[domain_realm]`; every other section is parsed, so a line there that is not
  a relation, brace or comment is an `InvalidLine` (MIT rejects a line without
  `=` too,
  [prof_parse.c:148–151](https://github.com/krb5/krb5/blob/krb5-1.22.2-final/src/util/profile/prof_parse.c#L148-L151)).
- Permanent protocol rejection checks run before discarded relations can hide
  forbidden protocol selections. They cover every relation of every section
  except `[domain_realm]` and the `auth_to_local_names` entries, `[login]` and
  `[appdefaults]` included, although MIT's library reads no `[login]` section
  (the removed `login.krb5` application read it through MIT 1.7, and its
  `krb4_*` keys through MIT 1.6); an enabled `krb4_*` key counts whatever its
  value is (`krb4_config` and `krb4_realms` are paths and are rejected as well).
  A `krb4_*`, `v4_*`, `pkinit_*`, `flag_rsa_protocol`, `kpasswd_unprotected` or
  `kpasswd_cleartext` selector loads when its value is empty or false (`0`,
  `no`, `off`, ...); `pkinit_key_exchange` and `pkinit_kex` are rejected for
  `rsa`, `rsa-only`, `key-transport` and `dh-less` and load for every other
  value; `kpasswd_protocol` and `kpasswd_version` load only for `protected`,
  `rfc3244` or a supported version number (`kpasswd_protocol = false` or an
  empty value is rejected). An empty value opens a pending subsection in
  `[realms]`, `[appdefaults]`, `[plugins]` and `[capaths]`, as in MIT, so
  `krb4_convert =` there is a `Policy` error where MIT reports a missing `{`; in
  `[libdefaults]` and `[login]` it is the empty-scalar extension and counts as
  disabled.

## Independent expected values

`tests/fixtures/profile/mit-sample.conf` copies the sample stanzas from
[krb5_conf.rst:1237–1256](https://github.com/krb5/krb5/blob/krb5-1.22.2-final/doc/admin/conf_files/krb5_conf.rst#L1237-L1256).
`mit_documentation_sample_matches_expected_values` checks `ATHENA.MIT.EDU`,
DNS booleans, three ordered Athena KDCs and two ordered example KDCs against
that sample and the scalar/list getters cited above. Port 88 is the crate's
existing endpoint normalization. This is a source-derived differential fixture,
not a claim that a live MIT process was executed.

The `resolve_realm_applies_bare_domain_tags_to_subdomains` fixture is
MIT's three-tag example at
[krb5_conf.rst:585–603](https://github.com/krb5/krb5/blob/krb5-1.22.2-final/doc/admin/conf_files/krb5_conf.rst#L585-L603):
`crash.mit.edu` and hosts below `.dev.mit.edu` map to `TEST.ATHENA.MIT.EDU`,
while `dev.mit.edu` and `mit.edu` map to `ATHENA.MIT.EDU`.

Composition and boundary tests live in `tests/config/profile*.rs`; the original
config tests remain, with deliberately changed expectations recorded in the
follow-up register and task evidence.

<a id="expansion"></a>
## Explicit-context name expansion (B1)

`config::parameters::expand(template, &ExpansionContext)` is pure: it reads no
environment, files or process identity. `DefaultName::{Ccache, Keytab,
ClientKeytab}.expand(&config.libdefaults, &context)` selects the first-wins
template for `default_ccache_name`, `default_keytab_name` or
`default_client_keytab_name`, then applies that same expander. Parsing still
preserves templates and does not discover facts or resolve names implicitly.
Expansion errors are raised when a name is resolved, not by ordinary parsing.

The contract follows MIT's
[parameter table](https://web.mit.edu/kerberos/krb5-1.22/doc/admin/conf_files/krb5_conf.html#parameter-expansion)
and the pinned
[1.22.2 scanner](https://github.com/krb5/krb5/blob/krb5-1.22.2-final/src/lib/krb5/os/expand_path.c).

| Parameter | Explicit context fact |
| --- | --- |
| `TEMP` | Temporary directory |
| `uid`, `euid` | Real/effective `u32` identities, Linux only |
| `USERID` | Real UID on Linux; supplied SID on Windows |
| `username` | Username of the effective identity, not `USER`/`USERNAME` text |
| `null` | Empty string, without a context field |
| `LIBDIR`, `BINDIR`, `SBINDIR` | Installation directories supplied by the embedding application |
| `USERCONFIGDIR`, `USERCONFIG` | Per-user MIT configuration directory |
| `APPDATA` | Roaming application data directory |

`USERCONFIGDIR` is the plan's spelling, supported as an explicit extension:
MIT documents `USERCONFIG`. The Windows directory facts and username may be
provided explicitly on any host; this is not Windows shell-folder or account
discovery. No installation prefix, SID, username or home-derived directory is
invented. Missing facts return `parameters::Failure::Unavailable`; unrecognized
names return `UnknownToken`, and an unterminated `%{` returns
`UnterminatedToken`. Exact names are required: MIT's incidental prefix matching
is deliberately not copied.

`%%` remains two percent signs; it is not an escape. `%%{TEMP}` produces one
literal percent followed by the replacement. Inserted values, including `%{uid}`,
unknown tokens and bare `%{`, remain literal and are never recursively expanded.
Caller facts retain their path separators, rather than MIT Windows' final slash
conversion. The result is resolved data: use literal-path APIs (`Keytab::load`,
`CCache::load`) after handling any store prefix, not token-expanding name APIs.
The name loaders read the Linux procfs UID/eUID and use the
consumer integration described below.

`tests/config/expansion.rs` covers each token, platform identity policy,
missing facts, exact-name errors, malformed tokens, literal percent signs,
nonrecursive Unicode replacements and resolution of all three profile names.

<a id="readers"></a>
## Reader adapters and dynamic providers (B2)

GO-config-1 names gokrb5 `Load`, `NewFromString`, `NewFromReader`,
`NewFromScanner`, `New` and `JSON`. Their Rust equivalents are respectively
`Config::load`/`from_path`, `parse`/`from_string`, `from_reader` (also accepts
`BufRead`), `new`, and `json`. No Go scanner object or redundant Rust scanner
constructor is required. The existing parity manifest has an area-level
`config` row, not a prescribed Rust constructor-name list.

`from_reader` reads at most **4 MiB plus one sentinel byte**, rejects oversize
input with `IncludeTooLarge`, rejects invalid UTF-8 with `Config::Io` carrying
`InvalidData`, and retains reader I/O causes. Successful bytes enter the same
include-aware composition as `parse`. Root and included bytes share the 4 MiB
budget (v0.2.2: 1 MiB, counted over included files only); a relative include
path resolves against the process working directory, as in v0.2.2 (a reader has
no base directory of its own), with the depth limit (8) and cycle check
unchanged and a file limit of 256 (v0.2.2: 64).

`module MODULEPATH:RESIDUAL` and `module = ...` relations are rejected with
`Config::UnsupportedDynamicModule` in Compatible and Strict modes. This also
applies in `[plugins]` (there only for the exact lowercase `module`: `MODULE` is
an unknown relation, as MIT never reads it), nested or ignored sections,
finalized/discarded scopes, and included sources. No dynamic code is loaded.
These cover MIT-config-54/55 refusal behavior, not the future WP-16
registered-provider implementation.

## Effective default-name consumers (B2)

Configured names now pass through `DefaultName::expand` with explicit facts
built by the credential-discovery adapter, outside profile parsing:

- Tokio ccache default load, save and update (both configured-only and
  environment-override variants), including Negotiate/blocking delegates.
- Tokio configured/default client keytab.
- Service validator and HTTP layer/service configured/default server keytab.

The name environment variables retain precedence. Their explicit values use the
UID-token expansion of the migration guide ("Credential filename identity
tokens"), not profile-template semantics. Expanded
profile values flow into literal-name/path handling without a second scan;
`DIR:` saves retain primary-file publication. The child-process regression
`ambient_templates_are_expanded_once` loads real credentials from a directory
whose substituted value itself contains `%{uid}`.

The adapter reads only requested facts: Linux real/effective IDs from the
procfs reader (`/proc/self/status`); `TMPDIR` (fallback `/tmp`) for non-Windows
TEMP;
Windows `TEMP` and `APPDATA`, with `USERCONFIG[DIR]` derived as
`APPDATA\\MIT\\Kerberos5`. Invalid Unicode is an error. The Windows environment
mapping is an explicit limitation, not a claim of native shell-folder lookup.
The three new environment reads are pinned by exact path/owner in
`ambient_guard`; transitive public consumers document them and literal-input
alternatives. Configured-name loaders avoid the name-override environment but
are not environment-free when their templates request these facts.

All three default-name relations have consumers. Ambient effective-username,
Windows SID and installation-directory discovery is unavailable under the
current no-unsafe/no-new-dependency implementation; such tokens fail typed
`Unavailable` instead of silently selecting a wrong credential. Applications
can supply those facts through the pure API and use explicit literal paths.
Dynamic-module refusal is delivered alongside composition and decoding.

<a id="relations-c1"></a>
## C1: initial typed libdefaults relations

The first group of typed public `LibDefaults` fields covers the 22 values from
`allow_des3` through `ignore_acceptor_hostname`; C2 completes the 43-relation
catalogue. `hostname::Canonicalization` preserves
`Never`, `Always`, and `Fallback`; boolean serde representations remain
compatible, with the additional string `"fallback"`. The boolean `LibDefaults`
builders take `Toggle`; convert a `bool` with `Toggle::from_bool`. New fields
are `default_rcache_name`, `dns_uri_lookup`,
`enforce_ok_as_delegate`, and `err_fmt`.

`src/config/libdefaults/relations.rs::RELATIONS` is the machine-readable source
for the generated catalogue. Its 43 literal rows contain six columns: relation,
value kind, MIT default, consumer symbol or `plan 2 WP-xx`, fail-closed rationale,
and named test. The initial group's tests are in `tests/config/relations_c1.rs`.
Every libdefaults relation is a **scalar lookup**; list tokens are inside that
first value. The generated catalogue is checked by the delivered step-F checker.

The production classifier reads the same table after complete decoding and
enctype resolution. `Config::diagnostics()` exposes its `NotYetEffective`
diagnostics alongside enctype diagnostics. Strict mode rejects every
selected deferred C1 relation. Compatible mode rejects explicit replay-store
names other than `none:` (persistent/cross-process protection is unavailable,
WP-20), and nonempty `extra_addresses` with `noaddresses=false` (address-bound
requests unavailable, WP-04). `none:` does **not** disable current memory replay
protection. With `noaddresses=true`, addresses are typed but only diagnosed.
Absent deferred relations do not generate a diagnostic or activate a feature.

No DNS canonicalization, TXT/URI discovery, GSS credential forwarding, acceptor
name relaxation, error formatting, or cache-format selection is added. Those
requests produce diagnostics: current behavior does not perform the requested
relaxation. GSS context builders reject credential delegation. AS
canonicalization is suppressed to preserve authenticated identity (v0.2.2 set
the option on unarmored AS requests); TGS options still consume the flag. The
table records that partial effectiveness
as WP-04, not as completed AS canonicalization.

Existing consumers now apply `forwardable` to AS and TGS request bits; false
clears a conflicting raw KDC-options bit. `Config::realm_for_host` selects a
domain mapping before `default_realm`, and the high-level service-realm lookup
uses it before its existing client-realm fallback. Explicit service realms
retain precedence. Clockskew reaches reply-validation and acceptor
options; enctype expressions and default-name loaders have WP-02/B2 consumers.

### MIT references and deliberate grammar differences

- [1.22 krb5.conf relation defaults](https://web.mit.edu/kerberos/krb5-1.22/doc/admin/conf_files/krb5_conf.html#libdefaults).
  Build-time `DEFCCNAME`, `DEFCKTNAME`, `DEFKTNAME` are not universal paths.
  This crate uses its B2 defaults. DNS KDC lookup defaults false here rather
  than MIT's true in DNS-enabled builds; URI discovery defaults false here
  because it is unavailable. Replay-name storage is unset here, not a claim
  that MIT's `dfl:` backend exists.
- [prof_get.c](https://github.com/krb5/krb5/blob/krb5-1.22.2-final/src/util/profile/prof_get.c):
  booleans include `on`, `off`, `nil`; historical `f` remains a gokrb5 extension.
  `ccache_type` is signed decimal i32, not a four-value parsing enum.
- [x-deltat.y:143–171](https://github.com/krb5/krb5/blob/krb5-1.22.2-final/src/lib/krb5/krb/x-deltat.y#L143-L171):
  C1 clockskew accepts seconds, ordered `d/h/m/s` terms, `h:m[:s]`, and
  `d-h:m:s`. Signed components are accepted when their checked i32 total is
  nonnegative. Colon fields after the first have at most two digits; duplicate
  or reordered units, concatenated whitespace-separated digits, overflow and
  trailing garbage are errors. Negative tolerances fail closed. MIT's context
  initializer actually reads clockskew as integer seconds: time syntax here is
  the requested extension. Unlike MIT's lexer, unknown trailing characters
  are not treated as end-of-input. Other duration relations use the same
  bounded interval parser described in C2 below.
- [localaddr.c](https://github.com/krb5/krb5/blob/krb5-1.22.2-final/src/lib/krb5/os/localaddr.c):
  address lists accept commas and ASCII whitespace. This crate deliberately
  rejects malformed address tokens instead of silently narrowing the list.

Parse diagnostics are excluded from serde. The serde round-trip regression
compares all serialized fields and explicitly pins that diagnostic exclusion.
The malformed-address regression expects `InvalidAddress` for a bad token
(v0.2.2 dropped it silently); a valid uppercase fixture keeps the case-folding
and address-order assertions of the v0.2.2 test.

<a id="relations-c2"></a>
## C2: complete 43-relation libdefaults catalogue

`RELATIONS` has **43 rows**, with six columns and one
production classifier. `relations_match_todo_15_item_2` compares its ordered
names and count with an independent literal checklist copied from todo 15
item 2. `tests/config/relations_c2.rs` provides one named table-driven test
per additional relation. Realm/section decoding and generated documentation are
also delivered, as described below; deferred mechanism providers remain plan 2.

MIT defaults and relation types are sourced from the pinned
[1.22.2 krb5.conf documentation, lines 274–420](https://github.com/krb5/krb5/blob/krb5-1.22.2-final/doc/admin/conf_files/krb5_conf.rst#L274-L420).
The table records each default explicitly. `k5login_authoritative` now defaults
true, matching MIT. No local-login authorization exists yet, so neither value
grants login; k5login directory/authority are diagnostic (WP-17).

New typed public fields preserve KCM service/socket names, the inert plugin
directory template, optional shortname suffix, total request duration, SPAKE
group names, and channel-binding-aware signaling. Empty shortname suffix is
distinct from unset. SPAKE words are case-insensitive and canonicalized to
`edwards25519`, `P-256`, `P-384`, `P-521`; empty lists remain empty. Unknown
names fail instead of MIT's trace-and-skip behavior. No SPAKE operation,
KCM connection, DNS qualification, or executable plugin loading occurs.

The remaining fail-closed rules apply in both modes:

- `noaddresses=false` (including `no_addresses`) requires unavailable
  address-bound requests and is rejected, even without extra addresses.
- Any nonzero `request_timeout` requires a total deadline across discovery,
  retries and password delivery; existing per-attempt timeouts do not satisfy
  it. It is rejected rather than wrapped in a cancellation-unsafe timeout.
- `verify_ap_req_nofail=true` requires unavailable initial-credential proof
  orchestration and is rejected (WP-11).
- `client_aware_channel_bindings=true` requires unavailable GSS signaling and
  is rejected (WP-12).

Zero/false values above are diagnostic; all explicitly selected deferred C2
relations are errors in Strict mode. `rdns`, realm-domain probing, clock
correction, shortname qualification, KCM and plugin settings cannot activate
their missing behaviors. SPAKE group and preauth preference lists are not
requirements to use a mechanism. `preferred_preauth_types` is diagnostic for
ordering (v0.2.2 had no diagnostics); the draft-9 IDs 14/15 are removed from the
default (v0.2.2: `[17, 16, 15, 14]`) and diagnosed individually.
`permitted_enctypes` remains an effective WP-02 cryptographic policy, not a
deferred relation.

`proxiable` now reaches both AS/TGS option consumers and the encoded AS request;
false clears a conflicting raw option bit, as for C1 forwardable. Existing
ticket/renewable lifetime consumers now receive the bounded MIT interval
parser used by C1 clockskew. Negative totals, overflow, malformed unit order,
and trailing garbage fail closed; zero renewable lifetime remains disabled.

[MIT init_ctx.c:265–270](https://github.com/krb5/krb5/blob/krb5-1.22.2-final/src/lib/krb5/krb/init_ctx.c#L265-L270)
uses the decimal signed-integer profile getter for `kdc_default_options` and
`kdc_timesync`. Bare option numbers now mean decimal; explicit `0x`/`0X`
bitmasks remain a documented extension. Signed values preserve their 32-bit
bit pattern. `kdc_timesync` accepts signed integers like the implementation
(nonzero means enabled), despite the documentation recommending 0 or 1.
Profile scalar first-wins applies (v0.2.2: the last value won), rather than
claiming the old
documentation's XOR wording describes the current getter.

[sendto_kdc.c:474–494](https://github.com/krb5/krb5/blob/krb5-1.22.2-final/src/lib/krb5/os/sendto_kdc.c#L474-L494)
defines effective Auto transport UDP preference: negative uses default 1465
(v0.2.2: never UDP first), large values cap at 32700 (v0.2.2: no cap), and
request size equal to the limit uses UDP first (as in v0.2.2). It governs KDC
requests only: `Auto` for a password change is TCP first and ignores it
(v0.2.2 applied it there too). Explicit TCP/UDP still bypass Auto selection.
Table-driven lib tests exercise this actual consumer, including limit 1 and cap
boundaries.

Three old fixture tests used `noaddresses=false`: each now asserts its typed
WP-04 error on the same original input, then checks its existing loading,
realm, and serialization behavior with an explicitly addressless copy. This
is a deliberate policy change, not silently weakening those fixtures. The
follow-up register records the behavior changes and their proofs.

<a id="relations-d"></a>
## D: typed realm and other profile sections

`REALM_RELATIONS` has **28 rows**: all 13 relations in the krb5.conf realms
section, nine client PKINIT relations, four additional KDC PKINIT names shared
by realm profiles, and two retained draft-9 rejection names. Each row has the
same six columns as `RELATIONS` (43 rows). `SECTION_RELATIONS` has six
rows: domain_realm, capaths, appdefaults, disable, enable_only, module.
`realm_and_section_catalogues_are_complete` verifies the exact independent
name lists. Every row has a named table-driven test.

References are pinned to **krb5-1.22.2-final**:

- [Realm relations](https://github.com/krb5/krb5/blob/krb5-1.22.2-final/doc/admin/conf_files/krb5_conf.rst#L424-L577).
- [Client PKINIT options](https://github.com/krb5/krb5/blob/krb5-1.22.2-final/doc/admin/conf_files/krb5_conf.rst#L967-L1203).
- [KDC PKINIT names/defaults](https://github.com/krb5/krb5/blob/krb5-1.22.2-final/doc/admin/conf_files/kdc_conf.rst#L766-L856).
- [Application lookup implementation](https://github.com/krb5/krb5/blob/krb5-1.22.2-final/src/lib/krb5/krb/appdefault.c#L38-L138).
- [Capaths/appdefaults/plugins examples and order](https://github.com/krb5/krb5/blob/krb5-1.22.2-final/doc/admin/conf_files/krb5_conf.rst#L614-L779).

### Realm values and classification

`Realm::relations` exposes typed `section_values::Value` variants: Boolean,
Text, List, Choice, Locations. Locations distinguish FILE, DIR, ENV, PKCS12,
and PKCS11 references; the latter two are identity-only. No files, environment
variables, native modules, certificates or credentials are loaded. PKINIT EKU
and DH choices are case-insensitive finite vocabularies. Unknown choices are
errors, not MIT's fallback-to-default behavior. The documented DH choices are
accepted; MIT's additional numeric rounding/prefix parsing is not copied.

Repeated endpoints, authorization rules, certificate rules, trust locations,
identities and hostnames retain source order. Scalars select their first value.
`primary_kdc` metadata takes precedence over the legacy master list; the primary
retry consumer remains WP-10. KDC and kpasswd endpoint consumers keep their
`host[:port]` syntax and the admin-server port-464 fallback, except that bare
IPv6 literals keep their full address and an IPv6 `admin_server` yields
`[addr]:464` (v0.2.2 cut `[::1]:749` to `[:464`; see CHANGELOG [0.3.0],
"Transport, DNS, IPv6, SRV and kpasswd retry"). This does not add Unix socket or
HTTPS proxy transport.

`disable_encrypted_timestamp=true` errors in both modes with
`NotYetEffective { relation: "disable_encrypted_timestamp", package:
"plan 2 WP-07" }`. False is diagnostic. PKINIT trust, EKU, CRL, freshness and
identity policies are diagnostic because no PKINIT certificate is accepted
today; no requested restriction is bypassed by a PKINIT exchange. Authorization
rules/names are diagnostic because no local-login grant is performed.
An admitted `auth_to_local_names` subsection emits one WP-17 diagnostic,
including an explicit empty map; omission and discarded later scopes emit none.
V4 and enabled draft-9 selectors keep todo-14's permanent typed rejection.
Every deferred diagnostic becomes an error in Strict mode.

Rule languages are retained as inert strings in typed lists. `auth_to_local`
checks its DEFAULT/RULE discriminator; certificate matching checks the initial
MIT component discriminator. **Full regex/rule-language compilation and
evaluation are not implemented** (WP-17/WP-06); no claim of complete semantic
validation of those languages is made. Rule-valued relations preserve trailing
`*` as regex syntax instead of treating it as the legacy value-final extension;
MIT's `tag*` final marker is supported (v0.2.2 treated `A*` as part of a realm
name and ignored `key* = value`).

### Application, graph and plugin APIs

`Config::appdefault(app, realm, relation)` returns a borrowed string using
app+realm, app, realm, global precedence. It selects the first scalar at the
winning path, even if empty. `appdefault_boolean` uses the same lookup and
returns `Result<Option<bool>>`: missing is None; malformed is an error rather
than MIT's silent false coercion. Application and realm keys preserve case.
The generic API follows the actual four-level `appdefault_get` implementation;
it does not add an undocumented fifth lookup in `[realms]`.

`Config::capath(client, server)` returns a typed `Route::Direct` for `.` or
`Route::Via` for ordered intermediate realm names; absent pairs remain None.
Mixed direct/intermediate values and empty/whitespace-containing realm tokens
are rejected. Case, repetitions and profile finals are preserved. The graph
is diagnostic WP-11 metadata, **not** active routing or transited validation.
The acceptor requires explicit caller transit policy for
cross-realm acceptance; callers do not acquire that policy by parsing capaths.

`Config::plugins` holds per-interface repeated disable/enable_only names. No
plugin registry or loading is introduced. Interface names and the control names
`disable`, `enable_only` and `module` preserve case and match exactly, like MIT
(`prof_tree.c` compares with `strcmp`): `CLPREAUTH` is an interface without a
consumer, and `DISABLE` or `MODULE` under an interface is an unknown relation.
The `[plugins]` header itself is case-insensitive, like every section header.
Controls that would disable the existing encrypted-timestamp mechanism
(`clpreauth` disable encrypted_timestamp or enable_only excluding it) fail
closed. Controls for unavailable mechanisms are diagnostic. `module` is
`UnsupportedDynamicModule` in every mode. Server-only `[kdcdefaults]`,
`[dbmodules]`, `[logging]` headers, including empty sections, construct
`ConfigDiagnostic::ServerOnly` in production and error in Strict mode. No server
configuration is acted upon.

The `[domain_realm]` map keeps its exact, longest-suffix and dotted-apex rules;
lookups now fold case and a bare tag covers its subdomains (v0.2.2 matched only
the exact name and `.suffix` tags). `auth_to_local_names` mapping keys preserve
principal case.
Application paths serialize as ordered path/value pairs so nonempty hierarchical
keys remain valid JSON. D adds no implicit ambient reads or plan-2 mechanism.
The generic PKINIT libdefaults/realm-subsection override hierarchy is not added
by this realm-section substep; its mechanism consumers remain WP-06.

<a id="diagnostics"></a>
## E: complete diagnostic promotion and classification review

`Config::diagnostics()` returns the diagnostics accumulated by profile parsing:
UnknownSection, UnknownRelation, NotYetEffective, UnsupportedSecureEnctype,
ServerOnly, and IgnoredPreauthType. Each is constructed in production and has
a strict-mode error. The conversion is an exhaustive match, so adding another
diagnostic requires an explicit error mapping. Strict parsing rejects **every**
diagnostic, including removed draft-9 preferences before their additional
NotYetEffective preference-ordering diagnostic can mask them.

UnknownSection includes empty headers; unknown nested relations/subsections
carry their full path. Unknown sections yield one section diagnostic rather
than one per contained option. Dynamic namespaces (application options,
realm/domain names, local-name maps and plugin interface names) remain open;
unknown relation names and shapes are reported. Finalized/discarded later
values do not generate diagnostics. Disabled recognized protocol selectors,
`safe_checksum_type`, and `no_addresses` are not mislabeled as typos.
Compatible mode cannot infer the security intent of unknown names: it reports
them, while Strict rejects them.

### Review of all three tables

All **43 libdefaults + 28 realm + 6 section rows** were reviewed. Effective
consumers and permanent protocol rejections have their tests/classification.
`classification_e` iterates every deferred production-table row and requires
an independently supplied boundary case: **25 libdefaults, 21 realm, 3 section
rows**. It parses real profiles, not just classification predicates.

Every deferred row has a satisfied/not-weaker value that returns its named
diagnostic in Compatible and fails in Strict. Where a valid value asks for
stricter behavior, both modes must fail with NotYetEffective:

| Scope | Relation | Satisfied side | Stricter side rejected |
| --- | --- | --- | --- |
| libdefaults | default_rcache_name | none: (memory protection retained) | dfl: |
| libdefaults | extra_addresses | list with noaddresses=true | nonempty list with noaddresses=false |
| libdefaults | noaddresses | true | false |
| libdefaults | request_timeout | 0 | positive total deadline |
| libdefaults | verify_ap_req_nofail | false | true |
| libdefaults | client_aware_channel_bindings | false | true |
| realms | disable_encrypted_timestamp | false | true |
| plugins / clpreauth | disable | absent mechanism such as pkinit | encrypted_timestamp |
| plugins / clpreauth | enable_only | includes encrypted_timestamp | excludes encrypted_timestamp |

Other deferred rows have **no valid stricter value against current behavior**;
this is an explicit test-case decision, not an omitted negative test. Their
per-row rationale records why: no certificate accepted, credential delegated,
local-login grant, KCM/native module used, DNS rewriting, or a preference/
presentation rather than a restriction. For example, CRL checking, delegation
enforcement, and authoritative k5login are already satisfied by the absence of
their corresponding acceptance/delegation/grant path. Capaths does not enable
cross-realm acceptance or override caller transit policy; default rejection
is stricter. Malformed values are not manufactured “tightening” examples.

### B2 unavailable facts: final disposition

| Token | Missing fact at credential-name resolution | Rationale |
| --- | --- | --- |
| username | typed Unavailable error | Never substitute an environment username or another user's credential. |
| USERID on Windows | typed Unavailable error | Native SID discovery is absent; guessing selects the wrong identity. |
| LIBDIR | typed Unavailable error | No known installation prefix; never search another credential location. |
| BINDIR | typed Unavailable error | No known installation prefix; never invent a path. |
| SBINDIR | typed Unavailable error | No known installation prefix; never invent a path. |
| uid/euid outside Linux | typed Unavailable error | Platform policy; do not implicitly equate UID and SID. |

These are errors in both modes **at effective credential-name resolution**,
not parse-time ambient discovery. Parsing retains templates; callers may
supply facts via ExpansionContext. Tests cover all three name selectors with
missing/supplied facts and the existing configured-cache consumer's causal
Unavailable error. The three effective table rows record the decision. Inert
plugin_base_dir containing `%{LIBDIR}` remains NotYetEffective: no module/path
is loaded/resolved. No identity or environment discovery was added.

### Plan QA fixture provenance

The host's `/etc/krb5.conf` was read on 2026-11-01. Its configuration values
are copied to `tests/fixtures/profile/host-e.conf`, with normalized comments/
whitespace and includedir replaced by an absolute test fixture path. It retains
rdns=false, default_domain, and the Heimdal fcc-mit-ticketflags option (now an
UnknownRelation diagnostic).

`/etc/krb5.conf.d/` was read and was **empty**. No real local crypto-policy
include could be copied. `host-e.d/crypto-policies` is explicitly Fedora-shaped,
using the secure AES+Camellia line already tested in todo 14—not a claim of a
Fedora installation on this host. Both the host-plus-include fixture and the
independent snippet parse in Compatible with diagnostics and AES IDs 20/19/18/17.
TEST.RSKRB5 disable_encrypted_timestamp=true fails with the named WP-07 error.
Tests read no host config at runtime and require no LF-only checkout or network.

<a id="catalogue"></a>
## F: generated catalogue and differential fixture provenance

[config-relations.md](config-relations.md) is generated directly from the three
Rust tables by `scripts/check-config-relations.py --write`. Its self-test asserts
checked-in text equals generated output after CRLF normalization; CI and prek
also run the read-only checker. It verifies the independent pinned inventories,
all 77 named tests, and complete literal tuple consumption. Documentation drift,
opaque expressions, duplicates, missing names/tests and comment/string decoys
are negative self-test cases. The document is packaged with this file and the
security policy; README links to it with a package-local relative link.

The MIT differential tests are **source-example-derived**, not live MIT runs:

| Test/fixture | MIT example and independent expected result |
| --- | --- |
| mit-sample.conf / mit_documentation_sample_matches_expected_values | krb5_conf.rst:1237–1256; ATHENA.MIT.EDU default, ordered three Athena and two EXAMPLE KDCs; scalar first-wins from prof_get.c:215–249. |
| resolve_realm_applies_bare_domain_tags_to_subdomains | krb5_conf.rst:585–603; crash.mit.edu and subdomains of dev.mit.edu map TEST.ATHENA.MIT.EDU, dev.mit.edu and mit.edu map ATHENA.MIT.EDU. |
| section_composition_d::appdefaults | krb5_conf.rst:709–731 and appdefault.c:38–138; app+realm before app before realm before global, using distinct strings to expose precedence. |
| section_composition_d::capaths | krb5_conf.rst:628–695; repeated intermediates retain client traversal order and dot means direct; test uses renamed realms and adds final-marker regression. |

All URLs above are pinned by the reference links in sections A/D. Host-e.conf
is a normalized host fixture, not an MIT differential oracle. Its Camellia
snippet retains the explicitly recorded Fedora-shaped provenance from E.

# Dependency admission

New dependencies of `rskrb5-ng` enter only through this process, which
`scripts/lint-gates/dep_admission.py` enforces (`--enforce`, `--self-test`) in the
`lint-gates` CI job. The rules come from three owner decisions of the parity
plan: D3 (new dependencies are optional, pure Rust, vetted, no C libraries),
D6 (vetted Rust crates that only call the OS are allowed) and D10 (features
without new dependencies are always compiled; dependency-bearing features are
optional, additive leaf flags).

## The rules

1. **Optional and leaf-only.** A direct dependency added after the baseline
   (below) is `optional = true` and enabled only by leaf features, the keys of
   `[package.metadata.rskrb5-ng.leaf-features]` in `Cargo.toml`. A dependency
   no `dep:` entry enables gets an implicit feature of its own name, which is
   not a leaf, so it fails. A dependency may serve several leaves. Its record
   lists them.
2. **The one non-optional exception** (owner, 2026-11-18): `rustix` under
   `[target.'cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))'.dependencies]`,
   with `default-features = false` and exactly the features its admission record
   lists, used only by the shared secure-environment check. `rustix` in
   `[dependencies]`, in any other target table or with another feature fails,
   and so does any second non-optional dependency. The record is written by the
   todo that adds the dependency.
3. **Forbidden crates**, in the normal, build or dev graph of any first-party
   package (the main crate, `rskrb5-ng-os` if present, the fuzz crate) and as a
   direct dependency of any kind or target (also under a `package =` rename):
   `openssl*`, `native-tls`, `ring`, `aws-lc*`, `cryptoki*`, `libloading` and
   `bindgen`.
4. **OS wrappers** (D6) may carry `links` keys or build scripts: `libc`,
   `linux-raw-sys`, `rustix`, `windows-sys`, `windows-targets` and
   `windows-link`, plus a macOS system-framework wrapper only if the todo that
   adds the macOS credential stores admits one. Any other package with a `links`
   key, or with a build-dependency on `cc`, `cmake` or `pkg-config`, fails.
5. **Companion crate.** A first-party package other than `rskrb5-ng-os` may not
   add a non-optional third-party dependency, and `rskrb5-ng-os` adds only its
   dependency on `rskrb5-ng`.
6. **Fuzz runtime.** The existing `libfuzzer-sys` to `cc` edge is grandfathered
   in the graph of the standalone fuzz crate only. It is a fuzzing runtime, not
   shipped code. The gate fails if `libfuzzer-sys`, or any package reachable only
   through it, appears in the graph of the main crate or of `rskrb5-ng-os`.
7. **A record per dependency.** Every dependency added after the baseline, dev
   dependencies included, needs a record below whose version is a locked version
   of that package.

## How the gate reads the graph

It walks the feature-resolved graph, `cargo tree --all-features -e
normal,build,dev --target <t> --prefix none --format '{p}'`, for
`x86_64-unknown-linux-gnu`, `x86_64-pc-windows-msvc`, `aarch64-apple-darwin` and
`i686-unknown-linux-gnu`, and reads `links` keys and build dependencies of the
packages found there from `cargo metadata --all-features`. Raw metadata alone
over-approximates: it reaches `ring` through an unused `hickory-proto` feature.
The main crate is resolved with `--locked`. The fuzz crate has no tracked lock;
cargo writes an ignored `fuzz/Cargo.lock` on the first run. `--offline` passes
through to cargo for runs without network access. A manifest-stage failure stops
before cargo is called.

## Executor decisions (an owner may veto)

- **Baseline.** The "added after the baseline" test uses the direct dependencies
  at `c790b57a21e0a681f1bbf8db41462bdf69f5c27f` (plan 1's accepted commit). They
  are grandfathered and need no record. The list below is that commit's direct
  dependencies. The gate also compares it with `git show <baseline>:Cargo.toml`
  when the commit is present; CI's checkout is shallow, so there it trusts the
  committed list.
- **Dev dependencies** added after the baseline need a record (not optionality),
  because the forbidden list and the vet policy apply to them.
- **Fuzz graph.** It is resolved from its own ignored lock, so it follows the
  registry state of the run, not a committed lock.

## Record format

One `###` heading per crate and one `- Field: value` line per field, all seven
mandatory. Text inside fenced blocks is ignored.

```text
### example-crate
- Version: 1.2.3
- Leaf flags: camellia, pkinit
- Licence: MIT OR Apache-2.0
- Source review: what was read and what it does with untrusted input
- Constant-time and zeroization: how secrets are compared and wiped (crypto crates)
- Cargo vet: audit or exemption in supply-chain/, with the reason
- Maintenance: last release, maintainers, advisories
- Features: fs, process (rustix only: the exact feature list of the target table)
```

A record may extend `deny.toml`'s licence allow-list (BSD-3-Clause, ISC) or its
duplicate-version skips, each with a reason stated in the record.

## Records

### camellia
- Version: 0.2.1
- Leaf flags: camellia
- Licence: MIT OR Apache-2.0 (both already on the `deny.toml` allow list; no change to it).
- Source review: read in full on 2026-11-18 from the crates.io tarball (sha256 `d3ed33f9863ee76491bbe0d7e16a225c694d8525287e320dc7fbe71ee212254c`, RustCrypto/block-ciphers, edition 2024, MSRV 1.85). Pure Rust, `#![deny(unsafe_code)]`, no `build.rs`, no `links`, no proc macro; its only dependency is `cipher` 0.5, which is already in the graph (`aes`, `des`). It is the block function only: it takes a key and 16-byte blocks and never parses wire data. This crate uses it for RFC 6803 CBC-CTS and as the cipher of CMAC (`cmac`).
- Constant-time and zeroization: NOT constant-time. `src/utils.rs` `f` reads four 256-byte S-box tables (`SBOXES[i][secret byte]`) once per byte and round; the key schedule (`set_ka`, `set_kb`) calls the same `f`. Table lookups indexed by key- and data-derived bytes leak through the data cache on CPUs that have one (a cache-timing exposure like table-based AES), so the implementation is not table-free. Decision, binding: Camellia enctypes never join the `DEFAULT` expansion, are usable only when named in `permitted_enctypes`, and `docs/security-policy.md#camellia` says why; `crypto::camellia::CONSTANT_TIME` is `false`. Zeroization: the cipher state (the expanded round keys) is wiped on drop only with the crate's `zeroize` feature, which this crate enables (`features = ["zeroize"]`, via `cipher/zeroize`); the key-schedule stack temporaries and register copies are not covered. The Kerberos layer wipes its own derived keys, PBKDF2 intermediates and plaintext scratch.
- Cargo vet: no upstream audit is imported for it; `supply-chain/config.toml` carries `[[exemptions.camellia]]` version 0.2.1, `safe-to-deploy`, like every other RustCrypto crate of the graph (`aes`, `des`, `cipher`); the exemption is not an independent audit, and the source review above is this record's evidence. `cargo vet --locked` passes.
- Maintenance: RustCrypto/block-ciphers, repository pushed 2026-11-17; 0.2.0 on 2026-04-10, 0.2.1 on 2026-06-16, about 2.7 million recent downloads. No RustSec advisory (`cargo audit` clean at admission).
- Features: `zeroize` (this crate's own feature, enabled by the `camellia` leaf)

### cmac
- Version: 0.8.0
- Leaf flags: camellia
- Licence: MIT OR Apache-2.0 (already on the allow list).
- Source review: read in full on 2026-11-18 from the crates.io tarball (sha256 `ac78aa94ce13e432b332a4d1bf2eff167d3a2520188ee05b337180a42fd2e62e`, RustCrypto/MACs, edition 2024, MSRV 1.85; 185 lines of source: `src/lib.rs` and `src/block_api.rs`). Pure Rust, no `unsafe` (the repository's lint table denies undocumented unsafe; there is none), no build script, no `links`. Dependencies: `cipher` 0.5 and `digest` 0.11 (feature `mac`), both already in the graph, and `dbl` 0.5.0 (RustCrypto/utils, 181 lines, `#![forbid(unsafe_code)]`, new to the graph, used only here: the GF(2^128) doubling of the CMAC subkeys, computed with shift and multiply-by-mask arithmetic, no branch on the data). Inputs are message bytes already in memory; no allocation and no parsing.
- Constant-time and zeroization: the CMAC loop is data-independent except the branch on the message length (`pos == buf.len()`), which is public. Tag verification goes through `digest::Mac::verify_slice`, which compares with `subtle` in constant time; this crate additionally refuses any tag whose length is not 16 before comparing. The security of the block function is that of `camellia` (above). With the `zeroize` feature, which this crate enables, `CmacCore` wipes its running state on drop (`cipher/zeroize` and `digest/zeroize` follow).
- Cargo vet: `[[exemptions.cmac]]` 0.8.0 and `[[exemptions.dbl]]` 0.5.0, both `safe-to-deploy`, in `supply-chain/config.toml`; exemptions, not independent audits. `cargo vet --locked` passes.
- Maintenance: RustCrypto/MACs, repository pushed 2026-11-17; 0.8.0 on 2026-04-10 (release candidates since 2025-05), about 9.6 million recent downloads; `dbl` 0.5.0 on 2025-09-03 with about 9.3 million. No RustSec advisory (`cargo audit` clean at admission).
- Features: `zeroize` (this crate's own feature, enabled by the `camellia` leaf)

### rustix
- Version: 1.1.6
- Leaf flags: none. The one non-optional exception of rule 2 (owner exception 2026-11-18, plan 2 D10, todo 11): `[target.'cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))'.dependencies]` with `default-features = false`, used only by the shared secure-environment check (`src/secure_env.rs`), which compares the real and effective user and group ids as MIT 1.22.2 `src/util/support/secure_getenv.c:83-99` does when `getresuid` is unavailable. Linux and Android read `AT_SECURE` from `/proc/self/auxv` with `std` and do not use it; Windows has no set-id processes.
- Licence: `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT`; this crate takes it under MIT (already on the `deny.toml` allow list; no change to it).
- Source review: read on 2026-11-19 from the crates.io tarball (sha256 `e5e76742e5294153d4dde1207dbec5bdd81eef6fabdc0d2118babadabfd858aa`, bytecodealliance/rustix, edition 2021, MSRV 1.65): `src/process/id.rs` (`getuid`, `geteuid`, `getgid`, `getegid`, stable since 0.x, no experimental or hash-named module) and the backend each one calls, `src/backend/libc/ugid/syscalls.rs:1-45` on the targets this table selects (macOS and the BSDs build the libc backend): one `unsafe` call of the libc function with no argument, the result wrapped in `Uid`/`Gid`. These calls cannot fail and take no input, so nothing untrusted reaches the crate. Dependencies on the targets of the table: `libc` 0.2.191 and `bitflags` 2.13.2 (both already `safe-to-deploy` in the graph) and `errno` 0.3.14 (rustix's `libc_errno`, MIT OR Apache-2.0, already in the lock through the test-only `tempfile`). It has a `build.rs` (cfg probing only; no `links`, no `cc`), allowed for OS wrappers by rule 4. D6: `rustix` and `libc` are on the OS-wrapper allow list; `errno` and `bitflags` carry no `links` key and no build dependency on `cc`, `cmake` or `pkg-config`.
- Constant-time and zeroization: not a cryptographic crate; it handles no secret. The decision it feeds is a boolean derived once per process.
- Cargo vet: `supply-chain/config.toml` raised `[[exemptions.rustix]]` 1.1.6 from `safe-to-run` to `safe-to-deploy`, and with it the two dependencies that become production edges, `[[exemptions.errno]]` 0.3.14 and `[[exemptions.linux-raw-sys]]` 0.12.1 (rustix's Linux backend, reached in the vet graph although this crate never enables rustix on Linux), each with `notes = "owner exception 2026-11-18 ..."`. Exemptions, not independent audits; the source review above is this record's evidence. `cargo vet --locked` passes.
- Maintenance: bytecodealliance/rustix, repository pushed 2026-11-12; 1.1.6 published 2026-10-27, the newest stable release, about 377 million recent downloads of the crate. No RustSec advisory for 1.1.6 (`cargo audit` clean at admission).
- Features: process

### keyutils-raw
- Version: 0.4.0
- Leaf flags: ccache-keyring
- Licence: BSD-3-Clause (the 3-clause BSD text, Copyright (c) 2018 Ben Boeckel). It is new to the `deny.toml` allow list, which this record extends with exactly `BSD-3-Clause`; `uninit` below is MIT, already allowed.
- Source review: read in full on 2026-11-19 from the crates.io tarball (sha256 `db322e79368bacfd8d7ecba9d9038866d2ff5e78b52377376f38b7360878392b`, mathstuf/rust-keyutils, edition 2018): `src/functions.rs` (643 lines), `src/types.rs`, `src/constants.rs`, `src/lib.rs`. It is the safe function layer over `libc::syscall(SYS_add_key | SYS_request_key | SYS_keyctl)`: each public function takes typed arguments (`KeyringSerial` is a `NonZeroI32`, strings are `&str`) and wraps one syscall in one `unsafe` block with `CString` arguments that outlive the call. This crate uses `keyctl_get_keyring_id`, `add_key`, `keyctl_search`, `keyctl_link`, `keyctl_unlink`, `keyctl_clear`, `keyctl_read`, `keyctl_describe`, `keyctl_set_timeout` and `keyctl_get_persistent(uid, ring)` only, which is what MIT 1.22.2 `src/lib/krb5/ccache/cc_keyring.c` calls. No `build.rs`, no `links`, no proc macro; dependencies `errno` 0.3 (already locked), `libc` 0.2 (already locked, an OS wrapper of rule 4), `log` 0.4 (already locked) and `uninit` 0.3.0 (new to the graph, MIT, 2709 lines, no dependencies, no build script; `keyctl_read` and `keyctl_describe` take the caller's buffer as `uninit::out_ref::Out<[u8]>`, which this crate builds from a `&mut [u8]` and never reads before the kernel wrote it). Hazards found and handled by this crate: `cstring()` unwraps on an interior NUL (this crate refuses a NUL in any name before the call), the `ignore()` helper asserts that a successful syscall returned 0 (the kernel contract), and a 64-bit key id panics (not possible on Linux). The sibling crates were read and refused: `linux-keyutils` 0.2.5 (Apache-2.0 OR MIT) can add only `user` keys, search only `user` keys, cannot create a keyring, has no keyring timeout and no uid for the persistent keyring, so MIT's layout (a cache is a named keyring of one key per credential) cannot be built on it; `keyutils` 0.4.0 parses key descriptions with `unwrap` (a `;` in a description, which a service principal may contain, panics `Keyring::read`) and brings a second `bitflags` major. `rustix` 1.1.6 has no keyctl module. D6: the crate only calls the OS; `libc` and `errno` carry no `links` key to `cc`, `cmake` or `pkg-config`.
- Constant-time and zeroization: not a cryptographic crate and it keeps no copy of a payload: `keyctl_read` writes into the caller's buffer, which this crate allocates as `Zeroizing<Vec<u8>>`, and `add_key` borrows the caller's slice (an owning zeroizing buffer of this crate). The kernel holds the payload in kernel memory (user keys) or encrypted tmpfs (`big_key`).
- Cargo vet: `supply-chain/config.toml` gets `[[exemptions.keyutils-raw]]` 0.4.0 and `[[exemptions.uninit]]` 0.3.0, both `safe-to-deploy`; exemptions, not independent audits, and the source review above is this record's evidence. `errno`, `libc` and `log` keep their existing exemptions. `cargo vet --locked` passes.
- Maintenance: mathstuf/rust-keyutils, 0.4.0 published 2023-08-17 (the newest release), about 505 thousand recent downloads, also the engine of the `keyutils` crate; `uninit` 0.3.0 is the version `keyutils-raw` requires (0.6.2 exists, 2023-11-20). No RustSec advisory (`cargo audit` clean at admission). The crate is stale rather than abandoned: the keyctl syscall ABI it wraps is stable, and the Linux leaf can move to another wrapper through this same record format without a change to the public API.
- Features: none (`keyutils-raw` has no features). It is a Linux-only dependency, `[target.'cfg(target_os = "linux")'.dependencies]`, optional, enabled only by the `ccache-keyring` leaf.

## Baseline

One line per direct dependency at the baseline commit, `<package> <kind>
<dependency>`.

```baseline
rskrb5-ng normal aes
rskrb5-ng normal base64
rskrb5-ng normal chrono
rskrb5-ng normal compcol
rskrb5-ng normal des
rskrb5-ng normal hex
rskrb5-ng normal getrandom
rskrb5-ng normal hickory-resolver
rskrb5-ng normal http
rskrb5-ng normal hmac
rskrb5-ng normal md-5
rskrb5-ng normal md4
rskrb5-ng normal pbkdf2
rskrb5-ng normal rasn
rskrb5-ng normal rasn-kerberos
rskrb5-ng normal rc4
rskrb5-ng normal serde
rskrb5-ng normal serde_json
rskrb5-ng normal sha1
rskrb5-ng normal sha2
rskrb5-ng normal thiserror
rskrb5-ng normal tokio
rskrb5-ng normal tower-layer
rskrb5-ng normal tower-service
rskrb5-ng normal zeroize
rskrb5-ng dev axum
rskrb5-ng dev hex
rskrb5-ng dev picky-asn1
rskrb5-ng dev picky-asn1-der
rskrb5-ng dev picky-krb
rskrb5-ng dev pretty_assertions
rskrb5-ng dev proc-macro2
rskrb5-ng dev proptest
rskrb5-ng dev serde
rskrb5-ng dev syn
rskrb5-ng dev tokio
rskrb5-ng dev toml
rskrb5-ng-fuzz normal libfuzzer-sys
rskrb5-ng-fuzz normal rskrb5-ng
```

## Tracked upstream items

### chrono (RUSTSEC-2026-0543)

`chrono` is reached through the `messages` feature (`rasn`, `rasn-kerberos`) and
ignored as an informational "unmaintained" advisory in `deny.toml` and
`.cargo/audit.toml`; `advisory_ignores.py` holds the two ignore sets equal.
State on 2026-11-18 (read from crates.io and GitHub that day):

- `rasn` 0.30.0 (2026-11-02), the latest release, still depends on `chrono ^0.4.38`
  (`default-features = false`, feature `alloc`), as 0.29.0 does. `rasn-kerberos`
  0.30.0 reaches it through `rasn`.
- `librasn/rasn` issue 597, "Replace chrono in the ASN.1 time types", is open
  with no comments; the default branch of that repository still declares
  `chrono`. The commit log since 0.30.0 holds no replacement.
- `chronotope/chrono` issue 1768, "Soft-deprecating chrono and chrono-tz", was
  closed as completed on 2026-11-17 once the advisory was filed; its maintainer
  recommends `jiff`. The latest `chrono` is 0.4.45; no patched version exists.
- `rasn-kerberos` exposes `KerberosTime` as a `chrono` type, so this crate cannot
  drop `chrono` without replacing its ASN.1 codec. Nothing was replaced and
  both ignores stay.

Remove the dependency, and the ignore from both files together, when a released
`rasn` drops `chrono`.

### Cargo lint exemption (rust-lang/cargo#17730)

`manual_readme = "allow"` in `Cargo.toml` mirrors the vendored core's temporary
exemption. The weekly scheduled CI run executes `upstream_issue.py`, which fails
when that issue is closed. The exemption is then removed from `Cargo.toml`, the
core and the allow set together.

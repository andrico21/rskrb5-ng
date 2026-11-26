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

### libc
- Version: 0.2.191
- Leaf flags: ccache-keyring
- Licence: MIT OR Apache-2.0 (both already on the `deny.toml` allow list; no change to it).
- Source review: read on 2026-11-19 from the crates.io tarball (sha256 `65cd87c9a6d60536580b316ad985726104730a5151c99845f2490428ef91240a`, rust-lang/libc, the lock's version). This crate calls no function of it: it names eleven `errno` constants (`ENOSYS`, `EOPNOTSUPP`, `EPERM`, `EACCES`, `EDQUOT`, `ENOKEY`, `EKEYREVOKED`, `EKEYEXPIRED`, `EINVAL`, `ENODEV`, `EILSEQ`) to map the kernel's refusals of the key calls to typed errors in `src/ccache/keyring/kernel.rs`. The numbers differ between Linux architectures (`EDQUOT` is 122 on x86 and 1133 on mips, `ENOKEY` 126 and 161: `src/unix/linux_like/linux/uclibc/mips/mod.rs:131-137` against `musl/b32/x86/mod.rs:380-385`), which is why the constants come from `libc` and are not written down here. `libc` is already in the graph (tokio, mio, socket2 and `keyutils-raw`); this record makes it a direct, optional, Linux-only dependency of the `ccache-keyring` leaf. It has a `build.rs` (cfg probing, no `links` key); D6 and rule 4 list `libc` as an OS wrapper.
- Constant-time and zeroization: not a cryptographic crate; this crate reads constants only.
- Cargo vet: `supply-chain/config.toml` already has `[[exemptions.libc]]` 0.2.191, `safe-to-deploy`; no change. `cargo vet --locked` passes.
- Maintenance: rust-lang/libc, 0.2.191 is the lock's release and the newest stable one; the crate is among the most downloaded of crates.io. No RustSec advisory for it (`cargo audit` clean at admission).
- Features: none beyond the defaults (`default-features = false` here; `keyutils-raw` enables `std`, which cargo unifies)

### tracing
- Version: 0.1.44
- Leaf flags: tracing
- Licence: MIT (already on the `deny.toml` allow list; no change to it). Its dependencies `tracing-core` 0.1.36 (MIT) and `pin-project-lite` 0.2.17 (Apache-2.0 OR MIT) are on it too.
- Source review: read on 2026-11-20 from the crates.io tarball (sha256 `63e71662fa4b2a2c3a26f570f037eb95bb1f85397f3cd8076caed2f026a6d100`, tokio-rs/tracing, edition 2018, MSRV 1.65; the lock's version, 7083 lines of source) with its core `tracing-core` 0.1.36 (sha256 `db97caf9d906fbde555dd62fa95ddba9eecfd14cb388e4f491a66d74cd5fb79a`, 6229 lines). Both have no `build.rs`, no `links` key and no proc macro on this graph: the `attributes` feature, which would add `tracing-attributes`, is not enabled. This crate uses only the `event!` macro (a call site with static metadata and a value set of formatted fields) and the `Level` type; it never creates a span, never calls `set_global_default`, `set_default` or `with_default` in library code, and never touches a `Dispatch`: the application owns its subscriber, and an application without one makes every call a no-op (the macros test `Interest` and the max level first). The `unsafe` of the two crates is the crate's own and stays inside them: `tracing-core` keeps its call sites in an intrusive linked list of atomics (`callsite.rs:239,469`), downcasts a subscriber through `TypeId` (`subscriber.rs`, `dispatcher.rs:314-323,450`) and has its own spin `Once` and `Mutex` for the no-std build (`spin/`, `lazy.rs`, not compiled here: `std` selects `once_cell`); `tracing` has `unsafe` only in `instrument.rs` (the `Instrumented` future, not used) and one `from_utf8_unchecked` over a stack buffer in `lib.rs:1100` (macro support for `format_args`). It parses nothing from the wire: field values are the values this crate formats from its own redacted `TraceEvent`s, whose fields hold counts, numeric codes, static names and bounded identity text, never a secret (the secret-absence test runs the adapter's output through a capturing subscriber). `pin-project-lite` 0.2.17 is a declarative macro crate (1770 lines, 18 `unsafe` in the projection machinery), reached through `tracing::instrument`, which this crate does not call.
- Constant-time and zeroization: not a cryptographic crate; it receives no secret, by the construction of `TraceEvent`.
- Cargo vet: `supply-chain/config.toml` already has `[[exemptions.tracing]]` 0.1.44 and `[[exemptions.tracing-core]]` 0.1.36, both `safe-to-deploy`, because `hickory-net` and `hickory-proto` (through `tokio`) already depend on them; no change. The exemptions are not independent audits, and the source review above is this record's evidence. `cargo vet --locked` passes.
- Maintenance: tokio-rs/tracing, 0.1.44 published 2025-12-18 (the newest stable release; 0.1.42 was yanked), about 286 million recent downloads of the crate (crates.io API, 2026-11-20). No RustSec advisory for `tracing` 0.1.44 or `tracing-core` 0.1.36 (`cargo audit` clean at admission). The crate is already in the graph of every closure that has `tokio` (through `hickory-resolver`), so the leaf adds a direct edge and no new node. `tracing-subscriber`, which the gap analysis lists as an optional candidate, is NOT admitted: the library never installs a subscriber, and the leaf's tests use a hand-written `tracing::Subscriber`.
- Features: `std` (this crate enables it with `default-features = false`; it selects `tracing-core/std`, which `hickory-net` already enables, so the build is the same as the one cargo unifies today)

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

### curve25519-dalek
- Version: 5.0.0
- Leaf flags: spake
- Licence: BSD-3-Clause (already on the `deny.toml` allow list since the `keyutils-raw` record; no change to it).
- Source review: read on 2026-11-20 from the crates.io tarball (sha256 `b5eed333089e2e1c1ac8c6c0398e5e2497b4c9926ca6d0365ed1e099afa5bc23`, dalek-cryptography/curve25519-dalek, edition 2024, MSRV 1.85), the paths this crate uses: `src/edwards.rs` (`CompressedEdwardsY::decompress`, `EdwardsPoint::compress`, `mul_base`, `mul_by_cofactor`, `is_identity`, the `Add`/`Sub`/`Mul<Scalar>` impls and `Zeroize`), `src/scalar.rs` (`from_bytes_mod_order`, `from_bytes_mod_order_wide`, `from_canonical_bytes`, `Zeroize`), `src/backend/mod.rs` (backend dispatch) and `build.rs`. Pure Rust; `build.rs` only selects cfgs (word size, `serial`/`simd`/`avx512` backend) and reads the compiler version through `rustc_version` 0.4.1 (already in the graph); no `links`, no `cc`. The `unsafe` code is the x86_64 SIMD backend (`src/backend/vector/**`, AVX2/AVX-512 intrinsics behind runtime CPU detection with `cpufeatures` 0.3.1, already `safe-to-deploy`) and one `const` table cast in `src/constants.rs:85`; the proc macro `curve25519-dalek-derive` 0.1.1 (MIT/Apache-2.0, 466 lines, new to the graph) only emits `#[target_feature]` attributes for that backend. Untrusted input reaches it in one place here: `decompress` of a 32-byte edwards25519 point. It accepts non-canonical encodings (a y coordinate of p or more is reduced, `FieldElement::from_bytes`) and does not check subgroup membership; this crate therefore re-compresses every decoded point and rejects one that does not encode back to the same bytes, and multiplies by the cofactor (RFC 9588 section 10.1). Not used: `group`, `ff`, `rand_core`, `digest`, `serde`, `legacy_compatibility`.
- Constant-time and zeroization: scalar multiplication (`EdwardsPoint * Scalar`, `mul_base`) is the constant-time windowed method of the crate (the `vartime_*` functions are not called); `Scalar::from_bytes_mod_order(_wide)` reduces with Montgomery arithmetic without data-dependent branches; equality of points is `subtle::ConstantTimeEq`. With the `zeroize` feature, which the `spake` leaf enables, `Scalar` and `EdwardsPoint` implement `Zeroize`; this crate holds its private scalar, the multiplier `w` and the shared element `K` in `Zeroizing` owners. Register and stack copies inside the crate are not covered.
- Cargo vet: `[[exemptions.curve25519-dalek]]` 5.0.0 and `[[exemptions.curve25519-dalek-derive]]` 0.1.1, `safe-to-deploy`; exemptions, not independent audits; the source review above is this record's evidence. `subtle` 2.6.1 (BSD-3-Clause, dalek-cryptography, new to the lock) gets a `safe-to-deploy` exemption too. `cargo vet --locked` passes.
- Maintenance: dalek-cryptography/curve25519-dalek, 5.0.0 published 2026-07-06 (the newest stable release), about 107 million recent downloads. RustSec RUSTSEC-2024-0344 (a timing variability in `Scalar29::sub`/`Scalar52::sub`) affects versions before 4.1.3 only; 5.0.0 is not affected. `cargo audit` clean at admission.
- Features: `precomputed-tables`, `zeroize` (`default-features = false`; `alloc` is not needed)

### p256
- Version: 0.14.0
- Leaf flags: spake, pkinit
- Licence: Apache-2.0 OR MIT (already on the allow list).
- Source review: read on 2026-11-20 from the crates.io tarball (sha256 `d2c9239b2dbc807adbbe147e8cf72ea7450c3a0aabe62cb8e75ff4ec22e1f72a`, RustCrypto/elliptic-curves, edition 2024, MSRV 1.85): `src/arithmetic/scalar.rs` (`PrimeField::from_repr`, `Reduce`, `DefaultIsZeroes`), `src/arithmetic.rs`, and the shared generic arithmetic of `primeorder` 0.14.0 it instantiates (`src/projective.rs` `mul` against `mul_vartime`, `src/affine.rs` `FromSec1Point` with SEC1 decompression). No `unsafe` in `src/`, no `build.rs`, no `links`. Dependencies new to the lock, all RustCrypto or zkcrypto, pure Rust and without build scripts: `elliptic-curve` 0.14.3, `primeorder` 0.14.0, `primefield` 0.14.0, `ff` 0.14.0, `group` 0.14.0, `sec1` 0.8.1, `der` 0.8.3 and `wnaf` 0.14.1; `crypto-bigint` 0.7.10, `hybrid-array`, `rand_core` 0.10.1, `base16ct` 1.0.0 and `subtle` are shared with the existing graph. Untrusted input here is a 33-byte compressed SEC1 point of the KDC; this crate checks the length and the `02`/`03` tag, decodes it with `FromSec1Point` (an x that is not a field element or has no square root is refused), refuses the identity, and re-encodes it to reject a non-canonical form.
- Constant-time and zeroization: `ProjectivePoint::mul` and `mul_by_generator` are the constant-time paths of `primeorder` (this crate never calls the `*_vartime` functions); field and scalar arithmetic come from `primefield` (constant-time Montgomery arithmetic over `crypto-bigint`; P-384 and P-521 use fiat-crypto generated field code) without secret-dependent branches. `Scalar`, `AffinePoint` and `ProjectivePoint` implement `DefaultIsZeroes`, so `Zeroizing<Scalar>` wipes them. `Reduce<FieldBytes>` is a single conditional subtraction, correct only below twice the order; this crate reduces the SPAKE multiplier itself through constant-time scalar arithmetic (two half-width `from_repr` calls, a multiply and an add) for all three NIST groups, see `p521`.
- Cargo vet: `[[exemptions.p256]]` 0.14.0 and the new shared exemptions `elliptic-curve` 0.14.3, `primeorder` 0.14.0, `primefield` 0.14.0, `ff` 0.14.0, `group` 0.14.0, `sec1` 0.8.1, `der` 0.8.3, `wnaf` 0.14.1, all `safe-to-deploy`; `crypto-bigint` 0.7.10 is raised from `safe-to-run` to `safe-to-deploy` because it becomes a production edge (`elliptic-curve`, `primefield`). Exemptions, not independent audits. `cargo vet --locked` passes.
- Maintenance: RustCrypto/elliptic-curves, 0.14.0 published 2026-07-03, about 81 million recent downloads; `elliptic-curve` 0.14.3 on 2026-10-25. No RustSec advisory for these versions (`cargo audit` clean at admission).
- Features: `arithmetic` (`default-features = false`; no `ecdh`, `pem`, `serde`, `std`). The `pkinit` leaf adds `ecdsa` and `pkcs8` (plan 2 todo 8): ECDSA P-256 signatures of the KDC's CMS and certificates are verified with `ecdsa::VerifyingKey` (`ecdsa` 0.17.0 `src/verifying.rs:161` `verify_prehash`, `src/hazmat.rs:136` `verify_prehashed`: range checks of r and s, no low-S normalization for P-256, `NORMALIZE_S = false`), software client keys sign deterministically with `SigningKey` (RFC 6979 nonces, `src/signing.rs:172`), and client keys are read from PKCS#8 or SEC1 DER (`elliptic-curve/pkcs8`, `sec1`). See the `ecdsa` notes under [rsa](#rsa).

### p384
- Version: 0.14.0
- Leaf flags: spake, pkinit
- Licence: Apache-2.0 OR MIT (already on the allow list).
- Source review: read on 2026-11-20 from the crates.io tarball (sha256 `d17b851e6b3e378ab4ecb07fa2ed23f4d15f075735f8fec9fa1e7bdce5f8301f`, RustCrypto/elliptic-curves, edition 2024, MSRV 1.85, `#![forbid(unsafe_code)]`): `src/arithmetic/scalar.rs`, `src/arithmetic.rs` and the shared `primeorder` and `primefield` code reviewed under `p256`. No `build.rs`, no `links`; the dependencies are those of `p256`. Untrusted input: a 49-byte compressed SEC1 point, handled as under `p256`.
- Constant-time and zeroization: as `p256` (`primeorder` constant-time `mul`, `DefaultIsZeroes` scalars and points).
- Cargo vet: `[[exemptions.p384]]` 0.14.0, `safe-to-deploy`, with the shared exemptions listed under `p256`. `cargo vet --locked` passes.
- Maintenance: RustCrypto/elliptic-curves, 0.14.0 published 2026-07-06, about 46 million recent downloads. No RustSec advisory (`cargo audit` clean at admission).
- Features: `arithmetic` (`default-features = false`); the `pkinit` leaf adds `ecdsa` and `pkcs8` for P-384 signatures and keys, as under `p256`.

### p521
- Version: 0.14.0
- Leaf flags: spake, pkinit
- Licence: Apache-2.0 OR MIT (already on the allow list).
- Source review: read on 2026-11-20 from the crates.io tarball (sha256 `4ad64cc32c2dc466317c12ee5853e61f159f9eab1fe7efade0395dc2e7b43449`, RustCrypto/elliptic-curves, edition 2024, MSRV 1.85): `src/lib.rs` (`Uint` is `U576` on 64-bit and `U544` on 32-bit targets), `src/arithmetic/scalar.rs` and `src/arithmetic/field.rs` (fiat-crypto generated field arithmetic from `fiat-crypto` 0.3.0, MIT OR Apache-2.0 OR BSD-1-Clause, taken under MIT, 99,806 lines of generated code without `unsafe`), plus the shared `primeorder` code. No `unsafe` in `src/`, no `build.rs`, no `links`. Finding that shapes this crate's code: `Reduce<FieldBytes>` for P-521 (`src/arithmetic/scalar.rs:81-85`) goes through `elliptic_curve::field::bytes_to_uint` (`elliptic-curve-0.14.3/src/field.rs:17-19`), which TRUNCATES the 66-byte input to 521 bits instead of reducing it modulo the order. The SPAKE multiplier of RFC 9588 section 5 is a 66-byte PRF+ output that must be reduced modulo the order (RFC 9588 section 10.3; MIT 1.22.2 `src/plugins/preauth/spake/openssl.c:149-157` uses `BN_div`), so this crate never calls `Reduce` on it: it splits the octet string into two halves, each below 2^264 and therefore a canonical scalar, and computes `high * 2^264 + low` with the crate's constant-time scalar multiply and add. The same helper serves P-256 and P-384. The RFC 9588 P-521 vectors (reduced multiplier, T, S, K) pass with it.
- Constant-time and zeroization: as `p256`; the private scalar is drawn by rejection sampling over 66 random bytes with the top seven bits cleared (`from_repr` refuses values of the order or more), so its value never influences the time beyond the retry count of rejected candidates.
- Cargo vet: `[[exemptions.p521]]` 0.14.0 and `[[exemptions.fiat-crypto]]` 0.3.0, `safe-to-deploy`, with the shared exemptions listed under `p256`. `cargo vet --locked` passes.
- Maintenance: RustCrypto/elliptic-curves, 0.14.0 published 2026-07-08, about 16 million recent downloads; `fiat-crypto` 0.3.0 on 2025-06-04 (mit-plv/fiat-crypto). No RustSec advisory (`cargo audit` clean at admission).
- Features: `arithmetic` (`default-features = false`); the `pkinit` leaf uses it for P-521 ECDH only (no feature added).

### cms
- Version: 0.3.0-rc.2
- Leaf flags: pkinit
- Licence: Apache-2.0 OR MIT (already on the allow list).
- Source review: read on 2026-11-21 from the crates.io tarball (sha256 `d089eddc8a5c984d82fcf1427367a6fa0d019d5af04b6e3197e86c8989533b8d`, RustCrypto/formats, edition 2024, MSRV 1.87, `#![forbid(unsafe_code)]` with one `unsafe` mention only in that attribute; no `build.rs`, no `links`). The paths this crate uses: `src/content_info.rs` (`ContentInfo`), `src/signed_data.rs` (`SignedData`, `EncapsulatedContentInfo`, `SignerInfo`, `SignerIdentifier`, `CertificateSet`, `SignerInfos`), `src/cert.rs` (`CertificateChoices`, `IssuerAndSerialNumber`) and `src/revocation.rs` (`RevocationInfoChoices`): plain `der` derive structures (`Sequence`, `Choice`, `SetOfVec`), so decoding is `der`'s strict DER reader (below) and every SET OF must arrive DER-sorted. It verifies nothing: signature and digest checks, signer selection, certificate chains and CRLs are this crate's own code in `src/preauth/pkinit/` over the decoded fields (the original DER of the signed attributes and of each `tbsCertificate` is re-encoded by `der` and compared byte for byte with what was received). With `default-features = false` the optional builder dependencies (`aes`, `cbc`, `rsa`, `signature`, `sha*`, `ansi-x963-kdf`) are not enabled; `builder` compiles without them and is not called. The version is a release candidate: it is the only `cms` release on the `der` 0.8 / `x509-cert` 0.3 generation that the rest of the RustCrypto graph (`p256` 0.14) requires; the manifest pins it exactly (`=0.3.0-rc.2`), so no other pre-release is taken implicitly.
- Constant-time and zeroization: not a cryptographic crate (ASN.1 structures only); it handles public CMS data. The signed AuthPack carries the client's DH public value, not a secret.
- Cargo vet: `[[exemptions.cms]]` 0.3.0-rc.2, `safe-to-deploy`; an exemption, not an independent audit; the source review above is this record's evidence. `cargo vet --locked` passes.
- Maintenance: RustCrypto/formats, 0.3.0-rc.2 published 2026-11-09; the newest stable release, 0.2.3, is on the `der` 0.7 generation and cannot share `der`/`spki` with `p256` 0.14. About 7.1 million recent downloads of the crate (crates.io API, 2026-11-21). No RustSec advisory (`cargo audit` clean at admission).
- Features: none (`default-features = false`; the default `pem` is not needed: PEM is decoded by `der`)

### crypto-bigint
- Version: 0.7.11
- Leaf flags: pkinit
- Licence: Apache-2.0 OR MIT (already on the allow list).
- Source review: read on 2026-11-21 from the crates.io tarball (sha256 `914c195c4d7fbc5ed7f88d14cbf85914d5c664967658d43404b263913a477e82`, RustCrypto/crypto-bigint, edition 2024, MSRV 1.87, no `build.rs`, no `links`). It was already in the graph (0.7.10, `elliptic-curve` and `primefield`, a `safe-to-deploy` exemption since the `p256` record); the `pkinit` leaf makes it a direct dependency for finite-field Diffie-Hellman (RFC 4556 section 3.2.3.1) and moves the lock to 0.7.11, which `rsa` 0.10.0 requires (`^0.7.11`). Paths used: `Uint` (`U2048`, `U4096`), `Odd`, `modular::FixedMontyParams::new_vartime` (the public MODP prime) and `modular::FixedMontyForm::pow` (`src/modular/fixed_monty_form/pow.rs:17`, which calls `pow_montgomery_form` with `VARTIME = false`, `src/modular/pow.rs:19-34`: a fixed-window exponentiation whose memory access and time do not depend on the exponent bits), and `pow_vartime` only on public values (the KDC's public value raised to the public subgroup order `q`, the RFC 2631 section 2.1.5 membership check). The `unsafe` occurrences (32 lines) are in the `hybrid-array` conversions and `Limb` casts of the crate's own code, not on these paths. The KDC's public value is untrusted input: this crate decodes it from DER, refuses values outside `2..=p-2` and values not in the order-`q` subgroup before exponentiation.
- Constant-time and zeroization: the client's private exponent is drawn from the OS random generator, held in a `Zeroizing` owner, and only ever used through the constant-time `pow`; `Uint` implements `DefaultIsZeroes` with the `zeroize` feature, which this crate enables. The shared secret is copied into a `Zeroizing<Vec<u8>>` immediately. Register and stack copies inside the crate are not covered.
- Cargo vet: `[[exemptions.crypto-bigint]]` moves from 0.7.10 to 0.7.11, `safe-to-deploy`, and `ctutils` (its constant-time selection helper) from 0.4.7 to 0.4.8; exemptions, not independent audits. `cargo vet --locked` passes.
- Maintenance: RustCrypto/crypto-bigint, 0.7.11 published 2026-11-08 (the newest stable release), about 102 million recent downloads (crates.io API, 2026-11-21). No RustSec advisory (`cargo audit` clean at admission).
- Features: `zeroize` (`default-features = false`)

### der
- Version: 0.8.3
- Leaf flags: pkinit
- Licence: Apache-2.0 OR MIT (already on the allow list).
- Source review: read on 2026-11-21 from the crates.io tarball (sha256 `6a996a108feb8b427a6e12fcf6af4aa83409b79d72c15337d7741368131ee004`, RustCrypto/formats, edition 2024, MSRV 1.85, `#![forbid(unsafe_code)]` with four narrowly allowed `repr(transparent)` reference casts in `src/bytes.rs:29`, `src/string.rs:26`, `src/asn1/octet_string.rs:37` and `src/asn1/sequence.rs:55`; no `build.rs`, no `links`). It was already in the graph through `sec1` (`p256`, the `spake` leaf); the `pkinit` leaf makes it direct. It is the DER reader of every untrusted PKINIT structure that `cms` and `x509-cert` define: lengths are checked against the remaining input before any allocation, indefinite lengths are refused in DER mode, nesting is bounded by `MAX_NESTING_DEPTH = 64` (`src/reader.rs:21`, enforced in `src/reader/position.rs:75`), and SET OF ordering and minimal encodings are enforced. This crate additionally bounds every input before decoding (the `MAX_*` constants of `preauth::pkinit`). The derive macro `der_derive` 0.8.0 (Apache-2.0 OR MIT, 3473 lines, `#![forbid(unsafe_code)]`) is new to the graph through `x509-cert`; `flagset` 0.4.7 (Apache-2.0, 1350 lines, used by `x509-cert` for the KeyUsage bit set) is new as well. `pem-rfc7468` 1.0.0 and `base64ct` 1.8.3 (both Apache-2.0 OR MIT, RustCrypto/formats, constant-time Base64 decoding without lookup tables, `#![forbid(unsafe_code)]` in `pem-rfc7468`; `base64ct` has `unsafe` only in its `str::from_utf8_unchecked` after encoding its own alphabet) come with the `pem` feature and decode the PEM files of anchors, pools, CRLs and identities.
- Constant-time and zeroization: the `zeroize` feature wipes `der`'s owned buffers of secret-bearing types this crate decodes (PKCS#8 private keys); Base64 decoding of PEM key files is constant-time in `base64ct`.
- Cargo vet: the existing `[[exemptions.der]]` 0.8.3 `safe-to-deploy`; new `safe-to-deploy` exemptions for `der_derive` 0.8.0, `flagset` 0.4.7, `pem-rfc7468` 1.0.0 and `base64ct` 1.8.3. Exemptions, not independent audits. `cargo vet --locked` passes.
- Maintenance: RustCrypto/formats, 0.8.3 published 2026-10-25 (the newest stable release), about 175 million recent downloads (crates.io API, 2026-11-21). No RustSec advisory (`cargo audit` clean at admission).
- Features: `alloc`, `oid`, `pem`, `zeroize` (`default-features = false`)

### rsa
- Version: 0.10.0
- Leaf flags: pkinit
- Licence: MIT OR Apache-2.0 (already on the allow list).
- Source review: read on 2026-11-21 from the crates.io tarball (sha256 `23e77fd77e0dea28b3011fd62d15445b7de7959333b0276d930e03be0f755699`, RustCrypto/RSA, edition 2024, MSRV 1.87, no `unsafe`, no `build.rs`, no `links`). Admitted for signature VERIFICATION only, as the plan's Must have allows (RUSTSEC-2023-0071, the Marvin timing attack on private-key operations, is marked patched in 0.10.0 by the advisory database and does not concern verification): RSA PKCS#1 v1.5 signatures on certificates of a KDC chain and on a KDC's CMS SignedData, which most deployed KDC certificates use. This crate never decrypts, never signs and never generates an RSA key with it; RSA client keys sign through the application's `Signer`. Paths used: `PublicKey` from an SPKI (`encoding`: `pkcs1` 0.8.0 and `pkcs8` 0.11.0 decoders, `src/encoding.rs`), `PublicKey::new_with_size_limits` checks (`src/public_key.rs:86-133,233-250`: modulus 1024 to 8192 bits, exponent 2 to 2^33-1, odd), and `pkcs1v15::verify` (`src/pkcs1v15.rs:429-442`: the signature length must equal the modulus size and the value must be below the modulus before the public exponentiation; `pkcs1v15_sign_unpad` compares the whole encoded message). This crate refuses moduli below 2048 bits before calling it. New to the graph: `crypto-primes` 0.7.2 (prime generation, a non-optional dependency of `rsa` that the verification path never reaches), `pkcs1` 0.8.0, `pkcs8` 0.11.0, `spki`, `signature` 3.0.0 (traits only) and `rfc6979` 0.6.0 (through `ecdsa`, deterministic nonces for the software EC signer).
- Constant-time and zeroization: verification handles public data only. `rfc6979` derives ECDSA nonces with HMAC-DRBG from the private scalar and the digest (RFC 6979 section 3.2), so a weak random generator cannot leak the software signer's key; `ecdsa::SigningKey` zeroizes its scalar on drop.
- Cargo vet: new `safe-to-deploy` exemptions for `rsa` 0.10.0, `crypto-primes` 0.7.2, `pkcs1` 0.8.0, `pkcs8` 0.11.0, `signature` 3.0.0, `ecdsa` 0.17.0 and `rfc6979` 0.6.0; exemptions, not independent audits; this record and the `ecdsa` note under `p256` are the evidence. `cargo vet --locked` passes.
- Maintenance: RustCrypto/RSA, 0.10.0 published 2026-11-08 (the newest stable release; RUSTSEC-2023-0071 lists `>= 0.10.0` as patched), about 75 million recent downloads; `ecdsa` 0.17.0 (2026-07-02, about 93 million) and `rfc6979` 0.6.0 (2026-06-30, about 92 million) are RustCrypto/signatures releases of the same generation; `crypto-primes` 0.7.2 (entropyxyz/crypto-primes, 2026-06-10, about 7.3 million). Figures from the crates.io API on 2026-11-21. `cargo audit` clean at admission.
- Features: `encoding`, `pkcs1v15` (`default-features = false`: no `getrandom`, no `std`)

### spki
- Version: 0.8.1
- Leaf flags: pkinit
- Licence: Apache-2.0 OR MIT (already on the allow list).
- Source review: read on 2026-11-21 from the crates.io tarball (sha256 `7ef958a98b9d5da290cfc78946e9f3e61e1e62a18db0d92cac0b83cc161491a9`, RustCrypto/formats, edition 2024, MSRV 1.85, `#![forbid(unsafe_code)]`, 870 lines, no `build.rs`, no `links`). `SubjectPublicKeyInfo` and `AlgorithmIdentifier` as `der` structures: the client's DH/ECDH public value is encoded with them (RFC 4556 section 3.2.3.1 `clientPublicValue`) and the public key of every certificate of a KDC chain is decoded with them before `ecdsa` or `rsa` sees it. No cryptography.
- Constant-time and zeroization: not applicable (public keys only).
- Cargo vet: `[[exemptions.spki]]` 0.8.1, `safe-to-deploy`; an exemption, not an independent audit. `cargo vet --locked` passes.
- Maintenance: RustCrypto/formats, 0.8.1 published 2026-10-05 (the newest stable release), about 155 million recent downloads (crates.io API, 2026-11-21). No RustSec advisory (`cargo audit` clean at admission).
- Features: `alloc` (`default-features = false`)

### x509-cert
- Version: 0.3.1
- Leaf flags: pkinit
- Licence: Apache-2.0 OR MIT (already on the allow list).
- Source review: read on 2026-11-21 from the crates.io tarball (sha256 `e9f58ad685a2945c7c063f5d69b5c27105d75bb85c740380d8fc64e79a098417`, RustCrypto/formats, edition 2024, MSRV 1.87, `#![forbid(unsafe_code)]`, 6418 lines, no `build.rs`, no `links`). The paths used: `Certificate`/`TbsCertificate` (`src/certificate.rs`), `Validity`/`Time` (`src/time.rs`), `Name` (`src/name.rs`), `crl::CertificateList` (`src/crl.rs`) and the extension types `ext::pkix::{BasicConstraints, KeyUsage, ExtendedKeyUsage, SubjectAltName, name::GeneralName}`. Like `cms`, it only defines `der` structures and validates nothing: there is no path validation in the crate, so this crate writes a BOUNDED IN-CRATE VALIDATOR over it with documented rules (`src/preauth/pkinit/chain.rs`; the plan allows this in place of a third-party path validator): at most 8 certificates per chain and 64 candidates, signature verification of every link, validity at the current time, `basicConstraints cA` and `keyCertSign` for every issuer, path length constraints, issuer/subject name chaining, unknown critical extensions refused, the chain must end at a configured anchor, and CRLs from `pkinit_revoke` (or the SignedData) checked by signature, issuer, time and serial. No third-party path validator was admitted: `x509-verify` 0.4.8 only checks one signature and builds no path, and no maintained pure-Rust path builder on the `der` 0.8 generation exists at admission.
- Constant-time and zeroization: not applicable (public certificates).
- Cargo vet: `[[exemptions.x509-cert]]` 0.3.1, `safe-to-deploy`; an exemption, not an independent audit. `cargo vet --locked` passes.
- Maintenance: RustCrypto/formats, 0.3.1 published 2026-11-20 (the newest stable release), about 30 million recent downloads (crates.io API, 2026-11-21). No RustSec advisory (`cargo audit` clean at admission).
- Features: none (`default-features = false`)

### hyper
- Version: 1.12.0
- Leaf flags: kkdcp-rustls
- Licence: MIT (already on the `deny.toml` allow list; no change to it).
- Source review: on 2026-11-21 from the crates.io tarball (sha256 `2c3e324da4c95177d6291d4c8730197c0d1822f8a9766814a4a44fa5ab797c9c`, hyperium/hyper, edition 2021, 22,758 lines of source): the manifest and feature table (with `client` and `http1` only: no server, HTTP/2, FFI or tracing code is compiled), and the API this crate calls, `src/client/conn/http1.rs` (`handshake`, `SendRequest::send_request`, the `Connection` future that this crate polls next to the request), `src/body/incoming.rs` (`Incoming`, `Body::poll_frame`) and `src/rt/io.rs` (`Read`, `Write`, `ReadBufCursor::remaining` and `put_slice`, which let this crate's I/O adapter avoid `unsafe`). The HTTP/1 state machine and its response parser (`src/proto/h1/**` over `httparse`) were NOT reviewed line by line: this record relies on their maturity and fuzzing upstream, which is the reason the plan fixes `hyper` (Context "Transport design") instead of an in-crate parser. Untrusted input is the proxy's HTTP response after TLS: this crate takes only a `200` status, never follows a redirect (hyper has no redirect logic; any other status is `KdcProxy::Status`), bounds the body itself (`Request::max_response`, 1 MiB, checked frame by frame before bytes are kept) and decodes the body only as a KDC-PROXY-MESSAGE (`transport::kkdcp`, fuzzed); hyper's default 400 KiB read buffer bounds the response head. No `build.rs`, no `links`; the `unsafe` code (16 files) is hyper's own buffer and waker machinery. New to the production graph with it: `httparse` 1.10.1 (MIT OR Apache-2.0, `build.rs` for SIMD cfg detection only, `unsafe` SIMD scanning), `http-body` 1.1.0 (MIT), `httpdate` 1.0.3 (MIT OR Apache-2.0, used by the server half only), `want` 0.3.2 (MIT) and its `try-lock` 0.2.5 (MIT), `atomic-waker` 1.1.2 (Apache-2.0 OR MIT); `bytes`, `futures-channel`, `futures-core`, `http`, `itoa`, `pin-project-lite`, `smallvec` and `tokio` are already production edges.
- Constant-time and zeroization: not a cryptographic crate. The request body (a KDC-PROXY-MESSAGE that frames the caller's AS-REQ, TGS-REQ or kpasswd request) is handed to hyper as a `Bytes` copy that hyper does not zeroize; the crate's own copy is a zeroizing owner. Residual copy recorded in `docs/security-policy.md` terms: TLS encrypts the copy on the wire, and memory copies of library internals are not promised to be wiped (gap.md shared contract).
- Cargo vet: `[[exemptions.hyper]]` 1.12.0, `[[exemptions.http-body]]` 1.1.0, `[[exemptions.httparse]]` 1.10.1 and `[[exemptions.atomic-waker]]` 1.1.2 are raised from `safe-to-run` (the `axum` dev-dependency) to `safe-to-deploy`; `[[exemptions.httpdate]]` 1.0.3, `[[exemptions.want]]` 0.3.2 and `[[exemptions.try-lock]]` 0.2.5 are new, `safe-to-deploy`. Exemptions, not independent audits; the source review above is this record's evidence. `cargo vet --locked` passes.
- Maintenance: hyperium/hyper, 1.12.0 published 2026-10-06 (the newest release), about 300 million recent downloads. No RustSec advisory for 1.12.0 (`cargo audit` clean at admission).
- Features: `client`, `http1` (`default-features = false`; no `server`, `http2`, `ffi` or `tracing`)

### rustls
- Version: 0.23.46
- Leaf flags: kkdcp-rustls
- Licence: `Apache-2.0 OR ISC OR MIT`, taken under MIT. Its certificate verifier `rustls-webpki` 0.103.17 and that crate's `untrusted` 0.9.0 are ISC only; this record extends the `deny.toml` licence allow list with exactly `ISC` (a permissive licence, on the plan's list of admissible extensions, Must have "Admission specifics").
- Source review: on 2026-11-21 from the crates.io tarballs (rustls sha256 `48e13bd8c0e9365c43cfa5c9e8f9ad49d3c8444926c9aac819e0e4dc503c8fdf`, 49,208 lines; rustls-webpki sha256 `e3a0760a887c14823fca5a1c970b01d47c328c696c0c64829d1df50e8f853fd5`, 10,622 lines; rustls-pki-types 1.16.0 sha256 `102f35f7de7b06d8c61f1cff6592f5253e0dea431c74867aad5dfd70f44663fb`; untrusted 0.9.0 sha256 `8ecb6da28b8a351d773b68d5825ac39017e680750f980f3a1a85cd8dd28a47c1`): the manifest and feature table (with `default-features = false`, `std` and `tls12` there is no `ring`, `aws-lc-rs`, `brotli`, `zlib` or `log`; the only crypto is the provider this crate passes), `build.rs` (it only sets a cfg on nightly for the unused `read_buf` feature; no `links`), and the API this crate calls: `ClientConfig::builder_with_provider`, `with_protocol_versions` (TLS 1.3 and 1.2, the only versions rustls implements, so nothing below 1.2 can be negotiated), `with_root_certificates`, `with_no_client_auth`, `RootCertStore::add`, `ServerName` and `pki_types::pem::PemObject`. The default verifier this crate relies on is `WebPkiServerVerifier` (chain building to the configured anchors with the provider's signature algorithms, validity time, the `serverAuth` key purpose, and the host-name check against the `ServerName` the connection was opened for); its code and rustls' record and handshake codecs were NOT reviewed line by line: this record relies on rustls' audits and fuzzing upstream. SNI is sent for a DNS-name `ServerName` (on by default) and not for an IP literal. This crate never installs a custom `ServerCertVerifier` (no certificate bypass), and its tests prove that a wrong anchor and a certificate for another host are refused.
- Constant-time and zeroization: the record protection and key exchange are the provider's (see `rustls-rustcrypto`); rustls wipes its traffic secrets with `zeroize` (already in the graph) when connections drop.
- Cargo vet: `[[exemptions.rustls]]` 0.23.46, `[[exemptions.rustls-webpki]]` 0.103.17, `[[exemptions.rustls-pki-types]]` 1.16.0, `safe-to-deploy`; `untrusted` 0.9.0 already has a `safe-to-deploy` exemption (it is in the lock through `ring`). Exemptions, not independent audits. `cargo vet --locked` passes.
- Maintenance: rustls/rustls, 0.23.46 published 2026-10-14, about 298 million recent downloads; rustls-webpki 0.103.17 published 2026-11-12. No RustSec advisory for these versions (`cargo audit` clean at admission).
- Features: `std`, `tls12` (`default-features = false`)

### rustls-rustcrypto
- Version: 0.1.0-pre.0
- Leaf flags: kkdcp-rustls
- Licence: MIT OR Apache-2.0 (already on the allow list). New crates it brings, all RustCrypto or dalek, pure Rust: `aead` 0.6.1, `aes-gcm` 0.11.1, `ghash` 0.6.0, `polyval` 0.7.3, `universal-hash` 0.6.1, `ctr` 0.10.1, `chacha20poly1305` 0.11.0, `poly1305` 0.9.1, `ecdsa` 0.17.0, `rfc6979` 0.6.0, `signature` 3.0.0, `ed25519` 3.0.0, `pkcs1` 0.8.0, `pkcs8` 0.11.0, `spki` 0.8.1, `pem-rfc7468` 1.0.0, `base64ct` 1.8.3, `hkdf` 0.13.0, `rsa` 0.10.0 and `crypto-primes` 0.7.2 (Apache-2.0 OR MIT), and `ed25519-dalek` 3.0.0 and `x25519-dalek` 3.0.0 (BSD-3-Clause, already allowed); `paste` 1.0.15 (MIT OR Apache-2.0) is a proc macro. `crypto-bigint` moves from 0.7.10 to 0.7.11 and `ctutils` from 0.4.7 to 0.4.8 (patch releases the new crates require).
- Source review: read in full on 2026-11-21 from the crates.io tarball (sha256 `c2856ab13701744c79101d343f8cebb5164eec3aafcf3ee1867b5b6033587daa`, RustCrypto/rustls-rustcrypto, edition 2024, MSRV 1.87, 1,699 lines of source in 17 files): `src/lib.rs` (the `CryptoProvider`: TLS 1.3 suites AES-128/256-GCM and ChaCha20-Poly1305, TLS 1.2 ECDHE-ECDSA and ECDHE-RSA suites with the same AEADs only, no CBC and no RSA key exchange; key exchange X25519, P-256, P-384; randomness from `getrandom`'s system generator), `src/kx.rs`, `src/aead.rs`, `src/aead/{gcm,chacha20}.rs` (per-record nonces from rustls' `Nonce::new(iv, seq)`), `src/verify.rs` and `src/verify/{ecdsa,eddsa,rsa}.rs` (the signature algorithms of the certificate and handshake verification: ECDSA P-256/P-384 with SHA-256/384, Ed25519, RSA PKCS#1 v1.5 and PSS with SHA-256/384/512, verification only), `src/sign*.rs` (server keys; not used by a client without client authentication), `src/hash.rs`, `src/hmac.rs`, `src/quic.rs` (not used) and `src/misc.rs`, whose one `unsafe` block transmutes a zero-length array in a const macro (sound). No `build.rs`, no `links`. Findings that shape this crate's use: the crate is a pre-release that its README calls not audited; it is used only behind the opt-in leaf, for the client side, and the plan names it as the required provider (D7). The AES-GCM suites declare `confidentiality_limit: u64::MAX` (rustls' own providers declare 2^24 records for TLS 1.3 key updates); one KDC exchange is a few records, far below any limit. `extract_keys` names every GCM suite `Aes256Gcm`, which matters only for kTLS secret extraction, which this crate never calls. `rsa` 0.10.0 is reached for verification only (RUSTSEC-2023-0071 concerns private-key operations, and `cargo audit` reports no advisory for 0.10.0; plan Must have allows `rsa` for verification only).
- Constant-time and zeroization: AES-GCM, ChaCha20-Poly1305, X25519 and the ECDH and ECDSA arithmetic are the constant-time RustCrypto and dalek implementations already admitted for the `spake` leaf generation (`p256`, `p384`, `curve25519-dalek` 5.0.0); tag comparisons go through `subtle`. Ephemeral key-exchange secrets are dropped after `complete`; with the `zeroize` feature, which this crate enables, the dalek secrets are wiped.
- Cargo vet: `safe-to-deploy` exemptions for `rustls-rustcrypto` 0.1.0-pre.0 and every new crate listed above; `crypto-bigint` 0.7.11 and `ctutils` 0.4.8 replace the 0.7.10 and 0.4.7 exemptions at the same level. Exemptions, not independent audits; the source review above is this record's evidence. `cargo vet --locked` passes.
- Maintenance: RustCrypto/rustls-rustcrypto, 0.1.0-pre.0 published 2026-11-09 (the first release of the 0.1 line, on the RustCrypto `digest` 0.11 generation this crate already uses), about 228 thousand recent downloads. `paste` 1.0.15 (dtolnay/paste, 2024-05-07) carries the informational advisory RUSTSEC-2024-0436 (unmaintained); it is a build-time proc macro that expands identifier concatenations inside `rustls-rustcrypto` and ships no code of its own, so both ignore lists (`deny.toml`, `.cargo/audit.toml`) carry it with that reason. No other advisory (`cargo audit` clean at admission apart from that informational one).
- Features: `std`, `tls12`, `zeroize` (`default-features = false`; no `logging`)

### tokio-rustls
- Version: 0.26.6
- Leaf flags: kkdcp-rustls
- Licence: MIT OR Apache-2.0 (already on the allow list).
- Source review: on 2026-11-21 from the crates.io tarball (sha256 `c9cc2678c2cdd569ef8215e2afd7954ada2ae20b4fdd2c5fe6139a3b02d105db`, rustls/tokio-rustls, 2,328 lines; a search finds no `unsafe` and there is no `build.rs`): the manifest (with `default-features = false` and `tls12` it enables neither `aws_lc_rs` nor `logging`) and the API this crate calls, `src/client.rs` (`TlsConnector::connect`, whose `Connect` future drives the handshake and surfaces a rustls error, a failed certificate verification among them, as `io::Error`, and `client::TlsStream`'s `AsyncRead`/`AsyncWrite`). It parses nothing itself; rustls does.
- Constant-time and zeroization: not a cryptographic crate; the secrets stay in rustls.
- Cargo vet: `[[exemptions.tokio-rustls]]` 0.26.6, `safe-to-deploy`; an exemption, not an independent audit. `cargo vet --locked` passes.
- Maintenance: rustls/tokio-rustls, 0.26.6 published 2026-09-28, about 255 million recent downloads. No RustSec advisory (`cargo audit` clean at admission).
- Features: `tls12` (`default-features = false`)

<a id="rskrb5-ng-os"></a>
### regex
- Version: 1.13.1
- Leaf flags: localauth, pkinit
- Licence: MIT OR Apache-2.0 (the crate and its direct dependencies `regex-automata` 0.4.18 and `regex-syntax` 0.8.11 alike; both already on the `deny.toml` allow list, no change to it).
- Source review: read on 2026-11-22 from the crates.io tarballs (sha256 `f020237b6c8eed93db2e2cb53c00c60a8e1bc73da7d073199a1180401450218d` for `regex`, `ad8553b9b26413251cbf30e620595c7a41b3887f03da04579c0e6b0d6a06b4b2` for `regex-automata`, `d6f6ff9a378485b298a5286656da665ba74413d36db0979633275d2e708145d4` for `regex-syntax`, all rust-lang/regex, edition 2021, MSRV 1.65, none with a `build.rs`, a `links` key or a proc macro) at the lock's versions: 1.13.1 is the release of 2026-07-15 and 0.4.18 of 2026-08-04, chosen over the newer 1.13.2 and 0.4.19 of 2026-11-18 because they have been public for months. What the leaf does with it: it compiles the `(regex)` selector and the `s/re/text/` expressions of an `auth_to_local` RULE (MIT `localauth_rule.c:98,119`) and matches them against the selection string built from a principal name; the pattern and the text come from the administrator's `krb5.conf`, the subject from a verified principal. The engine is the Pike VM of `regex-automata` (feature `nfa-pikevm`, reached through `meta`): O(pattern x subject) time, no backtracking, no look-around, no back-references, so a hostile pattern cannot make a match exponential. This crate adds its own bounds before compiling and matching (`localauth::MAX_*`): at most 2,048 bytes per rule and 512 per pattern, 256 per replacement text, at most 16 substitutions per rule and 256 replacements per substitution, a selection string and every intermediate result of at most 1,024 bytes, a compiled-size limit of 1 MiB (`RegexBuilder::size_limit`) and a nesting limit of 32. `regex-syntax` is `#![forbid(unsafe_code)]`; `regex` has one `unsafe impl` (the unstable `pattern` feature, off); `regex-automata` has `unsafe` in `util/lazy.rs`, `util/pool.rs` (the per-thread cache pool of `meta::Regex`) and in the dense/sparse/hybrid DFA and wire code, none of which is compiled with the features below except the first two. The feature set is `std`, `unicode-case` and `unicode-perl` on `regex` with `default-features = false`: no `perf` (so no `aho-corasick` and no `memchr` are compiled: they stay in `Cargo.lock` as optional edges and are not in the feature-resolved graph that `cargo tree` and `cargo deny` read), no `unicode-age`/`-bool`/`-gencat`/`-script`/`-segment` tables, no `logging`. New packages in the graph: `regex` and `regex-automata`; `regex-syntax` 0.8.11 and (outside this feature set) `memchr` 2.8.3 were already locked (dev graph through `proptest`).
- Second use (leaf `pkinit`, plan 2 todo 28, MIT-config-51): the client-side `pkinit_cert_match` rules (MIT `pkinit_matching.c`: `<SUBJECT>`, `<ISSUER>` and `<SAN>` components are POSIX extended regular expressions compiled with `regcomp(REG_EXTENDED)`). The pattern comes from the administrator's `krb5.conf`; the subject is the text rendering of a certificate of the client's own identity files (an RFC 2253-like DN or a SAN string), so it is local, not remote input. The leaf adds NO new package and enables NO new feature of `regex`; it does not enable `localauth` (`pkinit = [..., "dep:regex"]`). Bounded-engine rules (the `pkinit::matching` module): at most 32 rules per relation, 2,048 bytes per rule, 8 components per rule, 512 bytes per pattern, a compiled-size limit of 256 KiB and a nesting limit of 16 per pattern, 20 candidate certificates (MIT's `MAX_CREDS_ALLOWED`), and a budget of 1 MiB of subject text over one selection, so the work of a selection is bounded by pattern size x budget (the Pike VM is linear in both). The pattern is validated BEFORE `regex` sees it because the engine is not POSIX: back-references, every backslash escape other than one before ASCII punctuation (and not `\<`, `\>`, `` \` ``, `\'`, which GNU reads as operators), `(?` groups, and inside a bracket expression a backslash, a nested class other than `[:name:]` of the POSIX classes, `[.x.]`, `[=x=]` and the `&&`, `--` and `~~` set operators are rejected with a typed error naming the rule; `.` matches a line feed as POSIX does without `REG_NEWLINE`. Divergences from MIT are recorded in `docs/mit-krb5-parity.toml` (row MIT-config-51, `security_divergence`) and in `docs/review/parity-register.md`.
- Constant-time and zeroization: not a cryptographic crate. It receives principal names and configuration text, never a key or a password; the selection string is not a secret (it is the identity that the KDC already put in the ticket).
- Cargo vet: no upstream audit is imported; `supply-chain/config.toml` carries `[[exemptions.regex]]` 1.13.1 and `[[exemptions.regex-automata]]` 0.4.18, both `safe-to-deploy`, raises the existing `regex-syntax` 0.8.11 exemption from `safe-to-run` (a dev-only edge until now) to `safe-to-deploy`, and carries `[[exemptions.aho-corasick]]` 1.1.5, `safe-to-deploy`, because `cargo vet` reads the optional `perf-literal` edge of the lock although this crate never enables it. The exemptions are not independent audits, and the source review above is this record's evidence. `cargo vet --locked` passes.
- Maintenance: rust-lang/regex (BurntSushi and the Rust project), `regex` 1.13.2 published 2026-11-18 (the newest stable release, about 345 million recent downloads), `regex-automata` 0.4.19 (about 378 million); no release of either is yanked. No RustSec advisory against the locked versions (`cargo audit` clean at admission); the past advisories of the crate concern 1.5.x and older.
- Features: `std`, `unicode-case`, `unicode-perl` (this crate's selection; `default-features = false`; cargo enables `regex-automata` `alloc`, `syntax`, `meta`, `nfa-pikevm`, `std`, `unicode-case`, `unicode-perl`, `unicode-word-boundary` and `regex-syntax` `std`, `unicode-case`, `unicode-perl` from them)

### cookie_store
- Version: 0.22.1
- Leaf flags: http-client
- Licence: MIT OR Apache-2.0 (the crate and every new package it brings: `cookie` 0.18.3, `time` 0.3.55 with `time-core` 0.1.9, `time-macros` 0.2.32, `deranged` 0.5.9, `num-conv` 0.2.2 and `powerfmt` 0.2.1, `publicsuffix` 2.3.0, `psl-types` 2.0.11, `document-features` 0.2.12, `litrs` 1.0.0 and `version_check` 0.9.5 are `MIT OR Apache-2.0` or `MIT/Apache-2.0`; both already on the `deny.toml` allow list, no change to it).
- Source review: read on 2026-11-25 from the crates.io tarballs (`cookie_store` sha256 `15b2c103cf610ec6cae3da84a766285b42fd16aad564758459e6ecf128c75206`, pfernie/cookie_store, edition 2021, MSRV 1.88, no `build.rs`, no `links` key, no `unsafe` in `src/`; `cookie` 0.18.3 sha256 `d55f2d6c30eeec7d5c6f98bd4395d4abb1895629eab97ee6522d340623615f8a`, rwf2/cookie-rs, no `unsafe`, a `build.rs` that only asks `version_check` whether `doc_cfg` exists; `publicsuffix` 2.3.0 sha256 `6f42ea446cab60335f76979ec15e12619a2165b5ae2c12166bef27d283a9fadf` and `psl-types` 2.0.11 sha256 `33cb294fe86a74cbcf50d4445b37da762029549ebeea341421c7c70370f86cac`, both `#![forbid(unsafe_code)]`; `time` has `unsafe` for its niche-checked range types, which is the reason it is one of the most used crates of the ecosystem and the reason this record names it). The graph is NEW only for these 13 packages: `url`, `idna`, `percent-encoding`, `log` and `form_urlencoded` were already locked (hickory). What the leaf does with the crate: it is the cookie jar of the HTTP client (`http::cookies::CookieStore`). `cookie_store` implements the RFC 6265 storage model (section 5.3 domain matching, section 5.1.4 path matching, `Secure`, `HttpOnly`, expiry, the public-suffix check when a list is supplied) over `cookie`'s `Set-Cookie` parser. Untrusted input: the `Set-Cookie` headers of a server's response and the request URL. This crate bounds both before the jar sees them: a `Set-Cookie` value over 4096 bytes is dropped (the RFC 6265 section 6.1 minimum limit), a jar holds at most 256 cookies (the crate itself has no limit), only `http` and `https` URLs reach it, and a `Secure` cookie from a cleartext origin or a `Domain` attribute with no public-suffix list configured is refused before `insert_raw` is called (the crate would accept both). The leaf calls `insert_raw` and `matches` only: it never calls `store_response_cookies` or `parse`, because the crate logs the full cookie value of a non-`Secure` cookie at `debug` level through the `log` facade there, and cookies here are credentials. The default feature `serde_json` (and so persistence) is off: the jar lives in memory. The public-suffix list is NOT compiled in: the application passes the text of a list it chose (`publicsuffix::List` parses it), so an unset list is a typed refusal of every `Domain` attribute, never an implicit list and never public-suffix logic of this crate. The lock takes `cookie` 0.18.3 (2026-11-23), the release that fixes RUSTSEC-2026-0594 (private-cookie nonces that repeat in forked processes; this crate never enables `cookie`'s `private` feature, but `cargo deny` and `cargo audit` fail on 0.18.2 and the first admission pinned that release), and `litrs` 1.0.0 (2025-10-20) instead of its one-day-old 1.1.0.
- Constant-time and zeroization: not a cryptographic crate and not constant-time. Cookie values are credentials: the leaf keeps them only inside the jar, the jar type has no `Debug` output of a value, and a `Cookie` header built for a request is a sensitive `HeaderValue`. The crate does not zeroize its cookies on drop; that is a residual copy recorded in `docs/security-policy.md` by the documentation todo.
- Cargo vet: no upstream audit is imported; `supply-chain/config.toml` carries 13 new `[[exemptions.*]]` entries (`cookie`, `cookie_store`, `deranged`, `document-features`, `litrs`, `num-conv`, `powerfmt`, `psl-types`, `publicsuffix`, `time`, `time-core`, `time-macros`, `version_check`), all `safe-to-deploy`; they are not independent audits and the source review above is this record's evidence. `cargo vet --locked` passes.
- Maintenance: `cookie_store` 0.22.1 published 2026-02-16 (pfernie, about 32 million recent downloads), `cookie` (rwf2, about 77 million), `time` 0.3.55 published 2026-08-01 (about 264 million), `publicsuffix` 2.3.0 published 2024-11-14 (about 19 million, slow-moving by nature: the list data is not in the crate); no locked version is yanked. No RustSec advisory against the locked versions (`cargo audit` and `cargo deny check` clean at admission).
- Features: `public_suffix` with `default-features = false` (so no `serde_json` and no `preserve_order`); cargo enables `cookie` `percent-encode`, `time` `alloc`, `formatting`, `macros`, `parsing`, `std` and `publicsuffix` `idna`, `punycode` from it

### url
- Version: 2.5.9
- Leaf flags: http-client
- Licence: MIT OR Apache-2.0 (already on the `deny.toml` allow list).
- Source review: read on 2026-11-25 from the crates.io tarball (sha256 `f00cd2407bb42c0ef17be88d4cf020f5cceffd121665bac9b8b9493a369b3b1a`, servo/rust-url, no `build.rs`, no `links` key). It is already in `Cargo.lock` and in the normal graph of the default `tokio` feature (hickory-net and hickory-proto), so this record adds no package; it makes the crate a direct dependency of the `http-client` leaf only because `cookie_store`'s public API takes and returns `url::Url` and does not re-export it. What the leaf does with it: it builds one `Url` per cookie operation from a request URI that `http::Uri` parsed and `http::origin::Origin::of` already restricted to `http` or `https` with a host and no user information, and hands it to `cookie_store`; no `Url` ever comes from a server. The WHATWG parser has one `unsafe` block (`src/parser.rs`, `from_utf8_unchecked` over a buffer it filled with ASCII only); the other modules are safe code. No cryptography.
- Constant-time and zeroization: not a cryptographic crate; it sees URLs, never a secret.
- Cargo vet: the existing `[[exemptions.url]]` 2.5.9, `safe-to-deploy`, covers it; no new entry. `cargo vet --locked` passes.
- Maintenance: servo/rust-url, 2.5.9 published 2026-11-20 (the lock's version, newest release, about 283 million recent downloads); no release is yanked. No RustSec advisory against it (`cargo audit` clean at admission).
- Features: `std` with `default-features = false` (the default of `cookie_store`'s own dependency enables the same set)

### publicsuffix
- Version: 2.3.0
- Leaf flags: http-client
- Licence: MIT/Apache-2.0 (the same dual licence as the rest of the leaf, already on the `deny.toml` allow list).
- Source review: read on 2026-11-25 (see the `cookie_store` record for the tarball hash, `#![forbid(unsafe_code)]`, no `build.rs`, no `links` key). It is already in the graph as `cookie_store`'s own dependency, so this record adds no package; it is a direct dependency of the `http-client` leaf because `cookie_store::CookieStore::with_suffix_list` takes a `publicsuffix::List` and `cookie_store` does not re-export the crate. What the leaf does with it: `CookieStore::with_public_suffix_list(text)` parses the text of the list the application supplies with `List::from_bytes` (the text is bounded to 1 MiB first; the real list is about 250 KB); nothing else of the crate is called. The list is untrusted only in the sense that the application chose it; a text that does not parse is a typed error, never an empty list. The crate ships no list data, so the leaf has no implicit public-suffix list.
- Constant-time and zeroization: not a cryptographic crate; it sees a public list of suffixes.
- Cargo vet: the `[[exemptions.publicsuffix]]` 2.3.0 entry of the `cookie_store` record covers it; no new entry. `cargo vet --locked` passes.
- Maintenance: see the `cookie_store` record (2.3.0 published 2024-11-14, not yanked, no advisory).
- Features: none of its own (`default-features = false`; `cookie_store`'s dependency enables `punycode` and `idna`, which unify into the same build)

## The platform stores: `rskrb5-ng-os` (owner decision D11)

Plan 2 todo 14 looked for a vetted crate with a safe API for the Windows LSA
ticket cache, the macOS native cache (`API:`, Kerberos.framework CCAPI) and
KCM over Mach RPC, on 2026-11-19 (crates.io searches and source review; the
evidence log of todo 14 has the details). None qualifies:

- `windows-lsa` 0.2.1 (MIT, 74 downloads, one author, first release
  2026-08-08) retrieves only the TGT as a KRB-CRED, has no
  `KerbRetrieveEncodedTicketMessage` for service tickets and no
  `KerbPurgeTicketCacheExMessage`, writes a `#[repr(C)]` request through a
  `Vec<u8>` pointer with `ptr::write` (`src/sys.rs:331`, an unaligned typed
  write) and carries no vet audit. Rejected.
- `windows` and `windows-sys` are raw bindings: every call stays `unsafe` in
  the caller. `sspi`, `cross-krb5` and similar crates implement Kerberos
  through SSPI or GSS, which the plan forbids.
- No crate wraps CCAPI or the KCM Mach routine (`kcmrpc.defs`); `mach2` is raw
  bindings.

So, per D11, the stores live in the workspace member `rskrb5-ng-os`:

- it depends on `rskrb5-ng` and nothing else (rule 5): it uses the main
  crate's zeroizing owner instead of `zeroize`, and needs no record, no leaf
  flag and no vet entry;
- `rskrb5-ng` never depends on it, and it is `publish = false`;
- it declares the few OS functions it calls itself (secur32 on Windows;
  libSystem and Kerberos.framework on macOS, linked with `#[link]`, no
  wrapper crate, so rule 4's macOS framework wrapper is not used);
- its manifest takes the core lint profile with the one override of the
  vendored guidelines' unsafe-ffi overlay, `unsafe_code = "deny"`: every
  unsafe block and declaration carries `#[expect(unsafe_code, reason)]`, and
  every unsafe block a `SAFETY` comment. The OS replies are copied out and
  parsed by safe code that Miri checks.

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

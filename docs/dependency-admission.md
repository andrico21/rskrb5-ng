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

No dependency has been admitted since the baseline.

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

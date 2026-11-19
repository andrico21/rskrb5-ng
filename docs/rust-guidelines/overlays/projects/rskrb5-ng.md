# Project overlay: rskrb5-ng

**Load order:** core `RUST_GUIDELINES.md` ->
`overlays/domains/kerberos-credential-protocols.md` -> `overlays/domains/http-services.md`
-> this file.

`http-services.md` applies because the crate ships a server-side HTTP Negotiate Tower
layer (`NegotiateLayer`, which writes `401` challenge and reject responses) and an Axum
example that serves HTTP.

**Precedence:** strictest wins. Where the core, the two domain overlays, this file or a
sibling project's stricter practice that this file adopts pull apart, the stricter rule
applies. Nothing below weakens the core or a domain overlay (README, "The overlay
contract").

## The project

A number or a list below is stated only because `scripts/lint-gates/overlay_facts.py`
recomputes it from the tree in CI (`python3 scripts/lint-gates/overlay_facts.py --enforce`);
everything else is timeless or a dated record.

- **What:** `rskrb5-ng`, a pure-Rust Kerberos 5 client and service library (`Cargo.toml`
  `description`).
  - Package `rskrb5-ng`, version `0.3.0`; the lib target is `rskrb5_ng` (`Cargo.toml`
    `[package]` and `[lib]`).
  - Repository `andrico21/rskrb5-ng`, a standalone repository detached from the fork
    network: `gh api repos/andrico21/rskrb5-ng --jq .fork` prints `false`, and `.parent`
    and `.source` are `null`. Development happens on `main`, the default branch
    (`--jq .default_branch`).
  - It is an independent continuation of `rskrb5` (`clelange/rskrb5`). Upstream is not
    tracked: nothing is merged from it and nothing is proposed to it (`PROVENANCE.md`).
- **History:** the same code was published to crates.io as `rskrb5-patched` 0.2.1
  (2026-10-06) and 0.2.2 (2026-10-23) (`curl -A <agent>
  https://crates.io/api/v1/crates/rskrb5-patched | jq -r '.versions[] | .num + " " +
  .created_at'`). `rskrb5-ng` itself is not published (`curl -A <agent> -w '%{http_code}'
  https://crates.io/api/v1/crates/rskrb5-ng` prints `404`).
- **Consumer:** `kpasswd-rs` (at `76bc19b`, its `origin` `HEAD`) still vendors
  `rskrb5-patched` 0.2.1 as a **path dependency** (`crates/kpasswd-rs/Cargo.toml` line 62:
  `rskrb5 = { version = "0.2.1", package = "rskrb5-patched", path = "../../vendor/rskrb5",
  default-features = false, features = ["tokio"] }`) and denies warnings. So this crate's
  `[lints]` table runs inside the consumer's build.
- **Toolchain:** edition 2024; `rust-version` in `Cargo.toml` is the toolchain of the CI
  `msrv` job. CI runs floating `stable`, one dated `nightly-YYYY-MM-DD` for rustfmt, the
  second rustdoc run and fuzz, and the MSRV toolchain (`.github/workflows/ci.yml`).
  `src/lib.rs` has `#![forbid(unsafe_code)]`; `.cargo/config.toml` sets
  `build.warnings = "deny"`.
- **Lint baseline:** 0 baseline entries. `rg -c lint-migration src tests examples fuzz`
  prints nothing (exit 1). The transition baseline, its generator and
  `scripts/lint-ratchet/` were deleted in `3c70076`; the CI `lint-gates` job fails on any
  `lint-migration` match.
- **Gates** (`scripts/lint-gates/`, run by the CI `lint-gates` job and the prek
  `lint-gates` hook; `workflow_gate.py` holds both to its `REQUIRED` list; every script the
  job runs is named here, which `overlay_facts.py` checks): every
  `scripts/lint-gates/*.py --self-test` and `scripts/check-error-constructions.py
  --self-test`, then `scripts/check-config-relations.py --self-test` and
  `scripts/check-config-relations.py`, `package_links.py --enforce` (relative links of
  packaged Markdown stay in the package), `overlay_facts.py --enforce` (this overlay's
  recomputable facts), `changelog_rows.py --enforce` (every register behaviour change has
  a CHANGELOG bullet), `allow_gate.py --enforce`, `exception_gate.py --enforce` (the six
  sanctioned `expect` forms), `profile_eq.py --clippy-toml`, `completeness_check.py`,
  `facade_gate.py --enforce`, `prose_gate.py --enforce` (whole tree),
  `feature_closures.py check-ci .github/workflows/ci.yml`, `dep_admission.py --enforce` (the
  dependency admission rules of `docs/dependency-admission.md`), `leaf_features.py --enforce`
  (leaf flags are additive), `advisory_ignores.py --enforce` (the ignore sets of `deny.toml`
  and `.cargo/audit.toml` are equal), `fuzz_lint.py --enforce`,
  `fuzz_coverage.py --enforce`, `gate_hygiene.py --enforce`, `workflow_gate.py --enforce`,
  `scripts/check-error-constructions.py`, `scripts/check-github-ad-gate.py --self-test`,
  `scripts/check-ad-integration-env-smoke.py`, `scripts/run-gated-integration.sh
  self-test`, `scripts/release-publish.sh self-test`, and no `lint-migration` match.
- **Feature closures:** the 36 core feature closures are computed from the core features of the
  `[features]` table (`python3 scripts/lint-gates/feature_closures.py list`); each is a `closures`
  matrix entry in CI running `cargo clippy --all-targets <args> -- -D warnings` and `cargo test
  <args>`. The leaf flags are the keys of `[package.metadata.rskrb5-ng.leaf-features]` in
  `Cargo.toml`; each adds a `default + <leaf>` entry, a minimal-build entry and, once, an
  `--all-features` entry. `feature_closures.py check-ci` keeps the matrix complete.
- **CI jobs:** the blocking and the advisory sets are the ones named in project rule 8;
  `overlay_facts.py` compares them with the jobs of `.github/workflows/ci.yml`.
- **Fuzz targets:** `fuzz/fuzz_targets/` holds 15 `.rs` files and `fuzz/Cargo.toml` declares
  14 `[[bin]]` targets. `session_ticket.rs` is a shared helper module, not a target.
- **Review backlog:** closed. The row and key totals are in `docs/review/README.md`
  "Totals".
- **Ambient inputs:** 13 audited reader functions (15 reader/variable inventory entries
  over `KRB5_CONFIG`, `KRB5CCNAME`, `KRB5_KTNAME`, `KRB5_CLIENT_KTNAME`, `HOME`, `TMPDIR`,
  `TEMP` and `APPDATA`), listed in `READERS` of
  `tests/ambient_guard.rs` and enforced by `cargo test --all-features --test
  ambient_guard`. `src` has 37 `# Ambient input` sections (`rg '# Ambient input' src | wc
  -l`). `LibDefaults::new()` reads nothing; `LibDefaults::from_env()` is the explicit
  constructor that reads `HOME` (`src/config.rs`).
- **Vendored rules:** `docs/rust-guidelines/` holds the core, the two domain overlays and
  this file with `SHA256SUMS`. The root `RUST_GUIDELINES.md` index names the pin and the
  re-vendor procedure. CI (`docs-validate`) runs `(cd docs/rust-guidelines && sha256sum -c
  SHA256SUMS)`, and `profile_eq.py --clippy-toml` checks `Cargo.toml` and `clippy.toml`
  against the vendored core.
- **Core updates for a new stable:** by the procedure of project rule 14. The vendored
  core's "tracks stable Rust through" line names the stable the Section 9 profile was last
  verified on; `completeness_check.py` compares the profile with the current stable.

## Project rules

1. **The core and both domain overlays apply in full.** A gap is a dated deviation below,
   phrased as a task, never permission.
2. **Lint profile:** the core Section 9 profile, unchanged, in the root `Cargo.toml`, with
   **zero generated exemptions**. Only six `expect` forms are sanctioned:
   - on `#[cfg(test)]` modules, `clippy::missing_errors_doc`, `clippy::missing_panics_doc`
     and `clippy::too_long_first_doc_paragraph` (only those that fire) with
     `reason = "test code is not rendered API documentation"`, and
     `clippy::panic_in_result_fn` with `reason = "a test fails by panicking"`;
   - `missing_copy_implementations` on a secret-holding type, with
     `reason = "secret material must not be implicitly copied"`;
   - `#![expect(clippy::pub_use, reason = "public facade")]` in `src/lib.rs` only;
   - `clippy::missing_const_for_fn` with `reason = "deliberate: <path> - <why it must not be const>"`;
   - `clippy::unused_async_trait_impl` with `reason = "deliberate: <path> - <foreign trait> mandates async"`;
   - in `src/lib.rs` only, `#![cfg_attr(test, expect(dead_code_pub_in_binary, reason =
     "public API: unused inside the unit-test harness"))]`.
3. **No `#[allow]`/`#![allow]`/`cfg_attr(.., allow(..))` and no `unsafe` anywhere,**
   tests included. Environment-dependent tests set variables in a child test process.
4. **The 36 core feature closures lint and test clean; every leaf flag is additive, and is
   checked on top of the default build, the minimal build and all-features; Windows clippy
   clean.** The core closures are computed from the core features of the `[features]` table
   of `Cargo.toml`, never hand-listed. Each one passes `cargo clippy --all-targets -- -D
   warnings` and `cargo test`. A leaf flag is a key of
   `[package.metadata.rskrb5-ng.leaf-features]`; it enables optional dependencies and the code
   that uses them, and nothing else (`leaf_features.py` enforces it), and is never in
   `default`. Each leaf `L` is linted and tested as `--features L` on the default build, as
   `--no-default-features` with its declared minimal core features and `L`, and in the one
   `--all-features` run. Clippy with `--all-features --target x86_64-pc-windows-msvc` is
   clean too.
5. **The core's prose rules apply to all code:** cancel-safety sections, test docs,
   `Result`-returning tests, Drop audits and emptiness messages.
6. **Toolchain:** floating `stable` in CI (core Version Policy), never pinned;
   `rust-version` is the latest stable the crate was verified on, proven by an MSRV job.
7. **Dependencies** are at their latest major versions, with no pre-release pins. A new
   dependency enters only through `docs/dependency-admission.md` (`dep_admission.py`).
8. **CI is the core Section 12 list plus rmcp-server-kit's stricter practice,** all
   blocking: `fmt`; clippy and tests in every feature closure (`closures`);
   `clippy-windows`; `lib-feature-sets`; `readme-commands`; `test` on Linux, macOS and
   Windows; `i686`; `docs` (rustdoc `-D warnings` on stable and the dated nightly);
   `msrv`; `semver-checks`; `publish-dryrun`; `consumer` (the packaged crate as a path
   dependency with warnings denied, in the consumer's feature set and with default
   features); `deny`; `audit`; `vet`; `machete`; `taplo`; `docs-validate`; `lint-gates`
   (every gate listed above, including `package_links.py`,
   `scripts/check-error-constructions.py` and `scripts/check-config-relations.py`);
   `fuzz-build`; `package`; `cargo-issue` (on the weekly schedule only: it fails once
   rust-lang/cargo#17730 is closed, which ends the temporary `manual_readme` exemption).
   Advisory (`continue-on-error`): `geiger`,
   `rustdoc-nightly-canary`, and on schedule or dispatch `mutants` (32 shards),
   `mutants-report` and `fuzz`.
9. **Releases go only through the tag-gated workflows.** Release tags are `N.N.N`, without
   a `v`. The secret-free coordinator `release.yml` runs after a green CI run and, when an
   `N.N.N` tag equal to the `Cargo.toml` version points at a commit of `main`, dispatches
   `publish.yml` at the tag. Its token-free `verify` job builds and packages the crate
   (`--locked`); its `publish` job, in the `release` environment, uploads that package
   with `--no-verify` only if the sha256 matches (`docs/RELEASING.md`). Once a prior
   `rskrb5-ng` release exists, `cargo semver-checks` runs against the highest published
   version up to the candidate (`scripts/lint-gates/semver_baseline.py`; with none, it
   prints a notice and passes).
10. **Development files stay out of the published crate:** `RUST_GUIDELINES.md`,
    `docs/rust-guidelines/`, the lint scripts and `.cargo/` (`package.exclude`).
11. **Kerberos specifics:**
    - an explicitly configured enctype request list that names an enctype outside an
      explicit `permitted_enctypes` is **rejected with the enctype named**, never silently
      narrowed;
    - enctype tests assert on the **encoded** AS-REQ/TGS-REQ etype list;
    - every parser of attacker-controlled bytes has a fuzz target;
    - credential-mutating async functions carry a `# Cancel safety` section saying
      **NOT cancel-safe** (15 occurrences of the sentence `NOT cancel-safe: this mutates
      credentials on the KDC` in `src`).
12. **The frozen upstream PR heads are not maintained.** The `fix/*` branches and
    `rust-1-98-clippy-drift`, `hex-dev-dependency`, `export-padata-constants` and
    `kpasswd-verbatim-result-bytes` stay on the remote as they are, for the open upstream
    pull requests. They receive no commits and no deletion.
13. **Ambient inputs:** library code reads the environment only in named
    ambient-discovery constructors (`KRB5_CONFIG`, `KRB5CCNAME`, `KRB5_KTNAME`,
    `KRB5_CLIENT_KTNAME`, and `HOME` in `LibDefaults::from_env`) and in the credential
    template expansion (`TMPDIR` on non-Windows, `TEMP` and `APPDATA` on Windows, in
    `resolve_credential_template`). Each one is documented
    with an `# Ambient input` section and pinned by a guard test. There are no implicit
    reads anywhere else.
14. **A new stable Rust is adopted by procedure:** the core Section 9 profile is updated
    here by a reviewed commit, re-vendored, mirrored into `Cargo.toml`, and every new
    diagnostic is fixed directly. No exemption is added.

## Deviations to resolve

Each item is a task. "Todo N" refers to the owner's plan `rskrb5-ng-own-way`.

1. **Unpublished.** `rskrb5-ng` is not on crates.io
   (`https://crates.io/api/v1/crates/rskrb5-ng` returns `404`). The release workflow and
   `docs/RELEASING.md` are ready; publishing waits for the owner.
2. **`kpasswd-rs` still depends on `rskrb5-patched` 0.2.1** (`crates/kpasswd-rs/Cargo.toml`
   line 62). Its migration to `rskrb5-ng` is the consumer's own task.
3. 2026-11-14: commit `[registry] global-min-publish-age = "3 days"` and `[resolver]
   incompatible-publish-age = "deny"` in `.cargo/config.toml` (core Section 10); give any
   update bot (Dependabot `cooldown`, Renovate `minimumReleaseAge`) at least the same delay.
4. 2026-11-14: CI: install the gate tools at pinned versions (`cargo install
   cargo-deny@<version> --locked`, same for cargo-audit and cargo-vet where the project runs
   them); pins per core Section 12 (Required CI Tools).
5. 2026-11-14: delete the sanctioned `#![cfg_attr(test, expect(dead_code_pub_in_binary,
   ...))]` in `src/lib.rs` (project rule 2) in the commit that sets `rust-version = "1.101"`
   (Cargo 1.101, 2026-12-24, fixes the false positive, #17608; the expectation then becomes
   unfulfilled). Pre-check on beta.

### Closed (2026-11-14)

The Rust 1.100 tasks of 2026-11-14 that are resolved on `main`. The closing commits are not
listed: this file is re-vendored in the change that closes them, so each item names the
command that finds its commit.

- **`rust-version` 1.100** and the `msrv` job on 1.100.0 (`git log --oneline
  -S'rust-version = "1.100"' -- Cargo.toml`).
- **The Cargo lint table:** `[lints.cargo]` in `Cargo.toml` equals the core's
  `[workspace.lints.cargo]` (`profile_eq.py`), and what Cargo 1.100 reports is fixed (`git
  log --oneline -S'[lints.cargo]' -- Cargo.toml`).
- **Clippy 1.100:** `cargo clippy --all-targets -- -D warnings` is clean on 1.100 in every
  feature closure.

### Closed (2026-10-28)

The deviations recorded on 2026-10-25 that are now resolved on `main`, each with the
commits on `main` that closed it (`git merge-base --is-ancestor <commit> origin/main`):

- **Generated lint baseline** (rules 2 and 4): zero entries in `509c1c7` (todo 25), every
  feature closure strict in `856da18` (todo 26), the baseline and transition gates deleted
  in `3c70076` (todo 27), and the closures pipeline with Windows clippy in `bd6257a`
  (todo 28).
- **Open review backlog:** fixed or dismissed in `634adc6`, `2674c34`, `71ffd9c`,
  `340bfe0`, `4d42d0d`, `70fa923`, `ddf76cb`, `1f2019c`, `b804443` and `eec22c7` (todos 29
  to 38), indexed in `2c4a80b` (todo 39).
- **Parser fuzz coverage** (rule 11): 12 targets in `e283460` (todo 40).
- **Mutation-testing scope:** the mutation campaign in 8 shards in `8dd1753` (todo 41).
- **Prose rules on upstream-origin code** (rule 5): the prose gate over a clean-paths
  ratchet in `1b54b82` (todo 7), burned down by the Wave 2 merges through `dbe2f48` (todos
  8 to 21), and enforced on the whole tree in `3c70076` (todo 27).
- **Dependency majors held back** (rule 7): latest majors and stable `pbkdf2` 0.13 in
  `13db033` (todo 6).
- **Implicit environment reads** (rule 13): `RSKRB5_DNS_SERVER` became an explicit option
  in `ddf76cb` (todo 35), `LibDefaults::new()` stopped reading `UID` and `HOME` in
  `b804443` (todo 36), and `%{uid}` expansion stopped reading `UID` in `1f2019c` (todo
  37).
- **New-stable procedure not written** (rule 14): `docs/lint-policy.md` added in `3c70076`
  (todo 27).

## Common alignment steps (every project)

- **Lint tables:** the core Section 9 profile, unchanged; project additions go on top.
- **`clippy.toml`:** the core sample; duplicates and proper nouns appended, each with a reason.
- **`.cargo/config.toml`:** `[build] warnings = "deny"`, plus the cooldown keys `[registry]
  global-min-publish-age = "3 days"` and `[resolver] incompatible-publish-age = "deny"`
  (core Section 10).
- **CI:** the full core Section 12 list, including rustdoc `-D warnings` and `cargo machete`.
- **Guideline file:** a `RUST_GUIDELINES.md` pointer or vendoring index naming this overlay,
  with any vendored copy pinned and checksum-verified, never a partial copy.

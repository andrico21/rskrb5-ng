# Lint policy

`rskrb5-ng` passes the strictest lint profile of the vendored Rust guidelines
outright. There is no baseline: no `lint-migration:` expectation, no `allow`
attribute, and no exception outside the six forms below. Every feature closure
builds, lints and tests clean, and so does Windows.

## Where the profile comes from

- The `[lints]` tables in the root [`Cargo.toml`](../Cargo.toml) are the TOML
  fence of core Section 9, "The profile", in the vendored
  [core guidelines](https://github.com/andrico21/rskrb5-ng/blob/main/docs/rust-guidelines/RUST_GUIDELINES.md). The pin and the
  re-vendor procedure are in the [vendoring index](https://github.com/andrico21/rskrb5-ng/blob/main/RUST_GUIDELINES.md).
  `profile_eq.py` compares the two as parsed TOML; any difference fails.
- [`clippy.toml`](../clippy.toml) is the core sample. Only
  `allowed-duplicate-crates` (each with a reason comment, matching the
  `[[bans.skip]]` names in [`deny.toml`](../deny.toml)) and `doc-valid-idents`
  may differ, and only by appending.
- [`.cargo/config.toml`](https://github.com/andrico21/rskrb5-ng/blob/main/.cargo/config.toml) sets
  `build.warnings = "deny"`. CI keeps `-D warnings` on clippy and rustdoc.
  For local work in progress, `CARGO_BUILD_WARNINGS=allow` lets one cargo
  invocation build with warnings; CI sets it only where the profile is not
  the gate (`msrv`, `fuzz-build`, `fuzz`, `mutants`).
- [`rustfmt.toml`](../rustfmt.toml) is run with `nightly-2026-10-03`.
- The fuzz crate (`fuzz/Cargo.toml`) is a separate workspace without lint
  tables; `fuzz_lint.py` applies the root profile to it as command-line flags.
- On top of the core: the
  [Kerberos overlay](https://github.com/andrico21/rskrb5-ng/blob/main/docs/rust-guidelines/overlays/domains/kerberos-credential-protocols.md),
  the [HTTP services overlay](https://github.com/andrico21/rskrb5-ng/blob/main/docs/rust-guidelines/overlays/domains/http-services.md)
  and the [rskrb5-ng project overlay](https://github.com/andrico21/rskrb5-ng/blob/main/docs/rust-guidelines/overlays/projects/rskrb5-ng.md).
  Overlays may add rules and may not remove any.

## The six sanctioned exceptions

A lint that fires is fixed in code. The only `#[expect]`/`#![expect]`
attributes allowed anywhere in the Rust sources, including inside
`cfg_attr`, are these, with exactly these reason texts and on these item
kinds. The sources are `src`, `tests`, `examples`, `benches` and
`fuzz/fuzz_targets` plus everything the checkout's Cargo manifests compile:
build scripts and targets with a custom `path`
([`source_set.py`](https://github.com/andrico21/rskrb5-ng/blob/main/scripts/lint-gates/source_set.py)); a target outside
the checkout, an out-of-line `mod` in a file scanned on its own, or an empty
source set fails every gate. A lint path is read the way rustc reads it, so
`clippy :: r#unwrap_used` is `clippy::unwrap_used`, and an argument that is
not a lint path is reported, never dropped:

| # | Lints | Reason | Where |
|---|---|---|---|
| 1 | any of `clippy::missing_errors_doc`, `clippy::missing_panics_doc`, `clippy::too_long_first_doc_paragraph` (only those that fire) | `test code is not rendered API documentation` | outer, on a `mod` under `#[cfg(test)]` |
| 1 | `clippy::panic_in_result_fn` | `a test fails by panicking` | outer, on a `mod` under `#[cfg(test)]` |
| 2 | `missing_copy_implementations` | `secret material must not be implicitly copied` | outer, on a secret-holding type (`struct`, `enum`, `union`) |
| 3 | `clippy::pub_use` | `public facade` | `#![expect(..)]` at the crate root of `src/lib.rs` only |
| 4 | `clippy::missing_const_for_fn` | `deliberate: <path> - <why it must not be const>` (`<path>` contains `::`) | outer, on a `fn` (core "Public API of a library") |
| 5 | `clippy::unused_async_trait_impl` | `deliberate: <path> - <foreign trait> mandates async` (`<path>` contains `::`) | outer, on a `fn` or `impl` (core checklist) |
| 6 | `dead_code_pub_in_binary` | `public API: unused inside the unit-test harness` | `#![cfg_attr(test, expect(..))]` at the crate root of `src/lib.rs` only |

Form 6 exists because the lint fires on public items inside the library's
unit-test binary, and rustc accepts its expectation only at crate level.

Form 3 covers Clippy's crate-wide `pub_use`; `facade_gate.py` separately
restricts public re-exports to the crate-root scope of `src/lib.rs`.

Opting an *excluded* lint in on one item with
`#[deny(lint, reason = "...")]` is encouraged where its intent applies (core
Section 9, "Per-item use of an excluded lint"). It is not an exception and
passes every gate. `#[allow]`, `#![allow]` and `cfg_attr(.., allow(..))` are
forbidden.

## Gates

All gate scripts live in [`scripts/lint-gates/`](https://github.com/andrico21/rskrb5-ng/tree/main/scripts/lint-gates), use
the Python standard library only, and have a `--self-test` mode. CI runs them
in the `lint-gates` job of [`ci.yml`](https://github.com/andrico21/rskrb5-ng/blob/main/.github/workflows/ci.yml);
[`prek.toml`](https://github.com/andrico21/rskrb5-ng/blob/main/prek.toml) mirrors the fast ones as a pre-push hook.

| Command | What it enforces |
|---|---|
| `<script> --self-test`, for every script and `scripts/check-error-constructions.py` | each gate still detects what it claims to, on inline fixtures |
| `allow_gate.py --enforce` | no `allow` attribute anywhere, including nested `cfg_attr` lists and inner attributes |
| `exception_gate.py --enforce` | every `expect` is one of the six sanctioned forms above on a matching item; `lint-migration:`, `invariant:` and any other reason fail |
| (both gates) | fail closed on spelling the lexer cannot see through: `#`, `!` and `[` are read as separate tokens, so `# [allow(..)]` is still an attribute; a macro metavariable in or as an attribute (`#[$m]`, `#$t`), an `allow(..)`/`expect(..)` token tree passed to a macro, an attribute that does not start with a path, and `include!` or `#[path]` of anything but a relative `.rs` path without `..` are all reported |
| `profile_eq.py --clippy-toml` | `[lints]` equals the vendored core profile; `clippy.toml` equals the core sample apart from the two append-only keys |
| `completeness_check.py` | the profile is complete for the current stable: the rustc and `restriction` lints missing from `Cargo.toml` are exactly the documented exclusions |
| `facade_gate.py --enforce` | no `pub use` (or `pub(..) use`) outside the crate-root scope of `src/lib.rs`, cfg-disabled code included |
| `prose_gate.py --enforce` | the core's non-lint rules on every item of the whole tree (`--paths <globs>` narrows a local run; `facade_gate.py --paths` works the same way, and an empty selection selects nothing) |
| `feature_closures.py run` | every feature closure: `cargo clippy --all-targets <args> -- -D warnings`, then `cargo test <args>` |
| `feature_closures.py check-ci .github/workflows/ci.yml` | the matrix of the job whose id is `closures` lists exactly the computed closures, each once; the job is defined once, no other `closures:` key exists (no decoy job or matrix), the matrix has no `include`/`exclude`, the job has no `if`/`continue-on-error`, and its steps run exactly the strict clippy and test commands. Nothing may cap lints or swallow a failure: the job has no `env`, `defaults`, `shell`, `container` or `working-directory` and uses only the checkout, toolchain and cache actions; the workflow sets no `defaults` and no Cargo or rustc variable beyond `CARGO_TERM_COLOR`, `CARGO_INCREMENTAL`, `CARGO_NET_RETRY` and `RUST_BACKTRACE`; and `.cargo/config.toml` keeps `build.warnings = "deny"` with no `rustflags`, wrapper, `rustc` or Cargo/rustc `[env]` variable |
| `fuzz_lint.py --enforce` | the root profile on the nightly fuzz crate, in a disposable copy (without `--enforce` it reports the clippy result and exits 0, like every gate) |
| `fuzz_coverage.py --enforce` | the parser inventory of [`review/fuzz.md`](https://github.com/andrico21/rskrb5-ng/blob/main/docs/review/fuzz.md) exists and is not empty, lists every function the parser search finds, names only functions still defined in their source file, and names only targets of `fuzz/Cargo.toml` (`--coverage DIR` proves the mappings from coverage exports) |
| `workflow_gate.py --enforce` | the `lint-gates` job and the prek hook run every gate, plus the error-variant construction audit and the offline self-tests of `scripts/check-github-ad-gate.py`, `scripts/check-ad-integration-env-smoke.py`, `scripts/run-gated-integration.sh` and `scripts/release-publish.sh`, and the job may not be skipped or advisory; every action is pinned to a commit SHA, each `dtolnay/rust-toolchain` channel to one SHA, and the release workflows use CI's `# stable` revision |
| `scripts/check-error-constructions.py` | every public variant of the error enums in `src/error.rs` and `src/error/` has a construction expression outside its enum definition (patterns, strings and comments do not count); an enum body the scanner cannot read fails closed |
| `scripts/check-config-relations.py` and `--self-test` | literal Rust tables generate the packaged relation document exactly (CRLF-safe); all 43 libdefaults and 28 pinned realm names match independent inventories, all 77 rows name existing tests; malformed/duplicate/opaque tables, missing tests and documentation drift fail closed |
| `package_links.py --enforce` and `--self-test` | every relative Markdown link (inline, image, reference definition, autolink, HTML `href`/`src`; CRLF-safe, code skipped) in a file of `cargo package --list --allow-dirty` resolves to a packaged file or a directory holding one, and its fragment to a heading or anchor of a packaged Markdown target; files the package excludes are linked as `https://github.com/andrico21/rskrb5-ng/blob/main/...` (or `tree/main/...`), which must exist in the checkout; other schemes, root-absolute paths and paths leaving the package fail |
| `gate_hygiene.py --enforce` | the gate scripts carry no dead work: every `argparse` option is read, and every module-level helper is used outside a `self_test` |

Workflow execution admission is a strict, dependency-free YAML subset. The
mandatory jobs use only known plain keys, literal run commands and SHA-pinned
setup actions with version comments. Extra lint run steps are rejected, including
preparation steps that write interpreter settings through `GITHUB_ENV` or
`GITHUB_PATH`. Only the documented bytecode/color environment settings are allowed.

`docsrs_check.py` holds `[package.metadata.docs.rs]` to the advertised
optional APIs (`http`, `tower`); the `docs` job builds rustdoc with exactly
that feature set and `--cfg docsrs`, as docs.rs does, and checks the
`NegotiateLayer` and `send_with_negotiate` pages exist.

Two reports serve advisory jobs and are self-tested with the gates:
`geiger_report.py` classifies the `geiger` job's JSON scan (complete unless a
Rust source went unscanned outside build-script output) and prints the unsafe
totals of the crate and of its dependencies; `mutants_report.py --artifacts
DIR --expect-shards 32 [--register docs/review/mutants.md] [--allow-open]
--enforce` fails a mutation campaign with a missing or unfinished shard, or
(with the register) with a missed or timed-out mutant that has no final
status (`killed`, `equivalent`, or `hang` for a timeout only). Register rows
are `| campaign | mutant (full name) | file | function | operator | outcome |
status | proof or reason |`, keyed by the campaign SHA and the full
cargo-mutants name with its location; write a `|` inside a cell as `\|`.

`rg -n 'lint-migration' src tests examples fuzz` must print nothing.
`semver_baseline.py` is not a lint gate: it drives `cargo semver-checks`
against the highest published `rskrb5-ng` version at or below the candidate,
taken from crates.io (the `semver-checks` job). A published version equal to
the candidate must be this exact package (same `.crate` sha256), otherwise it
fails with "version already published; bump the version"; release tags whose
manifest names `rskrb5-ng` must carry their own version.

### Prose gate

`prose_gate.py` ports rmcp-server-kit's prose gates and adds one Kerberos
overlay rule. Each check has an `--only` selector:

- `cancel-safety`: a production `async fn` documents `# Cancel safety` with
  text under the heading, or carries a non-empty `cancel-safe:` note in the
  comment, doc and attribute lines attached directly above it (a blank line or
  another item in between detaches it);
- `credential-mutating`: an async `change_password*`, `set_password*` or
  `exchange_kpasswd*` has a `# Cancel safety` section containing
  `NOT cancel-safe`;
- `test-docs`: every test has a `///` doc;
- `test-result`: a test with a propagation site returns `Result`;
- `drop-audit`: a production `impl Drop` has a `Drop audit` note;
- `emptiness-message`: `assert!(x.is_empty())` carries a message.

Production means every file outside `tests/` and `benches/` (so `src`,
`examples`, fuzz targets and build scripts), minus `cfg(test)` code. Items a
macro generates are checked as well: every `macro_rules!` definition or macro
invocation whose tokens can produce an `async fn`, a test or a `Drop` impl is
scanned like source, metavariables read as identifiers
([`prose_scope.py`](https://github.com/andrico21/rskrb5-ng/blob/main/scripts/lint-gates/prose_scope.py)); `proptest!` cases
are exempt only from `test-docs` and `test-result`.

`test-result` requires `Result` only when the test body has a propagation site
([`prose_infallible.py`](https://github.com/andrico21/rskrb5-ng/blob/main/scripts/lint-gates/prose_infallible.py)).
Assertions (including error assertions) and known infallible construction or
ownership conversions don't count, because an unused `Ok(())` wrapper would
trigger `clippy::unnecessary_wraps`. Unknown calls, fallible calls nested in
conversions, `?`, `expect` and `unwrap` outside assertions still require it.

## Every closure, and Windows

`feature_closures.py list` computes the distinct closures of the `[features]`
table (`default` counts as a feature) and the canonical Cargo arguments for
each: 36 closures today. Each one must pass `cargo clippy --all-targets <args>
-- -D warnings` and `cargo test <args>`; `feature_closures.py run` runs both
for all of them. A consumer may therefore enable any feature combination under
its own strict lints. In CI each closure is one leg of the `closures` matrix,
written out statically and held equal to the computed list by `check-ci`.

Items used only under some features carry a precise `#[cfg(feature = ..)]`,
and Unix-only helpers carry `#[cfg(unix)]`, so nothing is dead or unused in any
closure or on Windows:

```bash
cargo clippy --all-targets --all-features --target x86_64-pc-windows-msvc -- -D warnings
```

CI runs the same clippy natively on `windows-latest` (the `clippy-windows`
job).

## A new stable toolchain

CI floats on `stable` (core Version Policy), so a new stable release can bring
new lints. The owner allows the executor to update the shared core. Then:

1. Run `python3 scripts/lint-gates/completeness_check.py`; it lists the new
   lints the profile doesn't cover.
2. In `andrico21/rust-guidelines`, make one commit that changes only the core
   Section 9 profile (each new lint at the level the core's inclusion rule
   gives), the Exclusions table (each excluded lint with its reason) and the
   "tracks stable through" line. Push it.
3. Re-vendor at the new pin ([`RUST_GUIDELINES.md`](https://github.com/andrico21/rskrb5-ng/blob/main/RUST_GUIDELINES.md))
   and mirror the profile into `Cargo.toml` `[lints]` (`profile_eq.py
   --clippy-toml` passes).
4. Fix every new diagnostic directly, in one `toolchain:` commit. No baseline
   exists, and none is ever added.
5. Once MSRV passes on the new stable, raise `rust-version` and the MSRV
   toolchain to it.

## Running the gates locally

- Run the scripts with `PYTHONDONTWRITEBYTECODE=1`, so no `__pycache__` is
  left in the tree for `cargo package`.
- Give each worktree its own `CARGO_TARGET_DIR`. Worktrees sharing one target
  directory can silently reuse stale test binaries.

## History

The 0.3 line first carried a generated, shrink-only `lint-migration:`
baseline for inherited upstream code, with differential and ratchet gates.
The baseline reached zero entries, and the machinery was then deleted. The
full transition record (the authorized upstream-line rewrites (a) to (p), the
removed gates and the divergence from the upstream PR branches) is
`docs/lint-baseline.md` at commit `856da18`:
`git show 856da18:docs/lint-baseline.md`.

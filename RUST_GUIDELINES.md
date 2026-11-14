# Rust guidelines (vendoring index)

This file is the **index** for the Rust rules that apply in this repository.
The rules themselves are the vendored universal guidelines under
`docs/rust-guidelines/`; the vendored core is
[`docs/rust-guidelines/RUST_GUIDELINES.md`](docs/rust-guidelines/RUST_GUIDELINES.md).
This index and the vendored directory are development-only. `package.exclude` in
`Cargo.toml` keeps them out of the published `rskrb5-ng` crate.

**Precedence: strictest wins.** Where the core, a domain overlay, the project overlay or a
practice the project overlay adopts pull apart, the stricter rule applies. No file here
weakens another (see the overlay contract below).

## Load order

Read, in this order, before writing or reviewing Rust code here:

1. [`docs/rust-guidelines/RUST_GUIDELINES.md`](docs/rust-guidelines/RUST_GUIDELINES.md) - universal core
2. [`docs/rust-guidelines/overlays/domains/kerberos-credential-protocols.md`](docs/rust-guidelines/overlays/domains/kerberos-credential-protocols.md) - Kerberos and credential-bearing protocol clients
3. [`docs/rust-guidelines/overlays/domains/http-services.md`](docs/rust-guidelines/overlays/domains/http-services.md) - HTTP services (the server-side Negotiate layer and the Axum example)
4. [`docs/rust-guidelines/overlays/projects/rskrb5-ng.md`](docs/rust-guidelines/overlays/projects/rskrb5-ng.md) - this project's overlay (always last)

The project overlay lists deviations that are still open. Treat them as tasks,
not as permission.

## Source and pin

- **Upstream repository:** `andrico21/rust-guidelines` (private; readable through `gh api`).
- **Pinned commit:** `6e1aa99db7ec468e78f8c7042678c6a0f06d0eb0` (2026-11-10).
- **Rule changes:** they are made upstream, by review, then re-vendored here. Errata found in the vendored text are reported upstream, never patched locally.

## Do not edit; re-vendor to update

The four files below are byte-for-byte copies of the upstream files at the pinned commit.
Do not edit them, and do not "fix" a rule locally. A local edit forks the rulebook silently,
and the next re-vendor would overwrite it. To update, follow the re-vendor procedure below.

## Vendored files

| File | Git blob at the pin | SHA-256 |
|------|---------------------|---------|
| `RUST_GUIDELINES.md` | `4a13d83d85599b5fbeaf44a3db96ed9c4ac1e7d1` | `d8459547e7962dee69889a8b8d717ef50bb657ca681a519d636cfadfc9fd18a7` |
| `overlays/domains/kerberos-credential-protocols.md` | `99da625eb44c51de0fb8d047edb6957319882bce` | `9f2d10141e4e576e0fdbe3873e633403454e4370a206c9dd0154b7bf9f9517d5` |
| `overlays/domains/http-services.md` | `a80c843f7f8b69e1026cc8bf50e465b253e6ea19` | `120d64975591eb62801c5f83586cebebcfe4495e939ef1b7bd376eb476859d83` |
| `overlays/projects/rskrb5-ng.md` | `b2b1920eea3617c62d82c3db1390f366cd544e35` | `3f6595ba3ffbb8af0000fbd407118e0bf431c56558b013bebdf5a76796bf62ae` |

`docs/rust-guidelines/SHA256SUMS` holds the same hashes. CI checks them with
`(cd docs/rust-guidelines && sha256sum -c SHA256SUMS)`.

The core and `http-services.md` are byte-identical to the copies vendored by
`rmcp-server-kit`, the lint profile's reference project.

## Not vendored

- **The repository `README.md`.** Its overlay contract is quoted verbatim below.
- **The other domain overlays** (`unsafe-ffi`, `embedded-no-std`, `mcp-servers`). This crate does not load them.
- **The other project overlays.**

## The overlay contract (verbatim excerpt, `README.md` at the pin)

1. **The core applies to every crate.** Every overlay is read *on top of* it.
2. **Domain overlays add rules for their domain and never weaken the core.** There is
   exactly one declared override: `unsafe-ffi.md` may lower `unsafe_code` from `forbid` to
   `deny`, and only with per-item `#[expect(unsafe_code, reason = "...")]`.
3. **Project overlays add project rules and record deviations.** They never weaken the core
   or a domain overlay. A deviation is dated, temporary, and phrased as a task.
4. **Lints: add, never remove.** The core Section 9 profile is the floor. Local exceptions
   are `#[expect(lint, reason = "...")]` on the narrowest item; manifests carry no
   group-level allows.
5. **If an overlay contradicts the core outside a declared override, the core wins.** The
   overlay is then a bug to fix in this repository.
6. **Order of precedence when rules pull apart:** security, then correctness, then
   cleanliness.

## Re-vendor procedure

1. Fetch all four files at the new pinned commit and prove blob-id identity:

   ```bash
   PIN=<new commit>
   for P in RUST_GUIDELINES.md overlays/domains/kerberos-credential-protocols.md \
            overlays/domains/http-services.md overlays/projects/rskrb5-ng.md; do
     gh api -H 'Accept: application/vnd.github.raw' \
       "repos/andrico21/rust-guidelines/contents/$P?ref=$PIN" \
       > "docs/rust-guidelines/$P"
     test "$(git hash-object "docs/rust-guidelines/$P")" = \
          "$(gh api "repos/andrico21/rust-guidelines/contents/$P?ref=$PIN" --jq .sha)"
   done
   ```

2. Regenerate and check `docs/rust-guidelines/SHA256SUMS`:

   ```bash
   (cd docs/rust-guidelines && sha256sum RUST_GUIDELINES.md \
      overlays/domains/kerberos-credential-protocols.md \
      overlays/domains/http-services.md overlays/projects/rskrb5-ng.md > SHA256SUMS)
   (cd docs/rust-guidelines && sha256sum -c SHA256SUMS)
   ```

3. Update this index: the pinned commit, its date, and the blob/hash table. Never edit
   the vendored bytes, and never write upstream from this checkout.
4. If the core's Section 9 profile or `clippy.toml` sample changed, the profile-equality
   gate (`scripts/lint-gates/profile_eq.py`) fails until `Cargo.toml` and `clippy.toml`
   match the new pin. Follow the new-stable procedure in `docs/lint-policy.md`.

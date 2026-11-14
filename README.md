# rskrb5-ng

`rskrb5-ng` (library `rskrb5_ng`) is a pure-Rust Kerberos 5 client and
service library with HTTP Negotiate (SPNEGO) support. It reads and writes
keytabs, credential caches and `krb5.conf`, runs AS/TGS exchanges and
password changes against a KDC, validates AP-REQs on the service side, and
parses PACs. The crate has no `unsafe` code (`#![forbid(unsafe_code)]`).

It continues [`rskrb5`](https://github.com/clelange/rskrb5) independently;
[`PROVENANCE.md`](PROVENANCE.md) records where the code comes from.

## Status

| Area | Status |
|---|---|
| Keytab, ccache and config files | File-backed keytabs and MIT FILE/WRFILE/DIR credential caches: parsing, serialization, lookup and redacted metadata JSON, covered by gokrb5 fixtures. `krb5.conf` parsing with `include`/`includedir`. |
| Crypto and Kerberos messages | AES-SHA1, AES-SHA2, DES3 and RC4-HMAC, DER message wrappers, KDC/AP/KRB-PRIV/KRB-SAFE/KRB-CRED helpers and kpasswd frames, covered by unit vectors and fixture round-trips. The default enctypes are AES only; RC4 and DES3 need `allow_rc4`/`allow_des3`. |
| High-level client | Tokio password, keytab and ccache login, AS/TGS exchange, referrals, renewal, service-ticket caching, S4U2Self/S4U2Proxy, kpasswd, diagnostics and ccache write-back. |
| Service and HTTP Negotiate | AP-REQ validation, replay detection, AP-REP mutual authentication, SPNEGO/GSSAPI tokens, HTTP helpers, 401 retry client wrappers, Tower middleware and an Axum example. |
| PAC and Active Directory | PAC container, validation info, UPN/DNS, credentials, delegation, device and claims data, checksums and AD credential summaries. The AD integration tests need a lab and aren't run in CI ([`docs/ad-integration.md`](docs/ad-integration.md)). |
| Review backlog | Every open item of the code review and of the second security-audit run is fixed with a regression test or dismissed with evidence: 78 rows, 75 fixed and 3 dismissed ([`docs/review/README.md`](https://github.com/andrico21/rskrb5-ng/blob/main/docs/review/README.md)). |
| Fuzzing | Each attacker-facing parser has a `cargo fuzz` target (13 targets, [`docs/review/fuzz.md`](https://github.com/andrico21/rskrb5-ng/blob/main/docs/review/fuzz.md)). |
| Follow-up review | The independent review of `6586b7a` is tracked row by row, with proofs, in [`docs/review/followup-6586b7a.md`](https://github.com/andrico21/rskrb5-ng/blob/main/docs/review/followup-6586b7a.md); `CHANGELOG.md` lists each behaviour change. |
| Parity with MIT krb5 and gokrb5 | Not complete. This release delivers the review follow-up, MIT `krb5.conf` profile semantics (work package WP-01) and the runtime encryption policy with its permanent rejections (WP-02, POL-01). The other work packages (WP-03 to WP-20) are planned, not delivered. The per-feature manifests are the source of truth: [MIT krb5 1.22.2](docs/mit-krb5-parity.md), 169 rows (36 implemented, 75 partial, 42 absent, 8 rejected, 1 omitted, 7 out of scope); [gokrb5 v8.4.4](docs/gokrb5-parity.md), 35 rows (18 implemented, 17 partial). |
| Not supported | API, KCM, KEYRING and MSLSA credential stores, FAST armor, PKINIT and system GSSAPI/SSPI facades. Unsupported credential stores fail with a typed error. |

The API can still change before 1.0. Wire formats, cryptographic behaviour
and the gokrb5 fixture parity are treated as compatibility-sensitive.
[`docs/mit-krb5-parity.md`](docs/mit-krb5-parity.md) and
[`docs/gokrb5-parity.md`](docs/gokrb5-parity.md) track parity with MIT krb5
1.22.2 and gokrb5 v8.4.4 feature by feature, from the machine-readable
`docs/mit-krb5-parity.toml` and `docs/gokrb5-parity.toml`, and list every
deliberate divergence.

The [security policy](docs/security-policy.md) documents runtime encryption
permission, permanent feature rejections, derivation limits and residual secret copies.

The generated [configuration relation catalogue](docs/config-relations.md)
lists typed settings, effective consumers, and fail-closed/deferred behavior.

## Quick start

```toml
[dependencies]
rskrb5-ng = "0.3"
```

Get a Negotiate `Authorization` header from the default credential cache
(blocking):

```rust,no_run
use rskrb5_ng::{BlockingNegotiateClient, Config};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load_default()?;
    let mut client = BlockingNegotiateClient::from_default_ccache(config)?;
    let header = client.authorization_header_for_host("HTTP", "www.example.com")?;
    // Send the header over TLS; never log this credential.
    drop(header);
    Ok(())
}
```

The same with the async client and an explicit FILE ccache:

```rust,no_run
use rskrb5_ng::{Config, NegotiateClient};

async fn authorization_header() -> Result<String, Box<dyn std::error::Error>> {
    let config = Config::load_default()?;
    let mut client = NegotiateClient::from_ccache_name(config, "FILE:/tmp/krb5cc")?;
    let header = client
        .authorization_header_for_host("HTTP", "www.example.com")
        .await?;
    Ok(header)
}
```

Both blocks are compiled as doctests. `Config::load_default` reads
`KRB5_CONFIG` and `from_default_ccache` reads `KRB5CCNAME`; use
`Config::parse` or `Config::load` and `from_ccache_name` to choose the
sources explicitly. The `http` feature adds 401 retry wrappers
(`http::send_with_negotiate` and the blocking variant), and
[`examples/axum-negotiate.rs`](examples/axum-negotiate.rs) shows the service
side:

```sh
KRB5_KTNAME=FILE:/path/to/http.keytab cargo run --example axum-negotiate --features http --no-default-features
```

Upgrading from the 0.2 releases? The `[0.3.0]` section of
[`CHANGELOG.md`](CHANGELOG.md) lists every change and links the migration
guide, which maps each renamed path and changed signature.

## Features

| Feature | Enables | Implies |
|---|---|---|
| `messages` | Kerberos ASN.1 message wrappers and protocol modules | |
| `spnego` | SPNEGO/GSSAPI tokens and Negotiate headers | `messages` |
| `tokio` | async KDC and kpasswd transports and the high-level clients | `messages` |
| `http` | `http` crate request/response helpers; with `tokio`, the 401 retry wrappers | `spnego` |
| `tower` | Tower Negotiate middleware for services | `http` |
| `serde` | JSON diagnostics and redacted metadata | |
| `evaluation` | the candidate-crate compatibility report | `spnego` |

The default features are `spnego`, `tokio` and `serde`. Every combination of
features is supported: the features resolve to 36 distinct closures, and CI
runs strict clippy and the tests in each one (the `closures` job, held equal
to `python3 scripts/lint-gates/feature_closures.py list`). The
compatibility report is generated with:

```sh
cargo run --no-default-features --features evaluation --bin rskrb5-ng-compat-report
```

## Local checks

These are the core commands CI runs; the `lint-gates` job of
[`ci.yml`](https://github.com/andrico21/rskrb5-ng/blob/main/.github/workflows/ci.yml)
runs further gates. [`docs/lint-policy.md`](docs/lint-policy.md) explains the
lint profile and each gate.

```sh
python3 -m pip install --require-hashes -r scripts/lint-gates/requirements.txt   # once: the CommonMark gates import markdown_it
cargo +nightly-2026-10-03 fmt --all -- --check
python3 scripts/lint-gates/feature_closures.py run   # clippy -D warnings and tests, every feature closure
cargo test --all-features
cargo test --doc --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
for s in scripts/lint-gates/*.py; do python3 "$s" --self-test; done
python3 scripts/lint-gates/allow_gate.py --enforce
python3 scripts/lint-gates/exception_gate.py --enforce
python3 scripts/lint-gates/profile_eq.py --clippy-toml
python3 scripts/lint-gates/completeness_check.py
python3 scripts/lint-gates/facade_gate.py --enforce
python3 scripts/lint-gates/prose_gate.py --enforce
python3 scripts/lint-gates/feature_closures.py check-ci .github/workflows/ci.yml
python3 scripts/lint-gates/fuzz_lint.py --enforce
cargo deny check && cargo audit && cargo vet --locked && cargo machete && taplo fmt --check
cargo package --locked
```

Run the Python gates with `PYTHONDONTWRITEBYTECODE=1`. The Docker MIT KDC
integration tests and the Active Directory tests are not part of CI; run them
locally with [`scripts/run-gated-integration.sh`](https://github.com/andrico21/rskrb5-ng/blob/main/scripts/run-gated-integration.sh)
as [`docs/gated-integration.md`](docs/gated-integration.md) describes.

## Releases

Releases are cut by tagging a CI-green commit on `main`; the tag-gated
`Release` workflow publishes it after the owner approves.
[`docs/RELEASING.md`](https://github.com/andrico21/rskrb5-ng/blob/main/docs/RELEASING.md) has the steps,
[`CHANGELOG.md`](CHANGELOG.md) the changes.

## License

Apache-2.0, like `rskrb5`. See [`LICENSE`](LICENSE), [`NOTICE`](NOTICE) and
[`PROVENANCE.md`](PROVENANCE.md).

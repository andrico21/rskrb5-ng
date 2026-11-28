# rskrb5-ng

`rskrb5-ng` (library `rskrb5_ng`) is a pure-Rust Kerberos 5 client and
service library with a GSS-API layer and HTTP Negotiate (SPNEGO) support. It
reads and writes keytabs, credential caches and `krb5.conf`, runs AS/TGS
exchanges with FAST, SPAKE, OTP and PKINIT pre-authentication, changes
passwords, administers principals through kadmind, validates AP-REQs and PACs
on the service side, and maps principals to local accounts. The crate has no
`unsafe` code (`#![forbid(unsafe_code)]`); the optional companion crate
`rskrb5-ng-os` holds the few OS calls of the Windows and macOS credential
stores.

It continues [`rskrb5`](https://github.com/clelange/rskrb5) independently;
[`PROVENANCE.md`](PROVENANCE.md) records where the code comes from.

## Status

| Area | Status |
|---|---|
| Keytab, ccache and config files | FILE, WRFILE and MEMORY keytabs; FILE, DIR and MEMORY credential caches with collections, KCM over its Unix socket and `KEYRING:` on Linux (`ccache-keyring`): parsing, serialization, owner-only atomic writes, locking and redacted metadata JSON, covered by gokrb5 and MIT 1.22.2 fixtures. `MSLSA:` on Windows and the macOS `API:` cache and Mach KCM come from the companion crate `rskrb5-ng-os`. `krb5.conf` parsing with MIT profile semantics and `include`/`includedir`. |
| Crypto and Kerberos messages | AES-SHA1, AES-SHA2, DES3, RC4-HMAC and Camellia (`camellia`), the Kerberos PRF and `KRB-FX-CF2`, DER message wrappers, KDC/AP/KRB-PRIV/KRB-SAFE/KRB-CRED helpers with an authenticated message API (`messages::AuthContext`) and kpasswd frames, covered by RFC vectors and fixture round-trips. The default enctypes are AES only; RC4 and DES3 need `allow_rc4`/`allow_des3`, and Camellia must be named in `permitted_enctypes`. |
| High-level client | Tokio password, keytab and ccache login and the stepwise exchange engine (`client::stepwise`): FAST armor (AS, and TGS on request), encrypted challenge, SPAKE (`spake`), OTP, PKINIT and anonymous PKINIT (`pkinit`). KDC discovery (profile, DNS SRV and URI, sites, registered locators), the MS-KKDCP proxy (built-in HTTPS transport with `kkdcp-rustls`), referrals, `[capaths]`, S4U2Self, S4U2Proxy and RBCD, `verify_init_creds`, renewal, service-ticket caching, kpasswd with password-expiry notices, the kadm5 administration client over RPCSEC_GSS (`kadm5`) and trace events (`trace`; the `tracing` adapter). |
| Service and HTTP Negotiate | AP-REQ validation with replay detection (in-memory, `file2` and `dfl` replay stores), AP-REP mutual authentication, the GSS-API (`gss`: names, credentials, contexts, channel bindings, delegation, IOV and AEAD wrapping, PRF, context and credential transfer, DCE style, S4U impersonation, IAKERB and the NegoEx framework), SPNEGO tokens, HTTP helpers, 401 retry client wrappers, Tower middleware, an Axum example, the HTTP client `http::agent::NegotiateHttpClient` (redirects, TLS channel bindings, a cookie jar with `http-client`) and the session manager `http::sessions::SessionManager`. |
| PAC and Active Directory | PAC container, validation info, UPN/DNS, credentials, delegation, device and claims data, the PAC verification policy (`pac::VerificationPolicy`), GSS name attributes and verified AD-CAMMAC authentication indicators, and AD credential summaries. Active Directory behaviour is verified against two Samba AD domains with a forest trust in containers; Windows-only behaviour is Samba-verified, not verified against Windows AD. The strict Windows AD gate needs a lab and isn't run in CI ([`docs/ad-integration.md`](docs/ad-integration.md)). |
| Review backlog | Every open item of the code review and of the second security-audit run is fixed with a regression test or dismissed with evidence: 78 rows, 75 fixed and 3 dismissed ([`docs/review/README.md`](https://github.com/andrico21/rskrb5-ng/blob/main/docs/review/README.md)). |
| Fuzzing | Each attacker-facing parser has a `cargo fuzz` target (41 targets, [`docs/review/fuzz.md`](https://github.com/andrico21/rskrb5-ng/blob/main/docs/review/fuzz.md)). |
| Live interoperability | The [`interop` workflow](https://github.com/andrico21/rskrb5-ng/blob/main/.github/workflows/interop.yml) builds pinned fixture images and runs the interop suites in containers on every push to `main` and weekly: 26 suites against an MIT krb5 1.22.2 realm (`mit` job) and all 31 with two Samba 4.22 AD domains added (`samba` job). `scripts/interop/run.sh suites` lists them; [`PROVENANCE.md`](PROVENANCE.md) states what they prove. |
| Follow-up review | The independent review of `6586b7a` is tracked row by row, with proofs, in [`docs/review/followup-6586b7a.md`](https://github.com/andrico21/rskrb5-ng/blob/main/docs/review/followup-6586b7a.md), and the defects and decisions of the parity work in [`docs/review/parity-register.md`](https://github.com/andrico21/rskrb5-ng/blob/main/docs/review/parity-register.md); `CHANGELOG.md` lists each behaviour change. |
| Parity with MIT krb5 and gokrb5 | Every in-scope row of both manifests is implemented with named tests; the rest are permanent rejections (D2, POL-01), out-of-scope server parts (D1) and two owner-decided omissions (the Windows `API:` cache, D13; gokrb5 `Client.Key`, D14: no long-term key leaves a client). The per-feature manifests are the source of truth: [MIT krb5 1.22.2](docs/mit-krb5-parity.md), 169 rows (153 implemented, 8 rejected, 1 omitted, 7 out of scope); [gokrb5 v8.4.4](docs/gokrb5-parity.md), 36 rows (35 implemented, 1 omitted). |
| Not supported | Server-side Kerberos (KDC, kadmind, kprop, the KDB, server-side pre-authentication and policy plugins), command-line tools, C plugin loading and system GSSAPI/SSPI facades. The insecure features rejected by name in the [security policy](docs/security-policy.md): single DES, Kerberos V4 and V4 conversion, RSA-mode and draft-9 PKINIT, export-strength RC4, unkeyed or weak checksums, unprotected password changes and blanket `allow_weak_crypto`. The Windows `API:` (KfW CCAPI) cache, which fails with a typed error. A bundled Kerberos scheme for NegoEx: the NegoEx framework takes caller-supplied mechanisms, as MIT's does. An accessor for a client's long-term key (gokrb5 `Client.Key`): no long-term key leaves a client. |

The API can still change before 1.0. Wire formats, cryptographic behaviour
and the gokrb5 fixture parity are treated as compatibility-sensitive.
[`docs/mit-krb5-parity.md`](docs/mit-krb5-parity.md) and
[`docs/gokrb5-parity.md`](docs/gokrb5-parity.md) track parity with MIT krb5
1.22.2 and gokrb5 v8.4.4 feature by feature, from the machine-readable
`docs/mit-krb5-parity.toml` and `docs/gokrb5-parity.toml`, and list every
deliberate divergence.

The [security policy](docs/security-policy.md) documents runtime encryption
permission, what each leaf flag does and does not grant, permanent feature
rejections, derivation limits, the TLS and channel-binding trust model and
residual secret copies.

The generated [configuration relation catalogue](docs/config-relations.md)
lists typed settings, their effective consumers, and the fail-closed,
feature-unavailable and out-of-scope diagnostics.

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

The leaf flags below each add optional dependencies
([`docs/dependency-admission.md`](docs/dependency-admission.md)) and compile
only their own modules and declared seams (`leaf_features.py`). None is a default, and none grants a runtime permission: a
configuration or a caller still has to ask for what it enables.

| Leaf flag | Enables | Needs |
|---|---|---|
| `camellia` | the Camellia enctypes of RFC 6803 | |
| `ccache-keyring` | the Linux kernel keyring credential cache (`KEYRING:`) | Linux |
| `http-client` | the built-in cookie jar of the HTTP client (`http::cookies`) | implies `http`; the client itself needs `tokio` |
| `kkdcp-rustls` | the built-in HTTPS transport (rustls with the RustCrypto provider) of the KDC proxy and the HTTP client | `tokio` |
| `localauth` | local authorization: `.k5login`, `auth_to_local` rules and names (`localauth`) | |
| `pkinit` | PKINIT and anonymous PKINIT, `pkinit_cert_match` | `messages` |
| `spake` | SPAKE pre-authentication (RFC 9588) | `messages` |
| `tracing` | an adapter from the library's trace events to the `tracing` crate | |

The default features are `spnego`, `tokio` and `serde`. Every combination of
features is supported: the core features resolve to 36 distinct closures, each
leaf flag is checked on the default and on its minimal build, and the
all-features build makes 53 closures in total. CI runs strict clippy and the
tests in each one (the `closures` job, held equal to
`python3 scripts/lint-gates/feature_closures.py list`). The
compatibility report is generated with:

```sh
cargo run --no-default-features --features evaluation --bin rskrb5-ng-compat-report
```

## Local checks

These are the commands of the
[`ci.yml`](https://github.com/andrico21/rskrb5-ng/blob/main/.github/workflows/ci.yml)
jobs `fmt`, `closures`, `test`, `docs`, `lint-gates`, the supply-chain jobs
and `package`; the workflow also runs platform, Miri, MSRV, consumer and fuzz
jobs. [`docs/lint-policy.md`](docs/lint-policy.md) explains the lint profile
and each gate.

```sh
python3 -m pip install --require-hashes -r scripts/lint-gates/requirements.txt   # once: the CommonMark gates import markdown_it
cargo +nightly-2026-10-03 fmt --all -- --check
cargo +nightly-2026-10-03 fmt --manifest-path fuzz/Cargo.toml -- --check
python3 scripts/lint-gates/feature_closures.py run   # clippy -D warnings and tests, every feature closure
cargo test --all-features --locked
cargo test --doc --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
for s in scripts/lint-gates/*.py scripts/check-error-constructions.py; do python3 "$s" --self-test || exit 1; done
python3 scripts/check-config-relations.py --self-test
python3 scripts/check-config-relations.py
python3 scripts/lint-gates/package_links.py --enforce
python3 scripts/lint-gates/overlay_facts.py --enforce
python3 scripts/lint-gates/changelog_rows.py --enforce
python3 scripts/lint-gates/allow_gate.py --enforce
python3 scripts/lint-gates/exception_gate.py --enforce
python3 scripts/lint-gates/profile_eq.py --clippy-toml
python3 scripts/lint-gates/completeness_check.py
python3 scripts/lint-gates/facade_gate.py --enforce
python3 scripts/lint-gates/prose_gate.py --enforce
python3 scripts/lint-gates/feature_closures.py check-ci .github/workflows/ci.yml
python3 scripts/lint-gates/dep_admission.py --enforce
python3 scripts/lint-gates/leaf_features.py --enforce
python3 scripts/lint-gates/advisory_ignores.py --enforce
python3 scripts/lint-gates/fuzz_lint.py --enforce
python3 scripts/lint-gates/fuzz_coverage.py --enforce
python3 scripts/lint-gates/gate_hygiene.py --enforce
python3 scripts/lint-gates/workflow_gate.py --enforce
python3 scripts/check-error-constructions.py
cargo deny check && cargo audit && cargo vet --locked && cargo machete && taplo fmt --check
cargo package --locked
```

Run the Python gates with `PYTHONDONTWRITEBYTECODE=1`. The live interop
suites run with Docker or Podman through `scripts/interop/run.sh all`
([`docs/gated-integration.md`](docs/gated-integration.md)). The upstream Docker
MIT KDC integration tests and the Active Directory gate are not part of CI; run
them locally with [`scripts/run-gated-integration.sh`](https://github.com/andrico21/rskrb5-ng/blob/main/scripts/run-gated-integration.sh)
as the same document describes.

## Releases

Releases are cut by tagging a CI-green commit on `main`; the tag-gated
`Release` workflow publishes it after the owner approves.
[`docs/RELEASING.md`](https://github.com/andrico21/rskrb5-ng/blob/main/docs/RELEASING.md) has the steps,
[`CHANGELOG.md`](CHANGELOG.md) the changes. No `rskrb5-ng` version is
published yet, and the companion crate `rskrb5-ng-os` is `publish = false`:
an application that wants the platform stores takes it from this repository.

## License

Apache-2.0, like `rskrb5`. See [`LICENSE`](LICENSE), [`NOTICE`](NOTICE) and
[`PROVENANCE.md`](PROVENANCE.md).

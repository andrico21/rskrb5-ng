# Gated Integration Validation

The gated integration tests reuse the gokrb5 Docker fixtures and run locally
through the checked-in runner, which fixes the container names, ports, and
environment variables.

The rskrb5-ng CI workflow (`.github/workflows/ci.yml`) has no Docker
integration job and no AD job, and its `workflow_dispatch` trigger declares no
inputs: these gates are local-only. The upstream `clelange/rskrb5` workflow ran
them on GitHub-hosted runners; `docs/gokrb5-parity.toml` keeps those runs as
evidence attributed to the upstream repository (status `historical-upstream`).

## Local Run

Run the full Docker-backed suite:

```sh
scripts/run-gated-integration.sh run
```

Run the password-change gate as well:

```sh
TEST_KPASSWD=1 scripts/run-gated-integration.sh run
```

Run one focused test while keeping the containers available for inspection:

```sh
RSKRB5_KEEP_CONTAINERS=1 scripts/run-gated-integration.sh run \
  --test client_integration docker_mit_kdc_dns_srv_as_login -- --nocapture
scripts/run-gated-integration.sh stop
```

The `start` command writes the environment file
`target/gated-integration/gated-integration.env`. The file can carry AD
keytab secrets, so the runner keeps it private:

- the directory is used only by the runner and is set to mode 0700; a symlink
  or a directory owned by another user is refused;
- the file is staged under a fresh mode-0600 name and renamed into place, so an
  earlier permissive file is replaced, never rewritten;
- `env` prints it with every keytab `*_HEX`/`*_BASE64` value replaced by
  `<redacted>`;
- `stop` deletes it, and so does `run` on exit unless `RSKRB5_KEEP_CONTAINERS=1`.

`RSKRB5_INTEGRATION_ENV_DIR` selects another directory, which gets the same
treatment. `scripts/run-gated-integration.sh self-test` checks this handling on
dummy secrets without Docker. To run custom cargo commands against
already-started fixtures:

```sh
scripts/run-gated-integration.sh start
scripts/run-gated-integration.sh env
scripts/run-gated-integration.sh test --test client_integration
scripts/run-gated-integration.sh stop
```

## Live Interop Harness

`scripts/interop/run.sh` (the `interop` workflow runs it on every `main` push)
builds the pinned MIT krb5 and Samba AD fixtures and runs the live suites in
Docker or Podman. Three optional variables serve local runs:

- `INTEROP_NAMESPACE=<name>` scopes the label, the networks and the container
  names of one run (`rskrb5-interop--<name>-...`), so `up` and `down` of one run
  never remove another run's fixtures. `INTEROP_PORT_OFFSET=<n>` shifts every
  default host port, so two runs can publish side by side. Unset, the names and
  ports are the ones CI uses.
- `INTEROP_BUILD_CA_DIR=<dir>` (Podman only) mounts a directory of extra root
  certificates read-only during image builds, for a host behind a proxy that
  inspects TLS. The download pins (sha256 and PGP) of the Dockerfiles still
  bind, and CI never sets it.
- `INTEROP_LOG_DIR=<dir>` collects the fixture logs with every generated secret
  redacted. The run records its secrets before using them; when that record is
  missing or redaction fails, the directory holds only `LOG-UPLOAD-REFUSED.txt`.

## Resolver Behavior

The DNS-SRV test uses the OS resolver through the Rust DNS resolver stack, so
the DNS fixture must be the active resolver while `TEST_DNS_KDC=1` is set. The
resolver configuration defaults to:

```sh
RSKRB5_CONFIGURE_RESOLVER=1 # Linux
RSKRB5_CONFIGURE_RESOLVER=0 # other local platforms
```

With `RSKRB5_CONFIGURE_RESOLVER=1`, the runner backs up `/etc/resolv.conf`,
writes the DNS fixture nameserver, and restores the backup during `stop`. If
that is too invasive for local debugging, disable DNS or resolver mutation:

```sh
TEST_DNS_KDC=0 scripts/run-gated-integration.sh run
RSKRB5_CONFIGURE_RESOLVER=0 scripts/run-gated-integration.sh start
```

When resolver configuration is disabled, `TEST_DNS_KDC` defaults to `0` so the
Rust DNS-SRV gate is skipped. The generated environment file still records `DNS_IP`; on Docker backends that expose container IPs directly, this is
the DNS container IP rather than the loopback publish address.
`TEST_HTTP_URL` also defaults to `http://127.0.0.1` in this mode so the live
HTTP Negotiate tests do not depend on DNS.

When diagnosing DNS directly, query the fixture before running Rust tests:

```sh
source target/gated-integration/gated-integration.env
dig @"$DNS_IP" -p 53 _kerberos._udp.TEST.GOKRB5 SRV
dig @"$DNS_IP" -p 53 cname.test.gokrb5 A
```

## macOS And Privileged Gates

On Darwin the runner defaults `RSKRB5_DIRECT_CONTAINER_IP=1`. This points the
Rust tests at Docker container IPs instead of host-forwarded KDC ports, which
avoids address-bound ticket mismatches seen with external `kinit`/`kvno`
coverage on local Docker backends. Override it when forwarded ports are known to
work:

```sh
RSKRB5_DIRECT_CONTAINER_IP=0 scripts/run-gated-integration.sh run
```

To run the DNS-SRV gate locally on Darwin, opt in to resolver mutation from an
interactive shell that can run `sudo`:

```sh
RSKRB5_CONFIGURE_RESOLVER=1 TEST_DNS_KDC=1 scripts/run-gated-integration.sh run
```

`TESTPRIVILEGED=1` is enabled by default and requires system Kerberos tools
(`kinit`, `kvno`) on `PATH`. On Homebrew installations:

```sh
PATH="/opt/homebrew/opt/krb5/bin:$PATH" scripts/run-gated-integration.sh run
```

## Active Directory Gate

`TESTAD=1` is not bootstrapped by this script. It needs the separate AD lab
documented in [`ad-integration.md`](ad-integration.md) or equivalent endpoints
supplied through `TEST_AD_USER_KDC_ADDR`, `TEST_AD_RESOURCE_KDC_ADDR`,
`TEST_AD_USER_ADMIN_ADDR`, and `TEST_AD_RESOURCE_ADMIN_ADDR`.
Lab-specific keytabs can be supplied with the `TEST_AD_*_KEYTAB_PATH`,
`TEST_AD_*_KEYTAB_HEX`, or `TEST_AD_*_KEYTAB_BASE64` variables documented in
the AD runbook. The runner preserves those values in its private environment
file and redacts the keytab values when `env` prints it.

Use `TESTAD_REQUIRED=1` for release or parity evidence so unreachable AD
endpoints fail instead of soft-skipping:

```sh
TESTAD=1 TESTAD_REQUIRED=1 cargo test --all-features --test client_ad_integration -- --nocapture
```

There is no hosted AD gate in rskrb5-ng: `ci.yml` has no AD job, and
`scripts/check-github-ad-gate.py --dispatch` refuses to dispatch until an AD job
and its `workflow_dispatch` inputs are restored. The secret setup such a job
needs is in [`github-ad-gate-setup.md`](github-ad-gate-setup.md).

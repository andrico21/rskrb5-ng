#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -n "${RSKRB5_INTEGRATION_ENV_FILE:-}" ]]; then
  echo "RSKRB5_INTEGRATION_ENV_FILE is no longer supported; set RSKRB5_INTEGRATION_ENV_DIR to a directory used only by this runner." >&2
  exit 2
fi
# A directory used only by this runner: it holds the generated environment,
# which may carry AD keytab secrets, so it is kept at mode 0700 and the file
# at mode 0600.
ENV_DIR="${RSKRB5_INTEGRATION_ENV_DIR:-"$ROOT_DIR/target/gated-integration"}"
ENV_FILE="$ENV_DIR/gated-integration.env"
RESOLV_CONF_BACKUP="${RSKRB5_RESOLV_CONF_BACKUP:-"$ROOT_DIR/target/resolv.conf.rskrb5.backup"}"

CONTAINERS=(
  dns
  krb5kdc
  krb5kdc-old
  krb5kdc-latest
  krb5kdc-resdom
  krb5kdc-shorttickets
  gokrb5-http
)

usage() {
  cat <<'EOF'
Usage: scripts/run-gated-integration.sh <command> [cargo-test-args...]

Commands:
  start       Start gokrb5 Docker integration fixtures and write the private
              environment file target/gated-integration/gated-integration.env.
  test        Source the environment file and run cargo test --all-features.
  run         Start fixtures, run tests, then stop fixtures unless RSKRB5_KEEP_CONTAINERS=1.
  stop        Stop known fixture containers, delete the environment file, and
              restore /etc/resolv.conf when a backup exists.
  env         Print the generated environment with keytab secret values redacted.
  self-test   Check the environment file handling on dummy secrets (no Docker).

Useful environment:
  TEST_KPASSWD=1                 Enable live password-change coverage.
  TESTAD=1                       Enable Active Directory tests, if the lab is reachable.
  TESTAD_REQUIRED=1              Fail instead of soft-skipping when TESTAD setup is unreachable.
  INTEGRATION_REQUIRED=0         Let the requested integration suite skip unreachable fixtures
                                 (the runner sets INTEGRATION_REQUIRED=1 by default).
  TEST_AD_*_KEYTAB_PATH          AD lab-specific keytab file overrides.
  TEST_AD_*_KEYTAB_HEX           AD lab-specific keytab hex secret overrides.
  TEST_AD_*_KEYTAB_BASE64        AD lab-specific keytab base64 secret overrides.
  TEST_DNS_KDC=1                 Enable DNS-SRV KDC discovery tests.
                                 Defaults to resolver configuration mode.
  TESTPRIVILEGED=1               Enable external kinit/kvno coverage. Defaults to 1.
  RSKRB5_CONFIGURE_RESOLVER=1    Point /etc/resolv.conf at the DNS fixture.
                                 Defaults to 1 on Linux and 0 elsewhere.
  RSKRB5_DIRECT_CONTAINER_IP=1   Use Docker container IPs instead of forwarded ports.
                                 Defaults to 1 on Darwin and 0 elsewhere.
  RSKRB5_KEEP_CONTAINERS=1       Keep containers after the run command exits.
  RSKRB5_INTEGRATION_ENV_DIR     Directory for the environment file; used only by
                                 this runner and set to mode 0700.
  DOCKER_PLATFORM=linux/amd64    Optional Docker --platform override.

Examples:
  scripts/run-gated-integration.sh run
  TEST_KPASSWD=1 scripts/run-gated-integration.sh run --test client_integration
  scripts/run-gated-integration.sh start
  scripts/run-gated-integration.sh test --test client_integration docker_mit_kdc_dns_srv_as_login -- --nocapture
  scripts/run-gated-integration.sh stop
EOF
}

docker_sudo=()
docker_sudo_checked=0

# Probes Docker access on first use, so commands that need no Docker
# (`env`, `self-test`) never run it.
docker_cmd() {
  if [[ "$docker_sudo_checked" == "0" ]]; then
    docker_sudo_checked=1
    if [[ "$(id -u)" != "0" ]] && ! docker ps >/dev/null 2>&1; then
      if command -v sudo >/dev/null 2>&1; then
        docker_sudo=(sudo)
      fi
    fi
  fi
  "${docker_sudo[@]}" docker "$@"
}

sudo_cmd() {
  if [[ "$(id -u)" == "0" ]]; then
    "$@"
  else
    sudo "$@"
  fi
}

docker_platform_args() {
  if [[ -n "${DOCKER_PLATFORM:-}" ]]; then
    printf '%s\n' --platform "$DOCKER_PLATFORM"
  fi
}

stop_containers() {
  docker_cmd rm -f "${CONTAINERS[@]}" >/dev/null 2>&1 || true
}

restore_resolver() {
  if [[ -f "$RESOLV_CONF_BACKUP" ]]; then
    sudo_cmd cp "$RESOLV_CONF_BACKUP" /etc/resolv.conf
    rm -f "$RESOLV_CONF_BACKUP"
  fi
}

remove_env_file() {
  rm -f "$ENV_FILE"
}

stop_all() {
  stop_containers
  remove_env_file
  restore_resolver
}

container_ip() {
  docker_cmd inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$1"
}

container_gateway() {
  docker_cmd inspect -f '{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}' "$1"
}

relax_dns_acl() {
  docker_cmd exec dns sh -lc \
    "ready=0; for _ in 1 2 3 4 5 6 7 8 9 10; do rndc status >/dev/null 2>&1 && ready=1 && break; sleep 1; done; test \"\$ready\" = 1 && sed -i 's/allow-query[[:space:]]*{[^}]*};/allow-query { any; };/' /etc/named.conf && rndc reconfig"
}

strip_port() {
  local value="$1"
  if [[ "$value" == *:* && "${value##*:}" =~ ^[0-9]+$ ]]; then
    printf '%s\n' "${value%:*}"
  else
    printf '%s\n' "$value"
  fi
}

configure_resolver() {
  local dns_ip="$1"
  local enabled="$2"

  if [[ "$enabled" != "1" ]]; then
    return
  fi

  mkdir -p "$(dirname "$RESOLV_CONF_BACKUP")"
  if [[ ! -f "$RESOLV_CONF_BACKUP" ]]; then
    sudo_cmd cp /etc/resolv.conf "$RESOLV_CONF_BACKUP"
  fi
  printf 'nameserver %s\n' "$dns_ip" | sudo_cmd tee /etc/resolv.conf >/dev/null
}

default_configure_resolver_enabled() {
  local enabled="${RSKRB5_CONFIGURE_RESOLVER:-}"
  if [[ -z "$enabled" ]]; then
    if [[ "$(uname -s)" == "Linux" ]]; then
      enabled=1
    else
      enabled=0
    fi
  fi
  printf '%s\n' "$enabled"
}

dig_short() {
  local server="$1"
  local name="$2"
  local record_type="$3"
  local host="${server%:*}"
  local port="${server##*:}"

  if [[ "$server" != *:* || ! "$port" =~ ^[0-9]+$ ]]; then
    host="$server"
    port=53
  fi

  dig @"$host" -p "$port" +time=1 +tries=1 +short "$name" "$record_type"
}

wait_for_dns_fixture() {
  local dns_server="$1"
  local http_addr="$2"

  if ! command -v dig >/dev/null 2>&1; then
    echo "dig not found; skipping DNS fixture readiness check." >&2
    return
  fi

  local srv_answer=""
  local http_answer=""
  for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    srv_answer="$(dig_short "$dns_server" _kerberos._udp.test.gokrb5 SRV 2>&1 || true)"
    http_answer="$(dig_short "$dns_server" cname.test.gokrb5 A 2>&1 || true)"
    if [[ "$srv_answer" == *"kdc.test.gokrb5."* && "$http_answer" == *"$http_addr"* ]]; then
      return
    fi
    sleep 1
  done

  {
    echo "DNS fixture did not become ready at $dns_server."
    echo "Last _kerberos._udp.test.gokrb5 SRV answer:"
    echo "$srv_answer"
    echo "Last cname.test.gokrb5 A answer:"
    echo "$http_answer"
  } >&2
  return 1
}

verify_configured_resolver() {
  local http_addr="$1"

  if ! command -v dig >/dev/null 2>&1; then
    echo "dig not found; skipping configured resolver verification." >&2
    return
  fi

  local srv_answer=""
  local http_answer=""
  for _ in 1 2 3 4 5; do
    srv_answer="$(dig +time=1 +tries=1 +short _kerberos._udp.test.gokrb5 SRV 2>&1 || true)"
    http_answer="$(dig +time=1 +tries=1 +short cname.test.gokrb5 A 2>&1 || true)"
    if [[ "$srv_answer" == *"kdc.test.gokrb5."* && "$http_answer" == *"$http_addr"* ]]; then
      return
    fi
    sleep 1
  done

  {
    echo "Configured resolver cannot query the DNS fixture."
    echo "Last _kerberos._udp.test.gokrb5 SRV answer:"
    echo "$srv_answer"
    echo "Last cname.test.gokrb5 A answer:"
    echo "$http_answer"
  } >&2
  return 1
}

# Creates the runner's environment directory at mode 0700, or brings an
# existing one owned by the invoking user to 0700; refuses a symlink or a
# directory owned by anyone else.
prepare_env_dir() {
  if [[ -L "$ENV_DIR" ]]; then
    echo "$ENV_DIR is a symlink; refusing to write keytab secrets through it." >&2
    return 1
  fi
  (umask 077 && mkdir -p "$ENV_DIR") || return 1
  if [[ ! -O "$ENV_DIR" ]]; then
    echo "$ENV_DIR is not owned by the current user; refusing to write keytab secrets into it." >&2
    return 1
  fi
  chmod 700 "$ENV_DIR" || return 1
}

# Every variable of the environment file, in file order. `write_env` and
# `print_env` both work from this list, never from the file's text.
ENV_NAMES=(
  INTEGRATION INTEGRATION_REQUIRED TESTPRIVILEGED TESTAD TESTAD_REQUIRED TEST_KPASSWD TEST_DNS_KDC
  TEST_AD_USER_KDC_ADDR TEST_AD_RESOURCE_KDC_ADDR TEST_AD_USER_ADMIN_ADDR TEST_AD_RESOURCE_ADMIN_ADDR
  TEST_AD_KDC_ADDR TEST_AD_RES_KDC_ADDR TEST_AD_ADMIN_ADDR TEST_AD_RES_ADMIN_ADDR
  TEST_AD_TESTUSER1_KEYTAB_PATH TEST_AD_TESTUSER1_KEYTAB_HEX TEST_AD_TESTUSER1_KEYTAB_BASE64
  TEST_AD_TESTUSER2_KEYTAB_PATH TEST_AD_TESTUSER2_KEYTAB_HEX TEST_AD_TESTUSER2_KEYTAB_BASE64
  TEST_AD_TESTUSER3_KEYTAB_PATH TEST_AD_TESTUSER3_KEYTAB_HEX TEST_AD_TESTUSER3_KEYTAB_BASE64
  TEST_AD_SYSHTTP_KEYTAB_PATH TEST_AD_SYSHTTP_KEYTAB_HEX TEST_AD_SYSHTTP_KEYTAB_BASE64
  TEST_KDC_ADDR TEST_OLD_KDC_ADDR TEST_LATEST_KDC_ADDR TEST_RESDOM_KDC_ADDR TEST_SHORT_KDC_ADDR
  TEST_KPASSWD_ADDR TEST_KPASSWD_SADDR TEST_HTTP_URL TEST_HTTP_ADDR DNS_IP DNSUTILS_OVERRIDE_NS
  RSKRB5_DNS_SERVER
)

# Keytab secret material: printed by `env` only as <redacted>.
is_secret_name() {
  [[ "$1" =~ ^TEST_AD_[A-Z0-9_]+_KEYTAB_(HEX|BASE64)$ ]]
}

write_env() {
  # The positional arguments, under the names the file exports. Each value is
  # serialized with `printf %q`, so a space, quote, `$(...)`, `;` or newline
  # in an operator value stays data when `test` sources the file.
  local TEST_KDC_ADDR="$1" TEST_OLD_KDC_ADDR="$2" TEST_LATEST_KDC_ADDR="$3"
  local TEST_RESDOM_KDC_ADDR="$4" TEST_SHORT_KDC_ADDR="$5" TEST_KPASSWD_ADDR="$6"
  local TEST_KPASSWD_SADDR="$7" DNS_IP="$8" DNSUTILS_OVERRIDE_NS="$9" RSKRB5_DNS_SERVER="$9"
  local TEST_HTTP_URL="${10}" TEST_HTTP_ADDR="${11}" TEST_DNS_KDC="${12}"
  # The runner is an explicit request for the integration suite: a fixture the
  # tests cannot reach fails them instead of skipping, unless the operator
  # sets INTEGRATION_REQUIRED=0.
  local INTEGRATION=1 INTEGRATION_REQUIRED="${INTEGRATION_REQUIRED:-1}"
  local TESTPRIVILEGED="${TESTPRIVILEGED:-1}" TESTAD="${TESTAD:-0}"
  local TESTAD_REQUIRED="${TESTAD_REQUIRED:-0}" TEST_KPASSWD="${TEST_KPASSWD:-0}"

  prepare_env_dir || return 1
  # Stage under a fresh mode-0600 name in the private directory, then rename:
  # the secrets never land in a file with umask-default or inherited
  # permissions, and an earlier permissive file is replaced, not rewritten.
  local staged name
  staged="$(mktemp "$ENV_DIR/.gated-integration.env.XXXXXX")" || return 1
  chmod 600 "$staged" || {
    rm -f "$staged"
    return 1
  }
  if ! for name in "${ENV_NAMES[@]}"; do
    printf 'export %s=%q\n' "$name" "${!name:-}"
  done >"$staged"; then
    rm -f "$staged"
    return 1
  fi
  mv -f "$staged" "$ENV_FILE" || {
    rm -f "$staged"
    return 1
  }
}

start_fixtures() {
  local platform_args=()
  while IFS= read -r arg; do
    platform_args+=("$arg")
  done < <(docker_platform_args)

  stop_containers

  docker_cmd run -d "${platform_args[@]}" -h kdc.test.gokrb5 \
    -v /etc/localtime:/etc/localtime:ro \
    -p 88:88 -p 88:88/udp -p 464:464 -p 464:464/udp \
    --name krb5kdc jcmturner/gokrb5:kdc-centos-default >/dev/null
  docker_cmd run -d "${platform_args[@]}" -h kdc.test.gokrb5 \
    -v /etc/localtime:/etc/localtime:ro \
    -p 78:88 -p 78:88/udp \
    --name krb5kdc-old jcmturner/gokrb5:kdc-older >/dev/null
  docker_cmd run -d "${platform_args[@]}" -h kdc.test.gokrb5 \
    -v /etc/localtime:/etc/localtime:ro \
    -p 98:88 -p 98:88/udp \
    --name krb5kdc-latest jcmturner/gokrb5:kdc-latest >/dev/null
  docker_cmd run -d "${platform_args[@]}" -h kdc.resdom.gokrb5 \
    -v /etc/localtime:/etc/localtime:ro \
    -p 188:88 -p 188:88/udp \
    --name krb5kdc-resdom jcmturner/gokrb5:kdc-resdom >/dev/null
  docker_cmd run -d "${platform_args[@]}" -h kdc.test.gokrb5 \
    -v /etc/localtime:/etc/localtime:ro \
    -p 58:88 -p 58:88/udp \
    --name krb5kdc-shorttickets jcmturner/gokrb5:kdc-shorttickets >/dev/null
  docker_cmd run -d "${platform_args[@]}" \
    --add-host host.test.gokrb5:127.0.0.88 \
    -v /etc/localtime:/etc/localtime:ro \
    -p 80:80 -p 443:443 \
    --name gokrb5-http jcmturner/gokrb5:http >/dev/null

  local direct="${RSKRB5_DIRECT_CONTAINER_IP:-}"
  if [[ -z "$direct" ]]; then
    if [[ "$(uname -s)" == "Darwin" ]]; then
      direct=1
    else
      direct=0
    fi
  fi

  local configure_resolver_enabled
  configure_resolver_enabled="$(default_configure_resolver_enabled)"
  local test_dns_kdc="${TEST_DNS_KDC:-$configure_resolver_enabled}"

  local primary_addr old_addr latest_addr resdom_addr short_addr kpasswd_addr kpasswd_sender_addr
  local dns_kdc_addr
  if [[ "$direct" == "1" ]]; then
    local primary_ip old_ip latest_ip resdom_ip short_ip
    primary_ip="$(container_ip krb5kdc)"
    old_ip="$(container_ip krb5kdc-old)"
    latest_ip="$(container_ip krb5kdc-latest)"
    resdom_ip="$(container_ip krb5kdc-resdom)"
    short_ip="$(container_ip krb5kdc-shorttickets)"
    primary_addr="$primary_ip:88"
    old_addr="$old_ip:88"
    latest_addr="$latest_ip:88"
    resdom_addr="$resdom_ip:88"
    short_addr="$short_ip:88"
    kpasswd_addr="$primary_ip:464"
    kpasswd_sender_addr="${TEST_KPASSWD_SADDR:-"$(container_gateway krb5kdc)"}"
    dns_kdc_addr="$primary_ip"
  else
    primary_addr="${TEST_KDC_ADDR:-127.0.0.1}"
    old_addr="${TEST_OLD_KDC_ADDR:-127.0.0.1}"
    latest_addr="${TEST_LATEST_KDC_ADDR:-127.0.0.1}"
    resdom_addr="${TEST_RESDOM_KDC_ADDR:-127.0.0.1}"
    short_addr="${TEST_SHORT_KDC_ADDR:-127.0.0.1}"
    kpasswd_addr="${TEST_KPASSWD_ADDR:-127.0.0.1}"
    kpasswd_sender_addr="${TEST_KPASSWD_SADDR:-127.0.0.1}"
    dns_kdc_addr="$(strip_port "$primary_addr")"
  fi

  local dns_bind_ns="${DNSUTILS_OVERRIDE_NS:-127.0.88.53:53}"
  local http_addr="${TEST_HTTP_ADDR:-127.0.0.1}"
  local http_url="${TEST_HTTP_URL:-}"
  if [[ -z "$http_url" ]]; then
    if [[ "$test_dns_kdc" == "1" ]]; then
      http_url="http://cname.test.gokrb5"
    else
      http_url="http://127.0.0.1"
    fi
  fi

  docker_cmd run -d "${platform_args[@]}" -h ns.test.gokrb5 \
    -v /etc/localtime:/etc/localtime:ro \
    -e "TEST_KDC_ADDR=$dns_kdc_addr" \
    -e "TEST_HTTP_ADDR=$http_addr" \
    -p "$dns_bind_ns:53" -p "$dns_bind_ns:53/udp" \
    --name dns jcmturner/gokrb5:dns >/dev/null
  relax_dns_acl

  local dns_ip="${DNS_IP:-}"
  if [[ -z "$dns_ip" ]]; then
    if [[ "$direct" == "1" ]]; then
      dns_ip="$(container_ip dns)"
    else
      dns_ip="${dns_bind_ns%:*}"
    fi
  fi
  local dns_override_ns="${DNSUTILS_OVERRIDE_NS:-"$dns_ip:53"}"

  if [[ "$test_dns_kdc" == "1" || "$http_url" == *".test.gokrb5"* ]]; then
    wait_for_dns_fixture "$dns_override_ns" "$http_addr"
  fi

  write_env \
    "$primary_addr" "$old_addr" "$latest_addr" "$resdom_addr" "$short_addr" \
    "$kpasswd_addr" "$kpasswd_sender_addr" "$dns_ip" "$dns_override_ns" \
    "$http_url" "$http_addr" "$test_dns_kdc"

  configure_resolver "$dns_ip" "$configure_resolver_enabled"
  if [[ "$configure_resolver_enabled" == "1" && "$test_dns_kdc" == "1" ]]; then
    verify_configured_resolver "$http_addr"
  fi

  echo "Started gokrb5 integration fixtures."
  echo "Environment written to $ENV_FILE"
}

run_tests() {
  if [[ ! -f "$ENV_FILE" ]]; then
    echo "Missing $ENV_FILE; run '$0 start' first." >&2
    return 1
  fi

  local name
  local -A overrides=()
  for name in "${ENV_NAMES[@]}"; do
    if [[ -v "$name" ]]; then overrides["$name"]="${!name}"; fi
  done
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  for name in "${!overrides[@]}"; do
    printf -v "$name" '%s' "${overrides[$name]}"
    export "$name"
  done
  local configure_resolver_enabled
  configure_resolver_enabled="$(default_configure_resolver_enabled)"
  configure_resolver "$DNS_IP" "$configure_resolver_enabled"
  if [[ "$configure_resolver_enabled" == "1" && "$TEST_DNS_KDC" == "1" ]]; then
    verify_configured_resolver "$TEST_HTTP_ADDR"
  fi
  cargo test --all-features "$@"
}

# Prints the environment with every non-empty keytab HEX/BASE64 override
# replaced by <redacted>; `test` sources the unredacted file directly. The
# values are read back by name and re-serialized, so a multiline secret
# never reaches the output, whatever its line structure.
print_env() {
  if [[ ! -f "$ENV_FILE" ]]; then
    echo "Missing $ENV_FILE; run '$0 start' first." >&2
    return 1
  fi
  (
    # shellcheck disable=SC1090
    source "$ENV_FILE"
    for name in "${ENV_NAMES[@]}"; do
      if is_secret_name "$name" && [[ -n "${!name:-}" ]]; then
        printf 'export %s=<redacted>\n' "$name"
      else
        printf 'export %s=%q\n' "$name" "${!name:-}"
      fi
    done
  )
}

# Exercises write_env, print_env and stop_all on dummy keytab secrets in a
# scratch directory, with Docker and sudo stubbed out: no container, resolver
# or network is touched.
self_test() {
  local scratch failures=0 printed
  local hex_secret="05020000dummyhexkeytabsecret"
  local b64_secret="BQIAAAdummyBase64KeytabSecret=="
  scratch="$(mktemp -d "${TMPDIR:-/tmp}/rskrb5-gated-selftest.XXXXXX")"
  ENV_DIR="$scratch/state"
  ENV_FILE="$ENV_DIR/gated-integration.env"
  RESOLV_CONF_BACKUP="$scratch/no-resolv-backup"
  docker_cmd() { return 0; }
  sudo_cmd() { return 0; }
  st_fail() {
    echo "self-test FAIL: $*" >&2
    failures=$((failures + 1))
  }
  mode_of() {
    ls -ld "$1" | cut -c1-10
  }

  # A permissive directory and env file left by an earlier run.
  umask 022
  mkdir -p "$ENV_DIR"
  chmod 755 "$ENV_DIR"
  printf 'stale\n' >"$ENV_FILE"
  chmod 644 "$ENV_FILE"

  TEST_AD_TESTUSER1_KEYTAB_HEX="$hex_secret" TEST_AD_SYSHTTP_KEYTAB_BASE64="$b64_secret" \
    write_env 127.0.0.1:88 127.0.0.1:78 127.0.0.1:98 127.0.0.1:188 127.0.0.1:58 \
    127.0.0.1:464 127.0.0.1 127.0.88.53 127.0.88.53:53 http://127.0.0.1 127.0.0.1 0

  [[ "$(mode_of "$ENV_FILE")" == "-rw-------" ]] ||
    st_fail "env file mode is $(mode_of "$ENV_FILE"), expected -rw-------"
  [[ "$(mode_of "$ENV_DIR")" == "drwx------" ]] ||
    st_fail "env directory mode is $(mode_of "$ENV_DIR"), expected drwx------"
  grep -qF "$hex_secret" "$ENV_FILE" ||
    st_fail "the env file lost the keytab override that the test command sources"

  printed="$(print_env)"
  [[ "$printed" != *"$hex_secret"* && "$printed" != *"$b64_secret"* ]] ||
    st_fail "env printed a keytab secret value"
  [[ "$printed" == *"export TEST_AD_TESTUSER1_KEYTAB_HEX=<redacted>"* &&
    "$printed" == *"export TEST_AD_SYSHTTP_KEYTAB_BASE64=<redacted>"* ]] ||
    st_fail "env did not mark the redacted keytab values"
  [[ "$printed" == *"export TEST_KDC_ADDR=127.0.0.1:88"* ]] ||
    st_fail "env dropped a non-secret value"

  stop_all
  [[ ! -e "$ENV_FILE" ]] || st_fail "stop left the env file with keytab secrets behind"

  # Operator values with spaces, quotes, substitutions, semicolons and
  # newlines are data: they round-trip byte for byte through the file the
  # test command sources, and nothing in them runs.
  local marker="$scratch/EXECUTED"
  local spaced_path="/tmp/lab keytabs/user's \"one\".keytab"
  local hostile_addr="kdc.example:88; touch $marker"
  local hostile_url="http://example.test/\$(touch $marker)/\`touch $marker\`"
  local wrapped_b64=$'BQIAAAdummy-first-line\nsecond-line-dummy-secret==\n'
  local wrapped_hex=$'0502000000\n  dummyhexsecondline'
  TEST_AD_TESTUSER1_KEYTAB_PATH="$spaced_path" TEST_AD_USER_KDC_ADDR="$hostile_addr" \
    TEST_AD_SYSHTTP_KEYTAB_BASE64="$wrapped_b64" TEST_AD_TESTUSER2_KEYTAB_HEX="$wrapped_hex" \
    write_env 127.0.0.1:88 127.0.0.1:78 127.0.0.1:98 127.0.0.1:188 127.0.0.1:58 \
    127.0.0.1:464 127.0.0.1 127.0.88.53 127.0.88.53:53 "$hostile_url" 127.0.0.1 0
  local loaded
  loaded="$(
    # shellcheck disable=SC1090
    source "$ENV_FILE" &&
      printf '%s\0' "$TEST_AD_TESTUSER1_KEYTAB_PATH" "$TEST_AD_USER_KDC_ADDR" "$TEST_HTTP_URL" \
        "$TEST_AD_SYSHTTP_KEYTAB_BASE64" "$TEST_AD_TESTUSER2_KEYTAB_HEX" "$INTEGRATION_REQUIRED" | od -An -c
  )" || st_fail "the env file with operator values does not source"
  [[ "$loaded" == "$(printf '%s\0' "$spaced_path" "$hostile_addr" "$hostile_url" "$wrapped_b64" "$wrapped_hex" 1 | od -An -c)" ]] ||
    st_fail "operator values did not round-trip through the env file"
  printed="$(print_env)"
  local secret_line
  while IFS= read -r secret_line; do
    [[ -z "${secret_line// /}" || "$printed" != *"$secret_line"* ]] ||
      st_fail "env printed a line of a multiline keytab secret: $secret_line"
  done <<<"$wrapped_b64"$'\n'"$wrapped_hex"
  [[ "$printed" == *"export TEST_AD_SYSHTTP_KEYTAB_BASE64=<redacted>"* &&
    "$printed" == *"export TEST_AD_TESTUSER2_KEYTAB_HEX=<redacted>"* ]] ||
    st_fail "env did not mark the multiline keytab values redacted"
  local seen="$scratch/seen-by-tests"
  cargo() { printf '%s' "$TEST_AD_SYSHTTP_KEYTAB_BASE64" >"$seen"; }
  RSKRB5_CONFIGURE_RESOLVER=0 run_tests >/dev/null || st_fail "test could not run on the operator values"
  unset -f cargo
  printf '%s' "$wrapped_b64" | cmp -s - "$seen" ||
    st_fail "the test command did not receive the complete multiline keytab value"
  [[ ! -e "$marker" ]] || st_fail "an operator value ran as a shell command"
  cargo() {
    [[ "$TESTAD" == 1 && "$TESTAD_REQUIRED" == 1 && "$TEST_KPASSWD" == 1 &&
      "$TEST_AD_USER_KDC_ADDR" == "override.example:88" ]] || return 1
  }
  TESTAD=1 TESTAD_REQUIRED=1 TEST_KPASSWD=1 TEST_AD_USER_KDC_ADDR=override.example:88 \
    RSKRB5_CONFIGURE_RESOLVER=0 run_tests >/dev/null || st_fail "saved environment replaced caller overrides"
  unset -f cargo
  # A requested run fails instead of skipping unless the operator opts out.
  INTEGRATION_REQUIRED=0 write_env 127.0.0.1:88 127.0.0.1:78 127.0.0.1:98 127.0.0.1:188 127.0.0.1:58 \
    127.0.0.1:464 127.0.0.1 127.0.88.53 127.0.88.53:53 http://127.0.0.1 127.0.0.1 0
  [[ "$(source "$ENV_FILE" && printf '%s' "$INTEGRATION_REQUIRED")" == "0" ]] ||
    st_fail "an operator INTEGRATION_REQUIRED=0 was not kept"
  stop_all

  # A symlinked environment directory is refused; nothing reaches its target.
  mkdir "$scratch/elsewhere"
  ENV_DIR="$scratch/linked"
  ENV_FILE="$ENV_DIR/gated-integration.env"
  ln -s "$scratch/elsewhere" "$ENV_DIR"
  if TEST_AD_TESTUSER1_KEYTAB_HEX="$hex_secret" \
    write_env 127.0.0.1:88 127.0.0.1:78 127.0.0.1:98 127.0.0.1:188 127.0.0.1:58 \
    127.0.0.1:464 127.0.0.1 127.0.88.53 127.0.88.53:53 http://127.0.0.1 127.0.0.1 0 2>/dev/null; then
    st_fail "write_env wrote through a symlinked environment directory"
  fi
  [[ -z "$(ls -A "$scratch/elsewhere")" ]] ||
    st_fail "a file reached the symlinked directory's target"

  rm -rf "$scratch"
  if [[ "$failures" -ne 0 ]]; then
    return 1
  fi
  echo "self-test: ok"
}

main() {
  local command="${1:-}"
  if [[ -z "$command" || "$command" == "-h" || "$command" == "--help" ]]; then
    usage
    exit 0
  fi
  shift || true

  case "$command" in
    start)
      start_fixtures
      ;;
    test)
      run_tests "$@"
      ;;
    run)
      if [[ "${RSKRB5_KEEP_CONTAINERS:-0}" != "1" ]]; then
        trap stop_all EXIT
      fi
      start_fixtures
      run_tests "$@"
      ;;
    stop)
      stop_all
      ;;
    env)
      print_env
      ;;
    self-test)
      self_test
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
}

main "$@"

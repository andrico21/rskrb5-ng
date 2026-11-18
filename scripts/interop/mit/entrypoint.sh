#!/bin/bash
# Entrypoint of the MIT krb5 1.22.2 interop fixture `mit-kdc` (realm TEST.RSKRB5).
#
# 1. Waits (bounded) for run.sh to stream the per-run secrets into the tmpfs
#    file /run/interop/secrets (NAME=value lines, values [A-Za-z0-9] only).
# 2. Runs every /opt/interop/mit/provision.d/*.sh in name order (idempotent
#    steps; the base realm is 10-base-realm.sh). Later lanes add scripts there.
# 3. Starts kadmind and krb5kdc, waits (bounded) until ports 88, 464 and 749
#    accept TCP connections, runs /opt/interop/mit/started.d/*.sh, then writes
#    /run/interop/ready. run.sh waits for that marker.
# 4. Exits non-zero, naming the fixture, as soon as either daemon exits.
# No secret is ever printed: provisioning output carries principal names only.
set -euo pipefail

readonly FIXTURE=mit-kdc
readonly RUN_DIR=/run/interop
readonly SECRETS="$RUN_DIR/secrets"
readonly READY="$RUN_DIR/ready"
readonly HOOKS=/opt/interop/mit

log() {
  printf 'interop[%s]: %s\n' "$FIXTURE" "$*" >&2
}

fail() {
  log "FAILED: $*"
  exit 1
}

wait_for_secrets() {
  local limit="${INTEROP_SECRETS_TIMEOUT:-120}" waited=0
  while [[ ! -f "$SECRETS" ]]; do
    if ((waited >= limit)); then
      fail "no secrets were delivered to $SECRETS within ${limit}s"
    fi
    sleep 1
    waited=$((waited + 1))
  done
}

# Exports each NAME=value line; names and values are validated, never evaluated.
load_secrets() {
  local name value
  while IFS='=' read -r name value; do
    [[ "$name" =~ ^INTEROP_[A-Z0-9_]+$ ]] || fail "malformed secret name in $SECRETS"
    [[ "$value" =~ ^[A-Za-z0-9]+$ ]] || fail "secret $name has characters outside [A-Za-z0-9]"
    printf -v "$name" '%s' "$value"
    export "${name?}"
  done <"$SECRETS"
}

run_hooks() {
  local stage="$1" script
  for script in "$HOOKS/$stage"/*.sh; do
    [[ -e "$script" ]] || continue
    log "$stage: ${script##*/}"
    bash "$script" || fail "$stage step ${script##*/} failed"
  done
}

tcp_open() {
  (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null
}

wait_for_ports() {
  local limit="${INTEROP_DAEMON_TIMEOUT:-60}" waited=0 port
  for port in 88 464 749; do
    until tcp_open "$port"; do
      if ((waited >= limit)); then
        fail "port $port did not accept connections within ${limit}s"
      fi
      sleep 1
      waited=$((waited + 1))
    done
  done
}

main() {
  umask 077
  mkdir -p "$RUN_DIR/out"
  rm -f "$READY"
  wait_for_secrets
  load_secrets
  run_hooks provision.d
  kadmind -nofork &
  local kadmind_pid=$!
  krb5kdc -n &
  local kdc_pid=$!
  trap 'kill "$kadmind_pid" "$kdc_pid" 2>/dev/null; exit 143' TERM INT
  wait_for_ports
  run_hooks started.d
  : >"$READY"
  log "ready (krb5kdc pid $kdc_pid, kadmind pid $kadmind_pid)"
  local status=0
  wait -n "$kadmind_pid" "$kdc_pid" || status=$?
  fail "a daemon exited with status $status"
}

main "$@"

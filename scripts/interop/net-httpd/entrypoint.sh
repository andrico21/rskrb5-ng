#!/bin/bash
# Entrypoint of the Negotiate HTTP fixture `httpd` (lane 1D-b).
#
# 1. Waits (bounded) for run.sh to stream the service keytab
#    (HTTP/httpd.test.rskrb5@TEST.RSKRB5) into the tmpfs /run/interop.
# 2. Installs it for the www-data workers in the tmpfs /run/gssapi (mode 0600,
#    owner www-data), then runs Apache in the foreground.
# 3. Waits (bounded) until port 80 accepts TCP connections, writes
#    /run/interop/ready, and exits non-zero naming the fixture when Apache
#    exits.
set -euo pipefail

readonly FIXTURE=httpd
readonly KEYTAB_IN=/run/interop/http.keytab
readonly KEYTAB=/run/gssapi/http.keytab
readonly READY=/run/interop/ready

log() {
  printf 'interop[%s]: %s\n' "$FIXTURE" "$*" >&2
}

fail() {
  log "FAILED: $*"
  exit 1
}

tcp_open() {
  (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null
}

main() {
  local limit="${INTEROP_SECRETS_TIMEOUT:-120}" waited=0
  rm -f "$READY"
  while [[ ! -s "$KEYTAB_IN" ]]; do
    ((waited < limit)) || fail "no keytab was delivered to $KEYTAB_IN within ${limit}s"
    sleep 1
    waited=$((waited + 1))
  done
  install -o www-data -g www-data -m 0600 "$KEYTAB_IN" "$KEYTAB"
  # shellcheck disable=SC1091
  source /etc/apache2/envvars
  mkdir -p "$APACHE_RUN_DIR" "$APACHE_LOCK_DIR" "$APACHE_LOG_DIR"
  apache2 -D FOREGROUND &
  local pid=$!
  trap 'kill "$pid" 2>/dev/null; exit 143' TERM INT
  limit="${INTEROP_DAEMON_TIMEOUT:-60}"
  waited=0
  until tcp_open 80; do
    kill -0 "$pid" 2>/dev/null || fail "apache2 exited before listening on 80"
    ((waited < limit)) || fail "port 80 did not accept connections within ${limit}s"
    sleep 1
    waited=$((waited + 1))
  done
  : >"$READY"
  log "ready (apache2 pid $pid, $(apache2 -v | head -n1))"
  local status=0
  wait "$pid" || status=$?
  fail "apache2 exited with status $status"
}

main "$@"

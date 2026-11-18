#!/bin/bash
# Entrypoint of the DNS fixture `dns` (lane 1D-b): runs CoreDNS with the
# per-run Corefile and zones that run.sh bind-mounted at /etc/coredns, waits
# (bounded) until both views answer the SOA of test.rskrb5 (port 53: the
# container-network view; port 1053: the host view, published on 127.0.0.1),
# writes /run/interop/ready, and exits non-zero naming the fixture when CoreDNS
# exits.
set -euo pipefail

readonly FIXTURE=dns
readonly READY=/run/interop/ready

log() {
  printf 'interop[%s]: %s\n' "$FIXTURE" "$*" >&2
}

fail() {
  log "FAILED: $*"
  exit 1
}

answers() {
  [[ -n "$(dig +short +time=1 +tries=1 -p "$1" @127.0.0.1 SOA test.rskrb5 2>/dev/null)" ]]
}

main() {
  rm -f "$READY"
  [[ -f /etc/coredns/Corefile ]] || fail "no Corefile mounted at /etc/coredns"
  coredns -conf /etc/coredns/Corefile &
  local pid=$! limit="${INTEROP_DAEMON_TIMEOUT:-60}" waited=0
  trap 'kill "$pid" 2>/dev/null; exit 143' TERM INT
  until answers 53 && answers 1053; do
    kill -0 "$pid" 2>/dev/null || fail "coredns exited before answering"
    ((waited < limit)) || fail "coredns did not answer on ports 53 and 1053 within ${limit}s"
    sleep 1
    waited=$((waited + 1))
  done
  kill -0 "$pid" 2>/dev/null || fail "coredns exited after answering (a zone did not load)"
  : >"$READY"
  log "ready (coredns pid $pid, $(coredns -version | head -n1))"
  local status=0
  wait "$pid" || status=$?
  fail "coredns exited with status $status"
}

main "$@"

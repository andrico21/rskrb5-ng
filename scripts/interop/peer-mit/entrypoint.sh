#!/bin/bash
# Entrypoint of the `mit-peer` fixture containers (lane 1F), run as the
# unprivileged user peer (10001): starts the external-peer adapter (frame
# protocol: see peer/peer.c), waits (bounded) until it accepts TCP connections,
# writes /run/interop/ready, and exits non-zero, naming the fixture, as soon as
# the adapter exits. Keytabs are streamed into /run/peer/keytabs by fixture.sh
# AFTER readiness; the adapter reads one only when a client asks for it.
# The adapter log (no secrets: command bytes and statuses) is tee'd to the
# container log and to /run/peer/adapter.log, which selfcheck.sh reads.
set -euo pipefail

readonly FIXTURE="${INTEROP_PEER_FIXTURE:-mit-peer}"
readonly PORT=4401
readonly READY=/run/interop/ready
readonly RUN_DIR=/run/peer

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
  umask 077
  mkdir -p "$RUN_DIR/keytabs"
  rm -f "$READY"
  : >"$RUN_DIR/adapter.log"
  # The idle bound is generous for tests that talk to a slow KDC; the frame
  # self-check starts its own adapter with a short one.
  PEER_IDLE_SECONDS="${PEER_IDLE_SECONDS:-30}" \
    peer-adapter 0.0.0.0 "$PORT" 2> >(tee -a "$RUN_DIR/adapter.log" >&2) &
  local adapter=$!
  trap 'kill "$adapter" 2>/dev/null; exit 143' TERM INT
  local limit="${INTEROP_DAEMON_TIMEOUT:-30}" waited=0
  until tcp_open "$PORT"; do
    if ((waited >= limit)); then
      fail "the adapter did not accept connections on $PORT within ${limit}s"
    fi
    sleep 1
    waited=$((waited + 1))
  done
  : >"$READY"
  log "ready (peer-adapter pid $adapter, port $PORT)"
  local status=0
  wait "$adapter" || status=$?
  fail "the adapter exited with status $status"
}

main "$@"

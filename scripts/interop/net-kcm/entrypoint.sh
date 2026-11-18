#!/bin/bash
# Entrypoint of the SSSD KCM fixture `kcm` (lane 1D-b): starts sssd_kcm
# (stderr logger), waits (bounded) for its socket /run/kcm/kcm.sock (the
# bind-mounted host directory), writes /run/interop/ready, and exits non-zero
# naming the fixture when sssd_kcm exits.
set -euo pipefail

readonly FIXTURE=kcm
readonly SOCKET=/run/kcm/kcm.sock
readonly READY=/run/interop/ready

log() {
  printf 'interop[%s]: %s\n' "$FIXTURE" "$*" >&2
}

fail() {
  log "FAILED: $*"
  exit 1
}

main() {
  rm -f "$READY" "$SOCKET"
  /usr/libexec/sssd/sssd_kcm --logger=stderr &
  local pid=$! limit="${INTEROP_DAEMON_TIMEOUT:-60}" waited=0
  trap 'kill "$pid" 2>/dev/null; exit 143' TERM INT
  until [[ -S "$SOCKET" ]]; do
    kill -0 "$pid" 2>/dev/null || fail "sssd_kcm exited before creating $SOCKET"
    ((waited < limit)) || fail "sssd_kcm did not create $SOCKET within ${limit}s"
    sleep 1
    waited=$((waited + 1))
  done
  : >"$READY"
  log "ready (sssd_kcm pid $pid, socket $SOCKET, $(dpkg-query -W -f '${Package} ${Version}' sssd-kcm))"
  local status=0
  wait "$pid" || status=$?
  fail "sssd_kcm exited with status $status"
}

main "$@"

#!/bin/bash
# Plan 2 todo 5 (WP-03, Camellia): two principals whose long-term keys are
# Camellia only, so every ticket and reply MIT builds for them is Camellia.
#   camelliauser                  password user (no pre-authentication)
#   camelliasvc/svc.test.rskrb5   service, +no_auth_data_required (no PAC, like
#                                 the other services of the fixture)
# The passwords are derived, not stored: the first 32 hex digits of
# sha256("rskrb5-interop camellia v1:<label>:<admin password>") with the label
# `user` or `service` and the per-run kadmin password. tests/interop_camellia
# derives the same values, so no new secret crosses the host/container
# boundary. Idempotent; nothing secret is printed.
set -euo pipefail

readonly REALM=TEST.RSKRB5
readonly KEYS=camellia256-cts-cmac:normal,camellia128-cts-cmac:normal

: "${INTEROP_MIT_ADMIN_PASSWORD:?}"

derive() {
  printf 'rskrb5-interop camellia v1:%s:%s' "$1" "$INTEROP_MIT_ADMIN_PASSWORD" | sha256sum | cut -c1-32
}

exists() {
  kadmin.local -r "$REALM" -q "getprinc $1" 2>/dev/null | grep -q '^Principal: '
}

# ensure NAME LABEL [addprinc options...]: creates NAME once, with Camellia keys only.
ensure() {
  local name="$1" label="$2" output
  shift 2
  if exists "$name"; then
    return 0
  fi
  output="$(kadmin.local -r "$REALM" -q "addprinc -e $KEYS $* -pw $(derive "$label") $name" 2>&1)" ||
    {
      printf 'kadmin.local failed for %s\n' "$name" >&2
      return 1
    }
  [[ "$output" == *"Principal \"$name@$REALM\" created"* ]] || {
    printf 'kadmin.local did not create %s\n' "$name" >&2
    return 1
  }
  printf 'created %s@%s with Camellia keys\n' "$name" "$REALM"
}

ensure camelliauser user
ensure camelliasvc/svc.test.rskrb5 service +no_auth_data_required

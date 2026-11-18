#!/bin/bash
# Principals of the `mit-peer` fixture (lane 1F, scripts/interop/peer-mit/),
# provisioned in the mit-kdc container before the daemons start (extension
# prefix range 70-79). Idempotent. Output carries principal names only.
#
#   peer/mit-peer.test.rskrb5  the adapter's acceptor service (random keys);
#                              keytab out/peer-acceptor.keytab
#   peer/rust.test.rskrb5      acceptor service of the Rust crate's tests;
#                              +no_auth_data_required (the acceptor refuses a
#                              PAC without KERB_VALIDATION_INFO today, see
#                              10-base-realm.sh); keytab out/peer-rust.keytab
#   peeruser                   initiator of the adapter (+requires_preauth);
#                              password derived per run from the admin password
#                              (the host derives the same value, see
#                              fixture_mit_peer_up), keytab out/peeruser.keytab
set -euo pipefail

readonly REALM=TEST.RSKRB5
readonly OUT=/run/interop/out

: "${INTEROP_MIT_ADMIN_PASSWORD:?}"

kadmin_query() {
  local query="$1" expect="$2" output
  output="$(kadmin.local -r "$REALM" -q "$query" 2>&1)" || {
    printf 'kadmin.local failed: %s\n' "${query%% -pw *}" >&2
    return 1
  }
  if [[ "$output" != *"$expect"* ]]; then
    printf 'kadmin.local did not report "%s" for: %s\n' "$expect" "${query%% -pw *}" >&2
    return 1
  fi
}

exists() {
  kadmin.local -r "$REALM" -q "getprinc $1" 2>/dev/null | grep -q '^Principal: '
}

ensure_principal() {
  local name="$1"
  shift
  if exists "$name"; then
    return 0
  fi
  kadmin_query "addprinc $* $name" "Principal \"$name@$REALM\" created"
  printf 'created %s@%s\n' "$name" "$REALM"
}

export_keytab() {
  local file="$OUT/$1" name="$2"
  rm -f "$file"
  kadmin_query "ktadd -k $file -norandkey $name" "added to keytab"
  printf 'exported %s@%s to out/%s\n' "$name" "$REALM" "$1"
}

# The password of peeruser: 32 hex digits of sha256("rskrb5-interop peer-user v1" + admin password).
peeruser_password="$(printf '%s' "rskrb5-interop peer-user v1${INTEROP_MIT_ADMIN_PASSWORD}" | sha256sum | cut -c1-32)"

ensure_principal peer/mit-peer.test.rskrb5 -randkey
ensure_principal peer/rust.test.rskrb5 +no_auth_data_required -randkey
ensure_principal peeruser +requires_preauth -pw "$peeruser_password"

export_keytab peer-acceptor.keytab peer/mit-peer.test.rskrb5
export_keytab peer-rust.keytab peer/rust.test.rskrb5
export_keytab peeruser.keytab peeruser

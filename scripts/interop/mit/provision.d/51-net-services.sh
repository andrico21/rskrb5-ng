#!/bin/bash
# Lane 1D-b (plan 2 todo 1): TEST.RSKRB5 principals of the network fixtures.
# Idempotent, runs before the daemons start; nothing secret is printed.
#
#   HTTP/httpd.test.rskrb5   Apache mod_auth_gssapi service of fixture httpd
#                            (net-httpd/), random keys, keytab out/httpd.keytab.
#                            Default principal flags: its tickets carry the MIT
#                            PAC, which the Apache/MIT acceptor ignores.
#   proxypwuser              disposable password-change account for kpasswd
#                            through the KDC proxy (fixture kdcproxy), with
#                            +requires_preauth; its first password is derived
#                            per run with the label kpasswd-old, and the
#                            kdcproxy self-check changes it to the kpasswd-new
#                            derivation (net-common/net.sh net_derive_secret).
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
  kadmin_query "addprinc $* $name" "Principal \"$name\" created"
  printf 'created %s\n' "$name"
}

ensure_principal "HTTP/httpd.test.rskrb5@$REALM" -randkey
rm -f "$OUT/httpd.keytab"
kadmin_query "ktadd -k $OUT/httpd.keytab -norandkey HTTP/httpd.test.rskrb5@$REALM" "added to keytab"
printf 'exported HTTP/httpd.test.rskrb5@%s to out/httpd.keytab\n' "$REALM"

old="$(printf 'rskrb5-interop %s v1:%s' kpasswd-old "$INTEROP_MIT_ADMIN_PASSWORD" | sha256sum | cut -c1-32)"
ensure_principal "proxypwuser@$REALM" +requires_preauth -pw "$old"
unset old

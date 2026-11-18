#!/bin/bash
# Lane 1D-b (plan 2 todo 1): the TEST.RSKRB5 side of the trust with the second
# MIT realm OTHER.RSKRB5 (fixture mit-other, scripts/interop/net-other/), plus
# the TEST principals of the network fixtures. Idempotent, runs before the
# daemons start (entrypoint.sh provision.d stage). No secret is printed.
#
# Cross-realm keys, both directions, identical in both KDCs:
#   krbtgt/OTHER.RSKRB5@TEST.RSKRB5   (TEST users -> OTHER services)
#   krbtgt/TEST.RSKRB5@OTHER.RSKRB5   (OTHER users -> TEST services)
# Same password (below), so the same salt-derived keys for every enctype of
# kdc.conf supported_enctypes (both realms list the same four AES enctypes),
# and kvno 1 on both sides. The password is derived per run from the per-run
# kadmin password: sha256("rskrb5-interop cross-realm v1:" + admin password),
# first 32 hex characters (scripts/interop/net-common/net.sh
# net_derive_secret computes the same value on the host for mit-other).
#
# The TEST KDC has NO [capaths] entry for FAR.EXAMPLE (the third realm, served
# by the mit-other container and reachable only through OTHER.RSKRB5), so a
# client needs its own [capaths] to find that route (net-other/fixture.sh).
#
# Profile fragment /etc/krb5.conf.d/50-other-realm.conf (read by the KDC and
# the tools in this container): where the OTHER KDC is, and the domain mapping
# the KDC uses to answer a host-based TEST.RSKRB5 request for a service under
# other.rskrb5 with a referral TGT krbtgt/OTHER.RSKRB5@TEST.RSKRB5.
set -euo pipefail

readonly REALM=TEST.RSKRB5
readonly OTHER=OTHER.RSKRB5

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

# ensure_principal NAME [addprinc options...]: creates NAME once.
ensure_principal() {
  local name="$1"
  shift
  if exists "$name"; then
    return 0
  fi
  kadmin_query "addprinc $* $name" "Principal \"$name\" created"
  printf 'created %s\n' "$name"
}

cross="$(printf 'rskrb5-interop %s v1:%s' cross-realm "$INTEROP_MIT_ADMIN_PASSWORD" | sha256sum | cut -c1-32)"
ensure_principal "krbtgt/$OTHER@$REALM" -pw "$cross"
ensure_principal "krbtgt/$REALM@$OTHER" -pw "$cross"
unset cross

cat >/etc/krb5.conf.d/50-other-realm.conf <<'EOF'
# Written by provision.d/50-other-realm.sh (lane 1D-b): the second realm.
[realms]
    OTHER.RSKRB5 = {
        kdc = kdc.other.rskrb5:88
        admin_server = kdc.other.rskrb5:749
        kpasswd_server = kdc.other.rskrb5:464
    }

[domain_realm]
    .other.rskrb5 = OTHER.RSKRB5
    other.rskrb5 = OTHER.RSKRB5
EOF

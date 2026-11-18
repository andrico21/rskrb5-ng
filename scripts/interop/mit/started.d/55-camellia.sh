#!/bin/bash
# Plan 2 todo 5 (WP-03, Camellia) self-check, after the daemons listen: the MIT
# client tools get a Camellia reply and a Camellia service ticket from this
# KDC, proven from the KRB5_TRACE of kinit and from `klist -e`. A fixture whose
# Camellia keys were silently replaced by AES keys fails here, before any test.
set -euo pipefail

readonly REALM=TEST.RSKRB5

: "${INTEROP_MIT_ADMIN_PASSWORD:?}"

# The TGS list also names the AES enctype of the TGT's session key: the MIT
# client only reuses a cached TGT whose session key it may use (the Camellia
# name stays first, so the service session key is Camellia).
workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT
cat >"$workdir/krb5.conf" <<'CONF'
[libdefaults]
    default_tkt_enctypes = camellia256-cts-cmac aes256-cts-hmac-sha384-192
    default_tgs_enctypes = camellia256-cts-cmac aes256-cts-hmac-sha384-192
CONF
export KRB5_CONFIG="$workdir/krb5.conf:/etc/krb5.conf"
export KRB5CCNAME="FILE:$workdir/ccache"
export KRB5_TRACE="$workdir/trace"

password="$(printf 'rskrb5-interop camellia v1:user:%s' "$INTEROP_MIT_ADMIN_PASSWORD" | sha256sum | cut -c1-32)"
printf '%s\n' "$password" | kinit "camelliauser@$REALM" >/dev/null
kvno "camelliasvc/svc.test.rskrb5@$REALM" >/dev/null || { cat "$workdir/trace" >&2; exit 1; }
klist -e >"$workdir/klist"

# The AS reply was encrypted in the user's Camellia key (etype info and key lines of the trace).
grep -Eq 'Selected etype info: etype camellia256-cts' "$workdir/trace" ||
  { echo 'self-check camellia: the trace shows no Camellia etype info' >&2; exit 1; }
grep -Eq 'AS key obtained.*camellia256-cts' "$workdir/trace" ||
  { echo 'self-check camellia: the trace shows no Camellia AS key' >&2; exit 1; }
# The service ticket and its session key are Camellia.
grep -Eq 'Etype \(skey, tkt\): camellia256-cts-cmac, camellia256-cts-cmac' "$workdir/klist" ||
  { echo 'self-check camellia: klist -e shows no Camellia service ticket' >&2; exit 1; }
sed -n '/camelliasvc/,+1p' "$workdir/klist"
echo 'self-check camellia: ok (etype info, AS key and service ticket are camellia256-cts-cmac)'
